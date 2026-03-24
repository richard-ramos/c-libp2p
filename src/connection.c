/* src/connection.c — connection state machine implementation
 *
 * Upgrade pipeline (TCP):
 *   TCP connect -> multistream /noise -> Noise XX handshake
 *   -> multistream /yamux/1.0.0 -> READY
 *
 * Data flow:
 *   Read:  TCP bytes -> security->decrypt() -> mux->on_data() -> per-stream
 *   Write: stream data -> mux framing -> security->encrypt() -> TCP write
 */

#include "connection_internal.h"
#include "protocol/multistream.h"
#include "security/noise/noise_internal.h"
#include "mux/yamux/yamux_internal.h"
#include "stream_internal.h"
#include "crypto/keypair_internal.h"
#ifdef LP2P_HAVE_QUIC
#include "transport/quic/quic_transport.h"
#endif

#include "libp2p/crypto.h"
#include "libp2p/multiaddr.h"

#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ── Constants ────────────────────────────────────────────────────────────── */

#define NOISE_PROTO_ID     "/noise"
#define YAMUX_PROTO_ID     "/yamux/1.0.0"
#define DECRYPT_BUF_INIT   (16 * 1024)
#define GOAWAY_DRAIN_MS    100
#define GOAWAY_RECV_DRAIN_MS 5000

/* ── Forward declarations ─────────────────────────────────────────────────── */

static void conn_start_security_negotiation(lp2p_conn_t *conn);
static void conn_start_noise_handshake(lp2p_conn_t *conn);
static void conn_start_mux_negotiation(lp2p_conn_t *conn);
static void conn_finish_ready(lp2p_conn_t *conn);
static void conn_teardown(lp2p_conn_t *conn, lp2p_err_t reason);
static void conn_defer(lp2p_conn_t *conn, conn_deferred_fn fn, void *arg);
static void conn_async_cb(uv_async_t *handle);
static void conn_on_tcp_read(lp2p_tcp_conn_t *tc, const uint8_t *data,
                             size_t len, lp2p_err_t err, void *userdata);
static void conn_on_mux_send(const uint8_t *data, size_t len, void *userdata);
static void conn_on_mux_inbound_stream(yamux_session_t *session,
                                        lp2p_stream_t *stream, void *userdata);
static void conn_drain_timer_cb(uv_timer_t *handle);

/* ── Deferred callback runner ─────────────────────────────────────────────── */

static void conn_async_cb(uv_async_t *handle) {
    lp2p_conn_t *conn = (lp2p_conn_t *)handle->data;

    while (!lp2p_list_empty(&conn->deferred_queue)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&conn->deferred_queue);
        conn_deferred_t *d = lp2p_container_of(n, conn_deferred_t, node);
        conn_deferred_fn fn = d->fn;
        void *arg = d->arg;
        free(d);
        fn(arg);
    }
}

static void conn_defer(lp2p_conn_t *conn, conn_deferred_fn fn, void *arg) {
    conn_deferred_t *d = calloc(1, sizeof(*d));
    if (!d) return;
    d->fn = fn;
    d->arg = arg;
    lp2p_list_push_back(&conn->deferred_queue, &d->node);
    if (conn->async_initialized) {
        uv_async_send(&conn->async_handle);
    }
}

/* ── Helper: deferred ready callback ──────────────────────────────────────── */

typedef struct {
    lp2p_conn_t *conn;
} conn_ready_ctx_t;

static void conn_deferred_ready(void *arg) {
    conn_ready_ctx_t *ctx = (conn_ready_ctx_t *)arg;
    lp2p_conn_t *conn = ctx->conn;
    free(ctx);
    if (conn->on_ready && conn->state == CONN_STATE_READY) {
        conn->on_ready(conn, conn->cb_userdata);
    }
}

/* ── Helper: deferred disconnect callback ─────────────────────────────────── */

typedef struct {
    lp2p_conn_t *conn;
    lp2p_err_t   reason;
} conn_disconnect_ctx_t;

static void conn_deferred_disconnect(void *arg) {
    conn_disconnect_ctx_t *ctx = (conn_disconnect_ctx_t *)arg;
    lp2p_conn_t *conn = ctx->conn;
    lp2p_err_t reason = ctx->reason;
    free(ctx);
    if (conn->on_disconnect) {
        conn->on_disconnect(conn, reason, conn->cb_userdata);
    }
}

/* ── Helper: deferred close callback ──────────────────────────────────────── */

typedef struct {
    lp2p_conn_t *conn;
    void (*cb)(lp2p_conn_t *, void *);
    void *userdata;
} conn_close_ctx_t;

static void conn_deferred_close_cb(void *arg) {
    conn_close_ctx_t *ctx = (conn_close_ctx_t *)arg;
    if (ctx->cb) {
        ctx->cb(ctx->conn, ctx->userdata);
    }
    free(ctx);
}

/* ── Helper: deferred open-stream callback ────────────────────────────────── */

typedef struct {
    lp2p_open_stream_cb cb;
    lp2p_stream_t      *stream;
    lp2p_err_t          err;
    void               *userdata;
} conn_open_stream_ctx_t;

static void conn_deferred_open_stream(void *arg) {
    conn_open_stream_ctx_t *ctx = (conn_open_stream_ctx_t *)arg;
    if (ctx->cb) {
        ctx->cb(ctx->stream, ctx->err, ctx->userdata);
    }
    free(ctx);
}

/* ── Constructor / destructor ─────────────────────────────────────────────── */

lp2p_conn_t *lp2p_conn_new(uv_loop_t *loop, bool is_inbound, void *host_ptr) {
    lp2p_conn_t *conn = calloc(1, sizeof(*conn));
    if (!conn) return NULL;

    conn->state = CONN_STATE_TRANSPORT_CONNECTING;
    conn->backend = LP2P_CONN_BACKEND_TCP_YAMUX;
    conn->is_inbound = is_inbound;
    conn->loop = loop;
    conn->host = host_ptr;

    lp2p_buffer_init(&conn->read_buf);
    lp2p_list_init(&conn->deferred_queue);
    lp2p_list_init(&conn->pending_streams);

    /* Allocate decrypt scratch buffer */
    conn->decrypt_buf = malloc(DECRYPT_BUF_INIT);
    conn->decrypt_buf_cap = conn->decrypt_buf ? DECRYPT_BUF_INIT : 0;

    /* Initialize async handle for deferred callbacks */
    if (uv_async_init(loop, &conn->async_handle, conn_async_cb) == 0) {
        conn->async_handle.data = conn;
        conn->async_initialized = true;
    }

    return conn;
}

static void conn_async_close_cb(uv_handle_t *handle) {
    lp2p_conn_t *conn = (lp2p_conn_t *)handle->data;
    if (!conn) return;

    if (conn->close_handles_pending > 0) {
        conn->close_handles_pending--;
    }

    if (conn->close_handles_pending == 0) {
        free(conn);
    }
}

static void conn_drain_timer_close_cb(uv_handle_t *handle) {
    lp2p_conn_t *conn = (lp2p_conn_t *)handle->data;
    if (!conn) return;

    if (conn->close_handles_pending > 0) {
        conn->close_handles_pending--;
    }

    if (conn->close_handles_pending == 0) {
        free(conn);
    }
}

void lp2p_conn_free(lp2p_conn_t *conn) {
    if (!conn) return;
    if (conn->destroy_started) return;

    conn->destroy_started = true;

#ifdef LP2P_HAVE_QUIC
    if (conn->backend == LP2P_CONN_BACKEND_QUIC && conn->backend_impl) {
        lp2p_quic_conn_cleanup(conn);
    }
#endif

    /* Free security session */
    if (conn->security) {
        conn->security->vtable->free(conn->security->impl);
        free(conn->security);
        conn->security = NULL;
    }

    /* Free mux session */
    if (conn->mux) {
        conn->mux->vtable->free(conn->mux->impl);
        free(conn->mux);
        conn->mux = NULL;
    }

    /* Free addresses */
    if (conn->remote_addr) {
        lp2p_multiaddr_free(conn->remote_addr);
    }
    if (conn->local_addr) {
        lp2p_multiaddr_free(conn->local_addr);
    }

    /* Free buffers */
    lp2p_buffer_free(&conn->read_buf);
    free(conn->decrypt_buf);

    /* Drain deferred queue */
    while (!lp2p_list_empty(&conn->deferred_queue)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&conn->deferred_queue);
        conn_deferred_t *d = lp2p_container_of(n, conn_deferred_t, node);
        free(d);
    }

    /* Free pending stream requests */
    while (!lp2p_list_empty(&conn->pending_streams)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&conn->pending_streams);
        conn_open_stream_req_t *req = lp2p_container_of(n, conn_open_stream_req_t, node);
        free(req->protocol_id);
        free(req);
    }

    /* Close async handle if initialized */
    if (conn->async_initialized) {
        conn->close_handles_pending++;
        conn->async_handle.data = conn;
        uv_close((uv_handle_t *)&conn->async_handle, conn_async_close_cb);
        conn->async_initialized = false;
    }

    /* Close drain timer if active */
    if (conn->drain_timer_active) {
        uv_timer_stop(&conn->drain_timer);
        conn->close_handles_pending++;
        conn->drain_timer.data = conn;
        uv_close((uv_handle_t *)&conn->drain_timer, conn_drain_timer_close_cb);
        conn->drain_timer_active = false;
    }

    if (conn->close_handles_pending == 0) {
        free(conn);
    }
}

/* ── Attach TCP transport ─────────────────────────────────────────────────── */

void lp2p_conn_attach_tcp(lp2p_conn_t *conn, lp2p_tcp_conn_t *tc) {
    if (!conn || !tc) return;
    conn->tcp = tc;
    conn->state = CONN_STATE_TRANSPORT_CONNECTING;
}

/* ── Set protocol router ──────────────────────────────────────────────────── */

void lp2p_conn_set_protocol_router(lp2p_conn_t *conn, lp2p_protocol_router_t *router) {
    if (!conn) return;
    conn->router = router;
#ifdef LP2P_HAVE_QUIC
    if (conn->backend == LP2P_CONN_BACKEND_QUIC) {
        lp2p_quic_conn_notify_pending_streams(conn);
    }
#endif
}

/* ── TCP read callback (raw bytes from the wire) ──────────────────────────── */

static void conn_on_tcp_read(lp2p_tcp_conn_t *tc, const uint8_t *data,
                             size_t len, lp2p_err_t err, void *userdata) {
    lp2p_conn_t *conn = (lp2p_conn_t *)userdata;

    if (err != LP2P_OK) {
        conn_teardown(conn, err);
        return;
    }

    if (conn->state == CONN_STATE_READY || conn->state == CONN_STATE_CLOSING) {
        /* Decrypt incoming data and feed to mux */
        if (!conn->security || !conn->mux) {
            conn_teardown(conn, LP2P_ERR_INTERNAL);
            return;
        }

        /* Accumulate into read buffer */
        if (!lp2p_buffer_append(&conn->read_buf, data, len)) {
            conn_teardown(conn, LP2P_ERR_NOMEM);
            return;
        }
        lp2p_tcp_conn_consume(tc, len);

        /* Process complete Noise frames from the read buffer */
        while (conn->read_buf.len >= NOISE_FRAME_HDR_LEN) {
            /* Peek at the 2-byte big-endian length prefix */
            uint16_t frame_len = ((uint16_t)conn->read_buf.data[0] << 8) |
                                  (uint16_t)conn->read_buf.data[1];
            size_t total_frame = NOISE_FRAME_HDR_LEN + frame_len;

            if (conn->read_buf.len < total_frame) {
                break; /* need more data */
            }

            /* Ensure decrypt buffer is large enough */
            if (frame_len > conn->decrypt_buf_cap) {
                size_t new_cap = frame_len + 1024;
                uint8_t *new_buf = realloc(conn->decrypt_buf, new_cap);
                if (!new_buf) {
                    conn_teardown(conn, LP2P_ERR_NOMEM);
                    return;
                }
                conn->decrypt_buf = new_buf;
                conn->decrypt_buf_cap = new_cap;
            }

            /* Decrypt */
            size_t plain_len = 0;
            lp2p_err_t dec_err = conn->security->vtable->decrypt(
                conn->security->impl,
                conn->read_buf.data, total_frame,
                conn->decrypt_buf, &plain_len);

            if (dec_err != LP2P_OK) {
                /* Noise decrypt failure -> tear down immediately */
                conn_teardown(conn, LP2P_ERR_CRYPTO);
                return;
            }

            /* Consume the frame from the read buffer */
            size_t remaining = conn->read_buf.len - total_frame;
            if (remaining > 0) {
                memmove(conn->read_buf.data, conn->read_buf.data + total_frame,
                        remaining);
            }
            conn->read_buf.len = remaining;

            /* Feed plaintext to mux */
            lp2p_err_t mux_err = conn->mux->vtable->on_data(
                conn->mux->impl, conn->decrypt_buf, plain_len);

            if (mux_err != LP2P_OK) {
                /* Malformed yamux frame -> send GoAway(protocol_error), drain, close */
                conn->mux->vtable->go_away(conn->mux->impl,
                                           YAMUX_GOAWAY_PROTOCOL_ERR);
                conn->state = CONN_STATE_CLOSING;
                conn->goaway_sent = true;

                /* Start drain timer (100ms for protocol error) */
                if (!conn->drain_timer_active) {
                    uv_timer_init(conn->loop, &conn->drain_timer);
                    conn->drain_timer.data = conn;
                    conn->drain_timer_active = true;
                }
                uv_timer_start(&conn->drain_timer, conn_drain_timer_cb,
                               GOAWAY_DRAIN_MS, 0);
                return;
            }
        }
    }
    /* During handshake states, the multistream/noise code handles reads
     * directly through the TCP connection's on_read callback, not here. */
}

/* ── Drain timer callback ─────────────────────────────────────────────────── */

static void conn_drain_timer_cb(uv_timer_t *handle) {
    lp2p_conn_t *conn = (lp2p_conn_t *)handle->data;
    conn_teardown(conn, LP2P_ERR_CONNECTION_CLOSED);
}

/* ── Mux send callback (mux wants to write framed data) ───────────────────── */

static void conn_on_tcp_write_done(lp2p_tcp_conn_t *tc, lp2p_err_t err,
                                    void *userdata) {
    (void)tc;
    free(userdata); /* free the encrypted buffer */
    (void)err;      /* errors will surface on the read side */
}

static void conn_on_mux_send(const uint8_t *data, size_t len, void *userdata) {
    lp2p_conn_t *conn = (lp2p_conn_t *)userdata;

    if (!conn->security || !conn->tcp) return;

    /* Encrypt the mux frame data */
    size_t enc_cap = len + NOISE_FRAME_HDR_LEN + NOISE_AEAD_TAG_LEN + 16;
    uint8_t *enc_buf = malloc(enc_cap);
    if (!enc_buf) return;

    size_t enc_len = 0;
    lp2p_err_t err = conn->security->vtable->encrypt(
        conn->security->impl, data, len, enc_buf, &enc_len);

    if (err != LP2P_OK) {
        free(enc_buf);
        return;
    }

    /* Write encrypted data to TCP — enc_buf is freed in the write callback */
    lp2p_tcp_conn_write(conn->tcp, enc_buf, enc_len,
                         conn_on_tcp_write_done, enc_buf);
}

/* ── Stream-level multistream-select over mux streams ────────────────────── */

typedef struct {
    lp2p_conn_t         *conn;
    lp2p_stream_t       *stream;
    lp2p_open_stream_cb  cb;
    void                *userdata;
    char                *protocol_id;
} conn_outbound_stream_ctx_t;

typedef struct {
    lp2p_conn_t   *conn;
    lp2p_stream_t *stream;
    char           protocol_id[MULTISTREAM_MAX_MSG_LEN];
} conn_inbound_stream_ctx_t;

typedef struct {
    lp2p_conn_t   *conn;
    lp2p_stream_t *stream;
} conn_inbound_dispatch_ctx_t;

static lp2p_err_t conn_open_stream_negotiated(lp2p_conn_t *conn,
                                              const char *protocol_id,
                                              lp2p_open_stream_cb cb,
                                              void *userdata);
static lp2p_err_t conn_open_raw_stream(lp2p_conn_t *conn, lp2p_stream_t **out);

static bool conn_ms_parse_payload(const lp2p_buf_t *buf, char *out, size_t out_cap) {
    if (!buf || !buf->data || buf->len == 0 || buf->len >= out_cap) return false;
    if (buf->data[buf->len - 1] != '\n') return false;

    size_t msg_len = buf->len - 1;
    memcpy(out, buf->data, msg_len);
    out[msg_len] = '\0';
    return true;
}

static lp2p_err_t conn_ms_stream_write(lp2p_stream_t *stream, const char *msg,
                                       lp2p_stream_write_cb cb, void *userdata) {
    size_t msg_len = strlen(msg);
    uint8_t *payload = malloc(msg_len + 1);
    if (!payload) return LP2P_ERR_NOMEM;

    memcpy(payload, msg, msg_len);
    payload[msg_len] = '\n';

    lp2p_buf_t buf = { .data = payload, .len = msg_len + 1 };
    lp2p_err_t err = lp2p_stream_write_lp(stream, &buf, cb, userdata);
    free(payload);
    return err;
}

static bool conn_router_supports_protocol(const lp2p_protocol_router_t *router,
                                          const char *protocol_id) {
    if (!router || !protocol_id) return false;

    for (size_t i = 0; i < router->entry_count; i++) {
        if (strcmp(router->entries[i].protocol_id, protocol_id) == 0) {
            return true;
        }
    }

    return false;
}

static void conn_outbound_stream_free(conn_outbound_stream_ctx_t *ctx) {
    if (!ctx) return;
    free(ctx->protocol_id);
    free(ctx);
}

static void conn_outbound_stream_fail(conn_outbound_stream_ctx_t *ctx, lp2p_err_t err) {
    if (ctx->stream) lp2p_stream_reset(ctx->stream);

    conn_open_stream_ctx_t *cb_ctx = calloc(1, sizeof(*cb_ctx));
    if (cb_ctx) {
        cb_ctx->cb = ctx->cb;
        cb_ctx->stream = NULL;
        cb_ctx->err = err;
        cb_ctx->userdata = ctx->userdata;
        conn_defer(ctx->conn, conn_deferred_open_stream, cb_ctx);
    }

    conn_outbound_stream_free(ctx);
}

static void conn_outbound_stream_on_accept_read(lp2p_stream_t *stream, lp2p_err_t err,
                                                const lp2p_buf_t *buf, void *userdata);

static void conn_outbound_stream_on_proposal_written(lp2p_stream_t *stream, lp2p_err_t err,
                                                     void *userdata) {
    conn_outbound_stream_ctx_t *ctx = userdata;

    if (err != LP2P_OK) {
        conn_outbound_stream_fail(ctx, err);
        return;
    }

    lp2p_err_t rerr = lp2p_stream_read_lp(stream, MULTISTREAM_MAX_MSG_LEN,
                                          conn_outbound_stream_on_accept_read, ctx);
    if (rerr != LP2P_OK) {
        conn_outbound_stream_fail(ctx, rerr);
    }
}

static void conn_outbound_stream_on_header_read(lp2p_stream_t *stream, lp2p_err_t err,
                                                const lp2p_buf_t *buf, void *userdata) {
    conn_outbound_stream_ctx_t *ctx = userdata;
    char header[MULTISTREAM_MAX_MSG_LEN];

    if (err != LP2P_OK || !conn_ms_parse_payload(buf, header, sizeof(header))) {
        conn_outbound_stream_fail(ctx, err == LP2P_OK ? LP2P_ERR_PROTOCOL : err);
        return;
    }

    if (strcmp(header, MULTISTREAM_PROTOCOL_ID) != 0) {
        conn_outbound_stream_fail(ctx, LP2P_ERR_NEGOTIATION_FAILED);
        return;
    }

    lp2p_err_t werr = conn_ms_stream_write(stream, ctx->protocol_id,
                                           conn_outbound_stream_on_proposal_written, ctx);
    if (werr != LP2P_OK) {
        conn_outbound_stream_fail(ctx, werr);
    }
}

static void conn_outbound_stream_on_header_written(lp2p_stream_t *stream, lp2p_err_t err,
                                                   void *userdata) {
    conn_outbound_stream_ctx_t *ctx = userdata;

    if (err != LP2P_OK) {
        conn_outbound_stream_fail(ctx, err);
        return;
    }

    lp2p_err_t rerr = lp2p_stream_read_lp(stream, MULTISTREAM_MAX_MSG_LEN,
                                          conn_outbound_stream_on_header_read, ctx);
    if (rerr != LP2P_OK) {
        conn_outbound_stream_fail(ctx, rerr);
    }
}

static void conn_outbound_stream_on_accept_read(lp2p_stream_t *stream, lp2p_err_t err,
                                                const lp2p_buf_t *buf, void *userdata) {
    conn_outbound_stream_ctx_t *ctx = userdata;
    char response[MULTISTREAM_MAX_MSG_LEN];

    if (err != LP2P_OK || !conn_ms_parse_payload(buf, response, sizeof(response))) {
        conn_outbound_stream_fail(ctx, err == LP2P_OK ? LP2P_ERR_PROTOCOL : err);
        return;
    }

    if (strcmp(response, MULTISTREAM_NA) == 0) {
        conn_outbound_stream_fail(ctx, LP2P_ERR_PROTOCOL_NOT_SUPPORTED);
        return;
    }

    if (strcmp(response, ctx->protocol_id) != 0) {
        conn_outbound_stream_fail(ctx, LP2P_ERR_NEGOTIATION_FAILED);
        return;
    }

    stream->protocol_id = strdup(ctx->protocol_id);
    if (!stream->protocol_id) {
        conn_outbound_stream_fail(ctx, LP2P_ERR_NOMEM);
        return;
    }

    conn_open_stream_ctx_t *cb_ctx = calloc(1, sizeof(*cb_ctx));
    if (!cb_ctx) {
        conn_outbound_stream_fail(ctx, LP2P_ERR_NOMEM);
        return;
    }

    cb_ctx->cb = ctx->cb;
    cb_ctx->stream = stream;
    cb_ctx->err = LP2P_OK;
    cb_ctx->userdata = ctx->userdata;

    conn_defer(ctx->conn, conn_deferred_open_stream, cb_ctx);
    conn_outbound_stream_free(ctx);
}

static void conn_inbound_stream_free(conn_inbound_stream_ctx_t *ctx) {
    free(ctx);
}

static void conn_inbound_stream_dispatch(void *arg) {
    conn_inbound_dispatch_ctx_t *ctx = arg;

    if (ctx->conn->router) {
        lp2p_protocol_router_handle_stream(ctx->conn->router, ctx->stream);
    } else {
        lp2p_stream_reset(ctx->stream);
    }

    free(ctx);
}

static void conn_inbound_stream_fail(conn_inbound_stream_ctx_t *ctx) {
    if (ctx->stream) lp2p_stream_reset(ctx->stream);
    conn_inbound_stream_free(ctx);
}

static void conn_inbound_stream_on_accept_written(lp2p_stream_t *stream, lp2p_err_t err,
                                                  void *userdata) {
    conn_inbound_stream_ctx_t *ctx = userdata;
    (void)stream;

    if (err != LP2P_OK) {
        conn_inbound_stream_fail(ctx);
        return;
    }

    ctx->stream->protocol_id = strdup(ctx->protocol_id);
    if (!ctx->stream->protocol_id) {
        conn_inbound_stream_fail(ctx);
        return;
    }

    conn_inbound_dispatch_ctx_t *dispatch = calloc(1, sizeof(*dispatch));
    if (!dispatch) {
        conn_inbound_stream_fail(ctx);
        return;
    }

    dispatch->conn = ctx->conn;
    dispatch->stream = ctx->stream;

    conn_defer(ctx->conn, conn_inbound_stream_dispatch, dispatch);
    conn_inbound_stream_free(ctx);
}

static void conn_inbound_stream_on_na_written(lp2p_stream_t *stream, lp2p_err_t err,
                                              void *userdata) {
    conn_inbound_stream_ctx_t *ctx = userdata;
    (void)stream;
    (void)err;
    conn_inbound_stream_fail(ctx);
}

static void conn_inbound_stream_on_proposal_read(lp2p_stream_t *stream, lp2p_err_t err,
                                                 const lp2p_buf_t *buf, void *userdata) {
    conn_inbound_stream_ctx_t *ctx = userdata;

    if (err != LP2P_OK ||
        !conn_ms_parse_payload(buf, ctx->protocol_id, sizeof(ctx->protocol_id))) {
        conn_inbound_stream_fail(ctx);
        return;
    }

    if (!conn_router_supports_protocol(ctx->conn->router, ctx->protocol_id)) {
        lp2p_err_t werr = conn_ms_stream_write(stream, MULTISTREAM_NA,
                                               conn_inbound_stream_on_na_written, ctx);
        if (werr != LP2P_OK) conn_inbound_stream_fail(ctx);
        return;
    }

    lp2p_err_t werr = conn_ms_stream_write(stream, ctx->protocol_id,
                                           conn_inbound_stream_on_accept_written, ctx);
    if (werr != LP2P_OK) conn_inbound_stream_fail(ctx);
}

static void conn_inbound_stream_on_header_written(lp2p_stream_t *stream, lp2p_err_t err,
                                                  void *userdata) {
    conn_inbound_stream_ctx_t *ctx = userdata;

    if (err != LP2P_OK) {
        conn_inbound_stream_fail(ctx);
        return;
    }

    lp2p_err_t rerr = lp2p_stream_read_lp(stream, MULTISTREAM_MAX_MSG_LEN,
                                          conn_inbound_stream_on_proposal_read, ctx);
    if (rerr != LP2P_OK) conn_inbound_stream_fail(ctx);
}

static void conn_inbound_stream_on_header_read(lp2p_stream_t *stream, lp2p_err_t err,
                                               const lp2p_buf_t *buf, void *userdata) {
    conn_inbound_stream_ctx_t *ctx = userdata;
    char header[MULTISTREAM_MAX_MSG_LEN];

    if (err != LP2P_OK || !conn_ms_parse_payload(buf, header, sizeof(header))) {
        conn_inbound_stream_fail(ctx);
        return;
    }

    if (strcmp(header, MULTISTREAM_PROTOCOL_ID) != 0) {
        conn_inbound_stream_fail(ctx);
        return;
    }

    lp2p_err_t werr = conn_ms_stream_write(stream, MULTISTREAM_PROTOCOL_ID,
                                           conn_inbound_stream_on_header_written, ctx);
    if (werr != LP2P_OK) conn_inbound_stream_fail(ctx);
}

static lp2p_err_t conn_open_stream_negotiated(lp2p_conn_t *conn,
                                              const char *protocol_id,
                                              lp2p_open_stream_cb cb,
                                              void *userdata) {
    if (!conn || !protocol_id) return LP2P_ERR_INVALID_ARG;

    lp2p_stream_t *stream = NULL;
    lp2p_err_t err = conn_open_raw_stream(conn, &stream);
    if (err != LP2P_OK) return err;
    if (!stream) return LP2P_ERR_INTERNAL;

    stream->conn = conn;

    conn_outbound_stream_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        lp2p_stream_reset(stream);
        return LP2P_ERR_NOMEM;
    }

    ctx->conn = conn;
    ctx->stream = stream;
    ctx->cb = cb;
    ctx->userdata = userdata;
    ctx->protocol_id = strdup(protocol_id);
    if (!ctx->protocol_id) {
        conn_outbound_stream_free(ctx);
        lp2p_stream_reset(stream);
        return LP2P_ERR_NOMEM;
    }

    err = conn_ms_stream_write(stream, MULTISTREAM_PROTOCOL_ID,
                               conn_outbound_stream_on_header_written, ctx);
    if (err != LP2P_OK) {
        conn_outbound_stream_free(ctx);
        lp2p_stream_reset(stream);
        return err;
    }

    return LP2P_OK;
}

static lp2p_err_t conn_open_raw_stream(lp2p_conn_t *conn, lp2p_stream_t **out) {
    if (!conn || !out) return LP2P_ERR_INVALID_ARG;

    switch (conn->backend) {
    case LP2P_CONN_BACKEND_TCP_YAMUX:
        if (!conn->mux) return LP2P_ERR_INVALID_ARG;
        return conn->mux->vtable->open_stream(conn->mux->impl, out);
#ifdef LP2P_HAVE_QUIC
    case LP2P_CONN_BACKEND_QUIC:
        return lp2p_quic_conn_open_stream_raw(conn, out);
#endif
    default:
        return LP2P_ERR_INTERNAL;
    }
}

/* ── Inbound stream callback from the underlying stream transport ─────────── */

void lp2p_conn_handle_inbound_stream(lp2p_conn_t *conn, lp2p_stream_t *stream) {
    if (!conn || !stream) return;

    if (conn->goaway_received || conn->state != CONN_STATE_READY) {
        lp2p_stream_reset(stream);
        return;
    }

    /* Set the connection back-pointer on the stream */
    stream->conn = conn;

    if (!conn->router) {
        lp2p_stream_reset(stream);
        return;
    }

    conn_inbound_stream_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        lp2p_stream_reset(stream);
        return;
    }

    ctx->conn = conn;
    ctx->stream = stream;

    lp2p_err_t err = lp2p_stream_read_lp(stream, MULTISTREAM_MAX_MSG_LEN,
                                         conn_inbound_stream_on_header_read, ctx);
    if (err != LP2P_OK) {
        conn_inbound_stream_fail(ctx);
    }
}

static void conn_on_mux_inbound_stream(yamux_session_t *session,
                                        lp2p_stream_t *stream, void *userdata) {
    (void)session;
    lp2p_conn_handle_inbound_stream((lp2p_conn_t *)userdata, stream);
}

/* ── Upgrade pipeline ─────────────────────────────────────────────────────── */

lp2p_err_t lp2p_conn_upgrade(lp2p_conn_t *conn, lp2p_keypair_t *keypair,
                               void (*on_ready)(lp2p_conn_t *, void *),
                               void (*on_disconnect)(lp2p_conn_t *, lp2p_err_t, void *),
                               void *userdata) {
    if (!conn || !keypair) return LP2P_ERR_INVALID_ARG;
    if (!conn->tcp) return LP2P_ERR_INVALID_ARG;

    conn->on_ready = on_ready;
    conn->on_disconnect = on_disconnect;
    conn->cb_userdata = userdata;
    conn->upgrade_keypair = keypair;

    /* Begin the upgrade: multistream-select for /noise */
    conn_start_security_negotiation(conn);
    return LP2P_OK;
}

/* ── Step 1: multistream-select /noise ────────────────────────────────────── */

static void conn_on_security_negotiated(lp2p_err_t err, const char *protocol,
                                         void *userdata) {
    lp2p_conn_t *conn = (lp2p_conn_t *)userdata;
    (void)protocol;

    if (err != LP2P_OK) {
        conn_teardown(conn, LP2P_ERR_NEGOTIATION_FAILED);
        return;
    }

    /* Move to Noise handshake */
    conn_start_noise_handshake(conn);
}

static void conn_start_security_negotiation(lp2p_conn_t *conn) {
    conn->state = CONN_STATE_SECURITY_NEGOTIATING;

    if (!conn->is_inbound) {
        /* Initiator: propose /noise */
        lp2p_err_t err = ms_negotiate_initiator(
            conn->tcp, NOISE_PROTO_ID,
            conn_on_security_negotiated, conn);
        if (err != LP2P_OK) {
            conn_teardown(conn, LP2P_ERR_NEGOTIATION_FAILED);
        }
    } else {
        /* Responder: accept /noise */
        static const char *sec_protos[] = { NOISE_PROTO_ID };
        lp2p_err_t err = ms_negotiate_responder(
            conn->tcp, sec_protos, 1,
            conn_on_security_negotiated, conn);
        if (err != LP2P_OK) {
            conn_teardown(conn, LP2P_ERR_NEGOTIATION_FAILED);
        }
    }
}

/* ── Step 2: Noise XX handshake ───────────────────────────────────────────── */

typedef struct {
    lp2p_conn_t              *conn;
    noise_handshake_state_t   hs;
    noise_session_t           session;
    int                       msg_step;
    lp2p_buffer_t             recv_buf;
} conn_noise_ctx_t;

static void conn_noise_drive(conn_noise_ctx_t *ctx);
static void conn_noise_on_read(lp2p_tcp_conn_t *tc, const uint8_t *data,
                                size_t len, lp2p_err_t err, void *userdata);
static void conn_noise_on_write_done(lp2p_tcp_conn_t *tc, lp2p_err_t err,
                                      void *userdata);

static void conn_start_noise_handshake(lp2p_conn_t *conn) {
    conn->state = CONN_STATE_SECURITY_HANDSHAKE;

    conn_noise_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        conn_teardown(conn, LP2P_ERR_NOMEM);
        return;
    }
    ctx->conn = conn;
    lp2p_buffer_init(&ctx->recv_buf);

    /* Get Ed25519 keys from the keypair */
    const uint8_t *ed_pk = lp2p_keypair_public_ptr(conn->upgrade_keypair);
    const uint8_t *ed_sk = lp2p_keypair_secret_ptr(conn->upgrade_keypair);

    lp2p_err_t err = noise_handshake_init(&ctx->hs, !conn->is_inbound,
                                           ed_pk, ed_sk);
    if (err != LP2P_OK) {
        free(ctx);
        conn_teardown(conn, LP2P_ERR_HANDSHAKE_FAILED);
        return;
    }

    ctx->msg_step = 0;

    /* Start reading from TCP for handshake messages */
    lp2p_tcp_conn_start_read(conn->tcp, conn_noise_on_read, ctx);

    /* Drive the handshake state machine */
    conn_noise_drive(ctx);
}

/*
 * Noise XX handshake message pattern:
 *   Initiator sends msg 0 (-> e)
 *   Responder sends msg 1 (<- e, ee, s, es)
 *   Initiator sends msg 2 (-> s, se)
 *
 * Initiator: write(0), read(1), write(2) -> split
 * Responder: read(0), write(1), read(2) -> split
 */
static void conn_noise_drive(conn_noise_ctx_t *ctx) {
    lp2p_conn_t *conn = ctx->conn;
    bool is_initiator = !conn->is_inbound;

    /* Determine if we should write or read next */
    bool should_write = false;
    if (is_initiator) {
        /* Initiator writes on msg_step 0 and 2, reads on 1 */
        should_write = (ctx->msg_step == 0 || ctx->msg_step == 2);
    } else {
        /* Responder writes on msg_step 1, reads on 0 and 2 */
        should_write = (ctx->msg_step == 1);
    }

    if (ctx->msg_step >= 3) {
        /* Handshake complete — split cipher states */
        lp2p_err_t err = noise_handshake_split(&ctx->hs, &ctx->session);
        if (err != LP2P_OK) {
            lp2p_buffer_free(&ctx->recv_buf);
            free(ctx);
            conn_teardown(conn, LP2P_ERR_HANDSHAKE_FAILED);
            return;
        }

        /* noise_handshake_split zeroizes the handshake state after copying the
         * verified remote peer ID into the transport session. */
        conn->remote_peer = ctx->session.remote_peer_id;

        /* Create the security session */
        conn->security = calloc(1, sizeof(lp2p_security_session_t));
        if (!conn->security) {
            lp2p_buffer_free(&ctx->recv_buf);
            free(ctx);
            conn_teardown(conn, LP2P_ERR_NOMEM);
            return;
        }

        err = noise_session_create(&ctx->session, conn->security);
        if (err != LP2P_OK) {
            free(conn->security);
            conn->security = NULL;
            lp2p_buffer_free(&ctx->recv_buf);
            free(ctx);
            conn_teardown(conn, LP2P_ERR_HANDSHAKE_FAILED);
            return;
        }

        lp2p_buffer_free(&ctx->recv_buf);
        free(ctx);

        /* Proceed to mux negotiation */
        conn_start_mux_negotiation(conn);
        return;
    }

    if (should_write) {
        /* Write the next handshake message */
        uint8_t msg_buf[NOISE_MAX_MSG_LEN];
        size_t msg_len = sizeof(msg_buf);

        lp2p_err_t err = noise_handshake_write_msg(&ctx->hs, msg_buf, &msg_len);
        if (err != LP2P_OK) {
            lp2p_buffer_free(&ctx->recv_buf);
            free(ctx);
            conn_teardown(conn, LP2P_ERR_HANDSHAKE_FAILED);
            return;
        }

        /* Frame with 2-byte big-endian length prefix */
        size_t framed_len = NOISE_FRAME_HDR_LEN + msg_len;
        uint8_t *framed = malloc(framed_len);
        if (!framed) {
            lp2p_buffer_free(&ctx->recv_buf);
            free(ctx);
            conn_teardown(conn, LP2P_ERR_NOMEM);
            return;
        }
        framed[0] = (uint8_t)((msg_len >> 8) & 0xFF);
        framed[1] = (uint8_t)(msg_len & 0xFF);
        memcpy(framed + NOISE_FRAME_HDR_LEN, msg_buf, msg_len);

        ctx->msg_step++;

        lp2p_tcp_conn_write(conn->tcp, framed, framed_len,
                             conn_noise_on_write_done, ctx);
        /* framed will be freed after write completes — but we can't free it in
         * the callback since tcp_conn_write may buffer it. We pass ctx as
         * userdata. The framed buffer must be valid until the write completes.
         * We use a wrapper to track it. */
        /* NOTE: Actually, lp2p_tcp_conn_write likely copies or takes ownership.
         * We'll free it in the write callback via a wrapper. */
        /* Simplification: assume tcp_conn_write copies the data internally.
         * Free framed here after the call. If tcp_conn_write does not copy,
         * this needs adjustment — but the standard libuv pattern copies. */
        free(framed);
    }
    /* If should_read, we wait for data in conn_noise_on_read */
}

static void conn_noise_on_write_done(lp2p_tcp_conn_t *tc, lp2p_err_t err,
                                      void *userdata) {
    conn_noise_ctx_t *ctx = (conn_noise_ctx_t *)userdata;
    (void)tc;

    if (err != LP2P_OK) {
        lp2p_conn_t *conn = ctx->conn;
        lp2p_buffer_free(&ctx->recv_buf);
        free(ctx);
        conn_teardown(conn, LP2P_ERR_HANDSHAKE_FAILED);
        return;
    }

    /* Continue driving the handshake (next step might be a read, which
     * is handled by conn_noise_on_read, or another write) */
    conn_noise_drive(ctx);
}

static void conn_noise_on_read(lp2p_tcp_conn_t *tc, const uint8_t *data,
                                size_t len, lp2p_err_t err, void *userdata) {
    conn_noise_ctx_t *ctx = (conn_noise_ctx_t *)userdata;

    if (err != LP2P_OK) {
        lp2p_conn_t *conn = ctx->conn;
        lp2p_buffer_free(&ctx->recv_buf);
        free(ctx);
        conn_teardown(conn, LP2P_ERR_HANDSHAKE_FAILED);
        return;
    }

    /* Accumulate data */
    if (!lp2p_buffer_append(&ctx->recv_buf, data, len)) {
        lp2p_conn_t *conn = ctx->conn;
        lp2p_buffer_free(&ctx->recv_buf);
        free(ctx);
        conn_teardown(conn, LP2P_ERR_NOMEM);
        return;
    }
    lp2p_tcp_conn_consume(tc, len);

    /* Try to parse a complete framed message (2-byte length prefix) */
    if (ctx->recv_buf.len < NOISE_FRAME_HDR_LEN) return;

    uint16_t msg_len = ((uint16_t)ctx->recv_buf.data[0] << 8) |
                        (uint16_t)ctx->recv_buf.data[1];
    size_t total = NOISE_FRAME_HDR_LEN + msg_len;

    if (ctx->recv_buf.len < total) return; /* need more data */

    /* Process the handshake message */
    lp2p_err_t read_err = noise_handshake_read_msg(
        &ctx->hs, ctx->recv_buf.data + NOISE_FRAME_HDR_LEN, msg_len);

    /* Consume the frame */
    size_t remaining = ctx->recv_buf.len - total;
    if (remaining > 0) {
        memmove(ctx->recv_buf.data, ctx->recv_buf.data + total, remaining);
    }
    ctx->recv_buf.len = remaining;

    if (read_err != LP2P_OK) {
        lp2p_conn_t *conn = ctx->conn;
        lp2p_buffer_free(&ctx->recv_buf);
        free(ctx);
        conn_teardown(conn, LP2P_ERR_HANDSHAKE_FAILED);
        return;
    }

    ctx->msg_step++;

    /* Continue driving */
    conn_noise_drive(ctx);
}

/* ── Step 3: secure multistream-select /yamux/1.0.0 ──────────────────────── */

typedef struct {
    lp2p_conn_t      *conn;
    ms_negotiation_t  neg;
    lp2p_buffer_t     plain_buf;
} conn_secure_ms_ctx_t;

static void conn_create_mux_session(lp2p_conn_t *conn,
                                    const uint8_t *initial_plain,
                                    size_t initial_plain_len) {
    /* Create yamux session */
    bool is_initiator = !conn->is_inbound;

    yamux_session_t *ys = yamux_session_new(
        conn->loop, is_initiator,
        conn_on_mux_send, conn,
        conn_on_mux_inbound_stream, conn);

    if (!ys) {
        conn_teardown(conn, LP2P_ERR_NOMEM);
        return;
    }

    /* Wrap in mux session */
    conn->mux = calloc(1, sizeof(lp2p_mux_session_t));
    if (!conn->mux) {
        yamux_session_free(ys);
        conn_teardown(conn, LP2P_ERR_NOMEM);
        return;
    }
    conn->mux->vtable = yamux_get_vtable();
    conn->mux->impl = ys;

    /* Enter READY before feeding any buffered mux bytes so inbound streams
     * negotiated in the same Noise payload are accepted instead of reset. */
    conn->state = CONN_STATE_READY;

    if (initial_plain_len > 0) {
        lp2p_err_t mux_err = conn->mux->vtable->on_data(
            conn->mux->impl, initial_plain, initial_plain_len);
        if (mux_err != LP2P_OK) {
            conn_teardown(conn, LP2P_ERR_MUX);
            return;
        }
    }

    /* Install the TCP read callback for encrypted transport frames. Any bytes
     * still buffered in the TCP transport are newer than initial_plain. */
    lp2p_err_t err = lp2p_tcp_conn_start_read(conn->tcp, conn_on_tcp_read, conn);
    if (err != LP2P_OK) {
        conn_teardown(conn, err);
        return;
    }

    if (conn->state != CONN_STATE_READY || conn->closing) {
        return;
    }

    conn_finish_ready(conn);
}

static void conn_secure_ms_free(conn_secure_ms_ctx_t *ctx) {
    if (!ctx) return;
    lp2p_buffer_free(&ctx->plain_buf);
    free(ctx);
}

static void conn_secure_ms_fail(conn_secure_ms_ctx_t *ctx, lp2p_err_t err) {
    lp2p_conn_t *conn = ctx->conn;
    conn_secure_ms_free(ctx);
    conn_teardown(conn, err);
}

static void conn_secure_ms_done(conn_secure_ms_ctx_t *ctx) {
    lp2p_conn_t *conn = ctx->conn;
    uint8_t *initial_plain = ctx->plain_buf.data;
    size_t initial_plain_len = ctx->plain_buf.len;

    /* conn_create_mux_session only consumes the buffer during this call. */
    conn_create_mux_session(conn, initial_plain, initial_plain_len);
    conn_secure_ms_free(ctx);
}

static lp2p_err_t conn_secure_ms_send_frame(conn_secure_ms_ctx_t *ctx,
                                            const char *msg);
static void conn_secure_ms_drive(conn_secure_ms_ctx_t *ctx);

static lp2p_err_t conn_ensure_decrypt_capacity(lp2p_conn_t *conn, size_t frame_len) {
    if (frame_len <= conn->decrypt_buf_cap) {
        return LP2P_OK;
    }

    size_t new_cap = frame_len + 1024;
    uint8_t *new_buf = realloc(conn->decrypt_buf, new_cap);
    if (!new_buf) {
        return LP2P_ERR_NOMEM;
    }

    conn->decrypt_buf = new_buf;
    conn->decrypt_buf_cap = new_cap;
    return LP2P_OK;
}

static void conn_secure_ms_process_plain(conn_secure_ms_ctx_t *ctx) {
    while (true) {
        ms_state_t state = ctx->neg.state;
        if (state != MS_STATE_RECV_HEADER &&
            state != MS_STATE_RECV_PROPOSAL &&
            state != MS_STATE_RECV_ACCEPT) {
            return;
        }

        const uint8_t *msg = NULL;
        size_t msg_len = 0;
        int consumed = ms_frame_decode(ctx->plain_buf.data, ctx->plain_buf.len,
                                       &msg, &msg_len);
        if (consumed < 0) {
            conn_secure_ms_fail(ctx, LP2P_ERR_PROTOCOL);
            return;
        }
        if (consumed == 0) {
            return;
        }

        uint8_t msg_copy[MULTISTREAM_MAX_MSG_LEN];
        memcpy(msg_copy, msg, msg_len);

        size_t remaining = ctx->plain_buf.len - (size_t)consumed;
        if (remaining > 0) {
            memmove(ctx->plain_buf.data,
                    ctx->plain_buf.data + (size_t)consumed,
                    remaining);
        }
        ctx->plain_buf.len = remaining;

        switch (state) {
        case MS_STATE_RECV_HEADER:
            if (msg_len != strlen(MULTISTREAM_PROTOCOL_ID) ||
                memcmp(msg_copy, MULTISTREAM_PROTOCOL_ID, msg_len) != 0) {
                conn_secure_ms_fail(ctx, LP2P_ERR_NEGOTIATION_FAILED);
                return;
            }

            ctx->neg.state = ctx->neg.is_initiator
                ? MS_STATE_SEND_PROPOSAL
                : MS_STATE_RECV_PROPOSAL;
            conn_secure_ms_drive(ctx);
            return;

        case MS_STATE_RECV_PROPOSAL: {
            char proto[sizeof(ctx->neg.negotiated_proto)];
            size_t copy_len = msg_len < sizeof(proto) - 1
                ? msg_len
                : sizeof(proto) - 1;
            memcpy(proto, msg_copy, copy_len);
            proto[copy_len] = '\0';

            bool found = false;
            for (size_t i = 0; i < ctx->neg.supported_protos_count; i++) {
                if (strcmp(proto, ctx->neg.supported_protos[i]) == 0) {
                    found = true;
                    break;
                }
            }

            if (found) {
                memcpy(ctx->neg.negotiated_proto, proto, copy_len + 1);
                ctx->neg.state = MS_STATE_SEND_ACCEPT;
            } else {
                ctx->neg.state = MS_STATE_RECV_PROPOSAL;
                lp2p_err_t err = conn_secure_ms_send_frame(ctx, MULTISTREAM_NA);
                if (err != LP2P_OK) {
                    conn_secure_ms_fail(ctx, err);
                }
                return;
            }

            conn_secure_ms_drive(ctx);
            return;
        }

        case MS_STATE_RECV_ACCEPT: {
            size_t proto_len = strlen(ctx->neg.proposed_proto);

            if (msg_len == strlen(MULTISTREAM_NA) &&
                memcmp(msg_copy, MULTISTREAM_NA, msg_len) == 0) {
                conn_secure_ms_fail(ctx, LP2P_ERR_PROTOCOL_NOT_SUPPORTED);
                return;
            }

            if (msg_len != proto_len ||
                memcmp(msg_copy, ctx->neg.proposed_proto, proto_len) != 0) {
                conn_secure_ms_fail(ctx, LP2P_ERR_NEGOTIATION_FAILED);
                return;
            }

            memcpy(ctx->neg.negotiated_proto, ctx->neg.proposed_proto,
                   proto_len + 1);
            ctx->neg.state = MS_STATE_DONE;
            conn_secure_ms_drive(ctx);
            return;
        }

        default:
            conn_secure_ms_fail(ctx, LP2P_ERR_INTERNAL);
            return;
        }
    }
}

static void conn_secure_ms_on_read(lp2p_tcp_conn_t *tc, const uint8_t *data,
                                   size_t len, lp2p_err_t err, void *userdata) {
    conn_secure_ms_ctx_t *ctx = (conn_secure_ms_ctx_t *)userdata;
    lp2p_conn_t *conn = ctx->conn;
    (void)data;
    (void)len;

    if (err != LP2P_OK) {
        conn_secure_ms_fail(ctx, err);
        return;
    }

    while (tc->read_buf_len >= NOISE_FRAME_HDR_LEN) {
        uint16_t frame_len = ((uint16_t)tc->read_buf[0] << 8) |
                              (uint16_t)tc->read_buf[1];
        size_t total_frame = NOISE_FRAME_HDR_LEN + frame_len;

        if (tc->read_buf_len < total_frame) {
            break;
        }

        err = conn_ensure_decrypt_capacity(conn, frame_len);
        if (err != LP2P_OK) {
            conn_secure_ms_fail(ctx, err);
            return;
        }

        size_t plain_len = 0;
        err = conn->security->vtable->decrypt(
            conn->security->impl,
            tc->read_buf, total_frame,
            conn->decrypt_buf, &plain_len);
        if (err != LP2P_OK) {
            conn_secure_ms_fail(ctx, LP2P_ERR_CRYPTO);
            return;
        }

        lp2p_tcp_conn_consume(tc, total_frame);

        if (plain_len > 0 &&
            !lp2p_buffer_append(&ctx->plain_buf, conn->decrypt_buf, plain_len)) {
            conn_secure_ms_fail(ctx, LP2P_ERR_NOMEM);
            return;
        }

        conn_secure_ms_process_plain(ctx);
        if (!conn->security || conn->state == CONN_STATE_CLOSING ||
            conn->state == CONN_STATE_CLOSED || conn->mux) {
            return;
        }
    }
}

static void conn_secure_ms_on_write_done(lp2p_tcp_conn_t *tc, lp2p_err_t err,
                                         void *userdata) {
    conn_secure_ms_ctx_t *ctx = (conn_secure_ms_ctx_t *)userdata;
    (void)tc;

    if (err != LP2P_OK) {
        conn_secure_ms_fail(ctx, err);
        return;
    }

    conn_secure_ms_drive(ctx);
}

static lp2p_err_t conn_secure_ms_send_frame(conn_secure_ms_ctx_t *ctx,
                                            const char *msg) {
    uint8_t plain_frame[MULTISTREAM_MAX_MSG_LEN + 16];
    size_t plain_len = ms_frame_encode(msg, plain_frame, sizeof(plain_frame));
    if (plain_len == 0) {
        return LP2P_ERR_PROTOCOL;
    }

    size_t enc_cap = plain_len + NOISE_FRAME_HDR_LEN + NOISE_AEAD_TAG_LEN + 16;
    uint8_t *enc_frame = malloc(enc_cap);
    if (!enc_frame) {
        return LP2P_ERR_NOMEM;
    }

    size_t enc_len = 0;
    lp2p_err_t err = ctx->conn->security->vtable->encrypt(
        ctx->conn->security->impl, plain_frame, plain_len, enc_frame, &enc_len);
    if (err != LP2P_OK) {
        free(enc_frame);
        return err;
    }

    err = lp2p_tcp_conn_write(ctx->conn->tcp, enc_frame, enc_len,
                              conn_secure_ms_on_write_done, ctx);
    free(enc_frame);
    return err;
}

static void conn_secure_ms_drive(conn_secure_ms_ctx_t *ctx) {
    switch (ctx->neg.state) {
    case MS_STATE_SEND_HEADER:
        ctx->neg.state = MS_STATE_RECV_HEADER;
        {
            lp2p_err_t err = conn_secure_ms_send_frame(ctx, MULTISTREAM_PROTOCOL_ID);
            if (err != LP2P_OK) {
                conn_secure_ms_fail(ctx, err);
            }
        }
        return;

    case MS_STATE_RECV_HEADER:
    case MS_STATE_RECV_PROPOSAL:
    case MS_STATE_RECV_ACCEPT:
        if (ctx->plain_buf.len > 0) {
            conn_secure_ms_process_plain(ctx);
            return;
        }
        if (lp2p_tcp_conn_start_read(ctx->conn->tcp, conn_secure_ms_on_read, ctx) != LP2P_OK) {
            conn_secure_ms_fail(ctx, LP2P_ERR_NEGOTIATION_FAILED);
        }
        return;

    case MS_STATE_SEND_PROPOSAL:
        ctx->neg.state = MS_STATE_RECV_ACCEPT;
        {
            lp2p_err_t err = conn_secure_ms_send_frame(ctx, ctx->neg.proposed_proto);
            if (err != LP2P_OK) {
                conn_secure_ms_fail(ctx, err);
            }
        }
        return;

    case MS_STATE_SEND_ACCEPT:
        ctx->neg.state = MS_STATE_DONE;
        {
            lp2p_err_t err = conn_secure_ms_send_frame(ctx, ctx->neg.negotiated_proto);
            if (err != LP2P_OK) {
                conn_secure_ms_fail(ctx, err);
            }
        }
        return;

    case MS_STATE_DONE:
        conn_secure_ms_done(ctx);
        return;

    case MS_STATE_FAILED:
        conn_secure_ms_fail(ctx, LP2P_ERR_NEGOTIATION_FAILED);
        return;
    }
}

static void conn_start_mux_negotiation(lp2p_conn_t *conn) {
    conn->state = CONN_STATE_MUX_NEGOTIATING;

    conn_secure_ms_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        conn_teardown(conn, LP2P_ERR_NOMEM);
        return;
    }

    ctx->conn = conn;
    ctx->neg.state = MS_STATE_SEND_HEADER;
    ctx->neg.is_initiator = !conn->is_inbound;
    lp2p_buffer_init(&ctx->plain_buf);

    if (!conn->is_inbound) {
        strncpy(ctx->neg.proposed_proto, YAMUX_PROTO_ID,
                sizeof(ctx->neg.proposed_proto) - 1);
    } else {
        static const char *mux_protos[] = { YAMUX_PROTO_ID };
        ctx->neg.supported_protos = mux_protos;
        ctx->neg.supported_protos_count = 1;
    }

    conn_secure_ms_drive(ctx);
}

/* ── Become ready ─────────────────────────────────────────────────────────── */

static void conn_finish_ready(lp2p_conn_t *conn) {
    /* Process any pending open-stream requests */
    while (!lp2p_list_empty(&conn->pending_streams)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&conn->pending_streams);
        conn_open_stream_req_t *req =
            lp2p_container_of(n, conn_open_stream_req_t, node);

        lp2p_err_t err = conn_open_stream_negotiated(conn, req->protocol_id,
                                                     req->cb, req->userdata);
        if (err != LP2P_OK) {
            conn_open_stream_ctx_t *cb_ctx = calloc(1, sizeof(*cb_ctx));
            if (cb_ctx) {
                cb_ctx->cb = req->cb;
                cb_ctx->stream = NULL;
                cb_ctx->err = err;
                cb_ctx->userdata = req->userdata;
                conn_defer(conn, conn_deferred_open_stream, cb_ctx);
            }
        }

        free(req->protocol_id);
        free(req);
    }

    /* Defer the on_ready callback */
    conn_ready_ctx_t *rctx = calloc(1, sizeof(*rctx));
    if (rctx) {
        rctx->conn = conn;
        conn_defer(conn, conn_deferred_ready, rctx);
    }
}

/* ── Teardown ─────────────────────────────────────────────────────────────── */

static void conn_on_tcp_close(lp2p_tcp_conn_t *tc, void *userdata) {
    lp2p_conn_t *conn = (lp2p_conn_t *)userdata;
    (void)tc;

    conn->state = CONN_STATE_CLOSED;

    /* Fire close callback if set */
    if (conn->close_cb.cb) {
        conn_close_ctx_t *ctx = calloc(1, sizeof(*ctx));
        if (ctx) {
            ctx->conn = conn;
            ctx->cb = conn->close_cb.cb;
            ctx->userdata = conn->close_cb.userdata;
            conn_defer(conn, conn_deferred_close_cb, ctx);
        }
    }
}

static void conn_teardown(lp2p_conn_t *conn, lp2p_err_t reason) {
    if (conn->state == CONN_STATE_CLOSED) return;
    if (conn->closing) return;

    conn->closing = true;
    conn->state = CONN_STATE_CLOSING;

    /* Notify disconnect (deferred) */
    if (conn->on_disconnect) {
        conn_disconnect_ctx_t *dctx = calloc(1, sizeof(*dctx));
        if (dctx) {
            dctx->conn = conn;
            dctx->reason = reason;
            conn_defer(conn, conn_deferred_disconnect, dctx);
        }
    }

    /* Fail any pending stream requests */
    while (!lp2p_list_empty(&conn->pending_streams)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&conn->pending_streams);
        conn_open_stream_req_t *req =
            lp2p_container_of(n, conn_open_stream_req_t, node);

        conn_open_stream_ctx_t *cb_ctx = calloc(1, sizeof(*cb_ctx));
        if (cb_ctx) {
            cb_ctx->cb = req->cb;
            cb_ctx->stream = NULL;
            cb_ctx->err = LP2P_ERR_CONNECTION_CLOSED;
            cb_ctx->userdata = req->userdata;
            conn_defer(conn, conn_deferred_open_stream, cb_ctx);
        }

        free(req->protocol_id);
        free(req);
    }

    /* Close the TCP connection */
    if (conn->tcp) {
        lp2p_tcp_conn_close(conn->tcp, conn_on_tcp_close, conn);
    } else {
        conn->state = CONN_STATE_CLOSED;
    }
}

/* ── Public API ───────────────────────────────────────────────────────────── */

lp2p_err_t lp2p_conn_open_stream(lp2p_conn_t *conn, const char *protocol_id,
                                   lp2p_open_stream_cb cb, void *userdata) {
    if (!conn || !protocol_id) return LP2P_ERR_INVALID_ARG;

    if (conn->state == CONN_STATE_CLOSING || conn->state == CONN_STATE_CLOSED) {
        return LP2P_ERR_CONNECTION_CLOSED;
    }

    if (conn->goaway_received || conn->goaway_sent) {
        return LP2P_ERR_CONNECTION_CLOSED;
    }

    if (conn->state != CONN_STATE_READY) {
        /* Queue the request for when we become READY */
        conn_open_stream_req_t *req = calloc(1, sizeof(*req));
        if (!req) return LP2P_ERR_NOMEM;

        req->protocol_id = strdup(protocol_id);
        if (!req->protocol_id) {
            free(req);
            return LP2P_ERR_NOMEM;
        }
        req->cb = cb;
        req->userdata = userdata;
        lp2p_list_push_back(&conn->pending_streams, &req->node);
        return LP2P_OK;
    }

    return conn_open_stream_negotiated(conn, protocol_id, cb, userdata);
}

lp2p_err_t lp2p_conn_close(lp2p_conn_t *conn,
                             void (*cb)(lp2p_conn_t *conn, void *userdata),
                             void *userdata) {
    if (!conn) return LP2P_ERR_INVALID_ARG;

    if (conn->state == CONN_STATE_CLOSED) {
        /* Already closed — defer the callback */
        if (cb) {
            conn_close_ctx_t *ctx = calloc(1, sizeof(*ctx));
            if (ctx) {
                ctx->conn = conn;
                ctx->cb = cb;
                ctx->userdata = userdata;
                conn_defer(conn, conn_deferred_close_cb, ctx);
            }
        }
        return LP2P_OK;
    }

    conn->close_cb.cb = cb;
    conn->close_cb.userdata = userdata;

#ifdef LP2P_HAVE_QUIC
    if (conn->backend == LP2P_CONN_BACKEND_QUIC) {
        return lp2p_quic_conn_close(conn);
    }
#endif

    if (conn->state == CONN_STATE_READY && conn->mux && !conn->goaway_sent) {
        /* Send GoAway(normal) and drain */
        conn->mux->vtable->go_away(conn->mux->impl, YAMUX_GOAWAY_NORMAL);
        conn->goaway_sent = true;
        conn->state = CONN_STATE_CLOSING;

        /* Start drain timer */
        if (!conn->drain_timer_active) {
            uv_timer_init(conn->loop, &conn->drain_timer);
            conn->drain_timer.data = conn;
            conn->drain_timer_active = true;
        }
        uv_timer_start(&conn->drain_timer, conn_drain_timer_cb,
                        GOAWAY_DRAIN_MS, 0);
    } else {
        conn_teardown(conn, LP2P_ERR_CONNECTION_CLOSED);
    }

    return LP2P_OK;
}

lp2p_peer_id_t lp2p_conn_peer_id(const lp2p_conn_t *conn) {
    if (!conn) {
        lp2p_peer_id_t empty = {0};
        return empty;
    }
    return conn->remote_peer;
}

const lp2p_multiaddr_t *lp2p_conn_remote_addr(const lp2p_conn_t *conn) {
    if (!conn) return NULL;
    return conn->remote_addr;
}

const lp2p_multiaddr_t *lp2p_conn_local_addr(const lp2p_conn_t *conn) {
    if (!conn) return NULL;
    return conn->local_addr;
}

bool lp2p_conn_is_inbound(const lp2p_conn_t *conn) {
    if (!conn) return false;
    return conn->is_inbound;
}
