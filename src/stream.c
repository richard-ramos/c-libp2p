/* src/stream.c — public stream API implementation
 *
 * The public lp2p_stream_* API delegates to the underlying mux session
 * (yamux) via the mux vtable. Read operations are handled by the mux
 * layer directly (yamux stores read state in its per-stream struct).
 *
 * For yamux, the lp2p_stream_t is embedded as the first field of
 * yamux_stream_t, so casting between them is safe.
 */

#include <stdlib.h>
#include <string.h>

#include "libp2p/stream.h"
#include "connection_internal.h"
#include "stream_internal.h"
#include "mux/yamux/yamux_internal.h"
#include "encoding/varint.h"
#ifdef LP2P_HAVE_QUIC
#include "transport/quic/quic_transport.h"
#endif

/* ── EOF deferred callbacks ──────────────────────────────────────────────── */
typedef struct {
    lp2p_stream_read_cb  cb;
    lp2p_stream_t       *stream;
    void                *ud;
} eof_ctx_t;

static void deliver_eof_deferred(void *arg) {
    eof_ctx_t *c = (eof_ctx_t *)arg;
    c->cb(c->stream, LP2P_ERR_EOF, NULL, c->ud);
    free(c);
}

static lp2p_err_t vtable_write_stream_direct(yamux_stream_t *ys,
                                              const uint8_t *data, size_t len,
                                              lp2p_stream_write_cb cb,
                                              void *userdata);

/* ── Read ─────────────────────────────────────────────────────────────────── */

lp2p_err_t lp2p_stream_read(lp2p_stream_t *stream, size_t max_bytes,
                              lp2p_stream_read_cb cb, void *userdata)
{
    if (!stream || !cb) return LP2P_ERR_INVALID_ARG;

#ifdef LP2P_HAVE_QUIC
    if (stream->conn && stream->conn->backend == LP2P_CONN_BACKEND_QUIC) {
        return lp2p_quic_stream_read(stream, max_bytes, cb, userdata);
    }
#endif

    /* The stream is actually a yamux_stream_t (pub field is first member) */
    yamux_stream_t *ys = (yamux_stream_t *)stream;

    if (ys->state == YAMUX_STREAM_RESET) return LP2P_ERR_STREAM_RESET;
    if (ys->read_pending) return LP2P_ERR_BUSY;

    /* Check if stream read-side is done */
    if ((ys->state == YAMUX_STREAM_REMOTE_CLOSE ||
         ys->state == YAMUX_STREAM_CLOSED) && ys->recv_buf.len == 0) {
        eof_ctx_t *ctx = malloc(sizeof(*ctx));
        if (!ctx) return LP2P_ERR_NOMEM;
        ctx->cb     = cb;
        ctx->stream = stream;
        ctx->ud     = userdata;
        yamux_defer(ys->session, deliver_eof_deferred, ctx);
        return LP2P_OK;
    }

    ys->read_pending = true;
    ys->read_lp      = false;
    ys->read_max     = max_bytes;
    ys->read_cb      = cb;
    ys->read_ud      = userdata;

    /* Try to satisfy immediately from recv buffer */
    yamux_stream_deliver_data(ys);

    return LP2P_OK;
}

lp2p_err_t lp2p_stream_read_lp(lp2p_stream_t *stream, size_t max_frame_len,
                                 lp2p_stream_read_cb cb, void *userdata)
{
    if (!stream || !cb) return LP2P_ERR_INVALID_ARG;

#ifdef LP2P_HAVE_QUIC
    if (stream->conn && stream->conn->backend == LP2P_CONN_BACKEND_QUIC) {
        return lp2p_quic_stream_read_lp(stream, max_frame_len, cb, userdata);
    }
#endif

    yamux_stream_t *ys = (yamux_stream_t *)stream;

    if (ys->state == YAMUX_STREAM_RESET) return LP2P_ERR_STREAM_RESET;
    if (ys->read_pending) return LP2P_ERR_BUSY;

    if ((ys->state == YAMUX_STREAM_REMOTE_CLOSE ||
         ys->state == YAMUX_STREAM_CLOSED) && ys->recv_buf.len == 0) {
        eof_ctx_t *ctx = malloc(sizeof(*ctx));
        if (!ctx) return LP2P_ERR_NOMEM;
        ctx->cb     = cb;
        ctx->stream = stream;
        ctx->ud     = userdata;
        yamux_defer(ys->session, deliver_eof_deferred, ctx);
        return LP2P_OK;
    }

    ys->read_pending = true;
    ys->read_lp      = true;
    ys->read_max     = max_frame_len;
    ys->read_cb      = cb;
    ys->read_ud      = userdata;

    yamux_stream_deliver_data(ys);

    return LP2P_OK;
}

/* ── Write ────────────────────────────────────────────────────────────────── */

lp2p_err_t lp2p_stream_write(lp2p_stream_t *stream, const lp2p_buf_t *buf,
                               lp2p_stream_write_cb cb, void *userdata)
{
    if (!stream || !buf || !buf->data) return LP2P_ERR_INVALID_ARG;

#ifdef LP2P_HAVE_QUIC
    if (stream->conn && stream->conn->backend == LP2P_CONN_BACKEND_QUIC) {
        return lp2p_quic_stream_write(stream, buf, cb, userdata);
    }
#endif

    yamux_stream_t *ys = (yamux_stream_t *)stream;
    if (!ys->session || !ys->session->on_send) return LP2P_ERR_INTERNAL;

    return ys->session->on_send ?
        vtable_write_stream_direct(ys, buf->data, buf->len, cb, userdata) :
        LP2P_ERR_INTERNAL;
}

/* Direct write that goes through yamux framing */
static lp2p_err_t vtable_write_stream_direct(yamux_stream_t *ys,
                                              const uint8_t *data, size_t len,
                                              lp2p_stream_write_cb cb,
                                              void *userdata)
{
    if (ys->state == YAMUX_STREAM_LOCAL_CLOSE ||
        ys->state == YAMUX_STREAM_CLOSED ||
        ys->state == YAMUX_STREAM_RESET) {
        return LP2P_ERR_STREAM_RESET;
    }

    if (ys->write_buf_bytes + len > ys->max_write_buf) {
        return LP2P_ERR_WOULD_BLOCK;
    }

    yamux_write_req_t *wr = calloc(1, sizeof(*wr));
    if (!wr) return LP2P_ERR_NOMEM;
    wr->data = malloc(len);
    if (!wr->data) { free(wr); return LP2P_ERR_NOMEM; }
    memcpy(wr->data, data, len);
    wr->len      = len;
    wr->cb       = cb;
    wr->userdata = userdata;
    wr->stream   = &ys->pub;

    lp2p_list_push_back(&ys->write_queue, &wr->node);
    ys->write_buf_bytes += len;

    yamux_stream_flush_writes(ys);
    return LP2P_OK;
}

lp2p_err_t lp2p_stream_write_lp(lp2p_stream_t *stream, const lp2p_buf_t *buf,
                                  lp2p_stream_write_cb cb, void *userdata)
{
    if (!stream || !buf || !buf->data) return LP2P_ERR_INVALID_ARG;

    /* Build length-prefixed frame: varint(len) + data */
    uint8_t varint_buf[10];
    size_t varint_len = lp2p_varint_encode(buf->len, varint_buf);
    size_t total_len = varint_len + buf->len;

    uint8_t *framed = malloc(total_len);
    if (!framed) return LP2P_ERR_NOMEM;
    memcpy(framed, varint_buf, varint_len);
    memcpy(framed + varint_len, buf->data, buf->len);

    lp2p_buf_t lp_buf = { .data = framed, .len = total_len };
    lp2p_err_t err = lp2p_stream_write(stream, &lp_buf, cb, userdata);
    free(framed);
    return err;
}

/* ── Lifecycle ────────────────────────────────────────────────────────────── */

lp2p_err_t lp2p_stream_close(lp2p_stream_t *stream, lp2p_stream_write_cb cb,
                               void *userdata)
{
    if (!stream) return LP2P_ERR_INVALID_ARG;

#ifdef LP2P_HAVE_QUIC
    if (stream->conn && stream->conn->backend == LP2P_CONN_BACKEND_QUIC) {
        return lp2p_quic_stream_close(stream, cb, userdata);
    }
#endif

    yamux_stream_t *ys = (yamux_stream_t *)stream;

    ys->close_cb = cb;
    ys->close_ud = userdata;

    /* Delegate to mux vtable close */
    const lp2p_mux_vtable_t *vt = yamux_get_vtable();
    return vt->close_stream(ys->session, stream);
}

lp2p_err_t lp2p_stream_reset(lp2p_stream_t *stream)
{
    if (!stream) return LP2P_ERR_INVALID_ARG;

#ifdef LP2P_HAVE_QUIC
    if (stream->conn && stream->conn->backend == LP2P_CONN_BACKEND_QUIC) {
        return lp2p_quic_stream_reset(stream);
    }
#endif

    yamux_stream_t *ys = (yamux_stream_t *)stream;

    const lp2p_mux_vtable_t *vt = yamux_get_vtable();
    return vt->reset_stream(ys->session, stream);
}

/* ── Introspection ────────────────────────────────────────────────────────── */

const char *lp2p_stream_protocol(const lp2p_stream_t *stream)
{
    if (!stream) return NULL;
    return stream->protocol_id;
}

void lp2p_stream_set_userdata(lp2p_stream_t *stream, void *data)
{
    if (!stream) return;
    stream->userdata = data;
}

void *lp2p_stream_get_userdata(const lp2p_stream_t *stream)
{
    if (!stream) return NULL;
    return stream->userdata;
}

lp2p_conn_t *lp2p_stream_connection(const lp2p_stream_t *stream)
{
    if (!stream) return NULL;
    return stream->conn;
}
