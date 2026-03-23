/* src/mux/yamux/yamux.c — Yamux multiplexer implementation
 *
 * Implements the Yamux stream multiplexing protocol over a single
 * transport connection. Wire format: 12-byte big-endian headers.
 */

#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

#include "mux/yamux/yamux_internal.h"
#include "encoding/varint.h"

/* ── Header encode/decode ─────────────────────────────────────────────────── */

void yamux_header_encode(const yamux_header_t *h, uint8_t buf[YAMUX_HEADER_SIZE])
{
    buf[0] = h->version;
    buf[1] = h->type;
    buf[2] = (uint8_t)(h->flags >> 8);
    buf[3] = (uint8_t)(h->flags & 0xFF);
    uint32_t sid = htonl(h->stream_id);
    memcpy(&buf[4], &sid, 4);
    uint32_t len = htonl(h->length);
    memcpy(&buf[8], &len, 4);
}

bool yamux_header_decode(const uint8_t buf[YAMUX_HEADER_SIZE], yamux_header_t *h)
{
    h->version = buf[0];
    h->type    = buf[1];
    h->flags   = ((uint16_t)buf[2] << 8) | buf[3];
    uint32_t sid, len;
    memcpy(&sid, &buf[4], 4);
    memcpy(&len, &buf[8], 4);
    h->stream_id = ntohl(sid);
    h->length    = ntohl(len);
    return (h->version == YAMUX_VERSION);
}

/* ── Deferred callback mechanism ──────────────────────────────────────────── */

static void yamux_async_cb(uv_async_t *handle)
{
    yamux_session_t *s = (yamux_session_t *)handle->data;
    /* Process all deferred callbacks */
    while (!lp2p_list_empty(&s->deferred_cbs)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&s->deferred_cbs);
        yamux_deferred_t *d = lp2p_container_of(n, yamux_deferred_t, node);
        d->fn(d->arg);
        free(d);
    }
}

void yamux_defer(yamux_session_t *session, yamux_deferred_fn fn, void *arg)
{
    yamux_deferred_t *d = calloc(1, sizeof(*d));
    if (!d) return;
    d->fn  = fn;
    d->arg = arg;
    lp2p_list_push_back(&session->deferred_cbs, &d->node);
    uv_async_send(&session->async_handle);
}

/* ── Frame sending ────────────────────────────────────────────────────────── */

void yamux_send_frame(yamux_session_t *session, uint8_t type, uint16_t flags,
                      uint32_t stream_id, uint32_t length,
                      const uint8_t *payload, size_t payload_len,
                      yamux_write_req_t *req)
{
    size_t total = YAMUX_HEADER_SIZE + payload_len;
    yamux_out_frame_t *f = calloc(1, sizeof(*f));
    if (!f) return;
    f->data = malloc(total);
    if (!f->data) { free(f); return; }
    f->len = total;
    f->write_req = req;

    yamux_header_t h = {
        .version   = YAMUX_VERSION,
        .type      = type,
        .flags     = flags,
        .stream_id = stream_id,
        .length    = length,
    };
    yamux_header_encode(&h, f->data);
    if (payload && payload_len > 0) {
        memcpy(f->data + YAMUX_HEADER_SIZE, payload, payload_len);
    }

    lp2p_list_push_back(&session->out_queue, &f->node);
    yamux_flush_out_queue(session);
}

void yamux_flush_out_queue(yamux_session_t *session)
{
    while (!lp2p_list_empty(&session->out_queue)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&session->out_queue);
        yamux_out_frame_t *f = lp2p_container_of(n, yamux_out_frame_t, node);

        if (session->on_send) {
            session->on_send(f->data, f->len, session->on_send_ud);
        }

        /* If this frame carried data for a write request, complete the req */
        if (f->write_req) {
            yamux_write_req_t *wr = f->write_req;
            if (wr->cb) {
                /* Defer the callback to next event-loop turn */
                typedef struct {
                    lp2p_stream_write_cb cb;
                    lp2p_stream_t       *stream;
                    void                *ud;
                } wr_cb_ctx_t;
                wr_cb_ctx_t *ctx = malloc(sizeof(*ctx));
                if (ctx) {
                    ctx->cb     = wr->cb;
                    ctx->stream = wr->stream;
                    ctx->ud     = wr->userdata;
                    /* We'll invoke inline for simplicity in the sync path.
                       In a real async impl this would be deferred. */
                }
                /* Invoke immediately but after frame is sent */
                wr->cb(wr->stream, LP2P_OK, wr->userdata);
            }
            free(wr->data);
            free(wr);
        }

        free(f->data);
        free(f);
    }
}

/* ── Stream lookup ────────────────────────────────────────────────────────── */

yamux_stream_t *yamux_stream_lookup(yamux_session_t *session, uint32_t id)
{
    for (size_t i = 0; i < YAMUX_MAX_STREAMS; i++) {
        if (session->streams[i] && session->streams[i]->id == id) {
            return session->streams[i];
        }
    }
    return NULL;
}

static int yamux_stream_add(yamux_session_t *session, yamux_stream_t *ys)
{
    for (size_t i = 0; i < YAMUX_MAX_STREAMS; i++) {
        if (!session->streams[i]) {
            session->streams[i] = ys;
            session->stream_count++;
            lp2p_list_push_back(&session->stream_list, &ys->node);
            return 0;
        }
    }
    return -1;
}

static void yamux_stream_remove(yamux_session_t *session, yamux_stream_t *ys)
{
    for (size_t i = 0; i < YAMUX_MAX_STREAMS; i++) {
        if (session->streams[i] == ys) {
            session->streams[i] = NULL;
            session->stream_count--;
            lp2p_list_remove(&session->stream_list, &ys->node);
            return;
        }
    }
}

/* ── Stream creation ──────────────────────────────────────────────────────── */

static yamux_stream_t *yamux_stream_new(yamux_session_t *session, uint32_t id)
{
    yamux_stream_t *ys = calloc(1, sizeof(*ys));
    if (!ys) return NULL;

    ys->session     = session;
    ys->id          = id;
    ys->state       = YAMUX_STREAM_INIT;
    ys->recv_window = YAMUX_DEFAULT_WINDOW;
    ys->send_window = YAMUX_DEFAULT_WINDOW;
    ys->max_write_buf = 1024 * 1024;  /* 1 MiB default max write buffer */

    lp2p_buffer_init(&ys->recv_buf);
    lp2p_list_init(&ys->write_queue);

    return ys;
}

void yamux_stream_free(yamux_stream_t *ys)
{
    if (!ys) return;

    /* Drain write queue */
    while (!lp2p_list_empty(&ys->write_queue)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&ys->write_queue);
        yamux_write_req_t *wr = lp2p_container_of(n, yamux_write_req_t, node);
        if (wr->cb) {
            wr->cb(wr->stream, LP2P_ERR_STREAM_RESET, wr->userdata);
        }
        free(wr->data);
        free(wr);
    }

    lp2p_buffer_free(&ys->recv_buf);
    free(ys->pub.protocol_id);
    free(ys);
}

/* ── Data delivery to app ─────────────────────────────────────────────────── */

/* Attempt to satisfy a pending read from the receive buffer */
void yamux_stream_deliver_data(yamux_stream_t *ys)
{
    if (!ys->read_pending || ys->recv_buf.len == 0) return;

    if (ys->read_lp) {
        /* Length-prefixed read: decode varint, wait for full frame */
        uint64_t frame_len;
        size_t consumed = lp2p_varint_decode(ys->recv_buf.data, ys->recv_buf.len,
                                              &frame_len);
        if (consumed == 0) return;  /* need more data for varint */
        if (frame_len > ys->read_max) {
            /* Frame too large */
            ys->read_pending = false;
            lp2p_stream_read_cb cb = ys->read_cb;
            void *ud = ys->read_ud;
            ys->read_cb = NULL;
            ys->read_ud = NULL;
            cb(&ys->pub, LP2P_ERR_PROTOCOL, NULL, ud);
            return;
        }
        if (ys->recv_buf.len - consumed < (size_t)frame_len) return;  /* need more data */

        /* Deliver the frame */
        lp2p_buf_t buf = {
            .data = ys->recv_buf.data + consumed,
            .len  = (size_t)frame_len,
        };
        ys->read_pending = false;
        lp2p_stream_read_cb cb = ys->read_cb;
        void *ud = ys->read_ud;
        ys->read_cb = NULL;
        ys->read_ud = NULL;

        /* Consume from recv buffer */
        size_t total = consumed + (size_t)frame_len;
        /* We need to copy the data before we shift the buffer,
           since buf.data points into recv_buf */
        uint8_t *copy = malloc(buf.len);
        if (copy) {
            memcpy(copy, buf.data, buf.len);
            buf.data = copy;
        }
        memmove(ys->recv_buf.data, ys->recv_buf.data + total,
                ys->recv_buf.len - total);
        ys->recv_buf.len -= total;

        cb(&ys->pub, LP2P_OK, &buf, ud);
        free(copy);
    } else {
        /* Raw read: deliver up to read_max bytes */
        size_t n = ys->recv_buf.len;
        if (n > ys->read_max) n = ys->read_max;

        uint8_t *copy = malloc(n);
        if (!copy) return;
        memcpy(copy, ys->recv_buf.data, n);

        memmove(ys->recv_buf.data, ys->recv_buf.data + n,
                ys->recv_buf.len - n);
        ys->recv_buf.len -= n;

        lp2p_buf_t buf = { .data = copy, .len = n };
        ys->read_pending = false;
        lp2p_stream_read_cb cb = ys->read_cb;
        void *ud = ys->read_ud;
        ys->read_cb = NULL;
        ys->read_ud = NULL;

        cb(&ys->pub, LP2P_OK, &buf, ud);
        free(copy);
    }

    /* Send window update if we consumed a lot of receive window */
    uint32_t consumed_window = YAMUX_DEFAULT_WINDOW - ys->recv_window;
    if (consumed_window >= YAMUX_DEFAULT_WINDOW / 2) {
        yamux_send_frame(ys->session, YAMUX_TYPE_WINDOW_UPDATE, 0,
                         ys->id, consumed_window, NULL, 0, NULL);
        ys->recv_window += consumed_window;
    }
}

/* Notify the app that the read-side is done (EOF or reset) */
static void yamux_stream_deliver_eof(yamux_stream_t *ys, lp2p_err_t err)
{
    if (!ys->read_pending) return;
    ys->read_pending = false;
    lp2p_stream_read_cb cb = ys->read_cb;
    void *ud = ys->read_ud;
    ys->read_cb = NULL;
    ys->read_ud = NULL;
    cb(&ys->pub, err, NULL, ud);
}

/* ── Write processing for a stream ────────────────────────────────────────── */

void yamux_stream_flush_writes(yamux_stream_t *ys)
{
    while (!lp2p_list_empty(&ys->write_queue)) {
        lp2p_list_node_t *n = ys->write_queue.head.next;
        yamux_write_req_t *wr = lp2p_container_of(n, yamux_write_req_t, node);

        if (wr->is_close) {
            /* Send FIN frame */
            lp2p_list_pop_front(&ys->write_queue);
            yamux_send_frame(ys->session, YAMUX_TYPE_DATA, YAMUX_FLAG_FIN,
                             ys->id, 0, NULL, 0, wr);
            if (ys->state == YAMUX_STREAM_ESTABLISHED) {
                ys->state = YAMUX_STREAM_LOCAL_CLOSE;
            } else if (ys->state == YAMUX_STREAM_REMOTE_CLOSE) {
                ys->state = YAMUX_STREAM_CLOSED;
            }
            continue;
        }

        size_t remaining = wr->len - wr->offset;
        if (remaining == 0) {
            /* Fully sent — complete */
            lp2p_list_pop_front(&ys->write_queue);
            ys->write_buf_bytes -= wr->len;
            yamux_send_frame(ys->session, YAMUX_TYPE_DATA, 0,
                             ys->id, 0, NULL, 0, wr);
            continue;
        }

        if (ys->send_window == 0) break;  /* flow control: blocked */

        /* Fragment into yamux frames, respecting send window and max frame size */
        size_t chunk = remaining;
        if (chunk > ys->send_window) chunk = ys->send_window;
        if (chunk > 65535) chunk = 65535;  /* respect Noise transport max */

        yamux_send_frame(ys->session, YAMUX_TYPE_DATA, 0,
                         ys->id, (uint32_t)chunk,
                         wr->data + wr->offset, chunk, NULL);
        wr->offset += chunk;
        ys->send_window -= (uint32_t)chunk;

        /* If fully sent now, pop and complete */
        if (wr->offset >= wr->len) {
            lp2p_list_pop_front(&ys->write_queue);
            ys->write_buf_bytes -= wr->len;
            /* Complete with callback */
            if (wr->cb) {
                wr->cb(wr->stream, LP2P_OK, wr->userdata);
            }
            free(wr->data);
            free(wr);
        }
    }
}

/* ── Keepalive ────────────────────────────────────────────────────────────── */

static void yamux_keepalive_cb(uv_timer_t *handle)
{
    yamux_session_t *s = (yamux_session_t *)handle->data;
    if (s->closed) return;

    if (s->ping_outstanding) {
        /* No response to previous ping — tear down */
        yamux_session_go_away(s, YAMUX_GOAWAY_NORMAL);
        return;
    }

    s->ping_id++;
    s->ping_outstanding = true;
    yamux_send_frame(s, YAMUX_TYPE_PING, YAMUX_FLAG_SYN,
                     0, s->ping_id, NULL, 0, NULL);
}

/* ── GoAway timer ─────────────────────────────────────────────────────────── */

static void yamux_goaway_timeout_cb(uv_timer_t *handle)
{
    yamux_session_t *s = (yamux_session_t *)handle->data;
    s->closed = true;
    /* Force-close all remaining streams */
    for (size_t i = 0; i < YAMUX_MAX_STREAMS; i++) {
        if (s->streams[i]) {
            yamux_stream_t *ys = s->streams[i];
            ys->state = YAMUX_STREAM_RESET;
            yamux_stream_deliver_eof(ys, LP2P_ERR_CONNECTION_CLOSED);
        }
    }
}

/* ── Frame processing ─────────────────────────────────────────────────────── */

static void yamux_process_flags(yamux_session_t *session, yamux_stream_t *ys,
                                 uint16_t flags)
{
    if (flags & YAMUX_FLAG_ACK) {
        if (ys->state == YAMUX_STREAM_SYN_SENT) {
            ys->state = YAMUX_STREAM_ESTABLISHED;
        }
    }
    if (flags & YAMUX_FLAG_FIN) {
        if (ys->state == YAMUX_STREAM_ESTABLISHED) {
            ys->state = YAMUX_STREAM_REMOTE_CLOSE;
        } else if (ys->state == YAMUX_STREAM_LOCAL_CLOSE) {
            ys->state = YAMUX_STREAM_CLOSED;
        }
        /* Deliver EOF to pending reads if recv buf is empty */
        if (ys->recv_buf.len == 0) {
            yamux_stream_deliver_eof(ys, LP2P_ERR_EOF);
        }
    }
    if (flags & YAMUX_FLAG_RST) {
        ys->state = YAMUX_STREAM_RESET;
        yamux_stream_deliver_eof(ys, LP2P_ERR_STREAM_RESET);
    }
}

static lp2p_err_t yamux_handle_frame(yamux_session_t *session,
                                      const yamux_header_t *h,
                                      const uint8_t *payload)
{
    switch (h->type) {
    case YAMUX_TYPE_DATA:
    case YAMUX_TYPE_WINDOW_UPDATE: {
        yamux_stream_t *ys = yamux_stream_lookup(session, h->stream_id);

        /* Handle SYN flag — new inbound stream */
        if ((h->flags & YAMUX_FLAG_SYN) && !ys) {
            if (session->remote_goaway || session->local_goaway) {
                /* Reject new streams after GoAway */
                yamux_send_frame(session, YAMUX_TYPE_DATA, YAMUX_FLAG_RST,
                                 h->stream_id, 0, NULL, 0, NULL);
                return LP2P_OK;
            }
            ys = yamux_stream_new(session, h->stream_id);
            if (!ys) return LP2P_ERR_NOMEM;
            ys->state = YAMUX_STREAM_SYN_RECV;
            if (yamux_stream_add(session, ys) < 0) {
                yamux_stream_free(ys);
                return LP2P_ERR_MUX;
            }
            /* Send ACK */
            yamux_send_frame(session, YAMUX_TYPE_WINDOW_UPDATE, YAMUX_FLAG_ACK,
                             h->stream_id, 0, NULL, 0, NULL);
            ys->state = YAMUX_STREAM_ESTABLISHED;

            /* Notify the application */
            if (session->on_stream) {
                session->on_stream(session, &ys->pub, session->on_stream_ud);
            }
        }

        if (!ys) {
            /* Unknown stream, might be a late frame for a closed stream */
            return LP2P_OK;
        }

        /* Process flags (FIN, RST, ACK) */
        yamux_process_flags(session, ys, h->flags);

        if (h->type == YAMUX_TYPE_DATA && h->length > 0) {
            if (ys->state == YAMUX_STREAM_RESET ||
                ys->state == YAMUX_STREAM_CLOSED) {
                return LP2P_OK;  /* discard */
            }
            /* Buffer received data */
            lp2p_buffer_append(&ys->recv_buf, payload, h->length);
            ys->recv_window -= h->length;

            /* Try to deliver to app */
            yamux_stream_deliver_data(ys);
        }

        if (h->type == YAMUX_TYPE_WINDOW_UPDATE) {
            /* Increase send window */
            ys->send_window += h->length;
            /* Try to flush blocked writes */
            yamux_stream_flush_writes(ys);
        }

        /* Clean up fully closed streams */
        if (ys->state == YAMUX_STREAM_CLOSED ||
            ys->state == YAMUX_STREAM_RESET) {
            if (ys->recv_buf.len == 0 && lp2p_list_empty(&ys->write_queue)) {
                yamux_stream_remove(session, ys);
                yamux_stream_free(ys);
            }
        }
        break;
    }

    case YAMUX_TYPE_PING:
        if (h->flags & YAMUX_FLAG_SYN) {
            /* Respond to ping */
            yamux_send_frame(session, YAMUX_TYPE_PING, YAMUX_FLAG_ACK,
                             0, h->length, NULL, 0, NULL);
        } else if (h->flags & YAMUX_FLAG_ACK) {
            /* Ping response */
            session->ping_outstanding = false;
        }
        break;

    case YAMUX_TYPE_GO_AWAY:
        session->remote_goaway = true;
        /* Start goaway timer — close after timeout or all streams done */
        if (session->stream_count == 0) {
            session->closed = true;
        } else {
            uv_timer_start(&session->goaway_timer, yamux_goaway_timeout_cb,
                           YAMUX_GOAWAY_TIMEOUT, 0);
        }
        break;

    default:
        return LP2P_ERR_PROTOCOL;
    }

    return LP2P_OK;
}

/* ── Data ingestion from transport ────────────────────────────────────────── */

lp2p_err_t yamux_session_on_data(yamux_session_t *session,
                                  const uint8_t *data, size_t len)
{
    if (session->closed) return LP2P_ERR_CONNECTION_CLOSED;

    lp2p_buffer_append(&session->recv_buf, data, len);

    while (session->recv_buf.len > 0) {
        if (!session->in_header) {
            /* Need at least 12 bytes for a header */
            if (session->recv_buf.len < YAMUX_HEADER_SIZE) break;

            if (!yamux_header_decode(session->recv_buf.data, &session->cur_header)) {
                return LP2P_ERR_PROTOCOL;
            }
            session->in_header = true;
            session->body_remaining = session->cur_header.length;

            /* Consume header bytes */
            memmove(session->recv_buf.data,
                    session->recv_buf.data + YAMUX_HEADER_SIZE,
                    session->recv_buf.len - YAMUX_HEADER_SIZE);
            session->recv_buf.len -= YAMUX_HEADER_SIZE;
        }

        /* Wait for body if needed */
        if (session->body_remaining > 0) {
            if (session->recv_buf.len < session->body_remaining) break;
        }

        /* Process full frame */
        const uint8_t *payload = (session->body_remaining > 0)
                                  ? session->recv_buf.data : NULL;
        lp2p_err_t err = yamux_handle_frame(session, &session->cur_header, payload);
        if (err != LP2P_OK) return err;

        /* Consume body */
        if (session->body_remaining > 0) {
            memmove(session->recv_buf.data,
                    session->recv_buf.data + session->body_remaining,
                    session->recv_buf.len - session->body_remaining);
            session->recv_buf.len -= session->body_remaining;
        }
        session->in_header = false;
        session->body_remaining = 0;
    }

    return LP2P_OK;
}

/* ── Session lifecycle ────────────────────────────────────────────────────── */

static void yamux_async_close_cb(uv_handle_t *handle)
{
    (void)handle;
}

yamux_session_t *yamux_session_new(
    uv_loop_t *loop,
    bool is_initiator,
    void (*on_send)(const uint8_t *data, size_t len, void *userdata),
    void *on_send_ud,
    void (*on_stream)(yamux_session_t *session, lp2p_stream_t *stream, void *userdata),
    void *on_stream_ud)
{
    yamux_session_t *s = calloc(1, sizeof(*s));
    if (!s) return NULL;

    s->loop          = loop;
    s->is_initiator  = is_initiator;
    s->next_stream_id = is_initiator ? 1 : 2;
    s->on_send       = on_send;
    s->on_send_ud    = on_send_ud;
    s->on_stream     = on_stream;
    s->on_stream_ud  = on_stream_ud;
    s->keepalive_interval = YAMUX_KEEPALIVE_SEC;

    lp2p_buffer_init(&s->recv_buf);
    lp2p_list_init(&s->stream_list);
    lp2p_list_init(&s->out_queue);
    lp2p_list_init(&s->deferred_cbs);
    memset(s->streams, 0, sizeof(s->streams));

    /* Init async handle for deferred callbacks */
    uv_async_init(loop, &s->async_handle, yamux_async_cb);
    s->async_handle.data = s;

    /* Init keepalive timer */
    uv_timer_init(loop, &s->keepalive_timer);
    s->keepalive_timer.data = s;
    uv_timer_start(&s->keepalive_timer, yamux_keepalive_cb,
                   s->keepalive_interval * 1000,
                   s->keepalive_interval * 1000);

    /* Init goaway timer (not started yet) */
    uv_timer_init(loop, &s->goaway_timer);
    s->goaway_timer.data = s;

    return s;
}

void yamux_session_free(yamux_session_t *session)
{
    if (!session) return;

    session->closed = true;

    /* Stop timers */
    uv_timer_stop(&session->keepalive_timer);
    uv_timer_stop(&session->goaway_timer);

    /* Free all streams */
    for (size_t i = 0; i < YAMUX_MAX_STREAMS; i++) {
        if (session->streams[i]) {
            yamux_stream_free(session->streams[i]);
            session->streams[i] = NULL;
        }
    }
    session->stream_count = 0;

    /* Drain out queue */
    while (!lp2p_list_empty(&session->out_queue)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&session->out_queue);
        yamux_out_frame_t *f = lp2p_container_of(n, yamux_out_frame_t, node);
        if (f->write_req) {
            free(f->write_req->data);
            free(f->write_req);
        }
        free(f->data);
        free(f);
    }

    /* Drain deferred callbacks */
    while (!lp2p_list_empty(&session->deferred_cbs)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&session->deferred_cbs);
        yamux_deferred_t *d = lp2p_container_of(n, yamux_deferred_t, node);
        free(d);
    }

    lp2p_buffer_free(&session->recv_buf);

    /* Close async handle */
    uv_close((uv_handle_t *)&session->async_handle, yamux_async_close_cb);
    uv_close((uv_handle_t *)&session->keepalive_timer, NULL);
    uv_close((uv_handle_t *)&session->goaway_timer, NULL);

    free(session);
}

/* ── Open outbound stream ─────────────────────────────────────────────────── */

lp2p_err_t yamux_session_open_stream(yamux_session_t *session,
                                      lp2p_stream_t **out)
{
    if (session->closed || session->local_goaway || session->remote_goaway) {
        return LP2P_ERR_CONNECTION_CLOSED;
    }

    uint32_t id = session->next_stream_id;
    session->next_stream_id += 2;

    yamux_stream_t *ys = yamux_stream_new(session, id);
    if (!ys) return LP2P_ERR_NOMEM;

    ys->state = YAMUX_STREAM_SYN_SENT;
    if (yamux_stream_add(session, ys) < 0) {
        yamux_stream_free(ys);
        return LP2P_ERR_MUX;
    }

    /* Send SYN via WindowUpdate frame (0-length data with SYN flag) */
    yamux_send_frame(session, YAMUX_TYPE_WINDOW_UPDATE, YAMUX_FLAG_SYN,
                     id, 0, NULL, 0, NULL);

    *out = &ys->pub;
    return LP2P_OK;
}

/* ── GoAway ───────────────────────────────────────────────────────────────── */

lp2p_err_t yamux_session_go_away(yamux_session_t *session, uint32_t error_code)
{
    if (session->local_goaway) return LP2P_OK;

    session->local_goaway = true;
    yamux_send_frame(session, YAMUX_TYPE_GO_AWAY, 0,
                     0, error_code, NULL, 0, NULL);

    if (session->stream_count == 0) {
        session->closed = true;
    } else {
        uv_timer_start(&session->goaway_timer, yamux_goaway_timeout_cb,
                       YAMUX_GOAWAY_TIMEOUT, 0);
    }

    return LP2P_OK;
}

/* ── Mux vtable implementation ────────────────────────────────────────────── */

static lp2p_err_t vtable_open_stream(void *impl, lp2p_stream_t **out)
{
    return yamux_session_open_stream((yamux_session_t *)impl, out);
}

static lp2p_err_t vtable_write_stream(void *impl, lp2p_stream_t *stream,
                                       const uint8_t *data, size_t len,
                                       lp2p_stream_write_cb cb, void *userdata)
{
    yamux_session_t *session = (yamux_session_t *)impl;
    yamux_stream_t *ys = (yamux_stream_t *)stream;

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

    wr->data     = malloc(len);
    if (!wr->data) { free(wr); return LP2P_ERR_NOMEM; }
    memcpy(wr->data, data, len);
    wr->len      = len;
    wr->offset   = 0;
    wr->cb       = cb;
    wr->userdata = userdata;
    wr->stream   = stream;

    lp2p_list_push_back(&ys->write_queue, &wr->node);
    ys->write_buf_bytes += len;

    yamux_stream_flush_writes(ys);
    return LP2P_OK;

    (void)session;
}

static lp2p_err_t vtable_close_stream(void *impl, lp2p_stream_t *stream)
{
    yamux_stream_t *ys = (yamux_stream_t *)stream;

    if (ys->state == YAMUX_STREAM_CLOSED ||
        ys->state == YAMUX_STREAM_RESET ||
        ys->state == YAMUX_STREAM_LOCAL_CLOSE) {
        return LP2P_OK;
    }

    /* Enqueue a FIN after all pending writes */
    yamux_write_req_t *wr = calloc(1, sizeof(*wr));
    if (!wr) return LP2P_ERR_NOMEM;
    wr->is_close = true;
    wr->stream   = stream;
    wr->cb       = ys->close_cb;
    wr->userdata = ys->close_ud;
    lp2p_list_push_back(&ys->write_queue, &wr->node);

    yamux_stream_flush_writes(ys);
    return LP2P_OK;

    (void)impl;
}

static lp2p_err_t vtable_reset_stream(void *impl, lp2p_stream_t *stream)
{
    yamux_session_t *session = (yamux_session_t *)impl;
    yamux_stream_t *ys = (yamux_stream_t *)stream;

    if (ys->state == YAMUX_STREAM_RESET || ys->state == YAMUX_STREAM_CLOSED) {
        return LP2P_OK;
    }

    /* Send RST frame */
    yamux_send_frame(session, YAMUX_TYPE_DATA, YAMUX_FLAG_RST,
                     ys->id, 0, NULL, 0, NULL);
    ys->state = YAMUX_STREAM_RESET;

    /* Notify pending reads */
    yamux_stream_deliver_eof(ys, LP2P_ERR_STREAM_RESET);

    /* Fail pending writes */
    while (!lp2p_list_empty(&ys->write_queue)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&ys->write_queue);
        yamux_write_req_t *wr = lp2p_container_of(n, yamux_write_req_t, node);
        if (wr->cb) {
            wr->cb(wr->stream, LP2P_ERR_STREAM_RESET, wr->userdata);
        }
        free(wr->data);
        free(wr);
    }
    ys->write_buf_bytes = 0;

    /* Remove stream */
    yamux_stream_remove(session, ys);
    yamux_stream_free(ys);

    return LP2P_OK;
}

static lp2p_err_t vtable_on_data(void *impl, const uint8_t *data, size_t len)
{
    return yamux_session_on_data((yamux_session_t *)impl, data, len);
}

static lp2p_err_t vtable_go_away(void *impl, uint32_t error_code)
{
    return yamux_session_go_away((yamux_session_t *)impl, error_code);
}

static void vtable_free(void *impl)
{
    yamux_session_free((yamux_session_t *)impl);
}

static const lp2p_mux_vtable_t yamux_vtable = {
    .open_stream  = vtable_open_stream,
    .write_stream = vtable_write_stream,
    .close_stream = vtable_close_stream,
    .reset_stream = vtable_reset_stream,
    .on_data      = vtable_on_data,
    .go_away      = vtable_go_away,
    .free         = vtable_free,
};

const lp2p_mux_vtable_t *yamux_get_vtable(void)
{
    return &yamux_vtable;
}
