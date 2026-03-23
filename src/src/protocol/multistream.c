/* src/protocol/multistream.c — multistream-select 1.0.0 negotiation */

#include "multistream.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Varint encoding/decoding (unsigned LEB128) ───────────────────────────── */

size_t ms_varint_encode(uint64_t val, uint8_t *buf)
{
    size_t i = 0;
    while (val >= 0x80) {
        buf[i++] = (uint8_t)(val & 0x7F) | 0x80;
        val >>= 7;
    }
    buf[i++] = (uint8_t)val;
    return i;
}

int ms_varint_decode(const uint8_t *buf, size_t len, uint64_t *out, size_t *consumed)
{
    uint64_t val = 0;
    size_t shift = 0;

    for (size_t i = 0; i < len && i < 10; i++) {
        val |= (uint64_t)(buf[i] & 0x7F) << shift;
        if ((buf[i] & 0x80) == 0) {
            *out = val;
            *consumed = i + 1;
            return 0;
        }
        shift += 7;
    }

    return -1; /* incomplete or overflow */
}

/* ── Frame encode/decode ──────────────────────────────────────────────────── */

size_t ms_frame_encode(const char *msg, uint8_t *out_buf, size_t out_cap)
{
    size_t msg_len = strlen(msg);
    size_t payload_len = msg_len + 1; /* msg + '\n' */

    uint8_t varint_buf[10];
    size_t varint_len = ms_varint_encode(payload_len, varint_buf);

    size_t total = varint_len + payload_len;
    if (total > out_cap) return 0;

    memcpy(out_buf, varint_buf, varint_len);
    memcpy(out_buf + varint_len, msg, msg_len);
    out_buf[varint_len + msg_len] = '\n';

    return total;
}

int ms_frame_decode(const uint8_t *buf, size_t len,
                    const uint8_t **out_msg, size_t *out_msg_len)
{
    if (len == 0) return 0;

    uint64_t payload_len;
    size_t varint_consumed;
    if (ms_varint_decode(buf, len, &payload_len, &varint_consumed) != 0) {
        return 0; /* need more data */
    }

    if (payload_len > MULTISTREAM_MAX_MSG_LEN) return -1;
    if (payload_len == 0) return -1;

    size_t total_frame = varint_consumed + (size_t)payload_len;
    if (len < total_frame) return 0; /* need more data */

    /* Verify trailing newline */
    if (buf[total_frame - 1] != '\n') return -1;

    *out_msg     = buf + varint_consumed;
    *out_msg_len = (size_t)payload_len - 1; /* exclude '\n' */

    return (int)total_frame;
}

/* ── Negotiation state machine context ────────────────────────────────────── */

typedef struct {
    ms_negotiation_t  neg;
    lp2p_tcp_conn_t  *tc;
    ms_negotiate_cb   cb;
    void             *userdata;
} ms_ctx_t;

static void ms_drive(ms_ctx_t *ctx);

/* ── Send a multistream frame ─────────────────────────────────────────────── */

static void ms_on_write_done(lp2p_tcp_conn_t *tc, lp2p_err_t err, void *userdata)
{
    ms_ctx_t *ctx = (ms_ctx_t *)userdata;
    if (err != LP2P_OK) {
        ctx->neg.state = MS_STATE_FAILED;
        ctx->cb(LP2P_ERR_NEGOTIATION_FAILED, NULL, ctx->userdata);
        free(ctx);
        return;
    }
    ms_drive(ctx);
}

static lp2p_err_t ms_send_frame(ms_ctx_t *ctx, const char *msg)
{
    uint8_t frame[MULTISTREAM_MAX_MSG_LEN + 16];
    size_t frame_len = ms_frame_encode(msg, frame, sizeof(frame));
    if (frame_len == 0) return LP2P_ERR_PROTOCOL;

    return lp2p_tcp_conn_write(ctx->tc, frame, frame_len,
                                ms_on_write_done, ctx);
}

/* ── Read callback — accumulate data and try to decode frames ─────────────── */

static void ms_on_read(lp2p_tcp_conn_t *tc, const uint8_t *data, size_t len,
                        lp2p_err_t err, void *userdata)
{
    ms_ctx_t *ctx = (ms_ctx_t *)userdata;
    ms_negotiation_t *neg = &ctx->neg;

    if (err != LP2P_OK) {
        neg->state = MS_STATE_FAILED;
        ctx->cb(LP2P_ERR_NEGOTIATION_FAILED, NULL, ctx->userdata);
        free(ctx);
        return;
    }

    /* Try to decode a frame from the TCP conn's read buffer */
    const uint8_t *msg;
    size_t msg_len;
    int consumed = ms_frame_decode(data, len, &msg, &msg_len);

    if (consumed < 0) {
        neg->state = MS_STATE_FAILED;
        ctx->cb(LP2P_ERR_PROTOCOL, NULL, ctx->userdata);
        free(ctx);
        return;
    }

    if (consumed == 0) {
        /* Need more data — keep reading */
        return;
    }

    /* Consume the frame bytes from the TCP buffer */
    lp2p_tcp_conn_consume(tc, (size_t)consumed);

    /* Process based on current state */
    switch (neg->state) {
    case MS_STATE_RECV_HEADER: {
        /* Expect /multistream/1.0.0 */
        if (msg_len != strlen(MULTISTREAM_PROTOCOL_ID) ||
            memcmp(msg, MULTISTREAM_PROTOCOL_ID, msg_len) != 0) {
            neg->state = MS_STATE_FAILED;
            ctx->cb(LP2P_ERR_NEGOTIATION_FAILED, NULL, ctx->userdata);
            free(ctx);
            return;
        }

        if (neg->is_initiator) {
            /* After receiving header, send our proposal */
            neg->state = MS_STATE_SEND_PROPOSAL;
        } else {
            /* Responder: after header exchange, wait for proposal */
            neg->state = MS_STATE_RECV_PROPOSAL;
        }
        ms_drive(ctx);
        break;
    }
    case MS_STATE_RECV_PROPOSAL: {
        /* Responder: check if we support this protocol */
        char proto[256];
        size_t copy_len = msg_len < sizeof(proto) - 1 ? msg_len : sizeof(proto) - 1;
        memcpy(proto, msg, copy_len);
        proto[copy_len] = '\0';

        bool found = false;
        for (size_t i = 0; i < neg->supported_protos_count; i++) {
            if (strcmp(proto, neg->supported_protos[i]) == 0) {
                found = true;
                break;
            }
        }

        if (found) {
            strncpy(neg->negotiated_proto, proto, sizeof(neg->negotiated_proto) - 1);
            neg->state = MS_STATE_SEND_ACCEPT;
        } else {
            /* Send "na" and wait for next proposal */
            uint8_t frame[64];
            size_t frame_len = ms_frame_encode(MULTISTREAM_NA, frame, sizeof(frame));
            if (frame_len == 0) {
                neg->state = MS_STATE_FAILED;
                ctx->cb(LP2P_ERR_PROTOCOL, NULL, ctx->userdata);
                free(ctx);
                return;
            }
            lp2p_tcp_conn_write(ctx->tc, frame, frame_len, ms_on_write_done, ctx);
            /* Stay in RECV_PROPOSAL state — the write callback will call ms_drive
               which will re-enter read. But we need to NOT advance state, so we
               handle this specially: set state to RECV_PROPOSAL before write done. */
            neg->state = MS_STATE_RECV_PROPOSAL;
            return; /* ms_on_write_done -> ms_drive will handle next */
        }
        ms_drive(ctx);
        break;
    }
    case MS_STATE_RECV_ACCEPT: {
        /* Initiator: check if responder accepted or sent "na" */
        if (msg_len == 2 && memcmp(msg, "na", 2) == 0) {
            neg->state = MS_STATE_FAILED;
            ctx->cb(LP2P_ERR_PROTOCOL_NOT_SUPPORTED, NULL, ctx->userdata);
            free(ctx);
            return;
        }

        /* Responder echoed back our protocol = accepted */
        size_t proto_len = strlen(neg->proposed_proto);
        if (msg_len == proto_len &&
            memcmp(msg, neg->proposed_proto, msg_len) == 0) {
            strncpy(neg->negotiated_proto, neg->proposed_proto,
                    sizeof(neg->negotiated_proto) - 1);
            neg->state = MS_STATE_DONE;
            ctx->cb(LP2P_OK, neg->negotiated_proto, ctx->userdata);
            free(ctx);
        } else {
            neg->state = MS_STATE_FAILED;
            ctx->cb(LP2P_ERR_NEGOTIATION_FAILED, NULL, ctx->userdata);
            free(ctx);
        }
        break;
    }
    default:
        neg->state = MS_STATE_FAILED;
        ctx->cb(LP2P_ERR_INTERNAL, NULL, ctx->userdata);
        free(ctx);
        break;
    }
}

/* ── State machine driver ─────────────────────────────────────────────────── */

static void ms_drive(ms_ctx_t *ctx)
{
    ms_negotiation_t *neg = &ctx->neg;

    switch (neg->state) {
    case MS_STATE_SEND_HEADER:
        neg->state = MS_STATE_RECV_HEADER;
        if (ms_send_frame(ctx, MULTISTREAM_PROTOCOL_ID) != LP2P_OK) {
            neg->state = MS_STATE_FAILED;
            ctx->cb(LP2P_ERR_NEGOTIATION_FAILED, NULL, ctx->userdata);
            free(ctx);
        }
        break;

    case MS_STATE_RECV_HEADER:
    case MS_STATE_RECV_PROPOSAL:
    case MS_STATE_RECV_ACCEPT:
        /* Start reading — the read callback handles frame processing */
        lp2p_tcp_conn_start_read(ctx->tc, ms_on_read, ctx);
        break;

    case MS_STATE_SEND_PROPOSAL:
        neg->state = MS_STATE_RECV_ACCEPT;
        if (ms_send_frame(ctx, neg->proposed_proto) != LP2P_OK) {
            neg->state = MS_STATE_FAILED;
            ctx->cb(LP2P_ERR_NEGOTIATION_FAILED, NULL, ctx->userdata);
            free(ctx);
        }
        break;

    case MS_STATE_SEND_ACCEPT:
        neg->state = MS_STATE_DONE;
        {
            uint8_t frame[MULTISTREAM_MAX_MSG_LEN + 16];
            size_t frame_len = ms_frame_encode(neg->negotiated_proto,
                                                frame, sizeof(frame));
            if (frame_len == 0) {
                neg->state = MS_STATE_FAILED;
                ctx->cb(LP2P_ERR_PROTOCOL, NULL, ctx->userdata);
                free(ctx);
                return;
            }
            /* After sending accept, we're done — but we need to wait for write to
               complete before signaling done. We'll use a special write callback. */
            lp2p_err_t err = lp2p_tcp_conn_write(ctx->tc, frame, frame_len,
                ms_on_write_done, ctx);
            if (err != LP2P_OK) {
                ctx->cb(LP2P_ERR_NEGOTIATION_FAILED, NULL, ctx->userdata);
                free(ctx);
            }
        }
        break;

    case MS_STATE_DONE:
        ctx->cb(LP2P_OK, neg->negotiated_proto, ctx->userdata);
        free(ctx);
        break;

    case MS_STATE_FAILED:
        ctx->cb(LP2P_ERR_NEGOTIATION_FAILED, NULL, ctx->userdata);
        free(ctx);
        break;
    }
}

/* ── Public API ───────────────────────────────────────────────────────────── */

lp2p_err_t ms_negotiate_initiator(lp2p_tcp_conn_t *tc,
                                   const char *protocol_id,
                                   ms_negotiate_cb cb, void *userdata)
{
    if (!tc || !protocol_id || !cb) return LP2P_ERR_INVALID_ARG;

    ms_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return LP2P_ERR_NOMEM;

    ctx->neg.state        = MS_STATE_SEND_HEADER;
    ctx->neg.is_initiator = true;
    strncpy(ctx->neg.proposed_proto, protocol_id,
            sizeof(ctx->neg.proposed_proto) - 1);
    ctx->tc       = tc;
    ctx->cb       = cb;
    ctx->userdata = userdata;

    ms_drive(ctx);
    return LP2P_OK;
}

lp2p_err_t ms_negotiate_responder(lp2p_tcp_conn_t *tc,
                                   const char **supported_protos,
                                   size_t count,
                                   ms_negotiate_cb cb, void *userdata)
{
    if (!tc || !supported_protos || count == 0 || !cb)
        return LP2P_ERR_INVALID_ARG;

    ms_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return LP2P_ERR_NOMEM;

    ctx->neg.state                 = MS_STATE_SEND_HEADER;
    ctx->neg.is_initiator          = false;
    ctx->neg.supported_protos      = supported_protos;
    ctx->neg.supported_protos_count = count;
    ctx->tc       = tc;
    ctx->cb       = cb;
    ctx->userdata = userdata;

    ms_drive(ctx);
    return LP2P_OK;
}
