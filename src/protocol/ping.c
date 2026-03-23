/* src/protocol/ping.c — /ipfs/ping/1.0.0 protocol implementation */

#include <stdlib.h>
#include <string.h>

#include <uv.h>
#include <sodium.h>

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/stream.h"
#include "libp2p/connection.h"
#include "libp2p/protocol.h"

#define PING_PROTOCOL_ID "/ipfs/ping/1.0.0"
#define PING_PAYLOAD_LEN 32

/* ── Forward declarations ────────────────────────────────────────────────── */

/* Internal header for ping — used by host.c */
#include "ping_internal.h"

/* ── Ping responder (inbound handler) ────────────────────────────────────── */

/*
 * The responder echoes each 32-byte ping payload and keeps the stream open
 * until the initiator closes it. go-libp2p reuses a single stream for
 * multiple ping exchanges.
 */

typedef struct {
    lp2p_stream_t *stream;
    uint8_t        payload[PING_PAYLOAD_LEN];
} ping_responder_ctx_t;

static void ping_responder_on_read(lp2p_stream_t *stream, lp2p_err_t err,
                                   const lp2p_buf_t *buf, void *userdata);

static void ping_responder_read_next(ping_responder_ctx_t *ctx) {
    lp2p_err_t err = lp2p_stream_read(ctx->stream, PING_PAYLOAD_LEN,
                                      ping_responder_on_read, ctx);
    if (err != LP2P_OK) {
        lp2p_stream_reset(ctx->stream);
        free(ctx);
    }
}

static void ping_responder_write_done(lp2p_stream_t *stream, lp2p_err_t err,
                                       void *userdata) {
    ping_responder_ctx_t *ctx = userdata;

    if (err != LP2P_OK) {
        lp2p_stream_reset(stream);
        free(ctx);
        return;
    }

    ping_responder_read_next(ctx);
}

static void ping_responder_on_read(lp2p_stream_t *stream, lp2p_err_t err,
                                    const lp2p_buf_t *buf, void *userdata) {
    ping_responder_ctx_t *ctx = userdata;

    if (err == LP2P_ERR_EOF || err == LP2P_ERR_CONNECTION_CLOSED) {
        lp2p_stream_close(stream, NULL, NULL);
        free(ctx);
        return;
    }

    if (err != LP2P_OK || !buf || buf->len != PING_PAYLOAD_LEN) {
        lp2p_stream_reset(stream);
        free(ctx);
        return;
    }

    /* Echo back the received bytes */
    memcpy(ctx->payload, buf->data, PING_PAYLOAD_LEN);
    lp2p_buf_t wbuf = { .data = ctx->payload, .len = PING_PAYLOAD_LEN };
    lp2p_err_t werr = lp2p_stream_write(stream, &wbuf,
                                          ping_responder_write_done, ctx);
    if (werr != LP2P_OK) {
        lp2p_stream_reset(stream);
        free(ctx);
    }
}

void lp2p_ping_handler(lp2p_stream_t *stream, void *userdata) {
    (void)userdata;
    ping_responder_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        lp2p_stream_reset(stream);
        return;
    }
    ctx->stream = stream;

    ping_responder_read_next(ctx);
}

/* ── Ping initiator (outbound, called by host) ───────────────────────────── */

typedef struct {
    lp2p_stream_t *stream;
    uint8_t        sent[PING_PAYLOAD_LEN];
    uint64_t       start_time;  /* nanoseconds from uv_hrtime() */
    void         (*cb)(lp2p_err_t err, uint64_t rtt_us, void *userdata);
    void          *userdata;
} ping_initiator_ctx_t;

static void ping_initiator_on_echo(lp2p_stream_t *stream, lp2p_err_t err,
                                    const lp2p_buf_t *buf, void *userdata) {
    ping_initiator_ctx_t *ctx = userdata;

    if (err != LP2P_OK || !buf || buf->len != PING_PAYLOAD_LEN) {
        if (ctx->cb) ctx->cb(err != LP2P_OK ? err : LP2P_ERR_PROTOCOL, 0, ctx->userdata);
        lp2p_stream_reset(stream);
        free(ctx);
        return;
    }

    /* Verify echo matches what we sent */
    if (memcmp(buf->data, ctx->sent, PING_PAYLOAD_LEN) != 0) {
        if (ctx->cb) ctx->cb(LP2P_ERR_PROTOCOL, 0, ctx->userdata);
        lp2p_stream_reset(stream);
        free(ctx);
        return;
    }

    /* Compute RTT in microseconds */
    uint64_t end_time = uv_hrtime();
    uint64_t rtt_us = (end_time - ctx->start_time) / 1000;

    /* Close stream gracefully */
    lp2p_stream_close(stream, NULL, NULL);

    if (ctx->cb) ctx->cb(LP2P_OK, rtt_us, ctx->userdata);
    free(ctx);
}

static void ping_initiator_write_done(lp2p_stream_t *stream, lp2p_err_t err,
                                       void *userdata) {
    ping_initiator_ctx_t *ctx = userdata;

    if (err != LP2P_OK) {
        if (ctx->cb) ctx->cb(err, 0, ctx->userdata);
        lp2p_stream_reset(stream);
        free(ctx);
        return;
    }

    /* Now read 32 bytes echo */
    lp2p_err_t rerr = lp2p_stream_read(stream, PING_PAYLOAD_LEN,
                                         ping_initiator_on_echo, ctx);
    if (rerr != LP2P_OK) {
        if (ctx->cb) ctx->cb(rerr, 0, ctx->userdata);
        lp2p_stream_reset(stream);
        free(ctx);
    }
}

static void ping_initiator_on_stream(lp2p_stream_t *stream, lp2p_err_t err,
                                      void *userdata) {
    ping_initiator_ctx_t *ctx = userdata;

    if (err != LP2P_OK || !stream) {
        if (ctx->cb) ctx->cb(err, 0, ctx->userdata);
        free(ctx);
        return;
    }

    ctx->stream = stream;

    /* Generate 32 random bytes */
    randombytes_buf(ctx->sent, PING_PAYLOAD_LEN);

    /* Record start time */
    ctx->start_time = uv_hrtime();

    /* Send the ping payload */
    lp2p_buf_t wbuf = { .data = ctx->sent, .len = PING_PAYLOAD_LEN };
    lp2p_err_t werr = lp2p_stream_write(stream, &wbuf,
                                          ping_initiator_write_done, ctx);
    if (werr != LP2P_OK) {
        if (ctx->cb) ctx->cb(werr, 0, ctx->userdata);
        lp2p_stream_reset(stream);
        free(ctx);
    }
}

lp2p_err_t lp2p_ping_start(lp2p_conn_t *conn,
                             void (*cb)(lp2p_err_t err, uint64_t rtt_us,
                                        void *userdata),
                             void *userdata) {
    if (!conn) return LP2P_ERR_INVALID_ARG;

    /* lp2p_ping_start opens a stream and passes ctx as userdata to
     * ping_initiator_on_stream. This is an alternative to lp2p_host_ping(). */
    ping_initiator_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return LP2P_ERR_NOMEM;
    ctx->cb       = cb;
    ctx->userdata = userdata;

    lp2p_err_t err = lp2p_conn_open_stream(conn, PING_PROTOCOL_ID,
                                             ping_initiator_on_stream, ctx);
    if (err != LP2P_OK) {
        free(ctx);
        return err;
    }

    return LP2P_OK;
}

/* Stream-based ping initiator used by lp2p_host_ping.
 * Called after the host has already opened the stream. */
lp2p_err_t lp2p_ping_initiate(lp2p_conn_t *conn,
                                lp2p_stream_t *stream,
                                void (*cb)(lp2p_err_t err, uint64_t rtt_us,
                                           void *userdata),
                                void *userdata) {
    if (!conn || !stream) return LP2P_ERR_INVALID_ARG;

    ping_initiator_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return LP2P_ERR_NOMEM;
    ctx->cb       = cb;
    ctx->userdata = userdata;
    ctx->stream   = stream;

    /* Generate 32 random bytes */
    randombytes_buf(ctx->sent, PING_PAYLOAD_LEN);

    /* Record start time */
    ctx->start_time = uv_hrtime();

    /* Send the ping payload */
    lp2p_buf_t wbuf = { .data = ctx->sent, .len = PING_PAYLOAD_LEN };
    lp2p_err_t err = lp2p_stream_write(stream, &wbuf,
                                         ping_initiator_write_done, ctx);
    if (err != LP2P_OK) {
        free(ctx);
        return err;
    }

    return LP2P_OK;
}
