/*
 * examples/echo_client.c — Dial a peer, send one /echo/1.0.0 message, print the reply.
 *
 * Usage: ./echo_client <multiaddr> [message]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "libp2p/libp2p.h"

#define ECHO_PROTO "/echo/1.0.0"
#define DEFAULT_MESSAGE "hello from echo_client"

static lp2p_host_t *g_host;

typedef struct {
    lp2p_conn_t   *conn;
    char          *message;
    size_t         message_len;
    uint8_t       *reply;
    size_t         reply_len;
} echo_ctx_t;

static void echo_start_timer_cb(uv_timer_t *handle);
static void echo_start_timer_close_cb(uv_handle_t *handle);
static void echo_on_stream(lp2p_stream_t *stream, lp2p_err_t err, void *userdata);
static void echo_on_write(lp2p_stream_t *stream, lp2p_err_t err, void *userdata);
static void echo_on_read(lp2p_stream_t *stream, lp2p_err_t err,
                         const lp2p_buf_t *buf, void *userdata);
static void echo_finish(echo_ctx_t *ctx);

static void echo_finish(echo_ctx_t *ctx)
{
    if (!ctx) return;
    free(ctx->reply);
    free(ctx->message);
    free(ctx);
    lp2p_host_close(g_host, NULL, NULL);
}

static void echo_on_read(lp2p_stream_t *stream, lp2p_err_t err,
                         const lp2p_buf_t *buf, void *userdata)
{
    echo_ctx_t *ctx = userdata;

    if (err != LP2P_OK || !buf || buf->len == 0) {
        fprintf(stderr, "echo read failed: %s\n", lp2p_strerror(err));
        lp2p_stream_reset(stream);
        echo_finish(ctx);
        return;
    }

    uint8_t *next = realloc(ctx->reply, ctx->reply_len + buf->len + 1);
    if (!next) {
        fprintf(stderr, "echo read failed: out of memory\n");
        lp2p_stream_reset(stream);
        echo_finish(ctx);
        return;
    }

    ctx->reply = next;
    memcpy(ctx->reply + ctx->reply_len, buf->data, buf->len);
    ctx->reply_len += buf->len;
    ctx->reply[ctx->reply_len] = '\0';

    if (ctx->reply_len < ctx->message_len) {
        lp2p_err_t rerr = lp2p_stream_read(stream, ctx->message_len - ctx->reply_len,
                                           echo_on_read, ctx);
        if (rerr != LP2P_OK) {
            fprintf(stderr, "echo read failed: %s\n", lp2p_strerror(rerr));
            lp2p_stream_reset(stream);
            echo_finish(ctx);
        }
        return;
    }

    printf("Echoed: %s\n", (char *)ctx->reply);
    lp2p_stream_close(stream, NULL, NULL);
    echo_finish(ctx);
}

static void echo_on_write(lp2p_stream_t *stream, lp2p_err_t err, void *userdata)
{
    echo_ctx_t *ctx = userdata;

    if (err != LP2P_OK) {
        fprintf(stderr, "echo write failed: %s\n", lp2p_strerror(err));
        lp2p_stream_reset(stream);
        echo_finish(ctx);
        return;
    }

    lp2p_err_t rerr = lp2p_stream_read(stream, ctx->message_len, echo_on_read, ctx);
    if (rerr != LP2P_OK) {
        fprintf(stderr, "echo read failed: %s\n", lp2p_strerror(rerr));
        lp2p_stream_reset(stream);
        echo_finish(ctx);
    }
}

static void echo_on_stream(lp2p_stream_t *stream, lp2p_err_t err, void *userdata)
{
    echo_ctx_t *ctx = userdata;

    if (err != LP2P_OK || !stream) {
        fprintf(stderr, "open_stream failed: %s\n", lp2p_strerror(err));
        echo_finish(ctx);
        return;
    }

    lp2p_buf_t buf = {
        .data = (uint8_t *)ctx->message,
        .len = ctx->message_len,
    };
    lp2p_err_t werr = lp2p_stream_write(stream, &buf, echo_on_write, ctx);
    if (werr != LP2P_OK) {
        fprintf(stderr, "echo write failed: %s\n", lp2p_strerror(werr));
        lp2p_stream_reset(stream);
        echo_finish(ctx);
    }
}

static void echo_start_timer_cb(uv_timer_t *handle)
{
    echo_ctx_t *ctx = handle->data;
    uv_timer_stop(handle);
    uv_close((uv_handle_t *)handle, echo_start_timer_close_cb);

    lp2p_err_t err = lp2p_conn_open_stream(ctx->conn, ECHO_PROTO, echo_on_stream, ctx);
    if (err != LP2P_OK) {
        fprintf(stderr, "open_stream failed: %s\n", lp2p_strerror(err));
        echo_finish(ctx);
    }
}

static void echo_start_timer_close_cb(uv_handle_t *handle)
{
    free(handle);
}

static void dial_cb(lp2p_conn_t *conn, lp2p_err_t err, void *userdata)
{
    echo_ctx_t *ctx = userdata;

    if (err != LP2P_OK || !conn) {
        fprintf(stderr, "dial failed: %s\n", lp2p_strerror(err));
        echo_finish(ctx);
        return;
    }

    ctx->conn = conn;
    printf("Connected\n");

    uv_timer_t *timer = malloc(sizeof(*timer));
    if (!timer) {
        fprintf(stderr, "open_stream failed: out of memory\n");
        echo_finish(ctx);
        return;
    }

    uv_timer_init(uv_default_loop(), timer);
    timer->data = ctx;
    uv_timer_start(timer, echo_start_timer_cb, 200, 0);
}

int main(int argc, char **argv)
{
    const char *target;
    const char *message = DEFAULT_MESSAGE;
    uv_loop_t *loop = uv_default_loop();

    if (argc < 2 || argc > 3) {
        fprintf(stderr, "Usage: %s <multiaddr> [message]\n", argv[0]);
        fprintf(stderr, "  e.g. %s /ip4/127.0.0.1/tcp/9000/p2p/12D3KooW... \"hello\"\n", argv[0]);
        return 1;
    }

    target = argv[1];
    if (argc == 3) {
        message = argv[2];
    }

    lp2p_keypair_t *kp = NULL;
    lp2p_err_t err = lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);
    if (err != LP2P_OK) {
        fprintf(stderr, "keygen failed: %s\n", lp2p_strerror(err));
        return 1;
    }

    lp2p_host_config_t cfg = {
        .keypair = kp,
    };

    err = lp2p_host_new(loop, &cfg, &g_host);
    if (err != LP2P_OK) {
        fprintf(stderr, "host_new failed: %s\n", lp2p_strerror(err));
        lp2p_keypair_free(kp);
        return 1;
    }

    echo_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        fprintf(stderr, "out of memory\n");
        lp2p_host_free(g_host);
        return 1;
    }

    ctx->message = strdup(message);
    if (!ctx->message) {
        fprintf(stderr, "out of memory\n");
        free(ctx);
        lp2p_host_free(g_host);
        return 1;
    }
    ctx->message_len = strlen(ctx->message);

    printf("Dialing %s ...\n", target);
    printf("Sending: %s\n", ctx->message);

    err = lp2p_host_dial(g_host, target, dial_cb, ctx);
    if (err != LP2P_OK) {
        fprintf(stderr, "dial failed: %s\n", lp2p_strerror(err));
        free(ctx->message);
        free(ctx);
        lp2p_host_free(g_host);
        return 1;
    }

    uv_run(loop, UV_RUN_DEFAULT);

    lp2p_host_free(g_host);
    uv_loop_close(loop);
    return 0;
}
