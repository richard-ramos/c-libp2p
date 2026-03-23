/* test_multistream.c — tests for multistream-select protocol negotiation */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <uv.h>

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/multiaddr.h"
#include "transport/transport.h"
#include "transport/tcp/tcp_transport.h"
#include "protocol/multistream.h"
#include "listener.h"
#include "dialer.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL: %s (line %d)\n", msg, __LINE__); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_RUN(fn) do { \
    printf("  Running %s...\n", #fn); \
    fn(); \
    tests_passed++; \
    printf("  PASS: %s\n", #fn); \
} while(0)

/* ── Test: varint encode/decode ───────────────────────────────────────────── */

static void test_varint_roundtrip(void)
{
    uint8_t buf[10];

    /* Small value */
    size_t n = ms_varint_encode(42, buf);
    TEST_ASSERT(n == 1, "42 should encode as 1 byte");
    TEST_ASSERT(buf[0] == 42, "42 should encode to 42");

    uint64_t val;
    size_t consumed;
    int rc = ms_varint_decode(buf, n, &val, &consumed);
    TEST_ASSERT(rc == 0, "decode should succeed");
    TEST_ASSERT(val == 42, "decoded value should be 42");
    TEST_ASSERT(consumed == 1, "consumed should be 1");

    /* Larger value needing 2 bytes */
    n = ms_varint_encode(300, buf);
    TEST_ASSERT(n == 2, "300 should encode as 2 bytes");
    rc = ms_varint_decode(buf, n, &val, &consumed);
    TEST_ASSERT(rc == 0, "decode should succeed");
    TEST_ASSERT(val == 300, "decoded value should be 300");
    TEST_ASSERT(consumed == 2, "consumed should be 2");
}

/* ── Test: frame encode/decode ────────────────────────────────────────────── */

static void test_frame_roundtrip(void)
{
    uint8_t frame[256];

    size_t flen = ms_frame_encode("/multistream/1.0.0", frame, sizeof(frame));
    TEST_ASSERT(flen > 0, "frame encode should succeed");

    const uint8_t *msg;
    size_t msg_len;
    int consumed = ms_frame_decode(frame, flen, &msg, &msg_len);
    TEST_ASSERT(consumed > 0, "frame decode should succeed");
    TEST_ASSERT((size_t)consumed == flen, "should consume entire frame");
    TEST_ASSERT(msg_len == strlen("/multistream/1.0.0"),
                "msg length should match");
    TEST_ASSERT(memcmp(msg, "/multistream/1.0.0", msg_len) == 0,
                "msg content should match");
}

/* ── Test: frame decode with partial data ─────────────────────────────────── */

static void test_frame_decode_partial(void)
{
    uint8_t frame[256];
    size_t flen = ms_frame_encode("test", frame, sizeof(frame));
    TEST_ASSERT(flen > 0, "encode should succeed");

    /* Feed only partial data */
    const uint8_t *msg;
    size_t msg_len;
    int consumed = ms_frame_decode(frame, 1, &msg, &msg_len);
    TEST_ASSERT(consumed == 0, "partial data should return 0 (need more)");

    /* Feed complete data */
    consumed = ms_frame_decode(frame, flen, &msg, &msg_len);
    TEST_ASSERT(consumed > 0, "complete data should decode");
    TEST_ASSERT(msg_len == 4, "msg should be 4 bytes");
    TEST_ASSERT(memcmp(msg, "test", 4) == 0, "content should match");
}

/* ── Test: "na" frame ─────────────────────────────────────────────────────── */

static void test_frame_na(void)
{
    uint8_t frame[64];
    size_t flen = ms_frame_encode("na", frame, sizeof(frame));
    TEST_ASSERT(flen > 0, "na frame encode should succeed");

    const uint8_t *msg;
    size_t msg_len;
    int consumed = ms_frame_decode(frame, flen, &msg, &msg_len);
    TEST_ASSERT(consumed > 0, "na frame decode should succeed");
    TEST_ASSERT(msg_len == 2, "na msg length should be 2");
    TEST_ASSERT(memcmp(msg, "na", 2) == 0, "content should be 'na'");
}

/* ── Test: full negotiation over loopback ─────────────────────────────────── */

typedef struct {
    lp2p_tcp_conn_t *server_tc;
    lp2p_tcp_conn_t *client_tc;
    bool initiator_done;
    bool responder_done;
    lp2p_err_t initiator_err;
    lp2p_err_t responder_err;
    char initiator_proto[256];
    char responder_proto[256];
    uv_timer_t stop_timer;
    const char **supported_protos;
    size_t supported_count;
} ms_test_ctx_t;

static void ms_stop_cb(uv_timer_t *handle)
{
    uv_stop(handle->loop);
}

static void on_initiator_done(lp2p_err_t err, const char *protocol, void *userdata)
{
    ms_test_ctx_t *ctx = (ms_test_ctx_t *)userdata;
    ctx->initiator_err = err;
    ctx->initiator_done = true;
    if (protocol) {
        strncpy(ctx->initiator_proto, protocol, sizeof(ctx->initiator_proto) - 1);
    }
    if (ctx->responder_done) {
        uv_timer_start(&ctx->stop_timer, ms_stop_cb, 50, 0);
    }
}

static void on_responder_done(lp2p_err_t err, const char *protocol, void *userdata)
{
    ms_test_ctx_t *ctx = (ms_test_ctx_t *)userdata;
    ctx->responder_err = err;
    ctx->responder_done = true;
    if (protocol) {
        strncpy(ctx->responder_proto, protocol, sizeof(ctx->responder_proto) - 1);
    }
    if (ctx->initiator_done) {
        uv_timer_start(&ctx->stop_timer, ms_stop_cb, 50, 0);
    }
}

static void ms_on_server_conn(lp2p_listener_t *listener, lp2p_conn_t *conn,
                               void *userdata)
{
    ms_test_ctx_t *ctx = (ms_test_ctx_t *)userdata;
    ctx->server_tc = (lp2p_tcp_conn_t *)conn;

    /* Start responder negotiation */
    ms_negotiate_responder(ctx->server_tc,
                           ctx->supported_protos,
                           ctx->supported_count,
                           on_responder_done, ctx);
}

static void ms_on_dial_conn(lp2p_conn_t *conn, lp2p_err_t err, void *userdata)
{
    ms_test_ctx_t *ctx = (ms_test_ctx_t *)userdata;
    if (err != LP2P_OK) return;
    ctx->client_tc = (lp2p_tcp_conn_t *)conn;

    /* Start initiator negotiation */
    ms_negotiate_initiator(ctx->client_tc, "/noise", on_initiator_done, ctx);
}

static void test_negotiation_success(void)
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    lp2p_transport_t *t = NULL;
    lp2p_tcp_transport_new(&loop, &t);

    lp2p_multiaddr_t *listen_addr = NULL;
    lp2p_multiaddr_parse("/ip4/127.0.0.1/tcp/0", &listen_addr);
    if (!listen_addr) {
        printf("  SKIP: multiaddr_parse not yet implemented\n");
        lp2p_tcp_transport_free(t);
        uv_loop_close(&loop);
        return;
    }

    lp2p_listener_t *listener = NULL;
    lp2p_listener_new(&loop, t, listen_addr, &listener);

    const char *protos[] = { "/noise", "/yamux/1.0.0" };
    ms_test_ctx_t ctx = {0};
    ctx.supported_protos = protos;
    ctx.supported_count = 2;
    uv_timer_init(&loop, &ctx.stop_timer);

    lp2p_listener_start(listener, ms_on_server_conn, &ctx);

    lp2p_tcp_transport_t *impl = (lp2p_tcp_transport_t *)t->impl;
    struct sockaddr_storage bound_addr;
    int namelen = sizeof(bound_addr);
    uv_tcp_getsockname(&impl->server, (struct sockaddr *)&bound_addr, &namelen);
    int port = ntohs(((struct sockaddr_in *)&bound_addr)->sin_port);

    char dial_str[64];
    snprintf(dial_str, sizeof(dial_str), "/ip4/127.0.0.1/tcp/%d", port);
    lp2p_multiaddr_t *dial_addr = NULL;
    lp2p_multiaddr_parse(dial_str, &dial_addr);

    lp2p_dialer_t *dialer = NULL;
    lp2p_dialer_new(&loop, t, 5000, &dialer);
    lp2p_dialer_dial(dialer, dial_addr, ms_on_dial_conn, &ctx);

    uv_timer_t safety;
    uv_timer_init(&loop, &safety);
    uv_timer_start(&safety, ms_stop_cb, 5000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    TEST_ASSERT(ctx.initiator_done, "initiator should have completed");
    TEST_ASSERT(ctx.responder_done, "responder should have completed");
    TEST_ASSERT(ctx.initiator_err == LP2P_OK, "initiator should succeed");
    TEST_ASSERT(ctx.responder_err == LP2P_OK, "responder should succeed");
    TEST_ASSERT(strcmp(ctx.initiator_proto, "/noise") == 0,
                "initiator should negotiate /noise");
    TEST_ASSERT(strcmp(ctx.responder_proto, "/noise") == 0,
                "responder should negotiate /noise");

    /* Cleanup */
    if (ctx.server_tc) lp2p_tcp_conn_close(ctx.server_tc, NULL, NULL);
    if (ctx.client_tc) lp2p_tcp_conn_close(ctx.client_tc, NULL, NULL);
    uv_run(&loop, UV_RUN_NOWAIT);

    lp2p_listener_free(listener);
    lp2p_dialer_free(dialer);
    if (dial_addr) lp2p_multiaddr_free(dial_addr);
    lp2p_multiaddr_free(listen_addr);
    lp2p_tcp_transport_free(t);

    uv_timer_stop(&safety);
    uv_close((uv_handle_t *)&safety, NULL);
    uv_close((uv_handle_t *)&ctx.stop_timer, NULL);
    uv_run(&loop, UV_RUN_NOWAIT);
    uv_loop_close(&loop);
}

/* ── Test: negotiation failure (unsupported protocol) ─────────────────────── */

static void ms_fail_on_dial_conn(lp2p_conn_t *conn, lp2p_err_t err, void *userdata)
{
    ms_test_ctx_t *ctx = (ms_test_ctx_t *)userdata;
    if (err != LP2P_OK) return;
    ctx->client_tc = (lp2p_tcp_conn_t *)conn;

    /* Propose a protocol the server doesn't support */
    ms_negotiate_initiator(ctx->client_tc, "/unsupported/1.0.0",
                           on_initiator_done, ctx);
}

static void test_negotiation_failure(void)
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    lp2p_transport_t *t = NULL;
    lp2p_tcp_transport_new(&loop, &t);

    lp2p_multiaddr_t *listen_addr = NULL;
    lp2p_multiaddr_parse("/ip4/127.0.0.1/tcp/0", &listen_addr);
    if (!listen_addr) {
        printf("  SKIP: multiaddr_parse not yet implemented\n");
        lp2p_tcp_transport_free(t);
        uv_loop_close(&loop);
        return;
    }

    lp2p_listener_t *listener = NULL;
    lp2p_listener_new(&loop, t, listen_addr, &listener);

    const char *protos[] = { "/noise" };
    ms_test_ctx_t ctx = {0};
    ctx.supported_protos = protos;
    ctx.supported_count = 1;
    uv_timer_init(&loop, &ctx.stop_timer);

    lp2p_listener_start(listener, ms_on_server_conn, &ctx);

    lp2p_tcp_transport_t *impl = (lp2p_tcp_transport_t *)t->impl;
    struct sockaddr_storage bound_addr;
    int namelen = sizeof(bound_addr);
    uv_tcp_getsockname(&impl->server, (struct sockaddr *)&bound_addr, &namelen);
    int port = ntohs(((struct sockaddr_in *)&bound_addr)->sin_port);

    char dial_str[64];
    snprintf(dial_str, sizeof(dial_str), "/ip4/127.0.0.1/tcp/%d", port);
    lp2p_multiaddr_t *dial_addr = NULL;
    lp2p_multiaddr_parse(dial_str, &dial_addr);

    lp2p_dialer_t *dialer = NULL;
    lp2p_dialer_new(&loop, t, 5000, &dialer);
    lp2p_dialer_dial(dialer, dial_addr, ms_fail_on_dial_conn, &ctx);

    uv_timer_t safety;
    uv_timer_init(&loop, &safety);
    uv_timer_start(&safety, ms_stop_cb, 5000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    TEST_ASSERT(ctx.initiator_done, "initiator should have completed");
    TEST_ASSERT(ctx.initiator_err == LP2P_ERR_PROTOCOL_NOT_SUPPORTED,
                "initiator should get PROTOCOL_NOT_SUPPORTED");

    /* Cleanup */
    if (ctx.server_tc) lp2p_tcp_conn_close(ctx.server_tc, NULL, NULL);
    if (ctx.client_tc) lp2p_tcp_conn_close(ctx.client_tc, NULL, NULL);
    uv_run(&loop, UV_RUN_NOWAIT);

    lp2p_listener_free(listener);
    lp2p_dialer_free(dialer);
    if (dial_addr) lp2p_multiaddr_free(dial_addr);
    lp2p_multiaddr_free(listen_addr);
    lp2p_tcp_transport_free(t);

    uv_timer_stop(&safety);
    uv_close((uv_handle_t *)&safety, NULL);
    uv_close((uv_handle_t *)&ctx.stop_timer, NULL);
    uv_run(&loop, UV_RUN_NOWAIT);
    uv_loop_close(&loop);
}

/* ── Main ─────────────────────────────────────────────────────────────────── */

int main(void)
{
    printf("test_multistream:\n");

    TEST_RUN(test_varint_roundtrip);
    TEST_RUN(test_frame_roundtrip);
    TEST_RUN(test_frame_decode_partial);
    TEST_RUN(test_frame_na);
    TEST_RUN(test_negotiation_success);
    TEST_RUN(test_negotiation_failure);

    printf("\n  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
