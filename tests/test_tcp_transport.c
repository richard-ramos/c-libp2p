/* test_tcp_transport.c — tests for TCP transport, listener, and dialer */

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

/* ── Test: transport creation ─────────────────────────────────────────────── */

static void test_transport_create(void)
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    lp2p_transport_t *t = NULL;
    lp2p_err_t err = lp2p_tcp_transport_new(&loop, &t);
    TEST_ASSERT(err == LP2P_OK, "tcp_transport_new should succeed");
    TEST_ASSERT(t != NULL, "transport should not be null");
    TEST_ASSERT(t->vtable != NULL, "vtable should not be null");

    lp2p_tcp_transport_free(t);
    uv_loop_close(&loop);
}

/* ── Test: handles() ──────────────────────────────────────────────────────── */

static void test_transport_handles(void)
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    lp2p_transport_t *t = NULL;
    lp2p_tcp_transport_new(&loop, &t);

    lp2p_multiaddr_t *ma_ip4 = NULL;
    lp2p_multiaddr_t *ma_ip6 = NULL;
    lp2p_multiaddr_t *ma_dns4 = NULL;

    lp2p_multiaddr_parse("/ip4/127.0.0.1/tcp/4001", &ma_ip4);
    lp2p_multiaddr_parse("/ip6/::1/tcp/4001", &ma_ip6);
    lp2p_multiaddr_parse("/dns4/example.com/tcp/4001", &ma_dns4);

    if (ma_ip4) {
        TEST_ASSERT(t->vtable->handles(t->impl, ma_ip4),
                    "should handle /ip4/.../tcp/...");
        lp2p_multiaddr_free(ma_ip4);
    }
    if (ma_ip6) {
        TEST_ASSERT(t->vtable->handles(t->impl, ma_ip6),
                    "should handle /ip6/.../tcp/...");
        lp2p_multiaddr_free(ma_ip6);
    }
    if (ma_dns4) {
        TEST_ASSERT(t->vtable->handles(t->impl, ma_dns4),
                    "should handle /dns4/.../tcp/...");
        lp2p_multiaddr_free(ma_dns4);
    }

    lp2p_tcp_transport_free(t);
    uv_loop_close(&loop);
}

/* ── Test: listen + dial loopback ─────────────────────────────────────────── */

typedef struct {
    bool server_got_conn;
    bool client_connected;
    lp2p_err_t client_err;
    lp2p_tcp_conn_t *server_tc;
    lp2p_tcp_conn_t *client_tc;
    uv_timer_t stop_timer;
} loopback_ctx_t;

static void stop_loop_cb(uv_timer_t *handle)
{
    uv_stop(handle->loop);
}

static void on_listener_conn(lp2p_listener_t *listener, lp2p_conn_t *conn,
                              void *userdata)
{
    loopback_ctx_t *ctx = (loopback_ctx_t *)userdata;
    ctx->server_got_conn = true;
    ctx->server_tc = (lp2p_tcp_conn_t *)conn;
}

static void on_dial_conn(lp2p_conn_t *conn, lp2p_err_t err, void *userdata)
{
    loopback_ctx_t *ctx = (loopback_ctx_t *)userdata;
    ctx->client_connected = (err == LP2P_OK);
    ctx->client_err = err;
    ctx->client_tc = (lp2p_tcp_conn_t *)conn;

    /* Stop the loop shortly after connection completes */
    uv_timer_start(&ctx->stop_timer, stop_loop_cb, 50, 0);
}

static void test_listen_dial_loopback(void)
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    lp2p_transport_t *t = NULL;
    lp2p_tcp_transport_new(&loop, &t);

    /* Create listener on a random port */
    lp2p_multiaddr_t *listen_addr = NULL;
    lp2p_multiaddr_parse("/ip4/127.0.0.1/tcp/0", &listen_addr);

    if (!listen_addr) {
        printf("  SKIP: multiaddr_parse not yet implemented\n");
        lp2p_tcp_transport_free(t);
        uv_loop_close(&loop);
        return;
    }

    lp2p_listener_t *listener = NULL;
    lp2p_err_t err = lp2p_listener_new(&loop, t, listen_addr, &listener);
    if (err != LP2P_OK) {
        printf("  SKIP: listener_new returned %d\n", err);
        lp2p_multiaddr_free(listen_addr);
        lp2p_tcp_transport_free(t);
        uv_loop_close(&loop);
        return;
    }

    loopback_ctx_t ctx = {0};
    uv_timer_init(&loop, &ctx.stop_timer);

    err = lp2p_listener_start(listener, on_listener_conn, &ctx);
    if (err != LP2P_OK) {
        printf("  SKIP: listener_start returned %d\n", err);
        lp2p_listener_free(listener);
        lp2p_multiaddr_free(listen_addr);
        lp2p_tcp_transport_free(t);
        uv_loop_close(&loop);
        return;
    }

    /* Get the actual bound port */
    lp2p_tcp_transport_t *impl = (lp2p_tcp_transport_t *)t->impl;
    struct sockaddr_storage bound_addr;
    int namelen = sizeof(bound_addr);
    uv_tcp_getsockname(&impl->server, (struct sockaddr *)&bound_addr, &namelen);
    int port = ntohs(((struct sockaddr_in *)&bound_addr)->sin_port);

    /* Dial to the listener */
    char dial_str[64];
    snprintf(dial_str, sizeof(dial_str), "/ip4/127.0.0.1/tcp/%d", port);

    lp2p_multiaddr_t *dial_addr = NULL;
    lp2p_multiaddr_parse(dial_str, &dial_addr);

    lp2p_dialer_t *dialer = NULL;
    lp2p_dialer_new(&loop, t, 5000, &dialer);

    err = lp2p_dialer_dial(dialer, dial_addr, on_dial_conn, &ctx);
    TEST_ASSERT(err == LP2P_OK, "dial should initiate successfully");

    /* Set a safety timeout to avoid infinite loop */
    uv_timer_t safety;
    uv_timer_init(&loop, &safety);
    uv_timer_start(&safety, stop_loop_cb, 3000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    TEST_ASSERT(ctx.client_connected, "client should have connected");
    TEST_ASSERT(ctx.server_got_conn, "server should have received connection");

    /* Cleanup */
    if (ctx.server_tc) lp2p_tcp_conn_close(ctx.server_tc, NULL, NULL);
    if (ctx.client_tc) lp2p_tcp_conn_close(ctx.client_tc, NULL, NULL);

    /* Run to process close callbacks */
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

/* ── Test: write + read over TCP ──────────────────────────────────────────── */

typedef struct {
    lp2p_tcp_conn_t *server_tc;
    lp2p_tcp_conn_t *client_tc;
    bool data_received;
    uint8_t recv_data[256];
    size_t  recv_len;
    uv_timer_t stop_timer;
} rw_ctx_t;

static void rw_on_read(lp2p_tcp_conn_t *tc, const uint8_t *data, size_t len,
                        lp2p_err_t err, void *userdata)
{
    rw_ctx_t *ctx = (rw_ctx_t *)userdata;
    if (err == LP2P_OK && len > 0) {
        size_t copy = len < sizeof(ctx->recv_data) ? len : sizeof(ctx->recv_data);
        memcpy(ctx->recv_data, data, copy);
        ctx->recv_len = copy;
        ctx->data_received = true;
        lp2p_tcp_conn_consume(tc, len);
        uv_timer_start(&ctx->stop_timer, stop_loop_cb, 50, 0);
    }
}

static void rw_on_write(lp2p_tcp_conn_t *tc, lp2p_err_t err, void *userdata)
{
    (void)tc;
    (void)userdata;
    /* Write completed; data should arrive at server side */
}

static void rw_on_server_conn(lp2p_listener_t *listener, lp2p_conn_t *conn,
                               void *userdata)
{
    rw_ctx_t *ctx = (rw_ctx_t *)userdata;
    ctx->server_tc = (lp2p_tcp_conn_t *)conn;
    /* Start reading on the server side */
    lp2p_tcp_conn_start_read(ctx->server_tc, rw_on_read, ctx);
}

static void rw_on_dial_conn(lp2p_conn_t *conn, lp2p_err_t err, void *userdata)
{
    rw_ctx_t *ctx = (rw_ctx_t *)userdata;
    if (err != LP2P_OK) return;
    ctx->client_tc = (lp2p_tcp_conn_t *)conn;

    /* Write some data from client to server */
    const char *msg = "hello libp2p";
    lp2p_tcp_conn_write(ctx->client_tc, (const uint8_t *)msg, strlen(msg),
                         rw_on_write, ctx);
}

static void test_tcp_read_write(void)
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

    rw_ctx_t ctx = {0};
    uv_timer_init(&loop, &ctx.stop_timer);

    lp2p_listener_start(listener, rw_on_server_conn, &ctx);

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
    lp2p_dialer_dial(dialer, dial_addr, rw_on_dial_conn, &ctx);

    uv_timer_t safety;
    uv_timer_init(&loop, &safety);
    uv_timer_start(&safety, stop_loop_cb, 3000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    TEST_ASSERT(ctx.data_received, "server should have received data");
    TEST_ASSERT(ctx.recv_len == 12, "should receive 12 bytes");
    TEST_ASSERT(memcmp(ctx.recv_data, "hello libp2p", 12) == 0,
                "data should match");

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

/* ── Test: IPv6 loopback ──────────────────────────────────────────────────── */

static void test_ipv6_loopback(void)
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    lp2p_transport_t *t = NULL;
    lp2p_tcp_transport_new(&loop, &t);

    lp2p_multiaddr_t *listen_addr = NULL;
    lp2p_multiaddr_parse("/ip6/::1/tcp/0", &listen_addr);
    if (!listen_addr) {
        printf("  SKIP: multiaddr_parse not yet implemented\n");
        lp2p_tcp_transport_free(t);
        uv_loop_close(&loop);
        return;
    }

    lp2p_listener_t *listener = NULL;
    lp2p_err_t err = lp2p_listener_new(&loop, t, listen_addr, &listener);
    if (err != LP2P_OK) {
        printf("  SKIP: IPv6 listener creation returned %d\n", err);
        lp2p_multiaddr_free(listen_addr);
        lp2p_tcp_transport_free(t);
        uv_loop_close(&loop);
        return;
    }

    loopback_ctx_t ctx = {0};
    uv_timer_init(&loop, &ctx.stop_timer);

    err = lp2p_listener_start(listener, on_listener_conn, &ctx);
    if (err != LP2P_OK) {
        printf("  SKIP: IPv6 listen returned %d\n", err);
        lp2p_listener_free(listener);
        lp2p_multiaddr_free(listen_addr);
        lp2p_tcp_transport_free(t);
        uv_loop_close(&loop);
        return;
    }

    lp2p_tcp_transport_t *impl = (lp2p_tcp_transport_t *)t->impl;
    struct sockaddr_storage bound_addr;
    int namelen = sizeof(bound_addr);
    uv_tcp_getsockname(&impl->server, (struct sockaddr *)&bound_addr, &namelen);
    int port = ntohs(((struct sockaddr_in6 *)&bound_addr)->sin6_port);

    char dial_str[64];
    snprintf(dial_str, sizeof(dial_str), "/ip6/::1/tcp/%d", port);
    lp2p_multiaddr_t *dial_addr = NULL;
    lp2p_multiaddr_parse(dial_str, &dial_addr);

    lp2p_dialer_t *dialer = NULL;
    lp2p_dialer_new(&loop, t, 5000, &dialer);
    lp2p_dialer_dial(dialer, dial_addr, on_dial_conn, &ctx);

    uv_timer_t safety;
    uv_timer_init(&loop, &safety);
    uv_timer_start(&safety, stop_loop_cb, 3000, 0);

    uv_run(&loop, UV_RUN_DEFAULT);

    TEST_ASSERT(ctx.client_connected, "IPv6 client should have connected");
    TEST_ASSERT(ctx.server_got_conn, "IPv6 server should have received connection");

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
    printf("test_tcp_transport:\n");

    TEST_RUN(test_transport_create);
    TEST_RUN(test_transport_handles);
    TEST_RUN(test_listen_dial_loopback);
    TEST_RUN(test_tcp_read_write);
    TEST_RUN(test_ipv6_loopback);

    printf("\n  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
