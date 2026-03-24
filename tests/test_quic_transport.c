/* test_quic_transport.c — tests for QUIC transport, listener, dialer, and streams */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/crypto.h"
#include "libp2p/multiaddr.h"
#include "libp2p/connection.h"
#include "libp2p/stream.h"
#include "libp2p/protocol.h"
#include "transport/transport.h"
#include "transport/quic/quic_transport.h"
#include "listener.h"
#include "dialer.h"
#include "protocol_router.h"
#include "connection_internal.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL: %s (line %d)\n", msg, __LINE__); \
        tests_failed++; \
        goto cleanup; \
    } \
} while (0)

#define TEST_RUN(fn) do { \
    int failed_before = tests_failed; \
    printf("  Running %s...\n", #fn); \
    fn(); \
    if (tests_failed == failed_before) { \
        tests_passed++; \
        printf("  PASS: %s\n", #fn); \
    } \
} while (0)

#define TEST_PROTO "/test/quic/1.0.0"
#define TEST_MESSAGE "hello quic transport"
#define LARGE_TEST_MESSAGE_LEN (128 * 1024)

typedef struct {
    lp2p_keypair_t *server_kp;
    lp2p_keypair_t *client_kp;
    lp2p_transport_t *server_transport;
    lp2p_transport_t *client_transport;
    lp2p_listener_t *listener;
    lp2p_dialer_t *dialer;
    lp2p_multiaddr_t *listen_addr;
    lp2p_multiaddr_t *dial_addr;
    lp2p_protocol_router_t *server_router;
    lp2p_conn_t *server_conn;
    lp2p_conn_t *client_conn;
    bool server_got_conn;
    bool client_connected;
    lp2p_err_t client_err;
    bool server_received;
    bool client_received;
    char server_msg[128];
    char client_msg[128];
    uint8_t *large_msg;
    size_t large_msg_len;
    bool server_large_received;
    bool client_large_received;
    uv_timer_t stop_timer;
    uv_timer_t safety_timer;
    bool stop_timer_init;
    bool safety_timer_init;
} quic_fixture_t;

static void stop_loop_cb(uv_timer_t *handle)
{
    uv_stop(handle->loop);
}

static void quic_fixture_cleanup(uv_loop_t *loop, quic_fixture_t *fx)
{
    if (fx->listener) lp2p_listener_free(fx->listener);
    if (fx->dialer) lp2p_dialer_free(fx->dialer);
    if (fx->dial_addr) lp2p_multiaddr_free(fx->dial_addr);
    if (fx->listen_addr) lp2p_multiaddr_free(fx->listen_addr);
    if (fx->server_transport) lp2p_quic_transport_free(fx->server_transport);
    if (fx->client_transport) lp2p_quic_transport_free(fx->client_transport);
    if (fx->server_router) lp2p_protocol_router_free(fx->server_router);
    if (fx->server_kp) lp2p_keypair_free(fx->server_kp);
    if (fx->client_kp) lp2p_keypair_free(fx->client_kp);
    free(fx->large_msg);

    if (fx->safety_timer_init) {
        uv_timer_stop(&fx->safety_timer);
        uv_close((uv_handle_t *)&fx->safety_timer, NULL);
    }
    if (fx->stop_timer_init) {
        uv_timer_stop(&fx->stop_timer);
        uv_close((uv_handle_t *)&fx->stop_timer, NULL);
    }

    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
}

static lp2p_err_t quic_fixture_init(uv_loop_t *loop, quic_fixture_t *fx)
{
    memset(fx, 0, sizeof(*fx));
    fx->client_err = LP2P_ERR_INTERNAL;

    if (uv_timer_init(loop, &fx->stop_timer) != 0) {
        return LP2P_ERR_INTERNAL;
    }
    fx->stop_timer_init = true;

    if (uv_timer_init(loop, &fx->safety_timer) != 0) {
        return LP2P_ERR_INTERNAL;
    }
    fx->safety_timer_init = true;

    lp2p_err_t err = lp2p_keypair_generate(LP2P_KEY_ED25519, &fx->server_kp);
    if (err != LP2P_OK) return err;

    err = lp2p_keypair_generate(LP2P_KEY_ED25519, &fx->client_kp);
    if (err != LP2P_OK) return err;

    err = lp2p_quic_transport_new(loop, fx->server_kp, &fx->server_transport);
    if (err != LP2P_OK) return err;

    err = lp2p_quic_transport_new(loop, fx->client_kp, &fx->client_transport);
    if (err != LP2P_OK) return err;

    return LP2P_OK;
}

static int quic_bound_port(lp2p_transport_t *transport)
{
    quic_transport_t *impl = (quic_transport_t *)transport->impl;
    struct sockaddr_storage bound_addr;
    int namelen = sizeof(bound_addr);

    if (uv_udp_getsockname(&impl->udp_server, (struct sockaddr *)&bound_addr, &namelen) != 0) {
        return -1;
    }

    if (bound_addr.ss_family == AF_INET) {
        return ntohs(((struct sockaddr_in *)&bound_addr)->sin_port);
    }

    if (bound_addr.ss_family == AF_INET6) {
        return ntohs(((struct sockaddr_in6 *)&bound_addr)->sin6_port);
    }

    return -1;
}

static lp2p_err_t make_quic_dial_addr(const lp2p_keypair_t *server_kp,
                                      int port,
                                      lp2p_multiaddr_t **out)
{
    lp2p_peer_id_t server_peer;
    lp2p_err_t err = lp2p_peer_id_from_keypair(server_kp, &server_peer);
    if (err != LP2P_OK) return err;

    char peer_str[128] = {0};
    size_t peer_len = sizeof(peer_str) - 1;
    err = lp2p_peer_id_to_string(&server_peer, peer_str, &peer_len);
    if (err != LP2P_OK) return err;
    peer_str[peer_len] = '\0';

    char dial_str[256];
    snprintf(dial_str, sizeof(dial_str),
             "/ip4/127.0.0.1/udp/%d/quic-v1/p2p/%s",
             port, peer_str);
    return lp2p_multiaddr_parse(dial_str, out);
}

static void fill_large_test_message(uint8_t *buf, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        buf[i] = (uint8_t)(((i * 31u) + 7u) & 0xffu);
    }
}

static void on_listener_conn(lp2p_listener_t *listener, lp2p_conn_t *conn, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;
    (void)listener;

    fx->server_got_conn = true;
    fx->server_conn = conn;

    if (fx->server_router) {
        lp2p_conn_set_protocol_router(conn, fx->server_router);
    }
}

static void on_dial_conn(lp2p_conn_t *conn, lp2p_err_t err, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;

    fx->client_connected = (err == LP2P_OK);
    fx->client_err = err;
    fx->client_conn = conn;

    uv_timer_start(&fx->stop_timer, stop_loop_cb, 100, 0);
}

static void server_echo_write_done(lp2p_stream_t *stream, lp2p_err_t err, void *userdata)
{
    (void)userdata;
    if (err == LP2P_OK) {
        lp2p_stream_close(stream, NULL, NULL);
    } else {
        lp2p_stream_reset(stream);
    }
}

static void server_echo_on_read(lp2p_stream_t *stream, lp2p_err_t err,
                                const lp2p_buf_t *buf, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;

    if (err != LP2P_OK || !buf || buf->len >= sizeof(fx->server_msg)) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
        return;
    }

    memcpy(fx->server_msg, buf->data, buf->len);
    fx->server_msg[buf->len] = '\0';
    fx->server_received = true;

    lp2p_buf_t reply = {
        .data = buf->data,
        .len = buf->len,
    };
    lp2p_err_t werr = lp2p_stream_write_lp(stream, &reply, server_echo_write_done, fx);
    if (werr != LP2P_OK) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
    }
}

static void server_echo_handler(lp2p_stream_t *stream, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;
    lp2p_err_t err = lp2p_stream_read_lp(stream, sizeof(fx->server_msg) - 1,
                                         server_echo_on_read, fx);
    if (err != LP2P_OK) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
    }
}

static void client_echo_on_read(lp2p_stream_t *stream, lp2p_err_t err,
                                const lp2p_buf_t *buf, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;

    if (err != LP2P_OK || !buf || buf->len >= sizeof(fx->client_msg)) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
        return;
    }

    memcpy(fx->client_msg, buf->data, buf->len);
    fx->client_msg[buf->len] = '\0';
    fx->client_received = true;

    lp2p_stream_close(stream, NULL, NULL);
    uv_timer_start(&fx->stop_timer, stop_loop_cb, 50, 0);
}

static void client_echo_on_write(lp2p_stream_t *stream, lp2p_err_t err, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;

    if (err != LP2P_OK) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
        return;
    }

    lp2p_err_t rerr = lp2p_stream_read_lp(stream, sizeof(fx->client_msg) - 1,
                                          client_echo_on_read, fx);
    if (rerr != LP2P_OK) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
    }
}

static void client_echo_on_stream(lp2p_stream_t *stream, lp2p_err_t err, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;

    if (err != LP2P_OK || !stream) {
        fx->client_err = err;
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
        return;
    }

    lp2p_buf_t msg = {
        .data = (const uint8_t *)TEST_MESSAGE,
        .len = strlen(TEST_MESSAGE),
    };
    lp2p_err_t werr = lp2p_stream_write_lp(stream, &msg, client_echo_on_write, fx);
    if (werr != LP2P_OK) {
        fx->client_err = werr;
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
    }
}

static void on_dial_conn_rw(lp2p_conn_t *conn, lp2p_err_t err, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;

    fx->client_connected = (err == LP2P_OK);
    fx->client_err = err;
    fx->client_conn = conn;

    if (err != LP2P_OK || !conn) {
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
        return;
    }

    lp2p_err_t serr = lp2p_conn_open_stream(conn, TEST_PROTO,
                                            client_echo_on_stream, fx);
    if (serr != LP2P_OK) {
        fx->client_err = serr;
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
    }
}

static void server_large_echo_on_read(lp2p_stream_t *stream, lp2p_err_t err,
                                      const lp2p_buf_t *buf, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;

    if (err != LP2P_OK || !buf || buf->len != fx->large_msg_len ||
        memcmp(buf->data, fx->large_msg, fx->large_msg_len) != 0) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
        return;
    }

    fx->server_large_received = true;

    lp2p_buf_t reply = {
        .data = buf->data,
        .len = buf->len,
    };
    lp2p_err_t werr = lp2p_stream_write_lp(stream, &reply, server_echo_write_done, fx);
    if (werr != LP2P_OK) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
    }
}

static void server_large_echo_handler(lp2p_stream_t *stream, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;
    lp2p_err_t err = lp2p_stream_read_lp(stream, fx->large_msg_len,
                                         server_large_echo_on_read, fx);
    if (err != LP2P_OK) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
    }
}

static void client_large_echo_on_read(lp2p_stream_t *stream, lp2p_err_t err,
                                      const lp2p_buf_t *buf, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;

    if (err != LP2P_OK || !buf || buf->len != fx->large_msg_len ||
        memcmp(buf->data, fx->large_msg, fx->large_msg_len) != 0) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
        return;
    }

    fx->client_large_received = true;

    lp2p_stream_close(stream, NULL, NULL);
    uv_timer_start(&fx->stop_timer, stop_loop_cb, 100, 0);
}

static void client_large_echo_on_write(lp2p_stream_t *stream, lp2p_err_t err, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;

    if (err != LP2P_OK) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
        return;
    }

    lp2p_err_t rerr = lp2p_stream_read_lp(stream, fx->large_msg_len,
                                          client_large_echo_on_read, fx);
    if (rerr != LP2P_OK) {
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
    }
}

static void client_large_echo_on_stream(lp2p_stream_t *stream, lp2p_err_t err, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;

    if (err != LP2P_OK || !stream) {
        fx->client_err = err;
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
        return;
    }

    lp2p_buf_t msg = {
        .data = fx->large_msg,
        .len = fx->large_msg_len,
    };
    lp2p_err_t werr = lp2p_stream_write_lp(stream, &msg, client_large_echo_on_write, fx);
    if (werr != LP2P_OK) {
        fx->client_err = werr;
        lp2p_stream_reset(stream);
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
    }
}

static void on_dial_conn_rw_large(lp2p_conn_t *conn, lp2p_err_t err, void *userdata)
{
    quic_fixture_t *fx = (quic_fixture_t *)userdata;

    fx->client_connected = (err == LP2P_OK);
    fx->client_err = err;
    fx->client_conn = conn;

    if (err != LP2P_OK || !conn) {
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
        return;
    }

    lp2p_err_t serr = lp2p_conn_open_stream(conn, TEST_PROTO,
                                            client_large_echo_on_stream, fx);
    if (serr != LP2P_OK) {
        fx->client_err = serr;
        uv_timer_start(&fx->stop_timer, stop_loop_cb, 0, 0);
    }
}

static void test_transport_create(void)
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    quic_fixture_t fx = {0};
    lp2p_err_t err = quic_fixture_init(&loop, &fx);
    TEST_ASSERT(err == LP2P_OK, "quic_fixture_init should succeed");
    TEST_ASSERT(fx.server_transport != NULL, "server transport should not be null");
    TEST_ASSERT(fx.client_transport != NULL, "client transport should not be null");
    TEST_ASSERT(fx.server_transport->vtable != NULL, "server transport vtable should not be null");
    TEST_ASSERT(fx.client_transport->vtable != NULL, "client transport vtable should not be null");

cleanup:
    quic_fixture_cleanup(&loop, &fx);
}

static void test_transport_handles(void)
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    quic_fixture_t fx = {0};
    lp2p_err_t err = quic_fixture_init(&loop, &fx);
    TEST_ASSERT(err == LP2P_OK, "quic_fixture_init should succeed");

    lp2p_multiaddr_t *ma_ip4 = NULL;
    lp2p_multiaddr_t *ma_ip6 = NULL;
    lp2p_multiaddr_t *ma_tcp = NULL;

    lp2p_multiaddr_parse("/ip4/127.0.0.1/udp/4001/quic-v1", &ma_ip4);
    lp2p_multiaddr_parse("/ip6/::1/udp/4001/quic-v1", &ma_ip6);
    lp2p_multiaddr_parse("/ip4/127.0.0.1/tcp/4001", &ma_tcp);

    if (ma_ip4) {
        TEST_ASSERT(fx.server_transport->vtable->handles(fx.server_transport->impl, ma_ip4),
                    "should handle /ip4/.../udp/.../quic-v1");
    }
    if (ma_ip6) {
        TEST_ASSERT(fx.server_transport->vtable->handles(fx.server_transport->impl, ma_ip6),
                    "should handle /ip6/.../udp/.../quic-v1");
    }
    if (ma_tcp) {
        TEST_ASSERT(!fx.server_transport->vtable->handles(fx.server_transport->impl, ma_tcp),
                    "should not handle TCP multiaddrs");
    }

cleanup:
    if (ma_ip4) lp2p_multiaddr_free(ma_ip4);
    if (ma_ip6) lp2p_multiaddr_free(ma_ip6);
    if (ma_tcp) lp2p_multiaddr_free(ma_tcp);
    quic_fixture_cleanup(&loop, &fx);
}

static void test_listen_dial_loopback(void)
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    quic_fixture_t fx = {0};
    lp2p_peer_id_t server_peer = {0};
    lp2p_peer_id_t client_peer = {0};
    lp2p_peer_id_t client_seen = {0};
    lp2p_peer_id_t server_seen = {0};
    lp2p_err_t err = quic_fixture_init(&loop, &fx);
    TEST_ASSERT(err == LP2P_OK, "quic_fixture_init should succeed");

    err = lp2p_peer_id_from_keypair(fx.server_kp, &server_peer);
    TEST_ASSERT(err == LP2P_OK, "server peer id should derive");
    err = lp2p_peer_id_from_keypair(fx.client_kp, &client_peer);
    TEST_ASSERT(err == LP2P_OK, "client peer id should derive");

    err = lp2p_multiaddr_parse("/ip4/127.0.0.1/udp/0/quic-v1", &fx.listen_addr);
    TEST_ASSERT(err == LP2P_OK, "listen multiaddr should parse");

    err = lp2p_listener_new(&loop, fx.server_transport, fx.listen_addr, &fx.listener);
    TEST_ASSERT(err == LP2P_OK, "listener_new should succeed");

    err = lp2p_listener_start(fx.listener, on_listener_conn, &fx);
    TEST_ASSERT(err == LP2P_OK, "listener_start should succeed");

    int port = quic_bound_port(fx.server_transport);
    TEST_ASSERT(port > 0, "server UDP port should be discoverable");

    err = make_quic_dial_addr(fx.server_kp, port, &fx.dial_addr);
    TEST_ASSERT(err == LP2P_OK, "dial multiaddr should build");

    err = lp2p_dialer_new(&loop, fx.client_transport, 5000, &fx.dialer);
    TEST_ASSERT(err == LP2P_OK, "dialer_new should succeed");

    err = lp2p_dialer_dial(fx.dialer, fx.dial_addr, on_dial_conn, &fx);
    TEST_ASSERT(err == LP2P_OK, "dial should initiate successfully");

    uv_timer_start(&fx.safety_timer, stop_loop_cb, 5000, 0);
    uv_run(&loop, UV_RUN_DEFAULT);

    if (fx.client_conn) client_seen = lp2p_conn_peer_id(fx.client_conn);
    if (fx.server_conn) server_seen = lp2p_conn_peer_id(fx.server_conn);

    TEST_ASSERT(fx.client_connected, "client should have connected");
    TEST_ASSERT(fx.client_err == LP2P_OK, "client dial should succeed");
    TEST_ASSERT(fx.server_got_conn, "server should have received connection");
    TEST_ASSERT(lp2p_peer_id_equal(&client_seen, &server_peer),
                "client connection peer id should match server");
    TEST_ASSERT(lp2p_peer_id_equal(&server_seen, &client_peer),
                "server connection peer id should match client");

cleanup:
    quic_fixture_cleanup(&loop, &fx);
}

static void test_stream_read_write(void)
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    quic_fixture_t fx = {0};
    lp2p_err_t err = quic_fixture_init(&loop, &fx);
    TEST_ASSERT(err == LP2P_OK, "quic_fixture_init should succeed");

    fx.server_router = lp2p_protocol_router_new(&loop);
    TEST_ASSERT(fx.server_router != NULL, "server router should allocate");

    err = lp2p_protocol_router_add(fx.server_router, TEST_PROTO, server_echo_handler, &fx);
    TEST_ASSERT(err == LP2P_OK, "server router should register protocol");

    err = lp2p_multiaddr_parse("/ip4/127.0.0.1/udp/0/quic-v1", &fx.listen_addr);
    TEST_ASSERT(err == LP2P_OK, "listen multiaddr should parse");

    err = lp2p_listener_new(&loop, fx.server_transport, fx.listen_addr, &fx.listener);
    TEST_ASSERT(err == LP2P_OK, "listener_new should succeed");

    err = lp2p_listener_start(fx.listener, on_listener_conn, &fx);
    TEST_ASSERT(err == LP2P_OK, "listener_start should succeed");

    int port = quic_bound_port(fx.server_transport);
    TEST_ASSERT(port > 0, "server UDP port should be discoverable");

    err = make_quic_dial_addr(fx.server_kp, port, &fx.dial_addr);
    TEST_ASSERT(err == LP2P_OK, "dial multiaddr should build");

    err = lp2p_dialer_new(&loop, fx.client_transport, 5000, &fx.dialer);
    TEST_ASSERT(err == LP2P_OK, "dialer_new should succeed");

    err = lp2p_dialer_dial(fx.dialer, fx.dial_addr, on_dial_conn_rw, &fx);
    TEST_ASSERT(err == LP2P_OK, "dial should initiate successfully");

    uv_timer_start(&fx.safety_timer, stop_loop_cb, 5000, 0);
    uv_run(&loop, UV_RUN_DEFAULT);

    TEST_ASSERT(fx.client_connected, "client should have connected");
    TEST_ASSERT(fx.server_got_conn, "server should have received connection");
    TEST_ASSERT(fx.server_received, "server should have received protocol payload");
    TEST_ASSERT(fx.client_received, "client should have received echoed payload");
    TEST_ASSERT(strcmp(fx.server_msg, TEST_MESSAGE) == 0,
                "server payload should match sent message");
    TEST_ASSERT(strcmp(fx.client_msg, TEST_MESSAGE) == 0,
                "client echo should match sent message");

cleanup:
    quic_fixture_cleanup(&loop, &fx);
}

static void test_stream_large_read_write(void)
{
    uv_loop_t loop;
    uv_loop_init(&loop);

    quic_fixture_t fx = {0};
    lp2p_err_t err = quic_fixture_init(&loop, &fx);
    TEST_ASSERT(err == LP2P_OK, "quic_fixture_init should succeed");

    fx.large_msg_len = LARGE_TEST_MESSAGE_LEN;
    fx.large_msg = malloc(fx.large_msg_len);
    TEST_ASSERT(fx.large_msg != NULL, "large test message should allocate");
    fill_large_test_message(fx.large_msg, fx.large_msg_len);

    fx.server_router = lp2p_protocol_router_new(&loop);
    TEST_ASSERT(fx.server_router != NULL, "server router should allocate");

    err = lp2p_protocol_router_add(fx.server_router, TEST_PROTO, server_large_echo_handler, &fx);
    TEST_ASSERT(err == LP2P_OK, "server router should register protocol");

    err = lp2p_multiaddr_parse("/ip4/127.0.0.1/udp/0/quic-v1", &fx.listen_addr);
    TEST_ASSERT(err == LP2P_OK, "listen multiaddr should parse");

    err = lp2p_listener_new(&loop, fx.server_transport, fx.listen_addr, &fx.listener);
    TEST_ASSERT(err == LP2P_OK, "listener_new should succeed");

    err = lp2p_listener_start(fx.listener, on_listener_conn, &fx);
    TEST_ASSERT(err == LP2P_OK, "listener_start should succeed");

    int port = quic_bound_port(fx.server_transport);
    TEST_ASSERT(port > 0, "server UDP port should be discoverable");

    err = make_quic_dial_addr(fx.server_kp, port, &fx.dial_addr);
    TEST_ASSERT(err == LP2P_OK, "dial multiaddr should build");

    err = lp2p_dialer_new(&loop, fx.client_transport, 5000, &fx.dialer);
    TEST_ASSERT(err == LP2P_OK, "dialer_new should succeed");

    err = lp2p_dialer_dial(fx.dialer, fx.dial_addr, on_dial_conn_rw_large, &fx);
    TEST_ASSERT(err == LP2P_OK, "dial should initiate successfully");

    uv_timer_start(&fx.safety_timer, stop_loop_cb, 10000, 0);
    uv_run(&loop, UV_RUN_DEFAULT);

    TEST_ASSERT(fx.client_connected, "client should have connected");
    TEST_ASSERT(fx.server_got_conn, "server should have received connection");
    TEST_ASSERT(fx.server_large_received, "server should have received large payload");
    TEST_ASSERT(fx.client_large_received, "client should have received large echoed payload");

cleanup:
    quic_fixture_cleanup(&loop, &fx);
}

int main(void)
{
    printf("test_quic_transport:\n");

    TEST_RUN(test_transport_create);
    TEST_RUN(test_transport_handles);
    TEST_RUN(test_listen_dial_loopback);
    TEST_RUN(test_stream_read_write);
    TEST_RUN(test_stream_large_read_write);

    printf("\n  Results: %d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
