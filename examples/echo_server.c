/*
 * examples/echo_server.c — Listen on /ip4/127.0.0.1/tcp/9000, echo back data.
 *
 * Usage: ./echo_server
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <uv.h>
#include "libp2p/libp2p.h"

#define ECHO_PROTO "/echo/1.0.0"
#define LISTEN_ADDR "/ip4/127.0.0.1/tcp/9000"
#define ECHO_MAX_READ 65536 /* 64 KiB */

static lp2p_host_t *g_host;
static const char *g_listen_addr = LISTEN_ADDR;

/* Forward declarations */
static void echo_read_cb(lp2p_stream_t *stream, lp2p_err_t err,
                          const lp2p_buf_t *buf, void *userdata);
static void echo_write_cb(lp2p_stream_t *stream, lp2p_err_t err,
                           void *userdata);

/* ── Write callback: after echoing data back, read more ──────────────────── */
static void echo_write_cb(lp2p_stream_t *stream, lp2p_err_t err,
                           void *userdata)
{
    (void)userdata;
    if (err != LP2P_OK) {
        fprintf(stderr, "echo write error: %s\n", lp2p_strerror(err));
        lp2p_stream_reset(stream);
        return;
    }
    /* Continue reading */
    lp2p_stream_read(stream, ECHO_MAX_READ, echo_read_cb, NULL);
}

/* ── Read callback: echo received data back ──────────────────────────────── */
static void echo_read_cb(lp2p_stream_t *stream, lp2p_err_t err,
                          const lp2p_buf_t *buf, void *userdata)
{
    (void)userdata;
    if (err == LP2P_ERR_EOF) {
        /* Remote closed their write side — close ours too */
        lp2p_stream_close(stream, NULL, NULL);
        return;
    }
    if (err != LP2P_OK) {
        fprintf(stderr, "echo read error: %s\n", lp2p_strerror(err));
        lp2p_stream_reset(stream);
        return;
    }
    /* Echo the data back */
    lp2p_stream_write(stream, buf, echo_write_cb, NULL);
}

/* ── Protocol handler: called for each inbound /echo/1.0.0 stream ────────── */
static void echo_handler(lp2p_stream_t *stream, void *userdata)
{
    (void)userdata;
    printf("New echo stream opened\n");
    lp2p_stream_read(stream, ECHO_MAX_READ, echo_read_cb, NULL);
}

/* ── Listen callback ─────────────────────────────────────────────────────── */
static void on_listen(lp2p_err_t err, void *userdata)
{
    (void)userdata;
    if (err != LP2P_OK) {
        fprintf(stderr, "Listen failed: %s\n", lp2p_strerror(err));
        exit(1);
    }

    /* Print peer ID */
    lp2p_peer_id_t pid = lp2p_host_peer_id(g_host);
    char pid_str[128];
    size_t pid_len = sizeof(pid_str);
    lp2p_peer_id_to_string(&pid, pid_str, &pid_len);

    printf("Echo server started\n");
    printf("Peer ID: %s\n", pid_str);
    printf("Listening on: %s/p2p/%s\n", g_listen_addr, pid_str);
}

/* ── Signal handler ──────────────────────────────────────────────────────── */
static void on_signal(uv_signal_t *handle, int signum)
{
    (void)signum;
    printf("\nShutting down...\n");
    uv_signal_stop(handle);
    uv_close((uv_handle_t *)handle, NULL);
    lp2p_host_close(g_host, NULL, NULL);
}

int main(int argc, char **argv)
{
    uv_loop_t *loop = uv_default_loop();

    if (argc > 2) {
        fprintf(stderr, "Usage: %s [listen-multiaddr]\n", argv[0]);
        fprintf(stderr, "  e.g. %s %s\n", argv[0], LISTEN_ADDR);
        fprintf(stderr, "  e.g. %s /ip4/127.0.0.1/udp/9000/quic-v1\n", argv[0]);
        return 1;
    }

    if (argc == 2) {
        g_listen_addr = argv[1];
    }

    /* Generate identity */
    lp2p_keypair_t *kp = NULL;
    lp2p_err_t err = lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);
    if (err != LP2P_OK) {
        fprintf(stderr, "keygen failed: %s\n", lp2p_strerror(err));
        return 1;
    }

    /* Configure host */
    const char *addrs[] = { g_listen_addr };
    lp2p_host_config_t cfg = {
        .keypair            = kp,
        .listen_addrs       = addrs,
        .listen_addrs_count = 1,
    };

    err = lp2p_host_new(loop, &cfg, &g_host);
    if (err != LP2P_OK) {
        fprintf(stderr, "host_new failed: %s\n", lp2p_strerror(err));
        lp2p_keypair_free(kp);
        return 1;
    }

    /* Register echo protocol handler */
    err = lp2p_host_set_stream_handler(g_host, ECHO_PROTO, echo_handler, NULL);
    if (err != LP2P_OK) {
        fprintf(stderr, "set_stream_handler failed: %s\n", lp2p_strerror(err));
        lp2p_host_free(g_host);
        return 1;
    }

    /* Start listening */
    err = lp2p_host_listen(g_host, on_listen, NULL);
    if (err != LP2P_OK) {
        fprintf(stderr, "listen failed: %s\n", lp2p_strerror(err));
        lp2p_host_free(g_host);
        return 1;
    }

    /* Handle Ctrl-C */
    uv_signal_t sig;
    uv_signal_init(loop, &sig);
    uv_signal_start(&sig, on_signal, SIGINT);

    /* Run event loop */
    uv_run(loop, UV_RUN_DEFAULT);

    lp2p_host_free(g_host);
    uv_loop_close(loop);
    return 0;
}
