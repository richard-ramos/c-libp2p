/*
 * examples/ping_peer.c — Dial a peer and ping it 5 times.
 *
 * Usage: ./ping_peer /ip4/1.2.3.4/tcp/9000/p2p/QmPeerID
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <uv.h>
#include "libp2p/libp2p.h"

#define PING_COUNT 5

static lp2p_host_t *g_host;
static int g_pings_done;

/* Forward declaration */
static void do_ping(lp2p_conn_t *conn);
static void start_ping_timer_cb(uv_timer_t *handle);
static void start_ping_timer_close_cb(uv_handle_t *handle);

/* ── Ping callback ───────────────────────────────────────────────────────── */
static void ping_cb(lp2p_err_t err, uint64_t rtt_us, void *userdata)
{
    lp2p_conn_t *conn = (lp2p_conn_t *)userdata;

    if (err != LP2P_OK) {
        fprintf(stderr, "ping failed: %s\n", lp2p_strerror(err));
        lp2p_host_close(g_host, NULL, NULL);
        return;
    }

    g_pings_done++;
    printf("ping %d/%d: RTT = %llu us (%.2f ms)\n",
           g_pings_done, PING_COUNT,
           (unsigned long long)rtt_us, rtt_us / 1000.0);

    if (g_pings_done < PING_COUNT) {
        do_ping(conn);
    } else {
        printf("Done.\n");
        lp2p_host_close(g_host, NULL, NULL);
    }
}

/* ── Send one ping ───────────────────────────────────────────────────────── */
static void do_ping(lp2p_conn_t *conn)
{
    lp2p_err_t err = lp2p_host_ping(g_host, conn, ping_cb, conn);
    if (err != LP2P_OK) {
        fprintf(stderr, "lp2p_host_ping failed: %s\n", lp2p_strerror(err));
        lp2p_host_close(g_host, NULL, NULL);
    }
}

static void start_ping_timer_cb(uv_timer_t *handle)
{
    lp2p_conn_t *conn = handle->data;
    uv_timer_stop(handle);
    uv_close((uv_handle_t *)handle, start_ping_timer_close_cb);
    do_ping(conn);
}

static void start_ping_timer_close_cb(uv_handle_t *handle)
{
    free(handle);
}

/* ── Dial callback ───────────────────────────────────────────────────────── */
static void dial_cb(lp2p_conn_t *conn, lp2p_err_t err, void *userdata)
{
    (void)userdata;
    if (err != LP2P_OK) {
        fprintf(stderr, "dial failed: %s\n", lp2p_strerror(err));
        lp2p_host_close(g_host, NULL, NULL);
        return;
    }

    lp2p_peer_id_t pid = lp2p_conn_peer_id(conn);
    char pid_str[128];
    size_t pid_len = sizeof(pid_str);
    lp2p_peer_id_to_string(&pid, pid_str, &pid_len);
    printf("Connected to %s\n", pid_str);

    g_pings_done = 0;

    uv_timer_t *timer = malloc(sizeof(*timer));
    if (!timer) {
        do_ping(conn);
        return;
    }

    uv_timer_init(uv_default_loop(), timer);
    timer->data = conn;
    uv_timer_start(timer, start_ping_timer_cb, 200, 0);
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <multiaddr>\n", argv[0]);
        fprintf(stderr, "  e.g. %s /ip4/127.0.0.1/tcp/9000/p2p/12D3KooW...\n", argv[0]);
        return 1;
    }

    const char *target = argv[1];
    uv_loop_t *loop = uv_default_loop();

    /* Generate ephemeral identity */
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

    /* Print our peer ID */
    lp2p_peer_id_t pid = lp2p_host_peer_id(g_host);
    char pid_str[128];
    size_t pid_len = sizeof(pid_str);
    lp2p_peer_id_to_string(&pid, pid_str, &pid_len);
    printf("Local Peer ID: %s\n", pid_str);
    printf("Dialing %s ...\n", target);

    /* Dial the target */
    err = lp2p_host_dial(g_host, target, dial_cb, NULL);
    if (err != LP2P_OK) {
        fprintf(stderr, "dial failed: %s\n", lp2p_strerror(err));
        lp2p_host_free(g_host);
        return 1;
    }

    uv_run(loop, UV_RUN_DEFAULT);

    lp2p_host_free(g_host);
    uv_loop_close(loop);
    return 0;
}
