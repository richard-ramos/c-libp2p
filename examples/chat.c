/*
 * examples/chat.c — Simple interactive chat over libp2p.
 *
 * Server mode (no args):  ./chat
 *   Listens on /ip4/0.0.0.0/tcp/9001
 *
 * Client mode (with arg): ./chat /ip4/1.2.3.4/tcp/9001/p2p/QmPeerID
 *   Dials the given peer and opens a /chat/1.0.0 stream
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <uv.h>
#include "libp2p/libp2p.h"

#define CHAT_PROTO  "/chat/1.0.0"
#define LISTEN_ADDR "/ip4/0.0.0.0/tcp/9001"
#define MAX_LINE    4096

static lp2p_host_t  *g_host;
static lp2p_stream_t *g_stream;
static uv_poll_t      g_stdin_poll;

/* Forward declarations */
static void start_stdin_reading(uv_loop_t *loop);
static void chat_read_cb(lp2p_stream_t *stream, lp2p_err_t err,
                          const lp2p_buf_t *buf, void *userdata);

/* ── Read from remote: print to stdout ───────────────────────────────────── */
static void chat_read_cb(lp2p_stream_t *stream, lp2p_err_t err,
                          const lp2p_buf_t *buf, void *userdata)
{
    (void)userdata;
    if (err == LP2P_ERR_EOF) {
        printf("[peer disconnected]\n");
        lp2p_stream_close(stream, NULL, NULL);
        lp2p_host_close(g_host, NULL, NULL);
        return;
    }
    if (err != LP2P_OK) {
        fprintf(stderr, "chat read error: %s\n", lp2p_strerror(err));
        lp2p_stream_reset(stream);
        lp2p_host_close(g_host, NULL, NULL);
        return;
    }

    /* Print received data */
    printf(">> %.*s", (int)buf->len, (const char *)buf->data);

    /* Continue reading */
    lp2p_stream_read(stream, MAX_LINE, chat_read_cb, NULL);
}

/* ── Write callback ──────────────────────────────────────────────────────── */
static void chat_write_cb(lp2p_stream_t *stream, lp2p_err_t err,
                           void *userdata)
{
    (void)stream;
    (void)userdata;
    if (err != LP2P_OK) {
        fprintf(stderr, "chat write error: %s\n", lp2p_strerror(err));
    }
}

/* ── Stdin poll callback: read a line, send it ───────────────────────────── */
static void on_stdin_readable(uv_poll_t *handle, int status, int events)
{
    (void)handle;
    (void)events;
    if (status < 0) return;
    if (!g_stream) return;

    char line[MAX_LINE];
    if (fgets(line, sizeof(line), stdin) == NULL) {
        /* EOF on stdin — close stream */
        printf("[closing]\n");
        uv_poll_stop(&g_stdin_poll);
        lp2p_stream_close(g_stream, NULL, NULL);
        lp2p_host_close(g_host, NULL, NULL);
        return;
    }

    lp2p_buf_t buf = { .data = (const uint8_t *)line, .len = strlen(line) };
    lp2p_stream_write(g_stream, &buf, chat_write_cb, NULL);
}

/* ── Start reading stdin ─────────────────────────────────────────────────── */
static void start_stdin_reading(uv_loop_t *loop)
{
    uv_poll_init(loop, &g_stdin_poll, 0 /* fd 0 = stdin */);
    uv_poll_start(&g_stdin_poll, UV_READABLE, on_stdin_readable);
    printf("Type a message and press Enter:\n");
}

/* ── Activate a chat stream (used by both server and client) ─────────────── */
static void activate_stream(lp2p_stream_t *stream, uv_loop_t *loop)
{
    g_stream = stream;
    lp2p_stream_read(stream, MAX_LINE, chat_read_cb, NULL);
    start_stdin_reading(loop);
}

/* ── Server: inbound stream handler ──────────────────────────────────────── */
static void chat_handler(lp2p_stream_t *stream, void *userdata)
{
    (void)userdata;
    printf("[peer connected]\n");
    activate_stream(stream, uv_default_loop());
}

/* ── Client: outbound stream opened ──────────────────────────────────────── */
static void on_stream_open(lp2p_stream_t *stream, lp2p_err_t err,
                            void *userdata)
{
    (void)userdata;
    if (err != LP2P_OK) {
        fprintf(stderr, "open stream failed: %s\n", lp2p_strerror(err));
        lp2p_host_close(g_host, NULL, NULL);
        return;
    }
    printf("[connected — chat stream open]\n");
    activate_stream(stream, uv_default_loop());
}

/* ── Listen callback (server mode) ───────────────────────────────────────── */
static void on_listen(lp2p_err_t err, void *userdata)
{
    (void)userdata;
    if (err != LP2P_OK) {
        fprintf(stderr, "Listen failed: %s\n", lp2p_strerror(err));
        exit(1);
    }

    lp2p_peer_id_t pid = lp2p_host_peer_id(g_host);
    char pid_str[128];
    size_t pid_len = sizeof(pid_str);
    lp2p_peer_id_to_string(&pid, pid_str, &pid_len);

    printf("Chat server started\n");
    printf("Peer ID: %s\n", pid_str);
    printf("Listening on: %s/p2p/%s\n", LISTEN_ADDR, pid_str);
    printf("Waiting for a peer to connect...\n");
}

/* ── Signal handler ──────────────────────────────────────────────────────── */
static void on_signal(uv_signal_t *handle, int signum)
{
    (void)signum;
    printf("\n[shutting down]\n");
    uv_signal_stop(handle);
    uv_close((uv_handle_t *)handle, NULL);
    uv_poll_stop(&g_stdin_poll);
    if (g_stream) lp2p_stream_close(g_stream, NULL, NULL);
    lp2p_host_close(g_host, NULL, NULL);
}

int main(int argc, char **argv)
{
    int is_client = (argc >= 2);
    uv_loop_t *loop = uv_default_loop();

    /* Generate identity */
    lp2p_keypair_t *kp = NULL;
    lp2p_err_t err = lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);
    if (err != LP2P_OK) {
        fprintf(stderr, "keygen failed: %s\n", lp2p_strerror(err));
        return 1;
    }

    const char *addrs[] = { LISTEN_ADDR };
    lp2p_host_config_t cfg = {
        .keypair            = kp,
        .listen_addrs       = is_client ? NULL : addrs,
        .listen_addrs_count = is_client ? 0    : 1,
    };

    err = lp2p_host_new(loop, &cfg, &g_host);
    if (err != LP2P_OK) {
        fprintf(stderr, "host_new failed: %s\n", lp2p_strerror(err));
        lp2p_keypair_free(kp);
        return 1;
    }

    /* Register chat protocol handler (used in server mode) */
    lp2p_host_set_stream_handler(g_host, CHAT_PROTO, chat_handler, NULL);

    /* Handle Ctrl-C */
    uv_signal_t sig;
    uv_signal_init(loop, &sig);
    uv_signal_start(&sig, on_signal, SIGINT);

    if (is_client) {
        /* Client mode: dial and open a /chat/1.0.0 stream */
        lp2p_peer_id_t pid = lp2p_host_peer_id(g_host);
        char pid_str[128];
        size_t pid_len = sizeof(pid_str);
        lp2p_peer_id_to_string(&pid, pid_str, &pid_len);
        printf("Local Peer ID: %s\n", pid_str);
        printf("Dialing %s ...\n", argv[1]);

        err = lp2p_host_new_stream(g_host, argv[1], CHAT_PROTO,
                                    on_stream_open);
        if (err != LP2P_OK) {
            fprintf(stderr, "new_stream failed: %s\n", lp2p_strerror(err));
            lp2p_host_free(g_host);
            return 1;
        }
    } else {
        /* Server mode: listen */
        err = lp2p_host_listen(g_host, on_listen, NULL);
        if (err != LP2P_OK) {
            fprintf(stderr, "listen failed: %s\n", lp2p_strerror(err));
            lp2p_host_free(g_host);
            return 1;
        }
    }

    uv_run(loop, UV_RUN_DEFAULT);

    lp2p_host_free(g_host);
    uv_loop_close(loop);
    return 0;
}
