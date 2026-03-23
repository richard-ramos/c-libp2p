#ifndef LIBP2P_HOST_H
#define LIBP2P_HOST_H

#include <uv.h>
#include "types.h"
#include "errors.h"
#include "stream.h"
#include "protocol.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Host configuration ───────────────────────────────────────────────────── */
typedef struct {
    lp2p_keypair_t       *keypair;               /* required; host takes ownership        */
    const char          **listen_addrs;           /* concrete bind multiaddr strings        */
    size_t                listen_addrs_count;
    const char          **announce_addrs;         /* advertised multiaddrs; NULL=listen     */
    size_t                announce_addrs_count;
    uint32_t              max_connections;        /* 0 = 256 default; UINT32_MAX = unlimited*/
    uint32_t              max_streams_per_conn;   /* 0 = 256 default                        */
    size_t                max_stream_read_buffer; /* 0 = 256 KiB default                   */
    size_t                max_stream_write_buffer;/* 0 = 256 KiB default                   */
    size_t                max_conn_read_buffer;   /* 0 = 1 MiB default                     */
    uint32_t              dial_timeout_ms;        /* default: 30000                         */
    uint32_t              handshake_timeout_ms;   /* default: 10000                         */
    uint32_t              protocol_timeout_ms;    /* default: 10000                         */
    uint32_t              keepalive_interval_s;   /* yamux keepalive (default: 30s, 0=off)  */
} lp2p_host_config_t;

/* ── Callbacks ────────────────────────────────────────────────────────────── */
typedef void (*lp2p_dial_cb)(lp2p_conn_t *conn, lp2p_err_t err, void *userdata);
typedef void (*lp2p_on_listen_cb)(lp2p_err_t err, void *userdata);

/* ── Lifecycle ────────────────────────────────────────────────────────────── */
lp2p_err_t lp2p_host_new(uv_loop_t *loop, const lp2p_host_config_t *config,
                           lp2p_host_t **out);
void       lp2p_host_free(lp2p_host_t *host);
lp2p_err_t lp2p_host_close(lp2p_host_t *host,
                             void (*cb)(lp2p_host_t *host, void *userdata),
                             void *userdata);

/* ── Listen & Dial ────────────────────────────────────────────────────────── */
lp2p_err_t lp2p_host_listen(lp2p_host_t *host, lp2p_on_listen_cb cb, void *userdata);
lp2p_err_t lp2p_host_dial(lp2p_host_t *host, const char *multiaddr,
                            lp2p_dial_cb cb, void *userdata);
lp2p_err_t lp2p_host_dial_peer(lp2p_host_t *host, const lp2p_peer_id_t *peer,
                                 lp2p_dial_cb cb, void *userdata);

/* ── Streams ──────────────────────────────────────────────────────────────── */
lp2p_err_t lp2p_host_set_stream_handler(lp2p_host_t *host, const char *protocol_id,
                                          lp2p_protocol_handler_fn handler, void *userdata);
lp2p_err_t lp2p_host_new_stream(lp2p_host_t *host, const char *multiaddr,
                                  const char *protocol_id, lp2p_open_stream_cb cb);

/* ── Built-ins ────────────────────────────────────────────────────────────── */
lp2p_err_t lp2p_host_ping(lp2p_host_t *host, lp2p_conn_t *conn,
                            void (*cb)(lp2p_err_t err, uint64_t rtt_us, void *userdata),
                            void *userdata);

/* ── Introspection ────────────────────────────────────────────────────────── */
lp2p_peer_id_t    lp2p_host_peer_id(const lp2p_host_t *host);
lp2p_peerstore_t *lp2p_host_peerstore(lp2p_host_t *host);
bool              lp2p_host_is_connected(const lp2p_host_t *host, const lp2p_peer_id_t *peer);

/* ── Connection events ────────────────────────────────────────────────────── */
lp2p_err_t lp2p_host_on_connection(lp2p_host_t *host,
                                     void (*cb)(lp2p_host_t *host, lp2p_conn_t *conn,
                                                void *userdata),
                                     void *userdata);
lp2p_err_t lp2p_host_on_disconnect(lp2p_host_t *host,
                                     void (*cb)(lp2p_host_t *host, lp2p_conn_t *conn,
                                                lp2p_err_t reason, void *userdata),
                                     void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_HOST_H */
