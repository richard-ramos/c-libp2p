/* src/connection_internal.h — internal connection types and functions */
#ifndef LP2P_CONNECTION_INTERNAL_H
#define LP2P_CONNECTION_INTERNAL_H

#include <uv.h>
#include <stdint.h>
#include <stdbool.h>

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/connection.h"
#include "libp2p/stream.h"
#include "libp2p/protocol.h"
#include "security/security.h"
#include "mux/mux.h"
#include "transport/tcp/tcp_transport.h"
#include "util/list.h"
#include "util/buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Connection state machine ─────────────────────────────────────────────── */

typedef enum {
    CONN_STATE_TRANSPORT_CONNECTING,
    CONN_STATE_SECURITY_NEGOTIATING,   /* multistream-select for /noise          */
    CONN_STATE_SECURITY_HANDSHAKE,     /* Noise XX in progress                   */
    CONN_STATE_MUX_NEGOTIATING,        /* multistream-select for /yamux/1.0.0    */
    CONN_STATE_READY,                  /* fully upgraded, streams can be opened   */
    CONN_STATE_CLOSING,                /* GoAway sent, draining streams           */
    CONN_STATE_CLOSED,
} conn_state_t;

/* ── Protocol router entry ────────────────────────────────────────────────── */

typedef struct {
    char                    *protocol_id;
    lp2p_protocol_handler_fn handler;
    void                    *userdata;
    lp2p_list_node_t         node;
} conn_proto_entry_t;

typedef struct {
    lp2p_list_t entries;   /* list of conn_proto_entry_t */
} conn_proto_router_t;

/* ── Pending open-stream request ──────────────────────────────────────────── */

typedef struct {
    char                *protocol_id;
    lp2p_open_stream_cb  cb;
    void                *userdata;
    lp2p_list_node_t     node;
} conn_open_stream_req_t;

/* ── Deferred callback ────────────────────────────────────────────────────── */

typedef void (*conn_deferred_fn)(void *arg);

typedef struct {
    lp2p_list_node_t node;
    conn_deferred_fn fn;
    void            *arg;
} conn_deferred_t;

/* ── Close callback info ──────────────────────────────────────────────────── */

typedef struct {
    void (*cb)(lp2p_conn_t *conn, void *userdata);
    void  *userdata;
} conn_close_cb_t;

/* ── The connection struct ────────────────────────────────────────────────── */

struct lp2p_conn {
    conn_state_t             state;

    /* Identity */
    lp2p_peer_id_t           remote_peer;
    lp2p_multiaddr_t        *remote_addr;
    lp2p_multiaddr_t        *local_addr;
    bool                     is_inbound;

    /* Subsystems */
    lp2p_security_session_t *security;
    lp2p_mux_session_t      *mux;

    /* Transport (TCP for now) */
    lp2p_tcp_conn_t         *tcp;

    /* Event loop */
    uv_loop_t               *loop;

    /* Read buffer for incoming raw bytes */
    lp2p_buffer_t            read_buf;

    /* Decrypt buffer (scratch space for security->decrypt) */
    uint8_t                 *decrypt_buf;
    size_t                   decrypt_buf_cap;

    /* Back-pointer to host */
    void                    *host;

    /* Protocol router for inbound streams */
    conn_proto_router_t     *router;

    /* Callbacks */
    void                   (*on_ready)(lp2p_conn_t *conn, void *userdata);
    void                   (*on_disconnect)(lp2p_conn_t *conn, lp2p_err_t reason,
                                            void *userdata);
    void                    *cb_userdata;

    /* Close state */
    conn_close_cb_t          close_cb;
    bool                     closing;
    uv_timer_t               drain_timer;
    bool                     drain_timer_active;

    /* Deferred callbacks (executed on next event-loop turn) */
    uv_async_t               async_handle;
    lp2p_list_t              deferred_queue;
    bool                     async_initialized;

    /* Upgrade context (transient, only during upgrade pipeline) */
    lp2p_keypair_t          *upgrade_keypair;    /* borrowed, not owned */

    /* connmgr list node */
    lp2p_list_node_t         node;

    /* Pending open-stream requests (queued if not yet READY) */
    lp2p_list_t              pending_streams;

    /* GoAway state */
    bool                     goaway_sent;
    bool                     goaway_received;
};

/* ── Internal API (used by host/dialer/listener) ──────────────────────────── */

/* NOTE: conn_pipeline_new and conn_pipeline_free are static within connection.c */

void lp2p_conn_attach_tcp(lp2p_conn_t *conn, lp2p_tcp_conn_t *tc);

lp2p_err_t lp2p_conn_upgrade(lp2p_conn_t *conn, lp2p_keypair_t *keypair,
                               void (*on_ready)(lp2p_conn_t *, void *),
                               void (*on_disconnect)(lp2p_conn_t *, lp2p_err_t, void *),
                               void *userdata);

void lp2p_conn_set_protocol_router(lp2p_conn_t *conn, conn_proto_router_t *router);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_CONNECTION_INTERNAL_H */
