/* src/connmgr_internal.h — connection manager internals */
#ifndef LP2P_CONNMGR_INTERNAL_H
#define LP2P_CONNMGR_INTERNAL_H

#include <uv.h>
#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/connection.h"
#include "util/list.h"
#include "util/map.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Connection states */
typedef enum {
    CONN_STATE_NEW,
    CONN_STATE_SECURING,
    CONN_STATE_MUXING,
    CONN_STATE_READY,
    CONN_STATE_CLOSING,
    CONN_STATE_CLOSED,
} lp2p_conn_state_t;

/* The full connection structure */
struct lp2p_conn {
    lp2p_list_node_t      node;            /* link in connmgr all_conns */
    uv_loop_t            *loop;

    /* Identity */
    lp2p_peer_id_t        peer_id;
    bool                  peer_id_known;
    bool                  is_inbound;

    /* Addressing */
    lp2p_multiaddr_t     *remote_addr;
    lp2p_multiaddr_t     *local_addr;

    /* State machine */
    lp2p_conn_state_t     state;

    /* Transport layer */
    void                 *tcp_conn;        /* lp2p_tcp_conn_t* */

    /* Security layer */
    void                 *security;        /* lp2p_security_session_t* */

    /* Mux layer */
    void                 *mux;             /* lp2p_mux_session_t* */

    /* Streams on this connection */
    lp2p_list_t           streams;
    uint32_t              stream_count;
    uint32_t              max_streams;

    /* Owning host */
    struct lp2p_host     *host;

    /* Creation timestamp */
    uint64_t              created_at;

    /* Close callback */
    void                (*close_cb)(lp2p_conn_t *conn, void *userdata);
    void                 *close_ud;
};

/* Connection manager */
typedef struct lp2p_connmgr {
    uv_loop_t    *loop;
    uint32_t      max_connections;
    uint32_t      max_streams_per_conn;

    /* peer_id_str -> canonical READY lp2p_conn_t* */
    lp2p_map_t    conns_by_peer;

    /* All active connections */
    lp2p_list_t   all_conns;
    uint32_t      conn_count;
} lp2p_connmgr_t;

/* Internal API */
lp2p_err_t lp2p_connmgr_new(uv_loop_t *loop, uint32_t max_conns,
                              uint32_t max_streams, lp2p_connmgr_t **out);
void       lp2p_connmgr_free(lp2p_connmgr_t *cm);

/* Create a new connection wrapping a raw TCP connection */
lp2p_conn_t *lp2p_conn_new(uv_loop_t *loop, void *tcp_conn, bool is_inbound,
                             struct lp2p_host *host);
void         lp2p_conn_destroy(lp2p_conn_t *conn);

/* Add a READY connection to the connmgr. Returns LP2P_OK or LP2P_ERR_MAX_CONNECTIONS. */
lp2p_err_t lp2p_connmgr_add(lp2p_connmgr_t *cm, lp2p_conn_t *conn);

/* Remove a connection from the connmgr */
void lp2p_connmgr_remove(lp2p_connmgr_t *cm, lp2p_conn_t *conn);

/* Get the canonical READY connection for a peer, or NULL */
lp2p_conn_t *lp2p_connmgr_get(lp2p_connmgr_t *cm, const lp2p_peer_id_t *peer);

/* Duplicate connection tie-breaking: returns the connection to keep.
   The other should be closed. */
lp2p_conn_t *lp2p_connmgr_tiebreak(lp2p_connmgr_t *cm,
                                      const lp2p_peer_id_t *local_peer,
                                      lp2p_conn_t *existing,
                                      lp2p_conn_t *incoming);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_CONNMGR_INTERNAL_H */
