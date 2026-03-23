/* src/connmgr_internal.h — connection manager internals */
#ifndef LP2P_CONNMGR_INTERNAL_H
#define LP2P_CONNMGR_INTERNAL_H

#include <uv.h>
#include "connection_internal.h"
#include "util/list.h"
#include "util/map.h"

#ifdef __cplusplus
extern "C" {
#endif

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

/* Compatibility wrapper for the real connection destructor. */
void         lp2p_conn_destroy(lp2p_conn_t *conn);

/* Add a connection to the connmgr. */
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
