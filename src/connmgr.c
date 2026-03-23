/* src/connmgr.c — connection manager: tracks connections, enforces limits */
#define _POSIX_C_SOURCE 200809L
#include "connmgr_internal.h"
#include "stream_internal.h"
#include "mux/mux.h"
#include <libp2p/crypto.h>
#include <libp2p/multiaddr.h>
#include "transport/tcp/tcp_transport.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Helpers ────────────────────────────────────────────────────────────── */

static char *peer_id_key(const lp2p_peer_id_t *pid) {
    char buf[128];
    size_t len = sizeof(buf);
    if (lp2p_peer_id_to_string(pid, buf, &len) != LP2P_OK)
        return NULL;
    return strndup(buf, len);
}

static bool conn_has_peer_id(const lp2p_conn_t *conn) {
    if (!conn) return false;
    return conn->remote_peer.len > 0;
}

void lp2p_conn_destroy(lp2p_conn_t *conn) {
    lp2p_conn_free(conn);
}

/* ── Connmgr lifecycle ─────────────────────────────────────────────────── */

lp2p_err_t lp2p_connmgr_new(uv_loop_t *loop, uint32_t max_conns,
                              uint32_t max_streams, lp2p_connmgr_t **out) {
    if (!loop || !out) return LP2P_ERR_INVALID_ARG;

    lp2p_connmgr_t *cm = calloc(1, sizeof(*cm));
    if (!cm) return LP2P_ERR_NOMEM;

    cm->loop = loop;
    cm->max_connections = (max_conns == 0) ? 256 : max_conns;
    cm->max_streams_per_conn = (max_streams == 0) ? 256 : max_streams;
    lp2p_list_init(&cm->all_conns);

    if (!lp2p_map_init(&cm->conns_by_peer, 32)) {
        free(cm);
        return LP2P_ERR_NOMEM;
    }

    *out = cm;
    return LP2P_OK;
}

void lp2p_connmgr_free(lp2p_connmgr_t *cm) {
    if (!cm) return;

    /* Destroy all tracked connections */
    while (!lp2p_list_empty(&cm->all_conns)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&cm->all_conns);
        lp2p_conn_t *conn = lp2p_container_of(n, lp2p_conn_t, node);
        lp2p_conn_destroy(conn);
    }

    lp2p_map_free(&cm->conns_by_peer);
    free(cm);
}

/* ── Connection management ─────────────────────────────────────────────── */

lp2p_err_t lp2p_connmgr_add(lp2p_connmgr_t *cm, lp2p_conn_t *conn) {
    if (!cm || !conn) return LP2P_ERR_INVALID_ARG;

    /* Enforce max_connections */
    if (cm->max_connections != UINT32_MAX &&
        cm->conn_count >= cm->max_connections) {
        return LP2P_ERR_MAX_CONNECTIONS;
    }

    if (conn->state == CONN_STATE_READY && conn_has_peer_id(conn)) {
        char *key = peer_id_key(&conn->remote_peer);
        if (!key) return LP2P_ERR_NOMEM;

        lp2p_conn_t *existing = lp2p_map_get(&cm->conns_by_peer, key);
        free(key);
        if (existing && existing != conn) {
            return LP2P_ERR_ALREADY_CONNECTED;
        }
    }

    lp2p_list_push_back(&cm->all_conns, &conn->node);
    cm->conn_count++;

    /* If READY and peer_id known, register in conns_by_peer */
    if (conn->state == CONN_STATE_READY && conn_has_peer_id(conn)) {
        char *key = peer_id_key(&conn->remote_peer);
        if (key) {
            lp2p_map_set(&cm->conns_by_peer, key, conn);
            free(key);
        }
    }

    return LP2P_OK;
}

void lp2p_connmgr_remove(lp2p_connmgr_t *cm, lp2p_conn_t *conn) {
    if (!cm || !conn) return;

    /* Remove from all_conns list */
    if (conn->node.prev && conn->node.next) {
        lp2p_list_remove(&cm->all_conns, &conn->node);
        cm->conn_count--;
    }

    /* Remove from conns_by_peer if it's the canonical connection */
    if (conn_has_peer_id(conn)) {
        char *key = peer_id_key(&conn->remote_peer);
        if (key) {
            lp2p_conn_t *existing = lp2p_map_get(&cm->conns_by_peer, key);
            if (existing == conn) {
                lp2p_map_del(&cm->conns_by_peer, key);
            }
            free(key);
        }
    }
}

lp2p_conn_t *lp2p_connmgr_get(lp2p_connmgr_t *cm, const lp2p_peer_id_t *peer) {
    if (!cm || !peer) return NULL;
    char *key = peer_id_key(peer);
    if (!key) return NULL;
    lp2p_conn_t *conn = lp2p_map_get(&cm->conns_by_peer, key);
    free(key);
    return conn;
}

/* Duplicate connection tie-break:
   Compare peer IDs lexicographically; smaller peer ID keeps its outbound
   connection; larger keeps its inbound. If same direction, keep oldest READY. */
lp2p_conn_t *lp2p_connmgr_tiebreak(lp2p_connmgr_t *cm,
                                      const lp2p_peer_id_t *local_peer,
                                      lp2p_conn_t *existing,
                                      lp2p_conn_t *incoming) {
    (void)cm;
    if (!existing) return incoming;
    if (!incoming) return existing;

    const lp2p_peer_id_t *remote = &existing->remote_peer;

    /* Determine who keeps which direction */
    size_t cmp_len = local_peer->len < remote->len ? local_peer->len : remote->len;
    int cmp = memcmp(local_peer->bytes, remote->bytes, cmp_len);
    if (cmp == 0 && local_peer->len != remote->len) {
        cmp = (local_peer->len < remote->len) ? -1 : 1;
    }

    /* cmp < 0: local is "smaller" → keep outbound (is_inbound==false)
       cmp > 0: local is "larger"  → keep inbound  (is_inbound==true)
       cmp == 0: shouldn't happen (connecting to self), keep existing */
    if (cmp == 0) return existing;

    bool keep_outbound = (cmp < 0);

    /* If existing and incoming have different directions, pick by rule */
    if (existing->is_inbound != incoming->is_inbound) {
        if (keep_outbound) {
            return existing->is_inbound ? incoming : existing;
        } else {
            return existing->is_inbound ? existing : incoming;
        }
    }

    /* Same direction: keep the existing connection for stability. */
    return existing;
}
