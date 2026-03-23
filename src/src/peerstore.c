/* src/peerstore.c — peer address and public key storage with TTL expiry */
#define _POSIX_C_SOURCE 200809L
#include "peerstore_internal.h"
#include <libp2p/crypto.h>
#include <libp2p/multiaddr.h>
#include <stdlib.h>
#include <string.h>

/* GC interval: check for expired addresses every 10 seconds */
#define GC_INTERVAL_MS 10000

/* ── Helpers ────────────────────────────────────────────────────────────── */

static ps_peer_t *find_peer(const lp2p_peerstore_t *ps,
                             const lp2p_peer_id_t *peer) {
    lp2p_list_node_t *n = ps->peers.head.next;
    while (n != &ps->peers.head) {
        ps_peer_t *p = lp2p_container_of(n, ps_peer_t, node);
        if (lp2p_peer_id_equal(&p->peer_id, peer))
            return p;
        n = n->next;
    }
    return NULL;
}

static ps_peer_t *find_or_create_peer(lp2p_peerstore_t *ps,
                                       const lp2p_peer_id_t *peer) {
    ps_peer_t *p = find_peer(ps, peer);
    if (p) return p;

    p = calloc(1, sizeof(*p));
    if (!p) return NULL;

    p->peer_id = *peer;
    lp2p_list_init(&p->addrs);
    lp2p_list_push_back(&ps->peers, &p->node);
    return p;
}

static void free_addr_entry(ps_addr_entry_t *ae) {
    if (ae) {
        lp2p_multiaddr_free(ae->addr);
        free(ae);
    }
}

static void free_peer(ps_peer_t *p) {
    if (!p) return;
    while (!lp2p_list_empty(&p->addrs)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&p->addrs);
        ps_addr_entry_t *ae = lp2p_container_of(n, ps_addr_entry_t, node);
        free_addr_entry(ae);
    }
    free(p->pubkey);
    free(p);
}

/* ── GC timer callback ─────────────────────────────────────────────────── */

static void gc_timer_cb(uv_timer_t *handle) {
    lp2p_peerstore_t *ps = (lp2p_peerstore_t *)handle->data;
    uint64_t now = uv_now(ps->loop);

    lp2p_list_node_t *pn = ps->peers.head.next;
    while (pn != &ps->peers.head) {
        ps_peer_t *peer = lp2p_container_of(pn, ps_peer_t, node);
        pn = pn->next;

        lp2p_list_node_t *an = peer->addrs.head.next;
        while (an != &peer->addrs.head) {
            ps_addr_entry_t *ae = lp2p_container_of(an, ps_addr_entry_t, node);
            an = an->next;
            if (ae->expires_at > 0 && now >= ae->expires_at) {
                lp2p_list_remove(&peer->addrs, &ae->node);
                free_addr_entry(ae);
            }
        }
    }
}

/* ── Internal: create/destroy ──────────────────────────────────────────── */

lp2p_err_t lp2p_peerstore_new(uv_loop_t *loop, lp2p_peerstore_t **out) {
    if (!loop || !out) return LP2P_ERR_INVALID_ARG;

    lp2p_peerstore_t *ps = calloc(1, sizeof(*ps));
    if (!ps) return LP2P_ERR_NOMEM;

    ps->loop = loop;
    lp2p_list_init(&ps->peers);

    uv_timer_init(loop, &ps->gc_timer);
    ps->gc_timer.data = ps;
    uv_timer_start(&ps->gc_timer, gc_timer_cb, GC_INTERVAL_MS, GC_INTERVAL_MS);
    uv_unref((uv_handle_t *)&ps->gc_timer);
    ps->gc_running = true;

    *out = ps;
    return LP2P_OK;
}

static void gc_timer_close_cb(uv_handle_t *handle) {
    (void)handle;
}

void lp2p_peerstore_free(lp2p_peerstore_t *ps) {
    if (!ps) return;

    if (ps->gc_running) {
        uv_timer_stop(&ps->gc_timer);
        if (!uv_is_closing((uv_handle_t *)&ps->gc_timer))
            uv_close((uv_handle_t *)&ps->gc_timer, gc_timer_close_cb);
        ps->gc_running = false;
    }

    while (!lp2p_list_empty(&ps->peers)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&ps->peers);
        ps_peer_t *p = lp2p_container_of(n, ps_peer_t, node);
        free_peer(p);
    }

    free(ps);
}

/* ── add_addr common logic ─────────────────────────────────────────────── */

static lp2p_err_t add_addr_common(lp2p_peerstore_t *ps,
                                    const lp2p_peer_id_t *peer,
                                    const lp2p_multiaddr_t *addr,
                                    uint64_t ttl_ms,
                                    bool from_identify) {
    if (!ps || !peer || !addr)
        return LP2P_ERR_INVALID_ARG;

    /* If addr has /p2p/<peerid>, it must match the peer arg */
    lp2p_peer_id_t addr_pid;
    if (lp2p_multiaddr_get_peer_id(addr, &addr_pid) == LP2P_OK) {
        if (!lp2p_peer_id_equal(&addr_pid, peer))
            return LP2P_ERR_PEER_ID_MISMATCH;
    }

    ps_peer_t *p = find_or_create_peer(ps, peer);
    if (!p) return LP2P_ERR_NOMEM;

    /* Check if we already have this address — update TTL if so */
    lp2p_list_node_t *n = p->addrs.head.next;
    while (n != &p->addrs.head) {
        ps_addr_entry_t *ae = lp2p_container_of(n, ps_addr_entry_t, node);
        if (lp2p_multiaddr_equal(ae->addr, addr)) {
            ae->ttl_ms = ttl_ms;
            ae->from_identify = from_identify;
            if (ttl_ms > 0) {
                ae->expires_at = uv_now(ps->loop) + ttl_ms;
            } else {
                ae->expires_at = 0;
            }
            return LP2P_OK;
        }
        n = n->next;
    }

    /* New address entry */
    ps_addr_entry_t *ae = calloc(1, sizeof(*ae));
    if (!ae) return LP2P_ERR_NOMEM;

    const char *ma_str = lp2p_multiaddr_string(addr);
    if (!ma_str) { free(ae); return LP2P_ERR_INVALID_MULTIADDR; }
    lp2p_err_t err = lp2p_multiaddr_parse(ma_str, &ae->addr);
    if (err != LP2P_OK) { free(ae); return err; }

    ae->ttl_ms = ttl_ms;
    ae->from_identify = from_identify;
    if (ttl_ms > 0) {
        ae->expires_at = uv_now(ps->loop) + ttl_ms;
    } else {
        ae->expires_at = 0;
    }

    lp2p_list_push_back(&p->addrs, &ae->node);
    return LP2P_OK;
}

/* ── Public API ────────────────────────────────────────────────────────── */

lp2p_err_t lp2p_peerstore_add_addr(lp2p_peerstore_t *ps,
                                     const lp2p_peer_id_t *peer,
                                     const lp2p_multiaddr_t *addr,
                                     uint64_t ttl_ms) {
    return add_addr_common(ps, peer, addr, ttl_ms, false);
}

lp2p_err_t lp2p_peerstore_add_addr_identify(lp2p_peerstore_t *ps,
                                              const lp2p_peer_id_t *peer,
                                              const lp2p_multiaddr_t *addr,
                                              uint64_t ttl_ms) {
    return add_addr_common(ps, peer, addr, ttl_ms, true);
}

void lp2p_peerstore_clear_identify_addrs(lp2p_peerstore_t *ps,
                                          const lp2p_peer_id_t *peer) {
    if (!ps || !peer) return;
    ps_peer_t *p = find_peer(ps, peer);
    if (!p) return;

    lp2p_list_node_t *n = p->addrs.head.next;
    while (n != &p->addrs.head) {
        ps_addr_entry_t *ae = lp2p_container_of(n, ps_addr_entry_t, node);
        n = n->next;
        if (ae->from_identify) {
            lp2p_list_remove(&p->addrs, &ae->node);
            free_addr_entry(ae);
        }
    }
}

lp2p_err_t lp2p_peerstore_add_pubkey(lp2p_peerstore_t *ps,
                                       const lp2p_peer_id_t *peer,
                                       const uint8_t *pubkey, size_t len) {
    if (!ps || !peer || !pubkey || len == 0)
        return LP2P_ERR_INVALID_ARG;

    /* Derive peer ID from protobuf PublicKey bytes and validate match */
    lp2p_peer_id_t derived;
    lp2p_err_t err = lp2p_peer_id_from_public_key(pubkey, len, &derived);
    if (err != LP2P_OK)
        return LP2P_ERR_INVALID_KEY;
    if (!lp2p_peer_id_equal(&derived, peer))
        return LP2P_ERR_PEER_ID_MISMATCH;

    ps_peer_t *p = find_or_create_peer(ps, peer);
    if (!p) return LP2P_ERR_NOMEM;

    free(p->pubkey);
    p->pubkey = malloc(len);
    if (!p->pubkey) { p->pubkey_len = 0; return LP2P_ERR_NOMEM; }
    memcpy(p->pubkey, pubkey, len);
    p->pubkey_len = len;

    return LP2P_OK;
}

bool lp2p_peerstore_has_peer(const lp2p_peerstore_t *ps,
                              const lp2p_peer_id_t *peer) {
    if (!ps || !peer) return false;
    const ps_peer_t *p = find_peer(ps, peer);
    if (!p) return false;

    if (p->pubkey && p->pubkey_len > 0)
        return true;

    uint64_t now = uv_now(ps->loop);
    lp2p_list_node_t *n = p->addrs.head.next;
    while (n != &p->addrs.head) {
        const ps_addr_entry_t *ae = lp2p_container_of(n, ps_addr_entry_t, node);
        if (ae->expires_at == 0 || now < ae->expires_at)
            return true;
        n = n->next;
    }

    return false;
}

size_t lp2p_peerstore_get_addrs(const lp2p_peerstore_t *ps,
                                 const lp2p_peer_id_t *peer,
                                 lp2p_multiaddr_t ***addrs_out) {
    if (!ps || !peer || !addrs_out) {
        if (addrs_out) *addrs_out = NULL;
        return 0;
    }

    const ps_peer_t *p = find_peer(ps, peer);
    if (!p || lp2p_list_empty(&p->addrs)) {
        *addrs_out = NULL;
        return 0;
    }

    uint64_t now = uv_now(ps->loop);

    /* Count non-expired addresses */
    size_t count = 0;
    lp2p_list_node_t *n = p->addrs.head.next;
    while (n != &p->addrs.head) {
        const ps_addr_entry_t *ae = lp2p_container_of(n, ps_addr_entry_t, node);
        if (ae->expires_at == 0 || now < ae->expires_at)
            count++;
        n = n->next;
    }

    if (count == 0) {
        *addrs_out = NULL;
        return 0;
    }

    lp2p_multiaddr_t **arr = calloc(count, sizeof(lp2p_multiaddr_t *));
    if (!arr) {
        *addrs_out = NULL;
        return 0;
    }

    size_t idx = 0;
    n = p->addrs.head.next;
    while (n != &p->addrs.head && idx < count) {
        const ps_addr_entry_t *ae = lp2p_container_of(n, ps_addr_entry_t, node);
        if (ae->expires_at == 0 || now < ae->expires_at) {
            const char *s = lp2p_multiaddr_string(ae->addr);
            if (s && lp2p_multiaddr_parse(s, &arr[idx]) == LP2P_OK)
                idx++;
        }
        n = n->next;
    }

    *addrs_out = arr;
    return idx;
}

void lp2p_peerstore_free_addrs(lp2p_multiaddr_t **addrs, size_t count) {
    if (!addrs) return;
    for (size_t i = 0; i < count; i++)
        lp2p_multiaddr_free(addrs[i]);
    free(addrs);
}

lp2p_err_t lp2p_peerstore_get_pubkey(const lp2p_peerstore_t *ps,
                                       const lp2p_peer_id_t *peer,
                                       uint8_t **pubkey_out, size_t *len_out) {
    if (!ps || !peer || !pubkey_out || !len_out)
        return LP2P_ERR_INVALID_ARG;

    const ps_peer_t *p = find_peer(ps, peer);
    if (!p || !p->pubkey || p->pubkey_len == 0)
        return LP2P_ERR_NOT_FOUND;

    *pubkey_out = malloc(p->pubkey_len);
    if (!*pubkey_out) return LP2P_ERR_NOMEM;
    memcpy(*pubkey_out, p->pubkey, p->pubkey_len);
    *len_out = p->pubkey_len;
    return LP2P_OK;
}

void lp2p_peerstore_free_pubkey(uint8_t *pubkey) {
    free(pubkey);
}
