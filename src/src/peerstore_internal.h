#ifndef LP2P_PEERSTORE_INTERNAL_H
#define LP2P_PEERSTORE_INTERNAL_H

#include <uv.h>
#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/peerstore.h"
#include "util/list.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A single address entry for a peer */
typedef struct {
    lp2p_list_node_t  node;
    lp2p_multiaddr_t *addr;
    uint64_t          ttl_ms;
    uint64_t          expires_at;    /* uv_now() + ttl_ms; 0 = never */
    bool              from_identify; /* true if set via identify protocol */
} ps_addr_entry_t;

/* A peer record in the peerstore */
typedef struct {
    lp2p_list_node_t  node;          /* for peers_list */
    lp2p_peer_id_t    peer_id;
    lp2p_list_t       addrs;         /* list of ps_addr_entry_t */
    uint8_t          *pubkey;        /* protobuf PublicKey bytes (owned) */
    size_t            pubkey_len;
} ps_peer_t;

struct lp2p_peerstore {
    uv_loop_t    *loop;
    uv_timer_t    gc_timer;
    lp2p_list_t   peers;             /* list of ps_peer_t */
    bool          gc_running;
};

/* Internal: create/destroy peerstore (called by host) */
lp2p_err_t lp2p_peerstore_new(uv_loop_t *loop, lp2p_peerstore_t **out);
void       lp2p_peerstore_free(lp2p_peerstore_t *ps);

/* Internal: add address from identify (tracked separately) */
lp2p_err_t lp2p_peerstore_add_addr_identify(lp2p_peerstore_t *ps,
                                              const lp2p_peer_id_t *peer,
                                              const lp2p_multiaddr_t *addr,
                                              uint64_t ttl_ms);

/* Internal: clear identify-sourced addresses for a peer */
void lp2p_peerstore_clear_identify_addrs(lp2p_peerstore_t *ps,
                                          const lp2p_peer_id_t *peer);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_PEERSTORE_INTERNAL_H */
