#ifndef LIBP2P_PEERSTORE_H
#define LIBP2P_PEERSTORE_H

#include "types.h"
#include "errors.h"

#ifdef __cplusplus
extern "C" {
#endif

lp2p_err_t lp2p_peerstore_add_addr(lp2p_peerstore_t *ps, const lp2p_peer_id_t *peer,
                                     const lp2p_multiaddr_t *addr, uint64_t ttl_ms);
lp2p_err_t lp2p_peerstore_add_pubkey(lp2p_peerstore_t *ps, const lp2p_peer_id_t *peer,
                                       const uint8_t *pubkey, size_t len);
bool       lp2p_peerstore_has_peer(const lp2p_peerstore_t *ps, const lp2p_peer_id_t *peer);
size_t     lp2p_peerstore_get_addrs(const lp2p_peerstore_t *ps, const lp2p_peer_id_t *peer,
                                     lp2p_multiaddr_t ***addrs_out);
lp2p_err_t lp2p_peerstore_get_pubkey(const lp2p_peerstore_t *ps, const lp2p_peer_id_t *peer,
                                       uint8_t **pubkey_out, size_t *len_out);
void       lp2p_peerstore_free_addrs(lp2p_multiaddr_t **addrs, size_t count);
void       lp2p_peerstore_free_pubkey(uint8_t *pubkey);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PEERSTORE_H */
