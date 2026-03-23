#ifndef LIBP2P_MULTIADDR_H
#define LIBP2P_MULTIADDR_H

#include "types.h"
#include "errors.h"

#ifdef __cplusplus
extern "C" {
#endif

lp2p_err_t  lp2p_multiaddr_parse(const char *str, lp2p_multiaddr_t **out);
lp2p_err_t  lp2p_multiaddr_from_bytes(const uint8_t *bytes, size_t len, lp2p_multiaddr_t **out);
void        lp2p_multiaddr_free(lp2p_multiaddr_t *ma);
bool        lp2p_multiaddr_equal(const lp2p_multiaddr_t *a, const lp2p_multiaddr_t *b);
lp2p_err_t  lp2p_multiaddr_get_peer_id(const lp2p_multiaddr_t *ma, lp2p_peer_id_t *out);
lp2p_err_t  lp2p_multiaddr_with_peer_id(const lp2p_multiaddr_t *base,
                                          const lp2p_peer_id_t *peer,
                                          lp2p_multiaddr_t **out);
const char    *lp2p_multiaddr_string(const lp2p_multiaddr_t *ma);
const uint8_t *lp2p_multiaddr_bytes(const lp2p_multiaddr_t *ma, size_t *len);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_MULTIADDR_H */
