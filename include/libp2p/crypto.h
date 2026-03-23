#ifndef LIBP2P_CRYPTO_H
#define LIBP2P_CRYPTO_H

#include "types.h"
#include "errors.h"

#ifdef __cplusplus
extern "C" {
#endif

lp2p_err_t lp2p_keypair_generate(lp2p_key_type_t type, lp2p_keypair_t **out);
lp2p_err_t lp2p_keypair_from_bytes(lp2p_key_type_t type, const uint8_t *priv,
                                    size_t len, lp2p_keypair_t **out);
lp2p_err_t lp2p_keypair_public_bytes(const lp2p_keypair_t *kp,
                                      uint8_t *out, size_t *out_len);
void       lp2p_keypair_free(lp2p_keypair_t *kp);

lp2p_err_t lp2p_peer_id_from_keypair(const lp2p_keypair_t *kp, lp2p_peer_id_t *out);
lp2p_err_t lp2p_peer_id_from_public_key(const uint8_t *pubkey, size_t len,
                                          lp2p_peer_id_t *out);
lp2p_err_t lp2p_peer_id_to_string(const lp2p_peer_id_t *id, char *out, size_t *out_len);
lp2p_err_t lp2p_peer_id_from_string(const char *str, lp2p_peer_id_t *out);
bool       lp2p_peer_id_equal(const lp2p_peer_id_t *a, const lp2p_peer_id_t *b);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_CRYPTO_H */
