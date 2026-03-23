/* src/crypto/keypair_internal.h — internal helpers for keypair access */
#ifndef LP2P_CRYPTO_KEYPAIR_INTERNAL_H
#define LP2P_CRYPTO_KEYPAIR_INTERNAL_H

#include <libp2p/types.h>
#include <stdint.h>

lp2p_key_type_t  lp2p_keypair_type(const lp2p_keypair_t *kp);
const uint8_t   *lp2p_keypair_public_ptr(const lp2p_keypair_t *kp);
const uint8_t   *lp2p_keypair_secret_ptr(const lp2p_keypair_t *kp);

#endif /* LP2P_CRYPTO_KEYPAIR_INTERNAL_H */
