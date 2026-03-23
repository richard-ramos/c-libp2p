/* src/crypto/keypair.c — Ed25519 keypair generation and serialization */
#include <libp2p/crypto.h>
#include <libp2p/errors.h>
#include <libp2p/types.h>
#include <sodium.h>
#include <stdlib.h>
#include <string.h>

struct lp2p_keypair {
    lp2p_key_type_t type;
    uint8_t secret_key[crypto_sign_SECRETKEYBYTES]; /* 64 bytes */
    uint8_t public_key[crypto_sign_PUBLICKEYBYTES]; /* 32 bytes */
};

static int sodium_initialized = 0;

static void ensure_sodium(void) {
    if (!sodium_initialized) {
        int rc = sodium_init();
        (void)rc;
        sodium_initialized = 1;
    }
}

lp2p_err_t lp2p_keypair_generate(lp2p_key_type_t type, lp2p_keypair_t **out) {
    if (type != LP2P_KEY_ED25519)
        return LP2P_ERR_INVALID_ARG;
    if (!out)
        return LP2P_ERR_INVALID_ARG;

    ensure_sodium();

    lp2p_keypair_t *kp = calloc(1, sizeof(*kp));
    if (!kp) return LP2P_ERR_NOMEM;

    kp->type = LP2P_KEY_ED25519;
    crypto_sign_keypair(kp->public_key, kp->secret_key);

    *out = kp;
    return LP2P_OK;
}

lp2p_err_t lp2p_keypair_from_bytes(lp2p_key_type_t type, const uint8_t *priv,
                                    size_t len, lp2p_keypair_t **out) {
    if (type != LP2P_KEY_ED25519)
        return LP2P_ERR_INVALID_ARG;
    if (!priv || !out)
        return LP2P_ERR_INVALID_ARG;

    ensure_sodium();

    lp2p_keypair_t *kp = calloc(1, sizeof(*kp));
    if (!kp) return LP2P_ERR_NOMEM;

    kp->type = LP2P_KEY_ED25519;

    if (len == crypto_sign_SECRETKEYBYTES) {
        /* full 64-byte secret key (seed + pubkey) */
        memcpy(kp->secret_key, priv, crypto_sign_SECRETKEYBYTES);
        /* extract public key from last 32 bytes */
        memcpy(kp->public_key, priv + crypto_sign_SEEDBYTES, crypto_sign_PUBLICKEYBYTES);
    } else if (len == crypto_sign_SEEDBYTES) {
        /* 32-byte seed */
        crypto_sign_seed_keypair(kp->public_key, kp->secret_key, priv);
    } else {
        free(kp);
        return LP2P_ERR_INVALID_KEY;
    }

    *out = kp;
    return LP2P_OK;
}

lp2p_err_t lp2p_keypair_public_bytes(const lp2p_keypair_t *kp,
                                      uint8_t *out, size_t *out_len) {
    if (!kp || !out || !out_len)
        return LP2P_ERR_INVALID_ARG;
    if (*out_len < crypto_sign_PUBLICKEYBYTES)
        return LP2P_ERR_INVALID_ARG;
    memcpy(out, kp->public_key, crypto_sign_PUBLICKEYBYTES);
    *out_len = crypto_sign_PUBLICKEYBYTES;
    return LP2P_OK;
}

void lp2p_keypair_free(lp2p_keypair_t *kp) {
    if (kp) {
        sodium_memzero(kp->secret_key, sizeof(kp->secret_key));
        free(kp);
    }
}

/* ── Internal helpers used by peer_id.c ──────────────────────────────────── */

lp2p_key_type_t lp2p_keypair_type(const lp2p_keypair_t *kp) {
    return kp->type;
}

const uint8_t *lp2p_keypair_public_ptr(const lp2p_keypair_t *kp) {
    return kp->public_key;
}

const uint8_t *lp2p_keypair_secret_ptr(const lp2p_keypair_t *kp) {
    return kp->secret_key;
}
