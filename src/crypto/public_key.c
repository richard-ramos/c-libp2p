/* src/crypto/public_key.c — remote PublicKey decode + signature verification */
#include <libp2p/crypto.h>
#include <libp2p/errors.h>
#include <libp2p/types.h>
#include "noise.pb-c.h"
#include "crypto/keypair_internal.h"
#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <stdlib.h>
#include <string.h>

/* ── Public key structure (for remote peer identity verification) ──────── */
typedef struct {
    lp2p_key_type_t type;
    uint8_t        *data;
    size_t          data_len;
} lp2p_public_key_t;

static lp2p_public_key_t *pubkey_decode(const uint8_t *buf, size_t len) {
    Noise__PublicKey *pb = noise__public_key__unpack(NULL, len, buf);
    if (!pb) return NULL;

    lp2p_public_key_t *pk = calloc(1, sizeof(*pk));
    if (!pk) {
        noise__public_key__free_unpacked(pb, NULL);
        return NULL;
    }

    switch (pb->type) {
    case NOISE__KEY_TYPE__Ed25519:   pk->type = LP2P_KEY_ED25519;   break;
    case NOISE__KEY_TYPE__RSA:       pk->type = LP2P_KEY_RSA;       break;
    case NOISE__KEY_TYPE__Secp256k1: pk->type = LP2P_KEY_SECP256K1; break;
    case NOISE__KEY_TYPE__ECDSA:     pk->type = LP2P_KEY_ECDSA;     break;
    default:
        free(pk);
        noise__public_key__free_unpacked(pb, NULL);
        return NULL;
    }

    pk->data_len = pb->data.len;
    pk->data = malloc(pk->data_len);
    if (!pk->data) {
        free(pk);
        noise__public_key__free_unpacked(pb, NULL);
        return NULL;
    }
    memcpy(pk->data, pb->data.data, pk->data_len);

    noise__public_key__free_unpacked(pb, NULL);
    return pk;
}

static void pubkey_free(lp2p_public_key_t *pk) {
    if (pk) {
        free(pk->data);
        free(pk);
    }
}

/* ── Ed25519 verify via libsodium ────────────────────────────────────────── */
static bool verify_ed25519(const uint8_t *key_data, size_t key_len,
                            const uint8_t *msg, size_t msg_len,
                            const uint8_t *sig, size_t sig_len) {
    if (key_len != crypto_sign_PUBLICKEYBYTES) return false;
    if (sig_len != crypto_sign_BYTES) return false;
    return crypto_sign_verify_detached(sig, msg, msg_len, key_data) == 0;
}

/* ── RSA verify via OpenSSL ──────────────────────────────────────────────── */
static bool verify_rsa(const uint8_t *key_data, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        const uint8_t *sig, size_t sig_len) {
    const uint8_t *p = key_data;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)key_len);
    if (!pkey) return false;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return false; }

    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, msg, msg_len) == 1 &&
        EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) {
        ok = true;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/* ── Secp256k1 verify via OpenSSL ────────────────────────────────────────── */
static bool verify_secp256k1(const uint8_t *key_data, size_t key_len,
                              const uint8_t *msg, size_t msg_len,
                              const uint8_t *sig, size_t sig_len) {
    /* Hash the message with SHA-256 first */
    uint8_t hash[32];
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) return false;
    if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(md_ctx, msg, msg_len) != 1 ||
        EVP_DigestFinal_ex(md_ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(md_ctx);
        return false;
    }
    EVP_MD_CTX_free(md_ctx);

    /* Parse the uncompressed secp256k1 public key */
    EVP_PKEY *pkey = NULL;
    EC_KEY *ec = EC_KEY_new_by_curve_name(NID_secp256k1);
    if (!ec) return false;

    const uint8_t *p = key_data;
    if (!o2i_ECPublicKey(&ec, &p, (long)key_len)) {
        EC_KEY_free(ec);
        return false;
    }

    pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
        EC_KEY_free(ec);
        EVP_PKEY_free(pkey);
        return false;
    }

    /* Verify DER-encoded ECDSA signature over the hash */
    EVP_PKEY_CTX *vctx = EVP_PKEY_CTX_new(pkey, NULL);
    bool ok = false;
    if (vctx &&
        EVP_PKEY_verify_init(vctx) == 1 &&
        EVP_PKEY_verify(vctx, sig, sig_len, hash, 32) == 1) {
        ok = true;
    }
    EVP_PKEY_CTX_free(vctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/* ── ECDSA (P-256) verify via OpenSSL ────────────────────────────────────── */
static bool verify_ecdsa(const uint8_t *key_data, size_t key_len,
                          const uint8_t *msg, size_t msg_len,
                          const uint8_t *sig, size_t sig_len) {
    /* Parse DER-encoded SubjectPublicKeyInfo for P-256 */
    const uint8_t *p = key_data;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)key_len);
    if (!pkey) {
        /* Try as raw EC point on P-256 */
        EC_KEY *ec = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
        if (!ec) return false;
        p = key_data;
        if (!o2i_ECPublicKey(&ec, &p, (long)key_len)) {
            EC_KEY_free(ec);
            return false;
        }
        pkey = EVP_PKEY_new();
        if (!pkey || EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
            EC_KEY_free(ec);
            EVP_PKEY_free(pkey);
            return false;
        }
    }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return false; }

    bool ok = false;
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, msg, msg_len) == 1 &&
        EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) {
        ok = true;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok;
}

/* ── Public API used by the noise handshake ──────────────────────────────── */

/* Verify a signature over msg using the protobuf-encoded PublicKey.
   This is NOT declared in crypto.h but is used internally by the noise layer. */
bool lp2p_public_key_verify(const uint8_t *pubkey_proto, size_t proto_len,
                             const uint8_t *msg, size_t msg_len,
                             const uint8_t *sig, size_t sig_len) {
    lp2p_public_key_t *pk = pubkey_decode(pubkey_proto, proto_len);
    if (!pk) return false;

    bool ok = false;
    switch (pk->type) {
    case LP2P_KEY_ED25519:
        ok = verify_ed25519(pk->data, pk->data_len, msg, msg_len, sig, sig_len);
        break;
    case LP2P_KEY_RSA:
        ok = verify_rsa(pk->data, pk->data_len, msg, msg_len, sig, sig_len);
        break;
    case LP2P_KEY_SECP256K1:
        ok = verify_secp256k1(pk->data, pk->data_len, msg, msg_len, sig, sig_len);
        break;
    case LP2P_KEY_ECDSA:
        ok = verify_ecdsa(pk->data, pk->data_len, msg, msg_len, sig, sig_len);
        break;
    }

    pubkey_free(pk);
    return ok;
}

/* Sign a message with a local Ed25519 keypair.
   sig must have >= 64 bytes. Returns LP2P_OK on success. */
lp2p_err_t lp2p_keypair_sign(const lp2p_keypair_t *kp,
                               const uint8_t *msg, size_t msg_len,
                               uint8_t *sig, size_t *sig_len) {
    if (!kp || !msg || !sig || !sig_len)
        return LP2P_ERR_INVALID_ARG;
    if (*sig_len < crypto_sign_BYTES)
        return LP2P_ERR_INVALID_ARG;

    /* Access the secret key through the internal API */
    const uint8_t *sk = lp2p_keypair_secret_ptr(kp);
    unsigned long long actual_len;
    if (crypto_sign_detached(sig, &actual_len, msg, msg_len, sk) != 0)
        return LP2P_ERR_CRYPTO;

    *sig_len = (size_t)actual_len;
    return LP2P_OK;
}
