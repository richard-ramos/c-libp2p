/*
 * noise_keys.c — Key operations for Noise XX handshake
 *
 * - X25519 ephemeral keypair generation
 * - Ed25519 -> X25519 conversion (libsodium)
 * - Identity signing/verification for noise-libp2p static keys
 * - Protobuf PublicKey encoding and peer ID derivation
 */

#include "noise_internal.h"
#include "noise.pb-c.h"

#include <sodium.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

/* ── X25519 ephemeral keypair ──────────────────────────────────────────────── */

lp2p_err_t noise_generate_x25519_keypair(noise_x25519_kp_t *kp)
{
    if (!kp) return LP2P_ERR_INVALID_ARG;

    /* Generate random scalar (private key) and compute public key */
    randombytes_buf(kp->sk, NOISE_DH_LEN);
    if (crypto_scalarmult_base(kp->pk, kp->sk) != 0)
        return LP2P_ERR_CRYPTO;

    return LP2P_OK;
}

/* ── Ed25519 -> X25519 conversion ──────────────────────────────────────────── */

lp2p_err_t noise_ed25519_to_x25519(const uint8_t ed_pk[NOISE_ED25519_PK_LEN],
                                     const uint8_t ed_sk[NOISE_ED25519_SK_LEN],
                                     noise_x25519_kp_t *out)
{
    if (!ed_pk || !ed_sk || !out) return LP2P_ERR_INVALID_ARG;

    if (crypto_sign_ed25519_pk_to_curve25519(out->pk, ed_pk) != 0)
        return LP2P_ERR_CRYPTO;

    if (crypto_sign_ed25519_sk_to_curve25519(out->sk, ed_sk) != 0)
        return LP2P_ERR_CRYPTO;

    return LP2P_OK;
}

/* ── Sign static key ───────────────────────────────────────────────────────── */

lp2p_err_t noise_sign_static_key(const uint8_t ed_sk[NOISE_ED25519_SK_LEN],
                                  const uint8_t static_pk[NOISE_DH_LEN],
                                  uint8_t sig[NOISE_ED25519_SIG_LEN])
{
    if (!ed_sk || !static_pk || !sig) return LP2P_ERR_INVALID_ARG;

    /* Message to sign: "noise-libp2p-static-key:" + static_pk (32 bytes) */
    uint8_t msg[NOISE_SIG_PREFIX_LEN + NOISE_DH_LEN];
    memcpy(msg, NOISE_SIG_PREFIX, NOISE_SIG_PREFIX_LEN);
    memcpy(msg + NOISE_SIG_PREFIX_LEN, static_pk, NOISE_DH_LEN);

    if (crypto_sign_detached(sig, NULL, msg, sizeof(msg), ed_sk) != 0)
        return LP2P_ERR_CRYPTO;

    return LP2P_OK;
}

/* ── Build protobuf-encoded PublicKey ──────────────────────────────────────── */

lp2p_err_t noise_build_identity_key(const uint8_t ed_pk[NOISE_ED25519_PK_LEN],
                                     uint8_t **out, size_t *out_len)
{
    if (!ed_pk || !out || !out_len) return LP2P_ERR_INVALID_ARG;

    Noise__PublicKey pk_msg = NOISE__PUBLIC_KEY__INIT;
    pk_msg.type = NOISE__KEY_TYPE__Ed25519;
    pk_msg.data.data = (uint8_t *)ed_pk;
    pk_msg.data.len  = NOISE_ED25519_PK_LEN;

    size_t packed_len = noise__public_key__get_packed_size(&pk_msg);
    uint8_t *buf = malloc(packed_len);
    if (!buf) return LP2P_ERR_NOMEM;

    noise__public_key__pack(&pk_msg, buf);
    *out = buf;
    *out_len = packed_len;
    return LP2P_OK;
}

/* ── Peer ID from protobuf-encoded PublicKey ───────────────────────────────── */

/*
 * For Ed25519 keys (32 bytes), the peer ID is the identity multihash
 * of the protobuf-encoded PublicKey:
 *   0x00 (identity hash fn) + varint(length) + raw_proto_bytes
 *
 * For keys > 42 bytes, SHA-256 multihash is used:
 *   0x12 0x20 + SHA-256(proto_bytes)
 */
lp2p_err_t noise_peer_id_from_pubkey_proto(const uint8_t *proto_buf, size_t proto_len,
                                            lp2p_peer_id_t *out)
{
    if (!proto_buf || !out) return LP2P_ERR_INVALID_ARG;

    if (proto_len <= 42) {
        /* Identity multihash: 0x00 + varint(len) + data */
        if (2 + proto_len > LP2P_PEER_ID_SIZE) return LP2P_ERR_INTERNAL;
        out->bytes[0] = 0x00;              /* identity hash code */
        out->bytes[1] = (uint8_t)proto_len; /* length (fits in 1 byte) */
        memcpy(out->bytes + 2, proto_buf, proto_len);
        out->len = 2 + proto_len;
    } else {
        /* SHA-256 multihash */
        uint8_t hash[32];
        SHA256(proto_buf, proto_len, hash);
        out->bytes[0] = 0x12; /* SHA-256 code */
        out->bytes[1] = 0x20; /* 32 bytes */
        memcpy(out->bytes + 2, hash, 32);
        out->len = 34;
    }

    return LP2P_OK;
}

/* ── Verify Ed25519 signature ──────────────────────────────────────────────── */

static lp2p_err_t verify_ed25519_sig(const uint8_t *pubkey, size_t pk_len,
                                      const uint8_t *sig, size_t sig_len,
                                      const uint8_t *msg, size_t msg_len)
{
    if (pk_len != NOISE_ED25519_PK_LEN || sig_len != NOISE_ED25519_SIG_LEN)
        return LP2P_ERR_HANDSHAKE_FAILED;

    if (crypto_sign_verify_detached(sig, msg, msg_len, pubkey) != 0)
        return LP2P_ERR_HANDSHAKE_FAILED;

    return LP2P_OK;
}

/* ── Verify RSA/Secp256k1/ECDSA signature via OpenSSL ──────────────────────── */

static lp2p_err_t verify_openssl_sig(int nid, const uint8_t *pubkey_der, size_t pk_len,
                                      const uint8_t *sig, size_t sig_len,
                                      const uint8_t *msg, size_t msg_len)
{
    const uint8_t *p = pubkey_der;
    EVP_PKEY *pkey = d2i_PUBKEY(NULL, &p, (long)pk_len);
    if (!pkey) return LP2P_ERR_HANDSHAKE_FAILED;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        EVP_PKEY_free(pkey);
        return LP2P_ERR_NOMEM;
    }

    const EVP_MD *md = EVP_sha256();
    lp2p_err_t ret = LP2P_ERR_HANDSHAKE_FAILED;

    if (EVP_DigestVerifyInit(mdctx, NULL, md, NULL, pkey) == 1 &&
        EVP_DigestVerify(mdctx, sig, sig_len, msg, msg_len) == 1) {
        ret = LP2P_OK;
    }

    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    return ret;
}

/* ── Verify remote handshake payload ───────────────────────────────────────── */

lp2p_err_t noise_verify_payload(const uint8_t *payload_buf, size_t payload_len,
                                 const uint8_t remote_static_pk[NOISE_DH_LEN],
                                 lp2p_peer_id_t *remote_id_out)
{
    if (!payload_buf || !remote_static_pk || !remote_id_out)
        return LP2P_ERR_INVALID_ARG;

    /* Decode the NoiseHandshakePayload protobuf */
    Noise__NoiseHandshakePayload *payload =
        noise__noise_handshake_payload__unpack(NULL, payload_len, payload_buf);
    if (!payload) return LP2P_ERR_HANDSHAKE_FAILED;

    lp2p_err_t err = LP2P_ERR_HANDSHAKE_FAILED;

    /* Must have identity_key and identity_sig */
    if (!payload->identity_key.data || payload->identity_key.len == 0 ||
        !payload->identity_sig.data || payload->identity_sig.len == 0) {
        goto done;
    }

    /* Decode the PublicKey from identity_key */
    Noise__PublicKey *pk =
        noise__public_key__unpack(NULL, payload->identity_key.len,
                                   payload->identity_key.data);
    if (!pk) goto done;

    /* Build the signed message: prefix + static_pk */
    uint8_t sign_msg[NOISE_SIG_PREFIX_LEN + NOISE_DH_LEN];
    memcpy(sign_msg, NOISE_SIG_PREFIX, NOISE_SIG_PREFIX_LEN);
    memcpy(sign_msg + NOISE_SIG_PREFIX_LEN, remote_static_pk, NOISE_DH_LEN);

    /* Verify based on key type */
    switch (pk->type) {
    case NOISE__KEY_TYPE__Ed25519:
        err = verify_ed25519_sig(pk->data.data, pk->data.len,
                                  payload->identity_sig.data,
                                  payload->identity_sig.len,
                                  sign_msg, sizeof(sign_msg));
        break;
    case NOISE__KEY_TYPE__RSA:
        err = verify_openssl_sig(0, pk->data.data, pk->data.len,
                                  payload->identity_sig.data,
                                  payload->identity_sig.len,
                                  sign_msg, sizeof(sign_msg));
        break;
    case NOISE__KEY_TYPE__Secp256k1:
    case NOISE__KEY_TYPE__ECDSA:
        err = verify_openssl_sig(0, pk->data.data, pk->data.len,
                                  payload->identity_sig.data,
                                  payload->identity_sig.len,
                                  sign_msg, sizeof(sign_msg));
        break;
    default:
        err = LP2P_ERR_HANDSHAKE_FAILED;
        break;
    }

    if (err == LP2P_OK) {
        /* Derive peer ID from the protobuf-encoded public key */
        err = noise_peer_id_from_pubkey_proto(payload->identity_key.data,
                                               payload->identity_key.len,
                                               remote_id_out);
    }

    noise__public_key__free_unpacked(pk, NULL);

done:
    noise__noise_handshake_payload__free_unpacked(payload, NULL);
    return err;
}
