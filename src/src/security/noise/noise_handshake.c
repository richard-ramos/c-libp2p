/*
 * noise_handshake.c — Noise XX handshake implementation
 *
 * Implements the Noise_XX_25519_ChaChaPoly_SHA256 handshake pattern:
 *   -> e
 *   <- e, ee, s, es
 *   -> s, se
 *
 * Each message 2 and 3 carries a NoiseHandshakePayload (protobuf) in the
 * encrypted s payload, containing the libp2p identity key and signature.
 */

#include "noise_internal.h"
#include "noise.pb-c.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

/* ── HMAC-SHA256 (using libsodium's crypto_auth_hmacsha256) ────────────────── */

static void hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t out[NOISE_HASH_LEN])
{
    crypto_auth_hmacsha256_state state;
    crypto_auth_hmacsha256_init(&state, key, key_len);
    crypto_auth_hmacsha256_update(&state, data, data_len);
    crypto_auth_hmacsha256_final(&state, out);
}

/* ── HKDF (2-output, per Noise spec) ──────────────────────────────────────── */

static void hkdf2(const uint8_t ck[NOISE_HASH_LEN],
                   const uint8_t *ikm, size_t ikm_len,
                   uint8_t out1[NOISE_HASH_LEN],
                   uint8_t out2[NOISE_HASH_LEN])
{
    uint8_t temp_key[NOISE_HASH_LEN];
    hmac_sha256(ck, NOISE_HASH_LEN, ikm, ikm_len, temp_key);

    /* output1 = HMAC(temp_key, 0x01) */
    uint8_t one = 0x01;
    hmac_sha256(temp_key, NOISE_HASH_LEN, &one, 1, out1);

    /* output2 = HMAC(temp_key, output1 || 0x02) */
    uint8_t buf[NOISE_HASH_LEN + 1];
    memcpy(buf, out1, NOISE_HASH_LEN);
    buf[NOISE_HASH_LEN] = 0x02;
    hmac_sha256(temp_key, NOISE_HASH_LEN, buf, sizeof(buf), out2);

    sodium_memzero(temp_key, sizeof(temp_key));
}

/* ── SHA-256 helper ────────────────────────────────────────────────────────── */

static void sha256(const uint8_t *data, size_t len, uint8_t out[NOISE_HASH_LEN])
{
    crypto_hash_sha256(out, data, len);
}

/* ── SymmetricState operations ─────────────────────────────────────────────── */

static void symmetric_init(noise_symmetric_state_t *ss, const char *protocol_name)
{
    size_t name_len = strlen(protocol_name);

    /* Initialize h */
    if (name_len <= NOISE_HASH_LEN) {
        memset(ss->h, 0, NOISE_HASH_LEN);
        memcpy(ss->h, protocol_name, name_len);
    } else {
        sha256((const uint8_t *)protocol_name, name_len, ss->h);
    }

    /* ck = h */
    memcpy(ss->ck, ss->h, NOISE_HASH_LEN);

    /* CipherState starts empty */
    ss->cs.has_key = false;
    ss->cs.n = 0;
    memset(ss->cs.k, 0, NOISE_AEAD_KEY_LEN);
}

static void mix_hash(noise_symmetric_state_t *ss, const uint8_t *data, size_t len)
{
    /* h = SHA-256(h || data) */
    crypto_hash_sha256_state state;
    crypto_hash_sha256_init(&state);
    crypto_hash_sha256_update(&state, ss->h, NOISE_HASH_LEN);
    crypto_hash_sha256_update(&state, data, len);
    crypto_hash_sha256_final(&state, ss->h);
}

static void mix_key(noise_symmetric_state_t *ss, const uint8_t *ikm, size_t ikm_len)
{
    uint8_t temp_k[NOISE_HASH_LEN];
    hkdf2(ss->ck, ikm, ikm_len, ss->ck, temp_k);

    /* Truncate temp_k to AEAD key length (same size for ChaChaPoly) */
    memcpy(ss->cs.k, temp_k, NOISE_AEAD_KEY_LEN);
    ss->cs.n = 0;
    ss->cs.has_key = true;

    sodium_memzero(temp_k, sizeof(temp_k));
}

/* ── AEAD encrypt/decrypt ──────────────────────────────────────────────────── */

static void nonce_to_bytes(uint64_t n, uint8_t out[NOISE_AEAD_NONCE_LEN])
{
    /* Noise spec: 4 bytes zeros + 8 bytes little-endian counter */
    memset(out, 0, 4);
    for (int i = 0; i < 8; i++)
        out[4 + i] = (uint8_t)(n >> (8 * i));
}

static lp2p_err_t encrypt_with_ad(noise_cipher_state_t *cs,
                                    const uint8_t *ad, size_t ad_len,
                                    const uint8_t *plain, size_t plain_len,
                                    uint8_t *out, size_t *out_len)
{
    if (!cs->has_key) {
        /* No key => pass through plaintext */
        memcpy(out, plain, plain_len);
        *out_len = plain_len;
        return LP2P_OK;
    }

    uint8_t nonce[NOISE_AEAD_NONCE_LEN];
    nonce_to_bytes(cs->n, nonce);

    unsigned long long clen;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            out, &clen, plain, plain_len, ad, ad_len, NULL, nonce, cs->k) != 0)
        return LP2P_ERR_CRYPTO;

    *out_len = (size_t)clen;
    cs->n++;
    return LP2P_OK;
}

static lp2p_err_t decrypt_with_ad(noise_cipher_state_t *cs,
                                    const uint8_t *ad, size_t ad_len,
                                    const uint8_t *cipher, size_t cipher_len,
                                    uint8_t *out, size_t *out_len)
{
    if (!cs->has_key) {
        memcpy(out, cipher, cipher_len);
        *out_len = cipher_len;
        return LP2P_OK;
    }

    uint8_t nonce[NOISE_AEAD_NONCE_LEN];
    nonce_to_bytes(cs->n, nonce);

    unsigned long long mlen;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out, &mlen, NULL, cipher, cipher_len, ad, ad_len, nonce, cs->k) != 0)
        return LP2P_ERR_HANDSHAKE_FAILED;

    *out_len = (size_t)mlen;
    cs->n++;
    return LP2P_OK;
}

/* ── Encrypt/decrypt and mix into handshake hash ───────────────────────────── */

static lp2p_err_t encrypt_and_hash(noise_symmetric_state_t *ss,
                                     const uint8_t *plain, size_t plain_len,
                                     uint8_t *out, size_t *out_len)
{
    lp2p_err_t err = encrypt_with_ad(&ss->cs, ss->h, NOISE_HASH_LEN,
                                      plain, plain_len, out, out_len);
    if (err != LP2P_OK) return err;
    mix_hash(ss, out, *out_len);
    return LP2P_OK;
}

static lp2p_err_t decrypt_and_hash(noise_symmetric_state_t *ss,
                                     const uint8_t *cipher, size_t cipher_len,
                                     uint8_t *out, size_t *out_len)
{
    /* Mix hash with ciphertext BEFORE decryption (per Noise spec) */
    uint8_t h_save[NOISE_HASH_LEN];
    memcpy(h_save, ss->h, NOISE_HASH_LEN);

    mix_hash(ss, cipher, cipher_len);

    /* Decrypt using saved h as AD */
    lp2p_err_t err = decrypt_with_ad(&ss->cs, h_save, NOISE_HASH_LEN,
                                      cipher, cipher_len, out, out_len);
    if (err != LP2P_OK) {
        /* Restore hash on failure */
        memcpy(ss->h, h_save, NOISE_HASH_LEN);
    }

    sodium_memzero(h_save, sizeof(h_save));
    return err;
}

/* ── DH operation ──────────────────────────────────────────────────────────── */

static lp2p_err_t dh(const uint8_t sk[NOISE_DH_LEN],
                       const uint8_t pk[NOISE_DH_LEN],
                       uint8_t out[NOISE_DH_LEN])
{
    if (crypto_scalarmult(out, sk, pk) != 0)
        return LP2P_ERR_CRYPTO;
    return LP2P_OK;
}

/* ── Build NoiseHandshakePayload ───────────────────────────────────────────── */

static lp2p_err_t build_handshake_payload(const uint8_t ed_pk[NOISE_ED25519_PK_LEN],
                                            const uint8_t ed_sk[NOISE_ED25519_SK_LEN],
                                            const uint8_t static_pk[NOISE_DH_LEN],
                                            uint8_t **out, size_t *out_len)
{
    uint8_t *identity_key = NULL;
    size_t identity_key_len = 0;
    lp2p_err_t err;

    /* Build protobuf-encoded PublicKey */
    err = noise_build_identity_key(ed_pk, &identity_key, &identity_key_len);
    if (err != LP2P_OK) return err;

    /* Sign the static key */
    uint8_t sig[NOISE_ED25519_SIG_LEN];
    err = noise_sign_static_key(ed_sk, static_pk, sig);
    if (err != LP2P_OK) {
        free(identity_key);
        return err;
    }

    /* Encode NoiseHandshakePayload */
    Noise__NoiseHandshakePayload payload = NOISE__NOISE_HANDSHAKE_PAYLOAD__INIT;
    payload.identity_key.data = identity_key;
    payload.identity_key.len  = identity_key_len;
    payload.has_identity_key  = 1;
    payload.identity_sig.data = sig;
    payload.identity_sig.len  = NOISE_ED25519_SIG_LEN;
    payload.has_identity_sig  = 1;

    size_t packed_len = noise__noise_handshake_payload__get_packed_size(&payload);
    uint8_t *buf = malloc(packed_len);
    if (!buf) {
        free(identity_key);
        return LP2P_ERR_NOMEM;
    }

    noise__noise_handshake_payload__pack(&payload, buf);
    free(identity_key);

    *out = buf;
    *out_len = packed_len;
    return LP2P_OK;
}

/* ── Handshake initialization ──────────────────────────────────────────────── */

lp2p_err_t noise_handshake_init(noise_handshake_state_t *hs,
                                 bool initiator,
                                 const uint8_t ed_pk[NOISE_ED25519_PK_LEN],
                                 const uint8_t ed_sk[NOISE_ED25519_SK_LEN])
{
    if (!hs || !ed_pk || !ed_sk) return LP2P_ERR_INVALID_ARG;

    memset(hs, 0, sizeof(*hs));
    hs->is_initiator = initiator;
    hs->msg_index = 0;

    /* Copy Ed25519 identity keys */
    memcpy(hs->local_ed25519_pk, ed_pk, NOISE_ED25519_PK_LEN);
    memcpy(hs->local_ed25519_sk, ed_sk, NOISE_ED25519_SK_LEN);

    /* Convert Ed25519 -> X25519 for static key */
    lp2p_err_t err = noise_ed25519_to_x25519(ed_pk, ed_sk, &hs->s);
    if (err != LP2P_OK) return err;

    /* Generate ephemeral X25519 keypair */
    err = noise_generate_x25519_keypair(&hs->e);
    if (err != LP2P_OK) return err;

    /* Initialize SymmetricState with protocol name */
    symmetric_init(&hs->symmetric, NOISE_PROTOCOL_NAME);

    /* XX pattern has empty prologue — mix empty hash */
    mix_hash(&hs->symmetric, (const uint8_t *)"", 0);

    return LP2P_OK;
}

/* ── Write handshake message ───────────────────────────────────────────────── */

lp2p_err_t noise_handshake_write_msg(noise_handshake_state_t *hs,
                                      uint8_t *out, size_t *out_len)
{
    if (!hs || !out || !out_len) return LP2P_ERR_INVALID_ARG;

    lp2p_err_t err;
    size_t pos = 0;
    uint8_t dh_result[NOISE_DH_LEN];

    if (hs->is_initiator && hs->msg_index == 0) {
        /*
         * Message 1 (initiator -> responder): -> e
         *
         * Send ephemeral public key, mix into hash.
         * Payload is empty (no encryption yet).
         */
        memcpy(out + pos, hs->e.pk, NOISE_DH_LEN);
        mix_hash(&hs->symmetric, hs->e.pk, NOISE_DH_LEN);
        pos += NOISE_DH_LEN;

        /* Empty payload (no key set yet, so encrypt_and_hash is passthrough) */
        size_t enc_len = 0;
        err = encrypt_and_hash(&hs->symmetric, NULL, 0, out + pos, &enc_len);
        if (err != LP2P_OK) return err;
        pos += enc_len;

    } else if (!hs->is_initiator && hs->msg_index == 1) {
        /*
         * Message 2 (responder -> initiator): <- e, ee, s, es
         */

        /* e: send ephemeral */
        memcpy(out + pos, hs->e.pk, NOISE_DH_LEN);
        mix_hash(&hs->symmetric, hs->e.pk, NOISE_DH_LEN);
        pos += NOISE_DH_LEN;

        /* ee: DH(e, re) */
        err = dh(hs->e.sk, hs->re, dh_result);
        if (err != LP2P_OK) return err;
        mix_key(&hs->symmetric, dh_result, NOISE_DH_LEN);

        /* s: encrypt static public key */
        size_t enc_len = 0;
        err = encrypt_and_hash(&hs->symmetric, hs->s.pk, NOISE_DH_LEN,
                                out + pos, &enc_len);
        if (err != LP2P_OK) return err;
        pos += enc_len;

        /* es: DH(s, re) */
        err = dh(hs->s.sk, hs->re, dh_result);
        if (err != LP2P_OK) return err;
        mix_key(&hs->symmetric, dh_result, NOISE_DH_LEN);

        /* Encrypt the handshake payload (identity key + signature) */
        uint8_t *payload_buf = NULL;
        size_t payload_len = 0;
        err = build_handshake_payload(hs->local_ed25519_pk, hs->local_ed25519_sk,
                                       hs->s.pk, &payload_buf, &payload_len);
        if (err != LP2P_OK) return err;

        enc_len = 0;
        err = encrypt_and_hash(&hs->symmetric, payload_buf, payload_len,
                                out + pos, &enc_len);
        free(payload_buf);
        if (err != LP2P_OK) return err;
        pos += enc_len;

    } else if (hs->is_initiator && hs->msg_index == 2) {
        /*
         * Message 3 (initiator -> responder): -> s, se
         */

        /* s: encrypt static public key */
        size_t enc_len = 0;
        err = encrypt_and_hash(&hs->symmetric, hs->s.pk, NOISE_DH_LEN,
                                out + pos, &enc_len);
        if (err != LP2P_OK) return err;
        pos += enc_len;

        /* se: DH(s, re) */
        err = dh(hs->s.sk, hs->re, dh_result);
        if (err != LP2P_OK) return err;
        mix_key(&hs->symmetric, dh_result, NOISE_DH_LEN);

        /* Encrypt the handshake payload */
        uint8_t *payload_buf = NULL;
        size_t payload_len = 0;
        err = build_handshake_payload(hs->local_ed25519_pk, hs->local_ed25519_sk,
                                       hs->s.pk, &payload_buf, &payload_len);
        if (err != LP2P_OK) return err;

        enc_len = 0;
        err = encrypt_and_hash(&hs->symmetric, payload_buf, payload_len,
                                out + pos, &enc_len);
        free(payload_buf);
        if (err != LP2P_OK) return err;
        pos += enc_len;

    } else {
        return LP2P_ERR_INTERNAL;
    }

    sodium_memzero(dh_result, sizeof(dh_result));
    *out_len = pos;
    hs->msg_index++;
    return LP2P_OK;
}

/* ── Read handshake message ────────────────────────────────────────────────── */

lp2p_err_t noise_handshake_read_msg(noise_handshake_state_t *hs,
                                     const uint8_t *msg, size_t msg_len)
{
    if (!hs || !msg) return LP2P_ERR_INVALID_ARG;

    lp2p_err_t err;
    size_t pos = 0;
    uint8_t dh_result[NOISE_DH_LEN];

    if (!hs->is_initiator && hs->msg_index == 0) {
        /*
         * Message 1 (received by responder): -> e
         */
        if (msg_len < NOISE_DH_LEN) return LP2P_ERR_HANDSHAKE_FAILED;

        memcpy(hs->re, msg, NOISE_DH_LEN);
        hs->has_re = true;
        mix_hash(&hs->symmetric, hs->re, NOISE_DH_LEN);
        pos += NOISE_DH_LEN;

        /* Decrypt empty payload */
        uint8_t dec_buf[256];
        size_t dec_len = 0;
        err = decrypt_and_hash(&hs->symmetric, msg + pos, msg_len - pos,
                                dec_buf, &dec_len);
        if (err != LP2P_OK) return err;

    } else if (hs->is_initiator && hs->msg_index == 1) {
        /*
         * Message 2 (received by initiator): <- e, ee, s, es
         */
        if (msg_len < NOISE_DH_LEN) return LP2P_ERR_HANDSHAKE_FAILED;

        /* e: read remote ephemeral */
        memcpy(hs->re, msg, NOISE_DH_LEN);
        hs->has_re = true;
        mix_hash(&hs->symmetric, hs->re, NOISE_DH_LEN);
        pos += NOISE_DH_LEN;

        /* ee: DH(e, re) */
        err = dh(hs->e.sk, hs->re, dh_result);
        if (err != LP2P_OK) return err;
        mix_key(&hs->symmetric, dh_result, NOISE_DH_LEN);

        /* s: decrypt remote static key */
        size_t s_enc_len = NOISE_DH_LEN + NOISE_AEAD_TAG_LEN;
        if (pos + s_enc_len > msg_len) return LP2P_ERR_HANDSHAKE_FAILED;

        uint8_t dec_s[NOISE_DH_LEN];
        size_t dec_s_len = 0;
        err = decrypt_and_hash(&hs->symmetric, msg + pos, s_enc_len,
                                dec_s, &dec_s_len);
        if (err != LP2P_OK) return err;
        if (dec_s_len != NOISE_DH_LEN) return LP2P_ERR_HANDSHAKE_FAILED;

        memcpy(hs->rs, dec_s, NOISE_DH_LEN);
        hs->has_rs = true;
        pos += s_enc_len;

        /* es: DH(e, rs) */
        err = dh(hs->e.sk, hs->rs, dh_result);
        if (err != LP2P_OK) return err;
        mix_key(&hs->symmetric, dh_result, NOISE_DH_LEN);

        /* Decrypt handshake payload */
        size_t payload_enc_len = msg_len - pos;
        uint8_t *dec_payload = malloc(payload_enc_len);
        if (!dec_payload) return LP2P_ERR_NOMEM;

        size_t dec_payload_len = 0;
        err = decrypt_and_hash(&hs->symmetric, msg + pos, payload_enc_len,
                                dec_payload, &dec_payload_len);
        if (err != LP2P_OK) {
            free(dec_payload);
            return err;
        }

        /* Verify remote identity */
        err = noise_verify_payload(dec_payload, dec_payload_len,
                                    hs->rs, &hs->remote_peer_id);
        free(dec_payload);
        if (err != LP2P_OK) return err;
        hs->remote_verified = true;

    } else if (!hs->is_initiator && hs->msg_index == 2) {
        /*
         * Message 3 (received by responder): -> s, se
         */

        /* s: decrypt remote static key */
        size_t s_enc_len = NOISE_DH_LEN + NOISE_AEAD_TAG_LEN;
        if (pos + s_enc_len > msg_len) return LP2P_ERR_HANDSHAKE_FAILED;

        uint8_t dec_s[NOISE_DH_LEN];
        size_t dec_s_len = 0;
        err = decrypt_and_hash(&hs->symmetric, msg + pos, s_enc_len,
                                dec_s, &dec_s_len);
        if (err != LP2P_OK) return err;
        if (dec_s_len != NOISE_DH_LEN) return LP2P_ERR_HANDSHAKE_FAILED;

        memcpy(hs->rs, dec_s, NOISE_DH_LEN);
        hs->has_rs = true;
        pos += s_enc_len;

        /* se: DH(e, rs) */
        err = dh(hs->e.sk, hs->rs, dh_result);
        if (err != LP2P_OK) return err;
        mix_key(&hs->symmetric, dh_result, NOISE_DH_LEN);

        /* Decrypt handshake payload */
        size_t payload_enc_len = msg_len - pos;
        uint8_t *dec_payload = malloc(payload_enc_len);
        if (!dec_payload) return LP2P_ERR_NOMEM;

        size_t dec_payload_len = 0;
        err = decrypt_and_hash(&hs->symmetric, msg + pos, payload_enc_len,
                                dec_payload, &dec_payload_len);
        if (err != LP2P_OK) {
            free(dec_payload);
            return err;
        }

        /* Verify remote identity */
        err = noise_verify_payload(dec_payload, dec_payload_len,
                                    hs->rs, &hs->remote_peer_id);
        free(dec_payload);
        if (err != LP2P_OK) return err;
        hs->remote_verified = true;

    } else {
        return LP2P_ERR_INTERNAL;
    }

    sodium_memzero(dh_result, sizeof(dh_result));
    hs->msg_index++;
    return LP2P_OK;
}

/* ── Split into transport cipher states ────────────────────────────────────── */

lp2p_err_t noise_handshake_split(noise_handshake_state_t *hs,
                                  noise_session_t *session)
{
    if (!hs || !session) return LP2P_ERR_INVALID_ARG;
    if (hs->msg_index != 3) return LP2P_ERR_INTERNAL;
    if (!hs->remote_verified) return LP2P_ERR_HANDSHAKE_FAILED;

    memset(session, 0, sizeof(*session));

    /* HKDF split: derive two keys from chaining key */
    uint8_t k1[NOISE_HASH_LEN], k2[NOISE_HASH_LEN];
    hkdf2(hs->symmetric.ck, (const uint8_t *)"", 0, k1, k2);

    /* Initiator sends with k1, receives with k2.
     * Responder sends with k2, receives with k1. */
    if (hs->is_initiator) {
        memcpy(session->send_cipher.k, k1, NOISE_AEAD_KEY_LEN);
        memcpy(session->recv_cipher.k, k2, NOISE_AEAD_KEY_LEN);
    } else {
        memcpy(session->send_cipher.k, k2, NOISE_AEAD_KEY_LEN);
        memcpy(session->recv_cipher.k, k1, NOISE_AEAD_KEY_LEN);
    }

    session->send_cipher.n = 0;
    session->send_cipher.has_key = true;
    session->recv_cipher.n = 0;
    session->recv_cipher.has_key = true;

    /* Copy handshake hash for channel binding */
    memcpy(session->handshake_hash, hs->symmetric.h, NOISE_HASH_LEN);

    /* Copy remote peer ID */
    memcpy(&session->remote_peer_id, &hs->remote_peer_id, sizeof(lp2p_peer_id_t));

    /* Zeroize handshake state */
    sodium_memzero(hs, sizeof(*hs));

    sodium_memzero(k1, sizeof(k1));
    sodium_memzero(k2, sizeof(k2));

    return LP2P_OK;
}
