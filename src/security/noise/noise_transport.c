/*
 * noise_transport.c — Post-handshake encrypted transport framing
 *
 * Framing: 2-byte big-endian length prefix + encrypted payload (includes AEAD tag)
 * Max Noise message: 65535 bytes
 *
 * Also implements the lp2p_security_vtable_t for integration with the
 * libp2p security layer.
 */

#include "noise_internal.h"

#include <sodium.h>
#include <stdlib.h>
#include <string.h>

/* ── AEAD helpers (same as handshake, but for transport) ───────────────────── */

static void nonce_to_bytes(uint64_t n, uint8_t out[NOISE_AEAD_NONCE_LEN])
{
    memset(out, 0, 4);
    for (int i = 0; i < 8; i++)
        out[4 + i] = (uint8_t)(n >> (8 * i));
}

/* ── Encrypt a frame ───────────────────────────────────────────────────────── */

lp2p_err_t noise_encrypt_frame(noise_cipher_state_t *cs,
                                const uint8_t *plain, size_t plain_len,
                                uint8_t *out, size_t *out_len)
{
    if (!cs || !out || !out_len) return LP2P_ERR_INVALID_ARG;
    if (!cs->has_key) return LP2P_ERR_CRYPTO;

    /* Ciphertext = plain + 16 byte tag */
    size_t ct_len = plain_len + NOISE_AEAD_TAG_LEN;
    if (ct_len > NOISE_MAX_MSG_LEN) return LP2P_ERR_INVALID_ARG;

    /* Frame: 2-byte BE length + ciphertext */
    size_t frame_len = NOISE_FRAME_HDR_LEN + ct_len;

    /* Write length prefix (big-endian, length of ciphertext) */
    out[0] = (uint8_t)(ct_len >> 8);
    out[1] = (uint8_t)(ct_len & 0xFF);

    uint8_t nonce[NOISE_AEAD_NONCE_LEN];
    nonce_to_bytes(cs->n, nonce);

    unsigned long long clen;
    if (crypto_aead_chacha20poly1305_ietf_encrypt(
            out + NOISE_FRAME_HDR_LEN, &clen,
            plain, plain_len,
            NULL, 0,  /* no AD for transport messages */
            NULL, nonce, cs->k) != 0)
        return LP2P_ERR_CRYPTO;

    cs->n++;
    *out_len = frame_len;
    return LP2P_OK;
}

/* ── Decrypt a frame ───────────────────────────────────────────────────────── */

lp2p_err_t noise_decrypt_frame(noise_cipher_state_t *cs,
                                const uint8_t *frame, size_t frame_len,
                                uint8_t *out, size_t *out_len)
{
    if (!cs || !frame || !out || !out_len) return LP2P_ERR_INVALID_ARG;
    if (!cs->has_key) return LP2P_ERR_CRYPTO;
    if (frame_len < NOISE_FRAME_HDR_LEN) return LP2P_ERR_PROTOCOL;

    /* Read length prefix */
    size_t ct_len = ((size_t)frame[0] << 8) | (size_t)frame[1];
    if (ct_len + NOISE_FRAME_HDR_LEN != frame_len) return LP2P_ERR_PROTOCOL;
    if (ct_len < NOISE_AEAD_TAG_LEN) return LP2P_ERR_PROTOCOL;
    if (ct_len > NOISE_MAX_MSG_LEN) return LP2P_ERR_PROTOCOL;

    uint8_t nonce[NOISE_AEAD_NONCE_LEN];
    nonce_to_bytes(cs->n, nonce);

    unsigned long long mlen;
    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out, &mlen, NULL,
            frame + NOISE_FRAME_HDR_LEN, ct_len,
            NULL, 0,  /* no AD */
            nonce, cs->k) != 0)
        return LP2P_ERR_CRYPTO;

    cs->n++;
    *out_len = (size_t)mlen;
    return LP2P_OK;
}

/* ── Security vtable implementation ────────────────────────────────────────── */

/*
 * The vtable expects a simple session handle. We wrap noise_session_t
 * and expose handshake/encrypt/decrypt/free.
 *
 * For the handshake vtable callback, we run a synchronous in-memory
 * XX handshake. In a real implementation this would be async over the
 * transport, but the vtable callback interface allows us to drive it
 * synchronously and call on_done when complete.
 */

typedef struct {
    noise_session_t  session;
    bool             handshake_done;

    /* Handshake state (kept until handshake completes) */
    noise_handshake_state_t *hs;
} noise_impl_t;

static lp2p_err_t vtable_handshake(void *session_ptr,
                                     void (*on_done)(lp2p_err_t err,
                                                      const lp2p_peer_id_t *remote_peer,
                                                      void *userdata),
                                     void *userdata)
{
    noise_impl_t *impl = (noise_impl_t *)session_ptr;

    if (impl->handshake_done) {
        /* Already completed */
        on_done(LP2P_OK, &impl->session.remote_peer_id, userdata);
        return LP2P_OK;
    }

    /* In a real implementation, the handshake messages would be exchanged
     * over the underlying transport connection. This vtable entry serves
     * as the hook point for the connection upgrade flow. The actual
     * message exchange is driven by noise_handshake_write_msg/read_msg
     * from the connection upgrade code. */
    on_done(LP2P_ERR_INTERNAL, NULL, userdata);
    return LP2P_ERR_INTERNAL;
}

static lp2p_err_t vtable_encrypt(void *session_ptr,
                                   const uint8_t *plain, size_t len,
                                   uint8_t *out, size_t *out_len)
{
    noise_impl_t *impl = (noise_impl_t *)session_ptr;
    if (!impl->handshake_done) return LP2P_ERR_INTERNAL;

    return noise_encrypt_frame(&impl->session.send_cipher,
                                plain, len, out, out_len);
}

static lp2p_err_t vtable_decrypt(void *session_ptr,
                                   const uint8_t *cipher, size_t len,
                                   uint8_t *out, size_t *out_len)
{
    noise_impl_t *impl = (noise_impl_t *)session_ptr;
    if (!impl->handshake_done) return LP2P_ERR_INTERNAL;

    return noise_decrypt_frame(&impl->session.recv_cipher,
                                cipher, len, out, out_len);
}

static void vtable_free(void *session_ptr)
{
    noise_impl_t *impl = (noise_impl_t *)session_ptr;
    if (!impl) return;

    if (impl->hs) {
        sodium_memzero(impl->hs, sizeof(*impl->hs));
        free(impl->hs);
    }

    sodium_memzero(&impl->session, sizeof(impl->session));
    free(impl);
}

static const lp2p_security_vtable_t noise_vtable = {
    .handshake = vtable_handshake,
    .encrypt   = vtable_encrypt,
    .decrypt   = vtable_decrypt,
    .free      = vtable_free,
};

/* ── Create security session from completed noise session ──────────────────── */

lp2p_err_t noise_session_create(noise_session_t *ns,
                                 lp2p_security_session_t *out)
{
    if (!ns || !out) return LP2P_ERR_INVALID_ARG;

    noise_impl_t *impl = calloc(1, sizeof(*impl));
    if (!impl) return LP2P_ERR_NOMEM;

    memcpy(&impl->session, ns, sizeof(noise_session_t));
    impl->handshake_done = true;
    impl->hs = NULL;

    out->vtable = &noise_vtable;
    out->impl = impl;

    return LP2P_OK;
}
