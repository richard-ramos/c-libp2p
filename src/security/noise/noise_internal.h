/*
 * noise_internal.h — Internal types and constants for Noise XX handshake
 *
 * Cipher suite: Noise_XX_25519_ChaChaPoly_SHA256
 */
#ifndef NOISE_INTERNAL_H
#define NOISE_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include <sodium.h>

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "security/security.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Constants ─────────────────────────────────────────────────────────────── */

#define NOISE_DH_LEN        32   /* X25519 key size */
#define NOISE_HASH_LEN      32   /* SHA-256 digest */
#define NOISE_AEAD_KEY_LEN  32   /* ChaChaPoly key */
#define NOISE_AEAD_TAG_LEN  16   /* Poly1305 tag */
#define NOISE_AEAD_NONCE_LEN 12  /* ChaChaPoly nonce (96-bit) */
#define NOISE_MAX_MSG_LEN   65535
#define NOISE_FRAME_HDR_LEN 2    /* big-endian length prefix */

#define NOISE_ED25519_PK_LEN   32
#define NOISE_ED25519_SK_LEN   64
#define NOISE_ED25519_SIG_LEN  64

/* Protocol name for hashing */
#define NOISE_PROTOCOL_NAME  "Noise_XX_25519_ChaChaPoly_SHA256"

/* Prefix for identity signatures */
#define NOISE_SIG_PREFIX     "noise-libp2p-static-key:"
#define NOISE_SIG_PREFIX_LEN 24

/* ── CipherState ───────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t  k[NOISE_AEAD_KEY_LEN];
    uint64_t n;       /* nonce counter */
    bool     has_key;
} noise_cipher_state_t;

/* ── SymmetricState ────────────────────────────────────────────────────────── */

typedef struct {
    noise_cipher_state_t cs;
    uint8_t              ck[NOISE_HASH_LEN]; /* chaining key */
    uint8_t              h[NOISE_HASH_LEN];  /* handshake hash */
} noise_symmetric_state_t;

/* ── X25519 keypair ────────────────────────────────────────────────────────── */

typedef struct {
    uint8_t pk[NOISE_DH_LEN]; /* public */
    uint8_t sk[NOISE_DH_LEN]; /* private (X25519 scalar) */
} noise_x25519_kp_t;

/* ── Handshake state ───────────────────────────────────────────────────────── */

typedef struct {
    bool                   is_initiator;
    noise_symmetric_state_t symmetric;

    /* local static key (X25519 derived from Ed25519) */
    noise_x25519_kp_t     s;

    /* local ephemeral key (X25519) */
    noise_x25519_kp_t     e;

    /* remote static public key (X25519) */
    uint8_t               rs[NOISE_DH_LEN];
    bool                  has_rs;

    /* remote ephemeral public key */
    uint8_t               re[NOISE_DH_LEN];
    bool                  has_re;

    /* local Ed25519 identity (for signing/encoding) */
    uint8_t               local_ed25519_pk[NOISE_ED25519_PK_LEN];
    uint8_t               local_ed25519_sk[NOISE_ED25519_SK_LEN];

    /* remote peer identity (set after verifying handshake payload) */
    lp2p_peer_id_t        remote_peer_id;
    bool                  remote_verified;

    /* message counter */
    int                   msg_index;
} noise_handshake_state_t;

/* ── Post-handshake session ────────────────────────────────────────────────── */

typedef struct {
    noise_cipher_state_t  send_cipher;
    noise_cipher_state_t  recv_cipher;
    uint8_t               handshake_hash[NOISE_HASH_LEN];
    lp2p_peer_id_t        remote_peer_id;
} noise_session_t;

/* ── noise_keys.c API ──────────────────────────────────────────────────────── */

lp2p_err_t noise_generate_x25519_keypair(noise_x25519_kp_t *kp);

lp2p_err_t noise_ed25519_to_x25519(const uint8_t ed_pk[NOISE_ED25519_PK_LEN],
                                     const uint8_t ed_sk[NOISE_ED25519_SK_LEN],
                                     noise_x25519_kp_t *out);

/* Sign: "noise-libp2p-static-key:" + static_x25519_pk */
lp2p_err_t noise_sign_static_key(const uint8_t ed_sk[NOISE_ED25519_SK_LEN],
                                  const uint8_t static_pk[NOISE_DH_LEN],
                                  uint8_t sig[NOISE_ED25519_SIG_LEN]);

/* Build protobuf-encoded PublicKey message for local Ed25519 identity */
lp2p_err_t noise_build_identity_key(const uint8_t ed_pk[NOISE_ED25519_PK_LEN],
                                     uint8_t **out, size_t *out_len);

/* Verify a remote NoiseHandshakePayload against their static X25519 key.
 * Extracts the remote peer ID on success. */
lp2p_err_t noise_verify_payload(const uint8_t *payload_buf, size_t payload_len,
                                 const uint8_t remote_static_pk[NOISE_DH_LEN],
                                 lp2p_peer_id_t *remote_id_out);

/* Derive peer ID from a protobuf-encoded PublicKey */
lp2p_err_t noise_peer_id_from_pubkey_proto(const uint8_t *proto_buf, size_t proto_len,
                                            lp2p_peer_id_t *out);

/* ── noise_handshake.c API ─────────────────────────────────────────────────── */

lp2p_err_t noise_handshake_init(noise_handshake_state_t *hs,
                                 bool initiator,
                                 const uint8_t ed_pk[NOISE_ED25519_PK_LEN],
                                 const uint8_t ed_sk[NOISE_ED25519_SK_LEN]);

/* Write the next handshake message. Returns the bytes to send. */
lp2p_err_t noise_handshake_write_msg(noise_handshake_state_t *hs,
                                      uint8_t *out, size_t *out_len);

/* Read and process a received handshake message. */
lp2p_err_t noise_handshake_read_msg(noise_handshake_state_t *hs,
                                     const uint8_t *msg, size_t msg_len);

/* Split the symmetric state into send/recv cipher states.
 * Call after 3 messages have been exchanged. */
lp2p_err_t noise_handshake_split(noise_handshake_state_t *hs,
                                  noise_session_t *session);

/* ── noise_transport.c API ─────────────────────────────────────────────────── */

/* Create a security session that wraps a completed noise_session_t */
lp2p_err_t noise_session_create(noise_session_t *ns,
                                 lp2p_security_session_t *out);

/* Encrypt with framing: 2-byte big-endian length + ciphertext + tag */
lp2p_err_t noise_encrypt_frame(noise_cipher_state_t *cs,
                                const uint8_t *plain, size_t plain_len,
                                uint8_t *out, size_t *out_len);

/* Decrypt a framed message */
lp2p_err_t noise_decrypt_frame(noise_cipher_state_t *cs,
                                const uint8_t *frame, size_t frame_len,
                                uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* NOISE_INTERNAL_H */
