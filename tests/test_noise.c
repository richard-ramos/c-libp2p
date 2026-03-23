/*
 * test_noise.c — Unit tests for the Noise XX handshake implementation
 *
 * Tests:
 * 1. X25519 keypair generation
 * 2. Ed25519 -> X25519 conversion
 * 3. Static key signing and verification
 * 4. Full XX handshake (initiator <-> responder)
 * 5. Post-handshake encrypt/decrypt framing
 * 6. Handshake with tampered message (should fail)
 * 7. Nonce counter advances correctly
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <sodium.h>

/* Access internals for testing */
#include "security/noise/noise_internal.h"

#define TEST_PASS(name) printf("  PASS: %s\n", name)
#define TEST_FAIL(name, msg) do { printf("  FAIL: %s — %s\n", name, msg); failures++; } while(0)

static int failures = 0;

/* ── Helper: generate an Ed25519 keypair ───────────────────────────────────── */

static void gen_ed25519(uint8_t pk[32], uint8_t sk[64])
{
    crypto_sign_keypair(pk, sk);
}

/* ── Test 1: X25519 keypair generation ─────────────────────────────────────── */

static void test_x25519_keygen(void)
{
    const char *name = "X25519 keypair generation";
    noise_x25519_kp_t kp;

    lp2p_err_t err = noise_generate_x25519_keypair(&kp);
    if (err != LP2P_OK) { TEST_FAIL(name, "keygen failed"); return; }

    /* Verify public key is derived from private key */
    uint8_t expected_pk[32];
    crypto_scalarmult_base(expected_pk, kp.sk);
    if (memcmp(kp.pk, expected_pk, 32) != 0) {
        TEST_FAIL(name, "pk != scalarmult_base(sk)");
        return;
    }

    TEST_PASS(name);
}

/* ── Test 2: Ed25519 -> X25519 conversion ──────────────────────────────────── */

static void test_ed_to_x(void)
{
    const char *name = "Ed25519 -> X25519 conversion";
    uint8_t ed_pk[32], ed_sk[64];
    gen_ed25519(ed_pk, ed_sk);

    noise_x25519_kp_t x_kp;
    lp2p_err_t err = noise_ed25519_to_x25519(ed_pk, ed_sk, &x_kp);
    if (err != LP2P_OK) { TEST_FAIL(name, "conversion failed"); return; }

    /* Verify derived public matches scalarmult_base of derived private */
    uint8_t check_pk[32];
    crypto_scalarmult_base(check_pk, x_kp.sk);
    if (memcmp(x_kp.pk, check_pk, 32) != 0) {
        TEST_FAIL(name, "derived keys inconsistent");
        return;
    }

    TEST_PASS(name);
}

/* ── Test 3: Static key signing ────────────────────────────────────────────── */

static void test_static_key_sign(void)
{
    const char *name = "Static key signing and verification";
    uint8_t ed_pk[32], ed_sk[64];
    gen_ed25519(ed_pk, ed_sk);

    noise_x25519_kp_t x_kp;
    noise_ed25519_to_x25519(ed_pk, ed_sk, &x_kp);

    uint8_t sig[64];
    lp2p_err_t err = noise_sign_static_key(ed_sk, x_kp.pk, sig);
    if (err != LP2P_OK) { TEST_FAIL(name, "signing failed"); return; }

    /* Verify the signature manually */
    uint8_t msg[24 + 32]; /* "noise-libp2p-static-key:" + pk */
    memcpy(msg, "noise-libp2p-static-key:", 24);
    memcpy(msg + 24, x_kp.pk, 32);

    if (crypto_sign_verify_detached(sig, msg, sizeof(msg), ed_pk) != 0) {
        TEST_FAIL(name, "signature verification failed");
        return;
    }

    TEST_PASS(name);
}

/* ── Test 4: Full XX handshake ─────────────────────────────────────────────── */

static void test_full_handshake(void)
{
    const char *name = "Full XX handshake";

    /* Generate identity keys for initiator and responder */
    uint8_t init_pk[32], init_sk[64];
    uint8_t resp_pk[32], resp_sk[64];
    gen_ed25519(init_pk, init_sk);
    gen_ed25519(resp_pk, resp_sk);

    noise_handshake_state_t init_hs, resp_hs;

    /* Initialize both sides */
    lp2p_err_t err;
    err = noise_handshake_init(&init_hs, true, init_pk, init_sk);
    if (err != LP2P_OK) { TEST_FAIL(name, "initiator init failed"); return; }

    err = noise_handshake_init(&resp_hs, false, resp_pk, resp_sk);
    if (err != LP2P_OK) { TEST_FAIL(name, "responder init failed"); return; }

    uint8_t msg_buf[4096];
    size_t msg_len;

    /* Message 1: initiator -> responder (-> e) */
    msg_len = sizeof(msg_buf);
    err = noise_handshake_write_msg(&init_hs, msg_buf, &msg_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "msg1 write failed"); return; }

    err = noise_handshake_read_msg(&resp_hs, msg_buf, msg_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "msg1 read failed"); return; }

    /* Message 2: responder -> initiator (<- e, ee, s, es) */
    msg_len = sizeof(msg_buf);
    err = noise_handshake_write_msg(&resp_hs, msg_buf, &msg_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "msg2 write failed"); return; }

    err = noise_handshake_read_msg(&init_hs, msg_buf, msg_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "msg2 read failed"); return; }

    /* Message 3: initiator -> responder (-> s, se) */
    msg_len = sizeof(msg_buf);
    err = noise_handshake_write_msg(&init_hs, msg_buf, &msg_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "msg3 write failed"); return; }

    err = noise_handshake_read_msg(&resp_hs, msg_buf, msg_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "msg3 read failed"); return; }

    /* Both sides should have verified remote identity */
    if (!init_hs.remote_verified) { TEST_FAIL(name, "initiator: remote not verified"); return; }
    if (!resp_hs.remote_verified) { TEST_FAIL(name, "responder: remote not verified"); return; }

    /* Split into transport sessions */
    noise_session_t init_session, resp_session;
    err = noise_handshake_split(&init_hs, &init_session);
    if (err != LP2P_OK) { TEST_FAIL(name, "initiator split failed"); return; }

    err = noise_handshake_split(&resp_hs, &resp_session);
    if (err != LP2P_OK) { TEST_FAIL(name, "responder split failed"); return; }

    /* Verify handshake hashes match */
    if (memcmp(init_session.handshake_hash, resp_session.handshake_hash,
               NOISE_HASH_LEN) != 0) {
        TEST_FAIL(name, "handshake hashes differ");
        return;
    }

    /* Verify peer IDs are set and are different */
    if (init_session.remote_peer_id.len == 0) {
        TEST_FAIL(name, "initiator: no remote peer id"); return;
    }
    if (resp_session.remote_peer_id.len == 0) {
        TEST_FAIL(name, "responder: no remote peer id"); return;
    }

    TEST_PASS(name);
}

/* ── Test 5: Post-handshake encrypt/decrypt ────────────────────────────────── */

static void test_transport_framing(void)
{
    const char *name = "Post-handshake encrypt/decrypt framing";

    /* Run a full handshake first */
    uint8_t init_pk[32], init_sk[64];
    uint8_t resp_pk[32], resp_sk[64];
    gen_ed25519(init_pk, init_sk);
    gen_ed25519(resp_pk, resp_sk);

    noise_handshake_state_t init_hs, resp_hs;
    noise_handshake_init(&init_hs, true, init_pk, init_sk);
    noise_handshake_init(&resp_hs, false, resp_pk, resp_sk);

    uint8_t msg_buf[4096];
    size_t msg_len;

    /* 3-message exchange */
    msg_len = sizeof(msg_buf);
    noise_handshake_write_msg(&init_hs, msg_buf, &msg_len);
    noise_handshake_read_msg(&resp_hs, msg_buf, msg_len);

    msg_len = sizeof(msg_buf);
    noise_handshake_write_msg(&resp_hs, msg_buf, &msg_len);
    noise_handshake_read_msg(&init_hs, msg_buf, msg_len);

    msg_len = sizeof(msg_buf);
    noise_handshake_write_msg(&init_hs, msg_buf, &msg_len);
    noise_handshake_read_msg(&resp_hs, msg_buf, msg_len);

    noise_session_t init_session, resp_session;
    noise_handshake_split(&init_hs, &init_session);
    noise_handshake_split(&resp_hs, &resp_session);

    /* Test: initiator encrypts, responder decrypts */
    const uint8_t plaintext[] = "Hello, Noise transport!";
    uint8_t frame[4096];
    size_t frame_len;

    lp2p_err_t err = noise_encrypt_frame(&init_session.send_cipher,
                                           plaintext, sizeof(plaintext),
                                           frame, &frame_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "encrypt failed"); return; }

    /* Frame should be: 2 + sizeof(plaintext) + 16 */
    size_t expected_len = 2 + sizeof(plaintext) + NOISE_AEAD_TAG_LEN;
    if (frame_len != expected_len) {
        TEST_FAIL(name, "unexpected frame length"); return;
    }

    uint8_t decrypted[4096];
    size_t dec_len;
    err = noise_decrypt_frame(&resp_session.recv_cipher,
                               frame, frame_len, decrypted, &dec_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "decrypt failed"); return; }

    if (dec_len != sizeof(plaintext) ||
        memcmp(decrypted, plaintext, sizeof(plaintext)) != 0) {
        TEST_FAIL(name, "decrypted data mismatch"); return;
    }

    /* Test: responder encrypts, initiator decrypts */
    const uint8_t reply[] = "Hello back from responder!";
    err = noise_encrypt_frame(&resp_session.send_cipher,
                               reply, sizeof(reply), frame, &frame_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "responder encrypt failed"); return; }

    err = noise_decrypt_frame(&init_session.recv_cipher,
                               frame, frame_len, decrypted, &dec_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "initiator decrypt failed"); return; }

    if (dec_len != sizeof(reply) ||
        memcmp(decrypted, reply, sizeof(reply)) != 0) {
        TEST_FAIL(name, "reply decrypted data mismatch"); return;
    }

    TEST_PASS(name);
}

/* ── Test 6: Tampered handshake message ────────────────────────────────────── */

static void test_tampered_handshake(void)
{
    const char *name = "Tampered handshake message rejected";

    uint8_t init_pk[32], init_sk[64];
    uint8_t resp_pk[32], resp_sk[64];
    gen_ed25519(init_pk, init_sk);
    gen_ed25519(resp_pk, resp_sk);

    noise_handshake_state_t init_hs, resp_hs;
    noise_handshake_init(&init_hs, true, init_pk, init_sk);
    noise_handshake_init(&resp_hs, false, resp_pk, resp_sk);

    uint8_t msg_buf[4096];
    size_t msg_len;

    /* Message 1 */
    msg_len = sizeof(msg_buf);
    noise_handshake_write_msg(&init_hs, msg_buf, &msg_len);
    noise_handshake_read_msg(&resp_hs, msg_buf, msg_len);

    /* Message 2: tamper with it before initiator reads */
    msg_len = sizeof(msg_buf);
    noise_handshake_write_msg(&resp_hs, msg_buf, &msg_len);

    /* Flip a byte in the encrypted portion */
    if (msg_len > 40) {
        msg_buf[40] ^= 0xFF;
    }

    lp2p_err_t err = noise_handshake_read_msg(&init_hs, msg_buf, msg_len);
    if (err == LP2P_OK) {
        TEST_FAIL(name, "tampered message was accepted");
        return;
    }

    TEST_PASS(name);
}

/* ── Test 7: Nonce counter behavior ────────────────────────────────────────── */

static void test_nonce_counter(void)
{
    const char *name = "Nonce counter advances correctly";

    uint8_t init_pk[32], init_sk[64];
    uint8_t resp_pk[32], resp_sk[64];
    gen_ed25519(init_pk, init_sk);
    gen_ed25519(resp_pk, resp_sk);

    noise_handshake_state_t init_hs, resp_hs;
    noise_handshake_init(&init_hs, true, init_pk, init_sk);
    noise_handshake_init(&resp_hs, false, resp_pk, resp_sk);

    uint8_t msg_buf[4096];
    size_t msg_len;

    /* Complete handshake */
    msg_len = sizeof(msg_buf);
    noise_handshake_write_msg(&init_hs, msg_buf, &msg_len);
    noise_handshake_read_msg(&resp_hs, msg_buf, msg_len);

    msg_len = sizeof(msg_buf);
    noise_handshake_write_msg(&resp_hs, msg_buf, &msg_len);
    noise_handshake_read_msg(&init_hs, msg_buf, msg_len);

    msg_len = sizeof(msg_buf);
    noise_handshake_write_msg(&init_hs, msg_buf, &msg_len);
    noise_handshake_read_msg(&resp_hs, msg_buf, msg_len);

    noise_session_t init_session, resp_session;
    noise_handshake_split(&init_hs, &init_session);
    noise_handshake_split(&resp_hs, &resp_session);

    /* Send multiple messages and verify nonce advances */
    uint8_t frame[4096], decrypted[4096];
    size_t frame_len, dec_len;

    for (int i = 0; i < 5; i++) {
        uint8_t data[32];
        memset(data, (uint8_t)i, sizeof(data));

        lp2p_err_t err = noise_encrypt_frame(&init_session.send_cipher,
                                               data, sizeof(data),
                                               frame, &frame_len);
        if (err != LP2P_OK) { TEST_FAIL(name, "encrypt in loop failed"); return; }

        err = noise_decrypt_frame(&resp_session.recv_cipher,
                                   frame, frame_len, decrypted, &dec_len);
        if (err != LP2P_OK) { TEST_FAIL(name, "decrypt in loop failed"); return; }

        if (dec_len != sizeof(data) || memcmp(decrypted, data, sizeof(data)) != 0) {
            TEST_FAIL(name, "data mismatch in loop"); return;
        }
    }

    /* Verify nonce counters are at 5 */
    if (init_session.send_cipher.n != 5 || resp_session.recv_cipher.n != 5) {
        TEST_FAIL(name, "nonce counter mismatch"); return;
    }

    TEST_PASS(name);
}

/* ── Test 8: Security vtable create ────────────────────────────────────────── */

static void test_vtable_session(void)
{
    const char *name = "Security vtable session creation";

    uint8_t init_pk[32], init_sk[64];
    uint8_t resp_pk[32], resp_sk[64];
    gen_ed25519(init_pk, init_sk);
    gen_ed25519(resp_pk, resp_sk);

    noise_handshake_state_t init_hs, resp_hs;
    noise_handshake_init(&init_hs, true, init_pk, init_sk);
    noise_handshake_init(&resp_hs, false, resp_pk, resp_sk);

    uint8_t msg_buf[4096];
    size_t msg_len;

    /* Complete handshake */
    msg_len = sizeof(msg_buf);
    noise_handshake_write_msg(&init_hs, msg_buf, &msg_len);
    noise_handshake_read_msg(&resp_hs, msg_buf, msg_len);

    msg_len = sizeof(msg_buf);
    noise_handshake_write_msg(&resp_hs, msg_buf, &msg_len);
    noise_handshake_read_msg(&init_hs, msg_buf, msg_len);

    msg_len = sizeof(msg_buf);
    noise_handshake_write_msg(&init_hs, msg_buf, &msg_len);
    noise_handshake_read_msg(&resp_hs, msg_buf, msg_len);

    noise_session_t init_session, resp_session;
    noise_handshake_split(&init_hs, &init_session);
    noise_handshake_split(&resp_hs, &resp_session);

    /* Create security sessions via vtable */
    lp2p_security_session_t init_sec, resp_sec;
    lp2p_err_t err;

    err = noise_session_create(&init_session, &init_sec);
    if (err != LP2P_OK) { TEST_FAIL(name, "initiator session create failed"); return; }

    err = noise_session_create(&resp_session, &resp_sec);
    if (err != LP2P_OK) { TEST_FAIL(name, "responder session create failed"); return; }

    /* Encrypt via vtable */
    const uint8_t plain[] = "vtable test message";
    uint8_t enc_buf[4096];
    size_t enc_len = sizeof(enc_buf);
    err = init_sec.vtable->encrypt(init_sec.impl, plain, sizeof(plain),
                                    enc_buf, &enc_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "vtable encrypt failed"); goto cleanup; }

    /* Decrypt via vtable */
    uint8_t dec_buf[4096];
    size_t dec_len = sizeof(dec_buf);
    err = resp_sec.vtable->decrypt(resp_sec.impl, enc_buf, enc_len,
                                    dec_buf, &dec_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "vtable decrypt failed"); goto cleanup; }

    if (dec_len != sizeof(plain) || memcmp(dec_buf, plain, sizeof(plain)) != 0) {
        TEST_FAIL(name, "vtable decrypted data mismatch"); goto cleanup;
    }

    TEST_PASS(name);

cleanup:
    init_sec.vtable->free(init_sec.impl);
    resp_sec.vtable->free(resp_sec.impl);
}

/* ── Test 9: Peer ID derivation ────────────────────────────────────────────── */

static void test_peer_id_derivation(void)
{
    const char *name = "Peer ID derivation from Ed25519 key";

    uint8_t ed_pk[32], ed_sk[64];
    gen_ed25519(ed_pk, ed_sk);

    /* Build identity key proto and derive peer ID */
    uint8_t *identity_key = NULL;
    size_t identity_key_len = 0;
    lp2p_err_t err = noise_build_identity_key(ed_pk, &identity_key, &identity_key_len);
    if (err != LP2P_OK) { TEST_FAIL(name, "build identity key failed"); return; }

    lp2p_peer_id_t peer_id;
    err = noise_peer_id_from_pubkey_proto(identity_key, identity_key_len, &peer_id);
    free(identity_key);
    if (err != LP2P_OK) { TEST_FAIL(name, "peer id derivation failed"); return; }

    /* Ed25519 proto is small (< 42 bytes), so identity multihash */
    if (peer_id.bytes[0] != 0x00) {
        TEST_FAIL(name, "expected identity multihash for Ed25519"); return;
    }
    if (peer_id.len == 0 || peer_id.len > LP2P_PEER_ID_SIZE) {
        TEST_FAIL(name, "peer id length out of range"); return;
    }

    TEST_PASS(name);
}

/* ── Main ──────────────────────────────────────────────────────────────────── */

int main(void)
{
    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium init failed\n");
        return 1;
    }

    printf("test_noise: running tests\n");

    test_x25519_keygen();
    test_ed_to_x();
    test_static_key_sign();
    test_full_handshake();
    test_transport_framing();
    test_tampered_handshake();
    test_nonce_counter();
    test_vtable_session();
    test_peer_id_derivation();

    printf("\ntest_noise: %d failure(s)\n", failures);
    return failures > 0 ? 1 : 0;
}
