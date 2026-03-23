/* test_peer_id.c — unit tests for peer ID generation from keypairs */
#include <stdio.h>
#include <string.h>
#include <libp2p/crypto.h>
#include <libp2p/errors.h>
#include <libp2p/types.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  %s ... ", #name);
#define PASS() printf("ok\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void test_generate_and_derive_peer_id(void) {
    TEST(generate_and_derive_peer_id);
    lp2p_keypair_t *kp = NULL;
    lp2p_err_t err = lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);
    if (err != LP2P_OK) { FAIL("keypair_generate"); return; }

    lp2p_peer_id_t pid;
    err = lp2p_peer_id_from_keypair(kp, &pid);
    if (err != LP2P_OK) { FAIL("peer_id_from_keypair"); lp2p_keypair_free(kp); return; }

    /* Ed25519 inline: identity multihash of 36-byte protobuf = 38 bytes */
    if (pid.len != 38) {
        printf("FAIL: expected len=38, got %zu\n", pid.len);
        tests_failed++;
        lp2p_keypair_free(kp);
        return;
    }

    /* First byte should be 0x00 (identity multihash code) */
    if (pid.bytes[0] != 0x00) {
        FAIL("expected identity multihash (0x00)");
        lp2p_keypair_free(kp);
        return;
    }

    lp2p_keypair_free(kp);
    PASS();
}

static void test_peer_id_deterministic(void) {
    TEST(peer_id_deterministic);
    lp2p_keypair_t *kp = NULL;
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);

    lp2p_peer_id_t pid1, pid2;
    lp2p_peer_id_from_keypair(kp, &pid1);
    lp2p_peer_id_from_keypair(kp, &pid2);

    if (!lp2p_peer_id_equal(&pid1, &pid2)) {
        FAIL("same keypair should produce same peer ID");
        lp2p_keypair_free(kp);
        return;
    }

    lp2p_keypair_free(kp);
    PASS();
}

static void test_peer_id_different_keys(void) {
    TEST(peer_id_different_keys);
    lp2p_keypair_t *kp1 = NULL, *kp2 = NULL;
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp1);
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp2);

    lp2p_peer_id_t pid1, pid2;
    lp2p_peer_id_from_keypair(kp1, &pid1);
    lp2p_peer_id_from_keypair(kp2, &pid2);

    if (lp2p_peer_id_equal(&pid1, &pid2)) {
        FAIL("different keypairs should produce different peer IDs");
        lp2p_keypair_free(kp1);
        lp2p_keypair_free(kp2);
        return;
    }

    lp2p_keypair_free(kp1);
    lp2p_keypair_free(kp2);
    PASS();
}

static void test_keypair_public_bytes(void) {
    TEST(keypair_public_bytes);
    lp2p_keypair_t *kp = NULL;
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);

    uint8_t pub[32];
    size_t pub_len = sizeof(pub);
    lp2p_err_t err = lp2p_keypair_public_bytes(kp, pub, &pub_len);
    if (err != LP2P_OK || pub_len != 32) {
        FAIL("public_bytes");
        lp2p_keypair_free(kp);
        return;
    }

    lp2p_keypair_free(kp);
    PASS();
}

static void test_keypair_from_bytes(void) {
    TEST(keypair_from_bytes);
    lp2p_keypair_t *kp1 = NULL;
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp1);

    /* Get the public key bytes */
    uint8_t pub1[32];
    size_t pub1_len = sizeof(pub1);
    lp2p_keypair_public_bytes(kp1, pub1, &pub1_len);

    /* We can't easily extract the secret key via public API for this test,
       but we can verify that invalid key type fails */
    lp2p_keypair_t *kp2 = NULL;
    lp2p_err_t err = lp2p_keypair_from_bytes(LP2P_KEY_RSA, pub1, 32, &kp2);
    if (err == LP2P_OK) {
        FAIL("should reject RSA key type");
        lp2p_keypair_free(kp1);
        lp2p_keypair_free(kp2);
        return;
    }

    lp2p_keypair_free(kp1);
    PASS();
}

int main(void) {
    printf("test_peer_id:\n");
    test_generate_and_derive_peer_id();
    test_peer_id_deterministic();
    test_peer_id_different_keys();
    test_keypair_public_bytes();
    test_keypair_from_bytes();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
