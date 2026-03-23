/* test_remote_keys.c — unit tests for remote key verification and peer ID
   derivation from protobuf-encoded PublicKey */
#include <stdio.h>
#include <string.h>
#include <libp2p/crypto.h>
#include <libp2p/errors.h>
#include <libp2p/types.h>
#include <sodium.h>
#include "encoding/varint.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  %s ... ", #name);
#define PASS() printf("ok\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

/* Manually encode a protobuf PublicKey for Ed25519 */
static size_t make_ed25519_pubkey_proto(const uint8_t *pubkey, size_t pubkey_len,
                                         uint8_t *out, size_t out_cap) {
    size_t pos = 0;
    /* field 1: tag 0x08, value 1 (Ed25519) */
    if (pos >= out_cap) return 0;
    out[pos++] = 0x08;
    if (pos >= out_cap) return 0;
    out[pos++] = 0x01;
    /* field 2: tag 0x12, length-prefixed key data */
    if (pos >= out_cap) return 0;
    out[pos++] = 0x12;
    uint8_t vbuf[10];
    size_t vn = lp2p_varint_encode(pubkey_len, vbuf);
    if (pos + vn + pubkey_len > out_cap) return 0;
    memcpy(out + pos, vbuf, vn);
    pos += vn;
    memcpy(out + pos, pubkey, pubkey_len);
    pos += pubkey_len;
    return pos;
}

static void test_ed25519_peer_id_from_public_key(void) {
    TEST(ed25519_peer_id_from_public_key);

    /* Generate a keypair */
    if (sodium_init() < 0 && sodium_init() < 0) {
        FAIL("sodium_init"); return;
    }

    uint8_t pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_keypair(pk, sk);

    /* Create protobuf encoding */
    uint8_t proto_buf[256];
    size_t proto_len = make_ed25519_pubkey_proto(pk, sizeof(pk),
                                                  proto_buf, sizeof(proto_buf));
    if (proto_len == 0) { FAIL("proto encode"); return; }

    /* Derive peer ID */
    lp2p_peer_id_t pid;
    lp2p_err_t err = lp2p_peer_id_from_public_key(proto_buf, proto_len, &pid);
    if (err != LP2P_OK) { FAIL("peer_id_from_public_key"); return; }

    /* Ed25519: 36-byte protobuf < 42, so identity multihash → 38 bytes */
    if (pid.len != 38) {
        printf("FAIL: expected len=38, got %zu\n", pid.len);
        tests_failed++;
        return;
    }
    if (pid.bytes[0] != 0x00) {
        FAIL("expected identity multihash"); return;
    }

    PASS();
}

static void test_ed25519_peer_id_matches_keypair(void) {
    TEST(ed25519_peer_id_matches_keypair);

    lp2p_keypair_t *kp = NULL;
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);

    /* Get peer ID from keypair */
    lp2p_peer_id_t pid1;
    lp2p_peer_id_from_keypair(kp, &pid1);

    /* Get public key bytes and manually create protobuf */
    uint8_t pub[32];
    size_t pub_len = sizeof(pub);
    lp2p_keypair_public_bytes(kp, pub, &pub_len);

    uint8_t proto_buf[256];
    size_t proto_len = make_ed25519_pubkey_proto(pub, pub_len,
                                                  proto_buf, sizeof(proto_buf));

    /* Get peer ID from protobuf */
    lp2p_peer_id_t pid2;
    lp2p_peer_id_from_public_key(proto_buf, proto_len, &pid2);

    /* Should match */
    if (!lp2p_peer_id_equal(&pid1, &pid2)) {
        FAIL("peer IDs should match");
        lp2p_keypair_free(kp);
        return;
    }

    lp2p_keypair_free(kp);
    PASS();
}

static void test_large_key_uses_sha256(void) {
    TEST(large_key_uses_sha256);

    /* Create a fake protobuf PublicKey that's >= 42 bytes */
    uint8_t fake_key[64];
    memset(fake_key, 0xAB, sizeof(fake_key));

    /* type=RSA(0), data=64 bytes of 0xAB */
    uint8_t proto_buf[256];
    size_t pos = 0;
    proto_buf[pos++] = 0x08; /* field 1 tag */
    proto_buf[pos++] = 0x00; /* RSA = 0 */
    proto_buf[pos++] = 0x12; /* field 2 tag */
    proto_buf[pos++] = 0x40; /* 64 bytes */
    memcpy(proto_buf + pos, fake_key, 64);
    pos += 64;
    /* Total protobuf: 68 bytes >= 42 → sha2-256 multihash */

    lp2p_peer_id_t pid;
    lp2p_err_t err = lp2p_peer_id_from_public_key(proto_buf, pos, &pid);
    if (err != LP2P_OK) { FAIL("peer_id_from_public_key"); return; }

    /* Should be sha2-256 multihash: 0x12 0x20 + 32 bytes = 34 */
    if (pid.len != 34) {
        printf("FAIL: expected len=34, got %zu\n", pid.len);
        tests_failed++;
        return;
    }
    if (pid.bytes[0] != 0x12 || pid.bytes[1] != 0x20) {
        FAIL("expected sha2-256 multihash prefix 0x12 0x20");
        return;
    }

    PASS();
}

int main(void) {
    printf("test_remote_keys:\n");
    test_ed25519_peer_id_from_public_key();
    test_ed25519_peer_id_matches_keypair();
    test_large_key_uses_sha256();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
