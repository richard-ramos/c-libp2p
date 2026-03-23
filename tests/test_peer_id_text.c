/* test_peer_id_text.c — unit tests for peer ID string encoding/decoding */
#include <stdio.h>
#include <string.h>
#include <libp2p/crypto.h>
#include <libp2p/errors.h>
#include <libp2p/types.h>
#include "encoding/multibase.h"
#include "encoding/multicodec.h"
#include "encoding/cid.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  %s ... ", #name);
#define PASS() printf("ok\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void test_to_string_roundtrip(void) {
    TEST(to_string_roundtrip);
    lp2p_keypair_t *kp = NULL;
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);

    lp2p_peer_id_t pid1;
    lp2p_peer_id_from_keypair(kp, &pid1);

    char str[128];
    size_t str_len = sizeof(str);
    lp2p_err_t err = lp2p_peer_id_to_string(&pid1, str, &str_len);
    if (err != LP2P_OK) { FAIL("to_string"); lp2p_keypair_free(kp); return; }

    lp2p_peer_id_t pid2;
    err = lp2p_peer_id_from_string(str, &pid2);
    if (err != LP2P_OK) { FAIL("from_string"); lp2p_keypair_free(kp); return; }

    if (!lp2p_peer_id_equal(&pid1, &pid2)) {
        FAIL("roundtrip mismatch");
        lp2p_keypair_free(kp);
        return;
    }

    lp2p_keypair_free(kp);
    PASS();
}

static void test_base58_starts_with_digit_or_letter(void) {
    TEST(base58_format);
    lp2p_keypair_t *kp = NULL;
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);

    lp2p_peer_id_t pid;
    lp2p_peer_id_from_keypair(kp, &pid);

    char str[128];
    size_t str_len = sizeof(str);
    lp2p_peer_id_to_string(&pid, str, &str_len);

    /* Base58btc string should only contain base58 chars */
    const char *valid = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    for (size_t i = 0; i < str_len; i++) {
        if (!strchr(valid, str[i])) {
            FAIL("invalid base58 char");
            lp2p_keypair_free(kp);
            return;
        }
    }

    lp2p_keypair_free(kp);
    PASS();
}

static void test_cidv1_base32_roundtrip(void) {
    TEST(cidv1_base32_roundtrip);
    lp2p_keypair_t *kp = NULL;
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);

    lp2p_peer_id_t pid1;
    lp2p_peer_id_from_keypair(kp, &pid1);

    /* Manually construct CIDv1/base32 form: b + base32(CIDv1(libp2p-key, multihash)) */
    uint8_t cid_bytes[256];
    size_t cid_len = lp2p_cid_encode(LP2P_CODEC_LIBP2P_KEY,
                                      pid1.bytes, pid1.len,
                                      cid_bytes, sizeof(cid_bytes));
    if (cid_len == 0) { FAIL("cid_encode"); lp2p_keypair_free(kp); return; }

    char b32_str[256];
    b32_str[0] = 'b'; /* multibase prefix for base32lower */
    size_t b32_len = lp2p_base32_encode(cid_bytes, cid_len,
                                         b32_str + 1, sizeof(b32_str) - 1);
    if (b32_len == 0) { FAIL("base32_encode"); lp2p_keypair_free(kp); return; }

    /* Now parse it back */
    lp2p_peer_id_t pid2;
    lp2p_err_t err = lp2p_peer_id_from_string(b32_str, &pid2);
    if (err != LP2P_OK) {
        printf("FAIL: from_string with CIDv1 (err=%d, str=%s)\n", err, b32_str);
        tests_failed++;
        lp2p_keypair_free(kp);
        return;
    }

    if (!lp2p_peer_id_equal(&pid1, &pid2)) {
        FAIL("CIDv1 roundtrip mismatch");
        lp2p_keypair_free(kp);
        return;
    }

    lp2p_keypair_free(kp);
    PASS();
}

static void test_from_string_invalid(void) {
    TEST(from_string_invalid);
    lp2p_peer_id_t pid;

    /* Empty string */
    if (lp2p_peer_id_from_string("", &pid) == LP2P_OK) {
        FAIL("should reject empty string"); return;
    }

    /* Invalid base58 */
    if (lp2p_peer_id_from_string("0OIl", &pid) == LP2P_OK) {
        FAIL("should reject invalid base58 chars"); return;
    }

    PASS();
}

int main(void) {
    printf("test_peer_id_text:\n");
    test_to_string_roundtrip();
    test_base58_starts_with_digit_or_letter();
    test_cidv1_base32_roundtrip();
    test_from_string_invalid();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
