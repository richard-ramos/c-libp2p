/* test_multiaddr.c — unit tests for multiaddr parsing and encoding */
#include <stdio.h>
#include <string.h>
#include <libp2p/multiaddr.h>
#include <libp2p/crypto.h>
#include <libp2p/errors.h>
#include <libp2p/types.h>

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  %s ... ", #name);
#define PASS() printf("ok\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void test_parse_ip4_tcp(void) {
    TEST(parse_ip4_tcp);
    lp2p_multiaddr_t *ma = NULL;
    lp2p_err_t err = lp2p_multiaddr_parse("/ip4/127.0.0.1/tcp/4001", &ma);
    if (err != LP2P_OK) { FAIL("parse"); return; }
    const char *s = lp2p_multiaddr_string(ma);
    if (strcmp(s, "/ip4/127.0.0.1/tcp/4001") != 0) {
        printf("FAIL: got '%s'\n", s);
        tests_failed++;
        lp2p_multiaddr_free(ma);
        return;
    }
    lp2p_multiaddr_free(ma);
    PASS();
}

static void test_parse_ip6_tcp(void) {
    TEST(parse_ip6_tcp);
    lp2p_multiaddr_t *ma = NULL;
    lp2p_err_t err = lp2p_multiaddr_parse("/ip6/::1/tcp/8080", &ma);
    if (err != LP2P_OK) { FAIL("parse"); return; }
    lp2p_multiaddr_free(ma);
    PASS();
}

static void test_parse_dns4_tcp(void) {
    TEST(parse_dns4_tcp);
    lp2p_multiaddr_t *ma = NULL;
    lp2p_err_t err = lp2p_multiaddr_parse("/dns4/example.com/tcp/443", &ma);
    if (err != LP2P_OK) { FAIL("parse"); return; }
    const char *s = lp2p_multiaddr_string(ma);
    if (strcmp(s, "/dns4/example.com/tcp/443") != 0) {
        printf("FAIL: got '%s'\n", s);
        tests_failed++;
        lp2p_multiaddr_free(ma);
        return;
    }
    lp2p_multiaddr_free(ma);
    PASS();
}

static void test_parse_quic_v1(void) {
    TEST(parse_quic_v1);
    lp2p_multiaddr_t *ma = NULL;
    lp2p_err_t err = lp2p_multiaddr_parse("/ip4/1.2.3.4/udp/9090/quic-v1", &ma);
    if (err != LP2P_OK) { FAIL("parse"); return; }
    const char *s = lp2p_multiaddr_string(ma);
    if (strcmp(s, "/ip4/1.2.3.4/udp/9090/quic-v1") != 0) {
        printf("FAIL: got '%s'\n", s);
        tests_failed++;
        lp2p_multiaddr_free(ma);
        return;
    }
    lp2p_multiaddr_free(ma);
    PASS();
}

static void test_parse_with_p2p(void) {
    TEST(parse_with_p2p);
    /* Generate a peer ID to use in the multiaddr */
    lp2p_keypair_t *kp = NULL;
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);
    lp2p_peer_id_t pid;
    lp2p_peer_id_from_keypair(kp, &pid);

    char pid_str[128];
    size_t pid_str_len = sizeof(pid_str);
    lp2p_peer_id_to_string(&pid, pid_str, &pid_str_len);

    char ma_str[256];
    snprintf(ma_str, sizeof(ma_str), "/ip4/127.0.0.1/tcp/4001/p2p/%s", pid_str);

    lp2p_multiaddr_t *ma = NULL;
    lp2p_err_t err = lp2p_multiaddr_parse(ma_str, &ma);
    if (err != LP2P_OK) {
        printf("FAIL: parse (err=%d, str=%s)\n", err, ma_str);
        tests_failed++;
        lp2p_keypair_free(kp);
        return;
    }

    /* Extract peer ID */
    lp2p_peer_id_t extracted;
    err = lp2p_multiaddr_get_peer_id(ma, &extracted);
    if (err != LP2P_OK) { FAIL("get_peer_id"); lp2p_multiaddr_free(ma); lp2p_keypair_free(kp); return; }
    if (!lp2p_peer_id_equal(&pid, &extracted)) { FAIL("peer_id mismatch"); lp2p_multiaddr_free(ma); lp2p_keypair_free(kp); return; }

    lp2p_multiaddr_free(ma);
    lp2p_keypair_free(kp);
    PASS();
}

static void test_equal(void) {
    TEST(equal);
    lp2p_multiaddr_t *a = NULL, *b = NULL;
    lp2p_multiaddr_parse("/ip4/10.0.0.1/tcp/80", &a);
    lp2p_multiaddr_parse("/ip4/10.0.0.1/tcp/80", &b);
    if (!lp2p_multiaddr_equal(a, b)) { FAIL("should be equal"); lp2p_multiaddr_free(a); lp2p_multiaddr_free(b); return; }
    lp2p_multiaddr_free(a);
    lp2p_multiaddr_free(b);
    PASS();
}

static void test_not_equal(void) {
    TEST(not_equal);
    lp2p_multiaddr_t *a = NULL, *b = NULL;
    lp2p_multiaddr_parse("/ip4/10.0.0.1/tcp/80", &a);
    lp2p_multiaddr_parse("/ip4/10.0.0.1/tcp/81", &b);
    if (lp2p_multiaddr_equal(a, b)) { FAIL("should not be equal"); lp2p_multiaddr_free(a); lp2p_multiaddr_free(b); return; }
    lp2p_multiaddr_free(a);
    lp2p_multiaddr_free(b);
    PASS();
}

static void test_with_peer_id(void) {
    TEST(with_peer_id);
    lp2p_multiaddr_t *base = NULL;
    lp2p_multiaddr_parse("/ip4/192.168.1.1/tcp/4001", &base);

    lp2p_keypair_t *kp = NULL;
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);
    lp2p_peer_id_t pid;
    lp2p_peer_id_from_keypair(kp, &pid);

    lp2p_multiaddr_t *full = NULL;
    lp2p_err_t err = lp2p_multiaddr_with_peer_id(base, &pid, &full);
    if (err != LP2P_OK) { FAIL("with_peer_id"); lp2p_multiaddr_free(base); lp2p_keypair_free(kp); return; }

    lp2p_peer_id_t extracted;
    err = lp2p_multiaddr_get_peer_id(full, &extracted);
    if (err != LP2P_OK) {
        FAIL("get_peer_id");
        lp2p_multiaddr_free(full); lp2p_multiaddr_free(base); lp2p_keypair_free(kp);
        return;
    }
    if (!lp2p_peer_id_equal(&pid, &extracted)) {
        FAIL("mismatch");
        lp2p_multiaddr_free(full); lp2p_multiaddr_free(base); lp2p_keypair_free(kp);
        return;
    }

    lp2p_multiaddr_free(full);
    lp2p_multiaddr_free(base);
    lp2p_keypair_free(kp);
    PASS();
}

static void test_invalid_protocol(void) {
    TEST(invalid_protocol);
    lp2p_multiaddr_t *ma = NULL;
    lp2p_err_t err = lp2p_multiaddr_parse("/foobar/test", &ma);
    if (err != LP2P_ERR_INVALID_MULTIADDR) { FAIL("should fail"); lp2p_multiaddr_free(ma); return; }
    PASS();
}

static void test_no_peer_id(void) {
    TEST(no_peer_id);
    lp2p_multiaddr_t *ma = NULL;
    lp2p_multiaddr_parse("/ip4/1.2.3.4/tcp/80", &ma);
    lp2p_peer_id_t pid;
    lp2p_err_t err = lp2p_multiaddr_get_peer_id(ma, &pid);
    if (err != LP2P_ERR_NOT_FOUND) { FAIL("should return NOT_FOUND"); lp2p_multiaddr_free(ma); return; }
    lp2p_multiaddr_free(ma);
    PASS();
}

static void test_bytes_roundtrip(void) {
    TEST(bytes_roundtrip);
    lp2p_multiaddr_t *ma = NULL;
    lp2p_multiaddr_parse("/ip4/10.20.30.40/tcp/5555", &ma);
    size_t len;
    const uint8_t *bytes = lp2p_multiaddr_bytes(ma, &len);
    if (!bytes || len == 0) { FAIL("bytes"); lp2p_multiaddr_free(ma); return; }
    /* Verify we got some binary data */
    if (len < 7) { FAIL("too short"); lp2p_multiaddr_free(ma); return; }
    lp2p_multiaddr_free(ma);
    PASS();
}

int main(void) {
    printf("test_multiaddr:\n");
    test_parse_ip4_tcp();
    test_parse_ip6_tcp();
    test_parse_dns4_tcp();
    test_parse_quic_v1();
    test_parse_with_p2p();
    test_equal();
    test_not_equal();
    test_with_peer_id();
    test_invalid_protocol();
    test_no_peer_id();
    test_bytes_roundtrip();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
