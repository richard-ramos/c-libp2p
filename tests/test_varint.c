/* test_varint.c — unit tests for unsigned LEB128 varint */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

/* We include the internal header directly since tests link against lp2p */
#include "encoding/varint.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { printf("  %s ... ", #name);
#define PASS() printf("ok\n"); tests_passed++; } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); tests_failed++; } while(0)

static void test_encode_zero(void) {
    TEST(encode_zero);
    uint8_t buf[10];
    size_t n = lp2p_varint_encode(0, buf);
    if (n != 1 || buf[0] != 0x00) { FAIL("expected 0x00"); return; }
    PASS();
}

static void test_encode_one(void) {
    TEST(encode_one);
    uint8_t buf[10];
    size_t n = lp2p_varint_encode(1, buf);
    if (n != 1 || buf[0] != 0x01) { FAIL("expected 0x01"); return; }
    PASS();
}

static void test_encode_127(void) {
    TEST(encode_127);
    uint8_t buf[10];
    size_t n = lp2p_varint_encode(127, buf);
    if (n != 1 || buf[0] != 0x7F) { FAIL("expected 0x7F"); return; }
    PASS();
}

static void test_encode_128(void) {
    TEST(encode_128);
    uint8_t buf[10];
    size_t n = lp2p_varint_encode(128, buf);
    if (n != 2 || buf[0] != 0x80 || buf[1] != 0x01) {
        FAIL("expected 0x80 0x01"); return;
    }
    PASS();
}

static void test_encode_300(void) {
    TEST(encode_300);
    uint8_t buf[10];
    size_t n = lp2p_varint_encode(300, buf);
    if (n != 2 || buf[0] != 0xAC || buf[1] != 0x02) {
        FAIL("expected 0xAC 0x02"); return;
    }
    PASS();
}

static void test_encode_large(void) {
    TEST(encode_large);
    uint8_t buf[10];
    size_t n = lp2p_varint_encode(UINT64_MAX, buf);
    if (n != 10) { FAIL("expected 10 bytes"); return; }
    PASS();
}

static void test_roundtrip(void) {
    TEST(roundtrip);
    uint64_t values[] = {0, 1, 127, 128, 255, 256, 300, 16383, 16384,
                         2097151, 268435455, UINT64_MAX};
    for (size_t i = 0; i < sizeof(values)/sizeof(values[0]); i++) {
        uint8_t buf[10];
        size_t enc = lp2p_varint_encode(values[i], buf);
        uint64_t decoded;
        size_t dec = lp2p_varint_decode(buf, enc, &decoded);
        if (dec != enc || decoded != values[i]) {
            FAIL("roundtrip failed"); return;
        }
    }
    PASS();
}

static void test_decode_truncated(void) {
    TEST(decode_truncated);
    /* 0x80 needs more bytes */
    uint8_t buf[] = {0x80};
    uint64_t val;
    size_t n = lp2p_varint_decode(buf, 1, &val);
    if (n != 0) { FAIL("expected 0 for truncated"); return; }
    PASS();
}

static void test_multicodec_codes(void) {
    TEST(multicodec_codes);
    /* Verify that specific protocol codes encode correctly */
    uint8_t buf[10];
    uint64_t val;

    /* tcp = 0x06 */
    size_t n = lp2p_varint_encode(0x06, buf);
    lp2p_varint_decode(buf, n, &val);
    if (val != 0x06) { FAIL("tcp"); return; }

    /* udp = 0x0111 */
    n = lp2p_varint_encode(0x0111, buf);
    lp2p_varint_decode(buf, n, &val);
    if (val != 0x0111) { FAIL("udp"); return; }

    /* p2p = 0x01A5 */
    n = lp2p_varint_encode(0x01A5, buf);
    lp2p_varint_decode(buf, n, &val);
    if (val != 0x01A5) { FAIL("p2p"); return; }

    /* quic-v1 = 0x01CD */
    n = lp2p_varint_encode(0x01CD, buf);
    lp2p_varint_decode(buf, n, &val);
    if (val != 0x01CD) { FAIL("quic-v1"); return; }

    PASS();
}

int main(void) {
    printf("test_varint:\n");
    test_encode_zero();
    test_encode_one();
    test_encode_127();
    test_encode_128();
    test_encode_300();
    test_encode_large();
    test_roundtrip();
    test_decode_truncated();
    test_multicodec_codes();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
