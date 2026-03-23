/* src/encoding/multibase.c — base58btc and base32lower encoding */
#include "encoding/multibase.h"
#include <string.h>

/* ── Base58 (Bitcoin alphabet) ────────────────────────────────────────────── */

static const char b58_alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

static const int8_t b58_decode_map[128] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
};

size_t lp2p_base58btc_encode(const uint8_t *data, size_t len,
                              char *out, size_t out_cap) {
    /* count leading zeros */
    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) zeros++;

    /* allocate enough space for base58 conversion */
    size_t size = (len - zeros) * 138 / 100 + 1;
    uint8_t buf[512];
    if (size > sizeof(buf)) return 0;
    memset(buf, 0, size);

    for (size_t i = zeros; i < len; i++) {
        int carry = data[i];
        for (size_t j = size; j-- > 0; ) {
            carry += 256 * (int)buf[j];
            buf[j] = carry % 58;
            carry /= 58;
        }
    }

    /* skip leading zeros in base58 result */
    size_t start = 0;
    while (start < size && buf[start] == 0) start++;

    size_t out_len = zeros + (size - start);
    if (out_len >= out_cap) return 0;

    for (size_t i = 0; i < zeros; i++)
        out[i] = '1';
    for (size_t i = start; i < size; i++)
        out[zeros + (i - start)] = b58_alphabet[buf[i]];
    out[out_len] = '\0';
    return out_len;
}

size_t lp2p_base58btc_decode(const char *str, size_t slen,
                              uint8_t *out, size_t out_cap) {
    /* count leading '1's */
    size_t zeros = 0;
    while (zeros < slen && str[zeros] == '1') zeros++;

    size_t size = (slen - zeros) * 733 / 1000 + 1;
    uint8_t buf[512];
    if (size > sizeof(buf)) return 0;
    memset(buf, 0, size);

    for (size_t i = zeros; i < slen; i++) {
        unsigned char ch = (unsigned char)str[i];
        if (ch >= 128) return 0;
        int val = b58_decode_map[ch];
        if (val < 0) return 0;

        int carry = val;
        for (size_t j = size; j-- > 0; ) {
            carry += 58 * (int)buf[j];
            buf[j] = carry & 0xFF;
            carry >>= 8;
        }
    }

    /* skip leading zeros in binary result */
    size_t start = 0;
    while (start < size && buf[start] == 0) start++;

    size_t out_len = zeros + (size - start);
    if (out_len > out_cap) return 0;

    memset(out, 0, zeros);
    memcpy(out + zeros, buf + start, size - start);
    return out_len;
}

/* ── Base32 lower (RFC 4648, no padding) ──────────────────────────────────── */

static const char b32_alphabet[] = "abcdefghijklmnopqrstuvwxyz234567";

static int8_t b32_val(char c) {
    if (c >= 'a' && c <= 'z') return c - 'a';
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

size_t lp2p_base32_encode(const uint8_t *data, size_t len,
                           char *out, size_t out_cap) {
    size_t out_len = (len * 8 + 4) / 5;
    if (out_len >= out_cap) return 0;

    size_t oi = 0;
    int buffer = 0, bits = 0;
    for (size_t i = 0; i < len; i++) {
        buffer = (buffer << 8) | data[i];
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            out[oi++] = b32_alphabet[(buffer >> bits) & 0x1F];
        }
    }
    if (bits > 0) {
        out[oi++] = b32_alphabet[(buffer << (5 - bits)) & 0x1F];
    }
    out[oi] = '\0';
    return oi;
}

size_t lp2p_base32_decode(const char *str, size_t slen,
                           uint8_t *out, size_t out_cap) {
    size_t out_len = slen * 5 / 8;
    if (out_len > out_cap) return 0;

    size_t oi = 0;
    int buffer = 0, bits = 0;
    for (size_t i = 0; i < slen; i++) {
        int8_t val = b32_val(str[i]);
        if (val < 0) return 0;
        buffer = (buffer << 5) | val;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[oi++] = (buffer >> bits) & 0xFF;
        }
    }
    return oi;
}
