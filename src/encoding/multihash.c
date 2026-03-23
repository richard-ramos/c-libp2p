/* src/encoding/multihash.c — multihash: identity and sha2-256 */
#include "encoding/multihash.h"
#include "encoding/multicodec.h"
#include "encoding/varint.h"
#include <openssl/evp.h>
#include <string.h>

size_t lp2p_multihash_encode(uint64_t fn_code,
                              const uint8_t *digest, size_t digest_len,
                              uint8_t *out, size_t out_cap) {
    uint8_t vbuf[10];
    size_t v1 = lp2p_varint_encode(fn_code, vbuf);
    uint8_t vbuf2[10];
    size_t v2 = lp2p_varint_encode(digest_len, vbuf2);
    size_t total = v1 + v2 + digest_len;
    if (total > out_cap) return 0;
    memcpy(out, vbuf, v1);
    memcpy(out + v1, vbuf2, v2);
    memcpy(out + v1 + v2, digest, digest_len);
    return total;
}

size_t lp2p_multihash_decode(const uint8_t *buf, size_t len,
                              uint64_t *fn_code,
                              const uint8_t **digest, size_t *digest_len) {
    uint64_t code;
    size_t n1 = lp2p_varint_decode(buf, len, &code);
    if (n1 == 0) return 0;

    uint64_t dlen;
    size_t n2 = lp2p_varint_decode(buf + n1, len - n1, &dlen);
    if (n2 == 0) return 0;

    if (n1 + n2 + dlen > len) return 0;

    *fn_code    = code;
    *digest     = buf + n1 + n2;
    *digest_len = (size_t)dlen;
    return n1 + n2 + dlen;
}

size_t lp2p_multihash_sha2_256(const uint8_t *data, size_t data_len,
                                uint8_t *out, size_t out_cap) {
    if (out_cap < 34) return 0;
    uint8_t hash[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return 0;
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, data_len) != 1 ||
        EVP_DigestFinal_ex(ctx, hash, NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        return 0;
    }
    EVP_MD_CTX_free(ctx);
    return lp2p_multihash_encode(LP2P_CODEC_SHA2_256, hash, 32, out, out_cap);
}

size_t lp2p_multihash_identity(const uint8_t *data, size_t data_len,
                                uint8_t *out, size_t out_cap) {
    return lp2p_multihash_encode(LP2P_CODEC_IDENTITY, data, data_len, out, out_cap);
}
