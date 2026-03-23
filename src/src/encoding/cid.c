/* src/encoding/cid.c — CIDv1 decode/encode for peer ID text parsing */
#include "encoding/cid.h"
#include "encoding/varint.h"
#include "encoding/multicodec.h"
#include <string.h>

bool lp2p_cid_decode(const uint8_t *cid_bytes, size_t cid_len,
                      uint64_t *version, uint64_t *codec,
                      const uint8_t **multihash, size_t *multihash_len) {
    uint64_t ver;
    size_t n1 = lp2p_varint_decode(cid_bytes, cid_len, &ver);
    if (n1 == 0 || ver != LP2P_CODEC_CIDV1) return false;

    uint64_t cod;
    size_t n2 = lp2p_varint_decode(cid_bytes + n1, cid_len - n1, &cod);
    if (n2 == 0) return false;

    *version       = ver;
    *codec         = cod;
    *multihash     = cid_bytes + n1 + n2;
    *multihash_len = cid_len - n1 - n2;
    return true;
}

size_t lp2p_cid_encode(uint64_t codec,
                        const uint8_t *multihash, size_t multihash_len,
                        uint8_t *out, size_t out_cap) {
    uint8_t vbuf[10];
    size_t v1 = lp2p_varint_encode(LP2P_CODEC_CIDV1, vbuf);
    uint8_t vbuf2[10];
    size_t v2 = lp2p_varint_encode(codec, vbuf2);
    size_t total = v1 + v2 + multihash_len;
    if (total > out_cap) return 0;
    memcpy(out, vbuf, v1);
    memcpy(out + v1, vbuf2, v2);
    memcpy(out + v1 + v2, multihash, multihash_len);
    return total;
}
