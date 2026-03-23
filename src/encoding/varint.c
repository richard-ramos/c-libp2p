/* src/encoding/varint.c — unsigned LEB128 varint */
#include "encoding/varint.h"

size_t lp2p_varint_encode(uint64_t val, uint8_t *buf) {
    size_t i = 0;
    do {
        uint8_t byte = val & 0x7F;
        val >>= 7;
        if (val)
            byte |= 0x80;
        buf[i++] = byte;
    } while (val);
    return i;
}

size_t lp2p_varint_decode(const uint8_t *buf, size_t len, uint64_t *out) {
    uint64_t val = 0;
    unsigned shift = 0;
    for (size_t i = 0; i < len && i < 10; i++) {
        uint64_t byte = buf[i];
        val |= (byte & 0x7F) << shift;
        shift += 7;
        if (!(byte & 0x80)) {
            *out = val;
            return i + 1;
        }
    }
    return 0; /* truncated or overflow */
}
