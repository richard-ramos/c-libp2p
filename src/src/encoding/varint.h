/* src/encoding/varint.h — unsigned LEB128 varint */
#ifndef LP2P_ENCODING_VARINT_H
#define LP2P_ENCODING_VARINT_H

#include <stddef.h>
#include <stdint.h>

/* Encode a uint64 as unsigned LEB128 into buf (must have >= 10 bytes).
   Returns number of bytes written. */
size_t lp2p_varint_encode(uint64_t val, uint8_t *buf);

/* Decode an unsigned LEB128 varint from buf[0..len).
   On success, stores value in *out and returns number of bytes consumed.
   On failure (truncated or overflow), returns 0. */
size_t lp2p_varint_decode(const uint8_t *buf, size_t len, uint64_t *out);

#endif /* LP2P_ENCODING_VARINT_H */
