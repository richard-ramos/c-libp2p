/* src/encoding/multihash.h — multihash: identity and sha2-256 */
#ifndef LP2P_ENCODING_MULTIHASH_H
#define LP2P_ENCODING_MULTIHASH_H

#include <stddef.h>
#include <stdint.h>

/* Encode a multihash.  fn_code is LP2P_CODEC_IDENTITY or LP2P_CODEC_SHA2_256.
   Writes <varint code><varint len><digest> into out.
   Returns total bytes written, or 0 on error. */
size_t lp2p_multihash_encode(uint64_t fn_code,
                              const uint8_t *digest, size_t digest_len,
                              uint8_t *out, size_t out_cap);

/* Decode a multihash from buf[0..len).
   On success stores fn_code, digest pointer (into buf) and digest_len.
   Returns total bytes consumed, or 0 on error. */
size_t lp2p_multihash_decode(const uint8_t *buf, size_t len,
                              uint64_t *fn_code,
                              const uint8_t **digest, size_t *digest_len);

/* Compute sha2-256 multihash of data.
   Writes the full multihash (varint 0x12 + varint 32 + 32-byte digest).
   Returns total bytes written. out must have >= 34 bytes. */
size_t lp2p_multihash_sha2_256(const uint8_t *data, size_t data_len,
                                uint8_t *out, size_t out_cap);

/* Compute identity multihash of data.
   Writes varint 0x00 + varint len + data.
   Returns total bytes written, or 0 on error. */
size_t lp2p_multihash_identity(const uint8_t *data, size_t data_len,
                                uint8_t *out, size_t out_cap);

#endif /* LP2P_ENCODING_MULTIHASH_H */
