/* src/encoding/cid.h — CIDv1 decode/encode for peer ID text parsing */
#ifndef LP2P_ENCODING_CID_H
#define LP2P_ENCODING_CID_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* Decode a CIDv1 binary blob.
   Returns true and sets codec and multihash pointer/length.
   The multihash pointer points into cid_bytes. */
bool lp2p_cid_decode(const uint8_t *cid_bytes, size_t cid_len,
                      uint64_t *version, uint64_t *codec,
                      const uint8_t **multihash, size_t *multihash_len);

/* Encode a CIDv1 binary blob from codec + multihash.
   Returns total bytes written, or 0 on error. */
size_t lp2p_cid_encode(uint64_t codec,
                        const uint8_t *multihash, size_t multihash_len,
                        uint8_t *out, size_t out_cap);

#endif /* LP2P_ENCODING_CID_H */
