/* src/encoding/multibase.h — base58btc and base32lower encoding */
#ifndef LP2P_ENCODING_MULTIBASE_H
#define LP2P_ENCODING_MULTIBASE_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

/* base58btc encode (Bitcoin alphabet). out must be large enough.
   Returns number of chars written (not including NUL). */
size_t lp2p_base58btc_encode(const uint8_t *data, size_t len,
                              char *out, size_t out_cap);

/* base58btc decode. Returns number of bytes written to out, or 0 on error. */
size_t lp2p_base58btc_decode(const char *str, size_t slen,
                              uint8_t *out, size_t out_cap);

/* base32 lower (RFC 4648 without padding) encode.
   Returns number of chars written (not including NUL). */
size_t lp2p_base32_encode(const uint8_t *data, size_t len,
                           char *out, size_t out_cap);

/* base32 lower (RFC 4648 without padding) decode.
   Returns number of bytes written to out, or 0 on error. */
size_t lp2p_base32_decode(const char *str, size_t slen,
                           uint8_t *out, size_t out_cap);

#endif /* LP2P_ENCODING_MULTIBASE_H */
