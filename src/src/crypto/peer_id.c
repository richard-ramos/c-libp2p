/* src/crypto/peer_id.c — peer ID derivation and text encoding/decoding */
#include <libp2p/crypto.h>
#include <libp2p/errors.h>
#include <libp2p/types.h>
#include "crypto/keypair_internal.h"
#include "encoding/varint.h"
#include "encoding/multibase.h"
#include "encoding/multicodec.h"
#include "encoding/multihash.h"
#include "encoding/cid.h"
#include <sodium.h>
#include <string.h>

/*
 * Protobuf encoding for libp2p PublicKey:
 *   message PublicKey {
 *     required KeyType Type = 1;   // varint, field 1
 *     required bytes   Data = 2;   // length-delimited, field 2
 *   }
 * Field 1 (Type):  tag = (1<<3)|0 = 0x08, value = key_type enum
 * Field 2 (Data):  tag = (2<<3)|2 = 0x12, length = varint, then bytes
 */
static size_t encode_pubkey_protobuf(lp2p_key_type_t type,
                                      const uint8_t *key_data, size_t key_len,
                                      uint8_t *out, size_t out_cap) {
    uint8_t tmp[10];
    size_t pos = 0;

    /* field 1: tag 0x08 + varint type */
    if (pos >= out_cap) return 0;
    out[pos++] = 0x08;
    size_t n = lp2p_varint_encode((uint64_t)type, tmp);
    if (pos + n > out_cap) return 0;
    memcpy(out + pos, tmp, n);
    pos += n;

    /* field 2: tag 0x12 + varint length + data */
    if (pos >= out_cap) return 0;
    out[pos++] = 0x12;
    n = lp2p_varint_encode(key_len, tmp);
    if (pos + n + key_len > out_cap) return 0;
    memcpy(out + pos, tmp, n);
    pos += n;
    memcpy(out + pos, key_data, key_len);
    pos += key_len;

    return pos;
}

/*
 * For Ed25519 keys (32-byte pubkey → 37-byte protobuf):
 *   protobuf is 37 bytes, which is < 42 → use identity multihash
 *   Result: 0x00 (identity) + varint(37) + 37 bytes = 39 bytes
 *
 * For keys >= 42 bytes protobuf: use sha2-256 multihash
 *   Result: 0x12 + 0x20 + 32-byte hash = 34 bytes
 */

lp2p_err_t lp2p_peer_id_from_keypair(const lp2p_keypair_t *kp,
                                      lp2p_peer_id_t *out) {
    if (!kp || !out)
        return LP2P_ERR_INVALID_ARG;

    /* Serialize public key to protobuf */
    uint8_t pubkey[crypto_sign_PUBLICKEYBYTES];
    size_t pubkey_len = sizeof(pubkey);
    lp2p_err_t err = lp2p_keypair_public_bytes(kp, pubkey, &pubkey_len);
    if (err != LP2P_OK) return err;

    uint8_t proto_buf[256];
    size_t proto_len = encode_pubkey_protobuf(
        lp2p_keypair_type(kp), pubkey, pubkey_len,
        proto_buf, sizeof(proto_buf));
    if (proto_len == 0)
        return LP2P_ERR_INTERNAL;

    return lp2p_peer_id_from_public_key(proto_buf, proto_len, out);
}

lp2p_err_t lp2p_peer_id_from_public_key(const uint8_t *pubkey, size_t len,
                                          lp2p_peer_id_t *out) {
    if (!pubkey || !out)
        return LP2P_ERR_INVALID_ARG;

    size_t mh_len;
    if (len < 42) {
        /* Use identity multihash (inline) */
        mh_len = lp2p_multihash_identity(pubkey, len, out->bytes, LP2P_PEER_ID_SIZE);
    } else {
        /* Use sha2-256 multihash */
        mh_len = lp2p_multihash_sha2_256(pubkey, len, out->bytes, LP2P_PEER_ID_SIZE);
    }

    if (mh_len == 0)
        return LP2P_ERR_INTERNAL;

    out->len = mh_len;
    return LP2P_OK;
}

lp2p_err_t lp2p_peer_id_to_string(const lp2p_peer_id_t *id,
                                    char *out, size_t *out_len) {
    if (!id || !out || !out_len)
        return LP2P_ERR_INVALID_ARG;

    if (id->len == 0) {
        if (*out_len < 1) return LP2P_ERR_INVALID_ARG;
        out[0] = '\0';
        *out_len = 0;
        return LP2P_ERR_INVALID_ARG;
    }

    /* Need room for encoded chars plus NUL terminator */
    if (*out_len < 2) return LP2P_ERR_INVALID_ARG;

    /* Emit legacy base58btc form (no multibase prefix) */
    size_t n = lp2p_base58btc_encode(id->bytes, id->len, out, *out_len - 1);
    if (n == 0) {
        out[0] = '\0';
        return LP2P_ERR_INVALID_ARG;
    }
    out[n] = '\0';
    *out_len = n;
    return LP2P_OK;
}

lp2p_err_t lp2p_peer_id_from_string(const char *str, lp2p_peer_id_t *out) {
    if (!str || !out)
        return LP2P_ERR_INVALID_ARG;

    size_t slen = strlen(str);
    if (slen == 0)
        return LP2P_ERR_INVALID_ARG;

    /* Try CIDv1/base32 form: starts with 'b' (multibase base32lower prefix) */
    if (str[0] == 'b' && slen > 1) {
        uint8_t cid_bytes[256];
        size_t cid_len = lp2p_base32_decode(str + 1, slen - 1,
                                             cid_bytes, sizeof(cid_bytes));
        if (cid_len > 0) {
            uint64_t version, codec;
            const uint8_t *mh;
            size_t mh_len;
            if (lp2p_cid_decode(cid_bytes, cid_len,
                                &version, &codec, &mh, &mh_len)) {
                if (codec == LP2P_CODEC_LIBP2P_KEY && mh_len <= LP2P_PEER_ID_SIZE) {
                    memcpy(out->bytes, mh, mh_len);
                    out->len = mh_len;
                    return LP2P_OK;
                }
            }
        }
    }

    /* Try legacy bare base58btc multihash */
    uint8_t decoded[256];
    size_t dec_len = lp2p_base58btc_decode(str, slen, decoded, sizeof(decoded));
    if (dec_len == 0 || dec_len > LP2P_PEER_ID_SIZE)
        return LP2P_ERR_INVALID_ARG;

    /* Validate it's a valid multihash */
    uint64_t fn_code;
    const uint8_t *digest;
    size_t digest_len;
    size_t consumed = lp2p_multihash_decode(decoded, dec_len,
                                             &fn_code, &digest, &digest_len);
    if (consumed == 0 || consumed != dec_len)
        return LP2P_ERR_INVALID_ARG;

    memcpy(out->bytes, decoded, dec_len);
    out->len = dec_len;
    return LP2P_OK;
}

bool lp2p_peer_id_equal(const lp2p_peer_id_t *a, const lp2p_peer_id_t *b) {
    if (!a || !b) return false;
    if (a->len != b->len) return false;
    return memcmp(a->bytes, b->bytes, a->len) == 0;
}
