/* src/transport/quic/quic_transport.c — QUIC transport via ngtcp2 + OpenSSL + libuv */

#include "quic_transport.h"
#include "quic_tls.h"
#include "connmgr_internal.h"
#include "connection_internal.h"
#include "crypto/keypair_internal.h"
#include "encoding/varint.h"
#include "libp2p/crypto.h"
#include "libp2p/multiaddr.h"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_boringssl.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/ec.h>
#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/rand.h>
#include <openssl/pem.h>

#include <sodium.h>
#include <uv.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

/* ════════════════════════════════════════════════════════════════════════════
 *  Constants
 * ════════════════════════════════════════════════════════════════════════════ */

#define QUIC_MAX_PKTLEN      1200
#define QUIC_STREAM_BUF_INIT 4096
#define QUIC_SCID_LEN        18
#define QUIC_APP_ERR_RESET   1
#define QUIC_WRITE_CHUNK_SIZE (16 * 1024)

struct quic_write_chunk {
    struct quic_write_chunk *next;
    uint8_t                 *data;
    size_t                   len;
    size_t                   offset;
    size_t                   acked;
    uint64_t                 stream_offset;
    bool                     fin;
};

typedef enum {
    QUIC_STREAM_ACTION_CLOSE,
    QUIC_STREAM_ACTION_RESET,
} quic_stream_action_t;

typedef struct {
    lp2p_conn_t          *conn;
    int64_t               stream_id;
    quic_stream_action_t  action;
    lp2p_stream_write_cb  close_cb;
    void                 *close_ud;
} quic_stream_deferred_action_t;

/* quic_now() was removed in newer ngtcp2 versions; use CLOCK_MONOTONIC */
static ngtcp2_tstamp quic_now(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ngtcp2_tstamp)ts.tv_sec * NGTCP2_SECONDS + (ngtcp2_tstamp)ts.tv_nsec;
}

/* Protobuf field tags for libp2p PublicKey message:
   message PublicKey { KeyType Type = 1; bytes Data = 2; }
   KeyType: Ed25519=1, RSA=0, Secp256k1=2, ECDSA=3 */
#define PB_TAG_TYPE  0x08  /* field 1, varint */
#define PB_TAG_DATA  0x12  /* field 2, length-delimited */

/* libp2p TLS handshake signature prefix */
static const char TLS_SIG_PREFIX[] = "libp2p-tls-handshake:";

/* ════════════════════════════════════════════════════════════════════════════
 *  Forward declarations
 * ════════════════════════════════════════════════════════════════════════════ */

static lp2p_err_t quic_listen(void *transport, const lp2p_multiaddr_t *addr,
                               void (*on_conn)(void *transport, lp2p_conn_t *conn,
                                               void *userdata),
                               void *userdata);
static lp2p_err_t quic_dial(void *transport, const lp2p_multiaddr_t *addr,
                              void (*on_conn)(lp2p_conn_t *conn, lp2p_err_t err, void *userdata),
                              void *userdata);
static void        quic_close(void *transport);
static bool        quic_handles(void *transport, const lp2p_multiaddr_t *addr);

static void quic_conn_write_packets(quic_conn_t *qc);
static void quic_conn_schedule_timer(quic_conn_t *qc);
static void quic_conn_free(quic_conn_t *qc);
static quic_stream_t *quic_conn_find_stream(quic_conn_t *qc, int64_t stream_id);
static quic_stream_t *quic_conn_create_stream(quic_conn_t *qc, int64_t stream_id);
static void quic_stream_deliver_data(quic_stream_t *qs);
static void quic_stream_maybe_notify(quic_stream_t *qs);
static bool quic_stream_is_remote_initiated(const quic_conn_t *qc, int64_t stream_id);
static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                       uint64_t offset, uint64_t datalen,
                                       void *user_data, void *stream_user_data);
static void quic_conn_remove(quic_conn_t *qc);
static bool sockaddr_to_quic_multiaddr(const struct sockaddr_storage *addr,
                                       const lp2p_peer_id_t *peer_id,
                                       lp2p_multiaddr_t **out);
static void quic_stream_free(quic_stream_t *qs);
static void quic_transport_maybe_close_udp(quic_transport_t *qt);
static void udp_close_cb(uv_handle_t *handle);
static ngtcp2_conn *quic_crypto_get_conn(ngtcp2_crypto_conn_ref *conn_ref);
static bool quic_conn_track_local_cid(quic_conn_t *qc, const ngtcp2_cid *cid);
static bool quic_conn_matches_local_cid(const quic_conn_t *qc,
                                        const uint8_t *data, size_t datalen);
static lp2p_err_t quic_stream_close_now(lp2p_stream_t *stream, lp2p_stream_write_cb cb,
                                        void *userdata);
static lp2p_err_t quic_stream_reset_now(lp2p_stream_t *stream);
static void quic_stream_deferred_action_run(void *arg);
static void quic_stream_deferred_action_cleanup(void *arg);
static lp2p_err_t quic_stream_schedule_action(lp2p_stream_t *stream,
                                              quic_stream_action_t action,
                                              lp2p_stream_write_cb cb,
                                              void *userdata);

static void quic_write_chunk_free(quic_write_chunk_t *chunk)
{
    if (!chunk) return;
    free(chunk->data);
    free(chunk);
}

static void quic_write_chunk_list_free(quic_write_chunk_t *head)
{
    while (head) {
        quic_write_chunk_t *next = head->next;
        quic_write_chunk_free(head);
        head = next;
    }
}

static void quic_stream_deferred_action_cleanup(void *arg)
{
    free(arg);
}

static void quic_stream_deferred_action_run(void *arg)
{
    quic_stream_deferred_action_t *action = arg;
    lp2p_conn_t *conn = action->conn;

    if (conn && conn->backend == LP2P_CONN_BACKEND_QUIC && conn->backend_impl) {
        quic_conn_t *qc = (quic_conn_t *)conn->backend_impl;
        quic_stream_t *qs = quic_conn_find_stream(qc, action->stream_id);

        if (qs) {
            if (action->action == QUIC_STREAM_ACTION_CLOSE) {
                (void)quic_stream_close_now(&qs->pub, action->close_cb, action->close_ud);
            } else {
                (void)quic_stream_reset_now(&qs->pub);
            }
        }
    }

    free(action);
}

static lp2p_err_t quic_stream_schedule_action(lp2p_stream_t *stream,
                                              quic_stream_action_t action,
                                              lp2p_stream_write_cb cb,
                                              void *userdata)
{
    if (!stream) return LP2P_ERR_INVALID_ARG;

    quic_stream_t *qs = (quic_stream_t *)stream;
    quic_conn_t *qc = qs->qconn;
    if (!qc || !qc->pub_conn) return LP2P_ERR_INVALID_ARG;

    quic_stream_deferred_action_t *deferred = calloc(1, sizeof(*deferred));
    if (!deferred) return LP2P_ERR_NOMEM;

    deferred->conn = qc->pub_conn;
    deferred->stream_id = qs->stream_id;
    deferred->action = action;
    deferred->close_cb = cb;
    deferred->close_ud = userdata;

    if (!lp2p_conn_defer(qc->pub_conn, quic_stream_deferred_action_run,
                         deferred, quic_stream_deferred_action_cleanup)) {
        return LP2P_ERR_NOMEM;
    }

    return LP2P_OK;
}

static void quic_stream_append_send_chunk(quic_stream_t *qs, quic_write_chunk_t *chunk)
{
    chunk->next = NULL;
    if (qs->send_tail) {
        qs->send_tail->next = chunk;
    } else {
        qs->send_head = chunk;
    }
    qs->send_tail = chunk;
}

static void quic_stream_append_retained_chunk(quic_stream_t *qs, quic_write_chunk_t *chunk)
{
    chunk->next = NULL;
    if (qs->retained_tail) {
        qs->retained_tail->next = chunk;
    } else {
        qs->retained_head = chunk;
    }
    qs->retained_tail = chunk;
}

static void quic_stream_pop_retained_head(quic_stream_t *qs)
{
    quic_write_chunk_t *chunk = qs->retained_head;
    if (!chunk) return;

    qs->retained_head = chunk->next;
    if (!qs->retained_head) {
        qs->retained_tail = NULL;
    }
    quic_write_chunk_free(chunk);
}

static const lp2p_transport_vtable_t quic_vtable = {
    .listen  = quic_listen,
    .dial    = quic_dial,
    .close   = quic_close,
    .handles = quic_handles,
};

/* ════════════════════════════════════════════════════════════════════════════
 *  Protobuf helpers — encode/decode libp2p PublicKey
 * ════════════════════════════════════════════════════════════════════════════ */

/* Encode a libp2p PublicKey protobuf: { Type: key_type, Data: pubkey_bytes }
   Returns bytes written to out, or 0 on error. */
static size_t pb_encode_public_key(lp2p_key_type_t key_type,
                                    const uint8_t *pubkey, size_t pubkey_len,
                                    uint8_t *out, size_t out_cap)
{
    /* field 1 (Type): tag(0x08) + varint(key_type)
       field 2 (Data): tag(0x12) + varint(pubkey_len) + pubkey */
    size_t needed = 1 + 1 + 1 + 1 + pubkey_len; /* minimal */
    if (pubkey_len > 127) needed++;  /* varint may take 2 bytes */
    if (out_cap < needed) return 0;

    size_t off = 0;
    out[off++] = PB_TAG_TYPE;
    out[off++] = (uint8_t)key_type;
    out[off++] = PB_TAG_DATA;
    if (pubkey_len < 128) {
        out[off++] = (uint8_t)pubkey_len;
    } else {
        out[off++] = (uint8_t)(0x80 | (pubkey_len & 0x7F));
        out[off++] = (uint8_t)(pubkey_len >> 7);
    }
    memcpy(out + off, pubkey, pubkey_len);
    off += pubkey_len;
    return off;
}

/* Decode a libp2p PublicKey protobuf. Returns 0 on success. */
static int pb_decode_public_key(const uint8_t *data, size_t data_len,
                                 lp2p_key_type_t *out_type,
                                 const uint8_t **out_pubkey, size_t *out_pubkey_len)
{
    size_t off = 0;
    bool got_type = false, got_data = false;

    while (off < data_len) {
        if (off >= data_len) return -1;
        uint8_t tag = data[off++];

        if (tag == PB_TAG_TYPE) {
            if (off >= data_len) return -1;
            uint64_t val = 0;
            int shift = 0;
            do {
                if (off > data_len) return -1;
                uint8_t b = data[off++];
                val |= (uint64_t)(b & 0x7F) << shift;
                shift += 7;
                if (!(b & 0x80)) break;
            } while (shift < 64);
            *out_type = (lp2p_key_type_t)val;
            got_type = true;
        } else if (tag == PB_TAG_DATA) {
            if (off >= data_len) return -1;
            uint64_t len = 0;
            int shift = 0;
            do {
                if (off > data_len) return -1;
                uint8_t b = data[off++];
                len |= (uint64_t)(b & 0x7F) << shift;
                shift += 7;
                if (!(b & 0x80)) break;
            } while (shift < 64);
            if (off + len > data_len) return -1;
            *out_pubkey = data + off;
            *out_pubkey_len = (size_t)len;
            off += (size_t)len;
            got_data = true;
        } else {
            /* skip unknown field */
            return -1;
        }
    }
    return (got_type && got_data) ? 0 : -1;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  ASN.1 encode/decode for the custom TLS extension SignedKey
 *  SEQUENCE { publicKey OCTET STRING, signature OCTET STRING }
 * ════════════════════════════════════════════════════════════════════════════ */

/* Encode ASN.1 DER length */
static size_t asn1_encode_length(size_t len, uint8_t *out)
{
    if (len < 128) {
        out[0] = (uint8_t)len;
        return 1;
    } else if (len < 256) {
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        return 2;
    } else {
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)(len & 0xFF);
        return 3;
    }
}

/* Encode SignedKey: SEQUENCE { OCTET STRING pubkey, OCTET STRING sig } */
static size_t asn1_encode_signed_key(const uint8_t *pubkey, size_t pk_len,
                                      const uint8_t *sig, size_t sig_len,
                                      uint8_t *out, size_t out_cap)
{
    /* Each OCTET STRING: tag(1) + length(1-3) + data
       SEQUENCE: tag(1) + length(1-3) + contents */

    /* Pre-calculate octet string sizes */
    uint8_t pk_len_enc[3], sig_len_enc[3];
    size_t pk_len_sz = asn1_encode_length(pk_len, pk_len_enc);
    size_t sig_len_sz = asn1_encode_length(sig_len, sig_len_enc);

    size_t pk_total = 1 + pk_len_sz + pk_len;   /* 0x04 + len + data */
    size_t sig_total = 1 + sig_len_sz + sig_len;
    size_t seq_content = pk_total + sig_total;

    uint8_t seq_len_enc[3];
    size_t seq_len_sz = asn1_encode_length(seq_content, seq_len_enc);
    size_t total = 1 + seq_len_sz + seq_content;

    if (out_cap < total) return 0;

    size_t off = 0;
    /* SEQUENCE tag */
    out[off++] = 0x30;
    memcpy(out + off, seq_len_enc, seq_len_sz);
    off += seq_len_sz;

    /* pubkey OCTET STRING */
    out[off++] = 0x04;
    memcpy(out + off, pk_len_enc, pk_len_sz);
    off += pk_len_sz;
    memcpy(out + off, pubkey, pk_len);
    off += pk_len;

    /* signature OCTET STRING */
    out[off++] = 0x04;
    memcpy(out + off, sig_len_enc, sig_len_sz);
    off += sig_len_sz;
    memcpy(out + off, sig, sig_len);
    off += sig_len;

    return off;
}

/* Decode SignedKey ASN.1: SEQUENCE { OCTET STRING, OCTET STRING } */
static int asn1_decode_signed_key(const uint8_t *data, size_t data_len,
                                   const uint8_t **out_pubkey, size_t *out_pk_len,
                                   const uint8_t **out_sig, size_t *out_sig_len)
{
    size_t off = 0;
    if (off >= data_len || data[off] != 0x30) return -1;
    off++;

    /* Decode SEQUENCE length */
    size_t seq_len = 0;
    if (data[off] < 128) {
        seq_len = data[off++];
    } else if (data[off] == 0x81) {
        off++;
        if (off >= data_len) return -1;
        seq_len = data[off++];
    } else if (data[off] == 0x82) {
        off++;
        if (off + 1 >= data_len) return -1;
        seq_len = ((size_t)data[off] << 8) | data[off + 1];
        off += 2;
    } else {
        return -1;
    }

    if (off + seq_len > data_len) return -1;

    /* First OCTET STRING (pubkey) */
    if (off >= data_len || data[off] != 0x04) return -1;
    off++;
    size_t pk_len = 0;
    if (data[off] < 128) {
        pk_len = data[off++];
    } else if (data[off] == 0x81) {
        off++;
        pk_len = data[off++];
    } else if (data[off] == 0x82) {
        off++;
        pk_len = ((size_t)data[off] << 8) | data[off + 1];
        off += 2;
    } else {
        return -1;
    }
    if (off + pk_len > data_len) return -1;
    *out_pubkey = data + off;
    *out_pk_len = pk_len;
    off += pk_len;

    /* Second OCTET STRING (signature) */
    if (off >= data_len || data[off] != 0x04) return -1;
    off++;
    size_t sig_len = 0;
    if (data[off] < 128) {
        sig_len = data[off++];
    } else if (data[off] == 0x81) {
        off++;
        sig_len = data[off++];
    } else if (data[off] == 0x82) {
        off++;
        sig_len = ((size_t)data[off] << 8) | data[off + 1];
        off += 2;
    } else {
        return -1;
    }
    if (off + sig_len > data_len) return -1;
    *out_sig = data + off;
    *out_sig_len = sig_len;

    return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Multiaddr parsing for /ip4|ip6/.../udp/.../quic-v1
 * ════════════════════════════════════════════════════════════════════════════ */

static int parse_quic_multiaddr(const char *ma_str,
                                 struct sockaddr_storage *out,
                                 bool *is_ipv6)
{
    char buf[256];
    strncpy(buf, ma_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *p = buf;
    if (*p == '/') p++;

    /* Parse protocol: ip4 or ip6 */
    char *slash = strchr(p, '/');
    if (!slash) return -1;
    *slash = '\0';

    int family;
    if (strcmp(p, "ip4") == 0) {
        family = AF_INET;
        *is_ipv6 = false;
    } else if (strcmp(p, "ip6") == 0) {
        family = AF_INET6;
        *is_ipv6 = true;
    } else {
        return -1;
    }

    /* Parse address */
    char *addr_str = slash + 1;
    slash = strchr(addr_str, '/');
    if (!slash) return -1;
    *slash = '\0';

    /* Parse "udp" */
    char *udp_str = slash + 1;
    slash = strchr(udp_str, '/');
    if (!slash) return -1;
    *slash = '\0';
    if (strcmp(udp_str, "udp") != 0) return -1;

    /* Parse port */
    char *port_str = slash + 1;
    slash = strchr(port_str, '/');
    if (!slash) return -1;
    *slash = '\0';

    int port = atoi(port_str);
    if (port < 0 || port > 65535) return -1;

    /* Parse "quic-v1" */
    char *quic_str = slash + 1;
    slash = strchr(quic_str, '/');
    if (slash) *slash = '\0';
    if (strcmp(quic_str, "quic-v1") != 0) return -1;

    memset(out, 0, sizeof(*out));
    if (family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        if (inet_pton(AF_INET, addr_str, &sin->sin_addr) != 1) return -1;
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        if (inet_pton(AF_INET6, addr_str, &sin6->sin6_addr) != 1) return -1;
    }

    return 0;
}

static socklen_t sockaddr_len(const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET6)
        return sizeof(struct sockaddr_in6);
    return sizeof(struct sockaddr_in);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  TLS certificate generation for libp2p QUIC
 * ════════════════════════════════════════════════════════════════════════════ */

lp2p_err_t quic_tls_generate_cert(const lp2p_keypair_t *identity_key,
                                   EVP_PKEY **out_tls_key,
                                   X509 **out_cert)
{
    EVP_PKEY *tls_key = NULL;
    X509 *cert = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    lp2p_err_t ret = LP2P_ERR_CRYPTO;

    /* Step 1: Generate ephemeral P-256 TLS keypair */
    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx) goto fail;
    if (EVP_PKEY_keygen_init(pctx) <= 0) goto fail;
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) goto fail;
    if (EVP_PKEY_keygen(pctx, &tls_key) <= 0) goto fail;
    EVP_PKEY_CTX_free(pctx);
    pctx = NULL;

    /* Step 2: Create self-signed X.509 cert */
    cert = X509_new();
    if (!cert) goto fail;

    /* Serial number: random 16 bytes */
    ASN1_INTEGER *serial = ASN1_INTEGER_new();
    if (!serial) goto fail;
    uint8_t serial_bytes[16];
    RAND_bytes(serial_bytes, sizeof(serial_bytes));
    serial_bytes[0] &= 0x7F; /* ensure positive */
    BIGNUM *bn_serial = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
    BN_to_ASN1_INTEGER(bn_serial, serial);
    X509_set_serialNumber(cert, serial);
    ASN1_INTEGER_free(serial);
    BN_free(bn_serial);

    /* Version 3 */
    X509_set_version(cert, 2);

    /* Subject/Issuer: empty (self-signed) */
    X509_NAME *name = X509_NAME_new();
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    X509_NAME_free(name);

    /* Validity: notBefore = now - 10 min, notAfter = now + 1 year */
    time_t now = time(NULL);
    ASN1_TIME *not_before = ASN1_TIME_new();
    ASN1_TIME *not_after = ASN1_TIME_new();
    ASN1_TIME_set(not_before, now - 600);   /* 10 minutes before now */
    ASN1_TIME_set(not_after, now + 365 * 24 * 3600);  /* 1 year */
    X509_set1_notBefore(cert, not_before);
    X509_set1_notAfter(cert, not_after);
    ASN1_TIME_free(not_before);
    ASN1_TIME_free(not_after);

    /* Set the public key */
    X509_set_pubkey(cert, tls_key);

    /* Step 3: Add custom extension OID 1.3.6.1.4.1.53594.1.1 */
    {
        /* Get the DER-encoded SubjectPublicKeyInfo of the cert's public key */
        uint8_t *spki_der = NULL;
        int spki_len = i2d_PUBKEY(tls_key, &spki_der);
        if (spki_len <= 0) goto fail;

        /* Build the data to sign: "libp2p-tls-handshake:" || SPKI_DER */
        size_t prefix_len = strlen(TLS_SIG_PREFIX);
        size_t tbs_len = prefix_len + (size_t)spki_len;
        uint8_t *tbs = malloc(tbs_len);
        if (!tbs) { OPENSSL_free(spki_der); goto fail; }
        memcpy(tbs, TLS_SIG_PREFIX, prefix_len);
        memcpy(tbs + prefix_len, spki_der, (size_t)spki_len);
        OPENSSL_free(spki_der);

        /* Sign with Ed25519 identity key using libsodium */
        const uint8_t *id_secret = lp2p_keypair_secret_ptr(identity_key);
        const uint8_t *id_public = lp2p_keypair_public_ptr(identity_key);
        uint8_t sig[crypto_sign_BYTES]; /* 64 bytes */
        unsigned long long sig_len_actual;
        if (crypto_sign_detached(sig, &sig_len_actual, tbs, tbs_len, id_secret) != 0) {
            free(tbs);
            goto fail;
        }
        free(tbs);

        /* Protobuf-encode the libp2p public key */
        uint8_t pb_pubkey[128];
        size_t pb_len = pb_encode_public_key(
            lp2p_keypair_type(identity_key),
            id_public,
            crypto_sign_PUBLICKEYBYTES,
            pb_pubkey, sizeof(pb_pubkey));
        if (pb_len == 0) goto fail;

        /* ASN.1 encode: SEQUENCE { OCTET STRING pubkey, OCTET STRING sig } */
        uint8_t ext_value[512];
        size_t ext_len = asn1_encode_signed_key(pb_pubkey, pb_len,
                                                 sig, (size_t)sig_len_actual,
                                                 ext_value, sizeof(ext_value));
        if (ext_len == 0) goto fail;

        /* Create the extension */
        ASN1_OBJECT *obj = OBJ_txt2obj(LP2P_TLS_EXTENSION_OID, 1);
        if (!obj) goto fail;

        ASN1_OCTET_STRING *ext_data = ASN1_OCTET_STRING_new();
        ASN1_OCTET_STRING_set(ext_data, ext_value, (int)ext_len);

        X509_EXTENSION *ext = X509_EXTENSION_create_by_OBJ(NULL, obj, 1 /* critical */, ext_data);
        if (!ext) {
            ASN1_OBJECT_free(obj);
            ASN1_OCTET_STRING_free(ext_data);
            goto fail;
        }
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
        ASN1_OBJECT_free(obj);
        ASN1_OCTET_STRING_free(ext_data);
    }

    /* Sign the certificate with the TLS key (ECDSA with SHA-256) */
    if (X509_sign(cert, tls_key, EVP_sha256()) == 0) goto fail;

    *out_tls_key = tls_key;
    *out_cert = cert;
    return LP2P_OK;

fail:
    if (pctx) EVP_PKEY_CTX_free(pctx);
    if (tls_key) EVP_PKEY_free(tls_key);
    if (cert) X509_free(cert);
    return ret;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  TLS peer certificate verification
 * ════════════════════════════════════════════════════════════════════════════ */

lp2p_err_t quic_tls_verify_peer_cert(X509 *cert,
                                      const lp2p_peer_id_t *expected_peer_id,
                                      lp2p_peer_id_t *out_peer_id)
{
    if (!cert || !out_peer_id) return LP2P_ERR_INVALID_ARG;

    /* Verify self-signature */
    EVP_PKEY *cert_pubkey = X509_get0_pubkey(cert);
    if (!cert_pubkey) return LP2P_ERR_HANDSHAKE_FAILED;
    if (X509_verify(cert, cert_pubkey) != 1) return LP2P_ERR_HANDSHAKE_FAILED;

    /* Check validity window */
    time_t now = time(NULL);
    const ASN1_TIME *nb = X509_get0_notBefore(cert);
    const ASN1_TIME *na = X509_get0_notAfter(cert);
    if (X509_cmp_time(nb, &now) > 0) return LP2P_ERR_HANDSHAKE_FAILED;
    if (X509_cmp_time(na, &now) < 0) return LP2P_ERR_HANDSHAKE_FAILED;

    /* Find the libp2p extension */
    ASN1_OBJECT *target_oid = OBJ_txt2obj(LP2P_TLS_EXTENSION_OID, 1);
    if (!target_oid) return LP2P_ERR_INTERNAL;

    int ext_idx = X509_get_ext_by_OBJ(cert, target_oid, -1);
    ASN1_OBJECT_free(target_oid);
    if (ext_idx < 0) return LP2P_ERR_HANDSHAKE_FAILED;

    X509_EXTENSION *ext = X509_get_ext(cert, ext_idx);
    if (!ext) return LP2P_ERR_HANDSHAKE_FAILED;

    ASN1_OCTET_STRING *ext_data = X509_EXTENSION_get_data(ext);
    if (!ext_data) return LP2P_ERR_HANDSHAKE_FAILED;

    const uint8_t *ext_bytes = ASN1_STRING_get0_data(ext_data);
    int ext_len = ASN1_STRING_length(ext_data);
    if (ext_len <= 0) return LP2P_ERR_HANDSHAKE_FAILED;

    /* Decode ASN.1 SignedKey */
    const uint8_t *pb_pubkey = NULL, *sig = NULL;
    size_t pb_pk_len = 0, sig_len = 0;
    if (asn1_decode_signed_key(ext_bytes, (size_t)ext_len,
                                &pb_pubkey, &pb_pk_len,
                                &sig, &sig_len) != 0) {
        return LP2P_ERR_HANDSHAKE_FAILED;
    }

    /* Decode the protobuf public key */
    lp2p_key_type_t key_type;
    const uint8_t *raw_pubkey = NULL;
    size_t raw_pk_len = 0;
    if (pb_decode_public_key(pb_pubkey, pb_pk_len, &key_type,
                              &raw_pubkey, &raw_pk_len) != 0) {
        return LP2P_ERR_HANDSHAKE_FAILED;
    }

    /* Verify signature over cert's SubjectPublicKeyInfo */
    uint8_t *spki_der = NULL;
    int spki_len = i2d_PUBKEY(cert_pubkey, &spki_der);
    if (spki_len <= 0) return LP2P_ERR_HANDSHAKE_FAILED;

    size_t prefix_len = strlen(TLS_SIG_PREFIX);
    size_t tbs_len = prefix_len + (size_t)spki_len;
    uint8_t *tbs = malloc(tbs_len);
    if (!tbs) { OPENSSL_free(spki_der); return LP2P_ERR_NOMEM; }
    memcpy(tbs, TLS_SIG_PREFIX, prefix_len);
    memcpy(tbs + prefix_len, spki_der, (size_t)spki_len);
    OPENSSL_free(spki_der);

    /* Verify based on key type */
    int sig_ok = 0;
    switch (key_type) {
    case LP2P_KEY_ED25519:
        if (raw_pk_len == crypto_sign_PUBLICKEYBYTES && sig_len == crypto_sign_BYTES) {
            sig_ok = (crypto_sign_verify_detached(sig, tbs, tbs_len, raw_pubkey) == 0);
        }
        break;
    case LP2P_KEY_ECDSA: {
        /* ECDSA P-256: raw_pubkey is the DER-encoded public key */
        const uint8_t *p = raw_pubkey;
        EVP_PKEY *ecdsa_key = d2i_PUBKEY(NULL, &p, (long)raw_pk_len);
        if (ecdsa_key) {
            EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
            if (md_ctx) {
                if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, ecdsa_key) == 1 &&
                    EVP_DigestVerify(md_ctx, sig, sig_len, tbs, tbs_len) == 1) {
                    sig_ok = 1;
                }
                EVP_MD_CTX_free(md_ctx);
            }
            EVP_PKEY_free(ecdsa_key);
        }
        break;
    }
    case LP2P_KEY_SECP256K1:
        /* Secp256k1 verification via OpenSSL or external lib — basic support */
        break;
    case LP2P_KEY_RSA: {
        const uint8_t *p = raw_pubkey;
        EVP_PKEY *rsa_key = d2i_PUBKEY(NULL, &p, (long)raw_pk_len);
        if (rsa_key) {
            EVP_MD_CTX *md_ctx = EVP_MD_CTX_new();
            if (md_ctx) {
                if (EVP_DigestVerifyInit(md_ctx, NULL, EVP_sha256(), NULL, rsa_key) == 1 &&
                    EVP_DigestVerify(md_ctx, sig, sig_len, tbs, tbs_len) == 1) {
                    sig_ok = 1;
                }
                EVP_MD_CTX_free(md_ctx);
            }
            EVP_PKEY_free(rsa_key);
        }
        break;
    }
    }
    free(tbs);

    if (!sig_ok) return LP2P_ERR_HANDSHAKE_FAILED;

    /* Derive peer ID from the embedded libp2p public key */
    lp2p_err_t err = lp2p_peer_id_from_public_key(pb_pubkey, pb_pk_len, out_peer_id);
    if (err != LP2P_OK) return err;

    /* If a specific peer was expected, check it matches */
    if (expected_peer_id && expected_peer_id->len > 0) {
        if (!lp2p_peer_id_equal(expected_peer_id, out_peer_id)) {
            return LP2P_ERR_PEER_ID_MISMATCH;
        }
    }

    return LP2P_OK;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  SSL_CTX creation for libp2p QUIC
 * ════════════════════════════════════════════════════════════════════════════ */

static const uint8_t lp2p_alpn[] = { 6, 'l', 'i', 'b', 'p', '2', 'p' };

static int alpn_select_cb(SSL *ssl, const unsigned char **out,
                           unsigned char *outlen,
                           const unsigned char *in, unsigned int inlen,
                           void *arg)
{
    (void)ssl;
    (void)arg;

    if (SSL_select_next_proto((unsigned char **)out, outlen,
                               lp2p_alpn, sizeof(lp2p_alpn),
                               in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }
    return SSL_TLSEXT_ERR_OK;
}

/* Custom verify callback: always accept (we verify the cert ourselves after handshake) */
static int tls_verify_cb(int preverify_ok, X509_STORE_CTX *ctx)
{
    (void)preverify_ok;
    (void)ctx;
    return 1; /* accept all — we do libp2p verification post-handshake */
}

lp2p_err_t quic_tls_create_ssl_ctx(const lp2p_keypair_t *identity_key,
                                    bool is_server,
                                    SSL_CTX **out)
{
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (!ctx) return LP2P_ERR_CRYPTO;

    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    if (is_server) {
        if (ngtcp2_crypto_boringssl_configure_server_context(ctx) != 0) {
            SSL_CTX_free(ctx);
            return LP2P_ERR_CRYPTO;
        }
    } else {
        if (ngtcp2_crypto_boringssl_configure_client_context(ctx) != 0) {
            SSL_CTX_free(ctx);
            return LP2P_ERR_CRYPTO;
        }
    }

    /* Generate cert and key */
    EVP_PKEY *tls_key = NULL;
    X509 *cert = NULL;
    lp2p_err_t err = quic_tls_generate_cert(identity_key, &tls_key, &cert);
    if (err != LP2P_OK) {
        SSL_CTX_free(ctx);
        return err;
    }

    if (SSL_CTX_use_certificate(ctx, cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx, tls_key) != 1) {
        X509_free(cert);
        EVP_PKEY_free(tls_key);
        SSL_CTX_free(ctx);
        return LP2P_ERR_CRYPTO;
    }
    X509_free(cert);
    EVP_PKEY_free(tls_key);

    /* Request client cert (both sides verify) */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, tls_verify_cb);

    /* ALPN */
    if (is_server) {
        SSL_CTX_set_alpn_select_cb(ctx, alpn_select_cb, NULL);
    } else {
        SSL_CTX_set_alpn_protos(ctx, lp2p_alpn, sizeof(lp2p_alpn));
    }

    /* ngtcp2 requires quic method on the SSL_CTX */
    SSL_CTX_set_default_verify_paths(ctx);

    *out = ctx;
    return LP2P_OK;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Random/crypto helpers for ngtcp2
 * ════════════════════════════════════════════════════════════════════════════ */

static void rand_cb(uint8_t *dest, size_t destlen,
                     const ngtcp2_rand_ctx *rand_ctx)
{
    (void)rand_ctx;
    RAND_bytes(dest, (int)destlen);
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid,
                                     uint8_t *token, size_t cidlen,
                                     void *user_data)
{
    (void)conn;
    RAND_bytes(cid->data, (int)cidlen);
    cid->datalen = cidlen;
    RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN);

    quic_conn_t *qc = (quic_conn_t *)user_data;
    if (qc && !quic_conn_track_local_cid(qc, cid)) {
        return NGTCP2_ERR_NOMEM;
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  ngtcp2 stream callbacks
 * ════════════════════════════════════════════════════════════════════════════ */

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags,
                                int64_t stream_id, uint64_t offset,
                                const uint8_t *data, size_t datalen,
                                void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)offset;
    (void)stream_user_data;

    quic_conn_t *qc = (quic_conn_t *)user_data;
    quic_stream_t *qs = quic_conn_find_stream(qc, stream_id);
    if (!qs) {
        qs = quic_conn_create_stream(qc, stream_id);
        if (!qs) return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    /* Append data to stream recv buffer */
    if (datalen > 0) {
        if (!lp2p_buffer_append(&qs->recv_buf, data, datalen)) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
    }

    if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
        qs->fin_received = true;
    }

    quic_stream_maybe_notify(qs);
    quic_stream_deliver_data(qs);

    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
    ngtcp2_conn_extend_max_offset(conn, datalen);

    return 0;
}

static int acked_stream_data_offset_cb(ngtcp2_conn *conn, int64_t stream_id,
                                       uint64_t offset, uint64_t datalen,
                                       void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)stream_user_data;

    quic_conn_t *qc = (quic_conn_t *)user_data;
    quic_stream_t *qs = quic_conn_find_stream(qc, stream_id);
    if (!qs) return 0;

    if (offset != qs->acked_offset) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    uint64_t ack_cursor = offset;
    uint64_t remaining = datalen;

    while (remaining > 0) {
        quic_write_chunk_t *chunk = qs->retained_head;
        size_t sent_len = 0;
        bool retained = true;

        if (chunk) {
            sent_len = chunk->len;
        } else {
            chunk = qs->send_head;
            sent_len = chunk ? chunk->offset : 0;
            retained = false;
        }

        if (!chunk) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (chunk->stream_offset + chunk->acked != ack_cursor) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }
        if (sent_len < chunk->acked) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        size_t available = sent_len - chunk->acked;
        if (available == 0) {
            return NGTCP2_ERR_CALLBACK_FAILURE;
        }

        size_t ackable = available;
        if ((uint64_t)ackable > remaining) {
            ackable = (size_t)remaining;
        }

        chunk->acked += ackable;
        ack_cursor += ackable;
        remaining -= ackable;

        if (retained) {
            while (qs->retained_head &&
                   qs->retained_head->acked == qs->retained_head->len) {
                quic_stream_pop_retained_head(qs);
            }
        }
    }

    qs->acked_offset = ack_cursor;

    while (qs->retained_head &&
           qs->retained_head->len == 0 &&
           qs->retained_head->stream_offset == qs->acked_offset) {
        quic_stream_pop_retained_head(qs);
    }

    return 0;
}

static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
    (void)conn;
    quic_conn_t *qc = (quic_conn_t *)user_data;

    quic_stream_t *qs = quic_conn_create_stream(qc, stream_id);
    if (!qs) return NGTCP2_ERR_CALLBACK_FAILURE;

    quic_stream_maybe_notify(qs);

    return 0;
}

static int stream_close_cb(ngtcp2_conn *conn, uint32_t flags,
                             int64_t stream_id, uint64_t app_error_code,
                             void *user_data, void *stream_user_data)
{
    (void)conn;
    (void)flags;
    (void)app_error_code;
    (void)stream_user_data;

    quic_conn_t *qc = (quic_conn_t *)user_data;

    /* Remove stream from the list */
    quic_stream_t **pp = &qc->streams;
    while (*pp) {
        if ((*pp)->stream_id == stream_id) {
            quic_stream_t *qs = *pp;
            *pp = qs->next;
            if (qs->read_pending) {
                if (qs->reset || app_error_code != NGTCP2_NO_ERROR) {
                    lp2p_stream_read_cb cb = qs->read_cb;
                    void *ud = qs->read_ud;
                    qs->read_pending = false;
                    qs->read_cb = NULL;
                    qs->read_ud = NULL;
                    if (cb) {
                        cb(&qs->pub, LP2P_ERR_STREAM_RESET, NULL, ud);
                    }
                } else {
                    quic_stream_deliver_data(qs);
                }
            }
            if (qs->close_cb) {
                qs->close_cb(&qs->pub, LP2P_OK, qs->close_ud);
            }
            quic_stream_free(qs);
            return 0;
        }
        pp = &(*pp)->next;
    }

    return 0;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
    (void)conn;
    quic_conn_t *qc = (quic_conn_t *)user_data;

    /* Verify remote peer certificate */
    SSL *ssl = qc->ssl;
    X509 *peer_cert = SSL_get_peer_certificate(ssl);
    if (!peer_cert) return NGTCP2_ERR_CALLBACK_FAILURE;

    const lp2p_peer_id_t *expected = qc->has_expected_peer_id ? &qc->expected_peer_id : NULL;
    lp2p_err_t err = quic_tls_verify_peer_cert(peer_cert, expected, &qc->remote_peer_id);
    X509_free(peer_cert);

    if (err != LP2P_OK) return NGTCP2_ERR_CALLBACK_FAILURE;

    qc->peer_id_verified = true;
    qc->state = QUIC_CONN_READY;
    qc->pub_conn->remote_peer = qc->remote_peer_id;
    qc->pub_conn->state = CONN_STATE_READY;

    if (!qc->pub_conn->remote_addr) {
        (void)sockaddr_to_quic_multiaddr(&qc->remote_addr, &qc->remote_peer_id,
                                         &qc->pub_conn->remote_addr);
    }
    if (!qc->pub_conn->local_addr) {
        (void)sockaddr_to_quic_multiaddr(&qc->local_addr, NULL,
                                         &qc->pub_conn->local_addr);
    }

    lp2p_quic_conn_notify_pending_streams(qc->pub_conn);

    /* Notify the callback */
    if (qc->is_server && qc->on_inbound_cb) {
        qc->on_inbound_cb(qc->transport, qc->pub_conn, qc->on_inbound_ud);
    } else if (!qc->is_server && qc->on_conn_cb) {
        qc->on_conn_cb(qc->pub_conn, LP2P_OK, qc->on_conn_ud);
        qc->on_conn_cb = NULL;
    }

    return 0;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  ngtcp2 connection creation helpers
 * ════════════════════════════════════════════════════════════════════════════ */

static ngtcp2_callbacks make_client_callbacks(void)
{
    ngtcp2_callbacks cb;
    memset(&cb, 0, sizeof(cb));

    /* Crypto callbacks provided by ngtcp2_crypto_boringssl */
    cb.client_initial           = ngtcp2_crypto_client_initial_cb;
    cb.recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt                  = ngtcp2_crypto_encrypt_cb;
    cb.decrypt                  = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask                  = ngtcp2_crypto_hp_mask_cb;
    cb.recv_retry               = ngtcp2_crypto_recv_retry_cb;
    cb.update_key               = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.get_path_challenge_data  = ngtcp2_crypto_get_path_challenge_data_cb;
    cb.version_negotiation      = ngtcp2_crypto_version_negotiation_cb;

    /* Application callbacks */
    cb.recv_stream_data        = recv_stream_data_cb;
    cb.acked_stream_data_offset = acked_stream_data_offset_cb;
    cb.stream_open             = stream_open_cb;
    cb.stream_close            = stream_close_cb;
    cb.rand                    = rand_cb;
    cb.get_new_connection_id   = get_new_connection_id_cb;
    cb.handshake_completed     = handshake_completed_cb;

    return cb;
}

static ngtcp2_callbacks make_server_callbacks(void)
{
    ngtcp2_callbacks cb;
    memset(&cb, 0, sizeof(cb));

    cb.recv_client_initial      = ngtcp2_crypto_recv_client_initial_cb;
    cb.recv_crypto_data         = ngtcp2_crypto_recv_crypto_data_cb;
    cb.encrypt                  = ngtcp2_crypto_encrypt_cb;
    cb.decrypt                  = ngtcp2_crypto_decrypt_cb;
    cb.hp_mask                  = ngtcp2_crypto_hp_mask_cb;
    cb.update_key               = ngtcp2_crypto_update_key_cb;
    cb.delete_crypto_aead_ctx   = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    cb.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;
    cb.get_path_challenge_data  = ngtcp2_crypto_get_path_challenge_data_cb;
    cb.version_negotiation      = ngtcp2_crypto_version_negotiation_cb;

    cb.recv_stream_data        = recv_stream_data_cb;
    cb.acked_stream_data_offset = acked_stream_data_offset_cb;
    cb.stream_open             = stream_open_cb;
    cb.stream_close            = stream_close_cb;
    cb.rand                    = rand_cb;
    cb.get_new_connection_id   = get_new_connection_id_cb;
    cb.handshake_completed     = handshake_completed_cb;

    return cb;
}

static ngtcp2_settings make_settings(void)
{
    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = quic_now();
    settings.max_tx_udp_payload_size = QUIC_MAX_PKTLEN;
    return settings;
}

static ngtcp2_transport_params make_transport_params(bool is_server)
{
    ngtcp2_transport_params params;
    ngtcp2_transport_params_default(&params);
    params.initial_max_streams_bidi = 128;
    params.initial_max_streams_uni = 0;
    params.initial_max_stream_data_bidi_local = 256 * 1024;
    params.initial_max_stream_data_bidi_remote = 256 * 1024;
    params.initial_max_data = 1024 * 1024;
    if (is_server) {
        RAND_bytes(params.original_dcid.data, QUIC_SCID_LEN);
        params.original_dcid.datalen = QUIC_SCID_LEN;
        params.original_dcid_present = 1;
    }
    return params;
}

static void quic_conn_remove(quic_conn_t *qc)
{
    if (!qc || !qc->transport) return;

    quic_conn_t **pp = &qc->transport->conns;
    while (*pp) {
        if (*pp == qc) {
            *pp = qc->next;
            qc->next = NULL;
            return;
        }
        pp = &(*pp)->next;
    }
}

static bool quic_conn_track_local_cid(quic_conn_t *qc, const ngtcp2_cid *cid)
{
    if (!qc || !cid || cid->datalen == 0) return false;

    for (quic_local_cid_t *it = qc->local_cids; it; it = it->next) {
        if (it->cid.datalen == cid->datalen &&
            memcmp(it->cid.data, cid->data, cid->datalen) == 0) {
            return true;
        }
    }

    quic_local_cid_t *entry = calloc(1, sizeof(*entry));
    if (!entry) return false;

    memcpy(&entry->cid, cid, sizeof(*cid));
    entry->next = qc->local_cids;
    qc->local_cids = entry;
    return true;
}

static bool quic_conn_matches_local_cid(const quic_conn_t *qc,
                                        const uint8_t *data, size_t datalen)
{
    if (!qc || !data || datalen == 0) return false;

    ngtcp2_version_cid vc;
    if (ngtcp2_pkt_decode_version_cid(&vc, data, datalen, QUIC_SCID_LEN) != 0) {
        return false;
    }

    for (const quic_local_cid_t *it = qc->local_cids; it; it = it->next) {
        if (it->cid.datalen == vc.dcidlen &&
            memcmp(it->cid.data, vc.dcid, vc.dcidlen) == 0) {
            return true;
        }
    }

    return false;
}

static bool sockaddr_to_quic_multiaddr(const struct sockaddr_storage *addr,
                                       const lp2p_peer_id_t *peer_id,
                                       lp2p_multiaddr_t **out)
{
    if (!addr || !out) return false;

    char ip[INET6_ADDRSTRLEN];
    uint16_t port = 0;
    const char *proto = NULL;

    if (addr->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        if (uv_inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip)) != 0) {
            return false;
        }
        port = ntohs(sin->sin_port);
        proto = "ip4";
    } else if (addr->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        if (uv_inet_ntop(AF_INET6, &sin6->sin6_addr, ip, sizeof(ip)) != 0) {
            return false;
        }
        port = ntohs(sin6->sin6_port);
        proto = "ip6";
    } else {
        return false;
    }

    char ma_str[512];
    if (peer_id && peer_id->len > 0) {
        char peer[128];
        size_t peer_len = sizeof(peer);
        if (lp2p_peer_id_to_string(peer_id, peer, &peer_len) != LP2P_OK) {
            return false;
        }
        snprintf(ma_str, sizeof(ma_str), "/%s/%s/udp/%u/quic-v1/p2p/%s",
                 proto, ip, port, peer);
    } else {
        snprintf(ma_str, sizeof(ma_str), "/%s/%s/udp/%u/quic-v1",
                 proto, ip, port);
    }

    return lp2p_multiaddr_parse(ma_str, out) == LP2P_OK;
}

static void quic_stream_free(quic_stream_t *qs)
{
    if (!qs) return;

    free(qs->pub.protocol_id);
    lp2p_buffer_free(&qs->recv_buf);

    quic_write_chunk_list_free(qs->send_head);
    quic_write_chunk_list_free(qs->retained_head);

    free(qs);
}

static ngtcp2_conn *quic_crypto_get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
    if (!conn_ref || !conn_ref->user_data) return NULL;
    return ((quic_conn_t *)conn_ref->user_data)->conn;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Stream management
 * ════════════════════════════════════════════════════════════════════════════ */

static quic_stream_t *quic_conn_find_stream(quic_conn_t *qc, int64_t stream_id)
{
    for (quic_stream_t *qs = qc->streams; qs; qs = qs->next) {
        if (qs->stream_id == stream_id) return qs;
    }
    return NULL;
}

static quic_stream_t *quic_conn_create_stream(quic_conn_t *qc, int64_t stream_id)
{
    quic_stream_t *qs = calloc(1, sizeof(*qs));
    if (!qs) return NULL;
    lp2p_buffer_init(&qs->recv_buf);
    qs->stream_id = stream_id;
    qs->qconn = qc;
    qs->pub.conn = qc->pub_conn;
    qs->next = qc->streams;
    qc->streams = qs;
    return qs;
}

static bool quic_stream_is_remote_initiated(const quic_conn_t *qc, int64_t stream_id)
{
    /* Bidirectional stream IDs:
     *   client-initiated: 0 mod 4
     *   server-initiated: 1 mod 4
     */
    int64_t kind = stream_id & 0x3;
    if (kind != 0 && kind != 1) {
        return false;
    }

    return qc->is_server ? (kind == 0) : (kind == 1);
}

static void quic_stream_consume_recv(quic_stream_t *qs, size_t n)
{
    if (n >= qs->recv_buf.len) {
        qs->recv_buf.len = 0;
        return;
    }

    memmove(qs->recv_buf.data, qs->recv_buf.data + n, qs->recv_buf.len - n);
    qs->recv_buf.len -= n;
}

static void quic_stream_deliver_eof(quic_stream_t *qs)
{
    lp2p_stream_read_cb cb = qs->read_cb;
    void *ud = qs->read_ud;

    qs->read_pending = false;
    qs->read_cb = NULL;
    qs->read_ud = NULL;

    if (cb) {
        cb(&qs->pub, LP2P_ERR_EOF, NULL, ud);
    }
}

static void quic_stream_deliver_data(quic_stream_t *qs)
{
    if (!qs || !qs->read_pending) return;

    if (qs->reset) {
        lp2p_stream_read_cb cb = qs->read_cb;
        void *ud = qs->read_ud;
        qs->read_pending = false;
        qs->read_cb = NULL;
        qs->read_ud = NULL;
        if (cb) {
            cb(&qs->pub, LP2P_ERR_STREAM_RESET, NULL, ud);
        }
        return;
    }

    if (qs->read_lp) {
        uint64_t frame_len = 0;
        size_t varint_len = lp2p_varint_decode(qs->recv_buf.data, qs->recv_buf.len, &frame_len);
        if (varint_len == 0) {
            if (qs->fin_received && qs->recv_buf.len == 0) {
                quic_stream_deliver_eof(qs);
            }
            return;
        }

        if (frame_len > qs->read_max) {
            lp2p_stream_read_cb cb = qs->read_cb;
            void *ud = qs->read_ud;
            qs->read_pending = false;
            qs->read_cb = NULL;
            qs->read_ud = NULL;
            if (cb) {
                cb(&qs->pub, LP2P_ERR_PROTOCOL, NULL, ud);
            }
            return;
        }

        size_t total = varint_len + (size_t)frame_len;
        if (qs->recv_buf.len < total) {
            if (qs->fin_received && qs->recv_buf.len == 0) {
                quic_stream_deliver_eof(qs);
            }
            return;
        }

        lp2p_stream_read_cb cb = qs->read_cb;
        void *ud = qs->read_ud;
        uint8_t *copy = NULL;
        lp2p_buf_t buf = { .len = (size_t)frame_len };

        if (buf.len > 0) {
            copy = malloc(buf.len);
            if (!copy) {
                cb(&qs->pub, LP2P_ERR_NOMEM, NULL, ud);
                qs->read_pending = false;
                qs->read_cb = NULL;
                qs->read_ud = NULL;
                return;
            }
            memcpy(copy, qs->recv_buf.data + varint_len, buf.len);
        }
        buf.data = copy;

        qs->read_pending = false;
        qs->read_cb = NULL;
        qs->read_ud = NULL;
        quic_stream_consume_recv(qs, total);
        if (cb) {
            cb(&qs->pub, LP2P_OK, &buf, ud);
        }
        free(copy);
        return;
    }

    if (qs->recv_buf.len > 0) {
        size_t n = qs->recv_buf.len < qs->read_max ? qs->recv_buf.len : qs->read_max;
        lp2p_stream_read_cb cb = qs->read_cb;
        void *ud = qs->read_ud;
        uint8_t *copy = malloc(n);
        if (!copy) {
            qs->read_pending = false;
            qs->read_cb = NULL;
            qs->read_ud = NULL;
            if (cb) {
                cb(&qs->pub, LP2P_ERR_NOMEM, NULL, ud);
            }
            return;
        }
        memcpy(copy, qs->recv_buf.data, n);
        lp2p_buf_t buf = { .data = copy, .len = n };

        qs->read_pending = false;
        qs->read_cb = NULL;
        qs->read_ud = NULL;
        quic_stream_consume_recv(qs, n);
        if (cb) {
            cb(&qs->pub, LP2P_OK, &buf, ud);
        }
        free(copy);
        return;
    }

    if (qs->fin_received) {
        quic_stream_deliver_eof(qs);
    }
}

static void quic_stream_maybe_notify(quic_stream_t *qs)
{
    if (!qs || qs->inbound_notified) return;
    if (!qs->qconn || !qs->qconn->pub_conn) return;
    if (!quic_stream_is_remote_initiated(qs->qconn, qs->stream_id)) return;

    lp2p_conn_t *conn = qs->qconn->pub_conn;
    if (conn->state != CONN_STATE_READY || !conn->router) return;

    qs->inbound_notified = true;
    lp2p_conn_handle_inbound_stream(conn, &qs->pub);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Packet I/O: writing packets out via libuv UDP
 * ════════════════════════════════════════════════════════════════════════════ */

typedef struct {
    uv_udp_send_t req;
    uint8_t       data[];
} udp_send_ctx_t;

static void udp_send_cb(uv_udp_send_t *req, int status)
{
    (void)status;
    udp_send_ctx_t *ctx = (udp_send_ctx_t *)req;
    free(ctx);
}

static bool quic_send_packet(quic_conn_t *qc, const uint8_t *data, size_t len)
{
    if (!qc || !qc->transport || !qc->transport->udp_initialized || len == 0) {
        return false;
    }

    udp_send_ctx_t *ctx = malloc(sizeof(*ctx) + len);
    if (!ctx) return false;

    memcpy(ctx->data, data, len);

    uv_buf_t buf = uv_buf_init((char *)ctx->data, (unsigned int)len);
    const struct sockaddr *dest = (const struct sockaddr *)&qc->remote_addr;
    int r = uv_udp_send(&ctx->req, &qc->transport->udp_server, &buf, 1, dest, udp_send_cb);
    if (r != 0) {
        free(ctx);
        return false;
    }

    return true;
}

static void quic_transport_maybe_close_udp(quic_transport_t *qt)
{
    if (!qt || !qt->udp_initialized || qt->listening || qt->conns) {
        return;
    }

    uv_udp_recv_stop(&qt->udp_server);
    if (!uv_is_closing((uv_handle_t *)&qt->udp_server)) {
        uv_close((uv_handle_t *)&qt->udp_server, udp_close_cb);
    }
    qt->udp_initialized = false;
}

static void quic_conn_write_packets(quic_conn_t *qc)
{
    if (!qc->conn || qc->state == QUIC_CONN_CLOSED) return;

    ngtcp2_path_storage ps;
    ngtcp2_path_storage_zero(&ps);

    ngtcp2_pkt_info pi;
    ngtcp2_tstamp ts = quic_now();

    for (;;) {
        int64_t stream_id = -1;
        const uint8_t *data = NULL;
        size_t data_len = 0;
        uint32_t flags = 0;
        quic_stream_t *send_stream = NULL;
        quic_write_chunk_t *chunk = NULL;

        for (quic_stream_t *qs = qc->streams; qs; qs = qs->next) {
            if (!qs->send_head) continue;
            send_stream = qs;
            chunk = qs->send_head;
            stream_id = qs->stream_id;
            data = chunk->data ? chunk->data + chunk->offset : NULL;
            data_len = chunk->len - chunk->offset;
            if (chunk->fin) {
                flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
            }
            break;
        }

        ngtcp2_ssize pdatalen = -1;
        ngtcp2_ssize nwrite = ngtcp2_conn_write_stream(
            qc->conn, &ps.path, &pi,
            qc->send_buf, sizeof(qc->send_buf),
            &pdatalen,
            flags,
            stream_id, data, data_len, ts);

        if (nwrite < 0) {
            if (nwrite == NGTCP2_ERR_WRITE_MORE) continue;
            if (nwrite == NGTCP2_ERR_STREAM_DATA_BLOCKED ||
                nwrite == NGTCP2_ERR_STREAM_SHUT_WR ||
                nwrite == NGTCP2_ERR_STREAM_NOT_FOUND) {
                break;
            }
            break;
        }
        if (nwrite == 0) break;

        if (send_stream && chunk && pdatalen >= 0) {
            chunk->offset += (size_t)pdatalen;
            if (chunk->offset >= chunk->len) {
                send_stream->send_head = chunk->next;
                if (!send_stream->send_head) {
                    send_stream->send_tail = NULL;
                }
                if (chunk->acked == chunk->len) {
                    quic_write_chunk_free(chunk);
                } else {
                    quic_stream_append_retained_chunk(send_stream, chunk);
                    if (chunk->fin) {
                        send_stream->fin_sent = true;
                    }
                }
            }
        }

        if (!quic_send_packet(qc, qc->send_buf, (size_t)nwrite)) {
            break;
        }
    }

    quic_conn_schedule_timer(qc);
}

lp2p_err_t lp2p_quic_conn_open_stream_raw(lp2p_conn_t *conn, lp2p_stream_t **out)
{
    if (!conn || !out) return LP2P_ERR_INVALID_ARG;
    if (conn->backend != LP2P_CONN_BACKEND_QUIC || !conn->backend_impl) {
        return LP2P_ERR_INVALID_ARG;
    }
    if (conn->state != CONN_STATE_READY) {
        return LP2P_ERR_BUSY;
    }

    quic_conn_t *qc = (quic_conn_t *)conn->backend_impl;
    int64_t stream_id = -1;
    int rv = ngtcp2_conn_open_bidi_stream(qc->conn, &stream_id, NULL);
    if (rv != 0) {
        return rv == NGTCP2_ERR_STREAM_ID_BLOCKED ? LP2P_ERR_WOULD_BLOCK : LP2P_ERR_TRANSPORT;
    }

    quic_stream_t *qs = quic_conn_create_stream(qc, stream_id);
    if (!qs) {
        ngtcp2_conn_shutdown_stream(qc->conn, 0, stream_id, QUIC_APP_ERR_RESET);
        quic_conn_write_packets(qc);
        return LP2P_ERR_NOMEM;
    }

    *out = &qs->pub;
    return LP2P_OK;
}

void lp2p_quic_conn_notify_pending_streams(lp2p_conn_t *conn)
{
    if (!conn || conn->backend != LP2P_CONN_BACKEND_QUIC || !conn->backend_impl) {
        return;
    }

    quic_conn_t *qc = (quic_conn_t *)conn->backend_impl;
    for (quic_stream_t *qs = qc->streams; qs; qs = qs->next) {
        quic_stream_maybe_notify(qs);
    }

    if (conn->state != CONN_STATE_READY) {
        return;
    }

    while (!lp2p_list_empty(&conn->pending_streams)) {
        lp2p_list_node_t *n = lp2p_list_pop_front(&conn->pending_streams);
        conn_open_stream_req_t *req = lp2p_container_of(n, conn_open_stream_req_t, node);

        lp2p_err_t err = lp2p_conn_open_stream(conn, req->protocol_id, req->cb, req->userdata);
        if (err != LP2P_OK && req->cb) {
            req->cb(NULL, err, req->userdata);
        }

        free(req->protocol_id);
        free(req);
    }
}

lp2p_err_t lp2p_quic_stream_read(lp2p_stream_t *stream, size_t max_bytes,
                                  lp2p_stream_read_cb cb, void *userdata)
{
    if (!stream || !cb) return LP2P_ERR_INVALID_ARG;

    quic_stream_t *qs = (quic_stream_t *)stream;
    if (qs->reset) return LP2P_ERR_STREAM_RESET;
    if (qs->read_pending) return LP2P_ERR_BUSY;

    if (qs->fin_received && qs->recv_buf.len == 0) {
        cb(stream, LP2P_ERR_EOF, NULL, userdata);
        return LP2P_OK;
    }

    qs->read_pending = true;
    qs->read_lp = false;
    qs->read_max = max_bytes;
    qs->read_cb = cb;
    qs->read_ud = userdata;
    quic_stream_deliver_data(qs);
    return LP2P_OK;
}

lp2p_err_t lp2p_quic_stream_read_lp(lp2p_stream_t *stream, size_t max_frame_len,
                                     lp2p_stream_read_cb cb, void *userdata)
{
    if (!stream || !cb) return LP2P_ERR_INVALID_ARG;

    quic_stream_t *qs = (quic_stream_t *)stream;
    if (qs->reset) return LP2P_ERR_STREAM_RESET;
    if (qs->read_pending) return LP2P_ERR_BUSY;

    if (qs->fin_received && qs->recv_buf.len == 0) {
        cb(stream, LP2P_ERR_EOF, NULL, userdata);
        return LP2P_OK;
    }

    qs->read_pending = true;
    qs->read_lp = true;
    qs->read_max = max_frame_len;
    qs->read_cb = cb;
    qs->read_ud = userdata;
    quic_stream_deliver_data(qs);
    return LP2P_OK;
}

lp2p_err_t lp2p_quic_stream_write(lp2p_stream_t *stream, const lp2p_buf_t *buf,
                                   lp2p_stream_write_cb cb, void *userdata)
{
    if (!stream || !buf || !buf->data) return LP2P_ERR_INVALID_ARG;

    quic_stream_t *qs = (quic_stream_t *)stream;
    quic_conn_t *qc = qs->qconn;
    if (!qc || !qc->conn || qc->state == QUIC_CONN_CLOSED || qs->reset || qs->fin_sent) {
        return LP2P_ERR_CONNECTION_CLOSED;
    }

    quic_write_chunk_t *new_head = NULL;
    quic_write_chunk_t *new_tail = NULL;
    uint64_t next_offset = qs->next_send_offset;
    size_t pos = 0;

    while (pos < buf->len) {
        size_t chunk_len = buf->len - pos;
        if (chunk_len > QUIC_WRITE_CHUNK_SIZE) {
            chunk_len = QUIC_WRITE_CHUNK_SIZE;
        }

        quic_write_chunk_t *chunk = calloc(1, sizeof(*chunk));
        if (!chunk) {
            quic_write_chunk_list_free(new_head);
            return LP2P_ERR_NOMEM;
        }

        chunk->data = malloc(chunk_len);
        if (!chunk->data) {
            quic_write_chunk_free(chunk);
            quic_write_chunk_list_free(new_head);
            return LP2P_ERR_NOMEM;
        }

        memcpy(chunk->data, buf->data + pos, chunk_len);
        chunk->len = chunk_len;
        chunk->stream_offset = next_offset;

        if (new_tail) {
            new_tail->next = chunk;
        } else {
            new_head = chunk;
        }
        new_tail = chunk;

        next_offset += chunk_len;
        pos += chunk_len;
    }

    if (!new_head) return LP2P_ERR_INVALID_ARG;

    if (qs->send_tail) {
        qs->send_tail->next = new_head;
    } else {
        qs->send_head = new_head;
    }
    qs->send_tail = new_tail;
    qs->next_send_offset = next_offset;

    quic_conn_write_packets(qc);
    if (cb) cb(stream, LP2P_OK, userdata);
    return LP2P_OK;
}

static lp2p_err_t quic_stream_close_now(lp2p_stream_t *stream, lp2p_stream_write_cb cb,
                                        void *userdata)
{
    if (!stream) return LP2P_ERR_INVALID_ARG;

    quic_stream_t *qs = (quic_stream_t *)stream;
    quic_conn_t *qc = qs->qconn;
    if (!qc || !qc->conn || qc->state == QUIC_CONN_CLOSED || qs->reset) {
        return LP2P_ERR_CONNECTION_CLOSED;
    }
    if (qs->fin_sent) {
        if (cb) cb(stream, LP2P_OK, userdata);
        return LP2P_OK;
    }

    quic_write_chunk_t *chunk = calloc(1, sizeof(*chunk));
    if (!chunk) return LP2P_ERR_NOMEM;
    chunk->fin = true;
    chunk->stream_offset = qs->next_send_offset;
    qs->fin_sent = true;

    quic_stream_append_send_chunk(qs, chunk);

    quic_conn_write_packets(qc);
    if (cb) cb(stream, LP2P_OK, userdata);
    return LP2P_OK;
}

static lp2p_err_t quic_stream_reset_now(lp2p_stream_t *stream)
{
    if (!stream) return LP2P_ERR_INVALID_ARG;

    quic_stream_t *qs = (quic_stream_t *)stream;
    quic_conn_t *qc = qs->qconn;
    if (!qc || !qc->conn) return LP2P_ERR_INVALID_ARG;
    if (qs->reset) return LP2P_OK;

    qs->reset = true;
    qs->fin_sent = true;
    (void)ngtcp2_conn_shutdown_stream(qc->conn, 0, qs->stream_id, QUIC_APP_ERR_RESET);
    quic_conn_write_packets(qc);
    quic_stream_deliver_data(qs);
    return LP2P_OK;
}

lp2p_err_t lp2p_quic_stream_close(lp2p_stream_t *stream, lp2p_stream_write_cb cb,
                                   void *userdata)
{
    return quic_stream_schedule_action(stream, QUIC_STREAM_ACTION_CLOSE, cb, userdata);
}

lp2p_err_t lp2p_quic_stream_reset(lp2p_stream_t *stream)
{
    return quic_stream_schedule_action(stream, QUIC_STREAM_ACTION_RESET, NULL, NULL);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Timer management for ngtcp2 expiry
 * ════════════════════════════════════════════════════════════════════════════ */

static void timer_cb(uv_timer_t *handle)
{
    quic_conn_t *qc = (quic_conn_t *)handle->data;
    if (!qc->conn) return;

    ngtcp2_tstamp now = quic_now();
    int rv = ngtcp2_conn_handle_expiry(qc->conn, now);
    if (rv != 0) {
        /* Connection timed out or fatal error */
        if (!qc->is_server && qc->on_conn_cb) {
            void (*cb)(lp2p_conn_t *, lp2p_err_t, void *) = qc->on_conn_cb;
            void *ud = qc->on_conn_ud;
            qc->on_conn_cb = NULL;
            qc->state = QUIC_CONN_CLOSED;
            cb(NULL, LP2P_ERR_TIMEOUT, ud);
            if (qc->pub_conn) {
                lp2p_conn_destroy(qc->pub_conn);
            }
            return;
        }

        if (qc->pub_conn) {
            lp2p_conn_t *conn = qc->pub_conn;
            void (*on_disconnect)(lp2p_conn_t *, lp2p_err_t, void *) = conn->on_disconnect;
            void *disconnect_ud = conn->cb_userdata;
            void (*close_cb)(lp2p_conn_t *, void *) = conn->close_cb.cb;
            void *close_ud = conn->close_cb.userdata;

            conn->on_disconnect = NULL;
            conn->close_cb.cb = NULL;
            conn->close_cb.userdata = NULL;
            conn->closing = true;
            conn->state = CONN_STATE_CLOSED;
            qc->state = QUIC_CONN_CLOSED;

            if (on_disconnect) {
                on_disconnect(conn, LP2P_ERR_TIMEOUT, disconnect_ud);
            }
            if (close_cb) {
                close_cb(conn, close_ud);
            }
            return;
        }

        qc->state = QUIC_CONN_CLOSED;
        return;
    }

    quic_conn_write_packets(qc);
}

static void quic_conn_schedule_timer(quic_conn_t *qc)
{
    if (!qc->conn) return;

    ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(qc->conn);
    ngtcp2_tstamp now = quic_now();

    if (expiry == UINT64_MAX) {
        uv_timer_stop(&qc->timer);
        return;
    }

    uint64_t timeout_ns = (expiry > now) ? (expiry - now) : 0;
    uint64_t timeout_ms = timeout_ns / 1000000ULL;
    if (timeout_ms == 0 && timeout_ns > 0) timeout_ms = 1;

    uv_timer_start(&qc->timer, timer_cb, timeout_ms, 0);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  UDP receive callback — dispatch to appropriate quic_conn_t
 * ════════════════════════════════════════════════════════════════════════════ */

static quic_conn_t *find_conn_by_dcid(quic_transport_t *qt,
                                       const uint8_t *data, size_t datalen)
{
    for (quic_conn_t *qc = qt->conns; qc; qc = qc->next) {
        if (quic_conn_matches_local_cid(qc, data, datalen)) {
            return qc;
        }
    }
    return NULL;
}

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    (void)handle;
    (void)suggested_size;
    buf->base = malloc(65536);
    buf->len = buf->base ? 65536 : 0;
}

static void udp_recv_cb(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                          const struct sockaddr *addr, unsigned flags)
{
    quic_transport_t *qt = (quic_transport_t *)handle->data;
    (void)flags;

    if (nread <= 0 || !addr) {
        free(buf->base);
        return;
    }

    /* Try to find an existing connection by DCID */
    quic_conn_t *qc = find_conn_by_dcid(qt, (const uint8_t *)buf->base, (size_t)nread);

    if (!qc && qt->listening) {
        /* New incoming connection: create a server-side quic_conn_t */
        qc = calloc(1, sizeof(*qc));
        if (!qc) { free(buf->base); return; }

        qc->transport = qt;
        qc->is_server = true;
        qc->state = QUIC_CONN_HANDSHAKING;
        qc->on_inbound_cb = qt->on_conn;
        qc->on_inbound_ud = qt->on_conn_ud;

        qc->pub_conn = lp2p_conn_new(qt->loop, true, NULL);
        if (!qc->pub_conn) {
            free(qc);
            free(buf->base);
            return;
        }
        qc->pub_conn->backend = LP2P_CONN_BACKEND_QUIC;
        qc->pub_conn->backend_impl = qc;

        memcpy(&qc->remote_addr, addr, sockaddr_len((const struct sockaddr_storage *)addr));

        /* Get local address */
        int namelen = sizeof(qc->local_addr);
        uv_udp_getsockname(&qt->udp_server, (struct sockaddr *)&qc->local_addr, &namelen);

        /* Generate SCID */
        RAND_bytes(qc->scid.data, QUIC_SCID_LEN);
        qc->scid.datalen = QUIC_SCID_LEN;
        if (!quic_conn_track_local_cid(qc, &qc->scid)) {
            lp2p_conn_destroy(qc->pub_conn);
            free(buf->base);
            return;
        }

        /* Extract DCID from the incoming initial packet */
        ngtcp2_version_cid vc;
        if (ngtcp2_pkt_decode_version_cid(&vc, (const uint8_t *)buf->base,
                                           (size_t)nread, QUIC_SCID_LEN) != 0) {
            lp2p_conn_destroy(qc->pub_conn);
            free(buf->base);
            return;
        }
        memcpy(qc->dcid.data, vc.scid, vc.scidlen);
        qc->dcid.datalen = vc.scidlen;

        /* Create SSL context and SSL object */
        lp2p_err_t err = quic_tls_create_ssl_ctx(qt->keypair, true, &qc->ssl_ctx);
        if (err != LP2P_OK) {
            lp2p_conn_destroy(qc->pub_conn);
            free(buf->base);
            return;
        }

        qc->ssl = SSL_new(qc->ssl_ctx);
        if (!qc->ssl) {
            SSL_CTX_free(qc->ssl_ctx);
            qc->ssl_ctx = NULL;
            lp2p_conn_destroy(qc->pub_conn);
            free(buf->base);
            return;
        }
        qc->conn_ref.get_conn = quic_crypto_get_conn;
        qc->conn_ref.user_data = qc;
        SSL_set_app_data(qc->ssl, &qc->conn_ref);
        SSL_set_accept_state(qc->ssl);

        /* Set up ngtcp2 connection */
        ngtcp2_path path;
        memset(&path, 0, sizeof(path));
        path.local.addr = (struct sockaddr *)&qc->local_addr;
        path.local.addrlen = sockaddr_len(&qc->local_addr);
        path.remote.addr = (struct sockaddr *)&qc->remote_addr;
        path.remote.addrlen = sockaddr_len(&qc->remote_addr);

        ngtcp2_callbacks callbacks = make_server_callbacks();
        ngtcp2_settings settings = make_settings();
        ngtcp2_transport_params params = make_transport_params(true);

        /* Copy the original DCID from the client's initial packet */
        memcpy(params.original_dcid.data, vc.dcid, vc.dcidlen);
        params.original_dcid.datalen = vc.dcidlen;

        ngtcp2_conn *conn = NULL;
        int rv = ngtcp2_conn_server_new(&conn, &qc->dcid, &qc->scid,
                                         &path, vc.version,
                                         &callbacks, &settings, &params,
                                         NULL, qc);
        if (rv != 0) {
            SSL_free(qc->ssl);
            SSL_CTX_free(qc->ssl_ctx);
            qc->ssl = NULL;
            qc->ssl_ctx = NULL;
            lp2p_conn_destroy(qc->pub_conn);
            free(buf->base);
            return;
        }
        qc->conn = conn;

        ngtcp2_conn_set_tls_native_handle(conn, qc->ssl);

        /* Initialize timer */
        uv_timer_init(qt->loop, &qc->timer);
        qc->timer.data = qc;
        qc->timer_initialized = true;

        /* Add to transport's connection list */
        qc->next = qt->conns;
        qt->conns = qc;
    }

    if (qc) {
        /* Feed data to ngtcp2 */
        ngtcp2_path path;
        memset(&path, 0, sizeof(path));
        path.local.addr = (struct sockaddr *)&qc->local_addr;
        path.local.addrlen = sockaddr_len(&qc->local_addr);
        path.remote.addr = (struct sockaddr *)addr;
        path.remote.addrlen = sockaddr_len((const struct sockaddr_storage *)addr);

        ngtcp2_pkt_info pi;
        memset(&pi, 0, sizeof(pi));

        ngtcp2_tstamp ts = quic_now();
        int rv = ngtcp2_conn_read_pkt(qc->conn, &path, &pi,
                                       (const uint8_t *)buf->base, (size_t)nread, ts);
        if (rv != 0 && rv != NGTCP2_ERR_DRAINING) {
            /* Connection error */
            if (!qc->is_server && qc->on_conn_cb) {
                void (*cb)(lp2p_conn_t *, lp2p_err_t, void *) = qc->on_conn_cb;
                void *ud = qc->on_conn_ud;
                qc->on_conn_cb = NULL;
                qc->state = QUIC_CONN_CLOSED;
                cb(NULL, LP2P_ERR_HANDSHAKE_FAILED, ud);
                if (qc->pub_conn) {
                    lp2p_conn_destroy(qc->pub_conn);
                }
            } else if (qc->pub_conn && qc->pub_conn->state != CONN_STATE_READY) {
                qc->state = QUIC_CONN_CLOSED;
                lp2p_conn_destroy(qc->pub_conn);
            }
            free(buf->base);
            return;
        }

        /* Write any response packets */
        quic_conn_write_packets(qc);
    }

    free(buf->base);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Transport vtable: handles
 * ════════════════════════════════════════════════════════════════════════════ */

static bool quic_handles(void *transport, const lp2p_multiaddr_t *addr)
{
    (void)transport;
    const char *s = lp2p_multiaddr_string(addr);
    if (!s) return false;

    /* Match /ip4/.../udp/.../quic-v1 or /ip6/.../udp/.../quic-v1 */
    if ((strncmp(s, "/ip4/", 5) == 0 || strncmp(s, "/ip6/", 5) == 0) &&
        strstr(s, "/udp/") != NULL &&
        strstr(s, "/quic-v1") != NULL) {
        return true;
    }
    return false;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Transport vtable: listen
 * ════════════════════════════════════════════════════════════════════════════ */

static lp2p_err_t quic_listen(void *transport, const lp2p_multiaddr_t *addr,
                               void (*on_conn)(void *transport, lp2p_conn_t *conn,
                                               void *userdata),
                               void *userdata)
{
    quic_transport_t *qt = (quic_transport_t *)transport;

    if (qt->listening) return LP2P_ERR_BUSY;
    if (qt->udp_initialized) return LP2P_ERR_BUSY;

    const char *ma_str = lp2p_multiaddr_string(addr);
    if (!ma_str) return LP2P_ERR_INVALID_MULTIADDR;

    bool is_ipv6;
    if (parse_quic_multiaddr(ma_str, &qt->listen_addr, &is_ipv6) != 0) {
        return LP2P_ERR_INVALID_MULTIADDR;
    }

    /* Initialize UDP socket */
    int rv = uv_udp_init(qt->loop, &qt->udp_server);
    if (rv != 0) return LP2P_ERR_TRANSPORT;
    qt->udp_initialized = true;
    qt->udp_server.data = qt;

    unsigned int bind_flags = is_ipv6 ? UV_UDP_IPV6ONLY : 0;
    rv = uv_udp_bind(&qt->udp_server, (const struct sockaddr *)&qt->listen_addr, bind_flags);
    if (rv != 0) {
        uv_close((uv_handle_t *)&qt->udp_server, udp_close_cb);
        qt->udp_initialized = false;
        return LP2P_ERR_TRANSPORT;
    }

    /* Start receiving UDP packets */
    rv = uv_udp_recv_start(&qt->udp_server, alloc_cb, udp_recv_cb);
    if (rv != 0) {
        uv_close((uv_handle_t *)&qt->udp_server, udp_close_cb);
        qt->udp_initialized = false;
        return LP2P_ERR_TRANSPORT;
    }

    qt->on_conn = on_conn;
    qt->on_conn_ud = userdata;
    qt->listening = true;

    return LP2P_OK;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Transport vtable: dial
 * ════════════════════════════════════════════════════════════════════════════ */

static lp2p_err_t quic_dial(void *transport, const lp2p_multiaddr_t *addr,
                              void (*on_conn)(lp2p_conn_t *conn, lp2p_err_t err, void *userdata),
                              void *userdata)
{
    quic_transport_t *qt = (quic_transport_t *)transport;

    const char *ma_str = lp2p_multiaddr_string(addr);
    if (!ma_str) return LP2P_ERR_INVALID_MULTIADDR;

    struct sockaddr_storage remote;
    bool is_ipv6;
    if (parse_quic_multiaddr(ma_str, &remote, &is_ipv6) != 0) {
        return LP2P_ERR_INVALID_MULTIADDR;
    }

    quic_conn_t *qc = calloc(1, sizeof(*qc));
    if (!qc) return LP2P_ERR_NOMEM;

    qc->transport = qt;
    qc->is_server = false;
    qc->state = QUIC_CONN_HANDSHAKING;
    qc->on_conn_cb = on_conn;
    qc->on_conn_ud = userdata;
    memcpy(&qc->remote_addr, &remote, sizeof(remote));

    qc->pub_conn = lp2p_conn_new(qt->loop, false, NULL);
    if (!qc->pub_conn) {
        free(qc);
        return LP2P_ERR_NOMEM;
    }
    qc->pub_conn->backend = LP2P_CONN_BACKEND_QUIC;
    qc->pub_conn->backend_impl = qc;

    /* Check for expected peer ID in multiaddr */
    lp2p_peer_id_t expected_pid;
    if (lp2p_multiaddr_get_peer_id(addr, &expected_pid) == LP2P_OK && expected_pid.len > 0) {
        qc->expected_peer_id = expected_pid;
        qc->has_expected_peer_id = true;
    }

    /* Generate SCID */
    RAND_bytes(qc->scid.data, QUIC_SCID_LEN);
    qc->scid.datalen = QUIC_SCID_LEN;
    if (!quic_conn_track_local_cid(qc, &qc->scid)) {
        lp2p_conn_destroy(qc->pub_conn);
        return LP2P_ERR_NOMEM;
    }

    /* Generate random DCID for initial connection */
    RAND_bytes(qc->dcid.data, QUIC_SCID_LEN);
    qc->dcid.datalen = QUIC_SCID_LEN;

    /* If not listening yet, init a UDP socket for the dial */
    if (!qt->udp_initialized) {
        int rv = uv_udp_init(qt->loop, &qt->udp_server);
        if (rv != 0) { lp2p_conn_destroy(qc->pub_conn); return LP2P_ERR_TRANSPORT; }
        qt->udp_initialized = true;
        qt->udp_server.data = qt;

        /* Bind to ephemeral port */
        struct sockaddr_storage bind_addr;
        memset(&bind_addr, 0, sizeof(bind_addr));
        if (is_ipv6) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&bind_addr;
            sin6->sin6_family = AF_INET6;
            sin6->sin6_port = 0;
            sin6->sin6_addr = in6addr_any;
        } else {
            struct sockaddr_in *sin = (struct sockaddr_in *)&bind_addr;
            sin->sin_family = AF_INET;
            sin->sin_port = 0;
            sin->sin_addr.s_addr = INADDR_ANY;
        }

        rv = uv_udp_bind(&qt->udp_server, (const struct sockaddr *)&bind_addr, 0);
        if (rv != 0) { lp2p_conn_destroy(qc->pub_conn); return LP2P_ERR_TRANSPORT; }

        rv = uv_udp_recv_start(&qt->udp_server, alloc_cb, udp_recv_cb);
        if (rv != 0) { lp2p_conn_destroy(qc->pub_conn); return LP2P_ERR_TRANSPORT; }
    }

    /* Get local address */
    int namelen = sizeof(qc->local_addr);
    uv_udp_getsockname(&qt->udp_server, (struct sockaddr *)&qc->local_addr, &namelen);

    /* Create SSL context and SSL object */
    lp2p_err_t err = quic_tls_create_ssl_ctx(qt->keypair, false, &qc->ssl_ctx);
    if (err != LP2P_OK) {
        lp2p_conn_destroy(qc->pub_conn);
        return err;
    }

    qc->ssl = SSL_new(qc->ssl_ctx);
    if (!qc->ssl) {
        SSL_CTX_free(qc->ssl_ctx);
        qc->ssl_ctx = NULL;
        lp2p_conn_destroy(qc->pub_conn);
        return LP2P_ERR_CRYPTO;
    }
    qc->conn_ref.get_conn = quic_crypto_get_conn;
    qc->conn_ref.user_data = qc;
    SSL_set_app_data(qc->ssl, &qc->conn_ref);
    SSL_set_connect_state(qc->ssl);

    /* Set up ngtcp2 client connection */
    ngtcp2_path path;
    memset(&path, 0, sizeof(path));
    path.local.addr = (struct sockaddr *)&qc->local_addr;
    path.local.addrlen = sockaddr_len(&qc->local_addr);
    path.remote.addr = (struct sockaddr *)&qc->remote_addr;
    path.remote.addrlen = sockaddr_len(&qc->remote_addr);

    ngtcp2_callbacks callbacks = make_client_callbacks();
    ngtcp2_settings settings = make_settings();
    ngtcp2_transport_params params = make_transport_params(false);

    ngtcp2_conn *conn = NULL;
    int rv = ngtcp2_conn_client_new(&conn, &qc->dcid, &qc->scid,
                                     &path, NGTCP2_PROTO_VER_V1,
                                     &callbacks, &settings, &params,
                                     NULL, qc);
    if (rv != 0) {
        SSL_free(qc->ssl);
        SSL_CTX_free(qc->ssl_ctx);
        qc->ssl = NULL;
        qc->ssl_ctx = NULL;
        lp2p_conn_destroy(qc->pub_conn);
        return LP2P_ERR_TRANSPORT;
    }
    qc->conn = conn;

    ngtcp2_conn_set_tls_native_handle(conn, qc->ssl);

    /* Initialize timer */
    uv_timer_init(qt->loop, &qc->timer);
    qc->timer.data = qc;
    qc->timer_initialized = true;

    /* Add to transport's connection list */
    qc->next = qt->conns;
    qt->conns = qc;

    /* Send initial handshake packets */
    quic_conn_write_packets(qc);

    return LP2P_OK;
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Transport vtable: close
 * ════════════════════════════════════════════════════════════════════════════ */

static void timer_close_cb(uv_handle_t *handle)
{
    quic_conn_t *qc = (quic_conn_t *)handle->data;
    if (!qc) return;

    if (qc->close_handles_pending > 0) {
        qc->close_handles_pending--;
    }
    if (qc->close_handles_pending == 0) {
        free(qc);
    }
}

static void udp_close_cb(uv_handle_t *handle) { (void)handle; }

static void quic_conn_free(quic_conn_t *qc)
{
    if (!qc || qc->cleanup_started) return;
    qc->cleanup_started = true;

    quic_transport_t *qt = qc->transport;
    quic_conn_remove(qc);

    if (qc->conn) {
        ngtcp2_conn_del(qc->conn);
        qc->conn = NULL;
    }

    if (qc->ssl) {
        SSL_free(qc->ssl);
        qc->ssl = NULL;
    }

    if (qc->ssl_ctx) {
        SSL_CTX_free(qc->ssl_ctx);
        qc->ssl_ctx = NULL;
    }

    /* Free all streams */
    quic_stream_t *qs = qc->streams;
    while (qs) {
        quic_stream_t *next = qs->next;
        quic_stream_free(qs);
        qs = next;
    }
    qc->streams = NULL;

    quic_local_cid_t *cid = qc->local_cids;
    while (cid) {
        quic_local_cid_t *next = cid->next;
        free(cid);
        cid = next;
    }
    qc->local_cids = NULL;

    /* Stop and close timer */
    if (qc->timer_initialized) {
        uv_timer_stop(&qc->timer);
        if (!uv_is_closing((uv_handle_t *)&qc->timer)) {
            qc->close_handles_pending++;
            qc->timer.data = qc;
            uv_close((uv_handle_t *)&qc->timer, timer_close_cb);
        }
        qc->timer_initialized = false;
    }

    if (qt) {
        quic_transport_maybe_close_udp(qt);
    }

    if (qc->close_handles_pending == 0) {
        free(qc);
    }
}

static void quic_close(void *transport)
{
    quic_transport_t *qt = (quic_transport_t *)transport;
    qt->listening = false;
    qt->on_conn = NULL;
    qt->on_conn_ud = NULL;
    quic_transport_maybe_close_udp(qt);

    if (qt->server_ssl_ctx) {
        SSL_CTX_free(qt->server_ssl_ctx);
        qt->server_ssl_ctx = NULL;
    }
}

lp2p_err_t lp2p_quic_conn_close(lp2p_conn_t *conn)
{
    if (!conn || conn->backend != LP2P_CONN_BACKEND_QUIC || !conn->backend_impl) {
        return LP2P_ERR_INVALID_ARG;
    }

    quic_conn_t *qc = (quic_conn_t *)conn->backend_impl;
    if (qc->state == QUIC_CONN_CLOSED || conn->state == CONN_STATE_CLOSED) {
        if (conn->close_cb.cb) {
            conn->close_cb.cb(conn, conn->close_cb.userdata);
        }
        return LP2P_OK;
    }

    if (qc->conn) {
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_zero(&ps);
        ngtcp2_pkt_info pi;
        ngtcp2_ccerr ccerr;

        ngtcp2_ccerr_default(&ccerr);
        ccerr.type = NGTCP2_CCERR_TYPE_APPLICATION;
        ccerr.error_code = NGTCP2_NO_ERROR;

        ngtcp2_ssize nwrite = ngtcp2_conn_write_connection_close(
            qc->conn, &ps.path, &pi, qc->send_buf, sizeof(qc->send_buf), &ccerr, quic_now());
        if (nwrite > 0) {
            (void)quic_send_packet(qc, qc->send_buf, (size_t)nwrite);
        }
    }

    void (*on_disconnect)(lp2p_conn_t *, lp2p_err_t, void *) = conn->on_disconnect;
    void *disconnect_ud = conn->cb_userdata;
    void (*close_cb)(lp2p_conn_t *, void *) = conn->close_cb.cb;
    void *close_ud = conn->close_cb.userdata;

    conn->on_disconnect = NULL;
    conn->close_cb.cb = NULL;
    conn->close_cb.userdata = NULL;
    conn->closing = true;
    conn->state = CONN_STATE_CLOSED;
    qc->state = QUIC_CONN_CLOSED;

    if (on_disconnect) {
        on_disconnect(conn, LP2P_ERR_CONNECTION_CLOSED, disconnect_ud);
    }
    if (close_cb) {
        close_cb(conn, close_ud);
    }

    return LP2P_OK;
}

void lp2p_quic_conn_cleanup(lp2p_conn_t *conn)
{
    if (!conn || conn->backend != LP2P_CONN_BACKEND_QUIC || !conn->backend_impl) {
        return;
    }

    quic_conn_t *qc = (quic_conn_t *)conn->backend_impl;
    conn->backend_impl = NULL;
    if (qc->pub_conn == conn) {
        qc->pub_conn = NULL;
    }
    quic_conn_free(qc);
}

/* ════════════════════════════════════════════════════════════════════════════
 *  Constructor / Destructor
 * ════════════════════════════════════════════════════════════════════════════ */

lp2p_err_t lp2p_quic_transport_new(uv_loop_t *loop, const lp2p_keypair_t *keypair,
                                    lp2p_transport_t **out)
{
    if (!loop || !keypair || !out) return LP2P_ERR_INVALID_ARG;

    lp2p_transport_t *t = calloc(1, sizeof(*t));
    if (!t) return LP2P_ERR_NOMEM;

    quic_transport_t *qt = calloc(1, sizeof(*qt));
    if (!qt) { free(t); return LP2P_ERR_NOMEM; }

    qt->loop = loop;
    qt->keypair = keypair;

    t->vtable = &quic_vtable;
    t->impl = qt;

    *out = t;
    return LP2P_OK;
}

void lp2p_quic_transport_free(lp2p_transport_t *t)
{
    if (!t) return;
    if (t->impl) {
        quic_transport_t *qt = (quic_transport_t *)t->impl;
        quic_conn_t *qc = qt->conns;
        qt->conns = NULL;
        while (qc) {
            quic_conn_t *next = qc->next;
            qc->next = NULL;
            qc->state = QUIC_CONN_CLOSED;
            if (qc->pub_conn) {
                lp2p_conn_destroy(qc->pub_conn);
            } else {
                quic_conn_free(qc);
            }
            qc = next;
        }

        qt->listening = false;
        qt->on_conn = NULL;
        qt->on_conn_ud = NULL;
        if (qt->udp_initialized && !uv_is_closing((uv_handle_t *)&qt->udp_server)) {
            uv_udp_recv_stop(&qt->udp_server);
            uv_close((uv_handle_t *)&qt->udp_server, udp_close_cb);
            qt->udp_initialized = false;
        }
        free(qt);
    }
    free(t);
}
