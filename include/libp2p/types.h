#ifndef LIBP2P_TYPES_H
#define LIBP2P_TYPES_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Opaque handle types ─────────────────────────────────────────────────── */
typedef struct lp2p_host       lp2p_host_t;
typedef struct lp2p_conn       lp2p_conn_t;
typedef struct lp2p_stream     lp2p_stream_t;
typedef struct lp2p_peerstore  lp2p_peerstore_t;
typedef struct lp2p_keypair    lp2p_keypair_t;
typedef struct lp2p_multiaddr  lp2p_multiaddr_t;

/* ── Byte buffer ──────────────────────────────────────────────────────────── */
typedef struct {
    const uint8_t *data;
    size_t         len;
} lp2p_buf_t;

/* ── Peer ID (32-byte inline storage for Ed25519 identity hash) ──────────── */
#define LP2P_PEER_ID_SIZE 39   /* max: 2-byte multihash prefix + 37 bytes */
typedef struct {
    uint8_t bytes[LP2P_PEER_ID_SIZE];
    size_t  len;
} lp2p_peer_id_t;

/* ── Key types ────────────────────────────────────────────────────────────── */
typedef enum {
    LP2P_KEY_ED25519   = 1,  /* local host key generation — only supported type */
    LP2P_KEY_RSA       = 0,  /* remote identity verification only               */
    LP2P_KEY_SECP256K1 = 2,  /* remote identity verification only               */
    LP2P_KEY_ECDSA     = 3,  /* remote identity verification only               */
} lp2p_key_type_t;

/* ── Logging ──────────────────────────────────────────────────────────────── */
typedef enum {
    LP2P_LOG_ERROR = 0,
    LP2P_LOG_WARN  = 1,
    LP2P_LOG_INFO  = 2,
    LP2P_LOG_DEBUG = 3,
    LP2P_LOG_TRACE = 4,
} lp2p_log_level_t;

typedef void (*lp2p_log_fn)(lp2p_log_level_t level, const char *module, const char *msg);

void lp2p_set_log_level(lp2p_log_level_t level);
void lp2p_set_log_handler(lp2p_log_fn fn);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_TYPES_H */
