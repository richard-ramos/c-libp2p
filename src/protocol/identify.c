/* src/protocol/identify.c — /ipfs/id/1.0.0 and /ipfs/id/push/1.0.0 */

#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include "identify_internal.h"
#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/stream.h"
#include "libp2p/connection.h"
#include "libp2p/peerstore.h"
#include "libp2p/multiaddr.h"
#include "libp2p/crypto.h"
#include "connmgr_internal.h"
#include "peerstore_internal.h"
#include "protocol_router.h"
#include "crypto/keypair_internal.h"
#include "identify.pb-c.h"

/* We need the host struct for building identify messages.
 * host_internal.h will provide the struct definition. */
#include "host_internal.h"

/* ── Varint helpers ──────────────────────────────────────────────────────── */

static size_t varint_encode(uint64_t val, uint8_t *buf) {
    size_t i = 0;
    while (val >= 0x80) {
        buf[i++] = (uint8_t)(val | 0x80);
        val >>= 7;
    }
    buf[i++] = (uint8_t)val;
    return i;
}

static int varint_decode(const uint8_t *buf, size_t len, uint64_t *out, size_t *consumed) {
    uint64_t val = 0;
    size_t i = 0;
    unsigned shift = 0;
    while (i < len && i < 10) {
        uint64_t b = buf[i];
        val |= (b & 0x7F) << shift;
        i++;
        if ((b & 0x80) == 0) {
            *out = val;
            *consumed = i;
            return 0;
        }
        shift += 7;
    }
    return -1; /* need more data or overflow */
}

/* ── Build protobuf-encoded PublicKey ────────────────────────────────────── */

/*
 * The PublicKey protobuf from the keys spec:
 *   message PublicKey {
 *     required KeyType Type = 1;
 *     required bytes Data = 2;
 *   }
 *   enum KeyType { Ed25519 = 1; ... }
 *
 * For Ed25519: Type=1, Data=32 bytes raw public key
 */
static lp2p_err_t build_pubkey_proto(const lp2p_keypair_t *kp,
                                      uint8_t **out, size_t *out_len) {
    const uint8_t *pk = lp2p_keypair_public_ptr(kp);
    if (!pk) return LP2P_ERR_INVALID_KEY;

    /* Protobuf encoding:
     * field 1 (varint, KeyType): tag=0x08, value=0x01 (Ed25519)
     * field 2 (bytes, Data):     tag=0x12, length=0x20, data=32 bytes
     * Total: 2 + 2 + 32 = 36 bytes */
    size_t len = 36;
    uint8_t *buf = malloc(len);
    if (!buf) return LP2P_ERR_NOMEM;

    buf[0] = 0x08; /* field 1, varint */
    buf[1] = 0x01; /* Ed25519 = 1 */
    buf[2] = 0x12; /* field 2, length-delimited */
    buf[3] = 0x20; /* 32 bytes */
    memcpy(buf + 4, pk, 32);

    *out = buf;
    *out_len = len;
    return LP2P_OK;
}

/* ── Build Identify protobuf from host state ─────────────────────────────── */

static lp2p_err_t build_identify_msg(struct lp2p_host *host,
                                      const lp2p_multiaddr_t *observed_addr,
                                      uint8_t **out, size_t *out_len) {
    Identify__Identify id_msg = IDENTIFY__IDENTIFY__INIT;

    /* publicKey */
    uint8_t *pubkey_proto = NULL;
    size_t   pubkey_proto_len = 0;
    lp2p_err_t err = build_pubkey_proto(host->keypair, &pubkey_proto, &pubkey_proto_len);
    if (err != LP2P_OK) return err;

    id_msg.publickey.data = pubkey_proto;
    id_msg.publickey.len  = pubkey_proto_len;
    id_msg.has_publickey  = 1;

    /* listenAddrs — multiaddr bytes for each listen address */
    size_t n_addrs = host->listen_addrs_count;
    ProtobufCBinaryData *addr_bufs = NULL;
    if (n_addrs > 0) {
        addr_bufs = calloc(n_addrs, sizeof(ProtobufCBinaryData));
        if (!addr_bufs) { free(pubkey_proto); return LP2P_ERR_NOMEM; }

        for (size_t i = 0; i < n_addrs; i++) {
            size_t mlen = 0;
            const uint8_t *mbytes = lp2p_multiaddr_bytes(host->listen_mas[i], &mlen);
            addr_bufs[i].data = (uint8_t *)mbytes;
            addr_bufs[i].len  = mlen;
        }
        id_msg.n_listenaddrs = n_addrs;
        id_msg.listenaddrs   = addr_bufs;
    }

    /* protocols — list of supported protocol IDs */
    const char *protos[LP2P_MAX_PROTOCOLS];
    size_t n_protos = lp2p_protocol_router_get_protocols(host->router, protos,
                                                          LP2P_MAX_PROTOCOLS);
    if (n_protos > 0) {
        id_msg.n_protocols = n_protos;
        id_msg.protocols   = (char **)protos;
    }

    /* observedAddr */
    if (observed_addr) {
        size_t olen = 0;
        const uint8_t *obytes = lp2p_multiaddr_bytes(observed_addr, &olen);
        id_msg.observedaddr.data = (uint8_t *)obytes;
        id_msg.observedaddr.len  = olen;
        id_msg.has_observedaddr  = 1;
    }

    /* protocolVersion */
    id_msg.protocolversion = (char *)IDENTIFY_PROTOCOL_VERSION;

    /* agentVersion */
    id_msg.agentversion = (char *)IDENTIFY_AGENT_VERSION;

    /* Pack */
    size_t packed_len = identify__identify__get_packed_size(&id_msg);
    uint8_t *packed = malloc(packed_len);
    if (!packed) {
        free(pubkey_proto);
        free(addr_bufs);
        return LP2P_ERR_NOMEM;
    }
    identify__identify__pack(&id_msg, packed);

    free(pubkey_proto);
    free(addr_bufs);

    *out = packed;
    *out_len = packed_len;
    return LP2P_OK;
}

/* ── Process received Identify message ───────────────────────────────────── */

static lp2p_err_t process_identify_msg(struct lp2p_host *host,
                                         lp2p_conn_t *conn,
                                         const uint8_t *data, size_t len) {
    Identify__Identify *msg = identify__identify__unpack(NULL, len, data);
    if (!msg) return LP2P_ERR_PROTOCOL;

    lp2p_peer_id_t remote_peer = lp2p_conn_peer_id(conn);
    lp2p_err_t err = LP2P_OK;

    /* Validate publicKey matches authenticated peer ID */
    if (msg->has_publickey && msg->publickey.len > 0) {
        lp2p_peer_id_t id_from_key;
        lp2p_err_t kerr = lp2p_peer_id_from_public_key(msg->publickey.data,
                                                         msg->publickey.len,
                                                         &id_from_key);
        if (kerr == LP2P_OK && !lp2p_peer_id_equal(&id_from_key, &remote_peer)) {
            /* Public key doesn't match authenticated peer — skip this identify */
            identify__identify__free_unpacked(msg, NULL);
            return LP2P_ERR_PEER_ID_MISMATCH;
        }

        /* Store the public key in peerstore */
        if (kerr == LP2P_OK) {
            lp2p_peerstore_add_pubkey(host->peerstore, &remote_peer,
                                       msg->publickey.data, msg->publickey.len);
        }
    }

    /* Process listen addresses — clear old identify-sourced addrs first */
    lp2p_peerstore_clear_identify_addrs(host->peerstore, &remote_peer);

    for (size_t i = 0; i < msg->n_listenaddrs; i++) {
        lp2p_multiaddr_t *ma = NULL;
        /* Parse multiaddr from raw bytes — we'd need a from_bytes function.
         * For now, reconstruct from bytes. The multiaddr module should support this.
         * If not available, we skip address processing. */
        /* TODO: lp2p_multiaddr_from_bytes() if available */
        (void)ma;
        (void)msg->listenaddrs[i];
    }

    identify__identify__free_unpacked(msg, NULL);
    return err;
}

/* ── Listener-side handler: /ipfs/id/1.0.0 ──────────────────────────────── */

typedef struct {
    struct lp2p_host *host;
    lp2p_stream_t    *stream;
    uint8_t          *msg_buf;
    size_t            msg_len;
} identify_listener_ctx_t;

static void identify_listener_write_done(lp2p_stream_t *stream, lp2p_err_t err,
                                           void *userdata) {
    identify_listener_ctx_t *ctx = userdata;
    (void)err;
    /* Close write side after sending identify */
    lp2p_stream_close(stream, NULL, NULL);
    free(ctx->msg_buf);
    free(ctx);
}

void lp2p_identify_handler(lp2p_stream_t *stream, void *userdata) {
    struct lp2p_host *host = userdata;
    if (!host || !stream) {
        if (stream) lp2p_stream_reset(stream);
        return;
    }

    identify_listener_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) { lp2p_stream_reset(stream); return; }

    ctx->host   = host;
    ctx->stream = stream;

    /* Get observed addr from the connection */
    lp2p_conn_t *conn = lp2p_stream_connection(stream);
    const lp2p_multiaddr_t *observed = conn ? lp2p_conn_remote_addr(conn) : NULL;

    /* Build identify message */
    lp2p_err_t err = build_identify_msg(host, observed, &ctx->msg_buf, &ctx->msg_len);
    if (err != LP2P_OK) {
        lp2p_stream_reset(stream);
        free(ctx);
        return;
    }

    /* Send as LP-prefixed message */
    lp2p_buf_t buf = { .data = ctx->msg_buf, .len = ctx->msg_len };
    err = lp2p_stream_write_lp(stream, &buf, identify_listener_write_done, ctx);
    if (err != LP2P_OK) {
        lp2p_stream_reset(stream);
        free(ctx->msg_buf);
        free(ctx);
    }
}

/* ── Dialer side: read identify after connection READY ───────────────────── */

typedef struct {
    struct lp2p_host *host;
    lp2p_conn_t      *conn;
    lp2p_stream_t    *stream;
} identify_dialer_ctx_t;

static void identify_dialer_on_read(lp2p_stream_t *stream, lp2p_err_t err,
                                      const lp2p_buf_t *buf, void *userdata) {
    identify_dialer_ctx_t *ctx = userdata;

    if (err == LP2P_OK && buf && buf->len > 0) {
        process_identify_msg(ctx->host, ctx->conn, buf->data, buf->len);
    }

    /* Close the stream regardless */
    lp2p_stream_close(stream, NULL, NULL);
    free(ctx);
}

static void identify_dialer_on_stream(lp2p_stream_t *stream, lp2p_err_t err,
                                        void *userdata) {
    identify_dialer_ctx_t *ctx = userdata;

    if (err != LP2P_OK || !stream) {
        free(ctx);
        return;
    }

    ctx->stream = stream;

    /* Read the LP-prefixed identify message from the listener */
    lp2p_err_t rerr = lp2p_stream_read_lp(stream, IDENTIFY_MAX_MSG_SIZE,
                                            identify_dialer_on_read, ctx);
    if (rerr != LP2P_OK) {
        lp2p_stream_reset(stream);
        free(ctx);
    }
}

lp2p_err_t lp2p_identify_dial(struct lp2p_host *host, lp2p_conn_t *conn) {
    if (!host || !conn) return LP2P_ERR_INVALID_ARG;

    identify_dialer_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return LP2P_ERR_NOMEM;
    ctx->host = host;
    ctx->conn = conn;

    lp2p_err_t err = lp2p_conn_open_stream(conn, IDENTIFY_PROTOCOL_ID,
                                             identify_dialer_on_stream, ctx);
    if (err != LP2P_OK) {
        free(ctx);
        return err;
    }

    return LP2P_OK;
}

/* ── Identify Push handler: /ipfs/id/push/1.0.0 ─────────────────────────── */

typedef struct {
    struct lp2p_host *host;
    lp2p_conn_t      *conn;
} identify_push_ctx_t;

static void identify_push_on_read(lp2p_stream_t *stream, lp2p_err_t err,
                                    const lp2p_buf_t *buf, void *userdata) {
    identify_push_ctx_t *ctx = userdata;

    if (err == LP2P_OK && buf && buf->len > 0) {
        lp2p_conn_t *conn = lp2p_stream_connection(stream);
        if (conn) {
            process_identify_msg(ctx->host, conn, buf->data, buf->len);
        }
    }

    lp2p_stream_close(stream, NULL, NULL);
    free(ctx);
}

void lp2p_identify_push_handler(lp2p_stream_t *stream, void *userdata) {
    struct lp2p_host *host = userdata;
    if (!host || !stream) {
        if (stream) lp2p_stream_reset(stream);
        return;
    }

    identify_push_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) { lp2p_stream_reset(stream); return; }
    ctx->host = host;

    /* Read the LP-prefixed identify push message */
    lp2p_err_t err = lp2p_stream_read_lp(stream, IDENTIFY_MAX_MSG_SIZE,
                                           identify_push_on_read, ctx);
    if (err != LP2P_OK) {
        lp2p_stream_reset(stream);
        free(ctx);
    }
}

/* ── Push identify to all connected peers ────────────────────────────────── */

typedef struct {
    uint8_t *msg_buf;
    size_t   msg_len;
} push_write_ctx_t;

static void push_write_done(lp2p_stream_t *stream, lp2p_err_t err,
                              void *userdata) {
    push_write_ctx_t *ctx = userdata;
    (void)err;
    lp2p_stream_close(stream, NULL, NULL);
    free(ctx->msg_buf);
    free(ctx);
}

static void push_on_stream(lp2p_stream_t *stream, lp2p_err_t err,
                             void *userdata) {
    push_write_ctx_t *ctx = userdata;
    if (err != LP2P_OK || !stream) {
        if (ctx) { free(ctx->msg_buf); free(ctx); }
        return;
    }

    lp2p_buf_t buf = { .data = ctx->msg_buf, .len = ctx->msg_len };
    lp2p_err_t werr = lp2p_stream_write_lp(stream, &buf, push_write_done, ctx);
    if (werr != LP2P_OK) {
        lp2p_stream_reset(stream);
        free(ctx->msg_buf);
        free(ctx);
    }
}

lp2p_err_t lp2p_identify_push_all(struct lp2p_host *host) {
    if (!host) return LP2P_ERR_INVALID_ARG;

    /* Build identify message once */
    uint8_t *msg = NULL;
    size_t   msg_len = 0;
    lp2p_err_t err = build_identify_msg(host, NULL, &msg, &msg_len);
    if (err != LP2P_OK) return err;

    /* Iterate all connected peers in connmgr and open push streams.
     * For each peer, we need to open /ipfs/id/push/1.0.0 and send the msg.
     * Iterate via the connmgr's all_conns list. */
    lp2p_list_node_t *node = host->connmgr->all_conns.head.next;
    lp2p_list_node_t *sentinel = &host->connmgr->all_conns.head;

    while (node != sentinel) {
        lp2p_conn_t *conn = lp2p_container_of(node, lp2p_conn_t, node);
        node = node->next;

        if (conn->state != CONN_STATE_READY) continue;

        /* Allocate a copy of the message for each peer */
        push_write_ctx_t *ctx = calloc(1, sizeof(*ctx));
        if (!ctx) continue;
        ctx->msg_buf = malloc(msg_len);
        if (!ctx->msg_buf) { free(ctx); continue; }
        memcpy(ctx->msg_buf, msg, msg_len);
        ctx->msg_len = msg_len;

        lp2p_err_t open_err = lp2p_conn_open_stream(conn,
                                                    IDENTIFY_PUSH_PROTOCOL_ID,
                                                    push_on_stream, ctx);
        if (open_err != LP2P_OK) {
            free(ctx->msg_buf);
            free(ctx);
        }
    }

    free(msg);
    return LP2P_OK;
}
