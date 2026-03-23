/* src/host.c — libp2p host implementation */

#include <stdlib.h>
#include <string.h>

#include <uv.h>

#include "host_internal.h"
#include "libp2p/host.h"
#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/stream.h"
#include "libp2p/connection.h"
#include "libp2p/multiaddr.h"
#include "libp2p/crypto.h"
#include "libp2p/peerstore.h"
#include "connmgr_internal.h"
#include "peerstore_internal.h"
#include "protocol_router.h"
#include "dialer.h"
#include "listener.h"
#include "transport/transport.h"
#include "transport/tcp/tcp_transport.h"
#include "protocol/ping_internal.h"
#include "protocol/identify_internal.h"

/* ── Default values ──────────────────────────────────────────────────────── */

#define DEFAULT_MAX_CONNECTIONS        256
#define DEFAULT_MAX_STREAMS_PER_CONN   256
#define DEFAULT_DIAL_TIMEOUT_MS        30000
#define DEFAULT_HANDSHAKE_TIMEOUT_MS   10000
#define DEFAULT_PROTOCOL_TIMEOUT_MS    10000
#define DEFAULT_KEEPALIVE_INTERVAL_S   30

/* ── Forward declarations ────────────────────────────────────────────────── */

static void host_on_inbound_raw_conn(lp2p_listener_t *listener, lp2p_conn_t *conn,
                                     void *userdata);
static void host_on_new_stream(lp2p_stream_t *stream, void *userdata);
static void host_fire_conn_callbacks(lp2p_host_t *host, lp2p_conn_t *conn);
static void host_fire_disconn_callbacks(lp2p_host_t *host, lp2p_conn_t *conn,
                                          lp2p_err_t reason);
static void dial_done(lp2p_conn_t *conn, lp2p_err_t err, void *userdata);
static void host_on_raw_dial_conn(lp2p_conn_t *conn, lp2p_err_t err, void *userdata);
static void host_on_upgraded_ready(lp2p_conn_t *conn, void *userdata);
static void host_on_upgraded_disconnect(lp2p_conn_t *conn, lp2p_err_t reason,
                                        void *userdata);
static void host_on_live_disconnect(lp2p_conn_t *conn, lp2p_err_t reason,
                                    void *userdata);
static void host_conn_destroy_done(lp2p_conn_t *conn, void *userdata);
static void host_pending_conn_close_done(lp2p_conn_t *conn, void *userdata);
static void host_live_conn_close_done(lp2p_conn_t *conn, void *userdata);
static void host_finish_inbound_conn(lp2p_host_t *host, lp2p_conn_t *conn);

static bool host_conn_has_peer_id(const lp2p_conn_t *conn) {
    return conn && lp2p_conn_peer_id(conn).len > 0;
}

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

lp2p_err_t lp2p_host_new(uv_loop_t *loop, const lp2p_host_config_t *config,
                           lp2p_host_t **out) {
    if (!loop || !config || !config->keypair || !out)
        return LP2P_ERR_INVALID_ARG;

    lp2p_host_t *h = calloc(1, sizeof(*h));
    if (!h) return LP2P_ERR_NOMEM;

    h->loop = loop;

    /* Apply config with defaults */
    h->config = *config;
    if (h->config.max_connections == 0)
        h->config.max_connections = DEFAULT_MAX_CONNECTIONS;
    if (h->config.max_streams_per_conn == 0)
        h->config.max_streams_per_conn = DEFAULT_MAX_STREAMS_PER_CONN;
    if (h->config.dial_timeout_ms == 0)
        h->config.dial_timeout_ms = DEFAULT_DIAL_TIMEOUT_MS;
    if (h->config.handshake_timeout_ms == 0)
        h->config.handshake_timeout_ms = DEFAULT_HANDSHAKE_TIMEOUT_MS;
    if (h->config.protocol_timeout_ms == 0)
        h->config.protocol_timeout_ms = DEFAULT_PROTOCOL_TIMEOUT_MS;
    if (h->config.keepalive_interval_s == 0)
        h->config.keepalive_interval_s = DEFAULT_KEEPALIVE_INTERVAL_S;

    /* Take ownership of keypair */
    h->keypair = config->keypair;

    /* Derive local peer ID */
    lp2p_err_t err = lp2p_peer_id_from_keypair(h->keypair, &h->local_peer_id);
    if (err != LP2P_OK) goto fail;

    /* Create peerstore */
    err = lp2p_peerstore_new(loop, &h->peerstore);
    if (err != LP2P_OK) goto fail;

    /* Create connection manager */
    err = lp2p_connmgr_new(loop, h->config.max_connections,
                             h->config.max_streams_per_conn, &h->connmgr);
    if (err != LP2P_OK) goto fail;

    /* Create protocol router */
    h->router = lp2p_protocol_router_new(loop);
    if (!h->router) { err = LP2P_ERR_NOMEM; goto fail; }

    /* Create TCP transport */
    err = lp2p_tcp_transport_new(loop, &h->transport);
    if (err != LP2P_OK) goto fail;

    /* Create dialer */
    err = lp2p_dialer_new(loop, h->transport, h->config.dial_timeout_ms,
                            &h->dialer);
    if (err != LP2P_OK) goto fail;

    /* Register built-in protocol handlers */
    lp2p_protocol_router_add(h->router, PING_PROTOCOL_ID,
                              lp2p_ping_handler, h);
    lp2p_protocol_router_add(h->router, IDENTIFY_PROTOCOL_ID,
                              lp2p_identify_handler, h);
    lp2p_protocol_router_add(h->router, IDENTIFY_PUSH_PROTOCOL_ID,
                              lp2p_identify_push_handler, h);

    /* Parse listen addresses */
    if (config->listen_addrs && config->listen_addrs_count > 0) {
        size_t count = config->listen_addrs_count;
        if (count > LP2P_MAX_LISTENERS) count = LP2P_MAX_LISTENERS;
        for (size_t i = 0; i < count; i++) {
            err = lp2p_multiaddr_parse(config->listen_addrs[i], &h->listen_mas[i]);
            if (err != LP2P_OK) goto fail;
            h->listen_addrs_count++;
        }
    }

    *out = h;
    return LP2P_OK;

fail:
    lp2p_host_free(h);
    return err;
}

void lp2p_host_free(lp2p_host_t *host) {
    if (!host) return;

    /* Free listeners */
    for (size_t i = 0; i < host->listener_count; i++) {
        lp2p_listener_free(host->listeners[i]);
    }

    /* Free parsed listen multiaddrs */
    for (size_t i = 0; i < host->listen_addrs_count; i++) {
        lp2p_multiaddr_free(host->listen_mas[i]);
    }

    if (host->dialer)    lp2p_dialer_free(host->dialer);
    if (host->transport) lp2p_tcp_transport_free(host->transport);
    if (host->router)    lp2p_protocol_router_free(host->router);
    if (host->connmgr)   lp2p_connmgr_free(host->connmgr);
    if (host->peerstore) lp2p_peerstore_free(host->peerstore);
    if (host->keypair)   lp2p_keypair_free(host->keypair);

    free(host);
}

/* ── Close ───────────────────────────────────────────────────────────────── */

static void host_close_check(lp2p_host_t *host) {
    if (host->close_pending == 0 && host->close_cb) {
        host->close_cb(host, host->close_ud);
    }
}

static void host_listener_close_done(lp2p_host_t *host) {
    host->close_pending--;
    host_close_check(host);
}

static void host_conn_close_done(lp2p_conn_t *conn, void *userdata) {
    lp2p_host_t *host = userdata;
    lp2p_connmgr_remove(host->connmgr, conn);
    host_fire_disconn_callbacks(host, conn, LP2P_OK);
    lp2p_conn_destroy(conn);
    host->close_pending--;
    host_close_check(host);
}

lp2p_err_t lp2p_host_close(lp2p_host_t *host,
                             void (*cb)(lp2p_host_t *host, void *userdata),
                             void *userdata) {
    if (!host) return LP2P_ERR_INVALID_ARG;
    if (host->closing) return LP2P_ERR_BUSY;

    host->closing  = true;
    host->close_cb = cb;
    host->close_ud = userdata;
    host->close_pending = 0;

    /* Close all listeners */
    for (size_t i = 0; i < host->listener_count; i++) {
        host->close_pending++;
        lp2p_listener_close(host->listeners[i]);
        /* For simplicity, decrement immediately since listener_close
         * is synchronous in the current implementation */
        host->close_pending--;
    }

    /* Close all connections */
    lp2p_list_node_t *node = host->connmgr->all_conns.head.next;
    lp2p_list_node_t *sentinel = &host->connmgr->all_conns.head;

    while (node != sentinel) {
        lp2p_conn_t *conn = lp2p_container_of(node, lp2p_conn_t, node);
        node = node->next; /* advance before close modifies the list */
        host->close_pending++;
        lp2p_conn_close(conn, host_conn_close_done, host);
    }

    /* If nothing to drain, fire callback on next tick */
    if (host->close_pending == 0 && cb) {
        /* Defer to next event loop turn */
        cb(host, userdata);
    }

    return LP2P_OK;
}

/* ── Listen ──────────────────────────────────────────────────────────────── */

typedef struct {
    lp2p_host_t       *host;
    lp2p_on_listen_cb   cb;
    void               *userdata;
    size_t              remaining;
    lp2p_err_t          first_err;
} listen_ctx_t;

lp2p_err_t lp2p_host_listen(lp2p_host_t *host, lp2p_on_listen_cb cb,
                               void *userdata) {
    if (!host) return LP2P_ERR_INVALID_ARG;

    if (host->listen_addrs_count == 0) {
        if (cb) cb(LP2P_OK, userdata);
        return LP2P_OK;
    }

    lp2p_err_t first_err = LP2P_OK;

    for (size_t i = 0; i < host->listen_addrs_count; i++) {
        lp2p_listener_t *listener = NULL;
        lp2p_err_t err = lp2p_listener_new(host->loop, host->transport,
                                             host->listen_mas[i], &listener);
        if (err != LP2P_OK) {
            if (first_err == LP2P_OK) first_err = err;
            continue;
        }

        err = lp2p_listener_start(listener, host_on_inbound_raw_conn, host);
        if (err != LP2P_OK) {
            lp2p_listener_free(listener);
            if (first_err == LP2P_OK) first_err = err;
            continue;
        }

        host->listeners[host->listener_count++] = listener;
    }

    if (cb) cb(first_err, userdata);
    return first_err;
}

/* ── Dial ────────────────────────────────────────────────────────────────── */

typedef struct {
    lp2p_host_t   *host;
    lp2p_dial_cb    cb;
    void           *userdata;
    lp2p_peer_id_t  expected_peer;
    bool            has_expected_peer;
} dial_ctx_t;

typedef struct {
    lp2p_host_t *host;
    dial_ctx_t  *dial_ctx;
} host_pending_conn_ctx_t;

static void host_conn_destroy_done(lp2p_conn_t *conn, void *userdata) {
    (void)userdata;
    lp2p_conn_destroy(conn);
}

static void host_pending_conn_close_done(lp2p_conn_t *conn, void *userdata) {
    host_pending_conn_ctx_t *ctx = userdata;
    if (ctx) {
        if (ctx->dial_ctx) free(ctx->dial_ctx);
        free(ctx);
    }
    lp2p_conn_destroy(conn);
}

static void host_live_conn_close_done(lp2p_conn_t *conn, void *userdata) {
    (void)userdata;
    lp2p_conn_destroy(conn);
}

static void host_on_live_disconnect(lp2p_conn_t *conn, lp2p_err_t reason,
                                    void *userdata) {
    lp2p_host_t *host = userdata;
    if (!host || !conn || host->closing) return;

    if (conn->node.prev && conn->node.next) {
        lp2p_connmgr_remove(host->connmgr, conn);
        host_fire_disconn_callbacks(host, conn, reason);
    }
}

static void host_on_upgraded_disconnect(lp2p_conn_t *conn, lp2p_err_t reason,
                                        void *userdata) {
    host_pending_conn_ctx_t *ctx = userdata;
    (void)conn;

    if (!ctx) return;

    if (ctx->dial_ctx) {
        if (ctx->dial_ctx->cb) ctx->dial_ctx->cb(NULL, reason, ctx->dial_ctx->userdata);
        free(ctx->dial_ctx);
        ctx->dial_ctx = NULL;
    }
}

static void host_on_upgraded_ready(lp2p_conn_t *conn, void *userdata) {
    host_pending_conn_ctx_t *ctx = userdata;
    if (!ctx || !conn) return;

    conn->host = ctx->host;
    conn->on_disconnect = host_on_live_disconnect;
    conn->cb_userdata = ctx->host;
    conn->close_cb.cb = host_live_conn_close_done;
    conn->close_cb.userdata = ctx->host;

    if (ctx->dial_ctx) {
        dial_done(conn, LP2P_OK, ctx->dial_ctx);
    } else {
        host_finish_inbound_conn(ctx->host, conn);
    }

    free(ctx);
}

static lp2p_err_t host_upgrade_raw_conn(lp2p_host_t *host, lp2p_tcp_conn_t *tc,
                                        bool is_inbound, dial_ctx_t *dial_ctx) {
    if (!host || !tc) return LP2P_ERR_INVALID_ARG;

    lp2p_conn_t *conn = lp2p_conn_new(host->loop, is_inbound, host);
    if (!conn) {
        lp2p_tcp_conn_close(tc, NULL, NULL);
        return LP2P_ERR_NOMEM;
    }

    lp2p_conn_attach_tcp(conn, tc);
    lp2p_conn_set_protocol_router(conn, host->router);

    host_pending_conn_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        lp2p_tcp_conn_close(tc, NULL, NULL);
        lp2p_conn_destroy(conn);
        return LP2P_ERR_NOMEM;
    }

    ctx->host = host;
    ctx->dial_ctx = dial_ctx;
    conn->close_cb.cb = host_pending_conn_close_done;
    conn->close_cb.userdata = ctx;

    lp2p_err_t err = lp2p_conn_upgrade(conn, host->keypair,
                                       host_on_upgraded_ready,
                                       host_on_upgraded_disconnect,
                                       ctx);
    if (err != LP2P_OK) {
        lp2p_tcp_conn_close(tc, NULL, NULL);
        conn->close_cb.cb = host_conn_destroy_done;
        conn->close_cb.userdata = NULL;
        lp2p_conn_destroy(conn);
        free(ctx);
    }

    return err;
}

static void host_on_raw_dial_conn(lp2p_conn_t *conn, lp2p_err_t err, void *userdata) {
    dial_ctx_t *ctx = userdata;

    if (err != LP2P_OK || !conn) {
        if (ctx && ctx->cb) ctx->cb(NULL, err, ctx->userdata);
        free(ctx);
        return;
    }

    lp2p_err_t uerr = host_upgrade_raw_conn(ctx->host, (lp2p_tcp_conn_t *)conn,
                                            false, ctx);
    if (uerr != LP2P_OK) {
        if (ctx->cb) ctx->cb(NULL, uerr, ctx->userdata);
        free(ctx);
    }
}

static void dial_done(lp2p_conn_t *conn, lp2p_err_t err, void *userdata) {
    dial_ctx_t *ctx = userdata;
    lp2p_peer_id_t remote_peer = lp2p_conn_peer_id(conn);

    if (err != LP2P_OK) {
        if (ctx->cb) ctx->cb(NULL, err, ctx->userdata);
        free(ctx);
        return;
    }

    /* Set host on the connection */
    conn->host = ctx->host;

    /* If we expected a specific peer, verify */
    if (ctx->has_expected_peer && host_conn_has_peer_id(conn)) {
        if (!lp2p_peer_id_equal(&remote_peer, &ctx->expected_peer)) {
            lp2p_conn_close(conn, host_conn_destroy_done, NULL);
            if (ctx->cb) ctx->cb(NULL, LP2P_ERR_PEER_ID_MISMATCH, ctx->userdata);
            free(ctx);
            return;
        }
    }

    /* Add to connection manager */
    lp2p_err_t add_err = lp2p_connmgr_add(ctx->host->connmgr, conn);
    if (add_err == LP2P_ERR_MAX_CONNECTIONS) {
        lp2p_conn_close(conn, host_conn_destroy_done, NULL);
        if (ctx->cb) ctx->cb(NULL, LP2P_ERR_MAX_CONNECTIONS, ctx->userdata);
        free(ctx);
        return;
    }

    if (add_err == LP2P_ERR_ALREADY_CONNECTED) {
        /* Check tiebreak */
        lp2p_conn_t *existing = lp2p_connmgr_get(ctx->host->connmgr, &remote_peer);
        if (existing) {
            lp2p_conn_t *winner = lp2p_connmgr_tiebreak(ctx->host->connmgr,
                                                           &ctx->host->local_peer_id,
                                                           existing, conn);
            if (winner == existing) {
                /* Close the new connection, use existing */
                lp2p_conn_close(conn, host_conn_destroy_done, NULL);
                if (ctx->cb) ctx->cb(existing, LP2P_OK, ctx->userdata);
                free(ctx);
                return;
            }
            /* New connection wins — remove old one */
            lp2p_connmgr_remove(ctx->host->connmgr, existing);
            host_fire_disconn_callbacks(ctx->host, existing, LP2P_OK);
            lp2p_conn_close(existing, host_conn_destroy_done, NULL);
            lp2p_connmgr_add(ctx->host->connmgr, conn);
        }
    }

    /* Fire connection callbacks */
    host_fire_conn_callbacks(ctx->host, conn);

    /* Auto-start identify as dialer */
    lp2p_identify_dial(ctx->host, conn);

    if (ctx->cb) ctx->cb(conn, LP2P_OK, ctx->userdata);
    free(ctx);
}

lp2p_err_t lp2p_host_dial(lp2p_host_t *host, const char *multiaddr,
                            lp2p_dial_cb cb, void *userdata) {
    if (!host || !multiaddr) return LP2P_ERR_INVALID_ARG;

    /* Parse multiaddr */
    lp2p_multiaddr_t *ma = NULL;
    lp2p_err_t err = lp2p_multiaddr_parse(multiaddr, &ma);
    if (err != LP2P_OK) return err;

    /* Check for /p2p component — if present, check existing connection */
    lp2p_peer_id_t peer_id;
    bool has_peer = (lp2p_multiaddr_get_peer_id(ma, &peer_id) == LP2P_OK);

    if (has_peer) {
        lp2p_conn_t *existing = lp2p_connmgr_get(host->connmgr, &peer_id);
        if (existing) {
            lp2p_multiaddr_free(ma);
            if (cb) cb(existing, LP2P_OK, userdata);
            return LP2P_OK;
        }
    }

    /* Create dial context */
    dial_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) { lp2p_multiaddr_free(ma); return LP2P_ERR_NOMEM; }
    ctx->host     = host;
    ctx->cb       = cb;
    ctx->userdata = userdata;
    if (has_peer) {
        ctx->expected_peer     = peer_id;
        ctx->has_expected_peer = true;
    }

    /* Dial via the dialer */
    err = lp2p_dialer_dial(host->dialer, ma, host_on_raw_dial_conn, ctx);
    lp2p_multiaddr_free(ma);

    if (err != LP2P_OK) {
        free(ctx);
        return err;
    }

    return LP2P_OK;
}

lp2p_err_t lp2p_host_dial_peer(lp2p_host_t *host, const lp2p_peer_id_t *peer,
                                 lp2p_dial_cb cb, void *userdata) {
    if (!host || !peer) return LP2P_ERR_INVALID_ARG;

    /* Check connmgr for existing connection */
    lp2p_conn_t *existing = lp2p_connmgr_get(host->connmgr, peer);
    if (existing) {
        if (cb) cb(existing, LP2P_OK, userdata);
        return LP2P_OK;
    }

    /* Look up addresses in peerstore */
    lp2p_multiaddr_t **addrs = NULL;
    size_t addr_count = lp2p_peerstore_get_addrs(host->peerstore, peer, &addrs);
    if (addr_count == 0 || !addrs)
        return LP2P_ERR_NOT_FOUND;

    /* Try the first address (in production, we'd try multiple / parallel) */
    /* Add /p2p/<peer_id> component to the address */
    lp2p_multiaddr_t *full_addr = NULL;
    lp2p_err_t err = lp2p_multiaddr_with_peer_id(addrs[0], peer, &full_addr);

    lp2p_peerstore_free_addrs(addrs, addr_count);

    if (err != LP2P_OK) return err;

    const char *addr_str = lp2p_multiaddr_string(full_addr);
    if (!addr_str) {
        lp2p_multiaddr_free(full_addr);
        return LP2P_ERR_INTERNAL;
    }

    err = lp2p_host_dial(host, addr_str, cb, userdata);
    lp2p_multiaddr_free(full_addr);
    return err;
}

/* ── Stream handler registration ─────────────────────────────────────────── */

lp2p_err_t lp2p_host_set_stream_handler(lp2p_host_t *host, const char *protocol_id,
                                          lp2p_protocol_handler_fn handler,
                                          void *userdata) {
    if (!host || !protocol_id || !handler)
        return LP2P_ERR_INVALID_ARG;

    return lp2p_protocol_router_add(host->router, protocol_id, handler, userdata);
}

/* ── New stream ──────────────────────────────────────────────────────────── */

typedef struct {
    lp2p_host_t        *host;
    char               *protocol_id;
    lp2p_open_stream_cb  stream_cb;
} new_stream_ctx_t;

static void new_stream_dial_done(lp2p_conn_t *conn, lp2p_err_t err,
                                   void *userdata) {
    new_stream_ctx_t *ctx = userdata;

    if (err != LP2P_OK || !conn) {
        if (ctx->stream_cb) ctx->stream_cb(NULL, err, NULL);
        free(ctx->protocol_id);
        free(ctx);
        return;
    }

    /* Open stream on the connection */
    lp2p_err_t serr = lp2p_conn_open_stream(conn, ctx->protocol_id, ctx->stream_cb,
                                              NULL);
    if (serr != LP2P_OK) {
        if (ctx->stream_cb) ctx->stream_cb(NULL, serr, NULL);
    }

    free(ctx->protocol_id);
    free(ctx);
}

lp2p_err_t lp2p_host_new_stream(lp2p_host_t *host, const char *multiaddr,
                                  const char *protocol_id,
                                  lp2p_open_stream_cb cb) {
    if (!host || !multiaddr || !protocol_id)
        return LP2P_ERR_INVALID_ARG;

    new_stream_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return LP2P_ERR_NOMEM;
    ctx->host       = host;
    ctx->protocol_id = strdup(protocol_id);
    ctx->stream_cb   = cb;

    if (!ctx->protocol_id) {
        free(ctx);
        return LP2P_ERR_NOMEM;
    }

    return lp2p_host_dial(host, multiaddr, new_stream_dial_done, ctx);
}

/* ── Ping ────────────────────────────────────────────────────────────────── */

typedef struct {
    lp2p_host_t *host;
    lp2p_conn_t *conn;
    void       (*cb)(lp2p_err_t err, uint64_t rtt_us, void *userdata);
    void        *userdata;
} host_ping_ctx_t;

static void host_ping_on_stream(lp2p_stream_t *stream, lp2p_err_t err,
                                  void *userdata) {
    host_ping_ctx_t *ctx = userdata;

    if (err != LP2P_OK || !stream) {
        if (ctx->cb) ctx->cb(err, 0, ctx->userdata);
        free(ctx);
        return;
    }

    /* Use the stream-based ping initiator */
    lp2p_err_t perr = lp2p_ping_initiate(ctx->conn, stream,
                                           ctx->cb, ctx->userdata);
    if (perr != LP2P_OK) {
        if (ctx->cb) ctx->cb(perr, 0, ctx->userdata);
        lp2p_stream_reset(stream);
    }

    free(ctx);
}

lp2p_err_t lp2p_host_ping(lp2p_host_t *host, lp2p_conn_t *conn,
                            void (*cb)(lp2p_err_t err, uint64_t rtt_us,
                                       void *userdata),
                            void *userdata) {
    if (!host || !conn) return LP2P_ERR_INVALID_ARG;

    host_ping_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return LP2P_ERR_NOMEM;
    ctx->host     = host;
    ctx->conn     = conn;
    ctx->cb       = cb;
    ctx->userdata = userdata;

    lp2p_err_t err = lp2p_conn_open_stream(conn, PING_PROTOCOL_ID,
                                             host_ping_on_stream, ctx);
    if (err != LP2P_OK) {
        free(ctx);
        return err;
    }

    return LP2P_OK;
}

/* ── Introspection ───────────────────────────────────────────────────────── */

lp2p_peer_id_t lp2p_host_peer_id(const lp2p_host_t *host) {
    if (!host) {
        lp2p_peer_id_t empty = {0};
        return empty;
    }
    return host->local_peer_id;
}

lp2p_peerstore_t *lp2p_host_peerstore(lp2p_host_t *host) {
    return host ? host->peerstore : NULL;
}

bool lp2p_host_is_connected(const lp2p_host_t *host, const lp2p_peer_id_t *peer) {
    if (!host || !peer) return false;
    return lp2p_connmgr_get(host->connmgr, peer) != NULL;
}

/* ── Connection event callbacks ──────────────────────────────────────────── */

lp2p_err_t lp2p_host_on_connection(lp2p_host_t *host,
                                     void (*cb)(lp2p_host_t *host,
                                                lp2p_conn_t *conn,
                                                void *userdata),
                                     void *userdata) {
    if (!host || !cb) return LP2P_ERR_INVALID_ARG;
    if (host->on_conn_count >= LP2P_MAX_CALLBACKS) return LP2P_ERR_INTERNAL;

    host->on_conn_cbs[host->on_conn_count].cb       = cb;
    host->on_conn_cbs[host->on_conn_count].userdata  = userdata;
    host->on_conn_count++;
    return LP2P_OK;
}

lp2p_err_t lp2p_host_on_disconnect(lp2p_host_t *host,
                                     void (*cb)(lp2p_host_t *host,
                                                lp2p_conn_t *conn,
                                                lp2p_err_t reason,
                                                void *userdata),
                                     void *userdata) {
    if (!host || !cb) return LP2P_ERR_INVALID_ARG;
    if (host->on_disconn_count >= LP2P_MAX_CALLBACKS) return LP2P_ERR_INTERNAL;

    host->on_disconn_cbs[host->on_disconn_count].cb       = cb;
    host->on_disconn_cbs[host->on_disconn_count].userdata  = userdata;
    host->on_disconn_count++;
    return LP2P_OK;
}

/* ── Internal: fire callbacks ────────────────────────────────────────────── */

static void host_fire_conn_callbacks(lp2p_host_t *host, lp2p_conn_t *conn) {
    for (size_t i = 0; i < host->on_conn_count; i++) {
        host->on_conn_cbs[i].cb(host, conn, host->on_conn_cbs[i].userdata);
    }
}

static void host_fire_disconn_callbacks(lp2p_host_t *host, lp2p_conn_t *conn,
                                          lp2p_err_t reason) {
    for (size_t i = 0; i < host->on_disconn_count; i++) {
        host->on_disconn_cbs[i].cb(host, conn, reason,
                                    host->on_disconn_cbs[i].userdata);
    }
}

/* ── Inbound connection handling ─────────────────────────────────────────── */

static void host_finish_inbound_conn(lp2p_host_t *host, lp2p_conn_t *conn) {
    lp2p_peer_id_t remote_peer = lp2p_conn_peer_id(conn);

    if (!conn || !host) {
        return;
    }

    /* Set host on the connection */
    conn->host = host;

    /* Add to connection manager */
    lp2p_err_t err = lp2p_connmgr_add(host->connmgr, conn);
    if (err == LP2P_ERR_MAX_CONNECTIONS) {
        lp2p_conn_close(conn, host_conn_destroy_done, NULL);
        return;
    }

    if (err == LP2P_ERR_ALREADY_CONNECTED && host_conn_has_peer_id(conn)) {
        lp2p_conn_t *existing = lp2p_connmgr_get(host->connmgr, &remote_peer);
        if (existing) {
            lp2p_conn_t *winner = lp2p_connmgr_tiebreak(host->connmgr,
                                                           &host->local_peer_id,
                                                           existing, conn);
            if (winner == existing) {
                lp2p_conn_close(conn, host_conn_destroy_done, NULL);
                return;
            }
            /* Incoming wins — evict old */
            lp2p_connmgr_remove(host->connmgr, existing);
            host_fire_disconn_callbacks(host, existing, LP2P_OK);
            lp2p_conn_close(existing, host_conn_destroy_done, NULL);
            lp2p_connmgr_add(host->connmgr, conn);
        }
    }

    /* Fire connection callbacks */
    host_fire_conn_callbacks(host, conn);

    /* Auto-start identify (as dialer side — read remote's identify) */
    lp2p_identify_dial(host, conn);
}

static void host_on_inbound_raw_conn(lp2p_listener_t *listener, lp2p_conn_t *conn,
                                     void *userdata) {
    lp2p_host_t *host = userdata;
    (void)listener;

    if (!conn || !host || host->closing) {
        if (conn) {
            lp2p_tcp_conn_close((lp2p_tcp_conn_t *)conn, NULL, NULL);
        }
        return;
    }

    (void)host_upgrade_raw_conn(host, (lp2p_tcp_conn_t *)conn, true, NULL);
}

/* ── Inbound stream handling (called by mux layer) ───────────────────────── */

static void host_on_new_stream(lp2p_stream_t *stream, void *userdata) {
    lp2p_host_t *host = userdata;
    if (!host || !stream) return;

    /* Route to protocol router */
    lp2p_protocol_router_handle_stream(host->router, stream);
}
