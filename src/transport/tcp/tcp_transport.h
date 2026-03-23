#ifndef LP2P_TCP_TRANSPORT_H
#define LP2P_TCP_TRANSPORT_H

#include <uv.h>
#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/multiaddr.h"
#include "transport/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── TCP raw connection (pre-upgrade) ─────────────────────────────────────── */
typedef struct lp2p_tcp_conn {
    uv_tcp_t         handle;
    uv_loop_t       *loop;
    bool             is_inbound;
    struct sockaddr_storage  local_addr;
    struct sockaddr_storage  remote_addr;

    /* Read state */
    uint8_t         *read_buf;
    size_t           read_buf_cap;
    size_t           read_buf_len;
    bool             reading;

    /* Callbacks for the connection layer */
    void           (*on_read)(struct lp2p_tcp_conn *tc, const uint8_t *data,
                              size_t len, lp2p_err_t err, void *userdata);
    void            *on_read_ud;

    /* Close state */
    bool             closing;
    void           (*on_close)(struct lp2p_tcp_conn *tc, void *userdata);
    void            *on_close_ud;
} lp2p_tcp_conn_t;

/* ── TCP transport ────────────────────────────────────────────────────────── */
typedef struct lp2p_tcp_transport {
    uv_loop_t   *loop;

    /* Listener state */
    uv_tcp_t     server;
    bool         listening;
    void       (*on_conn)(void *transport, lp2p_conn_t *conn);
    void        *on_conn_ud;
} lp2p_tcp_transport_t;

/* ── Dial context (pending outbound connection) ───────────────────────────── */
typedef struct {
    lp2p_tcp_transport_t *transport;
    uv_tcp_t             *tcp_handle;
    uv_connect_t          connect_req;
    void                (*on_conn)(lp2p_conn_t *conn, lp2p_err_t err, void *userdata);
    void                 *userdata;
} lp2p_tcp_dial_ctx_t;

/* ── API ──────────────────────────────────────────────────────────────────── */
lp2p_err_t lp2p_tcp_transport_new(uv_loop_t *loop, lp2p_transport_t **out);
void       lp2p_tcp_transport_free(lp2p_transport_t *t);

/* TCP raw connection ops */
lp2p_err_t lp2p_tcp_conn_start_read(lp2p_tcp_conn_t *tc,
    void (*cb)(lp2p_tcp_conn_t *tc, const uint8_t *data, size_t len,
               lp2p_err_t err, void *userdata),
    void *userdata);
lp2p_err_t lp2p_tcp_conn_write(lp2p_tcp_conn_t *tc, const uint8_t *data, size_t len,
    void (*cb)(lp2p_tcp_conn_t *tc, lp2p_err_t err, void *userdata),
    void *userdata);
void       lp2p_tcp_conn_close(lp2p_tcp_conn_t *tc,
    void (*cb)(lp2p_tcp_conn_t *tc, void *userdata), void *userdata);
void       lp2p_tcp_conn_consume(lp2p_tcp_conn_t *tc, size_t n);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_TCP_TRANSPORT_H */
