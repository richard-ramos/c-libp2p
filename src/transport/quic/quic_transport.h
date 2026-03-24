/* src/transport/quic/quic_transport.h — internal QUIC transport types */
#ifndef LP2P_QUIC_TRANSPORT_H
#define LP2P_QUIC_TRANSPORT_H

#include <uv.h>
#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/multiaddr.h"
#include "stream_internal.h"
#include "transport/transport.h"
#include "util/buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Forward declarations */
typedef struct quic_transport   quic_transport_t;
typedef struct quic_conn        quic_conn_t;
typedef struct quic_stream      quic_stream_t;
typedef struct quic_write_chunk quic_write_chunk_t;
typedef struct quic_local_cid   quic_local_cid_t;

/* ── QUIC stream (maps to lp2p_stream_t) ─────────────────────────────────── */
struct quic_stream {
    lp2p_stream_t    pub;
    int64_t          stream_id;
    quic_conn_t     *qconn;

    /* Receive buffer */
    lp2p_buffer_t    recv_buf;

    /* Read state */
    bool             read_pending;
    bool             read_lp;
    size_t           read_max;
    lp2p_stream_read_cb read_cb;
    void            *read_ud;

    /* Lifecycle callbacks */
    lp2p_stream_write_cb close_cb;
    void                *close_ud;

    /* App data kept alive for retransmission until stream teardown */
    quic_write_chunk_t *send_head;
    quic_write_chunk_t *send_tail;
    quic_write_chunk_t *retained_head;
    quic_write_chunk_t *retained_tail;

    /* Absolute stream offsets for send-buffer lifetime tracking */
    uint64_t          next_send_offset;
    uint64_t          acked_offset;

    /* Stream state */
    bool             inbound_notified;
    bool             fin_received;
    bool             fin_sent;
    bool             reset;

    /* Linked list of streams on a connection */
    quic_stream_t   *next;
};

/* ── QUIC connection ─────────────────────────────────────────────────────── */
typedef enum {
    QUIC_CONN_HANDSHAKING,
    QUIC_CONN_READY,
    QUIC_CONN_CLOSING,
    QUIC_CONN_CLOSED,
} quic_conn_state_t;

struct quic_conn {
    lp2p_conn_t             *pub_conn;
    quic_transport_t        *transport;
    ngtcp2_conn             *conn;
    ngtcp2_crypto_conn_ref   conn_ref;
    SSL                     *ssl;
    SSL_CTX                 *ssl_ctx;

    quic_conn_state_t        state;
    bool                     is_server;

    /* Remote peer info */
    struct sockaddr_storage  remote_addr;
    struct sockaddr_storage  local_addr;
    ngtcp2_cid               scid;
    ngtcp2_cid               dcid;

    /* Peer identity (extracted from TLS cert after handshake) */
    lp2p_peer_id_t           remote_peer_id;
    bool                     peer_id_verified;

    /* Expected peer ID from dial target (optional) */
    lp2p_peer_id_t           expected_peer_id;
    bool                     has_expected_peer_id;

    /* Timer for ngtcp2 expiry */
    uv_timer_t               timer;
    bool                     timer_initialized;

    /* Send buffer */
    uint8_t                  send_buf[65536];

    /* Streams on this connection */
    quic_stream_t           *streams;
    quic_local_cid_t        *local_cids;

    /* Callbacks */
    void                   (*on_conn_cb)(lp2p_conn_t *conn, lp2p_err_t err, void *userdata);
    void                    *on_conn_ud;
    void                   (*on_inbound_cb)(void *transport, lp2p_conn_t *conn,
                                            void *userdata);
    void                    *on_inbound_ud;

    /* Linked list for transport's connection tracking */
    quic_conn_t             *next;
    size_t                   close_handles_pending;
    bool                     cleanup_started;
};

struct quic_local_cid {
    ngtcp2_cid        cid;
    quic_local_cid_t *next;
};

/* ── QUIC transport ──────────────────────────────────────────────────────── */
struct quic_transport {
    uv_loop_t               *loop;
    const lp2p_keypair_t    *keypair;

    /* Listener state */
    uv_udp_t                 udp_server;
    bool                     udp_initialized;
    bool                     listening;
    struct sockaddr_storage  listen_addr;
    SSL_CTX                 *server_ssl_ctx;

    void                   (*on_conn)(void *transport, lp2p_conn_t *conn,
                                      void *userdata);
    void                    *on_conn_ud;

    /* All active connections */
    quic_conn_t             *conns;
};

/* ── Public API ──────────────────────────────────────────────────────────── */
lp2p_err_t lp2p_quic_transport_new(uv_loop_t *loop, const lp2p_keypair_t *keypair,
                                    lp2p_transport_t **out);
void       lp2p_quic_transport_free(lp2p_transport_t *t);

lp2p_err_t lp2p_quic_conn_open_stream_raw(lp2p_conn_t *conn, lp2p_stream_t **out);
void       lp2p_quic_conn_notify_pending_streams(lp2p_conn_t *conn);
lp2p_err_t lp2p_quic_conn_close(lp2p_conn_t *conn);
void       lp2p_quic_conn_cleanup(lp2p_conn_t *conn);

lp2p_err_t lp2p_quic_stream_read(lp2p_stream_t *stream, size_t max_bytes,
                                  lp2p_stream_read_cb cb, void *userdata);
lp2p_err_t lp2p_quic_stream_read_lp(lp2p_stream_t *stream, size_t max_frame_len,
                                     lp2p_stream_read_cb cb, void *userdata);
lp2p_err_t lp2p_quic_stream_write(lp2p_stream_t *stream, const lp2p_buf_t *buf,
                                   lp2p_stream_write_cb cb, void *userdata);
lp2p_err_t lp2p_quic_stream_close(lp2p_stream_t *stream, lp2p_stream_write_cb cb,
                                   void *userdata);
lp2p_err_t lp2p_quic_stream_reset(lp2p_stream_t *stream);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_QUIC_TRANSPORT_H */
