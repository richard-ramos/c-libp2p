/* src/mux/yamux/yamux_internal.h — yamux multiplexer internals */
#ifndef LP2P_YAMUX_INTERNAL_H
#define LP2P_YAMUX_INTERNAL_H

#include <uv.h>
#include <stdint.h>
#include <stdbool.h>
#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/stream.h"
#include "mux/mux.h"
#include "stream_internal.h"
#include "util/buffer.h"
#include "util/list.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Yamux wire constants ─────────────────────────────────────────────────── */
#define YAMUX_VERSION         0
#define YAMUX_HEADER_SIZE     12
#define YAMUX_DEFAULT_WINDOW  (256 * 1024)   /* 256 KiB */
#define YAMUX_MAX_STREAMS     256
#define YAMUX_KEEPALIVE_SEC   30
#define YAMUX_GOAWAY_TIMEOUT  5000  /* ms */

/* Frame types */
#define YAMUX_TYPE_DATA          0
#define YAMUX_TYPE_WINDOW_UPDATE 1
#define YAMUX_TYPE_PING          2
#define YAMUX_TYPE_GO_AWAY       3

/* Flags */
#define YAMUX_FLAG_SYN  0x0001
#define YAMUX_FLAG_ACK  0x0002
#define YAMUX_FLAG_FIN  0x0004
#define YAMUX_FLAG_RST  0x0008

/* GoAway error codes */
#define YAMUX_GOAWAY_NORMAL        0
#define YAMUX_GOAWAY_PROTOCOL_ERR  1
#define YAMUX_GOAWAY_INTERNAL_ERR  2

/* ── Yamux frame header (parsed) ──────────────────────────────────────────── */
typedef struct {
    uint8_t  version;
    uint8_t  type;
    uint16_t flags;
    uint32_t stream_id;
    uint32_t length;
} yamux_header_t;

/* ── Stream state ─────────────────────────────────────────────────────────── */
typedef enum {
    YAMUX_STREAM_INIT,
    YAMUX_STREAM_SYN_SENT,
    YAMUX_STREAM_SYN_RECV,
    YAMUX_STREAM_ESTABLISHED,
    YAMUX_STREAM_LOCAL_CLOSE,   /* we sent FIN */
    YAMUX_STREAM_REMOTE_CLOSE,  /* peer sent FIN */
    YAMUX_STREAM_CLOSED,
    YAMUX_STREAM_RESET,
} yamux_stream_state_t;

/* Forward decl */
typedef struct yamux_session yamux_session_t;

/* ── Per-stream write request ─────────────────────────────────────────────── */
typedef struct yamux_write_req {
    lp2p_list_node_t      node;
    uint8_t              *data;
    size_t                len;
    size_t                offset;       /* bytes already sent */
    lp2p_stream_write_cb  cb;
    void                 *userdata;
    lp2p_stream_t        *stream;
    bool                  is_close;     /* FIN frame after data */
} yamux_write_req_t;

/* ── Yamux stream ─────────────────────────────────────────────────────────── */
typedef struct yamux_stream {
    lp2p_stream_t          pub;           /* public handle — must be first */
    yamux_session_t       *session;
    uint32_t               id;
    yamux_stream_state_t   state;

    /* Flow control */
    uint32_t               recv_window;   /* our receive window (how much peer can send) */
    uint32_t               send_window;   /* peer's receive window (how much we can send) */

    /* Read state — at most one outstanding read */
    bool                   read_pending;
    bool                   read_lp;       /* length-prefixed read? */
    size_t                 read_max;
    lp2p_stream_read_cb    read_cb;
    void                  *read_ud;

    /* Receive buffer — data arrived before app read request */
    lp2p_buffer_t          recv_buf;

    /* Write queue */
    lp2p_list_t            write_queue;
    size_t                 write_buf_bytes;  /* total queued bytes */
    size_t                 max_write_buf;

    /* Protocol ID (set after multistream negotiation) */
    char                  *protocol_id;

    /* User data */
    void                  *userdata;

    /* Close callback */
    lp2p_stream_write_cb   close_cb;
    void                  *close_ud;

    /* Link in session's stream list */
    lp2p_list_node_t       node;
} yamux_stream_t;

/* ── Yamux session ────────────────────────────────────────────────────────── */
struct yamux_session {
    uv_loop_t             *loop;
    bool                   is_initiator;  /* dialer = true */
    uint32_t               next_stream_id;

    /* Streams indexed by ID — simple array for now */
    yamux_stream_t        *streams[YAMUX_MAX_STREAMS];
    size_t                 stream_count;

    /* All streams in a linked list for iteration */
    lp2p_list_t            stream_list;

    /* Receive buffer for partial frame parsing */
    lp2p_buffer_t          recv_buf;

    /* Currently parsing header? */
    bool                   in_header;
    yamux_header_t         cur_header;
    size_t                 body_remaining;

    /* Keepalive */
    uv_timer_t             keepalive_timer;
    uint32_t               ping_id;
    bool                   ping_outstanding;
    uint32_t               keepalive_interval; /* seconds */

    /* GoAway */
    bool                   local_goaway;
    bool                   remote_goaway;
    uv_timer_t             goaway_timer;

    /* Outbound frame queue — yamux frames ready to go on the wire */
    lp2p_list_t            out_queue;
    bool                   writing;

    /* Callback to push encrypted/raw bytes to the transport layer below */
    void                 (*on_send)(const uint8_t *data, size_t len,
                                    void *userdata);
    void                  *on_send_ud;

    /* Callback when a new inbound stream is opened by the remote */
    void                 (*on_stream)(yamux_session_t *session,
                                      lp2p_stream_t *stream, void *userdata);
    void                  *on_stream_ud;

    /* Async handle to defer callbacks to next event-loop iteration */
    uv_async_t             async_handle;
    lp2p_list_t            deferred_cbs;

    bool                   closed;
};

/* ── Deferred callback entry ──────────────────────────────────────────────── */
typedef void (*yamux_deferred_fn)(void *arg);
typedef struct {
    lp2p_list_node_t  node;
    yamux_deferred_fn fn;
    void             *arg;
} yamux_deferred_t;

/* ── Outbound frame entry ─────────────────────────────────────────────────── */
typedef struct {
    lp2p_list_node_t  node;
    uint8_t          *data;
    size_t            len;
    yamux_write_req_t *write_req;  /* if non-NULL, complete this after sending */
} yamux_out_frame_t;

/* ── API ──────────────────────────────────────────────────────────────────── */

/* Create a new yamux session. is_initiator: dialer=true, listener=false */
yamux_session_t *yamux_session_new(
    uv_loop_t *loop,
    bool is_initiator,
    void (*on_send)(const uint8_t *data, size_t len, void *userdata),
    void *on_send_ud,
    void (*on_stream)(yamux_session_t *session, lp2p_stream_t *stream, void *userdata),
    void *on_stream_ud
);

/* Free a yamux session (closes all streams) */
void yamux_session_free(yamux_session_t *session);

/* Feed received data from the transport into yamux */
lp2p_err_t yamux_session_on_data(yamux_session_t *session,
                                  const uint8_t *data, size_t len);

/* Open a new outbound stream */
lp2p_err_t yamux_session_open_stream(yamux_session_t *session,
                                      lp2p_stream_t **out);

/* Send GoAway */
lp2p_err_t yamux_session_go_away(yamux_session_t *session, uint32_t error_code);

/* Get the mux vtable for yamux */
const lp2p_mux_vtable_t *yamux_get_vtable(void);

/* ── Internal helpers ─────────────────────────────────────────────────────── */
void yamux_header_encode(const yamux_header_t *h, uint8_t buf[YAMUX_HEADER_SIZE]);
bool yamux_header_decode(const uint8_t buf[YAMUX_HEADER_SIZE], yamux_header_t *h);

void yamux_send_frame(yamux_session_t *session, uint8_t type, uint16_t flags,
                      uint32_t stream_id, uint32_t length,
                      const uint8_t *payload, size_t payload_len,
                      yamux_write_req_t *req);
void yamux_flush_out_queue(yamux_session_t *session);

yamux_stream_t *yamux_stream_lookup(yamux_session_t *session, uint32_t id);
void yamux_stream_deliver_data(yamux_stream_t *ys);
void yamux_stream_free(yamux_stream_t *ys);

void yamux_defer(yamux_session_t *session, yamux_deferred_fn fn, void *arg);
void yamux_stream_flush_writes(yamux_stream_t *ys);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_YAMUX_INTERNAL_H */
