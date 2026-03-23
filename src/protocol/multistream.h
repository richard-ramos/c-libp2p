#ifndef LP2P_MULTISTREAM_H
#define LP2P_MULTISTREAM_H

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "transport/tcp/tcp_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MULTISTREAM_PROTOCOL_ID "/multistream/1.0.0"
#define MULTISTREAM_NA          "na"
#define MULTISTREAM_MAX_MSG_LEN 1024

/* ── Varint helpers for multistream wire format ───────────────────────────── */
size_t ms_varint_encode(uint64_t val, uint8_t *buf);
int    ms_varint_decode(const uint8_t *buf, size_t len, uint64_t *out, size_t *consumed);

/* ── Frame encode/decode ──────────────────────────────────────────────────── */
/* Encode a message with varint-length prefix + newline:
   <varint: len(msg+'\n')><msg>\n
   Returns total bytes written to out_buf, or 0 on error. */
size_t ms_frame_encode(const char *msg, uint8_t *out_buf, size_t out_cap);

/* Attempt to decode a frame from a buffer. Returns:
 *  >0 : total frame bytes consumed; *out_msg points into buf, *out_msg_len set
 *   0 : need more data
 *  -1 : protocol error */
int ms_frame_decode(const uint8_t *buf, size_t len,
                    const uint8_t **out_msg, size_t *out_msg_len);

/* ── Negotiation state machine ────────────────────────────────────────────── */
typedef enum {
    MS_STATE_SEND_HEADER,
    MS_STATE_RECV_HEADER,
    MS_STATE_SEND_PROPOSAL,
    MS_STATE_RECV_PROPOSAL,
    MS_STATE_SEND_ACCEPT,
    MS_STATE_RECV_ACCEPT,
    MS_STATE_DONE,
    MS_STATE_FAILED,
} ms_state_t;

typedef struct {
    ms_state_t   state;
    bool         is_initiator;

    /* Protocol list for responder */
    const char **supported_protos;
    size_t       supported_protos_count;

    /* Initiator's proposed protocol */
    char         proposed_proto[256];

    /* Result */
    char         negotiated_proto[256];

    /* I/O buffer for accumulating partial frames */
    uint8_t      recv_buf[MULTISTREAM_MAX_MSG_LEN * 2];
    size_t       recv_buf_len;
} ms_negotiation_t;

/* High-level callback-based negotiation over a TCP connection */
typedef void (*ms_negotiate_cb)(lp2p_err_t err, const char *protocol, void *userdata);

/* Initiator: negotiate protocol_id over the raw TCP connection */
lp2p_err_t ms_negotiate_initiator(lp2p_tcp_conn_t *tc,
                                   const char *protocol_id,
                                   ms_negotiate_cb cb, void *userdata);

/* Responder: accept a negotiation, choosing from supported protocols */
lp2p_err_t ms_negotiate_responder(lp2p_tcp_conn_t *tc,
                                   const char **supported_protos,
                                   size_t count,
                                   ms_negotiate_cb cb, void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_MULTISTREAM_H */
