/* src/protocol/ping_internal.h — ping protocol internal API */
#ifndef LP2P_PING_INTERNAL_H
#define LP2P_PING_INTERNAL_H

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/stream.h"
#include "libp2p/protocol.h"

#define PING_PROTOCOL_ID "/ipfs/ping/1.0.0"

/* Inbound stream handler — registered in protocol router */
void lp2p_ping_handler(lp2p_stream_t *stream, void *userdata);

/* Start a ping on a connection (opens a new stream internally).
 * The callback receives the RTT in microseconds on success. */
lp2p_err_t lp2p_ping_start(lp2p_conn_t *conn,
                             void (*cb)(lp2p_err_t err, uint64_t rtt_us,
                                        void *userdata),
                             void *userdata);

/* Start ping on an already-opened stream (used when host manages stream opening) */
lp2p_err_t lp2p_ping_initiate(lp2p_conn_t *conn,
                                lp2p_stream_t *stream,
                                void (*cb)(lp2p_err_t err, uint64_t rtt_us,
                                           void *userdata),
                                void *userdata);

#endif /* LP2P_PING_INTERNAL_H */
