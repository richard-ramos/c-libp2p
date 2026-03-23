/* src/protocol/identify_internal.h — identify protocol internal API */
#ifndef LP2P_IDENTIFY_INTERNAL_H
#define LP2P_IDENTIFY_INTERNAL_H

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/stream.h"
#include "libp2p/protocol.h"

#define IDENTIFY_PROTOCOL_ID      "/ipfs/id/1.0.0"
#define IDENTIFY_PUSH_PROTOCOL_ID "/ipfs/id/push/1.0.0"
#define IDENTIFY_PROTOCOL_VERSION "ipfs/0.1.0"
#define IDENTIFY_AGENT_VERSION    "c-libp2p/0.1.0"
#define IDENTIFY_MAX_MSG_SIZE     (64 * 1024)  /* 64 KiB max identify message */

/* Inbound handler for /ipfs/id/1.0.0 — sends our identify info as listener */
void lp2p_identify_handler(lp2p_stream_t *stream, void *userdata);

/* Inbound handler for /ipfs/id/push/1.0.0 — receives remote identify push */
void lp2p_identify_push_handler(lp2p_stream_t *stream, void *userdata);

/* Dialer side: after connection is READY, open /ipfs/id/1.0.0 and read
 * the remote's identify message. Updates peerstore. */
lp2p_err_t lp2p_identify_dial(struct lp2p_host *host, lp2p_conn_t *conn);

/* Push our identify info to all connected peers
 * (called when listen addresses change) */
lp2p_err_t lp2p_identify_push_all(struct lp2p_host *host);

#endif /* LP2P_IDENTIFY_INTERNAL_H */
