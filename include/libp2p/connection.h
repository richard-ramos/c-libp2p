#ifndef LIBP2P_CONNECTION_H
#define LIBP2P_CONNECTION_H

#include "types.h"
#include "errors.h"
#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Open a new outbound stream on an existing READY connection. */
lp2p_err_t lp2p_conn_open_stream(lp2p_conn_t *conn, const char *protocol_id,
                                   lp2p_open_stream_cb cb, void *userdata);

/* Gracefully close one connection while leaving the host running. */
lp2p_err_t lp2p_conn_close(lp2p_conn_t *conn,
                             void (*cb)(lp2p_conn_t *conn, void *userdata),
                             void *userdata);

/* Introspection */
lp2p_peer_id_t          lp2p_conn_peer_id(const lp2p_conn_t *conn);
const lp2p_multiaddr_t *lp2p_conn_remote_addr(const lp2p_conn_t *conn);
const lp2p_multiaddr_t *lp2p_conn_local_addr(const lp2p_conn_t *conn);
bool                    lp2p_conn_is_inbound(const lp2p_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_CONNECTION_H */
