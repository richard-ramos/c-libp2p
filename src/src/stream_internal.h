/* src/stream_internal.h — internal stream definitions */
#ifndef LP2P_STREAM_INTERNAL_H
#define LP2P_STREAM_INTERNAL_H

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/stream.h"
#include "mux/mux.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * The lp2p_stream_t is the public-facing stream handle.
 * Each mux implementation embeds it at the start of its own stream struct
 * (e.g., yamux_stream_t). The stream.c layer delegates to the mux vtable
 * via the mux_session pointer.
 */
struct lp2p_stream {
    lp2p_mux_session_t  *mux_session;   /* back-pointer to the mux session */
    lp2p_conn_t         *conn;          /* owning connection */
    char                *protocol_id;   /* negotiated protocol */
    void                *userdata;      /* app userdata */
};

#ifdef __cplusplus
}
#endif

#endif /* LP2P_STREAM_INTERNAL_H */
