#ifndef LIBP2P_PROTOCOL_H
#define LIBP2P_PROTOCOL_H

#include "types.h"
#include "stream.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*lp2p_protocol_handler_fn)(lp2p_stream_t *stream, void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* LIBP2P_PROTOCOL_H */
