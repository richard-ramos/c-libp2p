/* src/protocol_router.h — protocol router internal header */
#ifndef LP2P_PROTOCOL_ROUTER_H
#define LP2P_PROTOCOL_ROUTER_H

#include <uv.h>
#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/protocol.h"
#include "libp2p/stream.h"
#include "util/map.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LP2P_MAX_PROTOCOLS 64

typedef struct {
    char                     *protocol_id;
    lp2p_protocol_handler_fn  handler;
    void                     *userdata;
} lp2p_protocol_entry_t;

typedef struct lp2p_protocol_router {
    uv_loop_t              *loop;
    lp2p_protocol_entry_t   entries[LP2P_MAX_PROTOCOLS];
    size_t                  entry_count;
} lp2p_protocol_router_t;

lp2p_protocol_router_t *lp2p_protocol_router_new(uv_loop_t *loop);
void  lp2p_protocol_router_free(lp2p_protocol_router_t *router);

lp2p_err_t lp2p_protocol_router_add(lp2p_protocol_router_t *router,
                                      const char *protocol_id,
                                      lp2p_protocol_handler_fn handler,
                                      void *userdata);
lp2p_err_t lp2p_protocol_router_remove(lp2p_protocol_router_t *router,
                                         const char *protocol_id);

/* Called by the connection layer when a new inbound stream is opened.
 * Runs multistream-select as responder and routes to the matched handler. */
void lp2p_protocol_router_handle_stream(lp2p_protocol_router_t *router,
                                          lp2p_stream_t *stream);

/* Get array of registered protocol IDs (pointers into entries, do not free).
 * Returns count. */
size_t lp2p_protocol_router_get_protocols(const lp2p_protocol_router_t *router,
                                            const char **out, size_t max);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_PROTOCOL_ROUTER_H */
