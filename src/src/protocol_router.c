/* src/protocol_router.c — protocol multiplexing router */

#include <stdlib.h>
#include <string.h>

#include "protocol_router.h"
#include "libp2p/stream.h"
#include "libp2p/errors.h"

/* -------------------------------------------------------------------------- */
/* Construction / destruction                                                  */
/* -------------------------------------------------------------------------- */

lp2p_protocol_router_t *lp2p_protocol_router_new(uv_loop_t *loop) {
    if (!loop) return NULL;
    lp2p_protocol_router_t *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->loop = loop;
    r->entry_count = 0;
    return r;
}

void lp2p_protocol_router_free(lp2p_protocol_router_t *router) {
    if (!router) return;
    for (size_t i = 0; i < router->entry_count; i++) {
        free(router->entries[i].protocol_id);
    }
    free(router);
}

/* -------------------------------------------------------------------------- */
/* Registration                                                                */
/* -------------------------------------------------------------------------- */

lp2p_err_t lp2p_protocol_router_add(lp2p_protocol_router_t *router,
                                      const char *protocol_id,
                                      lp2p_protocol_handler_fn handler,
                                      void *userdata) {
    if (!router || !protocol_id || !handler)
        return LP2P_ERR_INVALID_ARG;

    /* Check for duplicate — update in place */
    for (size_t i = 0; i < router->entry_count; i++) {
        if (strcmp(router->entries[i].protocol_id, protocol_id) == 0) {
            router->entries[i].handler  = handler;
            router->entries[i].userdata = userdata;
            return LP2P_OK;
        }
    }

    if (router->entry_count >= LP2P_MAX_PROTOCOLS)
        return LP2P_ERR_INTERNAL;

    char *id = strdup(protocol_id);
    if (!id) return LP2P_ERR_NOMEM;

    lp2p_protocol_entry_t *e = &router->entries[router->entry_count++];
    e->protocol_id = id;
    e->handler     = handler;
    e->userdata    = userdata;
    return LP2P_OK;
}

lp2p_err_t lp2p_protocol_router_remove(lp2p_protocol_router_t *router,
                                         const char *protocol_id) {
    if (!router || !protocol_id)
        return LP2P_ERR_INVALID_ARG;

    for (size_t i = 0; i < router->entry_count; i++) {
        if (strcmp(router->entries[i].protocol_id, protocol_id) == 0) {
            free(router->entries[i].protocol_id);
            /* Shift remaining entries */
            size_t remaining = router->entry_count - i - 1;
            if (remaining > 0)
                memmove(&router->entries[i], &router->entries[i + 1],
                        remaining * sizeof(lp2p_protocol_entry_t));
            router->entry_count--;
            return LP2P_OK;
        }
    }
    return LP2P_ERR_NOT_FOUND;
}

/* -------------------------------------------------------------------------- */
/* Stream handling                                                             */
/* -------------------------------------------------------------------------- */

/*
 * For inbound streams, the yamux layer has already opened the stream.
 * The multistream-select negotiation happens at the stream level (LP-framed
 * messages over the mux stream), NOT over the raw TCP connection.
 *
 * Since multistream negotiation over mux streams is an async state machine,
 * we implement a simplified synchronous-style handler here:
 *   1. Read multistream header (/multistream/1.0.0\n)
 *   2. Read proposed protocol
 *   3. If we support it, echo it back and dispatch
 *   4. If not, send "na\n" and reset
 *
 * In practice, for an MVP, the connection/mux layer performs the multistream
 * negotiation before delivering the stream to us with the protocol already set.
 * So handle_stream just looks up the protocol and dispatches.
 */

void lp2p_protocol_router_handle_stream(lp2p_protocol_router_t *router,
                                          lp2p_stream_t *stream) {
    if (!router || !stream) return;

    const char *proto = lp2p_stream_protocol(stream);
    if (!proto) {
        lp2p_stream_reset(stream);
        return;
    }

    for (size_t i = 0; i < router->entry_count; i++) {
        if (strcmp(router->entries[i].protocol_id, proto) == 0) {
            router->entries[i].handler(stream, router->entries[i].userdata);
            return;
        }
    }

    /* No handler found — reset the stream */
    lp2p_stream_reset(stream);
}

/* -------------------------------------------------------------------------- */
/* Introspection                                                               */
/* -------------------------------------------------------------------------- */

size_t lp2p_protocol_router_get_protocols(const lp2p_protocol_router_t *router,
                                            const char **out, size_t max) {
    if (!router || !out) return 0;
    size_t n = router->entry_count < max ? router->entry_count : max;
    for (size_t i = 0; i < n; i++) {
        out[i] = router->entries[i].protocol_id;
    }
    return n;
}
