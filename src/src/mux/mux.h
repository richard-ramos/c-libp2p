#ifndef LP2P_MUX_H
#define LP2P_MUX_H

/* Internal mux vtable — not part of the public API */

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/stream.h"

typedef struct {
    lp2p_err_t (*open_stream)(void *session, lp2p_stream_t **out);
    lp2p_err_t (*write_stream)(void *session, lp2p_stream_t *stream,
                                const uint8_t *data, size_t len,
                                lp2p_stream_write_cb cb, void *userdata);
    lp2p_err_t (*close_stream)(void *session, lp2p_stream_t *stream);
    lp2p_err_t (*reset_stream)(void *session, lp2p_stream_t *stream);
    lp2p_err_t (*on_data)(void *session, const uint8_t *data, size_t len);
    lp2p_err_t (*go_away)(void *session, uint32_t error_code);
    void       (*free)(void *session);
} lp2p_mux_vtable_t;

typedef struct {
    const lp2p_mux_vtable_t *vtable;
    void                    *impl;
} lp2p_mux_session_t;

#endif /* LP2P_MUX_H */
