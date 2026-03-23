#ifndef LP2P_DIALER_H
#define LP2P_DIALER_H

#include <uv.h>
#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/multiaddr.h"
#include "transport/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lp2p_dialer lp2p_dialer_t;

typedef void (*lp2p_dialer_cb)(lp2p_conn_t *conn, lp2p_err_t err, void *userdata);

struct lp2p_dialer {
    uv_loop_t        *loop;
    lp2p_transport_t *transport;
    uint32_t          timeout_ms;
};

lp2p_err_t lp2p_dialer_new(uv_loop_t *loop,
                             lp2p_transport_t *transport,
                             uint32_t timeout_ms,
                             lp2p_dialer_t **out);
lp2p_err_t lp2p_dialer_dial(lp2p_dialer_t *dialer,
                              const lp2p_multiaddr_t *addr,
                              lp2p_dialer_cb cb,
                              void *userdata);
void       lp2p_dialer_free(lp2p_dialer_t *dialer);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_DIALER_H */
