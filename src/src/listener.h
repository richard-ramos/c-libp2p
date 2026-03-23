#ifndef LP2P_LISTENER_H
#define LP2P_LISTENER_H

#include <uv.h>
#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/multiaddr.h"
#include "transport/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct lp2p_listener lp2p_listener_t;

typedef void (*lp2p_listener_conn_cb)(lp2p_listener_t *listener,
                                       lp2p_conn_t *conn,
                                       void *userdata);
typedef void (*lp2p_listener_error_cb)(lp2p_listener_t *listener,
                                        lp2p_err_t err,
                                        void *userdata);

struct lp2p_listener {
    uv_loop_t            *loop;
    lp2p_transport_t     *transport;
    lp2p_multiaddr_t     *listen_addr;
    bool                  active;

    lp2p_listener_conn_cb  on_conn;
    void                  *on_conn_ud;
    lp2p_listener_error_cb on_error;
    void                  *on_error_ud;
};

lp2p_err_t lp2p_listener_new(uv_loop_t *loop,
                               lp2p_transport_t *transport,
                               const lp2p_multiaddr_t *addr,
                               lp2p_listener_t **out);
lp2p_err_t lp2p_listener_start(lp2p_listener_t *listener,
                                 lp2p_listener_conn_cb on_conn,
                                 void *userdata);
lp2p_err_t lp2p_listener_close(lp2p_listener_t *listener);
void       lp2p_listener_free(lp2p_listener_t *listener);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_LISTENER_H */
