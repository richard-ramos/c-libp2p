#ifndef LP2P_TRANSPORT_H
#define LP2P_TRANSPORT_H

/* Internal transport vtable — not part of the public API */

#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/multiaddr.h"

typedef struct lp2p_transport lp2p_transport_t;

typedef struct {
    lp2p_err_t (*listen)(void *transport, const lp2p_multiaddr_t *addr,
                          void (*on_conn)(void *transport, lp2p_conn_t *conn,
                                          void *userdata),
                          void *userdata);
    lp2p_err_t (*dial)(void *transport, const lp2p_multiaddr_t *addr,
                        void (*on_conn)(lp2p_conn_t *conn, lp2p_err_t err, void *userdata),
                        void *userdata);
    void       (*close)(void *transport);
    bool       (*handles)(void *transport, const lp2p_multiaddr_t *addr);
} lp2p_transport_vtable_t;

struct lp2p_transport {
    const lp2p_transport_vtable_t *vtable;
    void                          *impl;
};

#endif /* LP2P_TRANSPORT_H */
