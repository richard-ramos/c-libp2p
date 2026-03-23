/* src/host_internal.h — internal host structure */
#ifndef LP2P_HOST_INTERNAL_H
#define LP2P_HOST_INTERNAL_H

#include <uv.h>
#include "libp2p/types.h"
#include "libp2p/errors.h"
#include "libp2p/host.h"
#include "libp2p/multiaddr.h"
#include "libp2p/crypto.h"
#include "connmgr_internal.h"
#include "peerstore_internal.h"
#include "protocol_router.h"
#include "dialer.h"
#include "listener.h"
#include "transport/transport.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LP2P_MAX_LISTENERS   16
#define LP2P_MAX_CALLBACKS    16

typedef void (*lp2p_host_conn_cb)(lp2p_host_t *host, lp2p_conn_t *conn,
                                    void *userdata);
typedef void (*lp2p_host_disconn_cb)(lp2p_host_t *host, lp2p_conn_t *conn,
                                       lp2p_err_t reason, void *userdata);

typedef struct {
    lp2p_host_conn_cb  cb;
    void              *userdata;
} host_conn_cb_entry_t;

typedef struct {
    lp2p_host_disconn_cb  cb;
    void                 *userdata;
} host_disconn_cb_entry_t;

struct lp2p_host {
    uv_loop_t               *loop;

    /* Identity */
    lp2p_keypair_t           *keypair;
    lp2p_peer_id_t            local_peer_id;

    /* Configuration */
    lp2p_host_config_t        config;

    /* Subsystems */
    lp2p_peerstore_t         *peerstore;
    lp2p_connmgr_t           *connmgr;
    lp2p_protocol_router_t   *router;
    lp2p_dialer_t            *dialer;
    lp2p_transport_t         *transport;

    /* Listeners */
    lp2p_listener_t          *listeners[LP2P_MAX_LISTENERS];
    size_t                    listener_count;

    /* Listen addresses (parsed multiaddrs) */
    lp2p_multiaddr_t         *listen_mas[LP2P_MAX_LISTENERS];
    size_t                    listen_addrs_count;

    /* Connection event callbacks */
    host_conn_cb_entry_t      on_conn_cbs[LP2P_MAX_CALLBACKS];
    size_t                    on_conn_count;
    host_disconn_cb_entry_t   on_disconn_cbs[LP2P_MAX_CALLBACKS];
    size_t                    on_disconn_count;

    /* Close state */
    bool                      closing;
    void                    (*close_cb)(lp2p_host_t *host, void *userdata);
    void                     *close_ud;
    uint32_t                  close_pending; /* number of conns/listeners draining */
};

#ifdef __cplusplus
}
#endif

#endif /* LP2P_HOST_INTERNAL_H */
