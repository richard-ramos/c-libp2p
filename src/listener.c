/* src/listener.c — inbound connection acceptance, triggers connection pipeline */

#include "listener.h"
#include "transport/tcp/tcp_transport.h"
#include <stdlib.h>
#include <string.h>

/* ── on_conn callback from the transport layer ────────────────────────────── */
static void listener_on_transport_conn(void *transport, lp2p_conn_t *conn)
{
    /* The transport passes us a raw TCP connection (cast as lp2p_conn_t*).
       We forward it to whoever registered with the listener. */
    lp2p_tcp_transport_t *impl = (lp2p_tcp_transport_t *)transport;

    /* Walk back to our listener via the transport's userdata.
       We stored the listener pointer in on_conn_ud. */
    lp2p_listener_t *listener = (lp2p_listener_t *)impl->on_conn_ud;
    if (listener && listener->on_conn) {
        listener->on_conn(listener, conn, listener->on_conn_ud);
    }
}

/* ── Public API ───────────────────────────────────────────────────────────── */

lp2p_err_t lp2p_listener_new(uv_loop_t *loop,
                               lp2p_transport_t *transport,
                               const lp2p_multiaddr_t *addr,
                               lp2p_listener_t **out)
{
    if (!loop || !transport || !addr || !out) return LP2P_ERR_INVALID_ARG;

    lp2p_listener_t *l = calloc(1, sizeof(*l));
    if (!l) return LP2P_ERR_NOMEM;

    l->loop      = loop;
    l->transport = transport;
    l->active    = false;

    /* Clone the multiaddr — we parse the string representation */
    const char *ma_str = lp2p_multiaddr_string(addr);
    if (!ma_str) {
        free(l);
        return LP2P_ERR_INVALID_MULTIADDR;
    }

    lp2p_err_t err = lp2p_multiaddr_parse(ma_str, &l->listen_addr);
    if (err != LP2P_OK) {
        free(l);
        return err;
    }

    *out = l;
    return LP2P_OK;
}

lp2p_err_t lp2p_listener_start(lp2p_listener_t *listener,
                                 lp2p_listener_conn_cb on_conn,
                                 void *userdata)
{
    if (!listener || !on_conn) return LP2P_ERR_INVALID_ARG;
    if (listener->active) return LP2P_ERR_BUSY;

    listener->on_conn    = on_conn;
    listener->on_conn_ud = userdata;

    /* Tell the transport to listen. We pass the listener pointer as userdata
       so the transport callback can find us. The transport vtable's listen
       stores on_conn/userdata inside the transport impl. */
    lp2p_err_t err = listener->transport->vtable->listen(
        listener->transport->impl,
        listener->listen_addr,
        listener_on_transport_conn,
        listener  /* userdata — stored as on_conn_ud in tcp_transport_t */
    );
    if (err != LP2P_OK) return err;

    listener->active = true;
    return LP2P_OK;
}

lp2p_err_t lp2p_listener_close(lp2p_listener_t *listener)
{
    if (!listener) return LP2P_ERR_INVALID_ARG;
    if (!listener->active) return LP2P_OK;

    listener->transport->vtable->close(listener->transport->impl);
    listener->active = false;
    return LP2P_OK;
}

void lp2p_listener_free(lp2p_listener_t *listener)
{
    if (!listener) return;
    if (listener->active) {
        lp2p_listener_close(listener);
    }
    if (listener->listen_addr) {
        lp2p_multiaddr_free(listener->listen_addr);
    }
    free(listener);
}
