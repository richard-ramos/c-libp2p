/* src/dialer.c — outbound dial logic, triggers connection pipeline */

#include "dialer.h"
#include "transport/tcp/tcp_transport.h"
#include "transport/dns_resolver.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Dial context for DNS resolution + TCP connect ────────────────────────── */

typedef struct {
    lp2p_dialer_t  *dialer;
    lp2p_dialer_cb  cb;
    void           *userdata;
    char            host[256];
    char            port[8];
    int             family;       /* AF_INET or AF_INET6 */
    uv_timer_t      timer;
    bool            timed_out;
    bool            completed;
} dial_ctx_t;

/* ── Timeout handling ─────────────────────────────────────────────────────── */

static void dial_timer_cb(uv_timer_t *handle)
{
    dial_ctx_t *ctx = (dial_ctx_t *)handle->data;
    if (ctx->completed) return;
    ctx->timed_out = true;
    ctx->completed = true;
    uv_timer_stop(&ctx->timer);
    uv_close((uv_handle_t *)&ctx->timer, NULL);
    ctx->cb(NULL, LP2P_ERR_TIMEOUT, ctx->userdata);
    free(ctx);
}

/* ── Transport dial callback ──────────────────────────────────────────────── */

static void on_transport_conn(lp2p_conn_t *conn, lp2p_err_t err, void *userdata)
{
    dial_ctx_t *ctx = (dial_ctx_t *)userdata;
    if (ctx->completed) return;
    ctx->completed = true;
    uv_timer_stop(&ctx->timer);
    uv_close((uv_handle_t *)&ctx->timer, NULL);
    ctx->cb(conn, err, ctx->userdata);
    free(ctx);
}

/* ── DNS resolution callback (for dns4/dns6 addresses) ────────────────────── */

static void on_dns_resolved(lp2p_err_t err, const struct sockaddr *addr, void *userdata)
{
    dial_ctx_t *ctx = (dial_ctx_t *)userdata;
    if (ctx->completed) { free(ctx); return; }

    if (err != LP2P_OK) {
        ctx->completed = true;
        uv_timer_stop(&ctx->timer);
        uv_close((uv_handle_t *)&ctx->timer, NULL);
        ctx->cb(NULL, LP2P_ERR_TRANSPORT, ctx->userdata);
        free(ctx);
        return;
    }

    /* Build an ip4 or ip6 multiaddr from the resolved address */
    char ip_str[INET6_ADDRSTRLEN];
    const char *proto;
    if (addr->sa_family == AF_INET) {
        uv_inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr,
                      ip_str, sizeof(ip_str));
        proto = "ip4";
    } else {
        uv_inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr,
                      ip_str, sizeof(ip_str));
        proto = "ip6";
    }

    char ma_str[512];
    snprintf(ma_str, sizeof(ma_str), "/%s/%s/tcp/%s", proto, ip_str, ctx->port);

    lp2p_multiaddr_t *resolved_addr;
    lp2p_err_t merr = lp2p_multiaddr_parse(ma_str, &resolved_addr);
    if (merr != LP2P_OK) {
        ctx->completed = true;
        uv_timer_stop(&ctx->timer);
        uv_close((uv_handle_t *)&ctx->timer, NULL);
        ctx->cb(NULL, merr, ctx->userdata);
        free(ctx);
        return;
    }

    /* Now dial via the transport */
    lp2p_err_t derr = ctx->dialer->transport->vtable->dial(
        ctx->dialer->transport->impl,
        resolved_addr,
        on_transport_conn,
        ctx
    );

    lp2p_multiaddr_free(resolved_addr);

    if (derr != LP2P_OK) {
        ctx->completed = true;
        uv_timer_stop(&ctx->timer);
        uv_close((uv_handle_t *)&ctx->timer, NULL);
        ctx->cb(NULL, derr, ctx->userdata);
        free(ctx);
    }
}

/* ── Multiaddr parsing for dialer ─────────────────────────────────────────── */

/* Check if multiaddr is dns4 or dns6 and extract hostname + port.
   Returns true if DNS resolution is needed. */
static bool parse_dns_multiaddr(const char *ma_str, char *host, size_t host_cap,
                                 char *port, size_t port_cap, int *family)
{
    char buf[512];
    strncpy(buf, ma_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *p = buf;
    if (*p == '/') p++;

    if (strncmp(p, "dns4/", 5) == 0) {
        *family = AF_INET;
        p += 5;
    } else if (strncmp(p, "dns6/", 5) == 0) {
        *family = AF_INET6;
        p += 5;
    } else {
        return false;
    }

    char *slash = strchr(p, '/');
    if (!slash) return false;
    size_t hlen = (size_t)(slash - p);
    if (hlen >= host_cap) return false;
    memcpy(host, p, hlen);
    host[hlen] = '\0';

    p = slash + 1;
    if (strncmp(p, "tcp/", 4) != 0) return false;
    p += 4;

    slash = strchr(p, '/');
    size_t plen = slash ? (size_t)(slash - p) : strlen(p);
    if (plen >= port_cap) return false;
    memcpy(port, p, plen);
    port[plen] = '\0';

    return true;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

lp2p_err_t lp2p_dialer_new(uv_loop_t *loop,
                             lp2p_transport_t *transport,
                             uint32_t timeout_ms,
                             lp2p_dialer_t **out)
{
    if (!loop || !transport || !out) return LP2P_ERR_INVALID_ARG;

    lp2p_dialer_t *d = calloc(1, sizeof(*d));
    if (!d) return LP2P_ERR_NOMEM;

    d->loop       = loop;
    d->transport  = transport;
    d->timeout_ms = timeout_ms > 0 ? timeout_ms : 30000;

    *out = d;
    return LP2P_OK;
}

lp2p_err_t lp2p_dialer_dial(lp2p_dialer_t *dialer,
                              const lp2p_multiaddr_t *addr,
                              lp2p_dialer_cb cb,
                              void *userdata)
{
    if (!dialer || !addr || !cb) return LP2P_ERR_INVALID_ARG;

    /* Check if transport handles this address */
    if (!dialer->transport->vtable->handles(dialer->transport->impl, addr)) {
        return LP2P_ERR_TRANSPORT;
    }

    const char *ma_str = lp2p_multiaddr_string(addr);
    if (!ma_str) return LP2P_ERR_INVALID_MULTIADDR;

    dial_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return LP2P_ERR_NOMEM;

    ctx->dialer   = dialer;
    ctx->cb       = cb;
    ctx->userdata = userdata;

    /* Start timeout timer */
    uv_timer_init(dialer->loop, &ctx->timer);
    ctx->timer.data = ctx;
    uv_timer_start(&ctx->timer, dial_timer_cb, dialer->timeout_ms, 0);

    /* Check if we need DNS resolution */
    if (parse_dns_multiaddr(ma_str, ctx->host, sizeof(ctx->host),
                             ctx->port, sizeof(ctx->port), &ctx->family)) {
        /* Resolve DNS first, then dial */
        lp2p_err_t err = lp2p_dns_resolve(dialer->loop, ctx->host, ctx->port,
                                            ctx->family, on_dns_resolved, ctx);
        if (err != LP2P_OK) {
            uv_timer_stop(&ctx->timer);
            uv_close((uv_handle_t *)&ctx->timer, NULL);
            free(ctx);
            return err;
        }
        return LP2P_OK;
    }

    /* Direct IP address — dial via transport immediately */
    lp2p_err_t err = dialer->transport->vtable->dial(
        dialer->transport->impl, addr, on_transport_conn, ctx);
    if (err != LP2P_OK) {
        uv_timer_stop(&ctx->timer);
        uv_close((uv_handle_t *)&ctx->timer, NULL);
        free(ctx);
        return err;
    }

    return LP2P_OK;
}

void lp2p_dialer_free(lp2p_dialer_t *dialer)
{
    if (!dialer) return;
    free(dialer);
}
