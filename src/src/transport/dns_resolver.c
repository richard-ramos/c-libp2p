/* src/transport/dns_resolver.c — DNS resolution for dns4/dns6 multiaddrs */

#include "dns_resolver.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    lp2p_dns_resolve_cb  cb;
    void                *userdata;
    uv_getaddrinfo_t     req;
} dns_resolve_ctx_t;

static void on_resolved(uv_getaddrinfo_t *req, int status, struct addrinfo *res)
{
    dns_resolve_ctx_t *ctx = (dns_resolve_ctx_t *)req->data;

    if (status != 0 || res == NULL) {
        ctx->cb(LP2P_ERR_TRANSPORT, NULL, ctx->userdata);
        if (res) uv_freeaddrinfo(res);
        free(ctx);
        return;
    }

    ctx->cb(LP2P_OK, res->ai_addr, ctx->userdata);
    uv_freeaddrinfo(res);
    free(ctx);
}

lp2p_err_t lp2p_dns_resolve(uv_loop_t *loop,
                              const char *hostname,
                              const char *port,
                              int family,
                              lp2p_dns_resolve_cb cb,
                              void *userdata)
{
    if (!loop || !hostname || !cb) return LP2P_ERR_INVALID_ARG;

    dns_resolve_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return LP2P_ERR_NOMEM;

    ctx->cb       = cb;
    ctx->userdata = userdata;
    ctx->req.data = ctx;

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = family;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int r = uv_getaddrinfo(loop, &ctx->req, on_resolved, hostname, port, &hints);
    if (r != 0) {
        free(ctx);
        return LP2P_ERR_TRANSPORT;
    }

    return LP2P_OK;
}
