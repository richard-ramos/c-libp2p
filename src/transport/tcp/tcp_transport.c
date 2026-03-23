/* src/transport/tcp/tcp_transport.c — TCP transport (listen + dial) via libuv */

#include "tcp_transport.h"
#include "libp2p/multiaddr.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ── Forward declarations ─────────────────────────────────────────────────── */
static lp2p_err_t tcp_listen(void *transport, const lp2p_multiaddr_t *addr,
                              void (*on_conn)(void *transport, lp2p_conn_t *conn),
                              void *userdata);
static lp2p_err_t tcp_dial(void *transport, const lp2p_multiaddr_t *addr,
                             void (*on_conn)(lp2p_conn_t *conn, lp2p_err_t err, void *userdata),
                             void *userdata);
static void tcp_close(void *transport);
static bool tcp_handles(void *transport, const lp2p_multiaddr_t *addr);

static const lp2p_transport_vtable_t tcp_vtable = {
    .listen  = tcp_listen,
    .dial    = tcp_dial,
    .close   = tcp_close,
    .handles = tcp_handles,
};

/* ── Multiaddr parsing helpers ────────────────────────────────────────────── */

/* Parse /ip4/<addr>/tcp/<port> or /ip6/<addr>/tcp/<port> from multiaddr string.
   Returns 0 on success. */
static int parse_tcp_multiaddr(const char *ma_str,
                                struct sockaddr_storage *out,
                                bool *is_ipv6)
{
    char buf[256];
    strncpy(buf, ma_str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    /* Tokenize: /ip4/127.0.0.1/tcp/4001 or /ip6/::1/tcp/4001 */
    char *p = buf;
    if (*p == '/') p++;

    char *proto = p;
    char *slash = strchr(p, '/');
    if (!slash) return -1;
    *slash = '\0';

    int family;
    if (strcmp(proto, "ip4") == 0) {
        family = AF_INET;
        *is_ipv6 = false;
    } else if (strcmp(proto, "ip6") == 0) {
        family = AF_INET6;
        *is_ipv6 = true;
    } else {
        return -1;
    }

    char *addr_str = slash + 1;
    slash = strchr(addr_str, '/');
    if (!slash) return -1;
    *slash = '\0';

    char *tcp_str = slash + 1;
    slash = strchr(tcp_str, '/');
    if (!slash) return -1;
    *slash = '\0';

    if (strcmp(tcp_str, "tcp") != 0) return -1;

    char *port_str = slash + 1;
    /* Strip anything after port (e.g. /p2p/...) */
    slash = strchr(port_str, '/');
    if (slash) *slash = '\0';

    int port = atoi(port_str);
    if (port < 0 || port > 65535) return -1;

    memset(out, 0, sizeof(*out));
    if (family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)out;
        sin->sin_family = AF_INET;
        sin->sin_port = htons((uint16_t)port);
        if (uv_inet_pton(AF_INET, addr_str, &sin->sin_addr) != 0) return -1;
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)out;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons((uint16_t)port);
        if (uv_inet_pton(AF_INET6, addr_str, &sin6->sin6_addr) != 0) return -1;
    }

    return 0;
}

/* ── Allocation callback for libuv reads ──────────────────────────────────── */
#define TCP_READ_BUF_SIZE 65536

static void alloc_cb(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf)
{
    (void)suggested_size;
    lp2p_tcp_conn_t *tc = (lp2p_tcp_conn_t *)handle->data;

    if (!tc->read_buf) {
        tc->read_buf = malloc(TCP_READ_BUF_SIZE);
        tc->read_buf_cap = TCP_READ_BUF_SIZE;
    }

    buf->base = (char *)tc->read_buf + tc->read_buf_len;
    buf->len  = tc->read_buf_cap - tc->read_buf_len;
}

static void read_cb(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf)
{
    lp2p_tcp_conn_t *tc = (lp2p_tcp_conn_t *)stream->data;

    if (nread < 0) {
        lp2p_err_t err = (nread == UV_EOF) ? LP2P_ERR_EOF : LP2P_ERR_TRANSPORT;
        if (tc->on_read) {
            tc->on_read(tc, NULL, 0, err, tc->on_read_ud);
        }
        return;
    }

    if (nread == 0) return;

    tc->read_buf_len += (size_t)nread;

    if (tc->on_read) {
        tc->on_read(tc, tc->read_buf, tc->read_buf_len, LP2P_OK, tc->on_read_ud);
    }
}

/* ── TCP raw connection ops ───────────────────────────────────────────────── */

lp2p_err_t lp2p_tcp_conn_start_read(lp2p_tcp_conn_t *tc,
    void (*cb)(lp2p_tcp_conn_t *tc, const uint8_t *data, size_t len,
               lp2p_err_t err, void *userdata),
    void *userdata)
{
    if (!tc || !cb) return LP2P_ERR_INVALID_ARG;

    tc->on_read    = cb;
    tc->on_read_ud = userdata;
    tc->handle.data = tc;

    if (!tc->reading) {
        int r = uv_read_start((uv_stream_t *)&tc->handle, alloc_cb, read_cb);
        if (r != 0) return LP2P_ERR_TRANSPORT;
        tc->reading = true;
    }

    /* When the connection state machine swaps read handlers, there may
     * already be buffered bytes waiting from the previous stage. Deliver
     * them immediately so protocol transitions don't stall until another
     * socket event arrives. */
    if (tc->read_buf_len > 0) {
        tc->on_read(tc, tc->read_buf, tc->read_buf_len, LP2P_OK, tc->on_read_ud);
    }

    return LP2P_OK;
}

/* Consume bytes from the front of the read buffer */
void lp2p_tcp_conn_consume(lp2p_tcp_conn_t *tc, size_t n)
{
    if (n >= tc->read_buf_len) {
        tc->read_buf_len = 0;
    } else {
        memmove(tc->read_buf, tc->read_buf + n, tc->read_buf_len - n);
        tc->read_buf_len -= n;
    }
}

typedef struct {
    uv_write_t       req;
    lp2p_tcp_conn_t *tc;
    void           (*cb)(lp2p_tcp_conn_t *tc, lp2p_err_t err, void *userdata);
    void            *userdata;
    uint8_t         *data;   /* owned copy */
} tcp_write_ctx_t;

static void write_done_cb(uv_write_t *req, int status)
{
    tcp_write_ctx_t *ctx = (tcp_write_ctx_t *)req->data;
    lp2p_err_t err = (status == 0) ? LP2P_OK : LP2P_ERR_TRANSPORT;
    void (*cb)(lp2p_tcp_conn_t *, lp2p_err_t, void *) = ctx->cb;
    lp2p_tcp_conn_t *tc = ctx->tc;
    void *ud = ctx->userdata;
    free(ctx->data);
    free(ctx);
    if (cb) cb(tc, err, ud);
}

lp2p_err_t lp2p_tcp_conn_write(lp2p_tcp_conn_t *tc, const uint8_t *data, size_t len,
    void (*cb)(lp2p_tcp_conn_t *tc, lp2p_err_t err, void *userdata),
    void *userdata)
{
    if (!tc || !data || len == 0) return LP2P_ERR_INVALID_ARG;

    tcp_write_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return LP2P_ERR_NOMEM;

    ctx->data = malloc(len);
    if (!ctx->data) { free(ctx); return LP2P_ERR_NOMEM; }
    memcpy(ctx->data, data, len);

    ctx->tc       = tc;
    ctx->cb       = cb;
    ctx->userdata = userdata;
    ctx->req.data = ctx;

    uv_buf_t buf = uv_buf_init((char *)ctx->data, (unsigned int)len);
    int r = uv_write(&ctx->req, (uv_stream_t *)&tc->handle, &buf, 1, write_done_cb);
    if (r != 0) {
        free(ctx->data);
        free(ctx);
        return LP2P_ERR_TRANSPORT;
    }

    return LP2P_OK;
}

static void close_handle_cb(uv_handle_t *handle)
{
    lp2p_tcp_conn_t *tc = (lp2p_tcp_conn_t *)handle->data;
    void (*cb)(lp2p_tcp_conn_t *, void *) = tc->on_close;
    void *ud = tc->on_close_ud;
    free(tc->read_buf);
    if (cb) cb(tc, ud);
}

void lp2p_tcp_conn_close(lp2p_tcp_conn_t *tc,
    void (*cb)(lp2p_tcp_conn_t *tc, void *userdata), void *userdata)
{
    if (!tc) return;
    if (tc->closing) return;
    tc->closing    = true;
    tc->on_close   = cb;
    tc->on_close_ud = userdata;
    tc->handle.data = tc;

    if (tc->reading) {
        uv_read_stop((uv_stream_t *)&tc->handle);
        tc->reading = false;
    }

    if (!uv_is_closing((uv_handle_t *)&tc->handle)) {
        uv_close((uv_handle_t *)&tc->handle, close_handle_cb);
    }
}

/* ── Listener (server) ────────────────────────────────────────────────────── */

static void on_new_connection(uv_stream_t *server, int status)
{
    lp2p_tcp_transport_t *impl = (lp2p_tcp_transport_t *)server->data;
    if (status < 0) return;

    lp2p_tcp_conn_t *tc = calloc(1, sizeof(*tc));
    if (!tc) return;

    uv_tcp_init(impl->loop, &tc->handle);
    tc->handle.data = tc;
    tc->loop = impl->loop;
    tc->is_inbound = true;

    if (uv_accept(server, (uv_stream_t *)&tc->handle) != 0) {
        uv_close((uv_handle_t *)&tc->handle, NULL);
        free(tc);
        return;
    }

    /* Get addresses */
    int namelen = sizeof(tc->remote_addr);
    uv_tcp_getpeername(&tc->handle, (struct sockaddr *)&tc->remote_addr, &namelen);
    namelen = sizeof(tc->local_addr);
    uv_tcp_getsockname(&tc->handle, (struct sockaddr *)&tc->local_addr, &namelen);

    /* For now we pass the raw tcp_conn as the lp2p_conn_t*. The connection layer
       (owned by coordinator) will wrap this properly. We cast through void*
       to signal that this is a raw TCP conn that needs upgrading. */
    if (impl->on_conn) {
        impl->on_conn(impl, (lp2p_conn_t *)tc);
    }
}

static lp2p_err_t tcp_listen(void *transport, const lp2p_multiaddr_t *addr,
                              void (*on_conn)(void *transport, lp2p_conn_t *conn),
                              void *userdata)
{
    lp2p_tcp_transport_t *impl = (lp2p_tcp_transport_t *)transport;
    if (impl->listening) return LP2P_ERR_BUSY;

    const char *ma_str = lp2p_multiaddr_string(addr);
    if (!ma_str) return LP2P_ERR_INVALID_MULTIADDR;

    struct sockaddr_storage saddr;
    bool is_ipv6;
    if (parse_tcp_multiaddr(ma_str, &saddr, &is_ipv6) != 0) {
        return LP2P_ERR_INVALID_MULTIADDR;
    }

    uv_tcp_init(impl->loop, &impl->server);
    impl->server.data = impl;

    if (is_ipv6) {
        uv_tcp_bind(&impl->server, (const struct sockaddr *)&saddr, UV_TCP_IPV6ONLY);
    } else {
        uv_tcp_bind(&impl->server, (const struct sockaddr *)&saddr, 0);
    }

    impl->on_conn    = on_conn;
    impl->on_conn_ud = userdata;

    int r = uv_listen((uv_stream_t *)&impl->server, 128, on_new_connection);
    if (r != 0) return LP2P_ERR_TRANSPORT;

    impl->listening = true;
    return LP2P_OK;
}

/* ── Dialer (client) ──────────────────────────────────────────────────────── */

static void on_connect(uv_connect_t *req, int status)
{
    lp2p_tcp_dial_ctx_t *ctx = (lp2p_tcp_dial_ctx_t *)req->data;

    if (status != 0) {
        uv_close((uv_handle_t *)ctx->tcp_handle, NULL);
        ctx->on_conn(NULL, LP2P_ERR_CONNECTION_REFUSED, ctx->userdata);
        /* libuv may still touch the connect request after this callback
         * returns, so the dial context cannot be freed here safely. */
        return;
    }

    lp2p_tcp_conn_t *tc = (lp2p_tcp_conn_t *)ctx->tcp_handle->data;

    /* Get addresses */
    int namelen = sizeof(tc->remote_addr);
    uv_tcp_getpeername(&tc->handle, (struct sockaddr *)&tc->remote_addr, &namelen);
    namelen = sizeof(tc->local_addr);
    uv_tcp_getsockname(&tc->handle, (struct sockaddr *)&tc->local_addr, &namelen);

    ctx->on_conn((lp2p_conn_t *)tc, LP2P_OK, ctx->userdata);
    /* Keep ctx alive after the callback returns; the embedded uv_connect_t
     * is still owned by libuv for the remainder of this event-loop turn. */
}

static lp2p_err_t tcp_dial(void *transport, const lp2p_multiaddr_t *addr,
                             void (*on_conn)(lp2p_conn_t *conn, lp2p_err_t err, void *userdata),
                             void *userdata)
{
    lp2p_tcp_transport_t *impl = (lp2p_tcp_transport_t *)transport;

    const char *ma_str = lp2p_multiaddr_string(addr);
    if (!ma_str) return LP2P_ERR_INVALID_MULTIADDR;

    struct sockaddr_storage saddr;
    bool is_ipv6;
    if (parse_tcp_multiaddr(ma_str, &saddr, &is_ipv6) != 0) {
        return LP2P_ERR_INVALID_MULTIADDR;
    }

    lp2p_tcp_conn_t *tc = calloc(1, sizeof(*tc));
    if (!tc) return LP2P_ERR_NOMEM;

    uv_tcp_init(impl->loop, &tc->handle);
    tc->handle.data = tc;
    tc->loop = impl->loop;
    tc->is_inbound = false;

    lp2p_tcp_dial_ctx_t *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) {
        free(tc);
        return LP2P_ERR_NOMEM;
    }

    ctx->transport   = impl;
    ctx->tcp_handle  = &tc->handle;
    ctx->on_conn     = on_conn;
    ctx->userdata    = userdata;
    ctx->connect_req.data = ctx;

    int r = uv_tcp_connect(&ctx->connect_req, &tc->handle,
                            (const struct sockaddr *)&saddr, on_connect);
    if (r != 0) {
        free(ctx);
        uv_close((uv_handle_t *)&tc->handle, NULL);
        /* tc will be freed after close completes; for simplicity mark it */
        return LP2P_ERR_TRANSPORT;
    }

    return LP2P_OK;
}

/* ── Close / handles ──────────────────────────────────────────────────────── */

static void server_close_cb(uv_handle_t *handle)
{
    (void)handle;
}

static void tcp_close(void *transport)
{
    lp2p_tcp_transport_t *impl = (lp2p_tcp_transport_t *)transport;
    if (impl->listening && !uv_is_closing((uv_handle_t *)&impl->server)) {
        uv_close((uv_handle_t *)&impl->server, server_close_cb);
        impl->listening = false;
    }
}

static bool tcp_handles(void *transport, const lp2p_multiaddr_t *addr)
{
    (void)transport;
    const char *s = lp2p_multiaddr_string(addr);
    if (!s) return false;

    /* Check if it starts with /ip4/ or /ip6/ and contains /tcp/ */
    if ((strncmp(s, "/ip4/", 5) == 0 || strncmp(s, "/ip6/", 5) == 0) &&
        strstr(s, "/tcp/") != NULL) {
        return true;
    }
    /* Also handle /dns4/ and /dns6/ with /tcp/ */
    if ((strncmp(s, "/dns4/", 6) == 0 || strncmp(s, "/dns6/", 6) == 0) &&
        strstr(s, "/tcp/") != NULL) {
        return true;
    }
    return false;
}

/* ── Constructor / destructor ─────────────────────────────────────────────── */

lp2p_err_t lp2p_tcp_transport_new(uv_loop_t *loop, lp2p_transport_t **out)
{
    if (!loop || !out) return LP2P_ERR_INVALID_ARG;

    lp2p_transport_t *t = calloc(1, sizeof(*t));
    if (!t) return LP2P_ERR_NOMEM;

    lp2p_tcp_transport_t *impl = calloc(1, sizeof(*impl));
    if (!impl) { free(t); return LP2P_ERR_NOMEM; }

    impl->loop = loop;
    t->vtable = &tcp_vtable;
    t->impl   = impl;

    *out = t;
    return LP2P_OK;
}

void lp2p_tcp_transport_free(lp2p_transport_t *t)
{
    if (!t) return;
    if (t->impl) {
        lp2p_tcp_transport_t *impl = (lp2p_tcp_transport_t *)t->impl;
        tcp_close(impl);
        free(impl);
    }
    free(t);
}
