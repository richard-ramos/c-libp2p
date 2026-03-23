#ifndef LP2P_DNS_RESOLVER_H
#define LP2P_DNS_RESOLVER_H

#include <uv.h>
#include "libp2p/types.h"
#include "libp2p/errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Resolve a hostname (dns4 or dns6) to a sockaddr.
 * family: AF_INET for dns4, AF_INET6 for dns6.
 * The callback receives the resolved address or an error. */
typedef void (*lp2p_dns_resolve_cb)(lp2p_err_t err,
                                     const struct sockaddr *addr,
                                     void *userdata);

lp2p_err_t lp2p_dns_resolve(uv_loop_t *loop,
                              const char *hostname,
                              const char *port,
                              int family,
                              lp2p_dns_resolve_cb cb,
                              void *userdata);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_DNS_RESOLVER_H */
