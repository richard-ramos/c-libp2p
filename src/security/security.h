#ifndef LP2P_SECURITY_H
#define LP2P_SECURITY_H

/* Internal security interface — not part of the public API */

#include "libp2p/types.h"
#include "libp2p/errors.h"

typedef struct lp2p_security_session lp2p_security_session_t;

typedef struct {
    /* Initiator: start the handshake and drive it to completion.
     * Calls back with the authenticated remote peer ID on success. */
    lp2p_err_t (*handshake)(void *session,
                             void (*on_done)(lp2p_err_t err,
                                             const lp2p_peer_id_t *remote_peer,
                                             void *userdata),
                             void *userdata);
    /* Encrypt plaintext into the outbound wire buffer */
    lp2p_err_t (*encrypt)(void *session, const uint8_t *plain, size_t len,
                           uint8_t *out, size_t *out_len);
    /* Decrypt incoming wire bytes into plaintext */
    lp2p_err_t (*decrypt)(void *session, const uint8_t *cipher, size_t len,
                           uint8_t *out, size_t *out_len);
    void       (*free)(void *session);
} lp2p_security_vtable_t;

struct lp2p_security_session {
    const lp2p_security_vtable_t *vtable;
    void                         *impl;
};

#endif /* LP2P_SECURITY_H */
