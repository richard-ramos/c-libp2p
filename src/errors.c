#include "libp2p/errors.h"

const char *lp2p_strerror(lp2p_err_t err)
{
    switch (err) {
        case LP2P_OK:                       return "success";
        case LP2P_ERR_NOMEM:                return "out of memory";
        case LP2P_ERR_INVALID_ARG:          return "invalid argument";
        case LP2P_ERR_INVALID_MULTIADDR:    return "invalid multiaddr";
        case LP2P_ERR_INVALID_KEY:          return "invalid key";
        case LP2P_ERR_CRYPTO:               return "cryptographic error";
        case LP2P_ERR_HANDSHAKE_FAILED:     return "handshake failed";
        case LP2P_ERR_NEGOTIATION_FAILED:   return "protocol negotiation failed";
        case LP2P_ERR_PROTOCOL_NOT_SUPPORTED: return "protocol not supported";
        case LP2P_ERR_PROTOCOL:             return "protocol error";
        case LP2P_ERR_CONNECTION_REFUSED:   return "connection refused";
        case LP2P_ERR_CONNECTION_CLOSED:    return "connection closed";
        case LP2P_ERR_BUSY:                 return "resource busy";
        case LP2P_ERR_STREAM_RESET:         return "stream reset";
        case LP2P_ERR_TIMEOUT:              return "operation timed out";
        case LP2P_ERR_EOF:                  return "end of file";
        case LP2P_ERR_WOULD_BLOCK:          return "operation would block";
        case LP2P_ERR_NOT_FOUND:            return "not found";
        case LP2P_ERR_TRANSPORT:            return "transport error";
        case LP2P_ERR_MUX:                  return "multiplexer error";
        case LP2P_ERR_PEER_ID_MISMATCH:     return "peer ID mismatch";
        case LP2P_ERR_MAX_CONNECTIONS:      return "maximum connections reached";
        case LP2P_ERR_ALREADY_CONNECTED:    return "already connected";
        case LP2P_ERR_INTERNAL:             return "internal error";
        default:                            return "unknown error";
    }
}
