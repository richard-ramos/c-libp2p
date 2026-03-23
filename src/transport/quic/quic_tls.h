/* src/transport/quic/quic_tls.h — libp2p QUIC TLS helpers */
#ifndef LP2P_QUIC_TLS_H
#define LP2P_QUIC_TLS_H

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "libp2p/types.h"
#include "libp2p/errors.h"

#ifdef __cplusplus
extern "C" {
#endif

/* libp2p TLS extension OID: 1.3.6.1.4.1.53594.1.1 */
#define LP2P_TLS_EXTENSION_OID "1.3.6.1.4.1.53594.1.1"

/* ALPN protocol identifier for libp2p */
#define LP2P_QUIC_ALPN "libp2p"

/*
 * Generate a self-signed TLS certificate for libp2p QUIC.
 *
 * Steps:
 * 1. Generate ephemeral P-256 TLS keypair
 * 2. Create self-signed X.509 cert valid for 1 year, notBefore -= 10 min
 * 3. Add custom extension OID 1.3.6.1.4.1.53594.1.1 with:
 *    ASN.1 SEQUENCE { publicKey OCTET STRING, signature OCTET STRING }
 *    where publicKey = protobuf-encoded libp2p public key
 *    and signature = sign("libp2p-tls-handshake:" || DER(SPKI)) with identity key
 * 4. Returns the EVP_PKEY (caller owns) and X509 (caller owns)
 */
lp2p_err_t quic_tls_generate_cert(const lp2p_keypair_t *identity_key,
                                   EVP_PKEY **out_tls_key,
                                   X509 **out_cert);

/*
 * Create an SSL_CTX configured for libp2p QUIC.
 * Sets up the certificate, private key, ALPN, and verification callback.
 * is_server: true for server mode, false for client mode.
 */
lp2p_err_t quic_tls_create_ssl_ctx(const lp2p_keypair_t *identity_key,
                                    bool is_server,
                                    SSL_CTX **out);

/*
 * Verify a remote peer's TLS certificate per the libp2p spec.
 * Extracts the peer ID from the certificate's custom extension.
 * If expected_peer_id is non-NULL, verifies it matches.
 * Returns the remote peer's ID in out_peer_id.
 */
lp2p_err_t quic_tls_verify_peer_cert(X509 *cert,
                                      const lp2p_peer_id_t *expected_peer_id,
                                      lp2p_peer_id_t *out_peer_id);

#ifdef __cplusplus
}
#endif

#endif /* LP2P_QUIC_TLS_H */
