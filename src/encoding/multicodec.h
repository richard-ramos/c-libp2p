/* src/encoding/multicodec.h — multicodec constants */
#ifndef LP2P_ENCODING_MULTICODEC_H
#define LP2P_ENCODING_MULTICODEC_H

#include <stdint.h>

/* Hash functions */
#define LP2P_CODEC_IDENTITY     0x00
#define LP2P_CODEC_SHA2_256     0x12

/* CID / key */
#define LP2P_CODEC_CIDV1        0x01
#define LP2P_CODEC_LIBP2P_KEY   0x72

/* Multiaddr protocol codes */
#define LP2P_PROTO_IP4          0x04
#define LP2P_PROTO_TCP          0x06
#define LP2P_PROTO_IP6          0x29
#define LP2P_PROTO_DNS4         0x36
#define LP2P_PROTO_DNS6         0x37
#define LP2P_PROTO_UDP          0x0111
#define LP2P_PROTO_P2P          0x01A5
#define LP2P_PROTO_QUIC_V1      0x01CD

#endif /* LP2P_ENCODING_MULTICODEC_H */
