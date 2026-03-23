cmake_minimum_required(VERSION 3.16)
project(c-libp2p VERSION 0.1.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# ── Build options ─────────────────────────────────────────────────────────────
option(LP2P_BUILD_TESTS    "Build unit and integration tests" ON)
option(LP2P_BUILD_EXAMPLES "Build example programs"          ON)
option(LP2P_ENABLE_QUIC    "Build QUIC transport (requires ngtcp2)" ON)

# ── Warnings ──────────────────────────────────────────────────────────────────
add_compile_options(-Wall -Wextra -Wpedantic -Wno-unused-parameter)

# ── Dependencies ──────────────────────────────────────────────────────────────
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

find_package(Libuv      REQUIRED)
find_package(Libsodium  REQUIRED)
find_package(OpenSSL    REQUIRED)
find_package(ProtobufC  REQUIRED)
if(LP2P_ENABLE_QUIC)
    find_package(Ngtcp2 REQUIRED)
endif()

# ── Generate protobuf-c sources ────────────────────────────────────────────────
find_program(PROTOC_C protoc-c REQUIRED)

set(PROTO_DIR  "${CMAKE_SOURCE_DIR}/proto")
set(PROTO_OUT  "${CMAKE_BINARY_DIR}/proto-gen")
file(MAKE_DIRECTORY "${PROTO_OUT}")

add_custom_command(
    OUTPUT "${PROTO_OUT}/noise.pb-c.c" "${PROTO_OUT}/noise.pb-c.h"
    COMMAND ${PROTOC_C} --c_out=${PROTO_OUT} --proto_path=${PROTO_DIR} noise.proto
    DEPENDS "${PROTO_DIR}/noise.proto"
    COMMENT "Generating noise.pb-c.[ch]"
)
add_custom_command(
    OUTPUT "${PROTO_OUT}/identify.pb-c.c" "${PROTO_OUT}/identify.pb-c.h"
    COMMAND ${PROTOC_C} --c_out=${PROTO_OUT} --proto_path=${PROTO_DIR} identify.proto
    DEPENDS "${PROTO_DIR}/identify.proto"
    COMMENT "Generating identify.pb-c.[ch]"
)
add_custom_target(proto_gen DEPENDS
    "${PROTO_OUT}/noise.pb-c.c"
    "${PROTO_OUT}/noise.pb-c.h"
    "${PROTO_OUT}/identify.pb-c.c"
    "${PROTO_OUT}/identify.pb-c.h"
)

# ── Library sources ────────────────────────────────────────────────────────────
set(LP2P_SOURCES
    src/errors.c
    src/util/buffer.c
    src/util/list.c
    src/util/map.c
    src/encoding/varint.c
    src/encoding/multibase.c
    src/encoding/multicodec.c
    src/encoding/cid.c
    src/encoding/multihash.c
    src/crypto/keypair.c
    src/crypto/peer_id.c
    src/crypto/public_key.c
    src/multiaddr.c
    src/peerstore.c
    src/connmgr.c
    src/connection.c
    src/stream.c
    src/protocol_router.c
    src/listener.c
    src/dialer.c
    src/host.c
    src/transport/tcp/tcp_transport.c
    src/transport/dns_resolver.c
    src/security/noise/noise_handshake.c
    src/security/noise/noise_transport.c
    src/security/noise/noise_keys.c
    src/mux/yamux/yamux.c
    src/protocol/multistream.c
    src/protocol/ping.c
    src/protocol/identify.c
    "${PROTO_OUT}/noise.pb-c.c"
    "${PROTO_OUT}/identify.pb-c.c"
)

if(LP2P_ENABLE_QUIC)
    list(APPEND LP2P_SOURCES src/transport/quic/quic_transport.c)
endif()

add_library(lp2p STATIC ${LP2P_SOURCES})
add_dependencies(lp2p proto_gen)

target_include_directories(lp2p
    PUBLIC  "${CMAKE_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_SOURCE_DIR}/src"
            "${PROTO_OUT}"
)
target_link_libraries(lp2p
    PUBLIC
        ${LIBUV_LIBRARIES}
        ${LIBSODIUM_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
        ${PROTOBUFC_LIBRARIES}
)
if(LP2P_ENABLE_QUIC)
    target_include_directories(lp2p PRIVATE ${NGTCP2_INCLUDE_DIRS})
    target_link_libraries(lp2p PUBLIC ${NGTCP2_LIBRARIES})
    target_compile_definitions(lp2p PUBLIC LP2P_HAVE_QUIC=1)
endif()

# ── Tests ─────────────────────────────────────────────────────────────────────
if(LP2P_BUILD_TESTS)
    enable_testing()

    set(TEST_SOURCES
        tests/test_varint.c
        tests/test_multiaddr.c
        tests/test_peer_id.c
        tests/test_peer_id_text.c
        tests/test_remote_keys.c
        tests/test_multistream.c
        tests/test_noise.c
        tests/test_yamux.c
        tests/test_ping.c
        tests/test_identify.c
        tests/test_identify_push.c
        tests/test_peerstore.c
        tests/test_tcp_transport.c
        tests/test_integration.c
        tests/test_custom_protocol.c
    )

    foreach(test_src ${TEST_SOURCES})
        get_filename_component(test_name ${test_src} NAME_WE)
        add_executable(${test_name} ${test_src})
        target_include_directories(${test_name} PRIVATE "${CMAKE_SOURCE_DIR}/src")
        target_link_libraries(${test_name} PRIVATE lp2p)
        add_test(NAME ${test_name} COMMAND ${test_name})
    endforeach()
endif()

# ── Examples ──────────────────────────────────────────────────────────────────
if(LP2P_BUILD_EXAMPLES)
    foreach(example echo_server chat ping_peer)
        add_executable(example_${example} examples/${example}.c)
        target_link_libraries(example_${example} PRIVATE lp2p)
    endforeach()
endif()
