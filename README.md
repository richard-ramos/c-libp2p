# c-libp2p

A C implementation of the [libp2p](https://libp2p.io/) networking stack. c-libp2p provides a modular, event-driven peer-to-peer networking library built on libuv, with support for TCP and QUIC transports, Noise, Yamux stream multiplexing, and the standard libp2p application protocols.

## Features

- **TCP transport** — powered by libuv for async, cross-platform I/O
- **QUIC transport** — optional, built on ngtcp2 + BoringSSL
- **Noise XX security handshake** — mutual authentication using Ed25519/X25519 (libsodium)
- **Yamux multiplexer** — multiple concurrent streams over a single connection
- **Multistream-select** — protocol negotiation on every stream
- **Ping protocol** — `/ipfs/ping/1.0.0` with RTT measurement
- **Identify protocol** — peer information exchange
- **Ed25519 host keys** — generated via libsodium; RSA, secp256k1, and ECDSA peer IDs supported for remote verification
- **Multiaddr** — full multiaddr parsing and serialization
- **Peerstore** — in-memory store for peer addresses and metadata

## Dependencies

| Dependency | Version | Purpose |
|------------|---------|---------|
| cmake | >= 3.16 | Build system |
| gcc or clang | any recent | C11 compiler |
| libuv | system | Async I/O event loop |
| libsodium | system | Ed25519/X25519 cryptography |
| protobuf-c + protoc-c | system | Protobuf serialization (Noise, Identify) |
| BoringSSL | commit `7d88bb1bf3372bda1134ad8bf624b25b88e0db86` | TLS/QUIC crypto (QUIC only) |
| ngtcp2 | v1.9.1 | QUIC transport (QUIC only) |
| Go | any recent | Required to build BoringSSL's QUIC parts (QUIC only) |

## Building

### Without QUIC (simple)

Install system dependencies:

```bash
sudo apt-get install -y build-essential cmake libuv1-dev libsodium-dev \
    libprotobuf-c-dev protobuf-c-compiler
```

Configure and build:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DLP2P_ENABLE_QUIC=OFF
cmake --build build --parallel $(nproc)
```

### With QUIC (full build)

QUIC support requires BoringSSL and ngtcp2 built from source. The steps below
build everything into `~/c-libp2p-deps` and then point the c-libp2p build at
those artifacts.

#### Step 1 — Install base dependencies

```bash
sudo apt-get install -y build-essential cmake git golang pkg-config \
    libuv1-dev libsodium-dev libprotobuf-c-dev protobuf-c-compiler \
    libnghttp3-dev
```

Go must be installed before building BoringSSL; it is needed to compile
BoringSSL's QUIC-specific assembly helpers.

#### Step 2 — Build BoringSSL

```bash
export WORKDIR=~/c-libp2p-deps
mkdir -p $WORKDIR && cd $WORKDIR

git clone https://boringssl.googlesource.com/boringssl
cd boringssl
git checkout 7d88bb1bf3372bda1134ad8bf624b25b88e0db86

cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
  -DBUILD_SHARED_LIBS=OFF
cmake --build build --parallel $(nproc)

# Verify that QUIC symbols are present (required):
nm build/libssl.a | grep SSL_set_quic_early_data_context

cd ..
```

The static libraries are at `build/libssl.a` and `build/libcrypto.a` directly
under the build directory.

#### Step 3 — Build ngtcp2 v1.9.1

```bash
cd $WORKDIR

git clone --recurse-submodules --depth 1 --branch v1.9.1 \
    https://github.com/ngtcp2/ngtcp2.git
cd ngtcp2

cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DENABLE_BORINGSSL=ON \
  -DENABLE_OPENSSL=OFF \
  -DBORINGSSL_INCLUDE_DIR=$WORKDIR/boringssl/include \
  "-DBORINGSSL_LIBRARIES=$WORKDIR/boringssl/build/libssl.a;$WORKDIR/boringssl/build/libcrypto.a" \
  -DENABLE_STATIC_LIB=ON \
  -DENABLE_SHARED_LIB=OFF
cmake --build build --parallel $(nproc)

cd ..
```

#### Step 4 — Build c-libp2p with QUIC enabled

```bash
cd /path/to/c-libp2p

cmake -B build \
  -DCMAKE_BUILD_TYPE=Release \
  -DLP2P_ENABLE_QUIC=ON \
  -DNGTCP2_ROOT=$WORKDIR/ngtcp2 \
  -DOPENSSL_INCLUDE_DIR=$WORKDIR/boringssl/include \
  -DOPENSSL_SSL_LIBRARY=$WORKDIR/boringssl/build/libssl.a \
  -DOPENSSL_CRYPTO_LIBRARY=$WORKDIR/boringssl/build/libcrypto.a \
  -DOPENSSL_VERSION=1.1.1
cmake --build build --parallel $(nproc)
```

## CMake Options

| Option | Default | Description |
|--------|---------|-------------|
| `LP2P_ENABLE_QUIC` | `OFF` | Enable QUIC transport (requires BoringSSL + ngtcp2) |
| `LP2P_BUILD_TESTS` | `ON` | Build the test suite |
| `LP2P_BUILD_EXAMPLES` | `ON` | Build example programs |
| `NGTCP2_ROOT` | — | Path to the ngtcp2 source root (QUIC builds) |
| `OPENSSL_INCLUDE_DIR` | — | Path to BoringSSL `include/` directory |
| `OPENSSL_SSL_LIBRARY` | — | Path to `libssl.a` |
| `OPENSSL_CRYPTO_LIBRARY` | — | Path to `libcrypto.a` |

## Running Examples

After a successful build, example binaries are in the `build/` directory.

### Echo server + ping client

```bash
# Terminal 1 — start the echo server
./build/example_echo_server
# Output:
#   Echo server started
#   Peer ID: 12D3KooW...
#   Listening on: /ip4/127.0.0.1/tcp/9000/p2p/12D3KooW...

# Terminal 2 — ping the echo server (copy the full multiaddr from above)
./build/example_ping_peer /ip4/127.0.0.1/tcp/9000/p2p/<peer-id>
```

The echo server listens on `127.0.0.1:9000` by default. If your setup uses
IPv6 loopback, use `/ip6/::1/tcp/9000/p2p/<peer-id>` instead.

### Interactive chat

The chat example operates in server mode (no arguments) or client mode (one
argument).

```bash
# Terminal 1 — start chat server (listens on /ip4/0.0.0.0/tcp/9001)
./build/example_chat
# Output:
#   Chat server started
#   Peer ID: 12D3KooW...
#   Listening on: /ip4/0.0.0.0/tcp/9001/p2p/12D3KooW...
#   Waiting for a peer to connect...

# Terminal 2 — connect as client
./build/example_chat /ip4/127.0.0.1/tcp/9001/p2p/<peer-id>
```

Type a message and press Enter in either terminal to send it to the peer.
Press Ctrl-C to exit.

## Running Interop Tests

The repository includes a small `go-libp2p` helper under `interop/go-libp2p/`
that can run as a server or as ping/echo clients against the C examples.

### Docker smoke test

If you want a containerized smoke test, use the existing interop harness:

```bash
cd interop
./test_interop.sh
```

This script builds the Docker images, starts the Go node from
`interop/Dockerfile.go-libp2p`, and runs the C `ping_peer` example against it.
It currently verifies ping interoperability in the `c -> go` direction.

### Local C <-> Go interop

Build the C examples and the Go helper:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DLP2P_ENABLE_QUIC=OFF
cmake --build build --parallel $(nproc) \
    --target example_echo_server example_echo_client example_ping_peer

cd interop/go-libp2p
go build -o /tmp/go-libp2p-interop .
cd ../..
```

#### Go clients -> C server

Start the C echo server:

```bash
./build/example_echo_server
```

It prints:

```text
Echo server started
Peer ID: 12D3KooW...
Listening on: /ip4/127.0.0.1/tcp/9000/p2p/12D3KooW...
```

Use the printed multiaddr as the `--target` for the Go clients:

```bash
/tmp/go-libp2p-interop ping-client \
    --target /ip4/127.0.0.1/tcp/9000/p2p/<c-peer-id> \
    --count 5

/tmp/go-libp2p-interop echo-client \
    --target /ip4/127.0.0.1/tcp/9000/p2p/<c-peer-id> \
    --message "hello from go to c"
```

Expected results:

- `ping-client` prints `ping 1/5` through `ping 5/5` and exits with `Done.`
- `echo-client` prints `Echoed: hello from go to c`

`example_echo_server` also serves `/ipfs/ping/1.0.0`, so it is enough for both
ping and echo checks.

#### C clients -> Go server

Start the Go helper in server mode:

```bash
/tmp/go-libp2p-interop server
```

It prints output like:

```text
GO_PEER_ID=12D3KooW...
GO_LISTEN_ADDR=/ip4/127.0.0.1/tcp/4001/p2p/12D3KooW...
GO_READY=1
```

Use the printed `/ip4/127.0.0.1/tcp/4001/p2p/...` multiaddr with the C clients:

```bash
./build/example_ping_peer /ip4/127.0.0.1/tcp/4001/p2p/<go-peer-id>
./build/example_echo_client /ip4/127.0.0.1/tcp/4001/p2p/<go-peer-id> \
    "hello from c to go"
```

Expected results:

- `example_ping_peer` prints 5 RTT lines and ends with `Done.`
- `example_echo_client` prints `Echoed: hello from c to go`

## Architecture

c-libp2p is organized as a layered stack:

```
┌─────────────────────────────────────────┐
│  Application protocols                  │
│  Ping (/ipfs/ping/1.0.0)                │
│  Identify (/ipfs/id/1.0.0)              │
│  Custom protocols (user-defined)        │
├─────────────────────────────────────────┤
│  Protocol negotiation                   │
│  Multistream-select                     │
├─────────────────────────────────────────┤
│  Stream multiplexer                     │
│  Yamux                                  │
├─────────────────────────────────────────┤
│  Security handshake                     │
│  Noise XX (Ed25519 + X25519)            │
├─────────────────────────────────────────┤
│  Transport                              │
│  TCP (libuv)  |  QUIC (ngtcp2+BoringSSL)│
└─────────────────────────────────────────┘
```

Each layer is independent. The `lp2p_host_t` handle is the main API entry point
and owns the event loop integration, connection manager, peerstore, and all
registered protocol handlers.

## API Quick Start

The full public API is in `include/libp2p/libp2p.h`. Below is the minimal
pattern for creating a listening host, registering a protocol handler, and
dialing a remote peer.

### Creating a listening host

```c
#include "libp2p/libp2p.h"

static void my_handler(lp2p_stream_t *stream, void *userdata)
{
    /* Called for every inbound /my/protocol/1.0.0 stream */
    lp2p_buf_t buf = { .data = (const uint8_t *)"hello\n", .len = 6 };
    lp2p_stream_write(stream, &buf, NULL, NULL);
    lp2p_stream_close(stream, NULL, NULL);
}

int main(void)
{
    uv_loop_t *loop = uv_default_loop();

    /* Generate an Ed25519 host keypair */
    lp2p_keypair_t *kp = NULL;
    lp2p_keypair_generate(LP2P_KEY_ED25519, &kp);  /* host takes ownership */

    /* Configure the host */
    const char *addrs[] = { "/ip4/0.0.0.0/tcp/9000" };
    lp2p_host_config_t cfg = {
        .keypair            = kp,
        .listen_addrs       = addrs,
        .listen_addrs_count = 1,
    };

    lp2p_host_t *host = NULL;
    lp2p_host_new(loop, &cfg, &host);

    /* Register a protocol handler */
    lp2p_host_set_stream_handler(host, "/my/protocol/1.0.0", my_handler, NULL);

    /* Start listening */
    lp2p_host_listen(host, NULL, NULL);

    uv_run(loop, UV_RUN_DEFAULT);

    lp2p_host_free(host);
    uv_loop_close(loop);
    return 0;
}
```

### Dialing a remote peer

```c
static void on_dial(lp2p_conn_t *conn, lp2p_err_t err, void *userdata)
{
    if (err != LP2P_OK) {
        fprintf(stderr, "dial failed: %s\n", lp2p_strerror(err));
        return;
    }
    /* conn is now authenticated and multiplexed — open a stream */
    lp2p_host_new_stream(host, multiaddr, "/my/protocol/1.0.0", on_stream_open);
}

/* Elsewhere: */
lp2p_host_dial(host, "/ip4/1.2.3.4/tcp/9000/p2p/12D3KooW...", on_dial, NULL);
```

### Key configuration fields

| Field | Default | Description |
|-------|---------|-------------|
| `keypair` | required | Ed25519 identity; host takes ownership |
| `listen_addrs` | NULL | Multiaddr strings to bind on |
| `max_connections` | 256 | 0 = default; UINT32_MAX = unlimited |
| `max_streams_per_conn` | 256 | Yamux stream limit per connection |
| `dial_timeout_ms` | 30000 | Outbound dial timeout |
| `handshake_timeout_ms` | 10000 | Noise handshake timeout |
| `keepalive_interval_s` | 30 | Yamux keepalive (0 = disabled) |

## Running Tests

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel $(nproc)
ctest --test-dir build --output-on-failure
```

The test suite covers varint encoding, multiaddr parsing, peer IDs, Noise
handshake, Yamux, Ping, Identify, TCP transport, and integration scenarios.

## Known Issues and Notes

- **BoringSSL commit is exact.** Only commit `7d88bb1bf3372bda1134ad8bf624b25b88e0db86` is compatible with ngtcp2 v1.9.1. Older commits may fail at link time with missing or changed QUIC symbols.
- **Go is required at BoringSSL build time.** BoringSSL uses Go to generate assembly for its QUIC code paths. `go` must be on `$PATH` when running cmake for BoringSSL.
- **BoringSSL library paths.** The static libs are at `build/libssl.a` and `build/libcrypto.a` directly under the BoringSSL build directory — not under any `ssl/` or `crypto/` subdirectory.
- **Echo server default address.** The echo server example binds to `127.0.0.1:9000`. When connecting from another terminal on the same machine, use `/ip4/127.0.0.1/tcp/9000/p2p/<peer-id>`. If the server reports an IPv6 address, use `/ip6/::1/tcp/9000/p2p/<peer-id>`.
- **Key generation.** Only `LP2P_KEY_ED25519` is supported for local host key generation. RSA, secp256k1, and ECDSA are recognized only for verifying remote peer identities.
