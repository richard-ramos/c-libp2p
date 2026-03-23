#!/bin/bash
# Install c-libp2p build dependencies on Ubuntu
set -e

echo "=== Installing c-libp2p build dependencies ==="

apt-get update -qq
apt-get install -y \
    build-essential \
    cmake \
    pkg-config \
    libuv1-dev \
    libsodium-dev \
    libssl-dev \
    libprotobuf-c-dev \
    protobuf-c-compiler \
    git \
    valgrind

# ngtcp2 is not in apt — build from source
echo ""
echo "=== Building ngtcp2 from source ==="
NGTCP2_VERSION="v1.9.1"
TMPDIR=$(mktemp -d)
cd "$TMPDIR"
git clone --depth 1 --branch "$NGTCP2_VERSION" https://github.com/ngtcp2/ngtcp2.git
cd ngtcp2
autoreconf -i 2>/dev/null || cmake -B build -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_OPENSSL=ON \
    -DENABLE_STATIC_LIB=ON
cmake --build build --parallel "$(nproc)"
cmake --install build
ldconfig

echo ""
echo "=== All dependencies installed! ==="
echo "Now run:"
echo "  mv ~/richard-ramos/nanoclaw/groups/telegram_main/c-libp2p ~/richard-ramos/c-libp2p"
echo "  cd ~/richard-ramos/c-libp2p"
echo "  cmake -B build && cmake --build build"
