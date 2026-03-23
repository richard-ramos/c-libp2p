#!/usr/bin/env bash
#
# interop/test_interop.sh — Run interop tests between c-libp2p and go-libp2p
#
# Usage: ./test_interop.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

PASS=0
FAIL=0

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

cleanup() {
    echo "Cleaning up containers..."
    docker compose down --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

# ── Build ────────────────────────────────────────────────────────────────────
echo "=== Building containers ==="
docker compose build --quiet

# ── Start go-libp2p node ─────────────────────────────────────────────────────
echo "=== Starting go-libp2p node ==="
docker compose up -d go-node

# Wait for go-node to be ready (max 30 seconds)
echo "Waiting for go-libp2p node to be ready..."
GO_MULTIADDR=""
for i in $(seq 1 30); do
    LOGS=$(docker compose logs go-node 2>/dev/null)
    if echo "$LOGS" | grep -q "GO_READY=1"; then
        # Extract the TCP IPv4 multiaddr (for container-to-container communication)
        GO_MULTIADDR=$(echo "$LOGS" | grep "GO_LISTEN_ADDR=" | grep "/ip4/" | grep "/tcp/" | head -1 | sed 's/.*GO_LISTEN_ADDR=//')
        # Replace the container IP with the service hostname
        GO_PEER_ID=$(echo "$LOGS" | grep "GO_PEER_ID=" | head -1 | sed 's/.*GO_PEER_ID=//')
        break
    fi
    sleep 1
done

if [ -z "$GO_MULTIADDR" ] || [ -z "$GO_PEER_ID" ]; then
    echo "ERROR: go-libp2p node did not start within 30 seconds"
    docker compose logs go-node
    exit 1
fi

echo "Go node ready: $GO_MULTIADDR"

# Build the multiaddr using the docker hostname
GO_TARGET="/ip4/go-node/tcp/4001/p2p/${GO_PEER_ID}"
echo "Target for c-node: $GO_TARGET"

# ── Test 1: Ping (TCP + Ed25519) ─────────────────────────────────────────────
echo ""
echo "=== Test 1: Ping go-libp2p via TCP (Ed25519 peer) ==="
PING_OUTPUT=$(docker compose run --rm c-node ping_peer "$GO_TARGET" 2>&1) || true

echo "$PING_OUTPUT"

# Check that at least one RTT was reported
if echo "$PING_OUTPUT" | grep -qE "RTT\s*=\s*[0-9]+ us"; then
    pass "ping: RTT reported over TCP with Ed25519 peer"
else
    fail "ping: no RTT reported"
fi

# Check that all 5 pings completed
if echo "$PING_OUTPUT" | grep -q "5/5"; then
    pass "ping: all 5 pings completed"
else
    fail "ping: did not complete 5 pings"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "=== Results ==="
echo "  Passed: $PASS"
echo "  Failed: $FAIL"
echo ""

if [ "$FAIL" -gt 0 ]; then
    echo "RESULT: FAIL"
    exit 1
else
    echo "RESULT: PASS"
    exit 0
fi
