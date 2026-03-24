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
docker compose build

# ── Start go-libp2p node ─────────────────────────────────────────────────────
echo "=== Starting go-libp2p node ==="
docker compose up -d go-node

# Wait for go-node to be ready (max 30 seconds)
echo "Waiting for go-libp2p node to be ready..."
GO_LOGS=""
GO_PEER_ID=""
for i in $(seq 1 30); do
    GO_LOGS=$(docker compose logs --no-color go-node 2>/dev/null || true)
    if echo "$GO_LOGS" | grep -q "GO_READY=1"; then
        GO_PEER_ID=$(echo "$GO_LOGS" | grep "GO_PEER_ID=" | head -1 | sed 's/.*GO_PEER_ID=//')
        break
    fi
    sleep 1
done

if [ -z "$GO_PEER_ID" ]; then
    echo "ERROR: go-libp2p node did not start within 30 seconds"
    docker compose logs go-node
    exit 1
fi

TCP_TARGET="/dns4/go-node/tcp/4001/p2p/${GO_PEER_ID}"
QUIC_TARGET="/dns4/go-node/udp/4001/quic-v1/p2p/${GO_PEER_ID}"

echo "Go node ready:"
echo "  TCP target:  $TCP_TARGET"
echo "  QUIC target: $QUIC_TARGET"

if echo "$GO_LOGS" | grep -q "GO_LISTEN_ADDR=.*/tcp/4001/p2p/"; then
    pass "go-node advertised a TCP listen address"
else
    fail "go-node did not advertise a TCP listen address"
fi

if echo "$GO_LOGS" | grep -q "GO_LISTEN_ADDR=.*/udp/4001/quic-v1/p2p/"; then
    pass "go-node advertised a QUIC listen address"
else
    fail "go-node did not advertise a QUIC listen address"
fi

# ── Test 1: Ping over TCP ────────────────────────────────────────────────────
echo ""
echo "=== Test 1: Ping go-libp2p via TCP ==="
PING_TCP_OUTPUT=$(timeout 60s docker compose run --rm -T c-node ping_peer "$TCP_TARGET" 2>&1) || true

echo "$PING_TCP_OUTPUT"

if echo "$PING_TCP_OUTPUT" | grep -qE "Connected to 12D3Koo"; then
    pass "ping/tcp: peer ID is shown in the connection banner"
else
    fail "ping/tcp: connection banner did not include the remote peer ID"
fi

if echo "$PING_TCP_OUTPUT" | grep -qE "RTT\s*=\s*[0-9]+ us"; then
    pass "ping: RTT reported over TCP with Ed25519 peer"
else
    fail "ping: no RTT reported"
fi

if echo "$PING_TCP_OUTPUT" | grep -q "5/5"; then
    pass "ping: all 5 pings completed"
else
    fail "ping: did not complete 5 pings"
fi

# ── Test 2: Echo over TCP ────────────────────────────────────────────────────
echo ""
echo "=== Test 2: Echo go-libp2p via TCP ==="
ECHO_TCP_OUTPUT=$(timeout 60s docker compose run --rm -T c-node echo_client "$TCP_TARGET" "hello from docker over tcp" 2>&1) || true

echo "$ECHO_TCP_OUTPUT"

if echo "$ECHO_TCP_OUTPUT" | grep -q "Echoed: hello from docker over tcp"; then
    pass "echo/tcp: echoed payload matched"
else
    fail "echo/tcp: echoed payload did not match"
fi

# ── Test 3: Ping over QUIC ───────────────────────────────────────────────────
echo ""
echo "=== Test 3: Ping go-libp2p via QUIC ==="
PING_QUIC_OUTPUT=$(timeout 60s docker compose run --rm -T c-node ping_peer "$QUIC_TARGET" 2>&1) || true

echo "$PING_QUIC_OUTPUT"

if echo "$PING_QUIC_OUTPUT" | grep -qE "RTT\s*=\s*[0-9]+ us"; then
    pass "ping/quic: RTT reported"
else
    fail "ping/quic: no RTT reported"
fi

if echo "$PING_QUIC_OUTPUT" | grep -q "5/5"; then
    pass "ping/quic: all 5 pings completed"
else
    fail "ping/quic: did not complete 5 pings"
fi

# ── Test 4: Echo over QUIC ───────────────────────────────────────────────────
echo ""
echo "=== Test 4: Echo go-libp2p via QUIC ==="
ECHO_QUIC_OUTPUT=$(timeout 60s docker compose run --rm -T c-node echo_client "$QUIC_TARGET" "hello from docker over quic" 2>&1) || true

echo "$ECHO_QUIC_OUTPUT"

if echo "$ECHO_QUIC_OUTPUT" | grep -q "Echoed: hello from docker over quic"; then
    pass "echo/quic: echoed payload matched"
else
    fail "echo/quic: echoed payload did not match"
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
