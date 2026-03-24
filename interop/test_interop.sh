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
CLIENT_TIMEOUT="${CLIENT_TIMEOUT:-40s}"
READY_TIMEOUT_S="${READY_TIMEOUT_S:-30}"
GO_CLIENT_TIMEOUT="${GO_CLIENT_TIMEOUT:-30s}"
GO_PING_COUNT="${GO_PING_COUNT:-3}"
GO_SETTLE="${GO_SETTLE:-100ms}"
GO_TCP_CLIENT_RETRIES="${GO_TCP_CLIENT_RETRIES:-3}"
GO_TCP_CLIENT_RETRY_DELAY="${GO_TCP_CLIENT_RETRY_DELAY:-1s}"

pass() { echo "  PASS: $1"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL + 1)); }

run_capture() {
    local __outvar=$1
    shift

    local tmp
    local tail_pid
    local status

    tmp=$(mktemp)
    : >"$tmp"

    tail -n +1 -f "$tmp" &
    tail_pid=$!

    set +e
    "$@" >"$tmp" 2>&1
    status=$?
    set -e

    kill "$tail_pid" 2>/dev/null || true
    wait "$tail_pid" 2>/dev/null || true
    printf -v "$__outvar" '%s' "$(cat "$tmp")"
    rm -f "$tmp"
    return "$status"
}

run_capture_retry() {
    local __outvar=$1
    local attempts=$2
    local delay=$3
    shift 3

    local combined=""
    local attempt_output=""
    local status=0
    local attempt=1

    while [ "$attempt" -le "$attempts" ]; do
        status=0
        run_capture attempt_output "$@" || status=$?

        if [ -n "$combined" ]; then
            combined+=$'\n'
        fi
        combined+="$attempt_output"

        if [ "$status" -eq 0 ]; then
            printf -v "$__outvar" '%s' "$combined"
            return 0
        fi

        if [ "$attempt" -lt "$attempts" ]; then
            echo "Retrying command after exit status ${status} (${attempt}/${attempts})..."
            sleep "$delay"
        fi

        attempt=$((attempt + 1))
    done

    printf -v "$__outvar" '%s' "$combined"
    return "$status"
}

wait_for_logs() {
    local service=$1
    local pattern=$2
    local timeout_s=$3
    local __outvar=$4
    local logs=""

    for _ in $(seq 1 "$timeout_s"); do
        logs=$(docker compose logs --no-color "$service" 2>/dev/null || true)
        if echo "$logs" | grep -qE "$pattern"; then
            printf -v "$__outvar" '%s' "$logs"
            return 0
        fi
        sleep 1
    done

    printf -v "$__outvar" '%s' "$logs"
    return 1
}

container_ip() {
    local service=$1
    local cid

    cid=$(docker compose ps -q "$service")
    if [ -z "$cid" ]; then
        return 1
    fi

    docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$cid"
}

wait_for_running() {
    local service=$1
    local timeout_s=$2
    local cid=""
    local state=""

    for _ in $(seq 1 "$timeout_s"); do
        cid=$(docker compose ps -q "$service")
        if [ -n "$cid" ]; then
            state=$(docker inspect -f '{{.State.Status}}' "$cid" 2>/dev/null || true)
            if [ "$state" = "running" ]; then
                return 0
            fi
        fi
        sleep 1
    done

    return 1
}

show_server_logs_on_failure() {
    if [ "$FAIL" -eq 0 ]; then
        return
    fi

    echo ""
    echo "=== Server Logs ==="
    docker compose logs --no-color go-node c-server-tcp c-server-quic 2>/dev/null || true
}

cleanup() {
    show_server_logs_on_failure
    echo "Cleaning up containers..."
    docker compose down --remove-orphans 2>/dev/null || true
}
trap cleanup EXIT

echo "=== Building containers ==="
docker compose build

echo "=== Starting interop containers ==="
docker compose up -d go-node c-node c-server-tcp c-server-quic

if ! wait_for_running c-node "$READY_TIMEOUT_S"; then
    echo "ERROR: c-node did not reach running state within ${READY_TIMEOUT_S} seconds"
    docker compose ps
    exit 1
fi

echo "Waiting for go-libp2p node to be ready..."
GO_LOGS=""
GO_PEER_ID=""
if wait_for_logs go-node 'GO_READY=1' "$READY_TIMEOUT_S" GO_LOGS; then
    GO_PEER_ID=$(echo "$GO_LOGS" | sed -n 's/.*GO_PEER_ID=//p' | head -1)
fi

if [ -z "$GO_PEER_ID" ]; then
    echo "ERROR: go-libp2p node did not start within ${READY_TIMEOUT_S} seconds"
    docker compose logs go-node
    exit 1
fi

GO_NODE_IP="$(container_ip go-node || true)"
if [ -z "$GO_NODE_IP" ]; then
    echo "ERROR: could not determine go-node container IP"
    exit 1
fi

GO_TCP_TARGET="/ip4/${GO_NODE_IP}/tcp/4001/p2p/${GO_PEER_ID}"
GO_QUIC_TARGET="/ip4/${GO_NODE_IP}/udp/4001/quic-v1/p2p/${GO_PEER_ID}"

echo "Go node ready:"
echo "  TCP target:  $GO_TCP_TARGET"
echo "  QUIC target: $GO_QUIC_TARGET"

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

echo ""
echo "Waiting for c-libp2p TCP server..."
C_TCP_LOGS=""
C_TCP_PEER_ID=""
if wait_for_logs c-server-tcp 'Listening on:' "$READY_TIMEOUT_S" C_TCP_LOGS; then
    C_TCP_PEER_ID=$(echo "$C_TCP_LOGS" | sed -n 's/^.*Peer ID: //p' | head -1)
fi
if [ -z "$C_TCP_PEER_ID" ]; then
    echo "ERROR: c-server-tcp did not start within ${READY_TIMEOUT_S} seconds"
    docker compose logs c-server-tcp
    exit 1
fi

echo "Waiting for c-libp2p QUIC server..."
C_QUIC_LOGS=""
C_QUIC_PEER_ID=""
if wait_for_logs c-server-quic 'Listening on:' "$READY_TIMEOUT_S" C_QUIC_LOGS; then
    C_QUIC_PEER_ID=$(echo "$C_QUIC_LOGS" | sed -n 's/^.*Peer ID: //p' | head -1)
fi
if [ -z "$C_QUIC_PEER_ID" ]; then
    echo "ERROR: c-server-quic did not start within ${READY_TIMEOUT_S} seconds"
    docker compose logs c-server-quic
    exit 1
fi

C_SERVER_TCP_IP="$(container_ip c-server-tcp || true)"
C_SERVER_QUIC_IP="$(container_ip c-server-quic || true)"

if [ -z "$C_SERVER_TCP_IP" ] || [ -z "$C_SERVER_QUIC_IP" ]; then
    echo "ERROR: could not determine c-libp2p server container IPs"
    exit 1
fi

C_TCP_TARGET="/ip4/${C_SERVER_TCP_IP}/tcp/9000/p2p/${C_TCP_PEER_ID}"
C_QUIC_TARGET="/ip4/${C_SERVER_QUIC_IP}/udp/9000/quic-v1/p2p/${C_QUIC_PEER_ID}"

echo "C servers ready:"
echo "  TCP target:  $C_TCP_TARGET"
echo "  QUIC target: $C_QUIC_TARGET"

echo ""
echo "=== Test 1: C -> Go ping over TCP ==="
PING_TCP_OUTPUT=""
PING_TCP_STATUS=0
run_capture PING_TCP_OUTPUT timeout "$CLIENT_TIMEOUT" docker compose exec --interactive=false -T c-node stdbuf -oL -eL ping_peer "$GO_TCP_TARGET" || PING_TCP_STATUS=$?

if [ "$PING_TCP_STATUS" -eq 0 ]; then
    pass "c->go ping/tcp: command exited successfully"
else
    fail "c->go ping/tcp: command exited with status $PING_TCP_STATUS"
fi

if echo "$PING_TCP_OUTPUT" | grep -qE "Connected to 12D3Koo"; then
    pass "c->go ping/tcp: peer ID is shown in the connection banner"
else
    fail "c->go ping/tcp: connection banner did not include the remote peer ID"
fi

if echo "$PING_TCP_OUTPUT" | grep -qE "RTT\s*=\s*[0-9]+ us"; then
    pass "c->go ping/tcp: RTT reported"
else
    fail "c->go ping/tcp: no RTT reported"
fi

if echo "$PING_TCP_OUTPUT" | grep -q "5/5"; then
    pass "c->go ping/tcp: all 5 pings completed"
else
    fail "c->go ping/tcp: did not complete 5 pings"
fi

echo ""
echo "=== Test 2: C -> Go echo over TCP ==="
ECHO_TCP_OUTPUT=""
ECHO_TCP_STATUS=0
run_capture ECHO_TCP_OUTPUT timeout "$CLIENT_TIMEOUT" docker compose exec --interactive=false -T c-node stdbuf -oL -eL echo_client "$GO_TCP_TARGET" "hello from docker over tcp" || ECHO_TCP_STATUS=$?

if [ "$ECHO_TCP_STATUS" -eq 0 ]; then
    pass "c->go echo/tcp: command exited successfully"
else
    fail "c->go echo/tcp: command exited with status $ECHO_TCP_STATUS"
fi

if echo "$ECHO_TCP_OUTPUT" | grep -q "Echoed: hello from docker over tcp"; then
    pass "c->go echo/tcp: echoed payload matched"
else
    fail "c->go echo/tcp: echoed payload did not match"
fi

echo ""
echo "=== Test 3: C -> Go ping over QUIC ==="
PING_QUIC_OUTPUT=""
PING_QUIC_STATUS=0
run_capture PING_QUIC_OUTPUT timeout "$CLIENT_TIMEOUT" docker compose exec --interactive=false -T c-node stdbuf -oL -eL ping_peer "$GO_QUIC_TARGET" || PING_QUIC_STATUS=$?

if [ "$PING_QUIC_STATUS" -eq 0 ]; then
    pass "c->go ping/quic: command exited successfully"
else
    fail "c->go ping/quic: command exited with status $PING_QUIC_STATUS"
fi

if echo "$PING_QUIC_OUTPUT" | grep -qE "RTT\s*=\s*[0-9]+ us"; then
    pass "c->go ping/quic: RTT reported"
else
    fail "c->go ping/quic: no RTT reported"
fi

if echo "$PING_QUIC_OUTPUT" | grep -q "5/5"; then
    pass "c->go ping/quic: all 5 pings completed"
else
    fail "c->go ping/quic: did not complete 5 pings"
fi

echo ""
echo "=== Test 4: C -> Go echo over QUIC ==="
ECHO_QUIC_OUTPUT=""
ECHO_QUIC_STATUS=0
run_capture ECHO_QUIC_OUTPUT timeout "$CLIENT_TIMEOUT" docker compose exec --interactive=false -T c-node stdbuf -oL -eL echo_client "$GO_QUIC_TARGET" "hello from docker over quic" || ECHO_QUIC_STATUS=$?

if [ "$ECHO_QUIC_STATUS" -eq 0 ]; then
    pass "c->go echo/quic: command exited successfully"
else
    fail "c->go echo/quic: command exited with status $ECHO_QUIC_STATUS"
fi

if echo "$ECHO_QUIC_OUTPUT" | grep -q "Echoed: hello from docker over quic"; then
    pass "c->go echo/quic: echoed payload matched"
else
    fail "c->go echo/quic: echoed payload did not match"
fi

echo ""
echo "=== Test 5: Go -> C ping over TCP ==="
GO_PING_TCP_OUTPUT=""
GO_PING_TCP_STATUS=0
run_capture_retry GO_PING_TCP_OUTPUT "$GO_TCP_CLIENT_RETRIES" "$GO_TCP_CLIENT_RETRY_DELAY" \
    timeout "$CLIENT_TIMEOUT" docker compose exec --interactive=false -T go-node \
    go-libp2p-interop ping-client \
    --target "$C_TCP_TARGET" \
    --count "$GO_PING_COUNT" \
    --settle "$GO_SETTLE" \
    --timeout "$GO_CLIENT_TIMEOUT" || GO_PING_TCP_STATUS=$?

if [ "$GO_PING_TCP_STATUS" -eq 0 ]; then
    pass "go->c ping/tcp: command exited successfully"
else
    fail "go->c ping/tcp: command exited with status $GO_PING_TCP_STATUS"
fi

if echo "$GO_PING_TCP_OUTPUT" | grep -q "Connected to ${C_TCP_PEER_ID}"; then
    pass "go->c ping/tcp: connected to the expected peer ID"
else
    fail "go->c ping/tcp: connection banner did not match the expected peer ID"
fi

if echo "$GO_PING_TCP_OUTPUT" | grep -qE "RTT\s*=\s*[0-9]+ us"; then
    pass "go->c ping/tcp: RTT reported"
else
    fail "go->c ping/tcp: no RTT reported"
fi

if echo "$GO_PING_TCP_OUTPUT" | grep -q "ping ${GO_PING_COUNT}/${GO_PING_COUNT}"; then
    pass "go->c ping/tcp: all pings completed"
else
    fail "go->c ping/tcp: did not complete ${GO_PING_COUNT} pings"
fi

echo ""
echo "=== Test 6: Go -> C echo over TCP ==="
GO_ECHO_TCP_OUTPUT=""
GO_ECHO_TCP_STATUS=0
run_capture_retry GO_ECHO_TCP_OUTPUT "$GO_TCP_CLIENT_RETRIES" "$GO_TCP_CLIENT_RETRY_DELAY" \
    timeout "$CLIENT_TIMEOUT" docker compose exec --interactive=false -T go-node \
    go-libp2p-interop echo-client \
    --target "$C_TCP_TARGET" \
    --message "hello from go to c over tcp" \
    --settle "$GO_SETTLE" \
    --timeout "$GO_CLIENT_TIMEOUT" || GO_ECHO_TCP_STATUS=$?

if [ "$GO_ECHO_TCP_STATUS" -eq 0 ]; then
    pass "go->c echo/tcp: command exited successfully"
else
    fail "go->c echo/tcp: command exited with status $GO_ECHO_TCP_STATUS"
fi

if echo "$GO_ECHO_TCP_OUTPUT" | grep -q "Echoed: hello from go to c over tcp"; then
    pass "go->c echo/tcp: echoed payload matched"
else
    fail "go->c echo/tcp: echoed payload did not match"
fi

echo ""
echo "=== Test 7: Go -> C ping over QUIC ==="
GO_PING_QUIC_OUTPUT=""
GO_PING_QUIC_STATUS=0
run_capture GO_PING_QUIC_OUTPUT timeout "$CLIENT_TIMEOUT" docker compose exec --interactive=false -T go-node \
    go-libp2p-interop ping-client \
    --target "$C_QUIC_TARGET" \
    --count "$GO_PING_COUNT" \
    --settle "$GO_SETTLE" \
    --timeout "$GO_CLIENT_TIMEOUT" || GO_PING_QUIC_STATUS=$?

if [ "$GO_PING_QUIC_STATUS" -eq 0 ]; then
    pass "go->c ping/quic: command exited successfully"
else
    fail "go->c ping/quic: command exited with status $GO_PING_QUIC_STATUS"
fi

if echo "$GO_PING_QUIC_OUTPUT" | grep -q "Connected to ${C_QUIC_PEER_ID}"; then
    pass "go->c ping/quic: connected to the expected peer ID"
else
    fail "go->c ping/quic: connection banner did not match the expected peer ID"
fi

if echo "$GO_PING_QUIC_OUTPUT" | grep -qE "RTT\s*=\s*[0-9]+ us"; then
    pass "go->c ping/quic: RTT reported"
else
    fail "go->c ping/quic: no RTT reported"
fi

if echo "$GO_PING_QUIC_OUTPUT" | grep -q "ping ${GO_PING_COUNT}/${GO_PING_COUNT}"; then
    pass "go->c ping/quic: all pings completed"
else
    fail "go->c ping/quic: did not complete ${GO_PING_COUNT} pings"
fi

echo ""
echo "=== Test 8: Go -> C echo over QUIC ==="
GO_ECHO_QUIC_OUTPUT=""
GO_ECHO_QUIC_STATUS=0
run_capture GO_ECHO_QUIC_OUTPUT timeout "$CLIENT_TIMEOUT" docker compose exec --interactive=false -T go-node \
    go-libp2p-interop echo-client \
    --target "$C_QUIC_TARGET" \
    --message "hello from go to c over quic" \
    --settle "$GO_SETTLE" \
    --timeout "$GO_CLIENT_TIMEOUT" || GO_ECHO_QUIC_STATUS=$?

if [ "$GO_ECHO_QUIC_STATUS" -eq 0 ]; then
    pass "go->c echo/quic: command exited successfully"
else
    fail "go->c echo/quic: command exited with status $GO_ECHO_QUIC_STATUS"
fi

if echo "$GO_ECHO_QUIC_OUTPUT" | grep -q "Echoed: hello from go to c over quic"; then
    pass "go->c echo/quic: echoed payload matched"
else
    fail "go->c echo/quic: echoed payload did not match"
fi

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
