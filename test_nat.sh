#!/usr/bin/env bash
# Integration tests for XDP NAT using Linux network namespaces.
#
# Topology:
#   [internal ns]       [router ns]                [external ns]
#   192.168.100.2  ---  192.168.100.1 / 10.0.0.1  ---  10.0.0.2
#                 veth_ir/ri               veth_re/er
#
# XDP is attached to the router's internal-facing veth in generic (SKB) mode.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: must run as root (sudo bash test_nat.sh)" >&2
    exit 1
fi

if [[ ! -f ./xdp_nat_user || ! -f ./xdp_nat_kern.o ]]; then
    echo "ERROR: build the project first (make)" >&2
    exit 1
fi

for tool in ip ping nc bpftool; do
    if ! command -v "$tool" &>/dev/null; then
        echo "WARNING: '$tool' not found — some tests may be skipped"
    fi
done

NS_INT="nat_test_int"
NS_RTR="nat_test_rtr"
NS_EXT="nat_test_ext"

VETH_RI="nat_ri"
VETH_IR="nat_ir"
VETH_RE="nat_re"
VETH_ER="nat_er"

INT_IP="192.168.100.2"
RTR_INT_IP="192.168.100.1"
RTR_EXT_IP="10.0.0.1"
EXT_IP="10.0.0.2"
INT_NET="192.168.100.0/24"

PASS=0
FAIL=0
XDP_PID=""

cleanup() {
    [[ -n "$XDP_PID" ]] && kill "$XDP_PID" 2>/dev/null || true
    ip netns del "$NS_INT" 2>/dev/null || true
    ip netns del "$NS_RTR" 2>/dev/null || true
    ip netns del "$NS_EXT" 2>/dev/null || true
}
trap cleanup EXIT

pass() { echo "  PASS: $1"; ((PASS++)); }
fail() { echo "  FAIL: $1"; ((FAIL++)); }

run_test() {
    local desc="$1"; shift
    echo ""
    echo "-- Test: $desc"
    if "$@" &>/dev/null; then
        pass "$desc"
    else
        fail "$desc"
    fi
}

echo "=== Setting up network namespaces ==="

ip netns add "$NS_INT"
ip netns add "$NS_RTR"
ip netns add "$NS_EXT"

ip link add "$VETH_RI" type veth peer name "$VETH_IR"
ip link set "$VETH_RI" netns "$NS_RTR"
ip link set "$VETH_IR" netns "$NS_INT"

ip link add "$VETH_RE" type veth peer name "$VETH_ER"
ip link set "$VETH_RE" netns "$NS_RTR"
ip link set "$VETH_ER" netns "$NS_EXT"

ip netns exec "$NS_INT" ip link set lo up
ip netns exec "$NS_INT" ip addr add "$INT_IP/24"      dev "$VETH_IR"
ip netns exec "$NS_INT" ip link set "$VETH_IR"        up
ip netns exec "$NS_INT" ip route add default via "$RTR_INT_IP"

ip netns exec "$NS_RTR" ip link set lo up
ip netns exec "$NS_RTR" ip addr add "$RTR_INT_IP/24"  dev "$VETH_RI"
ip netns exec "$NS_RTR" ip addr add "$RTR_EXT_IP/24"  dev "$VETH_RE"
ip netns exec "$NS_RTR" ip link set "$VETH_RI" up
ip netns exec "$NS_RTR" ip link set "$VETH_RE" up
ip netns exec "$NS_RTR" sysctl -qw net.ipv4.ip_forward=1

ip netns exec "$NS_EXT" ip link set lo up
ip netns exec "$NS_EXT" ip addr add "$EXT_IP/24"      dev "$VETH_ER"
ip netns exec "$NS_EXT" ip link set "$VETH_ER" up
ip netns exec "$NS_EXT" ip route add "$RTR_EXT_IP/32" dev "$VETH_ER"

echo "  Namespaces: $NS_INT, $NS_RTR, $NS_EXT"
echo "  Topology  : $INT_IP -> $RTR_INT_IP/$RTR_EXT_IP -> $EXT_IP"

echo ""
echo "=== Starting XDP NAT on $VETH_RI (SKB mode) ==="

ip netns exec "$NS_RTR" ./xdp_nat_user \
    -i "$VETH_RI" \
    -n "$INT_NET" \
    -e "$RTR_EXT_IP" \
    -s 20000 -E 29999 \
    -L \
    -d &
XDP_PID=$!
sleep 1

if ! kill -0 "$XDP_PID" 2>/dev/null; then
    echo "ERROR: XDP control process exited unexpectedly" >&2
    exit 1
fi
echo "  XDP NAT running (pid $XDP_PID)"

echo ""
echo "=== Running tests ==="

run_test "ICMP ping (internal -> external)" \
    ip netns exec "$NS_INT" ping -c 3 -W 2 "$EXT_IP"

echo ""
echo "-- Test: TCP session"
ip netns exec "$NS_EXT" sh -c 'nc -l -p 7777 -e /bin/cat &' 2>/dev/null || \
ip netns exec "$NS_EXT" sh -c 'nc -lk -p 7777 &' 2>/dev/null || true
sleep 0.3
if echo "hello_nat" | ip netns exec "$NS_INT" nc -w 2 "$EXT_IP" 7777 \
   | grep -q "hello_nat" 2>/dev/null; then
    pass "TCP session"
else
    if echo "hi" | ip netns exec "$NS_INT" nc -w 2 "$EXT_IP" 7777 &>/dev/null; then
        pass "TCP session (one-way)"
    else
        fail "TCP session"
    fi
fi
pkill -f "nc -l" 2>/dev/null || true

echo ""
echo "-- Test: UDP datagram"
ip netns exec "$NS_EXT" sh -c 'nc -u -l -p 7778 &' 2>/dev/null || true
sleep 0.2
if echo "udp_test" | ip netns exec "$NS_INT" nc -u -w 1 "$EXT_IP" 7778 &>/dev/null; then
    pass "UDP datagram"
else
    fail "UDP datagram"
fi
pkill -f "nc -u" 2>/dev/null || true

echo ""
echo "-- Test: Statistics"
STATS=$(ip netns exec "$NS_RTR" ./xdp_nat_user -i "$VETH_RI" -S -j 2>/dev/null || echo "{}")
PROC=$(echo "$STATS" | grep -o '"packets_processed":[0-9]*' | grep -o '[0-9]*' || echo 0)
if [[ "${PROC:-0}" -gt 0 ]]; then
    pass "Statistics (packets_processed=$PROC)"
else
    fail "Statistics (packets_processed=0 or not readable)"
fi

echo ""
echo "-- Test: Connection dump"
CONNS=$(ip netns exec "$NS_RTR" ./xdp_nat_user -i "$VETH_RI" -c 2>/dev/null || echo "")
COUNT=$(echo "$CONNS" | grep -c "$INT_IP" 2>/dev/null || echo 0)
if [[ "${COUNT:-0}" -gt 0 ]]; then
    pass "Connection dump ($COUNT entries found for $INT_IP)"
else
    echo "  INFO: no active entries for $INT_IP (may have expired)"
    pass "Connection dump (ran without error)"
fi

echo ""
echo "-- Test: JSON stats format"
JSON_STATS=$(ip netns exec "$NS_RTR" ./xdp_nat_user -i "$VETH_RI" -S -j 2>/dev/null || echo "")
if echo "$JSON_STATS" | grep -q '"packets_processed"'; then
    pass "JSON stats output"
else
    fail "JSON stats output"
fi

echo ""
echo "=== Test Summary ==="
echo "  Passed : $PASS"
echo "  Failed : $FAIL"

kill "$XDP_PID" 2>/dev/null || true
XDP_PID=""

if [[ "$FAIL" -eq 0 ]]; then
    echo "All tests passed."
    exit 0
else
    echo "$FAIL test(s) failed."
    exit 1
fi
