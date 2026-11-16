#!/usr/bin/env bash
# Multi-host harness: real TCP, QUIC, relays, hole punching, mDNS and AutoNAT between
# Linux network namespaces, with NAT routers in between. Needs root (or sudo), iproute2 and
# iptables. Usage: sudo harness/netns.sh path/to/netns_node
#
#   wn-relay  7.0.0.1  ── "internet" bridge (in wn-net) ──┬── wn-ra 7.0.0.2 (NAT) ── lan 192.168.10.0/24: wn-a1 .2, wn-a2 .3
#                                                               ├── wn-rb 7.0.0.3 (NAT) ── lan 192.168.20.0/24: wn-b1 .2
#                                                               └── wn-rc 7.0.0.4 (symmetric NAT) ── lan 192.168.30.0/24: wn-c1 .2
#
# Scenarios:
#   1. relay sees itself public; hosts behind NAT see themselves private and reserve on it
#   2. a1 ↔ b1 across two cone NATs: reached through the relay, then a direct path by hole punching
#   3. a1 ↔ c1 with a symmetric NAT: stays on the relay, stream and fetch still complete
#   4. a1 ↔ a2 on one LAN with no relay: found by mDNS, direct
#   5. QUIC to the relay through the symmetric NAT
set -euo pipefail
BIN=${1:?usage: netns.sh path/to/netns_node}
BIN=$(readlink -f "$BIN")
OUT=${OUT:-/tmp/wn-harness}
rm -rf "$OUT"; mkdir -p "$OUT"
NS=(wn-net wn-relay wn-ra wn-rb wn-rc wn-a1 wn-a2 wn-b1 wn-c1)
PIDS=()

cleanup() {
  for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done
  wait 2>/dev/null || true
  for n in "${NS[@]}"; do ip netns del "$n" 2>/dev/null || true; done
}
trap cleanup EXIT
cleanup

for n in "${NS[@]}"; do ip netns add "$n"; ip -n "$n" link set lo up; done
ip -n wn-net link add br0 type bridge && ip -n wn-net link set br0 up

# put namespace $1 on the internet bridge as $2
wan() {
  ip link add "v-$1" type veth peer name "w-$1"
  ip link set "v-$1" netns wn-net && ip -n wn-net link set "v-$1" master br0 up
  ip link set "w-$1" netns "$1" && ip -n "$1" link set "w-$1" name wan
  ip -n "$1" addr add "$2/24" dev wan && ip -n "$1" link set wan up
}
# a router $1 with LAN $2 (x.y.z) and hosts ($3...: ns:last-octet), NAT kind $NAT
router() {
  local r=$1 lan=$2; shift 2
  ip netns exec "$r" sysctl -qw net.ipv4.ip_forward=1
  ip -n "$r" link add br-lan type bridge && ip -n "$r" link set br-lan up
  ip -n "$r" addr add "$lan.1/24" dev br-lan
  for h in "$@"; do
    local ns=${h%%:*} oct=${h##*:}
    ip link add "l-$ns" type veth peer name "h-$ns"
    ip link set "l-$ns" netns "$r" && ip -n "$r" link set "l-$ns" master br-lan up
    ip link set "h-$ns" netns "$ns" && ip -n "$ns" link set "h-$ns" name eth0
    ip -n "$ns" addr add "$lan.$oct/24" dev eth0 && ip -n "$ns" link set eth0 up
    ip -n "$ns" route add default via "$lan.1"
  done
  if [ "$NAT" = symmetric ]; then
    ip netns exec "$r" iptables -t nat -A POSTROUTING -o wan -j MASQUERADE --random-fully
  else
    ip netns exec "$r" iptables -t nat -A POSTROUTING -o wan -j MASQUERADE
  fi
  # nothing comes in unasked
  ip netns exec "$r" iptables -A FORWARD -i wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip netns exec "$r" iptables -A FORWARD -i wan -j DROP
  # and the router itself answers nothing (a home router drops, it does not reset)
  ip netns exec "$r" iptables -A INPUT -i wan -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
  ip netns exec "$r" iptables -A INPUT -i wan -j DROP
}

wan wn-relay 7.0.0.1
wan wn-ra 7.0.0.2
wan wn-rb 7.0.0.3
wan wn-rc 7.0.0.4
NAT=cone router wn-ra 192.168.10 wn-a1:2 wn-a2:3
NAT=cone router wn-rb 192.168.20 wn-b1:2
NAT=symmetric router wn-rc 192.168.30 wn-c1:2

# multicast for mDNS on the LAN bridge
ip -n wn-a1 route add 224.0.0.0/4 dev eth0 2>/dev/null || true
ip -n wn-a2 route add 224.0.0.0/4 dev eth0 2>/dev/null || true

RELAY_ID=$("$BIN" id 1); A1=$("$BIN" id 11); A2=$("$BIN" id 12); B1=$("$BIN" id 21); C1=$("$BIN" id 31)
RELAY=/ip4/7.0.0.1/tcp/4747/p2p/$RELAY_ID
echo "relay $RELAY_ID a1 $A1 b1 $B1 c1 $C1 a2 $A2"

start() { # ns name args...
  local ns=$1 name=$2; shift 2
  ip netns exec "$ns" env RUST_LOG=${RUST_LOG:-info} "$BIN" "$@" >"$OUT/$name.out" 2>"$OUT/$name.log" &
  PIDS+=($!)
}
start wn-relay relay relay 1 7.0.0.1
sleep 1
start wn-a1 a1 host 11 "$RELAY"

FAIL=0
check() { # name ns args...
  local name=$1 ns=$2; shift 2
  echo "== $name"
  if ip netns exec "$ns" env RUST_LOG=${RUST_LOG:-info} timeout 180 "$BIN" "$@" >"$OUT/$name.json" 2>"$OUT/$name.log"; then
    echo "ok: $(cat "$OUT/$name.json")"
  else
    echo "FAILED: $(cat "$OUT/$name.json" 2>/dev/null)"; tail -n 30 "$OUT/$name.log"; FAIL=1
  fi
}

# 1. a1 reserves on the relay and learns it is behind NAT
for _ in $(seq 60); do grep -q "reservations=\[\"$RELAY_ID\"\]" "$OUT/a1.log" && break; sleep 1; done
grep -q "reservations=\[\"$RELAY_ID\"\]" "$OUT/a1.log" && echo "ok: a1 reserved on the relay" || { echo "FAILED: a1 has no reservation"; tail -n 30 "$OUT/a1.log"; FAIL=1; }

# 2. across two cone NATs: relay first, then direct
check cone-to-cone wn-b1 client 21 "$A1" "$RELAY" --expect direct
# 3. symmetric NAT: the relay carries it
check symmetric wn-c1 client 31 "$A1" "$RELAY" --expect relay
# 4. the same LAN, no relay: mDNS
check mdns wn-a2 client 12 "$A1" --expect direct

# 5. QUIC to the relay (UDP through the symmetric NAT)
check quic-relay wn-c1 client 32 "$A1" "/ip4/7.0.0.1/udp/4747/quic-v1/p2p/$RELAY_ID" --expect relay

# 1b. AutoNAT: the relay is public, a1 private (probes start some seconds in)
for _ in $(seq 90); do grep -q "nat=private" "$OUT/a1.log" && grep -q "nat=public" "$OUT/relay.log" && break; sleep 1; done
grep -q "nat=private" "$OUT/a1.log" && echo "ok: AutoNAT says a1 is private" || { echo "FAILED: AutoNAT gave a1 no private verdict"; FAIL=1; }
grep -q "nat=public" "$OUT/relay.log" && echo "ok: AutoNAT says the relay is public" || { echo "FAILED: AutoNAT gave the relay no public verdict"; FAIL=1; }

exit $FAIL
