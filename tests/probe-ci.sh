#!/usr/bin/env bash
# CI only: keenetic-vpn-probe.sh against the installed server, from the network
# namespace "ext" (192.0.2.2, "WAN" = veth-e), with the sing-box build AWG Manager
# runs on the router (amnezia-box fork, linux-amd64 of the same release) and with
# BusyBox applets instead of GNU tools where the router has BusyBox.
# This is a simulation: there is no Russian home network here.
set -euxo pipefail
FORK_VER="1.15.0-alpha.10-awgm.31"
FORK_SHA="67fd803b7c100f32a3a26d6e57a2b3ff170a8a0639a1374d743b41af5d3337c6"
W=/tmp/probe
mkdir -p "$W"
sudo apt-get -q install -y busybox tcpdump conntrack >/dev/null

gh release download "$FORK_VER" --repo hoaxisr/amnezia-box \
    --pattern "singbox-${FORK_VER}-linux-amd64" --dir "$W" --clobber
echo "$FORK_SHA  $W/singbox-${FORK_VER}-linux-amd64" | sha256sum -c
install -m 755 "$W/singbox-${FORK_VER}-linux-amd64" "$W/sing-box"
"$W/sing-box" version | head -1

# BusyBox applets first in PATH (the router's userland); curl, ip, iptables, tcpdump stay real.
BB="$(command -v busybox)"
mkdir -p "$W/bb"
for a in sh awk sed grep sort cut tr head tail mktemp base64 sha256sum date cat rm rmdir mkdir chmod cp sleep wc printf uname ls readlink od; do
    ln -sf "$(command -v busybox)" "$W/bb/$a"
done
BBPATH="$W/bb:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# The profile as the user copies it to the router; the CI server answers on 192.0.2.1.
sudo sed -E 's/^P_SERVER=.*/P_SERVER=192.0.2.1/; s/^P_NAME=.*/P_NAME=ci/' /root/hy2-probe.env > "$W/ci.env"
chmod 600 "$W/ci.env"
sudo sed -i -E 's/^PROBE_SERVER=.*/PROBE_SERVER=192.0.2.1/' /etc/hy2-secure/probe.env
sudo ip netns exec ext ip route replace default via 192.0.2.1 dev veth-e

probe() {   # extra args...; output JSON in $W/out.json
    sudo ip netns exec ext env PROBE_DEBUG=1 PATH="$BBPATH" "$BB" sh ./keenetic-vpn-probe.sh \
        --profile "$W/ci.env" --runs 2 --payload-bytes 300000 --singbox "$W/sing-box" --output "$W/out.json" "$@"
}
q() { sudo jq -r "$1" "$W/out.json"; }
t() { sudo jq -r --arg t "$1" ".servers[0].tests[] | select(.test == \$t) | $2" "$W/out.json"; }

# 1) clean route: all protocols, route verified by tcpdump on the WAN
probe --all --wan veth-e
sudo jq . "$W/out.json"
test "$(q .schema)" = "hy2-vpn-probe/1"
test "$(t reality .status)" = ok
test "$(t reality .route)" = verified
test "$(t hysteria2 .status)" = ok
test "$(t hysteria2 .route)" = verified
test "$(q '.servers[0].hysteria2_pin_enforced')" = yes
test "$(t tt_h2 .status)" = ok
test "$(t tt_h2 .route)" = verified
echo "tt_h3 via the router's sing-box: $(t tt_h3 .status) / $(t tt_h3 .error) / route $(t tt_h3 .route)"
test "$(q '.servers[0].records | length')" -ge 4
# no secrets in the result
for k in P_HY2_PASSWORD P_REALITY_UUID P_TT_PASS P_KEY; do
    v="$(sed -n "s/^$k=//p" "$W/ci.env")"
    if sudo grep -F "$v" "$W/out.json" >/dev/null; then echo "secret $k leaked into the JSON"; exit 1; fi
done
sudo cat "$W/out.json" > "$W/good.json"

# 2) auto-detected WAN (default route) works too
probe --reality
test "$(q '.wan.interface')" = veth-e
test "$(t reality .route)" = verified

# 3) a policy rule sends everything to a "VPN" interface, and there is no tcpdump:
#    the main route check fails -> route_unverified (the result must not count)
sudo ip netns exec ext ip link add nwg0 type dummy
sudo ip netns exec ext ip link set nwg0 up
sudo ip netns exec ext ip route add default dev nwg0 table 100
sudo ip netns exec ext ip rule add from all lookup 100 pref 100
# a PATH without tcpdump (conntrack stays: its evidence needs clean static checks)
mkdir -p "$W/nodump"
for x in curl ip iptables nft conntrack jq; do ln -sf "$(command -v "$x")" "$W/nodump/$x"; done
sudo ip netns exec ext env PATH="$W/bb:$W/nodump" "$BB" sh ./keenetic-vpn-probe.sh \
    --profile "$W/ci.env" --runs 1 --payload-bytes 0 --singbox "$W/sing-box" --output "$W/out.json" --reality --wan veth-e || true
q '.servers[0].tests'
test "$(t reality .route)" = route_unverified
test "$(q '.servers[0].route_static.ok')" = false
# 3b) same rule, but tcpdump sees the packets leave through the WAN (the socket is bound to it): verified
probe --reality --wan veth-e
test "$(t reality .status)" = ok
test "$(t reality .route)" = verified
sudo ip netns exec ext ip rule del pref 100

# 4) a local redirect of the test traffic: no packets from the test client reach the WAN
sudo ip netns exec ext iptables -t nat -A OUTPUT -p tcp -d 192.0.2.1 --dport 443 -j REDIRECT --to-ports 9
probe --reality --wan veth-e
test "$(t reality .route)" = route_unverified
test "$(t reality .status)" = fail
sudo ip netns exec ext iptables -t nat -F OUTPUT
# 4b) other traffic to the same server and port (like AWG Manager's own tunnel) is not
#     evidence: only packets from the test client's own sockets count
sudo ip netns exec ext setpriv --reuid=65534 --regid=65534 --clear-groups sh -c 'while :; do curl -sk -o /dev/null --max-time 2 https://192.0.2.1/; sleep 0.2; done' &
NOISE=$!
sudo ip netns exec ext iptables -t nat -A OUTPUT -p tcp -d 192.0.2.1 --dport 443 -m owner --uid-owner 0 -j REDIRECT --to-ports 9
probe --reality --wan veth-e
sudo kill "$NOISE" || true; sudo pkill -f "while :; do curl" || true
sudo ip netns exec ext iptables -t nat -F OUTPUT
test "$(t reality .route)" = route_unverified

# 5) WAN missing: the tests are skipped (they would take some other route)
probe --reality --wan nosuchwan0 || true
test "$(q '.wan.state')" = missing
test "$(t reality .status)" = skipped
test "$(t reality .error)" = wan_missing
test "$(t reality .route)" = route_unverified

# 6) no sing-box binary: skipped with a reason, not a fake success
sudo ip netns exec ext env PROBE_DEBUG=1 PATH="$BBPATH" "$BB" sh ./keenetic-vpn-probe.sh \
    --profile "$W/ci.env" --runs 1 --payload-bytes 0 --singbox /nonexistent --output "$W/out.json" --reality --hysteria --wan veth-e
test "$(t reality .status)" = skipped
test "$(t reality .error)" = missing_singbox
test "$(t hysteria2 .status)" = skipped

# 7) invalid profile: refused
sed 's/^P_SERVER=.*/P_SERVER=192.0.2.1;id/' "$W/ci.env" > "$W/bad.env"
rc=0
sudo ip netns exec ext env PROBE_DEBUG=1 PATH="$BBPATH" "$BB" sh ./keenetic-vpn-probe.sh \
    --profile "$W/bad.env" --singbox "$W/sing-box" --output "$W/out.json" --reality --wan veth-e || rc=$?
test "$rc" = 3

# 8) TrustTunnel through the official client (when sing-box has no trusttunnel), HTTP/2 and HTTP/3
TTC="$(find /tmp/ttc -type f -name trusttunnel_client | head -1)"
if [ -n "$TTC" ]; then
    SB_UP="$(find /tmp/sb -type f -name sing-box | head -1)"
    sudo ip netns exec ext env PROBE_DEBUG=1 PATH="$BBPATH" "$BB" sh ./keenetic-vpn-probe.sh \
        --profile "$W/ci.env" --runs 2 --payload-bytes 300000 --singbox "$SB_UP" --tt-client "$TTC" \
        --output "$W/out.json" --trusttunnel --wan veth-e || true
    sudo jq '.servers[0].tests' "$W/out.json"
    echo "tt client: h2 $(t tt_h2 .status) ($(t tt_h2 .error)), h3 $(t tt_h3 .status) ($(t tt_h3 .error))"
    test "$(t tt_h2 .status)" = ok
    test "$(t tt_h3 .status)" = ok          # a normal HTTP/3 run is not mistaken for a fallback
fi

# 8b) the router's own HMAC (BusyBox sh + sha256sum + printf) against OpenSSL, random keys
sed -n '/^hex_to_octal() {/,/^mac_of() {/p' keenetic-vpn-probe.sh | sed '$d' > "$W/hmac.sh"
for i in 1 2 3 4 5 6; do
    k="$(openssl rand -hex 32)"; m="v2|$(date +%s)|$(openssl rand -hex 8)|192.0.2.1|ppp0|tt_h3|a.com|8443|verified|ok|3/3|$i|1|"
    want="$(printf '%s' "$m" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$k" | awk '{print $NF}')"
    got="$(env PATH="$BBPATH" "$BB" sh -c ". $W/hmac.sh; SHA=sha256sum; hmac_selftest || exit 9; hmac_prepare $k; hmac_hex '$m'")"
    echo "busybox hmac $i: $got"; test "$got" = "$want"
done

# 8c) a VPN interface given as the WAN: no test runs (nothing could be proven)
sudo ip netns exec ext ip link add nwg1 type dummy 2>/dev/null || true
sudo ip netns exec ext ip addr add 10.99.0.1/24 dev nwg1 2>/dev/null || true
sudo ip netns exec ext ip link set nwg1 up
probe --reality --wan nwg1 || true
test "$(q '.wan.state')" = not_physical
test "$(t reality .status)" = skipped
test "$(t reality .route)" = route_unverified

# 8d) the router rewrites source ports (masquerade --random-fully): still verified, through conntrack
sudo ip netns exec ext iptables -t nat -A POSTROUTING -o veth-e -p tcp -j MASQUERADE --random-fully
probe --reality --wan veth-e
sudo ip netns exec ext iptables -t nat -F POSTROUTING
test "$(t reality .status)" = ok
test "$(t reality .route)" = verified

# 8e) HTTP/3 that silently falls back to HTTP/2 is a failure, not a success
if [ -n "$TTC" ]; then
    sudo ip netns exec ext iptables -A OUTPUT -p udp --dport 8443 -j DROP
    sudo ip netns exec ext env PROBE_DEBUG=1 PATH="$BBPATH" "$BB" sh ./keenetic-vpn-probe.sh \
        --profile "$W/ci.env" --runs 1 --payload-bytes 0 --singbox "$SB_UP" --tt-client "$TTC" \
        --output "$W/out.json" --trusttunnel --wan veth-e || true
    sudo ip netns exec ext iptables -D OUTPUT -p udp --dport 8443 -j DROP
    echo "h3 with UDP blocked: $(t tt_h3 .status) / $(t tt_h3 .error)"
    test "$(t tt_h3 .status)" = fail
fi

# 8f) a probe killed with SIGKILL leaves nothing that blocks or keeps running
sudo ip netns exec ext env PATH="$BBPATH" "$BB" sh ./keenetic-vpn-probe.sh \
    --profile "$W/ci.env" --runs 3 --payload-bytes 2000000 --singbox "$W/sing-box" --output "$W/k.json" --all --wan veth-e &
for i in $(seq 1 60); do pgrep -f probe-sing-box >/dev/null && break; sleep 0.5; done
sudo pkill -9 -f 'keenetic-vpn-probe.sh --profile' || true
sleep 1
probe --reality --wan veth-e                     # the stale lock does not block it
test "$(t reality .status)" = ok
sleep 1
test -z "$(pgrep -f probe-sing-box || true)"     # the leftovers of the killed run were stopped
test -z "$(ls -d /tmp/vpn-probe.* 2>/dev/null || true)"

# 9) AWG Manager check: an outbound imported from the hysteria2:// link (insecure, no pin) is flagged
PK="$(sed -n 's/^P_HY2_PIN_SPKI=//p' "$W/ci.env")"
sudo mkdir -p /opt/etc/awg-manager/singbox/config.d
printf '{"outbounds":[{"type":"hysteria2","tag":"a","server":"192.0.2.1","server_port":443,"password":"x","tls":{"enabled":true,"server_name":"s","insecure":true}}]}' \
    | sudo tee /opt/etc/awg-manager/singbox/config.d/10-tunnels.json >/dev/null
sudo ip netns exec ext env PROBE_DEBUG=1 PATH="$BBPATH" "$BB" sh ./keenetic-vpn-probe.sh --profile "$W/ci.env" --check-awg --output "$W/out.json"
test "$(q '.servers[0].awg_manager.insecure_without_pin')" = 1
printf '{"outbounds":[{"type":"hysteria2","tag":"a","server":"192.0.2.1","server_port":443,"password":"x","tls":{"enabled":true,"server_name":"s","certificate_public_key_sha256":["%s"]}}]}' "$PK" \
    | sudo tee /opt/etc/awg-manager/singbox/config.d/10-tunnels.json >/dev/null
sudo ip netns exec ext env PROBE_DEBUG=1 PATH="$BBPATH" "$BB" sh ./keenetic-vpn-probe.sh --profile "$W/ci.env" --check-awg --output "$W/out.json"
test "$(q '.servers[0].awg_manager.pinned_with_this_key')" = 1
test "$(q '.servers[0].awg_manager.insecure_without_pin')" = 0
sudo rm -rf /opt/etc/awg-manager

# 10) import on the server. First everything that must be rejected (before the real run is
#     imported: a run is taken only once), then the real run, then a replay of it.
imp() {   # $1 = file; prints the output, sets IRC
    IRC=0; sudo bash ./hy2-secure-install.sh --import-mts "$1" > "$W/imp.log" 2>&1 || IRC=$?
    cat "$W/imp.log"
}
SITE="$(sudo awk -F= '$1=="R_SITE"{print $2}' /usr/local/etc/xray/reality.env)"
# a changed result line
jq '.servers[0].records[0].r |= sub("\\|(ok|fail|degraded)\\|"; "|fail|")' "$W/good.json" > "$W/t1.json"
imp "$W/t1.json"; test "$IRC" = 1; grep -F 'wrong signature, or lines added, removed or changed' "$W/imp.log" >/dev/null
# a dropped line (e.g. hiding a failure): count and hash in the signed header no longer match
jq '.servers[0].records |= .[1:]' "$W/good.json" > "$W/t2.json"
imp "$W/t2.json"; test "$IRC" = 1; grep -F 'wrong signature, or lines added, removed or changed' "$W/imp.log" >/dev/null
# a changed header
jq '.servers[0].run.h |= sub("\\|ppp0\\||\\|veth-e\\|"; "|eth9|")' "$W/good.json" > "$W/t3.json"
imp "$W/t3.json"; test "$IRC" = 1
# unsigned (made without the key)
jq '.servers[0].run.mac = "none"' "$W/good.json" > "$W/t4.json"
imp "$W/t4.json"; test "$IRC" = 1; grep -F 'unsigned run(s)' "$W/imp.log" >/dev/null
# signed with the right key but 40 days old (the HMAC here comes from OpenSSL: it must agree)
KEY="$(sudo sed -n 's/^PROBE_KEY=//p' /etc/hy2-secure/probe.env)"
OLD_TS="$(( $(date +%s) - 40 * 86400 ))"
REC="v2|${OLD_TS}|00000000000000aa|192.0.2.1|veth-e|reality|${SITE}|443|verified|ok|2/2|50|300000|"
HDR="v2run|${OLD_TS}|00000000000000aa|192.0.2.1|veth-e|1|$(printf '%s\n' "$REC" | sha256sum | cut -c1-64)"
hm() { printf '%s' "$1" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${KEY}" | awk '{print $NF}'; }
jq -n --arg r "$REC" --arg m "$(hm "$REC")" --arg h "$HDR" --arg hm "$(hm "$HDR")" \
    '{schema:"hy2-vpn-probe/1",servers:[{run:{h:$h,mac:$hm},records:[{r:$r,mac:$m}]}]}' > "$W/t5.json"
imp "$W/t5.json"; test "$IRC" = 1; grep -F 'older than' "$W/imp.log" >/dev/null
# the same, fresh: accepted (proves the server and OpenSSL agree on HMAC-SHA256)
NOW_TS="$(date +%s)"
REC="v2|${NOW_TS}|00000000000000bb|192.0.2.1|veth-e|hysteria2|example.org|443|route_unverified|ok|2/2|50|300000|"
HDR="v2run|${NOW_TS}|00000000000000bb|192.0.2.1|veth-e|1|$(printf '%s\n' "$REC" | sha256sum | cut -c1-64)"
jq -n --arg r "$REC" --arg m "$(hm "$REC")" --arg h "$HDR" --arg hm "$(hm "$HDR")" \
    '{schema:"hy2-vpn-probe/1",servers:[{run:{h:$h,mac:$hm},records:[{r:$r,mac:$m}]}]}' > "$W/t6.json"
imp "$W/t6.json"; test "$IRC" = 0
# not JSON at all
printf 'not json' > "$W/junk.json"
imp "$W/junk.json"; test "$IRC" = 1
# the real run from the probe: accepted
imp "$W/good.json"; test "$IRC" = 0
grep -F 'result lines accepted' "$W/imp.log" >/dev/null
sudo grep -F "|reality|${SITE}|" /var/lib/hy2-secure/mts-records
n1="$(sudo cat /var/lib/hy2-secure/mts-records | wc -l)"
# replayed: ignored, nothing added
imp "$W/good.json"; test "$IRC" = 0
grep -F 'imported before: ignored (no replays)' "$W/imp.log" >/dev/null
test "$(sudo cat /var/lib/hy2-secure/mts-records | wc -l)" = "$n1"
# the server now reports the home-network status (no secrets in the report)
sudo bash ./hy2-secure-install.sh --diagnose --json "$W/diag.json" | tee "$W/diag.log"
grep -F 'Home network (MTS) for this SNI: ok' "$W/diag.log" >/dev/null
jq -e '.reality.mts_verified == true and .reality.vps_verified == true and .hysteria2.mts_verified == true' "$W/diag.json"
jq -e '.trusttunnel.h2.mts_verified == true' "$W/diag.json"
for k in H_PASSWORD; do
    v="$(sudo sed -n "s/^$k=//p" /etc/hysteria/node.env)"
    if grep -F "$v" "$W/diag.json" >/dev/null; then echo "secret in the report"; exit 1; fi
done
echo "probe CI checks passed"
