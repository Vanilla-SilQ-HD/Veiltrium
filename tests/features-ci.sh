#!/usr/bin/env bash
# CI only: the features added on 2026-10-20, end to end with real clients. Runs after the other
# steps of e2e.yml (tests/sites-setup.sh must have run: it provides the fast download target) and
# uses the sing-box (/tmp/sb) and TrustTunnel (/tmp/ttc) clients those steps downloaded.
#   a  traffic counters      b  limits, disable/enable, expiry     c  reset-client
#   d  standby servers       f  alerts (unreachable webhook)       g  the short command, QR codes
#   e  export, uninstall, import on the same machine (LAST: it reinstalls the node)
# FEATURES_REINSTALL=0 skips e.
set -euo pipefail
cd "$(dirname "$0")/.."
SB="$(find /tmp/sb -type f -name sing-box | head -1)"
TTC="$(find /tmp/ttc -type f -name trusttunnel_client | head -1)"
test -x "$SB"; test -x "$TTC"
W="$(mktemp -d)"
FAST_URL=http://11.22.33.44/fast       # 8 MB, no rate limit (tests/sites-setup.sh)
FAST_MIN=8000000
WHAT=204                               # what the client cases fetch: 204 (a probe) | big (the fast file, then a counter read)

inst() { sudo env NEEDRESTART_SUSPEND=1 VT_AUTO_REBOOT=0 PANEL_BINARY="${PANEL_BINARY:-}" bash ./veiltrium.sh "$@"; }
instenv() {   # VAR=value ... [installer arguments]
    local -a e=()
    while [ $# -gt 0 ] && [[ "$1" == *=* ]]; do e+=("$1"); shift; done
    sudo env NEEDRESTART_SUSPEND=1 VT_AUTO_REBOOT=0 PANEL_BINARY="${PANEL_BINARY:-}" ${e[@]+"${e[@]}"} bash ./veiltrium.sh "$@"
}
collect() { sudo bash ./veiltrium.sh --collect-traffic > /dev/null 2>&1 || true; }
code204() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 12 --socks5-hostname "127.0.0.1:$1" \
        https://www.gstatic.com/generate_204 || true
}
fetch() {   # $1 = local SOCKS port
    local r
    if [ "$WHAT" = big ]; then
        r="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 90 --socks5-hostname "127.0.0.1:$1" "$FAST_URL" || true)"
        collect      # while the client is still connected: the proxies count what has passed
        printf '%s' "$r"
    else
        code204 "$1"
    fi
}
wait_port() { for _ in $(seq 1 40); do [ -n "$(ss -Htln "sport = :$1")" ] && return 0; sleep 0.3; done; return 1; }
stop() { kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }

hy_case() {   # $1 = hysteria2:// link
    local pid c
    printf 'server: "%s"\nsocks5:\n  listen: 127.0.0.1:18101\n' \
        "$(printf '%s' "$1" | sed -E 's#@[^:/]+:#@127.0.0.1:#')" > "$W/h.yaml"
    /usr/local/bin/hysteria client -c "$W/h.yaml" > "$W/h.log" 2>&1 &
    pid=$!
    wait_port 18101 || true
    c="$(fetch 18101)"; stop "$pid"; if [ "$WHAT" = big ]; then collect; fi; printf '%s' "$c"
}
sb_case() {   # $1 = file with one sing-box outbound
    local pid c
    jq '.server = "127.0.0.1"' "$1" > "$W/ob.json"
    jq -n --slurpfile ob "$W/ob.json" '{log: {level: "error"},
        inbounds: [{type: "socks", tag: "in", listen: "127.0.0.1", listen_port: 18102}],
        outbounds: $ob, route: {final: $ob[0].tag}}' > "$W/sb.json"
    "$SB" run -c "$W/sb.json" > "$W/sb.log" 2>&1 &
    pid=$!
    wait_port 18102 || true
    c="$(fetch 18102)"; stop "$pid"; if [ "$WHAT" = big ]; then collect; fi; printf '%s' "$c"
}
tt_case() {   # $1 = user, $2 = password (HTTP/2)
    local c
    {
        printf 'loglevel = "info"\nvpn_mode = "general"\nkillswitch_enabled = false\n\n[endpoint]\n'
        printf 'hostname = "%s"\naddresses = ["127.0.0.1:%s"]\nusername = "%s"\npassword = "%s"\n' "$TSNI" "$TTPORT" "$1" "$2"
        printf 'has_ipv6 = false\nskip_verification = false\nupstream_protocol = "http2"\n'
        printf "certificate = '''\n%s\n'''\n" "$(sudo cat /etc/trusttunnel/cert.pem)"
        printf '\n[listener.socks]\naddress = "127.0.0.1:18103"\n'
    } > "$W/t.toml"
    sudo "$TTC" --config "$W/t.toml" > "$W/t.log" 2>&1 &
    wait_port 18103 || true
    sleep 2
    c="$(fetch 18103)"
    sudo pkill -f "trusttunnel_client --config $W/t.toml" || true
    for _ in $(seq 1 40); do [ -z "$(ss -Htln 'sport = :18103')" ] && break; sleep 0.3; done
    if [ "$WHAT" = big ]; then collect; fi
    printf '%s' "$c"
}
sec() {   # $1 = file, $2 = 2|4 -> that JSON object of a client file
    case "$2" in
        2) sudo awk '/^\{/{n++} n==1{print} n==1&&/^\}/{exit}' "$1" ;;
        4) sudo awk '/^\{/{n++} n==2{print} n==2&&/^\}/{exit}' "$1" ;;
    esac
}
arr() {   # $1 = file, $2 = n -> the n-th JSON array (a line "[" to a line "]") of a client file
    sudo awk -v want="$2" '/^\[$/{n++; f=(n==want)} f{print} f&&/^\]$/{f=0}' "$1"
}
fail() { echo "FAILED: $*"; tail -20 "$W"/*.log 2>/dev/null || true; exit 1; }
expect() {   # $1 = name, $2 = got, $3 = want (204 | not204 | big | notbig)
    local ok=0
    case "$3" in
        204) [ "$2" = 204 ] && ok=1 ;;
        not204) [ "$2" != 204 ] && ok=1 ;;
        big) [[ "$2" == "200 "* ]] && (( ${2#200 } >= FAST_MIN )) && ok=1 ;;
    esac
    echo "CASE $1 -> $2 (expected $3)"
    [ "$ok" = 1 ] || fail "$1"
}
creds() {   # the links without their display name: '#name' of hysteria2/vless, TLV field 0x0C of tt://
    sudo grep -hE '^(hysteria2|vless|tt)://' "$@" | python3 -c '
import base64, sys
for line in sys.stdin.read().split():
    if not line.startswith("tt://"):
        print(line.split("#")[0]); continue
    b = line.split("?", 1)[1]; d = base64.urlsafe_b64decode(b + "=" * (-len(b) % 4)); i = 0; out = []
    def vi():
        global i
        n = 1 << (d[i] >> 6); v = d[i] & 0x3f
        for k in range(1, n): v = (v << 8) | d[i + k]
        i += n; return v
    while i < len(d):
        t = vi(); n = vi()
        if t != 12: out.append("%d=%s" % (t, d[i:i + n].hex()))
        i += n
    print("tt", " ".join(out))'
}
ids() { for s in hysteria-server xray trusttunnel; do systemctl show "$s" -p InvocationID --value; done; }
state_is() {   # $1 = client, $2 = state, $3 = reason ("" = none)
    sudo bash ./veiltrium.sh --list-clients --json - 2>/dev/null | jq -e --arg n "$1" --arg s "$2" --arg r "${3:-}" \
        '.clients[] | select(.name == $n) | (.state == $s and ((.reason // "") == $r))' > /dev/null
}


TSNI="$(sudo awk -F= '$1=="T_SNI"{print $2}' /etc/trusttunnel/node.env)"
TTPORT=8443
MAIN=/root/veiltrium/client.txt
H_MAIN="$(sudo grep -m1 '^hysteria2://' "$MAIN")"
sec "$MAIN" 4 > "$W/m4.json"
T_U="$(sudo awk -F= '$1=="T_USER"{print $2}' /etc/trusttunnel/node.env)"
T_P="$(sudo awk -F= '$1=="T_PASS"{print $2}' /etc/trusttunnel/node.env)"
CF=/root/veiltrium/clients/carol.txt
load_carol() {
    C_H="$(sudo grep -m1 '^hysteria2://' "$CF")"
    sec "$CF" 4 > "$W/c4.json"
    C_TP="$(sudo awk -F= '$1=="C_TT_PASS"{print $2}' /etc/veiltrium/clients/carol.env)"
}
main_expect() {   # the main client is not affected by anything done to the others
    expect "main: hysteria2" "$(hy_case "$H_MAIN")" 204
    expect "main: VLESS Reality" "$(sb_case "$W/m4.json")" 204
    expect "main: TrustTunnel" "$(tt_case "$T_U" "$T_P")" 204
}
carol_expect() {   # 204 | not204
    load_carol
    expect "carol: hysteria2 ($1)" "$(hy_case "$C_H")" "$1"
    expect "carol: VLESS Reality ($1)" "$(sb_case "$W/c4.json")" "$1"
    expect "carol: TrustTunnel ($1)" "$(tt_case carol "$C_TP")" "$1"
    main_expect
}

# ======================================================================================
sec_a() {
    echo "== a. traffic counters"
sudo grep -E '^H_STATS_PORT=' /etc/hysteria/node.env > /dev/null || fail "no Hysteria statistics port in the node state"
sudo grep -E '^R_STATS_PORT=' /usr/local/etc/xray/reality.env > /dev/null || fail "no Xray statistics port in the node state"
sudo grep -E '^T_STATS_PORT=' /etc/trusttunnel/node.env > /dev/null || fail "no TrustTunnel statistics port in the node state"
sudo jq -e '.inbounds[0].settings.clients[0].email == "main"' /usr/local/etc/xray/config.json
sudo bash ./veiltrium.sh --traffic-reset > /dev/null 2>&1
sudo test -s "$CF" || fail "carol does not exist"
sudo systemctl stop veiltrium-traffic.timer 2>/dev/null || true
load_carol
WHAT=big
expect "main: hysteria2 download" "$(hy_case "$H_MAIN")" big
expect "main: VLESS Reality download" "$(sb_case "$W/m4.json")" big
expect "main: TrustTunnel download" "$(tt_case "$T_U" "$T_P")" big
expect "carol: hysteria2 download" "$(hy_case "$C_H")" big
expect "carol: VLESS Reality download" "$(sb_case "$W/c4.json")" big
expect "carol: TrustTunnel download" "$(tt_case carol "$C_TP")" big
WHAT=204
sudo bash ./veiltrium.sh --traffic --json - > "$W/traffic.json" 2> "$W/traffic.err" || { cat "$W/traffic.err"; exit 1; }
jq . "$W/traffic.json" | head -60
for c in main carol; do
    for p in hysteria2 vless trusttunnel; do
        jq -e --arg c "$c" --arg p "$p" '.clients[$c].by_protocol[$p] | (.up + .down) >= 8000000' "$W/traffic.json" > /dev/null \
            || fail "no counted traffic of $c through $p"
    done
    jq -e --arg c "$c" '.clients[$c].last_seen != null' "$W/traffic.json" > /dev/null
done
jq -e '.totals.down > 0 and .totals.up > 0' "$W/traffic.json" > /dev/null
if grep -E '[0-9a-f]{48}' "$W/traffic.json"; then fail "a secret in the traffic JSON"; fi
sudo bash ./veiltrium.sh --traffic > "$W/traffic.txt" 2>&1
grep -E '^  carol ' "$W/traffic.txt" > /dev/null

}
# ======================================================================================
sec_c() {
    echo "== c. reset-client"
sudo test -s "$CF" || fail "carol does not exist"
load_carol
if inst --reset-client main > "$W/rm.log" 2>&1; then fail "reset-client accepted main"; fi
grep -F 'VT_RECONFIGURE=1' "$W/rm.log" > /dev/null
OLD_H="$C_H"; cp "$W/c4.json" "$W/old4.json"; OLD_TP="$C_TP"
main0="$(creds "$MAIN")"
inst --reset-client carol > "$W/reset.log" 2>&1 || { cat "$W/reset.log"; exit 1; }
grep -F 'Client carol reset' "$W/reset.log" > /dev/null
load_carol
[ "$C_H" != "$OLD_H" ] || fail "the Hysteria link did not change"
[ "$C_TP" != "$OLD_TP" ] || fail "the TrustTunnel password did not change"
! cmp -s "$W/c4.json" "$W/old4.json" || fail "the Reality outbound did not change"
expect "carol after reset: new hysteria2" "$(hy_case "$C_H")" 204
expect "carol after reset: new VLESS Reality" "$(sb_case "$W/c4.json")" 204
expect "carol after reset: new TrustTunnel" "$(tt_case carol "$C_TP")" 204
expect "carol after reset: old hysteria2" "$(hy_case "$OLD_H")" not204
expect "carol after reset: old VLESS Reality" "$(sb_case "$W/old4.json")" not204
expect "carol after reset: old TrustTunnel" "$(tt_case carol "$OLD_TP")" not204
test "$main0" = "$(creds "$MAIN")"
main_expect

}
# ======================================================================================
sec_b() {
    echo "== b. limits, disable and enable, expiry"
sudo test -s "$CF" || fail "carol does not exist"
load_carol
if inst --set-client main --limit 1M > "$W/bad.log" 2>&1; then fail "a limit on main was accepted"; fi
if inst --set-client carol --limit abc > "$W/bad.log" 2>&1; then fail "a bad size was accepted"; fi
if inst --set-client carol > "$W/bad.log" 2>&1; then fail "--set-client without a setting was accepted"; fi
# settings alone restart nothing
ids0="$(ids)"
inst --set-client carol --limit 5G --reset monthly > "$W/set1.log" 2>&1 || { cat "$W/set1.log"; exit 1; }
test "$ids0" = "$(ids)"
sudo bash ./veiltrium.sh --list-clients --json - 2>/dev/null | jq -e '.clients[] | select(.name == "carol")
    | .limit == 5000000000 and .reset == "monthly" and .state == "active"'
inst --set-client carol --limit none --reset none > "$W/set2.log" 2>&1 || { cat "$W/set2.log"; exit 1; }
test "$ids0" = "$(ids)"
# a quota: counting starts when the limit is set; the traffic below passes it
inst --set-client carol --limit 1M > "$W/set3.log" 2>&1 || { cat "$W/set3.log"; exit 1; }
state_is carol active ""
WHAT=big
expect "carol (limit 1M): download" "$(hy_case "$C_H")" big
WHAT=204
if state_is carol disabled quota; then echo "the collector disabled carol (the timer path)"
else
    echo "enforcing by hand"
    inst --enforce > "$W/enf.log" 2>&1 || { cat "$W/enf.log"; exit 1; }
fi
state_is carol disabled quota || fail "carol is not disabled for the quota"
sudo bash ./veiltrium.sh --list-clients --json - 2>/dev/null | jq -e '.clients[] | select(.name == "carol") | .period_bytes >= 1000000'
sudo head -n1 "$CF" | grep -F 'DISABLED (quota)' > /dev/null
if sudo grep -F 'carol' /etc/hysteria/config.yaml /usr/local/etc/xray/config.json /etc/trusttunnel/credentials.toml; then
    fail "the disabled client is still in a config"
fi
carol_expect not204
if inst --enable-client carol > "$W/en.log" 2>&1; then fail "enable-client lifted a quota"; fi
grep -F 'has used its quota' "$W/en.log" > /dev/null
# lifting the limit brings the client back
inst --set-client carol --limit none > "$W/set4.log" 2>&1 || { cat "$W/set4.log"; exit 1; }
state_is carol active ""
carol_expect 204
sudo head -n1 "$CF" | grep -F 'DISABLED' && fail "the DISABLED header stayed"
# manual disable: survives --enforce, ends with --enable-client
inst --disable-client carol > "$W/dis.log" 2>&1 || { cat "$W/dis.log"; exit 1; }
state_is carol disabled manual
carol_expect not204
inst --enforce > "$W/enf2.log" 2>&1 || { cat "$W/enf2.log"; exit 1; }
state_is carol disabled manual || fail "--enforce lifted a manual disable"
inst --enable-client carol > "$W/ena.log" 2>&1 || { cat "$W/ena.log"; exit 1; }
state_is carol active ""
carol_expect 204
# an expired date
inst --set-client carol --expires 2020-01-01 > "$W/exp.log" 2>&1 || { cat "$W/exp.log"; exit 1; }
state_is carol disabled expired || fail "carol is not disabled for the expiry"
carol_expect not204
if inst --enable-client carol > "$W/en2.log" 2>&1; then fail "enable-client lifted an expiry"; fi
grep -F 'expired on' "$W/en2.log" > /dev/null
inst --set-client carol --expires none > "$W/exp2.log" 2>&1 || { cat "$W/exp2.log"; exit 1; }
state_is carol active ""
carol_expect 204
# the audit log has the changes
sudo bash ./veiltrium.sh --audit 200 > "$W/audit.txt" 2>&1
for a in 'action=add-client target=carol result=ok' 'action=reset-client target=carol result=ok' \
         'action=set-client target=carol result=ok' 'action=disable-client target=carol result=ok' \
         'action=client-disabled target=carol result=ok' 'action=client-enabled target=carol result=ok'; do
    grep -F "$a" "$W/audit.txt" > /dev/null || { cat "$W/audit.txt"; fail "no audit line: $a"; }
done

}
# ======================================================================================
sec_d() {
    echo "== d. standby servers"
snap() {
    sudo sh -c 'for f in /root/veiltrium/client.txt /root/veiltrium/clients/*.txt; do echo "== $f"; grep -v "^Veiltrium connection details" "$f"; done'
}
snap > "$W/snap0.txt"
instenv STANDBY_HOSTS=203.0.113.5,203.0.113.6 > "$W/sb1.log" 2>&1 || { tail -40 "$W/sb1.log"; exit 1; }
sudo bash ./veiltrium.sh --status --json - 2>/dev/null | jq -e '.standby == ["203.0.113.5", "203.0.113.6"]'
# Simulate a second node's saved-state snapshot without opening a remote control port.
# The source address differs; the shared state must still match. The other standby
# remains unverified, and changing a local restriction must invalidate the match.
receipt="$(sudo env PUBLIC_IP=203.0.113.5 PANEL_BINARY="${PANEL_BINARY:-}" bash ./veiltrium.sh --standby-receipt)"
sudo bash ./veiltrium.sh --verify-standby "$receipt" --json - > "$W/standby-state.json"
jq -e '.servers[0].state == "matching" and .servers[1].state == "unverified"' "$W/standby-state.json" > /dev/null
# --watch must reload real clients, deduplicate transitions and recover on the CLI path.
mkdir -p "$W/alert-bin"
cat > "$W/alert-bin/curl" <<'STUB'
#!/usr/bin/env bash
cat >> "${STANDBY_ALERT_LOG}.config"
printf '%s\n' "$*" >> "${STANDBY_ALERT_LOG}"
printf 200
STUB
chmod 755 "$W/alert-bin/curl"
watch_standby() {
    sudo env PATH="$W/alert-bin:$PATH" STANDBY_ALERT_LOG="$W/standby-notices" \
        ALERT_TG_TOKEN=none ALERT_WEBHOOK=https://alerts.invalid/standby-test bash ./veiltrium.sh --watch
}
watch_standby; watch_standby
# The second address has never been verified; the first has a matching snapshot.
test "$(sudo grep -c 'standby 203.0.113.6:' "$W/standby-notices")" = 1
inst --set-client carol --limit 5G > "$W/watch-limit.log" 2>&1 || { cat "$W/watch-limit.log"; exit 1; }
watch_standby; watch_standby
test "$(sudo grep -c 'snapshot differs' "$W/standby-notices")" = 1
inst --set-client carol --limit none > "$W/watch-unlimit.log" 2>&1 || { cat "$W/watch-unlimit.log"; exit 1; }
watch_standby; watch_standby
test "$(sudo grep -c 'matches this node again' "$W/standby-notices")" = 1
# No real channels were saved by the watcher; discard only this CI ledger.
sudo rm -f /var/lib/veiltrium/alert-state.standby
if sudo bash ./veiltrium.sh --verify-standby "${receipt};id" > "$W/receipt-bad.log" 2>&1; then fail "a malformed receipt was accepted"; fi
inst --set-client carol --limit 5G > "$W/receipt-limit.log" 2>&1 || { cat "$W/receipt-limit.log"; exit 1; }
sudo bash ./veiltrium.sh --standby-status --json - 2>/dev/null | jq -e '.servers[0].state == "changed"' > /dev/null
inst --set-client carol --limit none > "$W/receipt-unlimit.log" 2>&1 || { cat "$W/receipt-unlimit.log"; exit 1; }
sudo bash ./veiltrium.sh --standby-status --json - 2>/dev/null | jq -e '.servers[0].state == "matching"' > /dev/null
for f in "$MAIN" "$CF"; do
    sudo grep -c '^hysteria2://.*@203.0.113.5:443/' "$f" | grep -x 1 > /dev/null
    sudo grep -c '^vless://.*@203.0.113.6:443' "$f" | grep -x 1 > /dev/null
    test "$(sudo grep -c '^tt://' "$f")" = 3
done
sudo bash ./veiltrium.sh --show-client main --json - 2>/dev/null > "$W/main.json"
jq -e '.standby | length == 2' "$W/main.json" > /dev/null
jq -e '.hysteria2.standby_outbounds | length == 3 and .[2].type == "urltest"' "$W/main.json" > /dev/null
jq -e '.vless.standby_outbounds | length == 3 and .[2].type == "urltest"' "$W/main.json" > /dev/null
sec "$MAIN" 2 > "$W/m2.json"
arr "$MAIN" 1 > "$W/s2.json"; arr "$MAIN" 2 > "$W/s4.json"; arr "$MAIN" 3 > "$W/awg.json"
for f in m2 m4 s2 s4 awg; do jq -e . "$W/$f.json" > /dev/null || fail "$f is not valid JSON"; done
jq -e 'length == 3' "$W/s2.json" > /dev/null; jq -e 'length == 3' "$W/s4.json" > /dev/null; jq -e 'length == 3' "$W/awg.json" > /dev/null
# the delivered pieces form a config that the router's kind of sing-box accepts
jq -n --slurpfile a "$W/m2.json" --slurpfile b "$W/m4.json" --slurpfile s2 "$W/s2.json" --slurpfile s4 "$W/s4.json" \
    '{log: {level: "error"}, inbounds: [{type: "socks", tag: "in", listen: "127.0.0.1", listen_port: 18199}],
      outbounds: ($a + $b + $s2[0] + $s4[0]), route: {final: "Veiltrium-auto-hy2"}}' > "$W/standby-sb.json"
"$SB" check -c "$W/standby-sb.json"
# the same from the JSON interface
jq '{log: {level: "error"}, inbounds: [{type: "socks", tag: "in", listen: "127.0.0.1", listen_port: 18199}],
     outbounds: ([.hysteria2.outbound, .vless.outbound] + .hysteria2.standby_outbounds + .vless.standby_outbounds),
     route: {final: "Veiltrium-auto-reality"}}' "$W/main.json" > "$W/standby-sb2.json"
"$SB" check -c "$W/standby-sb2.json"
jq -n --slurpfile a "$W/awg.json" '{log: {level: "error"}, outbounds: $a[0]}' > "$W/awg-sb.json"
"$SB" check -c "$W/awg-sb.json"
# the phone bundle (subscription + sing-box profile) of main and an added client, with and without standby servers
bundle_check() {   # $1 = what, $2 = expected standby count
    local f n b
    for f in /root/veiltrium/client /root/veiltrium/clients/carol; do
        n="${f##*/}"
        sudo cat "$f.singbox.json" > "$W/prof-$n.json"
        jq -e . "$W/prof-$n.json" > /dev/null || fail "$1: $n profile is not valid JSON"
        "$SB" check -c "$W/prof-$n.json" || fail "$1: sing-box check failed on the $n profile"
        jq -e --argjson n "$2" '(.outbounds | map(select(.type == "hysteria2" or .type == "vless")) | length) == 2 * ($n + 1)' "$W/prof-$n.json" > /dev/null \
            || fail "$1: $n profile has the wrong outbounds"
        b="$(sudo cat "$f.sub")"
        test "$(printf '%s' "$b" | base64 -d | grep -c -E '^(hysteria2|vless)://')" = $(( 2 * ($2 + 1) )) || fail "$1: $n subscription has the wrong links"
        test "$(printf '%s' "$b" | base64 -d | grep -c '^tt://' || true)" = 0 || fail "$1: $n subscription carries a TrustTunnel link"
    done
    sudo bash ./veiltrium.sh --show-client carol --json - 2>/dev/null | jq -e '.subscription_base64 != null and (.singbox_profile.outbounds | length) > 3' > /dev/null \
        || fail "$1: carol JSON lacks the subscription or the profile"
}
bundle_check "with standby" 2
expect "main still works with standby servers listed" "$(hy_case "$H_MAIN")" 204
instenv STANDBY_HOSTS=none > "$W/sb2.log" 2>&1 || { tail -40 "$W/sb2.log"; exit 1; }
bundle_check "without standby" 0
sudo bash ./veiltrium.sh --status --json - 2>/dev/null | jq -e '(.standby | length) == 0'
snap > "$W/snap1.txt"
cmp "$W/snap0.txt" "$W/snap1.txt" || { diff "$W/snap0.txt" "$W/snap1.txt" | sed -E 's/[0-9a-f]{40,}/<secret>/g' | head -20; fail "the client files are not the same after STANDBY_HOSTS=none"; }
ids0="$(ids)"
if instenv STANDBY_HOSTS=10.1.2.3 > "$W/sb3.log" 2>&1; then fail "a private standby address was accepted"; fi
grep -F "is not a public IPv4 address" "$W/sb3.log" > /dev/null || { tail -20 "$W/sb3.log"; fail "no message about the bad standby address"; }
test "$ids0" = "$(ids)"

}
# ======================================================================================
sec_f() {
    echo "== f. alerts (an unreachable webhook)"
test "$(systemctl is-enabled veiltrium-watch.timer 2>/dev/null || true)" != enabled || fail "the watch timer is on without alert channels"
if inst --test-alert > "$W/ta0.log" 2>&1; then fail "--test-alert succeeded without channels"; fi
grep -F 'no alert channel is set' "$W/ta0.log" > /dev/null
if instenv ALERT_WEBHOOK=http://alerts.invalid/x --status > "$W/ah.log" 2>&1; then fail "a plain http webhook was accepted"; fi
grep -F 'ALERT_WEBHOOK must be an https://' "$W/ah.log" > /dev/null
ids0="$(ids)"
HOOK=https://alerts.invalid/hook/SECRETPATH123
instenv ALERT_WEBHOOK="$HOOK" > "$W/al1.log" 2>&1 || { tail -40 "$W/al1.log"; exit 1; }
test "$(systemctl is-enabled veiltrium-watch.timer)" = enabled
systemctl is-active veiltrium-watch.timer
test "$(sudo stat -c %a /etc/veiltrium/alerts.env)" = 600
test "$ids0" = "$(ids)"
rc=0; inst --test-alert > "$W/ta1.log" 2>&1 || rc=$?
cat "$W/ta1.log"
test "$rc" = 1
grep -F 'Webhook: failed' "$W/ta1.log" > /dev/null
grep -F 'a test alert was not delivered' "$W/ta1.log" > /dev/null
if grep -F 'SECRETPATH123' "$W/ta1.log" "$W/al1.log"; then fail "the webhook path (a secret) was printed"; fi
if sudo grep -F 'SECRETPATH123' /var/log/veiltrium-install.log; then fail "the webhook path is in the install log"; fi
if sudo journalctl -t veiltrium-alert --no-pager | grep -F 'SECRETPATH123'; then fail "the webhook path is in the journal"; fi
systemctl is-active hysteria-server xray trusttunnel
# the watch run itself is harmless (nothing is down: nothing to send)
sudo bash ./veiltrium.sh --watch
instenv ALERT_WEBHOOK=none > "$W/al2.log" 2>&1 || { tail -40 "$W/al2.log"; exit 1; }
test "$(systemctl is-enabled veiltrium-watch.timer 2>/dev/null || true)" != enabled || fail "the watch timer stayed on after ALERT_WEBHOOK=none"
sudo test ! -e /etc/veiltrium/alerts.env
if inst --test-alert > "$W/ta2.log" 2>&1; then fail "--test-alert succeeded after the channels were cleared"; fi

}
# ======================================================================================
sec_g() {
    echo "== g. the short command and QR codes"
    local VT=/usr/local/bin/veiltrium rc=0
    must() {   # $1 = text, $2 = file
        grep -F -- "$1" "$2" > /dev/null || { echo "MISSING '$1' in $2:"; cat "$2"; exit 1; }
    }
    command -v qrencode > /dev/null || fail "qrencode is not installed"
    ls -l "$VT" || fail "no $VT"
    sudo "$VT" status > "$W/cli-status.txt" 2>&1 || { cat "$W/cli-status.txt"; fail "veiltrium status failed"; }
    must 'hysteria-server: active' "$W/cli-status.txt"
    must 'clients: main + 1 added' "$W/cli-status.txt"
    sudo "$VT" clients > "$W/cli-clients.txt" 2>&1 || { cat "$W/cli-clients.txt"; fail "veiltrium clients failed"; }
    must 'carol' "$W/cli-clients.txt"
    sudo "$VT" qr main > "$W/qr.txt" 2>&1 || { cat "$W/qr.txt"; fail "veiltrium qr main failed"; }
    must 'Hysteria 2' "$W/qr.txt"
    must 'VLESS Reality' "$W/qr.txt"
    n="$(LC_ALL=C grep -c $'\xe2\x96' "$W/qr.txt" || true)"
    echo "QR block lines: $n"
    [ "$n" -gt 20 ] || { head -40 "$W/qr.txt"; fail "no QR code in the output"; }
    sudo "$VT" qr carol > "$W/qr2.txt" 2>&1 || { cat "$W/qr2.txt"; fail "veiltrium qr carol failed"; }
    must 'Hysteria 2' "$W/qr2.txt"
    if sudo "$VT" qr nobody > "$W/qr3.txt" 2>&1; then fail "qr of a missing client"; fi
    sudo "$VT" help > "$W/help.txt" 2>&1 || { cat "$W/help.txt"; fail "veiltrium help failed"; }
    must 'Modes:' "$W/help.txt"   # help = the installer's full --help
    if grep -x '#' "$W/help.txt" >/dev/null; then fail "stray '#' lines in --help"; fi
    rc=0; sudo "$VT" bogus > "$W/bogus.txt" 2>&1 || rc=$?
    [ "$rc" = 2 ] || { cat "$W/bogus.txt"; fail "an unknown command ended with $rc, not 2"; }
    must 'Usage: veiltrium COMMAND' "$W/bogus.txt"   # an unknown word: the wrapper's own usage
}
# ======================================================================================
sec_e() {
    echo "== e. export, uninstall, import on the same machine"
if [ "${FEATURES_REINSTALL:-1}" != 1 ]; then echo "export and import skipped"; return 0; fi
PASS='ci-export-passphrase-0001'
EXPF=/root/vt-ci-export.vtx
links0="$(creds "$MAIN" "$CF")"
test "$(printf '%s\n' "$links0" | grep -c .)" = 6
ssh0="$(sudo sshd -T | sort | sha256sum)"
sshf0="$(sudo sh -c 'sha256sum /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*')"
sudo rm -f "$EXPF"
if instenv VT_EXPORT_PASSPHRASE=short --export "$EXPF" > "$W/ex0.log" 2>&1; then fail "a short passphrase was accepted"; fi
sudo test ! -e "$EXPF"
instenv VT_EXPORT_PASSPHRASE="$PASS" --export "$EXPF" > "$W/ex.log" 2>&1 || { cat "$W/ex.log"; exit 1; }
test "$(sudo stat -c %a "$EXPF")" = 600
if sudo grep -a -F "$(sudo awk -F= '$1=="H_PASSWORD"{print $2}' /etc/hysteria/node.env)" "$EXPF"; then fail "the export is not encrypted"; fi
if instenv VT_EXPORT_PASSPHRASE="$PASS" --export "$EXPF" > "$W/ex1.log" 2>&1; then fail "--export overwrote a file"; fi
# uninstall
if inst --uninstall < /dev/null > "$W/un0.log" 2>&1; then fail "--uninstall ran without a confirmation"; fi
systemctl is-active hysteria-server xray trusttunnel
instenv VT_YES=uninstall --uninstall > "$W/un.log" 2>&1 || { cat "$W/un.log"; exit 1; }
tail -n 20 "$W/un.log"
for u in hysteria-server xray trusttunnel veiltrium-panel veiltrium-helper veiltrium-recover veiltrium-scanner-block \
         veiltrium-russia-check veiltrium-watch veiltrium-traffic; do
    test -z "$(systemctl list-unit-files "$u*" --no-legend 2>/dev/null)" || fail "the unit $u is still installed"
    if systemctl is-active --quiet "$u" 2>/dev/null; then fail "$u is still running"; fi
done
test -z "$(sudo ss -Htulpn 'sport = :443 or sport = :8443 or sport = :2096')" || fail "a port is still open"
if sudo nft list table inet veiltrium > /dev/null 2>&1; then fail "the firewall table is still loaded"; fi
sudo nft -c -f /etc/nftables.conf
if sudo grep -F veiltrium /etc/nftables.conf; then fail "/etc/nftables.conf still names veiltrium"; fi
for u in hysteria xray trusttunnel veiltrium-panel; do if id -u "$u" > /dev/null 2>&1; then fail "the user $u is still there"; fi; done
for p in /etc/hysteria /usr/local/etc/xray /etc/trusttunnel /etc/veiltrium /var/lib/veiltrium /root/veiltrium \
         /usr/local/bin/hysteria /usr/local/bin/xray /usr/local/bin/trusttunnel_endpoint /usr/local/bin/veiltrium-panel /usr/local/bin/veiltrium; do
    if sudo test -e "$p"; then fail "left over: $p"; fi
done
# what must stay: SSH untouched and reachable, the protective settings, the audit log
sudo test -f /etc/ssh/sshd_config.d/00-veiltrium-hardening.conf
sudo test -f /etc/fail2ban/jail.d/veiltrium-sshd.local
sudo test -s /var/log/veiltrium/audit.log
sudo grep -F 'action=uninstall' /var/log/veiltrium/audit.log > /dev/null
test "$ssh0" = "$(sudo sshd -T | sort | sha256sum)" || fail "the SSH settings changed"
test "$sshf0" = "$(sudo sh -c 'sha256sum /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*')" || fail "an SSH file changed"
test -n "$(ssh-keyscan -T 5 127.0.0.1 2> /dev/null | grep -F 'ssh-')" || fail "sshd does not answer after the uninstall"
# a second uninstall finds nothing
instenv VT_YES=uninstall --uninstall > "$W/un2.log" 2>&1 || { cat "$W/un2.log"; exit 1; }
# a fresh install from the export
panel_args=()
if [[ "${RELEASE_PANEL:-false}" != true ]]; then panel_args+=(PANEL_BINARY=/tmp/veiltrium-panel); fi
instenv GLOBALPING=0 "${panel_args[@]}" VT_IMPORT_PASSPHRASE="$PASS" --import "$EXPF" > "$W/imp.log" 2>&1 \
    || { tail -60 "$W/imp.log"; exit 1; }
grep -F 'Imported the node of' "$W/imp.log" > /dev/null
if [[ "${RELEASE_PANEL:-false}" == true ]]; then bash tests/release-panel-ci.sh; fi
if sudo grep -F 'ERROR:' /var/log/veiltrium-install.log; then fail "the import logged an error"; fi
links1="$(creds "$MAIN" "$CF")"
[ "$links0" = "$links1" ] || { echo "links changed:"; diff <(echo "$links0") <(echo "$links1") | sed -E 's/[0-9a-f]{20,}/<secret>/g'; exit 1; }
sudo bash ./veiltrium.sh --list-clients --json - 2>/dev/null | jq -e '.clients | map(.name) == ["main", "carol"]'
state_is carol active ""
H_MAIN="$(sudo grep -m1 '^hysteria2://' "$MAIN")"
sec "$MAIN" 4 > "$W/m4.json"
T_U="$(sudo awk -F= '$1=="T_USER"{print $2}' /etc/trusttunnel/node.env)"
T_P="$(sudo awk -F= '$1=="T_PASS"{print $2}' /etc/trusttunnel/node.env)"
TSNI="$(sudo awk -F= '$1=="T_SNI"{print $2}' /etc/trusttunnel/node.env)"
carol_expect 204
test "$ssh0" = "$(sudo sshd -T | sort | sha256sum)" || fail "the SSH settings differ after the import"
sudo env GLOBALPING=0 PANEL_BINARY="${PANEL_BINARY:-}" bash ./veiltrium.sh --diagnose > "$W/diag.log" 2>&1 || { cat "$W/diag.log"; exit 1; }
if grep -F 'ERROR' "$W/diag.log"; then fail "--diagnose printed an error after the import"; fi
sudo rm -f "$EXPF"
echo "features: all checks passed"
}

# ======================================================================================
# Each section runs in its own shell: one failure does not hide the others (the order is
# fixed; e reinstalls the node and must stay last).
if [ "${1:-all}" != all ]; then "sec_$1"; exit 0; fi
# the traffic timer and these tests would both change client states and read the counters
sudo systemctl stop veiltrium-traffic.timer
trap 'sudo systemctl start veiltrium-traffic.timer 2>/dev/null || true' EXIT
inst --add-client carol > "$W/add.log" 2>&1 || { cat "$W/add.log"; exit 1; }
FAILED=()
for s in a c b d f g e; do
    echo "######## section $s"
    bash "$0" "$s" || { FAILED+=("$s"); echo "######## SECTION $s FAILED"; }
done
if (( ${#FAILED[@]} )); then echo "failed sections: ${FAILED[*]}"; exit 1; fi
echo "features: all sections passed"
