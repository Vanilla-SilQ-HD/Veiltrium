#!/usr/bin/env bash
# CI only: added clients end to end. Runs after the install steps of e2e.yml and uses the
# sing-box (/tmp/sb) and TrustTunnel (/tmp/ttc) clients those steps downloaded.
#   add -> every protocol works with the new credentials (real clients), the main client
#   is untouched; a plain re-run changes nothing; a failed change rolls back; remove ->
#   the credentials stop working at once.
set -euo pipefail
cd "$(dirname "$0")/.."
SB="$(find /tmp/sb -type f -name sing-box | head -1)"
TTC="$(find /tmp/ttc -type f -name trusttunnel_client | head -1)"
test -x "$SB"; test -x "$TTC"
W="$(mktemp -d)"
inst() { sudo env NEEDRESTART_SUSPEND=1 VT_AUTO_REBOOT=0 bash ./veiltrium.sh "$@"; }
code204() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 12 --socks5-hostname "127.0.0.1:$1" \
        https://www.gstatic.com/generate_204 || true
}
wait_port() { for _ in $(seq 1 40); do [ -n "$(ss -Htln "sport = :$1")" ] && return 0; sleep 0.3; done; return 1; }
stop() { kill "$1" 2>/dev/null || true; wait "$1" 2>/dev/null || true; }

hy_case() {   # $1 = hysteria2:// link -> HTTP code through a Hysteria client using it
    local pid c
    printf 'server: "%s"\nsocks5:\n  listen: 127.0.0.1:18101\n' \
        "$(printf '%s' "$1" | sed -E 's#@[^:/]+:#@127.0.0.1:#')" > "$W/h.yaml"
    /usr/local/bin/hysteria client -c "$W/h.yaml" > "$W/h.log" 2>&1 &
    pid=$!
    wait_port 18101 || true
    c="$(code204 18101)"; stop "$pid"; printf '%s' "$c"
}
sb_case() {   # $1 = file with one sing-box outbound -> HTTP code through it
    local pid c
    jq '.server = "127.0.0.1"' "$1" > "$W/ob.json"
    jq -n --slurpfile ob "$W/ob.json" '{log: {level: "error"},
        inbounds: [{type: "socks", tag: "in", listen: "127.0.0.1", listen_port: 18102}],
        outbounds: $ob, route: {final: $ob[0].tag}}' > "$W/sb.json"
    "$SB" run -c "$W/sb.json" > "$W/sb.log" 2>&1 &
    pid=$!
    wait_port 18102 || true
    c="$(code204 18102)"; stop "$pid"; printf '%s' "$c"
}
tt_case() {   # $1 = user, $2 = password -> HTTP code through the TrustTunnel client (HTTP/2)
    local c
    {
        printf 'loglevel = "info"\nvpn_mode = "general"\nkillswitch_enabled = false\n\n[endpoint]\n'
        printf 'hostname = "%s"\naddresses = ["127.0.0.1:8443"]\nusername = "%s"\npassword = "%s"\n' "$TSNI" "$1" "$2"
        printf 'has_ipv6 = false\nskip_verification = false\nupstream_protocol = "http2"\n'
        printf "certificate = '''\n%s\n'''\n" "$(sudo cat /etc/trusttunnel/cert.pem)"
        printf '\n[listener.socks]\naddress = "127.0.0.1:18103"\n'
    } > "$W/t.toml"
    sudo "$TTC" --config "$W/t.toml" > "$W/t.log" 2>&1 &
    wait_port 18103 || true
    sleep 2
    c="$(code204 18103)"
    sudo pkill -f "trusttunnel_client --config $W/t.toml" || true
    for _ in $(seq 1 40); do [ -z "$(ss -Htln 'sport = :18103')" ] && break; sleep 0.3; done
    printf '%s' "$c"
}
tt_fields() {   # $1 = tt:// link -> "username name" from its TLV fields (0x05, 0x0C)
    python3 - "$1" <<'EOF'
import base64, sys
b = sys.argv[1].split('?', 1)[1]
d = base64.urlsafe_b64decode(b + '=' * (-len(b) % 4))
i, f = 0, {}
def vi():
    global i
    n = 1 << (d[i] >> 6); v = d[i] & 0x3f
    for k in range(1, n): v = (v << 8) | d[i + k]
    i += n
    return v
while i < len(d):
    t = vi(); n = vi(); f[t] = d[i:i + n]; i += n
print(f[5].decode(), f[12].decode())
EOF
}
sec() {   # $1 = file, $2 = 2|4|6 -> that JSON block of a client file
    case "$2" in
        2) sudo awk '/^\{/{n++} n==1{print} n==1&&/^\}/{exit}' "$1" ;;
        4) sudo awk '/^\{/{n++} n==2{print} n==2&&/^\}/{exit}' "$1" ;;
        6) sudo awk '/^\[$/{f=1} f{print} f&&/^\]$/{exit}' "$1" | jq '.[0]' ;;
    esac
}
expect() {   # $1 = name, $2 = got, $3 = want (204 | not204)
    local ok=0
    if [ "$3" = 204 ] && [ "$2" = 204 ]; then ok=1; fi
    if [ "$3" = not204 ] && [ "$2" != 204 ]; then ok=1; fi
    echo "CASE $1 -> $2 (expected $3)"
    if [ "$ok" != 1 ]; then tail -20 "$W"/*.log 2>/dev/null || true; exit 1; fi
}

TSNI="$(sudo awk -F= '$1=="T_SNI"{print $2}' /etc/trusttunnel/node.env)"
LABEL="$(sudo jq -r .node_name /var/lib/veiltrium/report.json)"
echo "node name: $LABEL"
[[ "$LABEL" =~ ^Veiltrium(-[A-Za-z0-9-]+)?$ ]]
MAIN=/root/veiltrium/client.txt
main_links() { sudo grep -E '^(hysteria2|vless|tt)://' "$MAIN"; }
main0="$(main_links)"
H_MAIN="$(sudo grep -m1 '^hysteria2://' "$MAIN")"
[[ "$H_MAIN" == hysteria2://main:* ]]          # a new node has a password per client

# ---- names that are not accepted --------------------------------------------------
for bad in Main main 'a b' '-x'; do
    if inst --add-client "$bad" > "$W/bad.log" 2>&1; then echo "accepted a bad name: $bad"; exit 1; fi
    grep -F 'a client name is 1-32 characters' "$W/bad.log" >/dev/null
done
if inst --remove-client nobody > "$W/bad.log" 2>&1; then echo "removed a client that does not exist"; exit 1; fi
grep -F 'no client nobody' "$W/bad.log" >/dev/null

# ---- add -----------------------------------------------------------------------------
inst --add-client anna > "$W/add.log" 2>&1 || { cat "$W/add.log"; exit 1; }
grep -F 'Client anna added; checked with real clients: Hysteria, VLESS Reality, TrustTunnel' "$W/add.log" >/dev/null
if grep -F 'MAIN client' "$W/add.log"; then echo "a per-client node must not change the main links"; exit 1; fi
if inst --add-client anna > "$W/dup.log" 2>&1; then echo "added the same client twice"; exit 1; fi
grep -F 'client anna already exists' "$W/dup.log" >/dev/null
test "$(sudo stat -c '%a' /etc/veiltrium/clients)" = 700
test "$(sudo stat -c '%a' /etc/veiltrium/clients/anna.env)" = 600
test "$(sudo stat -c '%a' /root/veiltrium/clients)" = 700
test "$(sudo stat -c '%a' /root/veiltrium/clients/anna.txt)" = 600
test "$main0" = "$(main_links)"
sudo bash ./veiltrium.sh --list-clients | tee "$W/list.txt"
grep -E '^  anna +added ' "$W/list.txt" >/dev/null
sudo bash ./veiltrium.sh --show-client anna > "$W/show.txt"
grep -m1 '^vless://' "$W/show.txt" >/dev/null
A=/root/veiltrium/clients/anna.txt
sudo bash ./veiltrium.sh --diagnose > "$W/diag.log" 2>&1 || { cat "$W/diag.log"; exit 1; }
if grep -F 'ERROR' "$W/diag.log"; then echo "--diagnose printed an error"; exit 1; fi
grep -F 'clients main + 1 added' "$W/diag.log" >/dev/null
A_UUID="$(sudo awk -F= '$1=="C_UUID"{print $2}' /etc/veiltrium/clients/anna.env)"
A_HP="$(sudo awk -F= '$1=="C_HY2_PASS"{print $2}' /etc/veiltrium/clients/anna.env)"
A_TP="$(sudo awk -F= '$1=="C_TT_PASS"{print $2}' /etc/veiltrium/clients/anna.env)"
sudo grep -Fx "    'anna': '${A_HP}'" /etc/hysteria/config.yaml >/dev/null
sudo jq -e '.clients.added == 1' /var/lib/veiltrium/report.json
sudo jq -e --arg u "$A_UUID" '.inbounds[0].settings.clients | any(.id == $u and .email == "anna")' /usr/local/etc/xray/config.json
sudo grep -Fx 'username = "anna"' /etc/trusttunnel/credentials.toml >/dev/null
A_H="$(sudo grep -m1 '^hysteria2://' "$A")"; A_V="$(sudo grep -m1 '^vless://' "$A")"; A_T="$(sudo grep -m1 '^tt://' "$A")"
[[ "$A_H" == "hysteria2://anna:${A_HP}@"* && "$A_H" == *"#${LABEL}" ]]
[[ "$A_V" == "vless://${A_UUID}@"* && "$A_V" == *"#${LABEL}" ]]
test "$(tt_fields "$A_T")" = "anna ${LABEL}"
sec "$A" 2 > "$W/a2.json"; sec "$A" 4 > "$W/a4.json"; sec "$A" 6 > "$W/a6.json"
jq -e --arg p "anna:${A_HP}" '.password == $p' "$W/a2.json"
jq -e --arg u "$A_UUID" '.uuid == $u' "$W/a4.json"
jq -e '.tag == "Veiltrium" and (.tls.certificate_public_key_sha256 | length) == 1' "$W/a6.json"
expect "anna: hysteria2 link"           "$(hy_case "$A_H")"           204
expect "anna: sing-box hysteria2 JSON"  "$(sb_case "$W/a2.json")"     204
expect "anna: AWG group JSON (pinned)"  "$(sb_case "$W/a6.json")"     204
expect "anna: VLESS Reality (sing-box)" "$(sb_case "$W/a4.json")"     204
expect "anna: TrustTunnel"              "$(tt_case anna "$A_TP")"     204
expect "anna: TrustTunnel, wrong password" "$(tt_case anna definitely-wrong)" not204
T_U="$(sudo awk -F= '$1=="T_USER"{print $2}' /etc/trusttunnel/node.env)"
T_P="$(sudo awk -F= '$1=="T_PASS"{print $2}' /etc/trusttunnel/node.env)"
expect "main: hysteria2 link"           "$(hy_case "$H_MAIN")"        204
expect "main: TrustTunnel"              "$(tt_case "$T_U" "$T_P")"    204
test "$(tt_fields "$(sudo grep -m1 '^tt://' "$MAIN")")" = "${T_U} ${LABEL}"

# ---- machine interface for the panel ---------------------------------------------------
sudo bash ./veiltrium.sh --status --json - > "$W/status.json" 2> "$W/status.err"
jq -e --arg l "$LABEL" '.schema == "veiltrium-status/1" and .node_name == $l and .services.xray == "active"
    and .clients.added == 1 and .hysteria2.port == 443 and (.reality.sni | length) > 0' "$W/status.json"
sudo bash ./veiltrium.sh --list-clients --json - > "$W/clients.json"
jq -e '.clients | map(.name) == ["main", "anna"]' "$W/clients.json"
if grep -F "$A_HP" "$W/clients.json" "$W/status.json"; then echo "a secret in a JSON overview"; exit 1; fi
sudo bash ./veiltrium.sh --show-client anna --json - > "$W/anna.json"
jq -e --arg h "$A_H" --arg v "$A_V" --arg t "$A_T" \
    '.hysteria2.link == $h and .vless.link == $v and .trusttunnel.link == $t and .hysteria2.awg_group[0].tag == "Veiltrium"' "$W/anna.json"
jq '.hysteria2.awg_group[0]' "$W/anna.json" > "$W/a6j.json"
expect "anna: AWG group JSON from --show-client --json" "$(sb_case "$W/a6j.json")" 204
if sudo bash ./veiltrium.sh --show-client ../anna --json - > /dev/null 2>&1; then echo "a path as a client name"; exit 1; fi

# ---- a plain re-run with clients changes nothing ---------------------------------------
KEEP="/etc/hysteria/config.yaml /etc/hysteria/node.env /usr/local/etc/xray/config.json
  /etc/trusttunnel/credentials.toml /etc/veiltrium/clients/anna.env /etc/veiltrium/node.env"
ids() { for s in hysteria-server xray trusttunnel; do systemctl show "$s" -p InvocationID --value; done; }
links() { sudo grep -hE '^(hysteria2|vless|tt)://' "$MAIN" "$A"; }
before="$(sudo sha256sum $KEEP)"; ids0="$(ids)"; links0="$(links)"
inst > "$W/rerun.log" 2>&1 || { tail -40 "$W/rerun.log"; exit 1; }
test "$before" = "$(sudo sha256sum $KEEP)"
test "$ids0" = "$(ids)"
test "$links0" = "$(links)"

# ---- a change that fails its check rolls back -------------------------------------------
sudo mkdir -p /run/systemd/system/xray.service.d
printf '[Service]\nExecStartPre=/bin/false\n' | sudo tee /run/systemd/system/xray.service.d/ci.conf >/dev/null
sudo systemctl daemon-reload
rc=0; inst --add-client bob > "$W/fail.log" 2>&1 || rc=$?
sudo rm -rf /run/systemd/system/xray.service.d; sudo systemctl daemon-reload
sudo systemctl reset-failed xray; sudo systemctl restart xray
echo "failed add: rc=$rc"; test "$rc" = 1
grep -F 'the previous clients and settings were restored' "$W/fail.log" >/dev/null
sudo test ! -e /etc/veiltrium/clients/bob.env
sudo test ! -e /root/veiltrium/clients/bob.txt
test "$before" = "$(sudo sha256sum $KEEP)"
test -z "$(sudo find /var/lib/veiltrium/txn -name pending)"
systemctl is-active hysteria-server xray trusttunnel
expect "anna after the rollback: hysteria2" "$(hy_case "$A_H")" 204

# ---- remove: the credentials stop working at once -----------------------------------------
sudo env NEEDRESTART_SUSPEND=1 VEILTRIUM_PROGRESS=1 bash ./veiltrium.sh --remove-client anna --json - \
    > "$W/rm.json" 2> "$W/rm.log" || { cat "$W/rm.log"; exit 1; }
jq -e '.ok == true and .action == "remove" and .name == "anna" and .main_hysteria_link_changed == false' "$W/rm.json"
test "$(grep '^::step ' "$W/rm.log" | cut -d' ' -f2 | tr '\n' ' ')" = "write restart check-hysteria check-reality check-trusttunnel commit finished "
grep -F 'Client anna removed' "$W/rm.log" >/dev/null
sudo jq -e '.clients.added == 0' /var/lib/veiltrium/report.json
sudo test ! -e /etc/veiltrium/clients/anna.env
sudo test ! -e "$A"
if sudo grep -F 'anna' /etc/hysteria/config.yaml /usr/local/etc/xray/config.json /etc/trusttunnel/credentials.toml; then
    echo "the removed client is still in a config"; exit 1
fi
expect "removed anna: hysteria2 link"   "$(hy_case "$A_H")"           not204
expect "removed anna: VLESS Reality"    "$(sb_case "$W/a4.json")"     not204
expect "removed anna: TrustTunnel"      "$(tt_case anna "$A_TP")"     not204
expect "main after the removal: hysteria2" "$(hy_case "$H_MAIN")"     204
test "$main0" = "$(main_links)"
echo "added clients: all checks passed"
