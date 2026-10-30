#!/usr/bin/env bash
# CI only: the web panel on an installed node (source build or published pinned release).
# Loopback only, nothing for the proxies or the outside, the panel's own VLESS Reality
# profile (and only it) gets through, a helper that runs only known requests, login and CSRF
# rules, a real client change through the API, a new password, and a re-run that changes nothing.
set -euo pipefail
cd "$(dirname "$0")/.."
W="$(mktemp -d)"
P=2096
U="http://127.0.0.1:$P"
J="$W/cookies"

# ---- services, sockets, sandbox -------------------------------------------------------
systemctl is-active veiltrium-panel veiltrium-helper.socket
test "$(sudo stat -c '%a %U %G' /run/veiltrium/helper.sock)" = "660 root veiltrium-panel"
test "$(sudo stat -c '%a %U %G' /etc/veiltrium-panel/auth)" = "640 root veiltrium-panel"
test "$(sudo stat -c '%a' /root/veiltrium/panel.txt)" = 600
systemctl show veiltrium-panel -p User -p IPAddressDeny -p NoNewPrivileges | tee "$W/unit.txt"
grep -x 'User=veiltrium-panel' "$W/unit.txt" >/dev/null
grep -x 'NoNewPrivileges=yes' "$W/unit.txt" >/dev/null
sudo systemd-analyze security veiltrium-panel --no-pager | tail -1
# listens on loopback only
sudo ss -Htlnp "sport = :$P" | tee "$W/ss.txt"
test "$(grep -c . "$W/ss.txt")" = 1
grep -F "127.0.0.1:$P" "$W/ss.txt" >/dev/null
if sudo ip netns exec ext timeout 5 bash -c "exec 3<>/dev/tcp/192.0.2.1/$P"; then echo "panel reachable from outside"; exit 1; fi
# the proxies cannot reach it (the firewall rejects the server's own addresses for them)
for u in hysteria xray trusttunnel; do
    if sudo timeout 5 runuser -u "$u" -- bash -c "exec 3<>/dev/tcp/127.0.0.1/$P" 2>/dev/null; then
        echo "service $u reached the panel"; exit 1
    fi
done
# the panel itself has no internet access: everything but localhost is denied to it
systemctl show veiltrium-panel -p IPAddressDeny -p IPAddressAllow | tee "$W/ip.txt"
grep -E '^IPAddressDeny=.*0\.0\.0\.0/0' "$W/ip.txt" >/dev/null
grep -E '^IPAddressAllow=.*127\.0\.0\.0/8' "$W/ip.txt" >/dev/null

# ---- the root helper: only for the panel's group, only known requests ---------------------
helper() {   # $1 = user, $2 = request line -> the reply
    sudo -u "$1" python3 -c '
import socket, sys
s = socket.socket(socket.AF_UNIX); s.settimeout(120); s.connect("/run/veiltrium/helper.sock")
s.sendall(sys.argv[1].encode() + b"\n"); out = b""
while True:
    b = s.recv(65536)
    if not b: break
    out += b
sys.stdout.write(out.decode())' "$2"
}
helper veiltrium-panel "list-clients" | tail -n 2 | tee "$W/h1.txt"
grep -x '::exit 0' "$W/h1.txt" >/dev/null
grep '^::json ' "$W/h1.txt" | cut -c8- | jq -e '.schema == "veiltrium-clients/1"'
for bad in "reboot" "status; id" "add-client main" "show-client ../../etc/shadow" "add-client \$(id)"; do
    helper veiltrium-panel "$bad" | tee "$W/hb.txt"
    grep -x '::exit 2' "$W/hb.txt" >/dev/null
done
if sudo -u nobody python3 -c 'import socket; s=socket.socket(socket.AF_UNIX); s.connect("/run/veiltrium/helper.sock")' 2>/dev/null; then
    echo "another user reached the helper"; exit 1
fi

# ---- HTTP: login, CSRF, host check -------------------------------------------------
PW="$(sudo sed -n 's/^Password: //p' /root/veiltrium/panel.txt)"
test "${#PW}" = 24
h=(-H 'Content-Type: application/json' -H 'X-Veiltrium: 1')
code() { curl -s -o "$W/body" -w '%{http_code}' "$@"; }
test "$(code "$U/api/status")" = 401
test "$(code -H "Host: evil.example:$P" "$U/")" = 421
test "$(code -X POST "$U/api/login" -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}")" = 403
test "$(code -X POST "$U/api/login" "${h[@]}" -H 'Origin: http://evil.example' -d "{\"password\":\"$PW\"}")" = 403
test "$(code -X POST "$U/api/login" "${h[@]}" -d '{"password":"definitely-wrong-password"}')" = 401
test "$(code -c "$J" -X POST "$U/api/login" "${h[@]}" -d "{\"password\":\"$PW\"}")" = 200
grep -F 'vt_session' "$J" >/dev/null
test "$(code -b "$J" "$U/")" = 200
grep -F '<title>Veiltrium</title>' "$W/body" >/dev/null
curl -s -D "$W/hdr" -o /dev/null -b "$J" "$U/api/status"
grep -i '^content-security-policy: .*frame-ancestors' "$W/hdr" >/dev/null
test "$(code -b "$J" "$U/api/status")" = 200
jq -e '.schema == "veiltrium-status/1" and .protection.firewall == true' "$W/body"
test "$(code "$U/api/standby")" = 401
test "$(code -b "$J" "$U/api/standby")" = 200
jq -e '.schema == "veiltrium-standby/1" and .max_age_seconds == 86400
    and (.local_receipt | startswith("vt-standby-1|")) and (.fingerprint | test("^[0-9a-f]{64}$"))' "$W/body"
test "$(code -b "$J" -X POST "$U/api/standby/verify" "${h[@]}" -d '{"receipt":"bad"}')" = 400
test "$(code -b "$J" "$U/api/clients")" = 200
jq -e '.clients[0].name == "main"' "$W/body"
test "$(code -b "$J" -X POST "$U/api/russia-check")" = 403                     # no CSRF header
test "$(code -b "$J" -X POST "$U/api/russia-check" "${h[@]}")" = 200
jq -e '.schema == "veiltrium-russia/1"' "$W/body"

# ---- the panel through VLESS Reality (PANEL_VPN=1, the default) ----------------------------
# A real Xray client in the outside namespace with the panel's profile from panel.txt: the panel answers on
# the server's address and a login works; the main client gets nothing there; no raw socket of a proxy
# service reaches the panel, except Xray's own panel outbound (source 127.0.0.2, the panel's port only).
sudo cat /root/veiltrium/panel.txt > "$W/panel.txt"
ADMIN="$(sudo awk -F= '$1=="R_ADMIN_UUID"{print $2}' /usr/local/etc/xray/reality.env)"
[[ "$ADMIN" =~ ^[0-9a-f-]{36}$ ]]
grep -E "^  vless://${ADMIN}@[0-9.]+:443\?.*#Veiltrium.*-panel$" "$W/panel.txt" >/dev/null
SRV="$(sed -n 's#^.*open in the browser:  http://\([0-9.]*\):'"$P"'/$#\1#p' "$W/panel.txt" | tail -n 1)"
[[ -n "$SRV" && "$SRV" != 127.0.0.1 ]]
sudo jq -e --arg a "$ADMIN" '(.inbounds[0].settings.clients[-1] == {id: $a, flow: "xtls-rprx-vision", email: "@panel"})
    and .routing.rules == [{type: "field", user: ["@panel"], network: "tcp", port: "2096", outboundTag: "panel"}]
    and .outbounds[0].tag == "direct"' /usr/local/etc/xray/config.json
systemctl show veiltrium-panel -p ExecStart --value | grep -F -- "--host $SRV" >/dev/null
sudo nft list chain inet veiltrium output | grep -E 'ip saddr 127\.0\.0\.2 ip daddr 127\.0\.0\.1 tcp dport 2096 accept' >/dev/null
xray_client() {   # $1 = UUID, $2 = SOCKS port: a client like the one in an app, in the outside namespace
    local pub sid sni
    pub="$(sudo awk -F= '$1=="R_PUB"{print $2}' /usr/local/etc/xray/reality.env)"
    sid="$(sudo awk -F= '$1=="R_SID"{print $2}' /usr/local/etc/xray/reality.env)"
    sni="$(sudo awk -F= '$1=="R_SITE"{print $2}' /usr/local/etc/xray/reality.env)"
    cat > "$W/x-$2.json" <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":$2,"protocol":"socks"}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"192.0.2.1","port":443,
   "users":[{"id":"$1","encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"$sni",
   "fingerprint":"chrome","publicKey":"$pub","shortId":"$sid"}}}]}
EOF
    sudo ip netns exec ext /usr/local/bin/xray run -c "$W/x-$2.json" > "$W/x-$2.log" 2>&1 &
    for _ in $(seq 1 30); do [ -n "$(sudo ip netns exec ext ss -Htln "sport = :$2")" ] && break; sleep 0.3; done
}
via() {   # $1 = SOCKS port, then curl arguments: the HTTP code through that client
    local port="$1"; shift
    sudo ip netns exec ext curl -s -o "$W/vbody" -w '%{http_code}' --max-time 10 --socks5-hostname "127.0.0.1:$port" "$@" || true
}
xray_client "$ADMIN" 18131
MAINU="$(sudo awk -F= '$1=="R_UUID"{print $2}' /usr/local/etc/xray/reality.env)"
xray_client "$MAINU" 18132
VU="http://$SRV:$P"
test "$(via 18131 "$VU/api/session")" = 401
test "$(via 18131 "$VU/")" = 200; grep -F '<title>Veiltrium</title>' "$W/vbody" >/dev/null
test "$(via 18131 -H "Host: evil.example:$P" "$VU/")" = 421
VJ="$W/vpn-cookies"
test "$(via 18131 -c "$VJ" -X POST "$VU/api/login" "${h[@]}" -H "Origin: $VU" -d "{\"password\":\"$PW\"}")" = 200
test "$(via 18131 -b "$VJ" "$VU/api/status")" = 200
jq -e '.schema == "veiltrium-status/1"' "$W/vbody"
test "$(via 18131 https://www.gstatic.com/generate_204)" = 204          # the profile is a normal VPN profile too
test "$(via 18131 http://192.0.2.1:22/)" != 401                       # only the panel's port goes to the panel
c="$(via 18132 "$VU/api/session")"; echo "main client -> panel: $c"; test "$c" != 401
c="$(via 18132 "http://127.0.0.1:$P/api/session")"; echo "main client -> 127.0.0.1:$P: $c"; test "$c" != 401
c="$(via 18132 https://www.gstatic.com/generate_204)"; test "$c" = 204   # the main client itself works
sudo pkill -f "$W/x-1813" || true
# raw sockets of the services: only Xray, only from 127.0.0.2, only to the panel's port
bindto() {   # $1 = user, $2 = source, $3 = port: 0 if the connection was made
    sudo timeout 5 runuser -u "$1" -- python3 -c 'import socket,sys
s=socket.socket(); s.settimeout(3); s.bind((sys.argv[1],0)); s.connect(("127.0.0.1",int(sys.argv[2])))' "$2" "$3" 2>/dev/null
}
bindto xray 127.0.0.2 "$P"
for u in hysteria trusttunnel; do if bindto "$u" 127.0.0.2 "$P"; then echo "$u reached the panel from 127.0.0.2"; exit 1; fi; done
if bindto xray 127.0.0.2 "$(sudo awk -F= '$1=="R_STATS_PORT"{print $2}' /usr/local/etc/xray/reality.env)"; then
    echo "xray reached another loopback port from 127.0.0.2"; exit 1
fi

# ---- PANEL_VPN=0 removes the profile (saved); PANEL_VPN=1 brings a new one ---------------------
sudo env NEEDRESTART_SUSPEND=1 VT_AUTO_REBOOT=0 PANEL_VPN=0 bash ./veiltrium.sh > "$W/pv0.log" 2>&1 || { tail -40 "$W/pv0.log"; exit 1; }
if sudo grep -E 'R_ADMIN_UUID|@panel' /usr/local/etc/xray/reality.env /usr/local/etc/xray/config.json; then echo "the panel profile stayed"; exit 1; fi
sudo jq -e 'has("routing") | not' /usr/local/etc/xray/config.json
if sudo grep -E '^  vless://' /root/veiltrium/panel.txt; then echo "panel.txt still offers the profile"; exit 1; fi
if systemctl show veiltrium-panel -p ExecStart --value | grep -F -- '--host'; then echo "the panel still accepts the server address"; exit 1; fi
if sudo nft list chain inet veiltrium output | grep -F '127.0.0.2'; then echo "the firewall still lets Xray reach the panel"; exit 1; fi
sudo grep -x 'N_PANEL_VPN=0' /etc/veiltrium/node.env >/dev/null
test "$(sudo sed -n 's/^Password: //p' /root/veiltrium/panel.txt)" = "$PW"     # the password is kept
sudo env NEEDRESTART_SUSPEND=1 VT_AUTO_REBOOT=0 PANEL_VPN=1 bash ./veiltrium.sh > "$W/pv1.log" 2>&1 || { tail -40 "$W/pv1.log"; exit 1; }
grep -F 'The panel is also reachable through VLESS Reality with its own profile' "$W/pv1.log" >/dev/null   # the installer's own check
ADMIN2="$(sudo awk -F= '$1=="R_ADMIN_UUID"{print $2}' /usr/local/etc/xray/reality.env)"
[[ "$ADMIN2" =~ ^[0-9a-f-]{36}$ && "$ADMIN2" != "$ADMIN" ]]
xray_client "$ADMIN" 18133; xray_client "$ADMIN2" 18134
c="$(via 18133 "$VU/api/session")"; echo "the old panel profile -> $c"; test "$c" != 401
test "$(via 18134 "$VU/api/session")" = 401
sudo pkill -f "$W/x-1813" || true
# the panel restarted with its new command line: sign in again
for _ in $(seq 1 20); do [ -n "$(ss -Htln "sport = :$P")" ] && break; sleep 0.3; done
test "$(code -c "$J" -X POST "$U/api/login" "${h[@]}" -d "{\"password\":\"$PW\"}")" = 200

# ---- a client change through the panel ------------------------------------------------
test "$(code -b "$J" -X POST "$U/api/clients" -H 'Content-Type: application/json' -d '{"name":"web1"}')" = 403   # no CSRF header
curl -sN -b "$J" -X POST "$U/api/clients" "${h[@]}" -d '{"name":"web1"}' --max-time 300 | tee "$W/add.ndjson"
jq -s -e 'map(.step // empty) | index("check-hysteria") != null and index("commit") != null' "$W/add.ndjson"
tail -n 1 "$W/add.ndjson" | jq -e '.result.ok == true and .result.name == "web1"'
test "$(code -b "$J" "$U/api/clients/web1")" = 200
jq -e '.name == "web1" and (.hysteria2.link | startswith("hysteria2://web1:"))' "$W/body"
L="$(jq -r .hysteria2.link "$W/body")"
printf 'server: "%s"\nsocks5:\n  listen: 127.0.0.1:18121\n' "$(printf '%s' "$L" | sed -E 's#@[^:/]+:#@127.0.0.1:#')" > "$W/h.yaml"
/usr/local/bin/hysteria client -c "$W/h.yaml" > "$W/h.log" 2>&1 &
hp=$!
for _ in $(seq 1 30); do [ -n "$(ss -Htln 'sport = :18121')" ] && break; sleep 0.3; done
c="$(curl -s -o /dev/null -w '%{http_code}' --max-time 12 --socks5-hostname 127.0.0.1:18121 https://www.gstatic.com/generate_204 || true)"
kill "$hp" || true
echo "web1 from the panel: hysteria2 -> $c"; test "$c" = 204
curl -sN -b "$J" -X DELETE "$U/api/clients/web1" "${h[@]}" --max-time 300 | tee "$W/rm.ndjson"
tail -n 1 "$W/rm.ndjson" | jq -e '.result.ok == true and .result.action == "remove"'
test "$(code -b "$J" -X DELETE "$U/api/clients/main" "${h[@]}")" = 400

# ---- a new password signs everybody out ------------------------------------------------
sudo bash ./veiltrium.sh --panel-password > "$W/pw.txt"
NEW="$(sed -n 's/^Password: //p' "$W/pw.txt")"
test "${#NEW}" = 24; test "$NEW" != "$PW"
for _ in $(seq 1 20); do [ -n "$(ss -Htln "sport = :$P")" ] && break; sleep 0.3; done
test "$(code -b "$J" "$U/api/status")" = 401
test "$(code -X POST "$U/api/login" "${h[@]}" -d "{\"password\":\"$PW\"}")" = 401
test "$(code -c "$J" -X POST "$U/api/login" "${h[@]}" -d "{\"password\":\"$NEW\"}")" = 200

# ---- a plain re-run keeps the panel as it is ----------------------------------------------
id0="$(systemctl show veiltrium-panel -p InvocationID --value)"
f0="$(sudo sha256sum /usr/local/bin/veiltrium-panel /etc/veiltrium-panel/auth /etc/systemd/system/veiltrium-panel.service)"
sudo env NEEDRESTART_SUSPEND=1 VT_AUTO_REBOOT=0 bash ./veiltrium.sh > "$W/rerun.log" 2>&1 || { tail -40 "$W/rerun.log"; exit 1; }
test "$id0" = "$(systemctl show veiltrium-panel -p InvocationID --value)"
test "$f0" = "$(sudo sha256sum /usr/local/bin/veiltrium-panel /etc/veiltrium-panel/auth /etc/systemd/system/veiltrium-panel.service)"
if sudo grep -F "$NEW" /var/log/veiltrium-install.log; then echo "the panel password is in the install log"; exit 1; fi
echo "panel: all checks passed"
