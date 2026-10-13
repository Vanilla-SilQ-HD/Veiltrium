#!/usr/bin/env bash
# CI only: the web panel on an installed node (installed with PANEL_BINARY=<this commit's
# build>). Loopback only, nothing for the proxies or the outside, a helper that runs only
# known requests, login and CSRF rules, a real client change through the API, a new
# password, and a re-run that changes nothing.
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
test "$(code -b "$J" "$U/api/clients")" = 200
jq -e '.clients[0].name == "main"' "$W/body"

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
