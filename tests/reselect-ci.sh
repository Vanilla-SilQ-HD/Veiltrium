#!/usr/bin/env bash
# CI only: Reality candidate checks, controlled re-selection, rollback,
# interruption, lock and trial, against the local test sites (tests/sites-setup.sh).
set -euxo pipefail
shopt -u patsub_replacement 2>/dev/null || true   # bash 5.2: "&" in ${var/a/b} would mean the match
RENV=/usr/local/etc/xray/reality.env
XCFG=/usr/local/etc/xray/config.json
CLIENT=/root/veiltrium/client.txt
inst() {   # VAR=value... -- args...
    local -a vars=()
    while (( $# )) && [[ "$1" != "--" ]]; do vars+=("$1"); shift; done
    [[ "${1:-}" == "--" ]] && shift
    sudo env NEEDRESTART_SUSPEND=1 VT_AUTO_REBOOT=0 "${vars[@]}" bash ./veiltrium.sh "$@"
}
site() { sudo awk -F= '$1=="R_SITE"{print $2}' "$RENV"; }
keys() { sudo grep -E '^R_(UUID|PRIV|PUB|SID)=' "$RENV"; }
link() { sudo grep -m1 "^$1://" "$CLIENT"; }
reality_via() {   # $1 = SNI; prints the HTTP code through the production port with a real Xray client
    local u pub sid
    u="$(sudo awk -F= '$1=="R_UUID"{print $2}' "$RENV")"; pub="$(sudo awk -F= '$1=="R_PUB"{print $2}' "$RENV")"
    sid="$(sudo awk -F= '$1=="R_SID"{print $2}' "$RENV")"
    cat > /tmp/rv.json <<EOF
{"log":{"loglevel":"warning"},"inbounds":[{"listen":"127.0.0.1","port":18111,"protocol":"socks"}],
 "outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":443,
   "users":[{"id":"$u","encryption":"none","flow":"xtls-rprx-vision"}]}]},
   "streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"$1",
   "fingerprint":"chrome","publicKey":"$pub","shortId":"$sid"}}}]}
EOF
    /usr/local/bin/xray run -c /tmp/rv.json > /tmp/rv.log 2>&1 &
    local pid=$! i
    for i in $(seq 1 20); do [ -n "$(ss -Htln 'sport = :18111')" ] && break; sleep 0.3; done
    curl -s -o /dev/null -w '%{http_code}' --max-time 10 --socks5-hostname 127.0.0.1:18111 https://cp.cloudflare.com/generate_204 || true
    kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
}


R0="$(site)"
KEYS0="$(keys)"
SECRETS="/etc/hysteria/node.env /etc/hysteria/server.crt /etc/hysteria/server.key /etc/hysteria/config.yaml /etc/trusttunnel/node.env /etc/trusttunnel/cert.pem /etc/trusttunnel/credentials.toml /etc/trusttunnel/hosts.toml"
SEC0="$(sudo sha256sum $SECRETS)"
HY2_LINK0="$(link hysteria2)"; TT_LINK0="$(link tt)"; VLESS0="$(link vless)"
CFG0="$(sudo sha256sum "$XCFG" "$RENV")"

# 1) dry run over every kind of candidate: gates and reasons; nothing on the server changes
sudo env REALITY_CANDIDATES="good1.cand.test badcert.cand.test noh2.cand.test multi.cand.test timeout.cand.test nxdomain.cand.test good2.cand.test" \
    bash ./veiltrium.sh --dry-run --json /tmp/dry.json | tee /tmp/dry.log
g() { jq -r --arg s "$1" ".reality.selection.candidates[] | select(.site == \$s) | $2" /tmp/dry.json; }
test "$(g good1.cand.test .gate)" = pass
test "$(g good2.cand.test .gate)" = pass
test "$(g good1.cand.test .fallback_real_certificate)" = ok
test "$(g "$R0" .gate)" = pass                       # the current site competes too
[[ "$(g badcert.cand.test .reason)" == *"certificate is not valid"* ]]
[[ "$(g noh2.cand.test .reason)" == *"no HTTP/2"* ]]
[[ "$(g multi.cand.test .reason)" == *"198.51.100.12"* ]]   # one dead CDN address fails the site
[[ "$(g timeout.cand.test .reason)" == *"no TCP connection"* ]]
[[ "$(g nxdomain.cand.test .reason)" == *"dns"* ]]
test "$(g good1.cand.test .score)" -lt "$(g good2.cand.test .score)"   # +80 ms RTT costs points
test "$(sudo sha256sum "$XCFG" "$RENV")" = "$CFG0"
test ! -e /etc/veiltrium/reality-candidates

# 2) a normal run with a new candidate list saves the list but does NOT switch
inst REALITY_CANDIDATES="good1.cand.test good2.cand.test" -- > /tmp/n1.log 2>&1 || { tail -50 /tmp/n1.log; exit 1; }
test "$(site)" = "$R0"
test "$(sudo sha256sum "$XCFG" "$RENV")" = "$CFG0"
sudo grep -x good1.cand.test /etc/veiltrium/reality-candidates
grep -F "Site ${R0} kept" /tmp/n1.log >/dev/null

# 3) controlled switch to a given site: only the VLESS sni changes
inst REALITY_SNI=good2.cand.test -- --reselect-reality > /tmp/s1.log 2>&1 || { tail -80 /tmp/s1.log; exit 1; }
test "$(site)" = good2.cand.test
test "$(keys)" = "$KEYS0"
test "$(sudo sha256sum $SECRETS)" = "$SEC0"
test "$(link hysteria2)" = "$HY2_LINK0"
test "$(link tt)" = "$TT_LINK0"
test "$(link vless)" = "${VLESS0/sni=${R0}&/sni=good2.cand.test&}"
grep -F 'change only sni (server_name)' /tmp/s1.log >/dev/null
sudo jq -e '.links_to_update == ["vless: only sni / server_name changes to good2.cand.test"]' /var/lib/veiltrium/report.json
sudo ip netns exec ext openssl s_client -connect 192.0.2.1:443 -servername good2.cand.test \
    -verify_hostname good2.cand.test -verify_return_error </dev/null 2>/dev/null | grep -F 'Verify return code: 0 (ok)'
test "$(reality_via good2.cand.test)" = 204

# 4) re-selection over the saved list: good1 is clearly better (no +80 ms) -> switch
inst -- --reselect-reality > /tmp/s2.log 2>&1 || { tail -80 /tmp/s2.log; exit 1; }
grep -F 'Decision:' /tmp/s2.log
test "$(site)" = good1.cand.test
test "$(keys)" = "$KEYS0"
test "$(sudo sha256sum $SECRETS)" = "$SEC0"

# 5) again: good1 is current and best -> kept, Xray not even restarted
T1="$(systemctl show xray -p ActiveEnterTimestampMonotonic --value)"
CFG1="$(sudo sha256sum "$XCFG" "$RENV")"
inst -- --reselect-reality > /tmp/s3.log 2>&1 || { tail -80 /tmp/s3.log; exit 1; }
grep -F 'Decision: kept good1.cand.test' /tmp/s3.log >/dev/null
test "$(sudo sha256sum "$XCFG" "$RENV")" = "$CFG1"
test "$(systemctl show xray -p ActiveEnterTimestampMonotonic --value)" = "$T1"

# 6) the new site passes the isolated test but fails on the production port -> rollback, exit 2
sudo nft add table inet citest
sudo nft add chain inet citest out '{ type filter hook output priority 10; policy accept; }'
sudo nft add rule inet citest out meta skuid 0 ip daddr 127.0.0.1 tcp dport 443 drop
rc=0; inst REALITY_SNI=good2.cand.test -- --reselect-reality > /tmp/rb.log 2>&1 || rc=$?
sudo nft delete table inet citest
echo "rc=$rc"; test "$rc" = 2
grep -F 'previous state restored' /tmp/rb.log >/dev/null
test "$(sudo sha256sum "$XCFG" "$RENV")" = "$CFG1"
test -z "$(sudo find /var/lib/veiltrium/txn -name pending)"
sudo jq -e '.rollbacks | length == 1' /var/lib/veiltrium/report.json
test "$(reality_via good1.cand.test)" = 204

# 7) every candidate unreachable: nothing changes
inst REALITY_CANDIDATES="timeout.cand.test nxdomain.cand.test" -- --reselect-reality > /tmp/un.log 2>&1 || { tail -60 /tmp/un.log; exit 1; }
grep -F 'Decision: kept good1.cand.test' /tmp/un.log >/dev/null   # the current site still competes and wins
grep -F 'timeout.cand.test: fail' /tmp/un.log >/dev/null
test "$(sudo sha256sum "$XCFG" "$RENV")" = "$CFG1"

# 8) interrupted in the middle of a switch, AFTER the new config is live.
PENDING=/var/lib/veiltrium/txn/reality/pending
kill_during_apply() {   # $1 = signal
    sudo rm -f /tmp/inst.pid
    # A background job of a non-interactive shell starts with SIGINT ignored, and bash cannot
    # trap a signal ignored on entry: restore the default first, as in a terminal.
    sudo setsid python3 -c 'import os, signal
signal.signal(signal.SIGINT, signal.SIG_DFL)
open("/tmp/inst.pid", "w").write(str(os.getpid()))
env = dict(os.environ, NEEDRESTART_SUSPEND="1", VT_AUTO_REBOOT="0", REALITY_SNI="good2.cand.test")
os.execvpe("bash", ["bash", "./veiltrium.sh", "--reselect-reality"], env)' > /tmp/kill.log 2>&1 &
    local i
    # wait until the unverified config is really in place (not just the marker)
    for i in $(seq 1 900); do
        if sudo test -e "$PENDING" && [ "$(sudo sha256sum "$XCFG")" != "$(echo "$CFG1" | head -n 1)" ]; then break; fi
        sleep 0.2
    done
    sudo test -e "$PENDING"
    [ "$(sudo sha256sum "$XCFG")" != "$(echo "$CFG1" | head -n 1)" ]
    sudo kill "-$1" "$(cat /tmp/inst.pid)"
    for i in $(seq 1 100); do sudo kill -0 "$(cat /tmp/inst.pid)" 2>/dev/null || break; sleep 0.3; done
}
restored() {   # the previous config and state are back, xray runs and works
    test ! -e "$PENDING"
    test "$(sudo sha256sum "$XCFG" "$RENV")" = "$CFG1"
    systemctl is-active xray
    test "$(reality_via good1.cand.test)" = 204
}
# 8a) SIGKILL, nobody runs the installer again: the watchdog timer restores within a minute
kill_during_apply KILL
systemctl is-active veiltrium-watchdog.timer
for i in $(seq 1 60); do sudo test -e "$PENDING" || break; sleep 2; done
sudo journalctl -t veiltrium-recover --no-pager | tail -3
restored
test "$(systemctl is-active veiltrium-watchdog.timer || true)" != active
# 8b) SIGKILL and then a reboot before the watchdog fires (simulated: the timer is gone, the
#     services stop, and at boot veiltrium-recover.service runs before them)
kill_during_apply KILL
sudo systemctl stop veiltrium-watchdog.timer
# a foreground child of the killed run (curl, openssl) may hold the lock a few seconds longer
for i in $(seq 1 60); do sudo flock -n /run/veiltrium.lock true && break; sleep 0.5; done
sudo systemctl stop xray
rc=0; sudo bash ./veiltrium.sh --diagnose > /tmp/d.log 2>&1 || rc=$?
grep -F 'interrupted change is pending' /tmp/d.log >/dev/null
sudo systemctl start veiltrium-recover.service
sudo systemctl start xray
restored
# 8c) Ctrl+C (SIGINT) and 8d) SIGTERM: restored right away by the run itself
for sig in INT TERM; do
    kill_during_apply "$sig"
    tail -5 /tmp/kill.log
    grep -F "restoring the previous settings" /tmp/kill.log >/dev/null
    if grep -F "== DONE ==" /tmp/kill.log >/dev/null; then echo "the run was not interrupted"; exit 1; fi
    restored
done
# 8e) the new config makes Xray fail to start (systemd refuses): rolled back, exit 2
sudo mkdir -p /run/systemd/system/xray.service.d
printf '[Service]\nExecStartPre=/bin/sh -c "grep -q good2.cand.test %s && exit 1 || exit 0"\n' "$XCFG" \
    | sudo tee /run/systemd/system/xray.service.d/ci.conf >/dev/null
sudo systemctl daemon-reload
rc=0; inst REALITY_SNI=good2.cand.test -- --reselect-reality > /tmp/sf.log 2>&1 || rc=$?
sudo rm -rf /run/systemd/system/xray.service.d; sudo systemctl daemon-reload
echo "rc=$rc"; test "$rc" = 2
grep -F 'previous state restored' /tmp/sf.log >/dev/null
sudo systemctl reset-failed xray || true
restored
# 8f) no helper processes or temporary files are left behind by any of these
test -z "$(pgrep -f '/root/.veiltrium' || true)"
test -z "$(sudo find /root -maxdepth 1 -name '.veiltrium.*')"

# 9) a second run while one is going: refused at once
sudo flock /run/veiltrium.lock sleep 20 &
sleep 1
rc=0; timeout 15 sudo bash ./veiltrium.sh > /tmp/lock.log 2>&1 || rc=$?
test "$rc" = 1
grep -F 'already running' /tmp/lock.log >/dev/null
wait

# 10) trial: an extra SNI for a limited time, production config untouched, ends by itself
sudo bash ./veiltrium.sh --trial-reality good2.cand.test --trial-minutes 5 | tee /tmp/trial.log
test -e /run/systemd/system/xray.service.d/50-veiltrium-trial.conf
systemctl show xray -p ExecStart | grep -F /run/veiltrium-trial/xray-trial.json >/dev/null
systemctl list-timers --all | grep -F veiltrium-trial-end
test "$(sudo sha256sum "$XCFG" "$RENV")" = "$CFG1"
test "$(reality_via good2.cand.test)" = 204
test "$(reality_via good1.cand.test)" = 204
sudo systemctl start veiltrium-trial-end.service       # what the timer does when it fires
for i in $(seq 1 60); do [ -e /run/systemd/system/xray.service.d/50-veiltrium-trial.conf ] || break; sleep 0.5; done
sleep 2; systemctl is-active xray
test ! -e /run/systemd/system/xray.service.d/50-veiltrium-trial.conf
systemctl show xray -p ExecStart | grep -F /usr/local/etc/xray/config.json >/dev/null
test "$(reality_via good2.cand.test)" != 204
test "$(reality_via good1.cand.test)" = 204
sudo bash ./veiltrium.sh --trial-reality good2.cand.test --trial-minutes 5 > /dev/null
sudo bash ./veiltrium.sh --trial-stop
test ! -e /run/systemd/system/xray.service.d/50-veiltrium-trial.conf
rc=0; sudo bash ./veiltrium.sh --trial-reality badcert.cand.test > /tmp/tb.log 2>&1 || rc=$?
test "$rc" = 1; grep -F 'certificate is not valid' /tmp/tb.log >/dev/null
test ! -e /run/systemd/system/xray.service.d/50-veiltrium-trial.conf

# back to the original site and the built-in list for the remaining steps
inst REALITY_SNI="$R0" REALITY_CANDIDATES=default -- --reselect-reality > /tmp/back.log 2>&1 || { tail -60 /tmp/back.log; exit 1; }
test "$(site)" = "$R0"
test "$(keys)" = "$KEYS0"
test "$(link vless)" = "$VLESS0"
test ! -e /etc/veiltrium/reality-candidates
echo "re-selection CI checks passed"
