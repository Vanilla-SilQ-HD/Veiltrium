#!/usr/bin/env bash
# Unit tests for the per-client traffic counters: the statistics blocks in the Hysteria and Xray
# configs (and that they are byte-stable), the saved state, the collector (fake Hysteria JSON, fake
# xray statsquery output and fake TrustTunnel /clients through stubs of curl and xray), counter
# resets, 90-day pruning, removed clients, the JSON fields and the "no secrets" rule. No network,
# no root, no services: everything lives in a temporary directory.
# shellcheck disable=SC2034,SC2046,SC2164,SC2086
set -u
cd "$(dirname "$0")/.."
# shellcheck source=../veiltrium.sh
source ./veiltrium.sh
set +eE
trap - ERR

FAIL=0
check() {   # got, want, name
    if [[ "$1" == "$2" ]]; then echo "ok   $3"; else echo "FAIL $3: got '$1', want '$2'"; FAIL=1; fi
}
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT

a48="$(printf 'a%.0s' {1..48})"; b48="$(printf 'b%.0s' {1..48})"; c48="$(printf 'c%.0s' {1..48})"
key43="$(printf 'K%.0s' {1..43})"; pub43="$(printf 'P%.0s' {1..43})"

# ---- the paths of one imaginary server ------------------------------------------------
HY2_DIR="${T}/etc/hysteria"; HY2_CONFIG="${HY2_DIR}/config.yaml"; HY2_CERT="${HY2_DIR}/server.crt"
HY2_KEY="${HY2_DIR}/server.key"; HY2_STATE="${HY2_DIR}/node.env"
XRAY_DIR="${T}/etc/xray"; XRAY_STATE="${XRAY_DIR}/reality.env"
TT_DIR="${T}/etc/trusttunnel"; TT_STATE="${TT_DIR}/node.env"
SCANNER_DIR="${T}/etc/veiltrium"; CLIENTS_DIR="${SCANNER_DIR}/clients"; NODE_ENV="${SCANNER_DIR}/node.env"
STATE_DIR="${T}/var/veiltrium"; TRAFFIC_FILE="${STATE_DIR}/traffic.json"; TRAFFIC_LOCK="${T}/traffic.lock"
install -d -m 700 "${HY2_DIR}" "${XRAY_DIR}" "${TT_DIR}" "${SCANNER_DIR}" "${CLIENTS_DIR}" "${STATE_DIR}"

# ---- configs -----------------------------------------------------------------------------
H_PASSWORD="${a48}"; H_AUTH=userpass; HY2_PORT=443; HY2_MASQ_URL="https://www.sony.com"
HY2_CERT="${HY2_CERT}"; HY2_KEY="${HY2_KEY}"
CL_NAMES=(anna); CL_UUID=(11111111-2222-4333-8444-555555555552); CL_HPASS=("${b48}"); CL_TPASS=("${c48}"); CL_CREATED=(2026-10-13)
H_STATS_PORT=""; H_STATS_SECRET=""
hy2_server_yaml "${T}/hy-old.yaml"
check "$(grep -c 'trafficStats' "${T}/hy-old.yaml")" 0 "Hysteria config without counters has no trafficStats (the text of earlier versions)"
H_STATS_PORT=34567; H_STATS_SECRET="${c48}"
hy2_server_yaml "${T}/hy-1.yaml"; hy2_server_yaml "${T}/hy-2.yaml"
check "$(cmp -s "${T}/hy-1.yaml" "${T}/hy-2.yaml" && echo same)" same "Hysteria config with counters: two generations are byte-identical"
check "$(grep -A2 '^trafficStats:' "${T}/hy-1.yaml" | tr '\n' '|')" "trafficStats:|  listen: 127.0.0.1:34567|  secret: '${c48}'|" "Hysteria config: loopback listen address and the secret"
check "$(diff <(sed '/^trafficStats:/,$d' "${T}/hy-1.yaml") "${T}/hy-old.yaml" >/dev/null && echo same)" same "Hysteria config: only the trafficStats block is added"
H_AUTH=password; hy2_server_yaml "${T}/hy-pw.yaml"; H_AUTH=userpass
check "$(grep -c '^trafficStats:' "${T}/hy-pw.yaml")" 1 "Hysteria config with the shared password has the counters too"

R_UUID="11111111-2222-4333-8444-555555555551"; R_PRIV="${key43}"; R_PUB="${pub43}"; R_SID="0123456789abcdef"; R_SITE=www.amazon.com
R_STATS_PORT=""
reality_server_json "${T}/xr-old.json" "" 443 www.amazon.com
check "$(grep -cE 'stats|api|policy|email": "main' "${T}/xr-old.json")" 0 "Xray config without counters: no stats, api, policy, main email (earlier text)"
R_STATS_PORT=34568
reality_server_json "${T}/xr-1.json" "" 443 www.amazon.com; reality_server_json "${T}/xr-2.json" "" 443 www.amazon.com
check "$(cmp -s "${T}/xr-1.json" "${T}/xr-2.json" && echo same)" same "Xray config with counters: two generations are byte-identical"
check "$(jq -r '.api.listen' "${T}/xr-1.json")" "127.0.0.1:34568" "Xray api listens on loopback"
check "$(jq -c '.api.services' "${T}/xr-1.json")" '["StatsService"]' "Xray api: StatsService only"
check "$(jq -c '.policy.levels["0"]' "${T}/xr-1.json")" '{"statsUserUplink":true,"statsUserDownlink":true}' "Xray policy: per-user counters"
check "$(jq -c '.stats' "${T}/xr-1.json")" '{}' "Xray stats enabled"
check "$(jq -r '[.inbounds[0].settings.clients[].email] | join(",")' "${T}/xr-1.json")" "main,anna" "Xray: the main client has the email main, added clients their names"
check "$(jq -r '.inbounds | length' "${T}/xr-1.json")" 1 "Xray: no extra inbound (the api listens by itself)"
reality_server_json "${T}/xr-test.json" 127.0.0.1 40000 www.amazon.com
check "$(grep -cE '"api"|"stats"|"policy"' "${T}/xr-test.json")" 0 "a loopback test server config never takes the statistics port"
reality_server_json "${T}/xr-trial.json" "" 443 www.amazon.com www.yahoo.com
check "$(jq -r '.api.listen' "${T}/xr-trial.json")" "127.0.0.1:34568" "a trial config keeps the statistics endpoint (counters survive a trial)"

# ---- the panel through VLESS Reality (PANEL_VPN) ------------------------------------------
check "$(grep -cE 'routing|"panel"|@panel' "${T}/xr-1.json")" 0 "Xray config without the panel profile: no routing, no panel outbound"
R_ADMIN_UUID="11111111-2222-4333-8444-555555555559"; PANEL_PORT=2096
reality_server_json "${T}/xr-pv.json" "" 443 www.amazon.com; reality_server_json "${T}/xr-pv2.json" "" 443 www.amazon.com
check "$(cmp -s "${T}/xr-pv.json" "${T}/xr-pv2.json" && echo same)" same "Xray config with the panel profile: two generations are byte-identical"
check "$(jq -r '[.inbounds[0].settings.clients[] | .email + "=" + .id] | join(",")' "${T}/xr-pv.json")" \
    "main=${R_UUID},anna=11111111-2222-4333-8444-555555555552,@panel=${R_ADMIN_UUID}" "the panel profile is the last client, email @panel"
check "$(jq -c '.routing.rules' "${T}/xr-pv.json")" \
    '[{"type":"field","user":["@panel"],"network":"tcp","port":"2096","outboundTag":"panel"}]' "routing: only the @panel user, TCP to the panel port"
check "$(jq -c '.outbounds' "${T}/xr-pv.json")" \
    '[{"protocol":"freedom","tag":"direct"},{"protocol":"freedom","tag":"panel","sendThrough":"127.0.0.2","settings":{"redirect":"127.0.0.1:2096"}}]' \
    "outbounds: direct stays first (the default), the panel outbound binds 127.0.0.2 and goes to the panel only"
check "$(diff <(jq -S 'del(.routing) | .outbounds |= .[:1] | .inbounds[0].settings.clients |= .[:-1]' "${T}/xr-pv.json") \
    <(jq -S . "${T}/xr-1.json") >/dev/null && echo same)" same "the panel profile adds nothing else"
reality_server_json "${T}/xr-pv-test.json" 127.0.0.1 40000 www.amazon.com
check "$(grep -cE 'routing|@panel|127\.0\.0\.2' "${T}/xr-pv-test.json")" 0 "a loopback test server never carries the panel profile"
reality_server_json "${T}/xr-pv-trial.json" "" 443 www.amazon.com www.yahoo.com
check "$(jq -r '.routing.rules[0].user[0]' "${T}/xr-pv-trial.json")" "@panel" "a trial config keeps the panel profile"
check "$([[ "${PANEL_VPN_EMAIL}" =~ ${CLIENT_RE} ]] && echo clash || echo distinct)" distinct "the panel profile's email can never be a client name"
save_reality_state
check "$(env_get "${XRAY_STATE}" R_ADMIN_UUID)" "${R_ADMIN_UUID}" "reality.env keeps the panel profile"
R_ADMIN_UUID=""; VT_RECONFIGURE=0; load_reality_state
check "${R_ADMIN_UUID}" "11111111-2222-4333-8444-555555555559" "load_reality_state reads the panel profile back"
sed -i 's/^R_ADMIN_UUID=.*/R_ADMIN_UUID=bad/' "${XRAY_STATE}"; load_reality_state
check "${R_ADMIN_UUID}|${R_SITE}" "|www.amazon.com" "a damaged panel profile is dropped, the keys stay"
R_ADMIN_UUID=""; sed -i '/^R_ADMIN_UUID=/d' "${XRAY_STATE}"

# ---- saved state -------------------------------------------------------------------------
HY2_SNI="www.sony.com"; H_MASQ=auto
save_hy2_state
check "$(env_get "${HY2_STATE}" H_STATS_PORT)" 34567 "node.env keeps the Hysteria statistics port"
check "$(env_get "${HY2_STATE}" H_STATS_SECRET)" "${c48}" "node.env keeps the Hysteria statistics secret"
save_reality_state
check "$(env_get "${XRAY_STATE}" R_STATS_PORT)" 34568 "reality.env keeps the statistics port"
H_STATS_PORT=""; H_STATS_SECRET=""; R_STATS_PORT=""
VT_RECONFIGURE=0
install -m 600 /dev/null "${HY2_CERT}"; install -m 600 /dev/null "${HY2_KEY}"
newcert() { openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$2" -out "$1" -days 30 -subj "/CN=$3" -addext "subjectAltName=DNS:$3" >/dev/null 2>&1; }
newcert "${HY2_CERT}" "${HY2_KEY}" www.sony.com
load_hy2_state; load_reality_state
check "${H_STATS_PORT}/${H_STATS_SECRET}" "34567/${c48}" "load_hy2_state reads the counters back"
check "${R_STATS_PORT}" 34568 "load_reality_state reads the counter port back"
printf 'T_USER=u1234abcd\nT_PASS=%s\nT_SNI=www.nvidia.com\nT_IPV6=false\nT_STATS_PORT=34569\n' "${c48}" > "${TT_STATE}"
newcert "${TT_DIR}/cert.pem" "${TT_DIR}/key.pem" www.nvidia.com
load_tt_state
check "${T_STATS_PORT}" 34569 "load_tt_state reads the TrustTunnel counter port back"
sed -i 's/^H_STATS_SECRET=.*/H_STATS_SECRET=zz/' "${HY2_STATE}"
load_hy2_state
check "${H_STATS_PORT}|${H_STATS_SECRET}" "|" "a damaged secret drops the counters (they are created again); the node itself stays"
check "${H_PASSWORD}" "${a48}" "...and the password is untouched"
sed -i 's/^R_STATS_PORT=.*/R_STATS_PORT=abc/' "${XRAY_STATE}"
load_reality_state
check "${R_STATS_PORT}|${R_SITE}" "|www.amazon.com" "a damaged Xray counter port is dropped, the keys stay"

# ---- stats_port_pick (ss stubbed: nothing listens) ----------------------------------------
STUB="${T}/stub"; install -d "${STUB}"
printf '#!/bin/sh\nif [ -n "${STUB_SS:-}" ]; then printf "%%s\\n" "$STUB_SS"; fi\nexit 0\n' > "${STUB}/ss"
chmod +x "${STUB}/ss"
OLDPATH="${PATH}"; PATH="${STUB}:${PATH}"
check "$(stats_port_pick 34567 hysteria 443 8443)" 34567 "a saved free port is kept"
p="$(stats_port_pick 34567 hysteria 34567 443)"
check "$([[ "${p}" =~ ^[0-9]{4,5}$ && "${p}" != 34567 ]] && echo new)" new "a saved port that is on the avoid list is replaced"
p="$(STUB_SS='LISTEN 0 4096 127.0.0.1:34567 users:(("nginx",pid=1,fd=3))' stats_port_pick 34567 hysteria 443)"
check "$([[ "${p}" != 34567 ]] && echo new)" new "a saved port held by another program is replaced"
check "$(STUB_SS='LISTEN 0 4096 127.0.0.1:34567 users:(("hysteria",pid=1,fd=3))' stats_port_pick 34567 hysteria 443)" 34567 "a saved port held by the proxy itself is kept"
p="$(stats_port_pick "" xray 443)"
check "$([[ "${p}" =~ ^[0-9]{4,5}$ ]] && echo port)" port "no saved port: a new one"
PATH="${OLDPATH}"

# ---- the collector -------------------------------------------------------------------------
# curl and xray are stubs that print what the fixtures say; curl keeps its arguments and stdin.
cat > "${STUB}/curl" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_DIR}/curl.args"
if [[ " $* " == *" -K - "* ]]; then cat >> "${STUB_DIR}/curl.stdin"; fi
[[ -z "${STUB_CURL_FAIL:-}" ]] || exit 22
url="${*: -1}"
case "${url}" in
    */traffic*) cat "${STUB_DIR}/hy.json" ;;
    */clients) cat "${STUB_DIR}/tt.json" ;;
    *) exit 22 ;;
esac
EOF
cat > "${STUB}/xray" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${STUB_DIR}/xray.args"
[[ -z "${STUB_XRAY_FAIL:-}" ]] || exit 1
cat "${STUB_DIR}/xr.json"
EOF
chmod +x "${STUB}/curl" "${STUB}/xray"
export STUB_DIR="${STUB}"
XRAY_BIN="${STUB}/xray"
PATH="${STUB}:${PATH}"

# a node with all three counters, one added client
H_STATS_PORT=34567; H_STATS_SECRET="${c48}"; H_AUTH=userpass; save_hy2_state
R_STATS_PORT=34568; R_SITE=www.amazon.com; save_reality_state
T_STATS_PORT=34569; T_USER=u1234abcd
printf 'T_USER=u1234abcd\nT_PASS=%s\nT_SNI=www.nvidia.com\nT_IPV6=false\nT_STATS_PORT=34569\n' "${c48}" > "${TT_STATE}"
write_client_env "${CLIENTS_DIR}/anna.env" anna 11111111-2222-4333-8444-555555555552 "${b48}" "${c48}" 2026-10-13

echo '{"main":{"tx":100,"rx":1000},"anna":{"tx":10,"rx":20},"ghost":{"tx":5,"rx":5}}' > "${STUB}/hy.json"
cat > "${STUB}/xr.json" <<'EOF'
{"stat": [
  {"name": "user>>>main>>>traffic>>>uplink", "value": "5"},
  {"name": "user>>>main>>>traffic>>>downlink", "value": 50},
  {"name": "user>>>anna>>>traffic>>>downlink", "value": "200"},
  {"name": "inbound>>>vless-in>>>traffic>>>uplink", "value": "999"},
  {"name": "user>>>ghost>>>traffic>>>uplink", "value": "7"}
]}
EOF
echo '[{"username":"u1234abcd","ip":null,"sessions":0,"inbound":70,"outbound":7},{"username":"anna","ip":"203.0.113.9","sessions":1,"inbound":2,"outbound":1}]' > "${STUB}/tt.json"

traffic_collect
q() { jq -r "$1" "${TRAFFIC_FILE}"; }
check "$(stat -c %a "${TRAFFIC_FILE}")" 600 "traffic.json is root-only (600)"
check "$(q '.schema')" "veiltrium-traffic/1" "schema"
check "$(q '.clients.main | "\(.up) \(.down)"')" "112 1120" "main: Hysteria 100/1000 + Xray 5/50 + TrustTunnel 7/70 (outbound = up, inbound = down)"
check "$(q '.clients.anna | "\(.up) \(.down)"')" "11 222" "anna: Hysteria 10/20 + Xray 0/200 + TrustTunnel 1/2"
check "$(q '.clients.main.by_protocol | keys | join(",")')" "hysteria2,trusttunnel,vless" "by protocol: all three"
check "$(q '.clients.main.by_protocol.vless | "\(.up) \(.down)"')" "5 50" "by protocol: Xray share of main"
check "$(q '.clients.anna.by_protocol.trusttunnel | "\(.up) \(.down)"')" "1 2" "by protocol: TrustTunnel share of anna"
check "$(q '.clients | keys | join(",")')" "anna,main" "an unknown id (ghost) and a non-user Xray counter are ignored"
check "$([[ "$(q '.clients.main.last_seen')" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:]{8}Z$ ]] && echo ok)" ok "last_seen is an ISO time"
today="$(date -u +%F)"
check "$(q ".daily[\"${today}\"].main | \"\(.up) \(.down)\"")" "112 1120" "the daily rollup has today's delta"
check "$(q '.tt_raw.main | "\(.up) \(.down)"')" "7 70" "TrustTunnel baseline saved"
check "$(grep -c "${c48}" "${TRAFFIC_FILE}")" 0 "no secret in traffic.json"
check "$(grep -c '203.0.113.9' "${TRAFFIC_FILE}")" 0 "no client address in traffic.json"
check "$(grep -c "${c48}" "${STUB}/curl.args")" 0 "the Hysteria secret is not on the curl command line"
check "$(grep -c "Authorization: ${c48}" "${STUB}/curl.stdin")" 1 "the Hysteria secret goes as the Authorization header (stdin)"
check "$(grep -c 'traffic?clear=1' "${STUB}/curl.args")" 1 "Hysteria is read with clear=1"
check "$(head -n 1 "${STUB}/xray.args")" "api statsquery --server=127.0.0.1:34568 -pattern user>>> -reset" "Xray is read with statsquery -reset"

# second reading: Hysteria and Xray deliver new deltas, TrustTunnel totals only grew
echo '{"main":{"tx":1,"rx":2}}' > "${STUB}/hy.json"; echo '{}' > "${STUB}/xr.json"
echo '[{"username":"u1234abcd","inbound":90,"outbound":9},{"username":"anna","inbound":2,"outbound":1}]' > "${STUB}/tt.json"
traffic_collect
check "$(q '.clients.main | "\(.up) \(.down)"')" "115 1142" "second reading: Hysteria 1/2 and TrustTunnel +2/+20 are added (totals become deltas)"
check "$(q '.clients.anna | "\(.up) \(.down)"')" "11 222" "second reading: anna did not change"

# a TrustTunnel restart: the totals start from zero again
echo '[{"username":"u1234abcd","inbound":30,"outbound":3},{"username":"anna","inbound":0,"outbound":0}]' > "${STUB}/tt.json"
echo '{}' > "${STUB}/hy.json"
traffic_collect
check "$(q '.clients.main | "\(.up) \(.down)"')" "118 1172" "TrustTunnel counter reset: the new total counts from zero"
check "$(q '.tt_raw.main | "\(.up) \(.down)"')" "3 30" "...and becomes the new baseline"

# nothing answers: the file stays exactly as it was
cp "${TRAFFIC_FILE}" "${T}/before.json"
STUB_CURL_FAIL=1 STUB_XRAY_FAIL=1 traffic_collect
check "$(cmp -s "${TRAFFIC_FILE}" "${T}/before.json" && echo same)" same "no endpoint answers: traffic.json is not touched"

# the shared-password Hysteria auth reports everybody as "user": that is main
H_AUTH=password; save_hy2_state
echo '{"user":{"tx":4,"rx":6}}' > "${STUB}/hy.json"
traffic_collect
check "$(q '.clients.main | "\(.up) \(.down)"')" "122 1178" "shared-password Hysteria: the id user is main"
H_AUTH=userpass; save_hy2_state

# 90-day pruning
old="$(date -u -d '100 days ago' +%F)"; recent="$(date -u -d '10 days ago' +%F)"
jq --arg o "${old}" --arg r "${recent}" '.daily[$o] = {main: {up: 1, down: 1}} | .daily[$r] = {main: {up: 2, down: 2}}' "${TRAFFIC_FILE}" > "${T}/p.json"
cp "${T}/p.json" "${TRAFFIC_FILE}"
echo '{"main":{"tx":1,"rx":1}}' > "${STUB}/hy.json"
traffic_collect
check "$(q '.daily | has("'"${old}"'")')" false "a rollup older than 90 days is dropped"
check "$(q '.daily | has("'"${recent}"'")')" true "a recent rollup stays"
check "$(q '.daily | keys | length')" 2 "recent and today"

# a removed client goes (its file is gone): the next reading drops it, and so does traffic_forget
check "$(q '.clients | has("anna")')" true "anna is in the file before the removal"
rm -f "${CLIENTS_DIR}/anna.env"
echo '{"anna":{"tx":9,"rx":9},"main":{"tx":1,"rx":1}}' > "${STUB}/hy.json"
traffic_collect
check "$(q '.clients | has("anna")')" false "a removed client's counters are dropped by the next reading"
check "$(q '[.daily[] | has("anna")] | any')" false "...also from the daily rollups"
check "$(q '.tt_raw | has("anna")')" false "...and its TrustTunnel baseline"
write_client_env "${CLIENTS_DIR}/anna.env" anna 11111111-2222-4333-8444-555555555552 "${b48}" "${c48}" 2026-10-13
echo '{"anna":{"tx":3,"rx":4}}' > "${STUB}/hy.json"
traffic_collect
check "$(q '.clients.anna | "\(.up) \(.down)"')" "3 4" "a new client of the same name starts at zero"
traffic_forget anna
check "$(q '.clients | has("anna")')" false "traffic_forget removes a client at once"

# reset keeps the TrustTunnel baseline
echo '{}' > "${STUB}/hy.json"
traffic_reset
check "$(q '.clients | length')" 0 "traffic_reset: all clients at zero"
check "$(q '.daily | length')" 0 "traffic_reset: no rollups"
check "$(q '.tt_raw.main.down')" 30 "traffic_reset keeps the TrustTunnel baseline (lifetime totals must not count again)"
traffic_collect
check "$(q '.clients.main.down // 0')" 0 "after a reset the unchanged TrustTunnel totals add nothing"

# a damaged file is kept aside and counting starts again
printf 'not json' > "${TRAFFIC_FILE}"
echo '{"main":{"tx":8,"rx":9}}' > "${STUB}/hy.json"
traffic_collect
# (the TrustTunnel totals of the running process, 3/30, count again: its baseline was in the lost file)
check "$(q '.clients.main | "\(.up) \(.down)"')" "11 39" "a damaged traffic.json: counting starts again"
check "$([[ -s "${TRAFFIC_FILE}.bad" ]] && echo kept)" kept "...and the damaged file is kept as .bad"

# ---- JSON fields -----------------------------------------------------------------------------
check "$(traffic_client_json main | jq -c '[.up, .down, (.last_seen | type)]')" '[11,39,"string"]' "client traffic: up, down, last_seen"
check "$(traffic_client_json nobody | jq -c '[.up, .down, .last_seen]')" '[0,0,null]' "an unseen client: zeros and null"
check "$(traffic_totals_json | jq -r '[.up, .down] | map(type) | join(",")')" "number,number" "status totals: numbers"
check "$(traffic_doc | jq -r '.clients | keys | join(",")')" "anna,main" "traffic document lists every client that exists"
check "$(traffic_doc | jq -r 'has("tt_raw")')" false "the internal baseline is not in the document"
LABEL=Veiltrium-PL; PUBLIC_IP=192.0.2.10; CL_NAMES=(anna); CL_CREATED=(2026-10-13)
check "$(clients_json | jq -c '[.clients[] | select(.name == "main") | .traffic | [.up, .down]][0]')" "[11,39]" "list-clients JSON carries traffic per client"
check "$(clients_json | jq -c '[.clients[] | select(.name == "anna") | .traffic | [.up, .down]][0]')" "[0,0]" "...zeros for a client without traffic"
check "$(declare -f client_json | grep -c 'traffic: \$traffic')" 1 "client_json has the traffic field"
check "$(declare -f status_json | grep -c 'traffic: \$traffic')" 1 "status_json has the traffic totals"
check "$(bytes_h 1536)" "1.5 KiB" "bytes_h"
check "$(bytes_h 12)" "12 B" "bytes_h small"

JSON_OUT=""
out="$(TRAFFIC_LOCK="${TRAFFIC_LOCK}" traffic_show 2>&1)"
check "$(grep -c '^  main ' <<<"${out}")" 1 "--traffic prints a row for main"
check "$(grep -c 'Counters: Hysteria on, VLESS Reality on, TrustTunnel on' <<<"${out}")" 1 "--traffic says which counters run"

echo
if (( FAIL == 0 )); then echo "traffic unit tests: all passed"; else echo "traffic unit tests: FAILED"; fi
exit "${FAIL}"
