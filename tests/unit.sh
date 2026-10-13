#!/usr/bin/env bash
# Unit tests for the decision logic of hy2-secure-install.sh: scoring, choice,
# home-network records. No network and no root needed; jq is required.
set -u
cd "$(dirname "$0")/.."
# shellcheck source=../hy2-secure-install.sh
source ./hy2-secure-install.sh
set +eE
trap - ERR

FAIL=0
check() {   # got, want, name
    if [[ "$1" == "$2" ]]; then echo "ok   $3"; else echo "FAIL $3: got '$1', want '$2'"; FAIL=1; fi
}
TMPD="$(mktemp -d)"
trap 'rm -rf "${TMPD}"' EXIT

# ---- score: fixed formula, integers, same input -> same output ---------------
check "$(reality_cost 40 10 0 100 0 untested)" 150 "cost: medians and spread"
check "$(reality_cost 40 10 1 100 2 untested)" 900 "cost: failures weigh 250 each"
check "$(reality_cost 40 10 0 100 0 ok)" 0 "cost: home-network success bonus, never below 0"
check "$(reality_cost 400 10 0 100 0 ok)" 310 "cost: home-network success bonus"
check "$(reality_cost 40 10 0 100 0 fail)" 750 "cost: home-network failure penalty"
check "$(reality_cost 40 10 0 100 0 route_unverified)" 150 "cost: unverified route does not count"
check "$(reality_cost 40 10 0 100 0 stale)" 150 "cost: stale result does not count"

# ---- choice ----------------------------------------------------------------
row() {   # site order gate cost
    printf '%s\t%s\t%s\treason\t192.0.2.10\t0\t10\t1\t0\t200\tok\t50\t0\tok\tuntested\t%s\n' "$1" "$2" "$3" "$4"
}
sel() { cat > "${TMPD}/selection.tsv"; }

{ row a.com 1 pass 200; row b.com 2 pass 150; row c.com 3 fail -1; } | sel
reality_choose ""
check "${R_CHOSEN}" b.com "fresh node: best score wins"
check "${R_TOP3}" "b.com a.com" "top 3 lists passing sites by score"
reality_choose a.com
check "${R_CHOSEN}" a.com "current site within the margin is kept (200 <= 150 + 50)"
reality_choose c.com
check "${R_CHOSEN}" b.com "current site failing the gates is replaced"
[[ "${R_DECISION}" == *"fails the checks"* ]]; check $? 0 "decision says why the current site was replaced"

{ row a.com 1 pass 201; row b.com 2 pass 150; } | sel
reality_choose a.com
check "${R_CHOSEN}" b.com "current site worse than the margin is replaced (201 > 150 + 50)"

{ row a.com 1 pass 1250; row b.com 2 pass 1000; } | sel
reality_choose a.com
check "${R_CHOSEN}" a.com "margin is 25% of the best for large scores (1250 <= 1000 + 250)"
{ row a.com 1 pass 1251; row b.com 2 pass 1000; } | sel
reality_choose a.com
check "${R_CHOSEN}" b.com "beyond 25% the better site wins"

{ row a.com 1 pass 150; row b.com 2 pass 150; } | sel
reality_choose ""
check "${R_CHOSEN}" a.com "ties: the list order decides (no randomness)"
first="${R_CHOSEN}"; reality_choose ""
check "${R_CHOSEN}" "${first}" "same input, same choice"

{ row a.com 1 fail -1; row b.com 2 fail -1; } | sel
reality_choose a.com
check "${R_CHOSEN}" "" "nothing passes: nothing is chosen"
check "${R_DECISION}" "no candidate passed the checks" "decision when nothing passes"

{ row a.com 1 pass 120; row b.com 2 pass 150; } | sel
R_CHOSEN=a.com; R_DECISION=x
selection_json > "${TMPD}/sel.json"
check "$(jq -r '.top3 | join(",")' "${TMPD}/sel.json")" "a.com,b.com" "selection JSON: top 3"
check "$(jq -r '.candidates[0].score' "${TMPD}/sel.json")" 120 "selection JSON: numeric score"
check "$(jq -r '.candidates[0].ipv4[0]' "${TMPD}/sel.json")" 192.0.2.10 "selection JSON: addresses"

# ---- home-network records --------------------------------------------------
now="$(date +%s)"
MTS_RECORDS="${TMPD}/records"
check "$(mts_status reality a.com)" untested "no probe data: untested"
{
    printf 'v2|%s|0123456789abcdef|192.0.2.1|ppp0|reality|a.com|443|verified|ok|3/3|100|2000000|\n' "${now}"
    printf 'v2|%s|0123456789abcdef|192.0.2.1|ppp0|reality|b.com|443|route_unverified|ok|3/3|100|2000000|\n' "${now}"
    printf 'v2|%s|0123456789abcdef|192.0.2.1|ppp0|reality|c.com|443|verified|ok|3/3|100|2000000|\n' "$(( now - 20 * 86400 ))"
    printf 'v2|%s|0123456789abcdef|192.0.2.1|ppp0|reality_trial|d.com|443|verified|degraded|3/3|100|30000|payload_stalled_rc28\n' "${now}"
    printf 'v2|%s|0123456789abcdef|192.0.2.1|ppp0|reality|e.com|443|verified|ok|3/3|100|2000000|\n' "$(( now - 100 ))"
    printf 'v2|%s|0123456789abcdef|192.0.2.1|ppp0|reality|e.com|443|verified|fail|0/3|0|0|transport_timeout\n' "${now}"
} > "${MTS_RECORDS}"
check "$(mts_status reality a.com)" ok "verified route + ok -> ok"
check "$(mts_status reality b.com)" route_unverified "unverified route never counts as proof"
check "$(mts_status reality c.com)" stale "older than ${MTS_MAX_AGE_DAYS} days -> stale"
check "$(mts_status reality d.com)" degraded "trial results count for the site"
check "$(mts_status reality e.com)" fail "the newest result wins"
check "$(mts_status hysteria2 a.com)" untested "other protocols are separate"
{
    printf 'v2|%s|1111111111111111|192.0.2.1|ppp0|reality|f.com|443|verified|ok|3/3|100|2000000|\n' "${now}"
    printf 'v2|%s|1111111111111111|192.0.2.1|ppp0|reality_trial|f.com|443|verified|fail|0/3|0|0|transport_timeout\n' "${now}"
    printf 'v2|%s|2222222222222222|192.0.2.1|ppp0|reality|g.com|443|verified|ok|3/3|100|2000000|\n' "$(( now - 50 ))"
    printf 'v2|%s|3333333333333333|192.0.2.1|ppp0|reality|g.com|443|route_unverified|skipped|0/0|0|0|missing_singbox\n' "${now}"
} >> "${MTS_RECORDS}"
check "$(mts_status reality f.com)" fail "same time: the worse result wins"
check "$(mts_status reality g.com)" ok "a newer skipped test does not hide an older real result"

# ---- names of Hysteria and TrustTunnel: never the Reality site ------------------
CAND_LIST=(a.com b.com c.com d.com)
prescreen_site() { PS_GATE=fail; [[ " ${STUB_PASS:-} " == *" $1 "* ]] && PS_GATE=pass; return 0; }
{ row a.com 1 pass 200; row b.com 2 pass 150; printf 'c.com\t3\tfail\tr\t\t0\t0\t0\t3\t\tuntested\t0\t0\tuntested\tuntested\t-1\n'; } | sel
sed -i '2s/\t10\t/\t5\t/' "${TMPD}/selection.tsv"     # b.com: faster TLS than a.com
check "$(pick_independent_sni a.com)" b.com "avoids the Reality site, first of the rest in list order"
check "$(pick_independent_sni b.com)" a.com "avoids the Reality site (other case)"
check "$(STUB_PASS=d.com pick_independent_sni a.com b.com)" d.com "falls back to a direct check of the list"
check "$(STUB_PASS='' pick_independent_sni a.com b.com)" c.com "last resort: the first name not avoided"
rm -f "${TMPD}/selection.tsv"
check "$(STUB_PASS='c.com d.com' pick_independent_sni a.com)" c.com "no evaluation this run: list order, direct check"
CAND_LIST=(a.com)
check "$(STUB_PASS='' pick_independent_sni a.com)" a.com "a one-site list cannot avoid it (still a name)"
unset -f prescreen_site

good="v2|${now}|0123456789abcdef|192.0.2.1|ppp0|tt_h3|www.example.com|8443|verified|ok|3/3|80|2000000|"
[[ "${good}" =~ ${MTS_RECORD_RE} ]]; check $? 0 "record format accepted"
for bad in "v2|${now}|0123456789abcdef|192.0.2.1|ppp0|reality|a.com;rm -rf|443|verified|ok|3/3|1|1|" \
           "v2|${now}|0123456789abcdef|192.0.2.1|ppp0|shell|a.com|443|verified|ok|3/3|1|1|" \
           "v2|${now}|0123456789abcdef|192.0.2.1|ppp0|reality|a.com|443|verified|ok|3/3|1|1|\$(id)" \
           "v2|${now}|192.0.2.1|reality|a.com|443|verified|ok|3/3|1|1|" \
           "v1|${now}|192.0.2.1|reality|a.com|443|verified|ok|3/3|1|1|"; do
    [[ "${bad}" =~ ${MTS_RECORD_RE} ]]; check $? 1 "malformed record rejected: ${bad:0:60}"
done

# ---- HMAC-SHA256: RFC 4231 vectors, NUL bytes, and agreement with OpenSSL --------
check "$(hmac_sha256_hex 0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b 'Hi There')" \
    b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7 "HMAC: RFC 4231 case 1"
check "$(hmac_sha256_hex 4a656665 'what do ya want for nothing?')" \
    5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 "HMAC: RFC 4231 case 2"
check "$(hmac_sha256_hex 363636363636363636363636363636365c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c 'hy2 selftest 0')" \
    eceb5cdcb23ee5101e51ccbdbe4a03877839af8f604b388843917dc0b6871cd5 "HMAC: NUL bytes in the pads and the inner hash"
for i in 1 2 3 4 5 6 7 8; do
    k="$(openssl rand -hex 32)"; m="v2|${now}|$(openssl rand -hex 8)|192.0.2.1|reality|a.com|443|verified|ok|3/3|${i}|1|"
    want="$(printf '%s' "${m}" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${k}" | awk '{print $NF}')"
    check "$(hmac_sha256_hex "${k}" "${m}")" "${want}" "HMAC agrees with OpenSSL (random key ${i})"
done

# ---- Reality config text: unchanged format (no restart on update) ------------
R_UUID="11111111-2222-4333-8444-555555555555"; R_PRIV="$(printf 'A%.0s' {1..43})"; R_SID="0123456789abcdef"
reality_server_json "${TMPD}/c1.json" "" 443 www.example.com
check "$(sha256sum < "${TMPD}/c1.json" | cut -c1-16)" "$(cat <<EOF | sha256sum | cut -c1-16
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
    "port": 443,
    "protocol": "vless",
    "settings": {"clients": [{"id": "${R_UUID}", "flow": "xtls-rprx-vision"}], "decryption": "none"},
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "target": "www.example.com:443",
        "serverNames": ["www.example.com"],
        "privateKey": "${R_PRIV}",
        "shortIds": ["${R_SID}"]
      }
    }
  }],
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
}
EOF
)" "production config text is byte-identical to earlier versions"
reality_server_json "${TMPD}/c2.json" 127.0.0.1 20001 a.com b.com c.com
check "$(jq -r '.inbounds[0].listen + " " + (.inbounds[0].streamSettings.realitySettings.serverNames | join(","))' "${TMPD}/c2.json")" \
    "127.0.0.1 a.com,b.com,c.com" "test/trial config: listen address and extra names"

# ---- ports of an existing node are kept unless given explicitly ------------------
XRAY_DIR="${TMPD}/xray"; TT_DIR="${TMPD}/tt"; mkdir -p "${XRAY_DIR}" "${TT_DIR}"
reality_server_json "${XRAY_DIR}/config.json" "" 8444 www.example.com
printf '# hy2-secure-install: TrustTunnel endpoint
listen_address = "0.0.0.0:9443"
ipv6_available = false
' > "${TT_DIR}/vpn.toml"
REALITY_PORT_GIVEN=""; TT_PORT_GIVEN=""; REALITY_PORT=443; TT_PORT=8443
load_ports
check "${REALITY_PORT}/${TT_PORT}" "8444/9443" "a re-run keeps the node's Reality and TrustTunnel ports"
REALITY_PORT_GIVEN=1; TT_PORT_GIVEN=1; REALITY_PORT=443; TT_PORT=8443
load_ports
check "${REALITY_PORT}/${TT_PORT}" "443/8443" "explicit REALITY_PORT / TT_PORT change them"
rm -f "${XRAY_DIR}/config.json" "${TT_DIR}/vpn.toml"; REALITY_PORT_GIVEN=""; TT_PORT_GIVEN=""
load_ports
check "${REALITY_PORT}/${TT_PORT}" "443/8443" "a new node uses the defaults"

# ---- added clients: config texts, order, links ----------------------------------
CLIENTS_DIR="${TMPD}/clients"; mkdir -p "${CLIENTS_DIR}"
mkclient() {   # name uuid-last-digit
    printf 'C_NAME=%s\nC_UUID=11111111-2222-4333-8444-55555555555%s\nC_HY2_PASS=%s\nC_TT_PASS=%s\nC_CREATED=2026-10-13\n' \
        "$1" "$2" "$(printf 'a%.0s' {1..48})" "$(printf 'b%.0s' {1..48})" > "${CLIENTS_DIR}/$1.env"
}
mkclient b-x 1; mkclient a_y 2; mkclient a-z 3
load_clients
check "${CL_NAMES[*]}" "a-z a_y b-x" "clients are sorted by name in the C locale (same config text everywhere)"
reality_server_json "${TMPD}/c3.json" "" 443 www.example.com
check "$(jq -c '.inbounds[0].settings.clients | map(.email // "main")' "${TMPD}/c3.json")" '["main","a-z","a_y","b-x"]' \
    "Reality: the main client first (no email, as before), then the added ones"
check "$(jq -r '.inbounds[0].settings.clients[1] | .id + " " + .flow' "${TMPD}/c3.json")" \
    "11111111-2222-4333-8444-555555555553 xtls-rprx-vision" "Reality: an added client has its own UUID and the vision flow"
HY2_PORT=443; HY2_CERT=/etc/hysteria/server.crt; HY2_KEY=/etc/hysteria/server.key
H_PASSWORD="$(printf 'c%.0s' {1..48})"; HY2_MASQ_URL="https://www.example.com"
saved=("${CL_NAMES[@]}"); CL_NAMES=()
H_AUTH=password; hy2_server_yaml "${TMPD}/h1.yaml"
check "$(sha256sum < "${TMPD}/h1.yaml" | cut -c1-16)" "$(cat <<EOF | sha256sum | cut -c1-16
# hy2-secure-install: Hysteria 2 server
listen: :443
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: '${H_PASSWORD}'
masquerade:
  type: proxy
  proxy:
    url: 'https://www.example.com'
    rewriteHost: true
EOF
)" "Hysteria config with one shared password is byte-identical to earlier versions"
CL_NAMES=("${saved[@]}")
H_AUTH=userpass; hy2_server_yaml "${TMPD}/h2.yaml"
check "$(sed -n '/^auth:/,/^masquerade:/p' "${TMPD}/h2.yaml" | sed '1d;$d' | cut -c1-14 | tr '\n' '|')" \
    "  type: userpa|  userpass:|    main: 'ccc|    'a-z': 'aa|    'a_y': 'aa|    'b-x': 'aa|" \
    "Hysteria userpass: main first (as before), then the added clients as quoted keys"
for n in 007 1e3 null true 2026-10-13; do
    CL_NAMES=("${n}"); hy2_server_yaml "${TMPD}/h3.yaml"
    check "$(grep -c "^    '${n}': " "${TMPD}/h3.yaml")" 1 "Hysteria userpass: the name ${n} stays a string"
done
CL_NAMES=("${saved[@]}")
T_USER=u1234abcd; T_PASS=pw0; tt_credentials_toml "${TMPD}/cred.toml"
check "$(grep -c '^\[\[client\]\]' "${TMPD}/cred.toml")/$(sed -n 2p "${TMPD}/cred.toml")" '4/username = "u1234abcd"' \
    "TrustTunnel credentials: main first, one [[client]] per added client"
CL_NAMES=(); tt_credentials_toml "${TMPD}/cred1.toml"
check "$(cat "${TMPD}/cred1.toml")" "$(printf '[[client]]\nusername = "u1234abcd"\npassword = "pw0"')" \
    "TrustTunnel credentials without added clients: the text earlier versions wrote"
CL_NAMES=("${saved[@]}")
HOST=192.0.2.1; HY2_SNI=www.example.org; CERT_SHA="$(printf 'd%.0s' {1..64})"; LABEL="Veiltrium-PL"
check "$(hy2_link "" "${H_PASSWORD}")" "hysteria2://${H_PASSWORD}@192.0.2.1:443/?sni=www.example.org&insecure=1&pinSHA256=${CERT_SHA}&pcs=${CERT_SHA}#Veiltrium-PL" \
    "hysteria2 link with one shared password, named after the node"
check "$(hy2_link a-z pw)" "hysteria2://a-z:pw@192.0.2.1:443/?sni=www.example.org&insecure=1&pinSHA256=${CERT_SHA}&pcs=${CERT_SHA}#Veiltrium-PL" \
    "hysteria2 link of a user: user:password, as the URI scheme defines it"
old="$(cat "${CLIENTS_DIR}"/*.env | sha256sum)"
renew_client_secrets
check "${CL_NAMES[*]} ${CL_CREATED[*]}" "a-z a_y b-x 2026-10-13 2026-10-13 2026-10-13" "HY2_RECONFIGURE: the clients keep their names and dates"
check "$([[ "${CL_HPASS[0]}" =~ ^[0-9a-f]{48}$ && "${CL_HPASS[0]}" != "$(printf 'a%.0s' {1..48})" && "${CL_UUID[0]}" != 11111111-2222-4333-8444-555555555553 ]] && echo new)" new \
    "HY2_RECONFIGURE: the clients get new secrets"
check "$(stat -c '%a' "${CLIENTS_DIR}/a-z.env")" 600 "client files stay 0600"
[[ "$(cat "${CLIENTS_DIR}"/*.env | sha256sum)" != "${old}" ]]; check $? 0 "HY2_RECONFIGURE rewrote the client files"
mkclient b-x 1; mkclient a_y 2; mkclient a-z 3; load_clients
mkclient bad 4; sed -i 's/^C_UUID=.*/C_UUID=$(id)/' "${CLIENTS_DIR}/bad.env"
( load_clients ) >/dev/null 2>&1; check $? 1 "a damaged client file stops the run"
rm -f "${CLIENTS_DIR}/bad.env"
mkclient other 5; sed -i 's/^C_NAME=.*/C_NAME=someone-else/' "${CLIENTS_DIR}/other.env"
( load_clients ) >/dev/null 2>&1; check $? 1 "a client file must carry its own name"
rm -f "${CLIENTS_DIR}/other.env"
for n in anna phone-1 a_b 0 "$(printf 'x%.0s' {1..32})"; do
    [[ "${n}" =~ ${CLIENT_RE} ]]; check $? 0 "client name accepted: ${n}"
done
for n in Anna "-x" "a b" "a;b" "$(printf 'x%.0s' {1..33})" ""; do
    [[ "${n}" =~ ${CLIENT_RE} ]]; check $? 1 "client name rejected: '${n}'"
done
for n in PL FI-2 x1; do [[ "${n}" =~ ${NAME_RE} ]]; check $? 0 "node name accepted: ${n}"; done
for n in "-PL" "PL-" "P L" "PL;x" "$(printf 'x%.0s' {1..17})"; do [[ "${n}" =~ ${NAME_RE} ]]; check $? 1 "node name rejected: '${n}'"; done

# connection details: the same layout for every client, every JSON block valid
R_UUID="11111111-2222-4333-8444-555555555555"; R_PUB="$(printf 'B%.0s' {1..43})"; R_SITE=www.example.com
REALITY_PORT=443; REALITY_FP=chrome; PK_SHA="$(printf 'E%.0s' {1..43})="; T_SNI=www.example.net; TT_PORT=8443
for who in main a_y; do
    client_details "${who}" "tt://?AAAA" "/root/x.txt" > "${TMPD}/d-${who}.txt"
    awk '/^\{/{n++} n==1{print} n==1&&/^\}/{exit}' "${TMPD}/d-${who}.txt" > "${TMPD}/s2.json"
    awk '/^\{/{n++} n==2{print} n==2&&/^\}/{exit}' "${TMPD}/d-${who}.txt" > "${TMPD}/s4.json"
    awk '/^\[$/{f=1} f{print} f&&/^\]$/{exit}' "${TMPD}/d-${who}.txt" > "${TMPD}/s6.json"
    want_pw="main:${H_PASSWORD}"; want_uuid="${R_UUID}"
    if [[ "${who}" != main ]]; then want_pw="a_y:$(printf 'a%.0s' {1..48})"; want_uuid=11111111-2222-4333-8444-555555555552; fi
    check "$(jq -r '.password' "${TMPD}/s2.json")" "${want_pw}" "details ${who}: sing-box outbound has the client's auth"
    check "$(jq -r '.uuid' "${TMPD}/s4.json")" "${want_uuid}" "details ${who}: VLESS outbound has the client's UUID"
    check "$(jq -r '.[0].tag + " " + .[0].password' "${TMPD}/s6.json")" "Veiltrium ${want_pw}" "details ${who}: the server in the AWG group is just Veiltrium"
    check "$(grep -c "#Veiltrium-PL\$" "${TMPD}/d-${who}.txt")" 2 "details ${who}: hysteria2 and vless links are named after the node"
    check "$(grep -c '^tt://' "${TMPD}/d-${who}.txt")" 1 "details ${who}: the tt:// link is included"
done
H_AUTH=password
client_details main "" "/root/x.txt" > "${TMPD}/d-legacy.txt"
check "$(awk '/^\{/{n++} n==1{print} n==1&&/^\}/{exit}' "${TMPD}/d-legacy.txt" | jq -r .password)" "${H_PASSWORD}" \
    "details of a node with one shared password: the plain password"
check "$(grep -c '^tt://' "${TMPD}/d-legacy.txt")" 0 "details without TrustTunnel: no tt:// link"

if (( FAIL )); then echo "UNIT TESTS FAILED"; exit 1; fi
echo "all unit tests passed"
