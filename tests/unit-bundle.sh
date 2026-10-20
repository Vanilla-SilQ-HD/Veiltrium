#!/usr/bin/env bash
# Unit tests for the per-client subscription (base64) and sing-box profile: links, standby
# servers, disabled clients, files, JSON fields. No network and no root needed; jq is required.
# shellcheck disable=SC2034,SC2164,SC2319
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
TMPD="$(mktemp -d)"
trap 'rm -rf "${TMPD}"' EXIT

date() { printf 'FIXED-DATE'; }
HOST=198.51.100.7; PUBLIC_IP="${HOST}"; LABEL="Veiltrium-XX"
HY2_PORT=443; HY2_SNI=hy.example.com; CERT_SHA=aabbcc; PK_SHA=ddeeff
H_AUTH=userpass; H_PASSWORD='pa"ss'; HY2_AUTH_MAIN="main:${H_PASSWORD}"
R_SITE=site.example.com; R_UUID=11111111-1111-1111-1111-111111111111; R_PUB=PUBKEY; R_SID=abcd1234
REALITY_PORT=443; REALITY_FP=chrome
T_SNI=tt.example.com; TT_PORT=8443; T_USER=vpn
CL_NAMES=(bob eve); CL_UUID=(22222222-2222-2222-2222-222222222222 33333333-3333-3333-3333-333333333333)
CL_HPASS=(bobpass evepass); CL_TPASS=(bobtt evett); CL_CREATED=(2026-10-20 2026-10-20)
CL_STATE=(active disabled); CL_REASON=("" manual)
CLIENT_FILE="${TMPD}/client.txt"; CLIENT_FILES_DIR="${TMPD}/clients"; VT_ROOT_DIR="${TMPD}"
TT_BIN=/nonexistent/tt
tt_export_link() { printf 'tt://%s@%s:%s#%s' "$1" "${2:-${PUBLIC_IP}}" "${TT_PORT}" "${3:-${LABEL}}"; }
traffic_client_json() { echo '{}'; }
client_limits_json() { echo '{}'; }

one() { printf '%s\n' "$1" | head -1; }
dec() { printf '%s' "$1" | base64 -d; }

for list in "" 203.0.113.5,198.51.100.9; do
    tag="standby=${list:-none}"
    if [[ -n "${list}" ]]; then standby_parse "${list}"; else STANDBY=(); fi
    n=${#STANDBY[@]}

    # ---- main client: the subscription decodes to exactly the expected links
    want="$(hy2_link main 'pa"ss')"
    for (( i = 0; i < n; i++ )); do want+=$'\n'"$(hy2_link main 'pa"ss' "${STANDBY[i]}" "${LABEL}-standby$(( i + 1 ))")"; done
    want+=$'\n'"$(vless_link "${R_UUID}")"
    for (( i = 0; i < n; i++ )); do want+=$'\n'"$(vless_link "${R_UUID}" "${STANDBY[i]}" "${LABEL}-standby$(( i + 1 ))")"; done
    b64="$(client_sub_b64 main)"
    check "$(dec "${b64}")" "${want}" "[${tag}] main: subscription = the expected links"
    [[ "${b64}" != *$'\n'* && "${b64}" =~ ^[A-Za-z0-9+/=]+$ ]]; check $? 0 "[${tag}] main: base64 on one line"
    check "$(dec "${b64}" | wc -l | tr -d ' ')" $(( 2 * (n + 1) - 1 )) "[${tag}] main: link count (no trailing newline)"
    check "$(dec "${b64}" | grep -c '^tt://' || true)" 0 "[${tag}] main: no TrustTunnel link"

    # ---- profile: valid, tags, pin
    p="$(client_singbox_profile_json main)"
    jq -e . >/dev/null <<<"${p}"; check $? 0 "[${tag}] main: profile is valid JSON"
    check "$(jq -r '[.outbounds[].tag] | join(",")' <<<"${p}")" \
        "hy2$(for (( i = 1; i <= n; i++ )); do printf ',hy2-standby%s' "${i}"; done),reality$(for (( i = 1; i <= n; i++ )); do printf ',reality-standby%s' "${i}"; done),auto,proxy,direct" \
        "[${tag}] main: outbound tags"
    check "$(jq -r '.outbounds[] | select(.tag == "hy2") | .tls.certificate_public_key_sha256[0] + " " + (.tls.insecure | tostring) + " " + .password' <<<"${p}")" \
        'ddeeff false main:pa"ss' "[${tag}] main: hysteria2 outbound keeps the pin, insecure false"
    check "$(jq -r '.outbounds[] | select(.tag == "auto") | (.outbounds | length | tostring) + " " + .type + " " + .interval + " " + (.tolerance | tostring) + " " + .url' <<<"${p}")" \
        "$(( 2 * (n + 1) )) urltest 3m 50 https://www.gstatic.com/generate_204" "[${tag}] main: urltest covers all outbounds"
    check "$(jq -r '.outbounds[] | select(.tag == "proxy") | .type + " " + .default + " " + .outbounds[0] + " " + (.outbounds | length | tostring)' <<<"${p}")" \
        "selector auto auto $(( 2 * (n + 1) + 1 ))" "[${tag}] main: selector proxy, default auto"
    check "$(jq -r '.inbounds[0] | .type + " " + (.auto_route | tostring) + " " + (.strict_route | tostring) + " " + .address[0] + " " + .stack' <<<"${p}")" \
        "tun true true 172.19.0.1/30 mixed" "[${tag}] main: tun inbound"
    check "$(jq -r '.route.final + " " + (.route.auto_detect_interface | tostring) + " " + (.route.rules | map(.action // .outbound) | join(","))' <<<"${p}")" \
        "proxy true sniff,hijack-dns,direct" "[${tag}] main: route"
    check "$(jq -r '.dns.servers[0] | .type + " " + .detour' <<<"${p}")" "https proxy" "[${tag}] main: DNS through the proxy"
    check "$(jq -r '.outbounds[] | select(.type == "vless") | .tls.utls.fingerprint' <<<"${p}" | sort -u)" chrome "[${tag}] main: vless keeps fp=chrome"

    # ---- client JSON
    js="$(client_json main "$(tt_export_link vpn)" "")"
    check "$(jq -r '.subscription_base64' <<<"${js}")" "${b64}" "[${tag}] main: JSON subscription_base64"
    check "$(jq -c '.singbox_profile' <<<"${js}")" "$(jq -c . <<<"${p}")" "[${tag}] main: JSON singbox_profile"

    # ---- added client, files
    rm -rf "${TMPD:?}/clients" "${TMPD}"/client.*
    client_details main "$(tt_export_link vpn)" "${CLIENT_FILE}" > "${TMPD}/main-details.txt"
    write_client_bundle "${CLIENT_FILE%.txt}" main
    check "$(stat -c %a "${TMPD}/client.sub" "${TMPD}/client.singbox.json" | tr '\n' ' ')" "600 600 " "[${tag}] main: files are 0600"
    check "$(cat "${TMPD}/client.sub")" "${b64}" "[${tag}] main: client.sub content"
    jq -e . "${TMPD}/client.singbox.json" >/dev/null; check $? 0 "[${tag}] main: client.singbox.json is valid JSON"
    install -d -m 700 "${CLIENT_FILES_DIR}"
    write_client_bundle "${CLIENT_FILES_DIR}/bob" bob
    check "$(dec "$(cat "${CLIENT_FILES_DIR}/bob.sub")" | head -1)" "$(hy2_link bob bobpass)" "[${tag}] bob: subscription starts with bob's hysteria2 link"
    check "$(jq -r '.outbounds[] | select(.tag == "reality") | .uuid' "${CLIENT_FILES_DIR}/bob.singbox.json")" 22222222-2222-2222-2222-222222222222 "[${tag}] bob: profile carries bob's UUID"
    before="$(stat -c %Y.%y "${CLIENT_FILES_DIR}/bob.sub")"
    sleep 0.05
    write_client_bundle "${CLIENT_FILES_DIR}/bob" bob
    check "$(stat -c %Y.%y "${CLIENT_FILES_DIR}/bob.sub")" "${before}" "[${tag}] bob: unchanged files are not rewritten"

    # ---- disabled client: null fields, no files, stale files removed
    js="$(client_json eve "" "")"
    check "$(jq -c '[.subscription_base64, .singbox_profile]' <<<"${js}")" "[null,null]" "[${tag}] eve (disabled): fields are null"
    echo stale > "${CLIENT_FILES_DIR}/eve.sub"; echo stale > "${CLIENT_FILES_DIR}/eve.singbox.json"
    write_client_bundle "${CLIENT_FILES_DIR}/eve" eve
    [[ ! -e "${CLIENT_FILES_DIR}/eve.sub" && ! -e "${CLIENT_FILES_DIR}/eve.singbox.json" ]]; check $? 0 "[${tag}] eve (disabled): no files"

    # ---- client file section
    d="$(client_details bob "" "${CLIENT_FILES_DIR}/bob.txt")"
    grep -q "^$(( n ? 8 : 7 ))) Phones and apps" <<<"${d}"; check $? 0 "[${tag}] bob: Phones and apps section is numbered after the others"
    grep -qF "${CLIENT_FILES_DIR}/bob.singbox.json" <<<"${d}"; check $? 0 "[${tag}] bob: section names the profile file"
    grep -q '^6) AWG Manager' <<<"${d}"; check $? 0 "[${tag}] bob: section 6 keeps its number"
    d="$(client_details eve "" "${CLIENT_FILES_DIR}/eve.txt")"
    grep -q 'This client is disabled' <<<"${d}"; check $? 0 "[${tag}] eve (disabled): section says there are no files"
done

if [[ "${FAIL}" == 0 ]]; then echo "ALL OK"; else echo "FAILED"; exit 1; fi
