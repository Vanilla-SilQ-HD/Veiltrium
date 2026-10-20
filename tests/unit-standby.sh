#!/usr/bin/env bash
# Unit tests for the standby servers (STANDBY_HOSTS): validation, client file and JSON
# output. No network and no root needed; jq is required.
#   tests/unit-standby.sh                     run the tests
#   tests/unit-standby.sh --gen SCRIPT [LIST] print the client output of SCRIPT (internal)
# shellcheck disable=SC2034,SC2319,SC2164
set -u
cd "$(dirname "$0")/.."

# Prints the client file text and JSON of a main and an added client with fixed fake state.
gen() {
    # shellcheck disable=SC1090
    source "$1"
    set +eE
    trap - ERR
    date() { printf 'FIXED-DATE'; }
    TMPD="$(mktemp -d)"
    HOST=198.51.100.7; PUBLIC_IP="${HOST}"; LABEL="Veiltrium-XX"
    HY2_PORT=443; HY2_SNI=hy.example.com; CERT_SHA=aabbcc; PK_SHA=ddeeff
    H_AUTH=userpass; H_PASSWORD='pa"ss'; HY2_AUTH_MAIN="main:${H_PASSWORD}"
    R_SITE=site.example.com; R_UUID=11111111-1111-1111-1111-111111111111; R_PUB=PUBKEY; R_SID=abcd1234
    REALITY_PORT=443; REALITY_FP=chrome
    T_SNI=tt.example.com; TT_PORT=8443; T_USER=vpn
    CL_NAMES=(bob); CL_UUID=(22222222-2222-2222-2222-222222222222); CL_HPASS=(bobpass); CL_TPASS=(bobtt); CL_CREATED=(2026-10-20)
    CLIENT_FILE=/nonexistent/client.txt
    TT_BIN=/nonexistent/tt
    # a fake endpoint: prints a link that names the address and the link name
    tt_export_link() { printf 'tt://%s@%s:%s#%s' "$1" "${2:-${PUBLIC_IP}}" "${TT_PORT}" "${3:-${LABEL}}"; }
    if [[ -n "${2:-}" ]]; then standby_parse "$2" || { echo "standby_parse failed: ${STANDBY_ERR}"; exit 1; }
    else STANDBY=(); fi
    local c t
    for c in main bob; do
        if [[ "${c}" == main ]]; then t="$(tt_export_link vpn)"; else t="$(tt_export_link bob)"; fi
        # (the baseline installer has no such function and no standby servers)
        if declare -F tt_standby_links >/dev/null; then tt_standby_links "${c}" "${t}"; fi
        echo "=== details ${c}"
        client_details "${c}" "${t}" "/root/veiltrium/${c}.txt"
        echo "=== json ${c}"
        client_json "${c}" "${t}" "$(printf '%s\n' "${TT_STANDBY_LINKS[@]+"${TT_STANDBY_LINKS[@]}"}" | grep . || true)"
    done
}

if [[ "${1:-}" == "--gen" ]]; then gen "$2" "${3:-}"; exit 0; fi

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

# ---- validation ---------------------------------------------------------------
parse() { standby_parse "$@"; echo $?; }
check "$(parse '')" 0 "empty list is no standby"
check "$(parse none)" 0 "none clears"
standby_parse "203.0.113.5, 198.51.100.9"; check "${STANDBY[*]}" "203.0.113.5 198.51.100.9" "two hosts (spaces allowed)"
check "$(parse 192.168.1.5)" 1 "private address rejected"
check "$(parse 10.0.0.1,203.0.113.5)" 1 "private address in a list rejected"
check "$(parse not-an-ip)" 1 "garbage rejected"
check "$(parse 203.0.113.5,203.0.113.5)" 1 "duplicate rejected"
check "$(parse 203.0.113.5,198.51.100.9 203.0.113.5)" 1 "own address rejected"
check "$(parse 203.0.113.5,198.51.100.9,192.0.2.1)" 0 "three hosts accepted"
check "$(parse 203.0.113.5,198.51.100.9,192.0.2.1,198.51.100.77)" 1 "four hosts rejected"
standby_parse 203.0.113.5,203.0.113.5 || true
[[ "${STANDBY_ERR}" == *"twice"* ]]; check $? 0 "duplicate message is clear"
standby_parse 192.168.1.5 || true
[[ "${STANDBY_ERR}" == *"192.168.1.5"* ]]; check $? 0 "bad address message names the address"

# ---- no standby: byte-identical to the previous version ------------------------
# BASELINE = the installer before the batch-2 features (d6d5f90: short command, --qr; no traffic counters in the client JSON);
# without that object (a shallow clone, as in CI) only 'none' is compared with the empty list.
BASELINE="${BASELINE_REF:-d6d5f90}"
if [[ -n "${BASELINE_FILE:-}" ]]; then HEAD_REF="${BASELINE_FILE}"   # an installer file given directly
elif git show "${BASELINE}:veiltrium.sh" > "${TMPD}/head.sh" 2>/dev/null; then HEAD_REF="${TMPD}/head.sh"
else echo "note: ${BASELINE} not available; comparing the current script with itself"; HEAD_REF=./veiltrium.sh; fi
# The traffic counters (a later feature) add a "traffic" object to the client JSON; drop it
# before comparing with the baseline, which does not have it.
strip_traffic() {   # file: rewritten without the "traffic" object
    awk '/^  "traffic": \{$/ {skip=1; if (prev ~ /^  \},$/) prev="  }"; next}
         skip {if ($0 ~ /^  \}$/) skip=0; next}
         {if (have) print prev; prev=$0; have=1}
         END {if (have) print prev}' "$1" > "$1.s" && mv -f "$1.s" "$1"
}
bash tests/unit-standby.sh --gen "${HEAD_REF}" > "${TMPD}/before.txt" 2>&1
bash tests/unit-standby.sh --gen ./veiltrium.sh none > "${TMPD}/after.txt" 2>&1
bash tests/unit-standby.sh --gen ./veiltrium.sh > "${TMPD}/after-empty.txt" 2>&1
strip_traffic "${TMPD}/before.txt"; strip_traffic "${TMPD}/after.txt"; strip_traffic "${TMPD}/after-empty.txt"
cmp -s "${TMPD}/after.txt" "${TMPD}/after-empty.txt"; check $? 0 "STANDBY_HOSTS=none gives the same output as unset"
check "$(wc -c < "${TMPD}/before.txt" | tr -d ' ')" "$(wc -c < "${TMPD}/after.txt" | tr -d ' ')" "no standby: same size as before"
if cmp -s "${TMPD}/before.txt" "${TMPD}/after.txt"; then check 1 1 "no standby: client files and JSON are byte-identical"
else check differs identical "no standby: client files and JSON are byte-identical"; diff "${TMPD}/before.txt" "${TMPD}/after.txt" | head -20; fi
[[ -s "${TMPD}/after.txt" && "$(grep -c '^=== ' "${TMPD}/after.txt")" == 4 ]]; check $? 0 "generator produced all four documents"

# ---- with standby servers -------------------------------------------------------
for list in 203.0.113.5 203.0.113.5,198.51.100.9; do
    n=$(( $(tr -cd , <<<"${list}" | wc -c) + 1 ))
    bash tests/unit-standby.sh --gen ./veiltrium.sh "${list}" > "${TMPD}/sb.txt" 2>&1
    # split into documents
    awk -v d="${TMPD}" '/^=== /{ f = d "/doc-" $2 "-" $3 ".out"; next } { print > f }' "${TMPD}/sb.txt"
    for c in main bob; do
        det="${TMPD}/doc-details-${c}.out"; js="${TMPD}/doc-json-${c}.out"
        jq -e . "${js}" >/dev/null 2>&1; check $? 0 "[${n}] ${c}: client JSON is valid"
        check "$(jq -r '.standby | length' "${js}")" "${n}" "[${n}] ${c}: JSON lists the standby hosts"
        check "$(jq -r '.hysteria2.standby_outbounds | length' "${js}")" $(( n + 1 )) "[${n}] ${c}: hysteria2 outbounds + urltest"
        check "$(jq -r '.hysteria2.standby_outbounds[-1] | .type + " " + .tag' "${js}")" "urltest Veiltrium-auto-hy2" "[${n}] ${c}: hysteria2 urltest tag"
        check "$(jq -r '.hysteria2.standby_outbounds[-1].outbounds | length' "${js}")" $(( n + 1 )) "[${n}] ${c}: urltest covers main + standby"
        check "$(jq -r '.hysteria2.standby_outbounds[-1] | .url + " " + .interval + " " + (.tolerance | tostring)' "${js}")" \
            "https://www.gstatic.com/generate_204 3m 50" "[${n}] ${c}: urltest url, interval, tolerance"
        check "$(jq -r '[.hysteria2.standby_outbounds[] | select(.type == "hysteria2") | .server] | join(",")' "${js}")" "${list}" "[${n}] ${c}: standby servers in the outbounds"
        check "$(jq -r '.hysteria2.awg_group | length' "${js}")" $(( n + 1 )) "[${n}] ${c}: awg group = main + standby"
        check "$(jq -r '.hysteria2.awg_group[1].tag + " " + .hysteria2.awg_group[1].server' "${js}")" "Veiltrium-standby1 203.0.113.5" "[${n}] ${c}: awg standby entry"
        check "$(jq -r '[.hysteria2.awg_group[] | has("password")] | all' "${js}")" true "[${n}] ${c}: awg entries carry the password"
        check "$(jq -r '.hysteria2.awg_group | (.[0] | del(.tag, .server)) == (.[1] | del(.tag, .server))' "${js}")" true "[${n}] ${c}: awg standby entry = main entry except tag/server"
        check "$(jq -r '.hysteria2.standby_links | length' "${js}")" "${n}" "[${n}] ${c}: hysteria2 standby links"
        [[ "$(jq -r '.hysteria2.standby_links[0]' "${js}")" == hysteria2://*@203.0.113.5:443/*"#Veiltrium-XX-standby1" ]]
        check $? 0 "[${n}] ${c}: hysteria2 standby link has the host and a suffixed name"
        check "$(jq -r '.vless.standby_outbounds | length' "${js}")" $(( n + 1 )) "[${n}] ${c}: vless outbounds + urltest"
        check "$(jq -r '.vless.standby_outbounds[0].tls.utls.fingerprint' "${js}")" chrome "[${n}] ${c}: standby vless keeps fp=chrome"
        check "$(jq -r '.vless.standby_outbounds[-1].outbounds | join(",")' "${js}" | cut -d, -f1-2)" "reality,reality-standby1" "[${n}] ${c}: vless urltest members"
        [[ "$(jq -r '.vless.standby_links[0]' "${js}")" == vless://*@203.0.113.5:443?*"fp=chrome"*"#Veiltrium-XX-standby1" ]]
        check $? 0 "[${n}] ${c}: vless standby link"
        check "$(jq -r '.trusttunnel.standby_links | length' "${js}")" "${n}" "[${n}] ${c}: tt standby links"
        check "$(jq -r '.hysteria2.outbound.server' "${js}")" 198.51.100.7 "[${n}] ${c}: main outbound still points to this node"
        # client file text: the extra JSON arrays are valid JSON
        grep -c 'Veiltrium-standby1' "${det}" >/dev/null; check $? 0 "[${n}] ${c}: file has the awg standby entry"
        check "$(grep -c '^hysteria2://' "${det}")" $(( n + 1 )) "[${n}] ${c}: file has main + standby hysteria2 links"
        check "$(grep -c '^vless://' "${det}")" $(( n + 1 )) "[${n}] ${c}: file has main + standby vless links"
        check "$(grep -c '^tt://' "${det}")" $(( n + 1 )) "[${n}] ${c}: file has main + standby tt links"
        [[ "$(grep -m1 '^hysteria2://' "${det}")" != *standby* ]]; check $? 0 "[${n}] ${c}: the first link is still the main one"
        # the awg group block (section 6) and the standby arrays of sections 2 and 4 are valid JSON
        sed -n '/^6) AWG Manager/,/^\]/p' "${det}" | sed '1,2d' | jq -e 'length' >/dev/null 2>&1; check $? 0 "[${n}] ${c}: file section 6 is valid JSON"
        check "$(sed -n '/^6) AWG Manager/,/^\]/p' "${det}" | sed '1,2d' | jq -r 'length')" $(( n + 1 )) "[${n}] ${c}: file section 6 has main + standby"
        awk '/Add all of them|Add all of them:/{f=1; next} f && /^\[/{p=1} p{print} p && /^\]/{exit}' "${det}" > "${TMPD}/arr.json"
        jq -e 'map(select(.type == "hysteria2")) | length' "${TMPD}/arr.json" >/dev/null 2>&1; check $? 0 "[${n}] ${c}: file standby array (section 2) is valid JSON"
        check "$(jq -r '.[-1].type' "${TMPD}/arr.json")" urltest "[${n}] ${c}: section 2 array ends with the urltest group"
        grep -q '^7) Standby servers: ' "${det}"; check $? 0 "[${n}] ${c}: file has the standby note (same ports)"
    done
done

if [[ "${FAIL}" == 0 ]]; then echo "ALL OK"; else echo "FAILED"; exit 1; fi
