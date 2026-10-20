#!/usr/bin/env bash
# Unit tests for the "stalled" status and the Russia bad_streak. No network, no root;
# jq is required, busybox is used for the probe part when present.
set -u
cd "$(dirname "$0")/.." || exit 1
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

# ---- mts_status: stalled ------------------------------------------------------
now="$(date +%s)"
MTS_RECORDS="${TMPD}/records"
rec() {   # test sni route status error [age_seconds]
    printf 'v2|%s|0123456789abcdef|192.0.2.1|ppp0|%s|%s|443|%s|%s|3/3|100|30000|%s\n' \
        "$(( now - ${6:-0} ))" "$1" "$2" "$3" "$4" "$5"
}
{
    rec reality a.com verified degraded payload_stalled_17kb
    rec reality b.com verified degraded payload_failed_rc28
    rec reality c.com verified degraded ""
    rec reality j.com verified degraded payload_stalled_rc28
    rec reality d.com verified ok ""
    rec reality e.com route_unverified degraded payload_stalled_17kb
    rec reality f.com verified degraded payload_stalled_17kb "$(( 20 * 86400 ))"
    rec reality_trial g.com verified degraded payload_stalled_0kb
    rec hysteria2 h.com verified fail payload_stalled_5kb
    rec reality i.com verified degraded payload_stalled_17kb 100
    rec reality i.com verified ok "" 0
} > "${MTS_RECORDS}"
check "$(mts_status reality a.com)" stalled "degraded + payload_stalled_* -> stalled"
check "$(mts_status reality b.com)" degraded "degraded with another error stays degraded"
check "$(mts_status reality j.com)" degraded "old probe token payload_stalled_rc28 stays degraded"
check "$(mts_status reality c.com)" degraded "degraded without error stays degraded"
check "$(mts_status reality d.com)" ok "ok stays ok"
check "$(mts_status reality e.com)" route_unverified "unverified route wins over stalled"
check "$(mts_status reality f.com)" stale "old stalled result is stale"
check "$(mts_status reality g.com)" stalled "trial result counts, 0 KB too"
check "$(mts_status hysteria2 h.com)" fail "fail is not stalled even with the error text"
check "$(mts_status reality i.com)" ok "the newest result wins over an older stalled one"
for r in "$(rec reality a.com verified degraded payload_stalled_4999kb)" "$(rec reality a.com verified degraded payload_stalled_0kb)"; do
    rc=1; if [[ "${r}" =~ ${MTS_RECORD_RE} ]]; then rc=0; fi
    check "${rc}" 0 "record format accepts ${r##*|}"
done
check "$(reality_cost 40 10 0 100 0 stalled)" 750 "cost: stalled is a penalty like degraded"

# ---- russia_streak_merge: bad_streak --------------------------------------------
streak() {   # verdict -> merged file kept as the saved state
    printf '{"verdict":"%s","checked_at":"x"}' "$1" > "${TMPD}/new.json"
    russia_streak_merge "${TMPD}/saved.json" "${TMPD}/new.json" > "${TMPD}/merged.json"
    # as russia_check does: an unchecked result replaces the saved file only if there is none
    if [[ "$1" != "unchecked" || ! -s "${TMPD}/saved.json" ]]; then cp "${TMPD}/merged.json" "${TMPD}/saved.json"; fi
    jq -r '"\(.bad_streak) \(.previous_verdict)"' "${TMPD}/merged.json"
}
rm -f "${TMPD}/saved.json"
check "$(streak reachable)" "0 null" "first check, reachable"
check "$(streak partly)" "1 reachable" "partly: +1"
check "$(streak blocked)" "2 partly" "blocked: +1"
check "$(streak unchecked)" "2 blocked" "unchecked: the value is kept"
check "$(jq -r .bad_streak "${TMPD}/saved.json")" 2 "unchecked does not replace the saved file"
check "$(streak blocked)" "3 blocked" "streak continues after an unchecked run"
check "$(streak reachable)" "0 blocked" "reachable resets"
rm -f "${TMPD}/saved.json"
check "$(streak blocked)" "1 null" "first check, blocked"
rm -f "${TMPD}/saved.json"
check "$(streak unchecked)" "0 null" "first check, unchecked: 0"
printf '{"verdict":"partly"}' > "${TMPD}/saved.json"   # an old file without bad_streak
check "$(streak partly)" "1 partly" "old file without bad_streak counts as 0"

# ---- probe: payload classification (POSIX sh) -------------------------------------
probe="tools/keenetic-vpn-probe.sh"
sed -n '/^classify_payload() {/,/^}/p' "${probe}" > "${TMPD}/classify.sh"
cat > "${TMPD}/classify-run.sh" <<'EOS'
PAYLOAD_BYTES=2000000
. "$1"
for b in 2000000 2100000 1500000 17000 999 0; do
    classify_payload "$b" 28
    printf '%s %s|%s\n' "$b" "${M_PAY}" "${M_ERR}"
done
EOS
want='2000000 ok|
2100000 ok|
1500000 stalled|payload_stalled_1500kb
17000 stalled|payload_stalled_17kb
999 stalled|payload_stalled_0kb
0 fail|payload_failed_rc28'
for sh in dash busybox; do
    command -v "${sh}" >/dev/null 2>&1 || { echo "skip ${sh} (not installed)"; continue; }
    if [[ "${sh}" == busybox ]]; then got="$(busybox sh "${TMPD}/classify-run.sh" "${TMPD}/classify.sh")"
    else got="$(dash "${TMPD}/classify-run.sh" "${TMPD}/classify.sh")"; fi
    check "${got}" "${want}" "probe classify_payload under ${sh}"
done
got="$(bash "${TMPD}/classify-run.sh" "${TMPD}/classify.sh")"
check "${got}" "${want}" "probe classify_payload under bash"
# every error token must fit the server's record format
while IFS='|' read -r _ tok; do
    rc=1; if [[ "${tok}" =~ ^[a-z0-9_]{0,40}$ ]]; then rc=0; fi
    check "${rc}" 0 "error token fits the record format: ${tok}"
done <<<"${want}"
# status_of keeps stalled as degraded
sed -n '/^status_of() {/,/^}/p' "${probe}" > "${TMPD}/status.sh"
check "$(M_OK=3 RUNS=3 M_PAY=stalled bash -c '. "$1"; status_of' _ "${TMPD}/status.sh")" degraded "status_of: stalled -> degraded"
check "$(M_OK=3 RUNS=3 M_PAY=ok bash -c '. "$1"; status_of' _ "${TMPD}/status.sh")" ok "status_of: ok"

exit "${FAIL}"
