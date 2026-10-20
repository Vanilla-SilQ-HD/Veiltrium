#!/usr/bin/env bash
# Unit tests for the per-client limits: size and date parsing, the period boundaries, the
# traffic merge that keeps the usage of the current period, the enforcement decisions, the
# configs without disabled clients (and byte-identical without limits), the client files
# (written byte-identical without limits, loaded, validated), the panel helper's line and the
# wrapper words. No network, no root, no services: everything lives in a temporary directory.
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
U1=11111111-2222-4333-8444-555555555551
U2=11111111-2222-4333-8444-555555555552
U3=11111111-2222-4333-8444-555555555553

HY2_DIR="${T}/etc/hysteria"; HY2_CERT="${HY2_DIR}/server.crt"; HY2_KEY="${HY2_DIR}/server.key"
SCANNER_DIR="${T}/etc/veiltrium"; CLIENTS_DIR="${SCANNER_DIR}/clients"
STATE_DIR="${T}/var/veiltrium"; TRAFFIC_FILE="${STATE_DIR}/traffic.json"; TRAFFIC_LOCK="${T}/traffic.lock"
CLIENT_FILES_DIR="${T}/root/clients"
install -d -m 700 "${CLIENTS_DIR}" "${STATE_DIR}" "${CLIENT_FILES_DIR}"
try() { ( "$@" ) > "${T}/out.txt" 2>&1; RC=$?; OUT="$(cat "${T}/out.txt")"; }

# ---- SIZE -----------------------------------------------------------------------------------
for pair in "1:1" "1000:1000" "5K:5000" "5k:5000" "1M:1000000" "50G:50000000000" "50g:50000000000" "2T:2000000000000" \
            "1000T:1000000000000000" "999999999999999:999999999999999" "1000000000000000:1000000000000000"; do
    check "$(parse_size "${pair%%:*}")" "${pair#*:}" "parse_size ${pair%%:*}"
done
for bad in "" 0 00 01 -1 +1 1.5G 1G1 G 1X 1KB 1Gi " 1" "1 " "1G " 1001T 1000001G 10000000000000000 1000000000000001 "5;id" '$(id)' "1e3" 0x10 "٣"; do
    check "[$(parse_size "${bad}")]" "[]" "parse_size rejects '${bad}'"
done
check "$(size_dec 50000000000)" "50 GB" "size_dec 50 GB"
check "$(size_dec 1500000000)" "1.5 GB" "size_dec 1.5 GB"
check "$(size_dec 999)" "999 B" "size_dec bytes"
check "$(size_dec 1000000000000000)" "1 PB" "size_dec 1 PB"

# ---- dates ----------------------------------------------------------------------------------
for d in 2026-10-20 2028-02-29 2026-12-31 2000-01-01; do date_ok "${d}"; check $? 0 "date_ok ${d}"; done
for d in "" 2026-13-01 2026-02-29 2026-02-30 2026-00-10 2026-10-00 2026-1-1 26-10-20 2026/10/20 "2026-10-20 " "2026-10-20x" "tomorrow" "2026-10-20;id" '$(id)' "-1" "2026-10-32"; do
    date_ok "${d}"; check $? 1 "date_ok rejects '${d}'"
done

# ---- period boundaries (a fixed 'today') --------------------------------------------------------
check "$(period_start_of daily 2026-10-20)" 2026-10-20 "daily: today"
check "$(period_start_of weekly 2026-10-19)" 2026-10-19 "weekly: a Monday starts its own week"
check "$(period_start_of weekly 2026-10-20)" 2026-10-19 "weekly: Tuesday -> Monday"
check "$(period_start_of weekly 2026-10-25)" 2026-10-19 "weekly: Sunday -> the Monday before"
check "$(period_start_of weekly 2026-10-26)" 2026-10-26 "weekly: the next Monday"
check "$(period_start_of weekly 2026-01-01)" 2025-12-29 "weekly: across the year"
check "$(period_start_of weekly 2026-03-01)" 2026-02-23 "weekly: across the month (Sunday 1 March)"
check "$(period_start_of weekly 2028-03-01)" 2028-02-28 "weekly: across a leap February"
check "$(period_start_of monthly 2026-10-20)" 2026-10-01 "monthly: the 1st"
check "$(period_start_of monthly 2026-10-01)" 2026-10-01 "monthly: on the 1st"
check "$(period_start_of monthly 2026-12-31)" 2026-12-01 "monthly: the last day of the year"
check "$(period_start_of monthly 2027-01-01)" 2027-01-01 "monthly: the year rolls over"
check "[$(period_start_of none 2026-10-20)]" "[]" "none: no period"
check "[$(period_start_of "" 2026-10-20)]" "[]" "empty mode: no period"

# ---- client files: byte-identical without limits ----------------------------------------------
write_client_env "${T}/plain.env" anna "${U2}" "${a48}" "${b48}" 2026-10-13
printf 'C_NAME=anna\nC_UUID=%s\nC_HY2_PASS=%s\nC_TT_PASS=%s\nC_CREATED=2026-10-13\n' "${U2}" "${a48}" "${b48}" > "${T}/plain.want"
check "$(cmp -s "${T}/plain.env" "${T}/plain.want" && echo same)" same "write_client_env: six arguments write the file of earlier versions"
write_client_env "${T}/plain2.env" anna "${U2}" "${a48}" "${b48}" 2026-10-13 "" "" none active ""
check "$(cmp -s "${T}/plain2.env" "${T}/plain.want" && echo same)" same "write_client_env: empty limit fields, reset none, state active add no keys"
write_client_env "${T}/plain3.env" anna "${U2}" "${a48}" "${b48}" 2026-10-13 0 "" "" "" ""
check "$(cmp -s "${T}/plain3.env" "${T}/plain.want" && echo same)" same "write_client_env: limit 0 is no limit"
check "$(stat -c %a "${T}/plain.env")" 600 "write_client_env: mode 600"
write_client_env "${T}/full.env" anna "${U2}" "${a48}" "${b48}" 2026-10-13 50000000000 2027-01-31 monthly disabled quota
check "$(tail -n +6 "${T}/full.env" | tr '\n' '|')" "C_LIMIT=50000000000|C_EXPIRES=2027-01-31|C_RESET=monthly|C_STATE=disabled|C_REASON=quota|" "write_client_env: every optional key"
write_client_env "${T}/dis.env" anna "${U2}" "${a48}" "${b48}" 2026-10-13 "" "" "" disabled ""
check "$(tail -n +6 "${T}/dis.env" | tr '\n' '|')" "C_STATE=disabled|C_REASON=manual|" "write_client_env: disabled without a reason is manual"

# the file validator accepts them (the same one the import uses)
check "$(env_file_ok "${T}/full.env" "C_NAME C_UUID C_HY2_PASS C_TT_PASS" "C_CREATED C_LIMIT C_EXPIRES C_RESET C_STATE C_REASON"; echo $?)" 0 "validator: a client file with all limit keys passes"
check "$(env_file_ok "${T}/plain.env" "C_NAME C_UUID C_HY2_PASS C_TT_PASS" "C_CREATED C_LIMIT C_EXPIRES C_RESET C_STATE C_REASON"; echo $?)" 0 "validator: an old client file still passes"
bad_value() {   # key, value, name
    cp "${T}/full.env" "${T}/h.env"
    sed -i "s|^$1=.*|$1=$2|" "${T}/h.env"
    check "$(env_file_ok "${T}/h.env" "C_NAME C_UUID C_HY2_PASS C_TT_PASS" "C_CREATED C_LIMIT C_EXPIRES C_RESET C_STATE C_REASON"; echo $?)" 1 "validator rejects $3"
}
bad_value C_LIMIT 0 "C_LIMIT=0"
bad_value C_LIMIT -5 "C_LIMIT negative"
bad_value C_LIMIT 5G "C_LIMIT=5G"
bad_value C_LIMIT 1000000000000001 "C_LIMIT above 10^15"
bad_value C_LIMIT 12345678901234567 "C_LIMIT of 17 digits"
bad_value C_LIMIT '1;id' "C_LIMIT with a command"
bad_value C_LIMIT '$(id)' "C_LIMIT with a substitution"
bad_value C_EXPIRES 2027-02-30 "an impossible date"
bad_value C_EXPIRES 2027-1-1 "a short date"
bad_value C_EXPIRES '2027-01-31;id' "a date with a command"
bad_value C_EXPIRES "\$'2027-01-31'" "a date in \$'' quoting"
bad_value C_RESET hourly "C_RESET=hourly"
bad_value C_RESET none "C_RESET=none (never written)"
bad_value C_RESET 'daily;id' "C_RESET with a command"
bad_value C_STATE active "C_STATE=active (never written)"
bad_value C_STATE 'disabled;id' "C_STATE with a command"
bad_value C_REASON bored "C_REASON=bored"
bad_value C_REASON '`id`' "C_REASON with backticks"
cp "${T}/full.env" "${T}/h.env"; echo 'C_LIMIT=1' >> "${T}/h.env"
check "$(env_file_ok "${T}/h.env" "C_NAME C_UUID C_HY2_PASS C_TT_PASS" "C_CREATED C_LIMIT C_EXPIRES C_RESET C_STATE C_REASON"; echo $?)" 1 "validator rejects a repeated key"

# ---- loading ---------------------------------------------------------------------------------
write_client_env "${CLIENTS_DIR}/anna.env" anna "${U2}" "${a48}" "${b48}" 2026-10-13
write_client_env "${CLIENTS_DIR}/bob.env" bob "${U3}" "${b48}" "${a48}" 2026-10-14 50000000000 2027-01-31 monthly
load_clients
check "${CL_NAMES[*]}" "anna bob" "load_clients: names"
check "[${CL_LIMIT[0]}] [${CL_EXPIRES[0]}] [${CL_RESET[0]}] [${CL_STATE[0]}] [${CL_REASON[0]}]" "[] [] [none] [active] []" "load_clients: a file without limits is active, no limits"
check "[${CL_LIMIT[1]}] [${CL_EXPIRES[1]}] [${CL_RESET[1]}] [${CL_STATE[1]}] [${CL_REASON[1]}]" "[50000000000] [2027-01-31] [monthly] [active] []" "load_clients: limits read"
write_client_env "${CLIENTS_DIR}/bob.env" bob "${U3}" "${b48}" "${a48}" 2026-10-14 50000000000 2027-01-31 monthly disabled quota
load_clients
check "[${CL_STATE[1]}] [${CL_REASON[1]}]" "[disabled] [quota]" "load_clients: disabled with its reason"
write_client_env_i 1 active "" - - none "${T}/bob2.env"
check "$(tail -n +6 "${T}/bob2.env" | tr '\n' '|')" "C_LIMIT=50000000000|C_EXPIRES=2027-01-31|" "write_client_env_i: a new state, limits kept, reset replaced"
write_client_env_i 0 active "" - - - "${T}/anna2.env"
check "$(cmp -s "${T}/anna2.env" "${CLIENTS_DIR}/anna.env" && echo same)" same "write_client_env_i: a client without limits is rewritten byte-identical"
for badline in "C_LIMIT=0" "C_LIMIT=abc" "C_EXPIRES=2027-02-31" "C_RESET=hourly" "C_STATE=maybe" "C_REASON=bored"; do
    cp "${CLIENTS_DIR}/bob.env" "${T}/bob.keep"
    echo "${badline}" >> "${CLIENTS_DIR}/bob.env"
    try load_clients
    [[ "${RC}" -ne 0 && "${OUT}" == *"is damaged"* ]]; check $? 0 "load_clients stops on ${badline}"
    cp "${T}/bob.keep" "${CLIENTS_DIR}/bob.env"
done
renew_client_secrets
check "[${CL_LIMIT[1]}] [${CL_EXPIRES[1]}] [${CL_RESET[1]}] [${CL_STATE[1]}] [${CL_REASON[1]}]" "[50000000000] [2027-01-31] [monthly] [disabled] [quota]" "VT_RECONFIGURE keeps limits and state"
check "$([[ "${CL_HPASS[1]}" != "${b48}" ]] && echo new)" new "VT_RECONFIGURE: new secrets"

# ---- decisions ---------------------------------------------------------------------------------
dec() { client_decision "$@"; }
TODAY=2026-10-20
check "$(dec active "" "" "" 0 ${TODAY})" "active" "decision: no limits"
check "$(dec active "" 100 "" 99 ${TODAY})" "active" "decision: below the quota"
check "$(dec active "" 100 "" 100 ${TODAY})" "disabled quota" "decision: quota reached exactly"
check "$(dec active "" 100 "" 5000 ${TODAY})" "disabled quota" "decision: quota exceeded"
check "$(dec active "" "" 2026-10-20 0 ${TODAY})" "active" "decision: the expiry day itself is valid"
check "$(dec active "" "" 2026-10-19 0 ${TODAY})" "disabled expired" "decision: the day after the expiry"
check "$(dec active "" "" 2027-01-01 0 ${TODAY})" "active" "decision: a future expiry"
check "$(dec active "" 100 2026-10-19 500 ${TODAY})" "disabled expired" "decision: expired wins over quota"
check "$(dec active "" "" 2025-12-31 0 2026-01-01)" "disabled expired" "decision: year boundary"
check "$(dec disabled manual 100 "" 0 ${TODAY})" "disabled manual" "decision: manual stays"
check "$(dec disabled "" 100 "" 0 ${TODAY})" "disabled manual" "decision: disabled without a reason counts as manual"
check "$(dec disabled quota 100 "" 100 ${TODAY})" "disabled quota" "decision: quota still reached"
check "$(dec disabled quota 100 "" 10 ${TODAY})" "active" "decision: quota disable ends when usage is below the limit"
check "$(dec disabled quota "" "" 10 ${TODAY})" "active" "decision: quota disable ends when the limit is removed"
check "$(dec disabled expired "" 2026-10-19 0 ${TODAY})" "disabled expired" "decision: still expired"
check "$(dec disabled expired "" 2026-12-01 0 ${TODAY})" "active" "decision: a new date re-enables"
check "$(dec disabled quota 100 2026-10-01 10 ${TODAY})" "disabled expired" "decision: the reason follows the condition"
check "$(dec active "" 1000000000000000 "" 999999999999999 ${TODAY})" "active" "decision: large numbers"

# ---- the traffic merge keeps the usage of the period ---------------------------------------------
now="2026-10-20T10:00:00Z"
merge() {   # cur, h, periods, today
    jq -n -c --argjson cur "$1" --argjson h "$2" --argjson x null --argjson t null --argjson known '["main","qa","qb"]' \
        --argjson periods "$3" --arg now "${now}" --arg today "$4" --arg cutoff 2026-07-01 "${TRAFFIC_MERGE_JQ}"
}
out="$(merge '{}' '{"qa":{"up":10,"down":20}}' '{"qa":"2026-10-20"}' 2026-10-20)"
check "$(jq -c '.clients.qa | {up, down, period_start, period_bytes}' <<<"${out}")" '{"up":10,"down":20,"period_start":"2026-10-20","period_bytes":30}' "merge: a limited client gets its period"
check "$(jq -c '.clients.qb' <<<"${out}")" "null" "merge: a client without a period is not added without traffic"
out2="$(merge "${out}" '{"qa":{"up":1,"down":2}}' '{"qa":"2026-10-20"}' 2026-10-20)"
check "$(jq -r '.clients.qa.period_bytes' <<<"${out2}")" 33 "merge: the period usage adds up (30 + 3)"
check "$(jq -r '.clients.qa.up' <<<"${out2}")" 11 "merge: the lifetime counters add up as before"
out3="$(merge "${out2}" '{"qa":{"up":4,"down":0}}' '{"qa":"2026-10-21"}' 2026-10-21)"
check "$(jq -c '.clients.qa | {period_start, period_bytes}' <<<"${out3}")" '{"period_start":"2026-10-21","period_bytes":4}' "merge: a new period starts from zero, the new traffic counts"
out4="$(merge "${out2}" '{}' '{"qa":"2026-10-21"}' 2026-10-21)"
check "$(jq -c '.clients.qa | {period_start, period_bytes}' <<<"${out4}")" '{"period_start":"2026-10-21","period_bytes":0}' "merge: the boundary resets a client that had no traffic"
out5="$(merge "${out2}" '{"qa":{"up":1,"down":1}}' '{"qa":""}' 2026-12-31)"
check "$(jq -c '.clients.qa | {period_start, period_bytes}' <<<"${out5}")" '{"period_start":"2026-10-20","period_bytes":35}' "merge: no reset mode: one period that never rolls over"
out6="$(merge '{}' '{"qa":{"up":1,"down":1}}' '{"qa":""}' 2026-10-20)"
check "$(jq -r '.clients.qa.period_start' <<<"${out6}")" 2026-10-20 "merge: no reset mode: the period starts today"
out7="$(merge '{"clients":{"qa":{"up":1,"down":1,"last_seen":null,"by_protocol":{}}}}' '{}' '{}' 2026-10-20)"
check "$(jq -c '.clients.qa | has("period_bytes")' <<<"${out7}")" false "merge: without periods the client entries are as before"
out8="$(jq -n -c --argjson cur '{}' --argjson h '{"qa":{"up":1,"down":2}}' --argjson x null --argjson t null --argjson known '["main","qa"]' \
    --arg now "${now}" --arg today 2026-10-20 --arg cutoff 2026-07-01 "${TRAFFIC_MERGE_JQ}")"
check "$(jq -c '.clients.qa | has("period_bytes")' <<<"${out8}")" false "merge: called without the periods argument (older callers) still works"

# ---- periods for the collector ---------------------------------------------------------------------
write_client_env "${CLIENTS_DIR}/anna.env" anna "${U2}" "${a48}" "${b48}" 2026-10-13
write_client_env "${CLIENTS_DIR}/bob.env" bob "${U3}" "${b48}" "${a48}" 2026-10-14 50000000000 "" weekly
write_client_env "${CLIENTS_DIR}/cy.env" cy "${U1}" "${c48}" "${a48}" 2026-10-14 1000 "" ""
write_client_env "${CLIENTS_DIR}/dee.env" dee "${U1}" "${c48}" "${a48}" 2026-10-14 "" "" daily
write_client_env "${CLIENTS_DIR}/eve.env" eve "${U1}" "${c48}" "${a48}" 2026-10-14 "" 2027-01-01 ""
check "$(client_periods_json 2026-10-20 | jq -c .)" '{"bob":"2026-10-19","cy":"","dee":"2026-10-20"}' "client_periods_json: limited or resetting clients only"
rm -f "${CLIENTS_DIR}"/{cy,dee,eve}.env

# ---- enforcement plans from a fake traffic.json -----------------------------------------------------
rm -f "${CLIENTS_DIR}"/*.env
mk() {   # name limit expires reset state reason
    write_client_env "${CLIENTS_DIR}/$1.env" "$1" "${U2}" "${a48}" "${b48}" 2026-10-13 "$2" "$3" "$4" "$5" "$6"
}
mk plain "" "" "" "" ""
mk qa 50000000000 "" none active ""          # over quota
mk qb 50000000000 "" none active ""          # under quota
mk qc "" 2026-10-19 "" active ""             # expired yesterday
mk qd "" 2026-10-20 "" active ""             # expires today: still valid
mk qe 50000000000 "" daily disabled quota    # period rolled over since: back
mk qf 50000000000 "" daily disabled manual   # manual: stays
mk qg 50000000000 "" none disabled quota     # still over quota: stays
mk qh 50000000000 2026-10-01 none disabled quota   # over quota and expired: reason changes
mk qi "" "" "" disabled expired               # no expiry any more: back
mk qj 50000000000 "" weekly active ""        # over quota last week, new week
cat > "${TRAFFIC_FILE}" <<'EOF'
{"schema":"veiltrium-traffic/1","clients":{
 "qa":{"up":1,"down":1,"period_start":"-","period_bytes":50000000000},
 "qb":{"up":1,"down":1,"period_start":"-","period_bytes":10},
 "qe":{"up":1,"down":1,"period_start":"2026-10-19","period_bytes":60000000000},
 "qf":{"up":1,"down":1,"period_start":"2026-10-19","period_bytes":60000000000},
 "qg":{"up":1,"down":1,"period_start":"-","period_bytes":60000000000},
 "qh":{"up":1,"down":1,"period_start":"-","period_bytes":60000000000},
 "qj":{"up":1,"down":1,"period_start":"2026-10-12","period_bytes":90000000000}
}}
EOF
load_clients
enforce_plan 2026-10-20
plan=""
for (( k = 0; k < ${#PLAN_NAMES[@]}; k++ )); do plan+="${PLAN_NAMES[k]}=${PLAN_STATE[k]}/${PLAN_REASON[k]} "; done
check "${plan}" "qa=disabled/quota qc=disabled/expired qe=active/ qh=disabled/expired qi=active/ " "enforce_plan: quota, expiry, a daily reset re-enables, manual stays, the reason follows"
check "${PLAN_TEXT[0]}" "client qa disabled: quota 50 GB reached" "enforce_plan: the quota message"
check "${PLAN_TEXT[1]}" "client qc disabled: expired on 2026-10-19" "enforce_plan: the expiry message"
check "${PLAN_TEXT[2]}" "client qe re-enabled" "enforce_plan: the re-enable message"
check "[${PLAN_TEXT[3]}]" "[]" "enforce_plan: a change of reason alone has no message"
check "${PLAN_LIMIT[0]}${PLAN_EXPIRES[0]}${PLAN_RESET[0]}" "---" "enforce_plan: settings are kept as they are"
# the next Monday: qj is a new week (period start 2026-10-12 is old on 2026-10-20 -> bytes 0, stays active)
enforce_plan 2026-10-27
plan=""
for (( k = 0; k < ${#PLAN_NAMES[@]}; k++ )); do plan+="${PLAN_NAMES[k]}=${PLAN_STATE[k]}/${PLAN_REASON[k]} "; done
check "${plan}" "qa=disabled/quota qc=disabled/expired qd=disabled/expired qe=active/ qh=disabled/expired qi=active/ " "enforce_plan: a week later (qd expires, qj stays active)"
printf '%s\n' "${PLAN_NAMES[@]}" > /dev/null
# a damaged / missing traffic file counts as no usage
rm -f "${TRAFFIC_FILE}"
enforce_plan 2026-10-20
plan=""
for (( k = 0; k < ${#PLAN_NAMES[@]}; k++ )); do plan+="${PLAN_NAMES[k]} "; done
check "${plan}" "qc qh qi " "enforce_plan: no readable counters: a quota stop stays (the reason may still change), nobody new is stopped for quota"
echo '{"clients":{"qa":{"period_start":"-","period_bytes":"x"}}}' > "${TRAFFIC_FILE}"
enforce_plan 2026-10-20
check "${#PLAN_NAMES[@]}" 5 "enforce_plan: a bad number counts as zero usage (a readable file: quota stops end)"
cat > "${TRAFFIC_FILE}" <<'EOF'
{"clients":{"qa":{"period_start":"-","period_bytes":50000000000}}}
EOF
check "$( ( load_clients; enforce_needed ) >/dev/null 2>&1; echo $?)" 0 "enforce_needed: yes when a client must change"
rm -f "${CLIENTS_DIR}"/*.env
mk plain "" "" "" "" ""
mk qb 50000000000 "" none active ""
echo '{"clients":{"qb":{"period_start":"-","period_bytes":10}}}' > "${TRAFFIC_FILE}"
check "$(enforce_needed >/dev/null 2>&1; echo $?)" 1 "enforce_needed: no when nothing changes (the timer does not restart anything)"
check "$(ENFORCE_FAILED="${T}/ef"; enforce_backoff_ok; echo $?)" 0 "enforce_backoff_ok: no failure marker"
: > "${T}/ef"
check "$(ENFORCE_FAILED="${T}/ef"; enforce_backoff_ok; echo $?)" 1 "enforce_backoff_ok: a fresh failure marker holds the timer back"
touch -d '2 hours ago' "${T}/ef"
check "$(ENFORCE_FAILED="${T}/ef"; enforce_backoff_ok; echo $?)" 0 "enforce_backoff_ok: an old marker does not"

# ---- configs without disabled clients ------------------------------------------------------------------
rm -f "${CLIENTS_DIR}"/*.env
H_PASSWORD="${a48}"; H_AUTH=userpass; HY2_PORT=443; HY2_MASQ_URL="https://www.sony.com"; H_STATS_PORT=""; H_STATS_SECRET=""
R_UUID="${U1}"; R_PRIV="${key43}"; R_PUB="${pub43}"; R_SID="0123456789abcdef"; R_SITE=www.amazon.com; R_STATS_PORT=34568
T_USER=u1234abcd; T_PASS="${c48}"
gen_all() {   # prefix: the three configs from the loaded clients
    hy2_server_yaml "${T}/$1.yaml"; reality_server_json "${T}/$1.json" "" 443 www.amazon.com; tt_credentials_toml "${T}/$1.toml"
}
# reference: written with the arrays of an earlier version (no limit arrays at all)
CL_NAMES=(anna bob); CL_UUID=("${U2}" "${U3}"); CL_HPASS=("${a48}" "${b48}"); CL_TPASS=("${b48}" "${a48}"); CL_CREATED=(x y)
CL_LIMIT=(); CL_EXPIRES=(); CL_RESET=(); CL_STATE=(); CL_REASON=()
gen_all before
mk anna "" "" "" "" ""
write_client_env "${CLIENTS_DIR}/anna.env" anna "${U2}" "${a48}" "${b48}" x
write_client_env "${CLIENTS_DIR}/bob.env" bob "${U3}" "${b48}" "${a48}" y
load_clients
gen_all active
for e in yaml json toml; do
    check "$(cmp -s "${T}/before.${e}" "${T}/active.${e}" && echo same)" same "configs: ${e} byte-identical when no client has limits"
done
write_client_env "${CLIENTS_DIR}/bob.env" bob "${U3}" "${b48}" "${a48}" y 50000000000 "" monthly      # limits, active
load_clients
gen_all limited
for e in yaml json toml; do
    check "$(cmp -s "${T}/before.${e}" "${T}/limited.${e}" && echo same)" same "configs: ${e} unchanged by limits of an active client"
done
write_client_env "${CLIENTS_DIR}/bob.env" bob "${U3}" "${b48}" "${a48}" y 50000000000 "" monthly disabled quota
load_clients
gen_all off
check "$(grep -c "bob" "${T}/off.yaml")" 0 "Hysteria: a disabled client is left out of userpass"
check "$(grep -c "anna" "${T}/off.yaml")" 1 "Hysteria: the other client stays"
check "$(grep -c "main" "${T}/off.yaml")" 1 "Hysteria: main stays"
check "$(grep -c "${U3}" "${T}/off.json")" 0 "Xray: a disabled client is left out"
check "$(grep -c "${U2}" "${T}/off.json")" 1 "Xray: the other client stays"
check "$(jq -r '[.inbounds[0].settings.clients[].email] | join(",")' "${T}/off.json")" "main,anna" "Xray: main and anna"
check "$(grep -c 'username = "bob"' "${T}/off.toml")" 0 "TrustTunnel: a disabled client is left out"
check "$(grep -c 'username = "anna"' "${T}/off.toml")" 1 "TrustTunnel: the other client stays"
check "$(grep -c '^\[\[client\]\]' "${T}/off.toml")" 2 "TrustTunnel: main + anna"
write_client_env "${CLIENTS_DIR}/anna.env" anna "${U2}" "${a48}" "${b48}" x "" "" "" disabled manual
load_clients
gen_all alloff
check "$(sed -n '/userpass:/,/^masquerade:/p' "${T}/alloff.yaml" | grep -c "^    ")" 1 "Hysteria: only main when every added client is disabled"
check "$(jq -r '[.inbounds[0].settings.clients[].email] | join(",")' "${T}/alloff.json")" "main" "Xray: only main"
check "$(grep -c '^\[\[client\]\]' "${T}/alloff.toml")" 1 "TrustTunnel: only main"
write_client_env "${CLIENTS_DIR}/anna.env" anna "${U2}" "${a48}" "${b48}" x
write_client_env "${CLIENTS_DIR}/bob.env" bob "${U3}" "${b48}" "${a48}" y
load_clients
gen_all back
for e in yaml json toml; do
    check "$(cmp -s "${T}/before.${e}" "${T}/back.${e}" && echo same)" same "configs: ${e} identical to the original after enabling again"
done

# ---- the details file of a disabled client -------------------------------------------------------------
check "$(client_disabled_line bob quota)" "DISABLED (quota): the server does not accept this client until it is enabled again (bash veiltrium.sh --enable-client bob)." "client_disabled_line"
mkdir -p "${CLIENT_FILES_DIR}"
printf 'Veiltrium connection details: node X\nrest\n' > "${CLIENT_FILES_DIR}/bob.txt"
write_client_env "${CLIENTS_DIR}/bob.env" bob "${U3}" "${b48}" "${a48}" y 5000 "" "" disabled expired
load_clients
client_file_mark bob
check "$(head -n1 "${CLIENT_FILES_DIR}/bob.txt" | cut -c1-23)" "DISABLED (expired): the" "client_file_mark: the header at the top"
check "$(wc -l < "${CLIENT_FILES_DIR}/bob.txt" | tr -d ' ')" 3 "client_file_mark: the rest of the file is kept"
write_client_env "${CLIENTS_DIR}/bob.env" bob "${U3}" "${b48}" "${a48}" y 5000 "" "" disabled quota
load_clients
client_file_mark bob
check "$(grep -c '^DISABLED' "${CLIENT_FILES_DIR}/bob.txt")" 1 "client_file_mark: the header is replaced, not doubled"
check "$(head -n1 "${CLIENT_FILES_DIR}/bob.txt" | cut -c1-22)" "DISABLED (quota): the " "client_file_mark: the new reason"
write_client_env "${CLIENTS_DIR}/bob.env" bob "${U3}" "${b48}" "${a48}" y 5000
load_clients
client_file_mark bob
check "$(cat "${CLIENT_FILES_DIR}/bob.txt" | tr '\n' '|')" "Veiltrium connection details: node X|rest|" "client_file_mark: the header goes when the client is active"

# ---- the list and JSON of clients --------------------------------------------------------------------------
write_client_env "${CLIENTS_DIR}/bob.env" bob "${U3}" "${b48}" "${a48}" y 50000000000 2027-01-31 monthly disabled quota
load_clients
check "$(client_limits_line 1 | sed 's/^ *//')" "DISABLED (quota); limit 50 GB; expires 2027-01-31; resets monthly" "client_limits_line"
check "[$(client_limits_line 0)]" "[]" "client_limits_line: nothing for a plain client"
trc='{"bob":{"up":5,"down":6,"period_start":"2026-10-01","period_bytes":50000000000}}'
check "$(client_limits_json bob "${trc}" | jq -c .)" '{"state":"disabled","reason":"quota","limit":50000000000,"expires":"2027-01-31","reset":"monthly","period_start":"2026-10-01","period_bytes":50000000000}' "client_limits_json: a limited client"
check "$(client_limits_json anna "${trc}" | jq -c .)" '{"state":"active","reason":null,"limit":null,"expires":null,"reset":"none","period_start":null,"period_bytes":null}' "client_limits_json: a plain client"
check "$(client_limits_json main "${trc}" | jq -c .state)" '"active"' "client_limits_json: main is active"

# ---- the panel helper's line ---------------------------------------------------------------------------------
cat > "${T}/fake.sh" <<'EOF'
#!/bin/bash
printf '{"args":"%s","source":"%s"}\n' "$*" "${VEILTRIUM_SOURCE:-}"
EOF
SCRIPT_PATH="${T}/fake.sh"
helper() { printf '%s\n' "$1" | helper_main 2>/dev/null; }
out="$(helper 'set-client bob limit=5000000000 expires=2027-01-31 reset=weekly')"
[[ "${out}" == *'"args":"--set-client bob --limit 5000000000 --expires 2027-01-31 --reset weekly --json -"'* && "${out}" == *'"source":"panel"'* && "${out}" == *'::exit 0'* ]]
check $? 0 "helper: set-client with all three settings"
out="$(helper 'set-client bob limit=none expires=none reset=none')"
[[ "${out}" == *'"args":"--set-client bob --limit none --expires none --reset none --json -"'* ]]; check $? 0 "helper: set-client with none everywhere"
out="$(helper 'disable-client bob')"; [[ "${out}" == *'"args":"--disable-client bob --json -"'* && "${out}" == *'::exit 0'* ]]; check $? 0 "helper: disable-client"
out="$(helper 'enable-client bob')"; [[ "${out}" == *'"args":"--enable-client bob --json -"'* && "${out}" == *'::exit 0'* ]]; check $? 0 "helper: enable-client"
refused() {   # request, name
    out="$(helper "$1")"
    [[ "${out}" == *'request refused'* && "${out}" == *'::exit 2'* && "${out}" != *'"args"'* ]]
    check $? 0 "helper refuses $2"
}
refused 'set-client main limit=5 expires=none reset=none' "set-client main"
refused 'disable-client main' "disable-client main"
refused 'enable-client main' "enable-client main"
refused 'disable-client' "disable-client without a name"
refused 'disable-client Bob' "disable-client with a capital"
refused 'disable-client bob; id' "disable-client with a command"
refused 'enable-client bob extra' "enable-client with an extra word"
refused 'set-client bob' "set-client without settings"
refused 'set-client bob limit=5' "set-client with one setting"
refused 'set-client bob limit=5 expires=none' "set-client with two settings"
refused 'set-client bob expires=none limit=5 reset=none' "set-client with the settings in another order"
refused 'set-client bob limit=5 expires=none reset=none extra=1' "set-client with a fourth setting"
refused 'set-client bob limit=5 expires=none reset=none ' "set-client with a trailing space"
refused 'set-client bob  limit=5 expires=none reset=none' "set-client with a double space"
refused ' set-client bob limit=5 expires=none reset=none' "set-client with a leading space"
refused 'set-client bob limit=5G expires=none reset=none' "a limit with a suffix (the panel sends bytes)"
refused 'set-client bob limit=-5 expires=none reset=none' "a negative limit"
refused 'set-client bob limit=1.5 expires=none reset=none' "a decimal limit"
refused 'set-client bob limit=12345678901234567 expires=none reset=none' "a limit of 17 digits"
refused 'set-client bob limit= expires=none reset=none' "an empty limit"
refused 'set-client bob limit=5 expires=tomorrow reset=none' "a word as the date"
refused 'set-client bob limit=5 expires=2027-1-31 reset=none' "a short date"
refused 'set-client bob limit=5 expires=2027-01-31T00:00 reset=none' "a date with a time"
refused 'set-client bob limit=5 expires=none reset=hourly' "an unknown reset mode"
refused 'set-client bob limit=5 expires=none reset=daily;id' "a command after the mode"
refused 'set-client bob limit=5;id expires=none reset=daily' "a command in the limit"
refused 'set-client bob limit=$(id) expires=none reset=daily' "a substitution in the limit"
refused 'set-client bob limit=5 expires=none reset=daily --json /etc/passwd' "an option appended"
refused 'set-client bob;id limit=5 expires=none reset=daily' "a command after the name"
refused 'set-client ../x limit=5 expires=none reset=daily' "a path as the name"
refused 'set-client -x limit=5 expires=none reset=daily' "a name that is an option"
refused 'enforce' "enforce (not a panel request)"
refused 'set-client' "set-client alone"
# a request that is one line with something after a newline is cut at the newline by read: the first line decides
out="$(printf 'disable-client bob\nuninstall\n' | helper_main 2>/dev/null)"
[[ "${out}" == *'"args":"--disable-client bob --json -"'* && "${out}" != *uninstall* ]]; check $? 0 "helper: only the first line is read"


# ---- the commands, with the transaction stubbed ----------------------------------------------------------------------
# clients_change is the tested machinery of add/remove/reset; here it only records the call and moves the
# staged files into place (what the real one does before it writes the configs).
CHANGE_CALLS=0
clients_change() {
    CHANGE_CALLS=$((CHANGE_CALLS + 1)); CHANGE_MODE="$1"
    local f
    for f in "${TMPD}/apply"/*.env; do mv -f "${f}" "${CLIENTS_DIR}/${f##*/}"; done
    load_clients
}
ALERTS=(); AUDITS=()
alert_notify() { ALERTS+=("$1: $2"); }
audit_append() { AUDITS+=("$1 $2 $3"); }
TMPD="$(mktemp -d)"
rm -f "${CLIENTS_DIR}"/*.env "${CLIENT_FILES_DIR}"/*.txt
mk anna "" "" "" "" ""
mk bob 5000 "" none disabled quota
printf 'Veiltrium connection details: node X\nrest\n' > "${CLIENT_FILES_DIR}/bob.txt"
echo '{"clients":{"bob":{"period_start":"-","period_bytes":6000},"anna":{"up":1,"down":1}}}' > "${TRAFFIC_FILE}"
load_clients
SET_LIMIT=10000; SET_EXPIRES=""; SET_RESET=""
CHANGE_CALLS=0; ALERTS=(); AUDITS=()
client_limits_main set-client bob >/dev/null
check "${CHANGE_CALLS} ${CHANGE_MODE}" "1 apply" "set-client: a higher limit re-enables through clients_change apply"
check "$(tail -n +6 "${CLIENTS_DIR}/bob.env" | tr '\n' '|')" "C_LIMIT=10000|" "set-client: the new limit is saved, the state is active again"
check "${ALERTS[*]}" "client: client bob re-enabled" "set-client: the re-enable is alerted"
check "${AUDITS[*]}" "client-enabled bob ok" "set-client: the re-enable has an audit line of its own"
check "$(jq -c '.clients.bob.period_bytes' "${TRAFFIC_FILE}")" 6000 "set-client: the usage of a client that keeps its limit stays"
# the other way: a lower limit stops it at once
SET_LIMIT=6000; CHANGE_CALLS=0; ALERTS=(); AUDITS=()
client_limits_main set-client bob >/dev/null
check "$(tail -n +6 "${CLIENTS_DIR}/bob.env" | tr '\n' '|')" "C_LIMIT=6000|C_STATE=disabled|C_REASON=quota|" "set-client: a limit at the usage stops the client"
check "${ALERTS[*]}" "client: client bob disabled: quota 6 KB reached" "set-client: the stop is alerted"
# settings only: no state change, no clients_change
SET_LIMIT=""; SET_EXPIRES=2027-06-30; SET_RESET=weekly; CHANGE_CALLS=0; ALERTS=(); AUDITS=()
client_limits_main set-client anna >/dev/null
check "${CHANGE_CALLS}" 0 "set-client: settings alone restart nothing"
check "$(tail -n +6 "${CLIENTS_DIR}/anna.env" | tr '\n' '|')" "C_EXPIRES=2027-06-30|C_RESET=weekly|" "set-client: expiry and reset saved"
check "${#ALERTS[@]}" 0 "set-client: no alert without a state change"
# removing everything
SET_LIMIT=none; SET_EXPIRES=none; SET_RESET=none
client_limits_main set-client anna >/dev/null
plain_anna="$(printf 'C_NAME=anna\nC_UUID=%s\nC_HY2_PASS=%s\nC_TT_PASS=%s\nC_CREATED=2026-10-13\n' "${U2}" "${a48}" "${b48}")"
check "$(cat "${CLIENTS_DIR}/anna.env")" "${plain_anna}" "set-client: none everywhere gives the file of a plain client again"
check "$(jq -c '.clients.anna | has("period_bytes")' "${TRAFFIC_FILE}")" false "set-client: no limit and no reset: no period usage is kept"
# manual disable, then enable
SET_LIMIT=""; SET_EXPIRES=""; SET_RESET=""
CHANGE_CALLS=0; ALERTS=(); AUDITS=()
client_limits_main disable-client anna >/dev/null
check "$(tail -n +6 "${CLIENTS_DIR}/anna.env" | tr '\n' '|')" "C_STATE=disabled|C_REASON=manual|" "disable-client: manual"
check "${CHANGE_CALLS} ${ALERTS[*]}" "1 client: client anna disabled manually" "disable-client: one change, alerted"
check "${#AUDITS[@]}" 0 "disable-client: no extra audit line (the command's own line covers it)"
CHANGE_CALLS=0
client_limits_main disable-client anna >/dev/null
check "${CHANGE_CALLS}" 0 "disable-client: already disabled changes nothing"
client_limits_main enable-client anna >/dev/null
check "$(cat "${CLIENTS_DIR}/anna.env")" "${plain_anna}" "enable-client: back to the plain file"
# enable refuses while the quota is used up / the date has passed
try client_limits_main enable-client bob
[[ "${RC}" -ne 0 && "${OUT}" == *"has used its quota (6 KB of 6 KB)"* && "${OUT}" == *"--set-client bob --limit"* ]]; check $? 0 "enable-client: refused over quota, says what to do"
mk dan "" 2026-01-01 "" disabled expired
load_clients
try client_limits_main enable-client dan
[[ "${RC}" -ne 0 && "${OUT}" == *"expired on 2026-01-01"* && "${OUT}" == *"--expires"* ]]; check $? 0 "enable-client: refused after the expiry, says what to do"
mk dan "" "" "" disabled manual
load_clients
CHANGE_CALLS=0
client_limits_main enable-client dan >/dev/null
check "${CHANGE_CALLS}" 1 "enable-client: a manual disable without limits is lifted"
# --enforce
rm -f "${CLIENTS_DIR}"/*.env
mk anna "" "" "" "" ""
mk e1 1000 "" none active ""
mk e2 "" 2026-01-01 "" active ""
mk e3 1000 "" none disabled quota
mk e4 1000 "" none disabled manual
echo '{"clients":{"e1":{"period_start":"-","period_bytes":1000},"e3":{"period_start":"-","period_bytes":5}}}' > "${TRAFFIC_FILE}"
load_clients
CHANGE_CALLS=0; ALERTS=(); AUDITS=(); RESULT_EXTRA='{}'
client_limits_main enforce "" >/dev/null
check "${CHANGE_CALLS} ${CHANGE_MODE}" "1 apply" "enforce: all changes in ONE clients_change"
check "$(jq -c . <<<"${RESULT_EXTRA}")" '{"changed":["e1","e2","e3"]}' "enforce: the result lists the changed clients"
check "${AUDITS[*]}" "client-disabled e1 ok client-disabled e2 ok client-enabled e3 ok" "enforce: an audit line per state change"
check "${#ALERTS[@]}" 3 "enforce: an alert per state change"
check "${CL_STATE[*]}" "active disabled disabled active disabled" "enforce: the new states (anna e1 e2 e3 e4)"
CHANGE_CALLS=0; ALERTS=(); AUDITS=()
out="$(client_limits_main enforce "" 2>&1)"
check "${CHANGE_CALLS}" 0 "enforce: a second run changes nothing (no restart)"
[[ "${out}" == *"No client needs a change"* ]]; check $? 0 "enforce: says so"
rm -rf "${TMPD}"

# ---- the command line -------------------------------------------------------------------------------------------
cat > "${T}/stub.sh" <<'EOF'
#!/bin/bash
echo "ARGS:$*"
EOF
cli_wrapper_text "${T}/stub.sh" > "${T}/veiltrium"
W() { bash "${T}/veiltrium" "$@" 2>&1; }
check "$(W limit bob --limit 50G --expires 2027-01-31 --reset monthly)" "ARGS:--set-client bob --limit 50G --expires 2027-01-31 --reset monthly" "wrapper: limit NAME ..."
check "$(W disable bob)" "ARGS:--disable-client bob" "wrapper: disable NAME"
check "$(W enable bob)" "ARGS:--enable-client bob" "wrapper: enable NAME"
cli() { bash ./veiltrium.sh "$@" 2>&1; }
out="$(cli --set-client bob --limit 12x)"; [[ "${out}" == *"is not a size"* ]]; check $? 0 "CLI: a bad size is refused"
out="$(cli --set-client bob --limit 1001T)"; [[ "${out}" == *"is not a size"* ]]; check $? 0 "CLI: a size above 10^15 is refused"
out="$(cli --set-client bob --expires 2027-02-30)"; [[ "${out}" == *"is not a date"* ]]; check $? 0 "CLI: an impossible date is refused"
out="$(cli --set-client bob --reset hourly)"; [[ "${out}" == *"--reset needs"* ]]; check $? 0 "CLI: a bad reset mode is refused"
out="$(cli --set-client bob)"; [[ "${out}" == *"needs at least one"* ]]; check $? 0 "CLI: --set-client without a setting is refused"
out="$(cli --set-client main --limit 5G)"; [[ "${out}" == *"main client has no limits"* ]]; check $? 0 "CLI: main has no limits"
out="$(cli --disable-client main)"; [[ "${out}" == *"main client has no limits"* ]]; check $? 0 "CLI: main cannot be disabled"
out="$(cli --add-client bob --limit 5G)"; [[ "${out}" == *"belong to --set-client"* ]]; check $? 0 "CLI: the limit options belong to --set-client"
for m in --set-client --disable-client --enable-client; do
    check "$(grep -cE -- "^#    bash veiltrium.sh ${m}( |$)" veiltrium.sh)" 1 "help lists ${m} once"
done
check "$(grep -cE -- "^#    bash veiltrium.sh --enforce( |$)" veiltrium.sh)" 1 "help lists --enforce once"

if (( FAIL )); then echo "limits unit tests FAILED"; exit 1; fi
echo "limits unit tests passed"
