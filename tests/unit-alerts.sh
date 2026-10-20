#!/usr/bin/env bash
# Unit tests for alerts and updates: setting validation, masking, once-per-change state,
# the curl command line (no token on it), version comparison, --update refusing a wrong file.
# No network and no root needed; jq is required.
# shellcheck disable=SC2034,SC2317,SC2154
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
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT
ALERTS_ENV="${T}/alerts.env"; ALERT_STATE="${T}/state/alert-state"; SCANNER_DIR="${T}"
LABEL="Veiltrium-XX"; PUBLIC_IP="198.51.100.7"

TOKEN="123456789:AAH_abcdefghijklmnopqrstuvwxyz-0123456"
HOOK="https://hooks.example.com/services/T0/B0/secretpart?x=1"

# ---- validation ---------------------------------------------------------------
v() { if "$@"; then echo yes; else echo no; fi; }
check "$(v alert_valid_token "${TOKEN}")" yes "token: valid"
check "$(v alert_valid_token "12:short")" no "token: too short"
check "$(v alert_valid_token "${TOKEN};id")" no "token: no shell characters"
check "$(v alert_valid_token "abc:AAH_abcdefghijklmnopqrstuvwxyz-0123456")" no "token: numeric id only"
check "$(v alert_valid_chat 123456789)" yes "chat: id"
check "$(v alert_valid_chat -100123456789)" yes "chat: negative id"
check "$(v alert_valid_chat @my_channel)" yes "chat: @name"
check "$(v alert_valid_chat '@a')" no "chat: @name too short"
check "$(v alert_valid_chat '1 2')" no "chat: space"
check "$(v alert_valid_hook "${HOOK}")" yes "webhook: valid"
check "$(v alert_valid_hook 'http://hooks.example.com/x')" no "webhook: http refused"
check "$(v alert_valid_hook 'https://hooks.example.com/a b')" no "webhook: space"
check "$(v alert_valid_hook 'https://hooks.example.com/a"b')" no "webhook: quote"
check "$(v alert_valid_hook "https://hooks.example.com/a'b")" no "webhook: apostrophe"
check "$(v alert_valid_hook 'https://hooks.example.com/a\b')" no "webhook: backslash"
check "$(v alert_valid_hook "https://example.com/$(printf 'a%.0s' {1..520})")" no "webhook: too long"

# ---- masking ------------------------------------------------------------------
check "$(alert_mask_token "${TOKEN}")" "123456789:****" "mask hides the secret half"
check "$(A_TOKEN="${TOKEN}"; A_CHAT=42; A_HOOK="${HOOK}"; alert_describe | grep -c 'AAH_\|secretpart' || true)" 0 "describe shows no token and no webhook path"
check "$(A_HOOK="${HOOK}"; alert_describe)" "webhook (hooks.example.com)" "describe: webhook host only"

# ---- settings: given, saved, cleared --------------------------------------------
prep() { ( ALERT_TG_TOKEN="${1:-}" ALERT_TG_CHAT="${2:-}" ALERT_WEBHOOK="${3:-}"; alert_prepare; printf '%s|%s|%s|%s|%s' "${A_ENABLED}" "${A_DIRTY}" "${A_TOKEN:+T}" "${A_CHAT}" "${A_HOOK:+H}"; ) 2>&1; }
check "$(prep)" "0|0|||" "nothing given, nothing saved: off"
check "$(prep "${TOKEN}" 42 "")" "1|1|T|42|" "telegram given"
refused() {   # name, want-substring, then prep args
    local n="$1" w="$2" out; shift 2
    out="$(prep "$@")"
    if [[ "${out}" == *"${w}"* ]]; then echo "ok   ${n}: refused"; else echo "FAIL ${n}: refused (got: ${out})"; FAIL=1; fi
}
refused "token without chat" "need both" "${TOKEN}" "" ""
refused "bad token" "not a Telegram bot token" bad 42 ""
refused "bad chat" "ALERT_TG_CHAT must be" "${TOKEN}" "a b" ""
refused "http webhook" "https://" "" "" "http://x.example.com"
# save and reload
( ALERT_TG_TOKEN="${TOKEN}"; ALERT_TG_CHAT=42; ALERT_WEBHOOK="${HOOK}"; alert_prepare; alert_save )
check "$(stat -c %a "${ALERTS_ENV}")" 600 "alerts.env is 600"
check "$(prep)" "1|0|T|42|H" "saved settings are read back"
check "$(prep none "" "")" "1|1|||H" "none clears telegram (webhook stays)"
( ALERT_TG_TOKEN=none; ALERT_WEBHOOK=none; alert_prepare; alert_save )
check "$([[ -e "${ALERTS_ENV}" ]] && echo yes || echo no)" no "everything cleared: file removed"
# a damaged saved file is ignored, not trusted
printf 'ALERT_TG_TOKEN=bad;id\nALERT_WEBHOOK=http://x\n' > "${ALERTS_ENV}"
check "$(prep)" "0|0|||" "invalid saved values are ignored"
rm -f "${ALERTS_ENV}"

# ---- curl: token never on the command line --------------------------------------
mkdir -p "${T}/bin"
cat > "${T}/bin/curl" <<'EOF'
#!/usr/bin/env bash
{ printf 'ARGV:'; printf ' [%s]' "$@"; printf '\n'; } >> "${STUB_LOG}"
cat > "${STUB_LOG}.stdin.$$" 2>/dev/null
cat "${STUB_LOG}.stdin.$$" >> "${STUB_LOG}.stdin"; rm -f "${STUB_LOG}.stdin.$$"
printf '%s' "${STUB_CODE:-200}"
exit "${STUB_RC:-0}"
EOF
chmod +x "${T}/bin/curl"
export STUB_LOG="${T}/curl.log"
OLDPATH="${PATH}"; PATH="${T}/bin:${PATH}"
: > "${STUB_LOG}"; : > "${STUB_LOG}.stdin"
A_TOKEN="${TOKEN}"; A_CHAT=42; A_HOOK="${HOOK}"; A_ENABLED=1
alert_send "hello" test
check "${A_RES_TG}/${A_RES_HOOK}" "ok/ok" "send: both channels ok"
check "$(grep -c "AAH_\|${TOKEN}\|secretpart" "${STUB_LOG}" || true)" 0 "no token and no webhook path in curl's arguments"
check "$(grep -c "bot${TOKEN}/sendMessage" "${STUB_LOG}.stdin" || true)" 1 "token goes through the curl config on stdin"
check "$(grep -c -- '--proto\] \[=https\] \[--tlsv1.2\] \[--max-time\] \[10\]' "${STUB_LOG}" || true)" 2 "https only, TLS 1.2+, 10 s timeout"
check "$(grep -c 'chat_id=42' "${STUB_LOG}" || true)" 1 "chat id sent"
STUB_CODE=401 alert_send "x" test
check "${A_RES_TG}" "failed: HTTP 401" "telegram HTTP error reported"
STUB_RC=28 STUB_CODE=000 alert_send "x" test
check "${A_RES_TG}" "failed: curl exit 28" "curl failure reported"
check "$(printf '%s' "${A_RES_TG} ${A_RES_HOOK}" | grep -c "AAH_" || true)" 0 "results hold no token"
# the webhook body is JSON with the fields
: > "${STUB_LOG}"
alert_notify down "svc down"
body="$(grep -o '\[{"node.*}\]' "${STUB_LOG}" | sed 's/^\[//; s/\]$//' | head -n1)"
check "$(jq -r '[.node, .server, .event, .text] | join("|")' <<<"${body}")" "Veiltrium-XX|198.51.100.7|down|Veiltrium-XX (198.51.100.7): svc down" "webhook JSON"
A_ENABLED=0; : > "${STUB_LOG}"
alert_notify down "silent"
check "$(wc -c < "${STUB_LOG}")" 0 "no channels: nothing is sent"
A_ENABLED=1

# ---- state changes alert once ----------------------------------------------------
sent=0
alert_send() { sent=$((sent + 1)); LAST_EVENT="$2"; LAST_TEXT="$1"; }   # count instead of sending
SVC_UP=1
svc_is_active() { (( SVC_UP == 1 )); }
rm -rf "${T}/state"
alert_watch_services hysteria-server
check "${sent}" 0 "service up: no alert"
SVC_UP=0
alert_watch_services hysteria-server
check "${sent}" 0 "down once: no alert yet"
alert_watch_services hysteria-server
check "${sent}:${LAST_EVENT}" "1:down" "down in 2 checks: one alert"
alert_watch_services hysteria-server; alert_watch_services hysteria-server
check "${sent}" 1 "still down: no repeat"
SVC_UP=1
alert_watch_services hysteria-server
check "${sent}:${LAST_EVENT}" "2:recovered" "back up: one recovered alert"
alert_watch_services hysteria-server
check "${sent}" 2 "still up: no repeat"
SVC_UP=0; alert_watch_services xray; SVC_UP=1; alert_watch_services xray; SVC_UP=0; alert_watch_services xray
check "${sent}" 2 "a single failed check between good ones does not alert"
SVC_UP=1; alert_watch_services xray

sent=0; rm -rf "${T}/state"
alert_russia_eval partly 1 "MTS"
check "${sent}" 0 "russia: streak 1, no alert"
alert_russia_eval blocked 2 "MTS, Rostelecom"
check "${sent}:${LAST_EVENT}" "1:russia" "russia: streak 2, one alert"
[[ "${LAST_TEXT}" == *"--export / --import"* && "${LAST_TEXT}" == *"standby"* ]] && echo "ok   russia: text has the hint" || { echo "FAIL russia: hint"; FAIL=1; }
alert_russia_eval blocked 3 "MTS"
check "${sent}" 1 "russia: streak 3, no repeat"
alert_russia_eval reachable 0 "MTS"
check "${sent}:${LAST_EVENT}" "2:recovered" "russia: reachable again, one alert"
alert_russia_eval reachable 0 "MTS"
check "${sent}" 2 "russia: reachable stays quiet"
rm -rf "${T}/state"
alert_russia_eval reachable 0 "MTS"
check "${sent}" 2 "russia: reachable without a previous alert is quiet"
PATH="${OLDPATH}"

# ---- versions -----------------------------------------------------------------------
cmpv() {
    local a b
    a="$(ver_key "$1")" || { echo bad; return; }; b="$(ver_key "$2")" || { echo bad; return; }
    if (( a < b )); then echo older; elif (( a > b )); then echo newer; else echo same; fi
}
check "$(cmpv 2026-10-20.2 v2026.10.20.10)" older "2026-10-20.2 < v2026.10.20.10 (numeric, not text)"
check "$(cmpv 2026-10-20.2 v2026.10.21)" older "2026-10-20.2 < v2026.10.21"
check "$(cmpv 2026-10-20.2 v2026.10.20.2)" same "equal versions"
check "$(cmpv 2026-10-20 v2026.10.20.1)" older "no suffix is the first release of the day"
check "$(cmpv 2026-10-20 v2026.10.20)" same "no suffix equals no suffix"
check "$(cmpv 2026-11-01 v2026.10.31.9)" newer "newer than the latest tag"
check "$(cmpv 2026-10-09.1 v2026.10.09.1)" same "leading zeros are not octal"
check "$(cmpv bad v2026.10.20)" bad "not a version"
check "$(ver_to_tag 2026-10-20.2)" "v2026.10.20.2" "version to tag"
atom='<link rel="alternate" href="https://github.com/X/Y/releases/tag/v2026.10.13"/>
<link href="https://github.com/X/Y/releases/tag/panel-v0.1.2"/>
<link href="https://github.com/X/Y/releases/tag/v2026.10.20.10"/>
<link href="https://github.com/X/Y/releases/tag/v2026.10.20.2"/>'
check "$(printf '%s\n' "${atom}" | update_tags_from_text | update_max_tag)" "v2026.10.20.10" "newest installer tag in a feed (panel tags ignored)"
check "$(printf '[{"name": "v2026.10.13"},{"name": "v2026.10.14.1"}]' | update_tags_from_text | update_max_tag)" "v2026.10.14.1" "newest tag in the API answer"
check "$(printf 'nothing here' | update_tags_from_text | update_max_tag)" "" "no tags: empty"

# ---- --update refuses a file that is not exactly the tagged release -----------------
mk() {   # file version [first line] [end marker]
    { echo "${3:-#!/usr/bin/env bash}"; echo "SCRIPT_VERSION=\"$2\""; echo 'echo hi'; echo "${4:-# ==== VEILTRIUM END ====}"; } > "$1"
}
mk "${T}/ok.sh" 2026-10-20.10
update_verify "${T}/ok.sh" v2026.10.20.10 && echo "ok   update_verify: matching file passes" || { echo "FAIL update_verify: matching file: ${UPD_ERR}"; FAIL=1; }
mk "${T}/old.sh" 2026-10-20.2
update_verify "${T}/old.sh" v2026.10.20.10; check "$?:${UPD_ERR}" "1:the script says version 2026-10-20.2, not 2026.10.20.10" "update_verify: SCRIPT_VERSION differs from the tag"
mk "${T}/nobash.sh" 2026-10-20.10 "#!/bin/sh"
update_verify "${T}/nobash.sh" v2026.10.20.10; check "$?" 1 "update_verify: not a bash script"
mk "${T}/trunc.sh" 2026-10-20.10 "#!/usr/bin/env bash" "# cut"
update_verify "${T}/trunc.sh" v2026.10.20.10; check "$?" 1 "update_verify: truncated file"
mk "${T}/syn.sh" 2026-10-20.10 "#!/usr/bin/env bash" "if then fi ((
# ==== VEILTRIUM END ===="
update_verify "${T}/syn.sh" v2026.10.20.10; check "$?" 1 "update_verify: bash -n fails"
: > "${T}/empty.sh"
update_verify "${T}/empty.sh" v2026.10.20.10; check "$?" 1 "update_verify: empty file"

# update_main end to end with a stub that "downloads" a wrong-version file: refuses, removes it, does not run it
UPD_DIR="${T}/upd"; mkdir -p "${UPD_DIR}"
SCRIPT_VERSION="2026-10-20.2"
update_latest() { UPD_TAG="v2026.10.20.10"; return 0; }
cat > "${T}/bin/curl" <<EOF
#!/usr/bin/env bash
out=""; while (( \$# )); do if [[ "\$1" == "-o" ]]; then out="\$2"; fi; shift; done
{ echo '#!/usr/bin/env bash'; echo 'SCRIPT_VERSION="2026-10-20.3"'; echo 'touch "${T}/RAN"'; echo '# ==== VEILTRIUM END ===='; } > "\${out}"
EOF
chmod +x "${T}/bin/curl"
PATH="${T}/bin:${OLDPATH}"
out="$( (VT_YES=1 update_main) 2>&1 )"; rc=$?
check "${rc}" 1 "update_main: wrong version refused (exit 1)"
[[ "${out}" == *"refusing to update"* ]] && echo "ok   update_main: says why" || { echo "FAIL update_main: message: ${out}"; FAIL=1; }
check "$(ls "${UPD_DIR}" | wc -l)" 0 "update_main: the refused file is removed"
check "$([[ -e "${T}/RAN" ]] && echo ran || echo not-run)" not-run "update_main: the refused file never runs"
# nothing newer: nothing downloaded
update_latest() { UPD_TAG="v2026.10.20.2"; return 0; }
out="$(update_main 2>&1)"
[[ "${out}" == *"Up to date"* ]] && echo "ok   update_main: up to date" || { echo "FAIL update_main up to date: ${out}"; FAIL=1; }
PATH="${OLDPATH}"

if (( FAIL )); then echo "unit-alerts: FAILED"; exit 1; fi
echo "unit-alerts: all passed"
