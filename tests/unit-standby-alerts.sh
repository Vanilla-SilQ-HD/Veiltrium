#!/usr/bin/env bash
# No root/network: per-channel transition delivery and real snapshot expiry/drift.
set -u
cd "$(dirname "$0")/.." || exit 1
source ./veiltrium.sh
set +eE
trap - ERR
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT
FAIL=0
check() { if [[ "$1" == "$2" ]]; then echo "ok   $3"; else echo "FAIL $3: $1 != $2"; FAIL=1; fi; }
ALERT_STATE="${T}/alerts"; STATE_DIR="${T}/state"
A_ENABLED=1; A_TOKEN=synthetic-token; A_CHAT=42; A_HOOK=https://example.invalid/synthetic-hook
LABEL=Test; PUBLIC_IP=203.0.113.10
TG_OK=1; HOOK_OK=1
logger() { :; }
eval "$(declare -f load_clients | sed '1s/load_clients/real_load_clients/')"
alert_send() {
    A_RES_TG=off; A_RES_HOOK=off
    if [[ -n "${A_TOKEN}" ]]; then
        printf 'tg|%s|%s\n' "$2" "$1" >> "${T}/sent"
        A_RES_TG=failed; if (( TG_OK )); then A_RES_TG=ok; fi
    fi
    if [[ -n "${A_HOOK}" ]]; then
        printf 'hook|%s|%s\n' "$2" "$1" >> "${T}/sent"
        A_RES_HOOK=failed; if (( HOOK_OK )); then A_RES_HOOK=ok; fi
    fi
}
count() { if [[ -f "${T}/sent" ]]; then grep -c "${1:-.}" "${T}/sent" || true; else echo 0; fi; }
# A loader must run inside the snapshot collection; its failure must not resolve alerts.
load_clients() { [[ "${LOAD_OK:-1}" == 1 ]]; }
set_hy2_auth_main() { :; }
eval "$(declare -f standby_status_json | sed '1s/standby_status_json/real_standby_status_json/')"
standby_status_json() { cat "${T}/snapshot"; }
snapshot() { jq -n --arg s "$1" '{schema:"veiltrium-standby/1",servers:[{server:"203.0.113.5",state:$s}]}' > "${T}/snapshot"; }
snapshot matching; alert_watch_standby
check "$(count)" 0 'initial matching is quiet'
snapshot changed; alert_watch_standby; alert_watch_standby
check "$(count)" 2 'changed snapshot alerts each channel once'
check "$(grep -c 'not a live connectivity test' "${T}/sent")" 2 'messages describe the evidence limit'
snapshot stale; alert_watch_standby; alert_watch_standby
check "$(count)" 4 'new problem state alerts once'
snapshot matching; alert_watch_standby; alert_watch_standby
check "$(count 'standby_recovered')" 2 'recovery after a delivered warning alerts once per channel'
HOOK_OK=0; snapshot unverified; alert_watch_standby; alert_watch_standby
check "$(count '^tg|standby|')" 3 'successful channel does not repeat while other channel fails'
check "$(count '^hook|standby|')" 4 'failed channel retries'
HOOK_OK=1; alert_watch_standby; alert_watch_standby
check "$(count '^hook|standby|')" 5 'successful retry is then quiet'
check "${A_TOKEN}|${A_HOOK}" 'synthetic-token|https://example.invalid/synthetic-hook' 'channels restored after selective delivery'
snapshot matching; alert_watch_standby
check "$(count 'standby_recovered')" 4 'both channels recover after warnings'
# All sends failing must not invent a recovery for an undelivered problem.
TG_OK=0; HOOK_OK=0; snapshot changed; alert_watch_standby
before="$(count)"; snapshot matching; alert_watch_standby
check "$(count)" "${before}" 'no recovery for a warning that never arrived'
TG_OK=1; HOOK_OK=1
snapshot changed; alert_watch_standby
saved="$(cat "${ALERT_STATE}.standby")"; before="$(count)"
LOAD_OK=0 alert_watch_standby
printf '{"schema":"bad","servers":[]}' > "${T}/snapshot"; alert_watch_standby
check "$(cat "${ALERT_STATE}.standby")" "${saved}" 'failed collection or malformed data preserves state'
check "$(count)" "${before}" 'read failure sends no false recovery'
jq -n '{schema:"veiltrium-standby/1",servers:[]}' > "${T}/snapshot"; alert_watch_standby
check "$(grep -c '^s_' "${ALERT_STATE}.standby" || true)" 0 'removed hosts forgotten without recovery'
snapshot matching; alert_watch_standby
check "$(count)" "${before}" 're-added matching host starts quietly'
A_ENABLED=0; snapshot stale; alert_watch_standby
check "$(count)" "${before}" 'no configured alerts means no notification'
A_ENABLED=1; alert_watch_standby
before="$(count)"; A_CHAT=43; alert_watch_standby
check "$(count)" "$((before + 2))" 'new channel settings receive the current problem'
check "$(stat -c %a "${ALERT_STATE}.standby")" 600 'ledger is root-private'
check "$(grep -c 'synthetic-token\|synthetic-hook' "${T}/sent" || true)" 0 'notification bodies contain no channel secrets'
# Real signed snapshots: changing local clients and expiry must reach the alert evaluator.
standby_status_json() { real_standby_status_json; }
rm -f "${ALERT_STATE}.standby" "${T}/sent"
PROBE_KEY="$(printf 'ab%.0s' {1..32})"; STANDBY=(203.0.113.5)
HY2_CERT="${T}/no-cert"; TT_DIR="${T}/no-tt"
H_AUTH=userpass; H_PASSWORD=synthetic-password; H_SNI=hy.example; H_MASQ=auto; HY2_PORT=443
R_SITE=reality.example; R_PRIV=private; R_PUB=public; R_UUID=uuid; R_SID=short; REALITY_PORT=443
T_USER=main; T_PASS=tt-password; T_SNI=tt.example; TT_PORT=8443
CL_NAMES=(alice); CL_UUID=(alice-id); CL_HPASS=(pass); CL_TPASS=(tt-pass)
CL_LIMIT=(''); CL_EXPIRES=(''); CL_RESET=(none); CL_STATE=(active); CL_REASON=('')
install -d -m 700 "${STATE_DIR}/standby"
PUBLIC_IP=203.0.113.5; standby_receipt > "${STATE_DIR}/standby/203.0.113.5.receipt"; PUBLIC_IP=203.0.113.10
alert_watch_standby; check "$(count)" 0 'real fresh matching snapshot stays quiet'
# A freshly loaded client restriction must participate; globals outside the subshell stay unchanged.
load_clients() { CL_LIMIT=(500); }
alert_watch_standby; alert_watch_standby
check "$(count)" 2 'watch loads clients before comparing fingerprints'
check "${CL_LIMIT[0]}" '' 'snapshot collection does not change watcher globals'
load_clients() { :; }
alert_watch_standby
check "$(count 'standby_recovered')" 2 'matching real fingerprint recovers'
now="$(date +%s)"; line="vt-standby-1|203.0.113.5|$((now - 86401))|$(standby_fingerprint)"
printf '%s|%s\n' "${line}" "$(hmac_sha256_hex "${PROBE_KEY}" "${line}")" > "${STATE_DIR}/standby/203.0.113.5.receipt"
alert_watch_standby; alert_watch_standby
check "$(count 'older than 24 hours')" 2 'actual receipt expiry alerts once'
# Use the real on-disk client loader, as --watch does on an installed node.
CLIENTS_DIR="${T}/clients"; mkdir -p "${CLIENTS_DIR}"
write_client_env "${CLIENTS_DIR}/alice.env" alice 11111111-1111-1111-1111-111111111111 "$(printf 'aa%.0s' {1..24})" "$(printf 'bb%.0s' {1..24})" 2026-10-30
real_load_clients
load_clients() { real_load_clients; }
PUBLIC_IP=203.0.113.5; standby_receipt > "${STATE_DIR}/standby/203.0.113.5.receipt"; PUBLIC_IP=203.0.113.10
alert_watch_standby; before="$(count)"
printf 'C_LIMIT=500\n' >> "${CLIENTS_DIR}/alice.env"
alert_watch_standby; alert_watch_standby
check "$(count)" "$((before + 2))" 'real saved client edit produces one warning per channel'
ALERTS_ENV="${T}/saved-alerts"; A_DIRTY=1; A_ENABLED=0
alert_save
check "$([[ -e "${ALERT_STATE}.standby" ]] && echo present || echo removed)" removed 'turning all channels off removes the standby ledger'
if (( FAIL )); then echo 'standby-alerts: FAILED'; exit 1; fi
echo 'standby-alerts: all passed'
