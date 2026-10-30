#!/usr/bin/env bash
# No root/network/services: compare independent node snapshots and reject forged receipts.
set -u
cd "$(dirname "$0")/.." || exit 1
source ./veiltrium.sh
set +eE
trap - ERR
T="$(mktemp -d)"
trap 'rm -rf "${T}"' EXIT
FAIL=0
check() { if [[ "$1" == "$2" ]]; then echo "ok   $3"; else echo "FAIL $3: $1 != $2"; FAIL=1; fi; }
STATE_DIR="${T}/state"; HY2_CERT="${T}/hy.crt"; TT_DIR="${T}/tt"; MTS_RECORDS="${T}/mts"
JSON_OUT="${T}/result.json"
PROBE_KEY="$(printf 'ab%.0s' {1..32})"
PUBLIC_IP=203.0.113.5
H_AUTH=userpass; H_PASSWORD=main-password; H_SNI=hy.example; H_MASQ=auto; HY2_PORT=443
R_SITE=reality.example; R_PRIV=private; R_PUB=public; R_UUID=uuid; R_SID=short; REALITY_PORT=443
T_USER=main; T_PASS=tt-password; T_SNI=tt.example; TT_PORT=8443
CL_NAMES=(alice); CL_UUID=(alice-uuid); CL_HPASS=(alice-password); CL_TPASS=(alice-tt)
CL_LIMIT=(500000); CL_EXPIRES=(2027-01-01); CL_RESET=(monthly); CL_STATE=(active); CL_REASON=('')
STANDBY=(203.0.113.5)
fp="$(standby_fingerprint)"
receipt="$(standby_receipt)"
standby_receipt_valid "${receipt}"; check $? 0 'a shared-node receipt authenticates'
PUBLIC_IP=198.51.100.9; N_NAME=PL; R_ADMIN_UUID=local-admin; H_STATS_PORT=29999
check "$(standby_fingerprint)" "${fp}" 'address, label, panel account and stats ports may differ'
standby_verify "${receipt}"
check "$(jq -r '.servers[0].state' "${JSON_OUT}")" matching 'matching snapshot is recorded'
check "$(stat -c %a "${STATE_DIR}/standby/203.0.113.5.receipt")" 600 'stored receipt is root-only'
before="$(cat "${STATE_DIR}/standby/203.0.113.5.receipt")"
CL_HPASS=(new-password)
check "$(standby_status_json | jq -r '.servers[0].state')" changed 'credential reset immediately invalidates the match'
CL_HPASS=(alice-password); CL_STATE=(disabled); CL_REASON=(manual)
check "$(standby_status_json | jq -r '.servers[0].state')" changed 'manual disable differs'
CL_STATE=(active); CL_REASON=(''); CL_LIMIT=(600000)
check "$(standby_status_json | jq -r '.servers[0].state')" changed 'limit changes differ'
CL_LIMIT=(500000); CL_NAMES=(); CL_UUID=(); CL_HPASS=(); CL_TPASS=()
check "$(standby_status_json | jq -r '.servers[0].state')" changed 'client removal differs'
CL_NAMES=(alice); CL_UUID=(alice-uuid); CL_HPASS=(alice-password); CL_TPASS=(alice-tt)
tampered="${receipt/203.0.113.5/203.0.113.6}"
(standby_verify "${tampered}") >"${T}/error" 2>&1; check $? 1 'changing the address without resigning is rejected'
check "$(cat "${STATE_DIR}/standby/203.0.113.5.receipt")" "${before}" 'invalid input preserves previous receipt'
PUBLIC_IP=203.0.113.6
foreign="$(standby_receipt)"
(standby_verify "${foreign}") >"${T}/error" 2>&1; check $? 1 'valid receipt for an unconfigured address is rejected'
line="vt-standby-1|203.0.113.5|$(( $(date +%s) - 86401 ))|${fp}"
old="${line}|$(hmac_sha256_hex "${PROBE_KEY}" "${line}")"
(standby_verify "${old}") >"${T}/error" 2>&1; check $? 1 'expired snapshot is refused on import'
printf '%s' "${old}" > "${STATE_DIR}/standby/203.0.113.5.receipt"
check "$(standby_status_json | jq -r '.servers[0].state')" stale 'previously stored snapshot expires'
line="vt-standby-1|203.0.113.5|$(( $(date +%s) + 601 ))|${fp}"
future="${line}|$(hmac_sha256_hex "${PROBE_KEY}" "${line}")"
(standby_verify "${future}") >"${T}/error" 2>&1; check $? 1 'future timestamp is refused'
PROBE_KEY="$(printf 'cd%.0s' {1..32})"
check "$(standby_status_json | jq -r '.servers[0].state')" unverified 'key rotation invalidates cached authentication'
for bad in '' '../x' "${receipt};id" "${receipt}"$'\nstatus'; do
    standby_receipt_valid "${bad}"; check $? 1 'malformed receipt rejected'
done
if (( FAIL )); then exit 1; fi
echo 'standby state tests passed'
