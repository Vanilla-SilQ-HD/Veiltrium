#!/usr/bin/env bash
# Unit tests for the maintenance additions of veiltrium.sh: --uninstall (path lists, the
# nftables.conf edit), the audit log, --reset-client and the helper's request list, the
# server load in --status. No network and no root needed; jq is required.
# shellcheck disable=SC2034,SC2319,SC2164
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

# ---- uninstall: the lists ----------------------------------------------------------
paths="$(uninstall_paths)"
kept="$(uninstall_kept_paths)"
in_list() { grep -Fxq -- "$1" <<<"$2"; }   # item, list

# every unit the script writes or enables by a literal name is stopped and removed
miss=""
for u in $(grep -oE 'veiltrium-[a-z-]+(@)?\.(service|timer|socket)' veiltrium.sh | sort -u); do
    [[ " ${UNINSTALL_UNITS[*]} ${UNINSTALL_RUNTIME_UNITS[*]} " == *" ${u} "* ]] || miss+=" ${u}"
done
check "${miss}" "" "uninstall: every veiltrium-* unit named in the script is in the unit lists"
miss=""
for u in hysteria-server.service xray.service trusttunnel.service; do
    [[ " ${UNINSTALL_UNITS[*]} " == *" ${u} "* ]] || miss+=" ${u}"
done
check "${miss}" "" "uninstall: the three proxy units are in the list"
# unit files written under /etc/systemd/system by a literal name
miss=""
for u in $(grep -oE '/etc/systemd/system/[A-Za-z0-9@.-]+\.(service|timer|socket)' veiltrium.sh | grep -v 'hy2-' | sort -u); do   # hy2-*: the old names, removed by remove_old_names
    in_list "${u}" "${paths}" || miss+=" ${u}"
done
check "${miss}" "" "uninstall: every unit file written under /etc/systemd/system is in the path list"
# the russia-check units are written as veiltrium-russia-check.${u}
for u in service timer; do
    in_list "/etc/systemd/system/veiltrium-russia-check.${u}" "${paths}"
    check $? 0 "uninstall: veiltrium-russia-check.${u} is in the path list"
done
# the runtime ones (systemd-run, trial) are stopped and their files removed
for u in veiltrium-watchdog.timer veiltrium-watchdog.service veiltrium-trial-end.timer veiltrium-trial-end.service; do
    [[ " ${UNINSTALL_RUNTIME_UNITS[*]} " == *" ${u} "* ]]; check $? 0 "uninstall: runtime unit ${u} is stopped"
done
in_list "${TRIAL_DROPIN}" "${paths}"; check $? 0 "uninstall: the trial drop-in is removed"
in_list "${RUN_DIR}" "${paths}"; check $? 0 "uninstall: the trial run directory is removed"

# binaries and directories named by the script's own variables
for p in "${HY2_BIN}" "${XRAY_BIN}" "${TT_BIN}" "${PANEL_BIN}" "${SCANNER_BIN}" "${RECOVER_BIN}" \
         "${HY2_DIR}" "${XRAY_DIR}" "${TT_DIR}" "${SCANNER_DIR}" "${PANEL_ETC}" "${STATE_DIR}" "${PANEL_LIB}" \
         "${VT_ROOT_DIR}" /etc/needrestart/conf.d/50-veiltrium.conf "${LOG_FILE}"; do
    in_list "${p}" "${paths}"; check $? 0 "uninstall: ${p} is in the path list"
done
# the users
[[ " ${UNINSTALL_USERS[*]} " == *" hysteria "* && " ${UNINSTALL_USERS[*]} " == *" xray "* \
   && " ${UNINSTALL_USERS[*]} " == *" trusttunnel "* && " ${UNINSTALL_USERS[*]} " == *" veiltrium-panel "* ]]
check $? 0 "uninstall: the four service users are listed"
# every useradd in the script has its user in the list
miss=""
for u in $(grep -oE 'useradd [^|]* (hysteria|xray|trusttunnel|veiltrium-panel)$' veiltrium.sh | awk '{print $NF}' | sort -u); do
    [[ " ${UNINSTALL_USERS[*]} " == *" ${u} "* ]] || miss+=" ${u}"
done
check "${miss}" "" "uninstall: every user the script creates is removed"

# never SSH, fail2ban, updates, journald, sysctl, the audit log
bad=""
while IFS= read -r p; do
    case "${p}" in
        /etc/ssh*|/etc/fail2ban*|/etc/apt*|*unattended-upgrades*|/etc/sysctl.d*|/etc/systemd/journald*|/etc/modules-load.d*|\
        /etc/default*|/etc/logrotate.d*|/etc/nftables.conf|/etc/nftables.conf.orig-*|/var/log/veiltrium|/var/log/veiltrium/*|/root/.ssh*) bad+=" ${p}" ;;
    esac
    uninstall_protected "${p}" && bad+=" protected:${p}"
    [[ "${p}" == /*/* && "${p}" != *..* && "${p}" != *" "* ]] || bad+=" shape:${p}"
done <<<"${paths}"
check "${bad}" "" "uninstall: no path of the list touches SSH, fail2ban, updates, sysctl, journald or the audit log"
overlap=""
while IFS= read -r p; do in_list "${p}" "${paths}" && overlap+=" ${p}"; done <<<"${kept}"
check "${overlap}" "" "uninstall: nothing is both removed and kept"
miss=""
for p in /etc/ssh/sshd_config.d/00-veiltrium-hardening.conf /etc/fail2ban/jail.d/veiltrium-sshd.local \
         /etc/apt/apt.conf.d/52veiltrium-unattended-upgrades /etc/systemd/journald.conf.d/50-veiltrium.conf \
         /etc/sysctl.d/99-zz-veiltrium-hardening.conf; do
    in_list "${p}" "${kept}" || miss+=" ${p}"
    grep -Fq -- "${p}" veiltrium.sh || miss+=" (not in script: ${p})"
done
check "${miss}" "" "uninstall: the kept list names the hardening files the installer writes"
uninstall_protected /etc/ssh/sshd_config; check $? 0 "uninstall_protected: /etc/ssh/sshd_config"
uninstall_protected /etc/hysteria; check $? 1 "uninstall_protected: /etc/hysteria is not protected"

# uninstall_rm refuses unsafe arguments and removes only what it is given
mkdir -p "${T}/d/x"; touch "${T}/d/x/f"
uninstall_rm "" >/dev/null 2>&1; uninstall_rm "/" >/dev/null 2>&1; uninstall_rm "/etc" >/dev/null 2>&1
uninstall_rm "${T}/d/../d" >/dev/null 2>&1
check "$([[ -f "${T}/d/x/f" ]] && echo kept)" kept "uninstall_rm: empty, root, one-component and .. arguments remove nothing"
uninstall_rm "${T}/d/x" >/dev/null 2>&1
check "$([[ -e "${T}/d/x" ]] && echo exists || echo gone)" gone "uninstall_rm: removes a listed path"
check "$([[ -d "${T}/d" ]] && echo kept)" kept "uninstall_rm: its parent stays"

# the confirmation: VT_YES=uninstall passes; anything else without a terminal refuses
check "$(VT_YES=uninstall uninstall_confirm >/dev/null 2>&1; echo $?)" 0 "uninstall_confirm: VT_YES=uninstall"
if command -v setsid >/dev/null 2>&1; then   # a new session has no controlling terminal: /dev/tty cannot be opened
    check "$(VT_YES=yes timeout 20 setsid -w bash -c 'source ./veiltrium.sh; set +eE; trap - ERR; LIGHT=1; uninstall_confirm' </dev/null >/dev/null 2>&1; echo $?)" 1 "uninstall_confirm: VT_YES=yes and no terminal refuses"
fi

# ---- the nftables.conf edit keeps every other line ----------------------------------
cat > "${T}/nftables.conf" <<EOF
#!/usr/sbin/nft -f
# veiltrium: server firewall.
# Only our own table is recreated; rules of fail2ban and other services are left alone.

table inet veiltrium
delete table inet veiltrium

table inet veiltrium {
    set ssh_ports {
        type inet_service
        elements = { 22 }
    }
    chain input {
        type filter hook input priority filter; policy drop;
        tcp dport @ssh_ports accept
    }
}
table inet mine {
    chain input { type filter hook input priority 0; policy accept; }
}
# my own comment mentioning veiltrium in the middle
include "/etc/mine/extra.nft"
include "${SCANNER_FILE}"
EOF
nft_conf_strip < "${T}/nftables.conf" > "${T}/stripped"
check "$(grep -c 'inet veiltrium\|scanners.nft\|^# veiltrium:\|Only our own' "${T}/stripped")" 0 "nft strip: the veiltrium table, comments and the scanner include are gone"
check "$(grep -c 'table inet mine' "${T}/stripped")" 1 "nft strip: another table stays"
check "$(grep -c 'include "/etc/mine/extra.nft"' "${T}/stripped")" 1 "nft strip: another include stays"
check "$(grep -c '^# my own comment' "${T}/stripped")" 1 "nft strip: a user comment stays"
check "$(grep -c 'ssh_ports\|policy drop' "${T}/stripped")" 0 "nft strip: nothing of the table body is left"
check "$(sed -n 1p "${T}/stripped")" '#!/usr/sbin/nft -f' "nft strip: the first line stays"
# a file made of our parts only has no meaningful line left
sed -n '1,/^}$/p' "${T}/nftables.conf" | nft_conf_strip > "${T}/only"
grep -qvE '^[[:space:]]*(#.*)?$' "${T}/only"; check $? 1 "nft strip: a file with only our parts ends up without rules"
# no include line, no table: unchanged
printf 'table inet x {\n}\n' > "${T}/plain"
check "$(nft_conf_strip < "${T}/plain" | cmp - "${T}/plain" && echo same)" same "nft strip: a foreign file is unchanged"

# ---- audit log -------------------------------------------------------------------------
line="$(VEILTRIUM_SOURCE=panel audit_line add-client alice ok)"
[[ "${line}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\ source=panel\ action=add-client\ target=alice\ result=ok$ ]]
check $? 0 "audit line: format (${line})"
check "$(VEILTRIUM_SOURCE=evil audit_line install "" ok | cut -d' ' -f2-)" "source=cli action=install target=- result=ok" "audit line: unknown source becomes cli, empty target -"
check "$(audit_line remove-client 'a b;rm' failed | cut -d' ' -f4)" "target=-" "audit line: a target with odd characters is not logged"
check "$(audit_line import 'node 1.enc' ok | cut -d' ' -f4)" "target=-" "audit line: a spaced target is not logged"
check "$(audit_line export node-1.enc rolled-back | cut -d' ' -f4-5)" "target=node-1.enc result=rolled-back" "audit line: file name and rolled-back result"
check "$(audit_line install '' weird | cut -d' ' -f5)" "result=failed" "audit line: an unknown result is failed"
audit_line 'Bad Action' x ok >/dev/null 2>&1; check $? 1 "audit line: an invalid action is refused"
# a secret passed as a target never reaches the log
secret="$(printf 'a%.0s' {1..48})"
check "$(audit_line add-client "pw:${secret}" ok | grep -c "${secret}")" 0 "audit line: no secret"

AUDIT_DIR="${T}/log/veiltrium"; AUDIT_LOG="${AUDIT_DIR}/audit.log"
audit_append add-client alice ok
audit_append reset-client alice rolled-back
check "$(wc -l < "${AUDIT_LOG}" | tr -d ' ')" 2 "audit_append: two lines"
check "$(stat -c %a "${AUDIT_LOG}")" 640 "audit log mode 640"
check "$(stat -c %a "${AUDIT_DIR}")" 750 "audit directory mode 750"
JSON_OUT=""
check "$(audit_show 1 | grep -c 'action=reset-client')" 1 "audit_show: the last line"
JSON_OUT="${T}/audit.json"
audit_show 5
check "$(jq -r 'length' "${T}/audit.json")" 2 "audit_show --json: an array of two entries"
check "$(jq -r '.[1] | "\(.source) \(.action) \(.target) \(.result)"' "${T}/audit.json")" "cli reset-client alice rolled-back" "audit_show --json: fields"
rm -f "${AUDIT_LOG}"
audit_show 5; check "$(jq -c . "${T}/audit.json")" "[]" "audit_show --json: no log is an empty array"
JSON_OUT=""

# ---- reset-client ----------------------------------------------------------------------
out="$(bash veiltrium.sh --reset-client main 2>&1)"; rc=$?
check "${rc}" 1 "--reset-client main is refused"
[[ "${out}" == *VT_RECONFIGURE=1* ]]; check $? 0 "--reset-client main: the message names VT_RECONFIGURE=1"
out="$(bash veiltrium.sh --reset-client 2>&1)"; check "$?" 1 "--reset-client without a name is refused"
for n in main 'Bad' 'a b' '../x' '' 'x;y' "$(printf 'a%.0s' {1..40})"; do
    if [[ "${n}" =~ ${CLIENT_RE} && "${n}" != "main" ]]; then check accepted refused "name '${n}' refused"; else check refused refused "name '${n}' refused"; fi
done
grep -q 'clients_change reset' veiltrium.sh; check $? 0 "--reset-client goes through clients_change"

# ---- the root helper -------------------------------------------------------------------
cat > "${T}/fake.sh" <<'EOF'
#!/bin/bash
printf '{"args":"%s","source":"%s"}\n' "$*" "${VEILTRIUM_SOURCE:-}"
EOF
SCRIPT_PATH="${T}/fake.sh"
helper() { printf '%s\n' "$1" | helper_main 2>/dev/null; }
out="$(helper 'reset-client bob')"
[[ "${out}" == *'"args":"--reset-client bob --json -"'* && "${out}" == *'"source":"panel"'* && "${out}" == *'::exit 0'* ]]
check $? 0 "helper: reset-client NAME runs --reset-client NAME with VEILTRIUM_SOURCE=panel"
for req in 'reset-client main' 'reset-client' 'reset-client Bad' 'reset-client ../x' 'reset-client a b' 'uninstall' 'audit' 'reset-client bob; id'; do
    out="$(helper "${req}")"
    [[ "${out}" == *'request refused'* && "${out}" == *'::exit 2'* && "${out}" != *'"args"'* ]]
    check $? 0 "helper refuses '${req}'"
done
out="$(helper 'add-client bob')"; [[ "${out}" == *'"args":"--add-client bob --json -"'* ]]; check $? 0 "helper: add-client still works"

# ---- the server load in --status ---------------------------------------------------------
load="$(server_load_json)"
check "$(jq -r '[.cpus >= 1, .load.m1 >= 0, .memory_mb.total > 0, .memory_mb.used <= .memory_mb.total, .disk_mb.total > 0, .disk_mb.used <= .disk_mb.total] | all' <<<"${load}")" true "server_load_json: load, memory and disk are numbers that make sense"
grep -q 'resources: \$resources' veiltrium.sh; check $? 0 "status_json carries the resources"

if (( FAIL )); then echo "maintenance unit tests FAILED"; exit 1; fi
echo "maintenance unit tests passed"
