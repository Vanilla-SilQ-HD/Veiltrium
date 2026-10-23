#!/usr/bin/env bash
# =============================================================================
#  Veiltrium - Secure Multi-Protocol VPN Deployment
#  https://github.com/Vanilla-SilQ-HD/Veiltrium
#
#  veiltrium.sh: self-contained, hardened installer for Hysteria 2,
#  VLESS Reality (Xray) and TrustTunnel on a fresh Ubuntu 26.04 server. No
#  third-party panels or install scripts: only the official release binaries,
#  SHA-256 pinned.
#
#  Nodes installed by the earlier hy2-secure-install.sh move to the Veiltrium
#  names on their first run of this script: state, keys, passwords and links are
#  kept; HY2_RECONFIGURE and HY2_AUTO_REBOOT still work as old names.
#
#  One run as root, no questions asked:
#    1. upgrades the system and enables automatic security updates;
#    2. hardens SSH WITHOUT disabling password login;
#    3. sets up an nftables firewall: only SSH and the proxy ports are reachable;
#    4. enables fail2ban and kernel hardening;
#    5. installs the proxies as separate users in a systemd sandbox;
#    6. blocks the proxies from reaching the server itself and private networks;
#    7. picks the Reality mask site by measured, reproducible checks with a real
#       Reality client (see "Reality mask site selection" below);
#    8. configures every protocol, tests the connections and prints the links.
#
#  Each protocol keeps its own TLS identity, saved between runs:
#    - VLESS Reality: target/serverNames = a real third-party HTTPS site;
#    - Hysteria 2: its own self-signed certificate, pinned by the clients;
#    - TrustTunnel: its own self-signed certificate, embedded in the tt:// link.
#  Changing the Reality site never touches the Hysteria or TrustTunnel
#  certificates, and no secret (password, key, UUID, shortId) changes unless
#  VT_RECONFIGURE=1 is given.
#
#  Re-running is safe: passwords, keys, certificates and the chosen sites are
#  kept. Settings given as variables (HY2_SNI, TT_SNI, HY2_MASQUERADE_URL,
#  REALITY_CANDIDATES) are saved and stay in effect on later runs.
#
#  Modes:
#    bash veiltrium.sh                     install / update / repair
#    bash veiltrium.sh --update            download the newest release, check it, run it as an install
#    bash veiltrium.sh --check-update      is a newer release out? (no changes)
#
#  Reality site:
#    bash veiltrium.sh --reselect-reality  re-evaluate the Reality site
#                                                   (only the VLESS sni changes)
#    bash veiltrium.sh --dry-run           what --reselect-reality would do; no changes
#    bash veiltrium.sh --trial-reality SITE[,SITE]   temporary extra Reality
#                                                   names for a probe from home; auto-revert
#    bash veiltrium.sh --trial-stop        end a Reality trial now
#
#  Clients:
#    bash veiltrium.sh --add-client NAME   a new client: own credentials for all protocols
#    bash veiltrium.sh --remove-client NAME   revoke a client
#    bash veiltrium.sh --reset-client NAME new credentials for a client (the old ones stop working)
#    bash veiltrium.sh --set-client NAME [--limit SIZE|none] [--expires YYYY-MM-DD|none] [--reset none|daily|weekly|monthly]
#                                          traffic limit, expiry date and periodic reset of an added client
#    bash veiltrium.sh --disable-client NAME   stop accepting a client (kept; --enable-client brings it back)
#    bash veiltrium.sh --enable-client NAME    accept a disabled client again
#    bash veiltrium.sh --enforce           apply limits and expiry now (the traffic timer does it every 5 minutes)
#    bash veiltrium.sh --list-clients      the clients of this node
#    bash veiltrium.sh --show-client NAME  connection details of a client (main: the first one)
#    bash veiltrium.sh --qr NAME           terminal QR codes of a client's links (main: the first one)
#    bash veiltrium.sh --traffic           traffic per client (up/down, last seen); --json - for JSON
#    bash veiltrium.sh --traffic-reset     set all traffic counters to zero
#
#  Checks and alerts:
#    bash veiltrium.sh --status --json -   a fast overview as JSON (no tests, no secrets)
#    bash veiltrium.sh --diagnose          check the node; no changes
#    bash veiltrium.sh --check-russia      can Russian networks reach this server? (Globalping)
#    bash veiltrium.sh --import-mts FILE   import results of tools/keenetic-vpn-probe.sh (optional)
#    bash veiltrium.sh --test-alert        send a test message to the alert channels (ALERT_*)
#    bash veiltrium.sh --audit [N]         the last N (default 50) lines of the audit log
#
#  The node itself:
#    bash veiltrium.sh --panel-password    a new web panel password (signs everybody out)
#    bash veiltrium.sh --export FILE      pack this node (all secrets, encrypted with a passphrase)
#    bash veiltrium.sh --import FILE       install on a new server with the same secrets (links differ
#                                                   only by the address)
#    bash veiltrium.sh --uninstall         remove Veiltrium from this server (asks to type "uninstall";
#                                                   SSH, fail2ban, updates and sysctl hardening stay)
#    bash veiltrium.sh --help
#
#  Standby servers: deploy a second VPS from an export of this node, then run
#  STANDBY_HOSTS=<its IPv4>[,more] bash veiltrium.sh here (saved; "none" clears). Every link,
#  sing-box outbound (with a urltest group) and the AWG Manager group then also list the
#  standby servers (same ports assumed). Re-export after adding or removing clients.
#
#  To regenerate everything:  VT_RECONFIGURE=1 bash veiltrium.sh
#  Without VLESS Reality:     REALITY_ENABLE=0 bash veiltrium.sh
# =============================================================================
if [ -z "${BASH_VERSION:-}" ]; then
    echo "Run it with bash:  bash $0"
    exit 1
fi
set -Eeuo pipefail
umask 022

SCRIPT_VERSION="2026-10-21"

# ---- Pinned versions (change only together with the checksums) -------------
HY2_VERSION="v2.13.0"
HY2_SHA256_AMD64="907ba8c9693edb104b20582681fb7dc15639d5b64a9cbb616a7b539190a86691"
HY2_SHA256_ARM64="a68a61a84452ca250ce0368202521965ca9cc9d801a404f1dc9008ac6cf677a7"
# Xray (XTLS/Xray-core) for VLESS Reality. Do not move to 26.9.8+ before it is
# checked with sing-box clients: those versions reject a ClientHello without
# X25519MLKEM768, which sing-box clients do not send by default.
XRAY_VERSION="v26.3.27"
XRAY_SHA256_AMD64="23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae"
XRAY_SHA256_ARM64="4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c"
# TrustTunnel endpoint (TrustTunnel/TrustTunnel), latest stable release
TT_VERSION="v1.1.0"
TT_SHA256_AMD64="91c2ea3db7416a01b5258a4c047ec22890490bc55e1b194206031aa75144f0e7"
TT_SHA256_ARM64="c2aee17a1ced349283cba4775202e2baba053b8ea835d4cc23dc67d16c6b9686"

# Veiltrium web panel: this repository's own release, SHA-256 pinned like the proxies.
# Empty sums: no release pinned yet (the panel is skipped unless PANEL_BINARY is given).
PANEL_VERSION="panel-v0.1.7"
PANEL_SHA256_AMD64="05de4e5105b7f9d7fb55b47cb4ee9447db5c2a70478e8cf351988a4e9f87bcf0"
PANEL_SHA256_ARM64="656edd1808f89eeb2ae0a079f1661bb7c3c56e7904263ee090f624f256a126a6"

# ---- Settings (can be overridden with environment variables) ---------------
HY2_PORT="${HY2_PORT:-443}"
# Reality mask site candidates. All checked on 2026-10-07: reachable from
# Russia, TLS 1.3 + h2 + X25519, and a real Reality handshake works with them
# (www.microsoft.com, www.playstation.com and www.hp.com failed and are left out).
# The order only breaks ties: the site is chosen by measurements (see below).
DEFAULT_CANDIDATES="www.amazon.com www.yahoo.com www.samsung.com www.sony.com www.aliexpress.com www.nvidia.com www.intel.com www.lenovo.com www.asus.com www.toyota.com"
# Explicit list (saved for later runs; "default" goes back to the built-in list).
# MASK_SITES is the old name of the same setting.
REALITY_CANDIDATES="${REALITY_CANDIDATES:-${MASK_SITES:-}}"
REALITY_SNI="${REALITY_SNI:-}"                 # one fixed Reality site (checked before use)
REALITY_RESELECT="${REALITY_RESELECT:-0}"      # 1: re-evaluate the Reality site (same keys)
HY2_SNI="${HY2_SNI:-}"                         # Hysteria SNI; saved; "auto": a candidate other than the Reality site
HY2_MASQUERADE_URL="${HY2_MASQUERADE_URL:-}"   # saved; "auto": https://<Hysteria SNI>
TT_SNI="${TT_SNI:-}"                           # TrustTunnel hostname; saved; "auto": a candidate other than Reality/Hysteria
REALITY_ENABLE_GIVEN="${REALITY_ENABLE:+1}"    # given explicitly: wins over an imported node's setting
REALITY_ENABLE="${REALITY_ENABLE:-1}"          # 0: no VLESS Reality
REALITY_PORT_GIVEN="${REALITY_PORT:+1}"       # given explicitly: change the port; else keep the node's
REALITY_PORT="${REALITY_PORT:-443}"
REALITY_FP="${REALITY_FP:-chrome}"             # TLS client fingerprint (uTLS)
TT_ENABLE_GIVEN="${TT_ENABLE:+1}"
TT_ENABLE="${TT_ENABLE:-1}"                    # 0: no TrustTunnel
TT_PORT_GIVEN="${TT_PORT:+1}"
TT_PORT="${TT_PORT:-8443}"                     # TrustTunnel listens on TCP and UDP on this port
PUBLIC_IP="${PUBLIC_IP:-}"                     # empty: detected automatically
# Node name in client apps: "Veiltrium-<NODE_NAME>". Saved; empty on a new node: the
# server's country code (e.g. PL); "auto": detect again; "none": just "Veiltrium".
NODE_NAME="${NODE_NAME:-}"
# Standby servers (comma-separated public IPv4, max 3; "none" clears; saved): copies of this node
# on the same ports, added to every client link/config so clients switch if this address is blocked.
STANDBY_HOSTS="${STANDBY_HOSTS:-}"
GLOBALPING="${GLOBALPING:-}"                   # 1 (default, saved): check from Russian networks that the server's
                                               # address answers (Globalping probes; the address is sent to them); 0: off
# Domains blocked in Russia by the RKN (curated, without sites that only geoblock Russians):
# a blocked name is never chosen as the Reality site or a server name.
RU_BLOCKLISTS="${RU_BLOCKLISTS:-https://raw.githubusercontent.com/itdoginfo/allow-domains/main/Categories/block.lst}"
PANEL_ENABLE="${PANEL_ENABLE:-1}"              # 0: no web panel
PANEL_PORT_GIVEN="${PANEL_PORT:+1}"             # given explicitly: change the port; else keep the node's
PANEL_PORT="${PANEL_PORT:-2096}"               # the panel listens on 127.0.0.1 only (SSH tunnel)
PANEL_BINARY="${PANEL_BINARY:-}"               # a local panel binary instead of the release (tests)
PANEL_VPN="${PANEL_VPN:-}"                     # 1 (default, saved): the panel also through VLESS Reality, with a
                                               # separate admin profile (no new open port); 0: SSH tunnel only
SCANNER_BLOCK="${SCANNER_BLOCK:-1}"            # 1: proxy ports stay silent for known scanner networks
VT_RECONFIGURE="${VT_RECONFIGURE:-${HY2_RECONFIGURE:-0}}"   # 1: new passwords, keys and certificates
VT_AUTO_REBOOT="${VT_AUTO_REBOOT:-${HY2_AUTO_REBOOT:-1}}"   # 1: a NEW node reboots in a minute if updates require it
AUTO_REBOOT_TIME="${AUTO_REBOOT_TIME:-01:30}"
MTS_MAX_AGE_DAYS="${MTS_MAX_AGE_DAYS:-14}"     # older home-network probe results are ignored
TRIAL_MINUTES="${TRIAL_MINUTES:-30}"

LOG_FILE="/var/log/veiltrium-install.log"
VT_ROOT_DIR="/root/veiltrium"                  # what root reads: client details, probe profile, panel password
CLIENT_FILE="${VT_ROOT_DIR}/client.txt"
PROBE_PROFILE="${VT_ROOT_DIR}/probe.env"
HY2_BIN="/usr/local/bin/hysteria"
HY2_DIR="/etc/hysteria"
HY2_CONFIG="${HY2_DIR}/config.yaml"
HY2_CERT="${HY2_DIR}/server.crt"
HY2_KEY="${HY2_DIR}/server.key"
HY2_STATE="${HY2_DIR}/node.env"
XRAY_BIN="/usr/local/bin/xray"
XRAY_DIR="/usr/local/etc/xray"
XRAY_STATE="${XRAY_DIR}/reality.env"
TT_BIN="/usr/local/bin/trusttunnel_endpoint"
TT_DIR="/etc/trusttunnel"
TT_STATE="${TT_DIR}/node.env"
SCANNER_DIR="/etc/veiltrium"
SCANNER_FILE="${SCANNER_DIR}/scanners.nft"
SCANNER_BIN="/usr/local/sbin/veiltrium-scanner-block"
CANDIDATES_FILE="${SCANNER_DIR}/reality-candidates"
PROBE_ENV="${SCANNER_DIR}/probe.env"           # key that authenticates home-network probe results
NODE_ENV="${SCANNER_DIR}/node.env"             # N_NAME: the saved node name
CLIENTS_DIR="${SCANNER_DIR}/clients"           # added clients: <name>.env with their credentials
CLIENT_FILES_DIR="${VT_ROOT_DIR}/clients"           # their connection details: <name>.txt
STATE_DIR="/var/lib/veiltrium"
REPORT_FILE="${STATE_DIR}/report.json"
SELECTION_FILE="${STATE_DIR}/reality-selection.json"
MTS_RECORDS="${STATE_DIR}/mts-records"
MTS_LAST_IMPORT="${STATE_DIR}/mts-last-import.json"
MTS_RUNS="${STATE_DIR}/mts-runs"
RUSSIA_FILE="${STATE_DIR}/russia.json"         # the last check from Russian networks (Globalping)
TRAFFIC_FILE="${STATE_DIR}/traffic.json"       # per-client traffic counters (see traffic_collect)
TRAFFIC_LOCK="/run/veiltrium-traffic.lock"     # its own lock: the timer and an install must not write at once
TXN_DIR="${STATE_DIR}/txn"                     # backups of changes in progress (see txn_begin)
ENFORCE_FAILED="${STATE_DIR}/enforce-failed"      # set while a timer-started --enforce runs; left behind if it fails
RECOVER_BIN="/usr/local/sbin/veiltrium-recover"
CLI_BIN="/usr/local/bin/veiltrium"            # the short command (cli_wrapper_text)
WATCHDOG_UNIT="veiltrium-watchdog"
RUN_DIR="/run/veiltrium-trial"
TRIAL_CONFIG="${RUN_DIR}/xray-trial.json"
TRIAL_ENV="${RUN_DIR}/trial.env"
TRIAL_END="${RUN_DIR}/trial-end.sh"
TRIAL_DROPIN_DIR="/run/systemd/system/xray.service.d"
TRIAL_DROPIN="${TRIAL_DROPIN_DIR}/50-veiltrium-trial.conf"
TRIAL_UNIT="veiltrium-trial-end"
TOTAL_STEPS=13
PANEL_BIN="/usr/local/bin/veiltrium-panel"
PANEL_LIB="/usr/local/lib/veiltrium"            # the copy of this script the panel helper runs
PANEL_ETC="/etc/veiltrium-panel"                # readable by the panel's group (the node's own state is not)
PANEL_AUTH="${PANEL_ETC}/auth"
PANEL_FILE="${VT_ROOT_DIR}/panel.txt"
HELPER_SOCK="/run/veiltrium/helper.sock"
AUDIT_DIR="/var/log/veiltrium"
AUDIT_LOG="${AUDIT_DIR}/audit.log"
LOGROTATE_FILE="/etc/logrotate.d/veiltrium"
AUDIT_ACTION=""; AUDIT_TARGET=""; AUDIT_ROLLBACK=0   # set once a mode that changes the node starts (see audit_append)

# ---- Output -----------------------------------------------------------------
# Project identification for people (terminal and install log only; never written
# into a server config). Client apps show the node as "Veiltrium-<NODE_NAME>" (LABEL).
banner() {
    printf '\nVeiltrium %s\nSecure Multi-Protocol VPN Deployment\nHysteria2 | VLESS Reality | TrustTunnel\n' "${SCRIPT_VERSION}"
}
LIGHT=0   # 1 in the maintenance modes: no install log
step() { printf '\n\033[1;36m[%s/%s] %s\033[0m\n' "$1" "${TOTAL_STEPS}" "$2"; }
info() { printf '    %s\n' "$*"; }
ok()   { printf '    \033[32m✔\033[0m %s\n' "$*"; }
warn() { printf '    \033[33m!\033[0m %s\n' "$*"; }
die()  {
    trap - ERR
    printf '\n\033[1;31m✖ ERROR: %s\033[0m\n' "$*" >&2
    if (( LIGHT == 0 )); then printf '  Full log: %s\n' "${LOG_FILE}" >&2; fi
    exit "${DIE_CODE:-1}"
}

DIE_CODE=""
TMPD=""
TEE_PID=""
CLIENT_PID=""
SERVER_PID=""
TXN_OPEN=()
TRIAL_STARTING=0
CLIENT_FILES_STALE=0
CHANGES=(); LINKS_CHANGED=(); ROLLBACKS=()
HAVE_PSP=0
# Added clients (sorted by name; see load_clients). The first client, "main", keeps
# the credentials in the protocol state files.
CL_NAMES=(); CL_UUID=(); CL_HPASS=(); CL_TPASS=(); CL_CREATED=()
# Optional limits of an added client: bytes per period ("" = none), last day (UTC, "" = never),
# period reset (none|daily|weekly|monthly), state (active|disabled) and why (manual|quota|expired).
CL_LIMIT=(); CL_EXPIRES=(); CL_RESET=(); CL_STATE=(); CL_REASON=()
CLIENT_LIMIT_MAX=1000000000000000
H_AUTH=""; HY2_AUTH_MAIN=""
# Loopback statistics endpoints of the proxies (traffic counters); empty on a node from before them.
H_STATS_PORT=""; H_STATS_SECRET=""; R_STATS_PORT=""; T_STATS_PORT=""
# The panel's VLESS profile (PANEL_VPN=1): its own UUID, only in the production config; empty = off.
R_ADMIN_UUID=""
PANEL_VPN_EMAIL="@panel"                       # never a client name (CLIENT_RE): the routing and statistics key
PANEL_VPN_SRC="127.0.0.2"                      # the source address of Xray's way to the panel (the firewall's key)
N_NAME=""; LABEL="Veiltrium"
N_STANDBY=""; STANDBY=(); STANDBY_ERR=""

# ---- Helpers ----------------------------------------------------------------
fetch() {
    curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --retry-delay 3 \
        --connect-timeout 15 --max-time 300 -o "$2" "$1"
}
sha_ok() { printf '%s  %s\n' "$2" "$1" | sha256sum -c --status -; }

# Value for a single-quoted YAML string
yaml_sq() { local q="'"; local s="${1//${q}/${q}${q}}"; printf "'%s'" "${s}"; }
# Value for a JSON string (without the quotes)
json_escape() { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; printf '%s' "${s}"; }
url_encode() {
    local LC_ALL=C raw="$1" out="" ch i
    for (( i = 0; i < ${#raw}; i++ )); do
        ch="${raw:i:1}"
        case "${ch}" in
            [a-zA-Z0-9.~_-]) out+="${ch}" ;;
            *) printf -v out '%s%%%02X' "${out}" "'${ch}" ;;
        esac
    done
    printf '%s' "${out}"
}

ms() { awk -v t="${1:-0}" 'BEGIN { printf "%d", t * 1000 + 0.5 }'; }
median() {
    printf '%s\n' "$@" | sort -n | awk '{ a[NR] = $1 }
        END { if (NR == 0) print 0; else if (NR % 2) print a[(NR + 1) / 2]; else printf "%d\n", (a[NR / 2] + a[NR / 2 + 1]) / 2 }'
}

is_public_ipv4() {
    local o='(0|[1-9][0-9]{0,2})'
    [[ "$1" =~ ^${o}\.${o}\.${o}\.${o}$ ]] || return 1
    local a=$((10#${BASH_REMATCH[1]})) b=$((10#${BASH_REMATCH[2]})) \
          c=$((10#${BASH_REMATCH[3]})) d=$((10#${BASH_REMATCH[4]}))
    (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1
    (( a != 0 && a != 10 && a != 127 && a < 224 )) || return 1
    (( a != 100 || b < 64 || b > 127 )) || return 1
    (( a != 169 || b != 254 )) || return 1
    (( a != 172 || b < 16 || b > 31 )) || return 1
    (( a != 192 || b != 168 )) || return 1
    (( a != 198 || (b != 18 && b != 19) )) || return 1
    return 0
}

# The server's public IPv4: the source address of the default route; an external
# lookup only if the server sits behind NAT. Prints nothing if nothing was found.
detect_public_ip() {
    local local_ip ext_ip
    local_ip="$(ip -4 route get 1.1.1.1 2>/dev/null \
        | awk '{for (i = 1; i < NF; i++) if ($i == "src") {print $(i + 1); exit}}' || true)"
    if is_public_ipv4 "${local_ip}"; then printf '%s' "${local_ip}"; return 0; fi
    ext_ip="$(curl -4 -fsS --max-time 8 --max-filesize 64 https://api.ipify.org 2>/dev/null | tr -d '[:space:]' || true)"
    if is_public_ipv4 "${ext_ip}"; then printf '%s' "${ext_ip}"; return 0; fi
    printf '%s' "${local_ip}"
}

detect_ssh_ports() {
    local p
    local -a found=()
    if [[ -n "${SSH_CONNECTION:-}" ]]; then
        found+=("$(awk '{print $4}' <<<"${SSH_CONNECTION}")")
    fi
    if command -v sshd >/dev/null 2>&1; then
        while read -r p; do found+=("${p}"); done < <(sshd -T 2>/dev/null | awk '$1=="port"{print $2}' || true)
    fi
    while read -r p; do found+=("${p}"); done < <(systemctl show ssh.socket -p Listen --value 2>/dev/null \
        | grep -oE ':[0-9]+ \(Stream\)' | grep -oE '[0-9]+' || true)
    while read -r p; do found+=("${p}"); done < <(ss -Htlnp 2>/dev/null \
        | awk '/"sshd/ {n = split($4, a, ":"); print a[n]}' || true)
    SSH_PORTS=()
    for p in "${found[@]}"; do
        [[ "${p}" =~ ^[0-9]{1,5}$ ]] || continue
        (( p >= 1 && p <= 65535 )) || continue
        [[ " ${SSH_PORTS[*]} " == *" ${p} "* ]] || SSH_PORTS+=("${p}")
    done
    if (( ${#SSH_PORTS[@]} == 0 )); then
        warn "Could not detect the SSH port; keeping the standard port 22 open."
        SSH_PORTS=(22)
    fi
}

DOMAIN_RE='^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
URL_RE='^https?://[^[:space:]'\''"]+$'

# Existing Hysteria node from a previous run. Sets H_PASSWORD, H_SNI, H_PORT,
# H_MASQ ("auto" or a URL; empty if none), H_AUTH (password|userpass; empty: a new node).
load_hy2_state() {
    H_PASSWORD=""; H_SNI=""; H_PORT=""; H_MASQ=""; H_AUTH=""; H_STATS_PORT=""; H_STATS_SECRET=""
    [[ "${VT_RECONFIGURE}" != "1" ]] || return 0
    [[ -e "${HY2_STATE}" || -e "${HY2_CONFIG}" ]] || return 0    # a new node
    local damaged=""
    if [[ -s "${HY2_STATE}" ]]; then
        # shellcheck disable=SC1090
        source "${HY2_STATE}"
    fi
    if [[ -z "${H_PASSWORD}" || ! "${H_SNI}" =~ ${DOMAIN_RE} || ! "${H_PORT}" =~ ^[0-9]{1,5}$ ]]; then
        damaged="${HY2_STATE}"
    elif [[ ! -s "${HY2_CERT}" || ! -s "${HY2_KEY}" ]] || \
         [[ "$(openssl x509 -in "${HY2_CERT}" -noout -pubkey 2>/dev/null)" != "$(openssl pkey -in "${HY2_KEY}" -pubout 2>/dev/null)" ]]; then
        damaged="${HY2_CERT} / ${HY2_KEY} (missing or not a pair)"
    fi
    if [[ -n "${damaged}" && ! -e "${CLIENT_FILE}" ]]; then
        damaged=""; H_PASSWORD=""; H_SNI=""; H_PORT=""; H_MASQ=""; H_AUTH=""; H_STATS_PORT=""; H_STATS_SECRET=""   # a first install that never finished: start over
    fi
    if [[ -n "${damaged}" ]]; then
        die "the Hysteria node is damaged (${damaged}); nothing was changed. New password and certificate (clients must be updated): VT_RECONFIGURE=1 bash $0"
    fi
    # Nodes from before 2026-10-09 have no H_MASQ: take what their config.yaml uses
    # ("auto" when it is https://<SNI>), so the first run of this version changes nothing.
    if [[ -z "${H_MASQ}" ]]; then
        local url
        url="$(sed -n "s/^    url: '\(.*\)'\$/\1/p" "${HY2_CONFIG}" 2>/dev/null | head -n 1 || true)"
        if [[ -n "${url}" && "${url}" != "https://${H_SNI}" && "${url}" =~ ${URL_RE} ]]; then H_MASQ="${url}"; fi
    fi
    if [[ "${H_MASQ}" != "auto" && ! "${H_MASQ}" =~ ${URL_RE} ]]; then H_MASQ="auto"; fi
    # Nodes from before 2026-10-13 have one shared password; they move to per-user
    # passwords (userpass) only when the first client is added.
    if [[ -n "${H_PASSWORD}" && "${H_AUTH}" != "userpass" ]]; then H_AUTH="password"; fi
    # Nodes from before the traffic counters have no statistics endpoint (the installer adds it).
    [[ "${H_STATS_PORT}" =~ ^[0-9]{1,5}$ ]] || H_STATS_PORT=""
    [[ "${H_STATS_SECRET}" =~ ^[0-9a-f]{48}$ ]] || H_STATS_SECRET=""
    if [[ -z "${H_STATS_PORT}" || -z "${H_STATS_SECRET}" ]]; then H_STATS_PORT=""; H_STATS_SECRET=""; fi
    return 0
}

# The Hysteria auth string of the main client: the password, or "main:<password>"
# once the node has per-user passwords. Sets HY2_AUTH_MAIN.
set_hy2_auth_main() {
    if [[ "${H_AUTH}" == "userpass" ]]; then HY2_AUTH_MAIN="main:${H_PASSWORD}"; else HY2_AUTH_MAIN="${H_PASSWORD}"; fi
    return 0
}

save_hy2_state() {
    install -m 600 /dev/null "${HY2_STATE}.new"
    printf 'H_PASSWORD=%q\nH_SNI=%q\nH_PORT=%q\nH_MASQ=%q\nH_AUTH=%q\n' \
        "${H_PASSWORD}" "${HY2_SNI}" "${HY2_PORT}" "${H_MASQ}" "${H_AUTH}" > "${HY2_STATE}.new"
    if [[ -n "${H_STATS_PORT}" && -n "${H_STATS_SECRET}" ]]; then
        printf 'H_STATS_PORT=%q\nH_STATS_SECRET=%q\n' "${H_STATS_PORT}" "${H_STATS_SECRET}" >> "${HY2_STATE}.new"
    fi
    mv -f "${HY2_STATE}.new" "${HY2_STATE}"
}

# Hysteria server config ($1 = file) from H_AUTH, H_PASSWORD, the clients, HY2_PORT and
# HY2_MASQ_URL. With one shared password the text is exactly what earlier versions wrote.
hy2_server_yaml() {
    local auth i
    # H_STATS_PORT / H_STATS_SECRET add the traffic statistics API on 127.0.0.1 (Hysteria v2.13.0:
    # GET /traffic with the secret as the Authorization header; ids are the user names, and "user"
    # with the shared-password auth).
    if [[ "${H_AUTH}" == "userpass" ]]; then
        auth="  type: userpass"$'\n'"  userpass:"$'\n'"    main: $(yaml_sq "${H_PASSWORD}")"
        for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
            if [[ "${CL_STATE[i]:-}" == "disabled" ]]; then continue; fi
            auth+=$'\n'"    $(yaml_sq "${CL_NAMES[i]}"): $(yaml_sq "${CL_HPASS[i]}")"
        done
    else
        auth="  type: password"$'\n'"  password: $(yaml_sq "${H_PASSWORD}")"
    fi
    cat > "$1" <<EOF
# veiltrium: Hysteria 2 server
listen: :${HY2_PORT}
tls:
  cert: ${HY2_CERT}
  key: ${HY2_KEY}
auth:
${auth}
masquerade:
  type: proxy
  proxy:
    url: $(yaml_sq "${HY2_MASQ_URL}")
    rewriteHost: true
EOF
    if [[ -n "${H_STATS_PORT}" && -n "${H_STATS_SECRET}" ]]; then
        printf 'trafficStats:\n  listen: 127.0.0.1:%s\n  secret: %s\n' "${H_STATS_PORT}" "$(yaml_sq "${H_STATS_SECRET}")" >> "$1"
    fi
}

# hysteria2:// share link. $1 = user ("" with one shared password), $2 = password,
# $3 = server (default: this node), $4 = link name (default: the node name).
# A user is written as user:password, as the Hysteria URI scheme defines it.
hy2_link() {
    local auth
    auth="$(url_encode "$2")"
    if [[ -n "$1" ]]; then auth="$(url_encode "$1"):${auth}"; fi
    printf 'hysteria2://%s@%s:%s/?sni=%s&insecure=1&pinSHA256=%s&pcs=%s#%s' "${auth}" "${3:-${HOST}}" "${HY2_PORT}" \
        "$(url_encode "${HY2_SNI}")" "${CERT_SHA}" "${CERT_SHA}" "$(url_encode "${4:-${LABEL}}")"
}

# ---- Node name and added clients ----------------------------------------------
NAME_RE='^[A-Za-z0-9]([A-Za-z0-9-]{0,14}[A-Za-z0-9])?$'
CLIENT_RE='^[a-z0-9][a-z0-9_-]{0,31}$'
# The panel helper's whole line for --set-client (one regex for the line: name, bytes or none, date or none, mode).
HELPER_SET_RE='^set-client ([a-z0-9][a-z0-9_-]{0,31}) limit=(none|[0-9]{1,16}) expires=(none|[0-9]{4}-[0-9]{2}-[0-9]{2}) reset=(none|daily|weekly|monthly)$'

# The saved node name. Sets N_NAME (may be empty), N_SAVED (1: a choice was saved) and LABEL.
load_node_name() {
    N_NAME=""; N_SAVED=0; N_GLOBALPING=""; N_STANDBY=""; N_PANEL_VPN=""
    if [[ -s "${NODE_ENV}" ]]; then
        # shellcheck disable=SC1090
        source "${NODE_ENV}"
        # a failed country lookup saves no name: it is tried again on the next run
        if grep -q '^N_NAME=' "${NODE_ENV}"; then N_SAVED=1; fi
    fi
    [[ -z "${N_NAME}" || "${N_NAME}" =~ ${NAME_RE} ]] || N_NAME=""
    LABEL="Veiltrium${N_NAME:+-${N_NAME}}"
    # GLOBALPING: explicit setting, else the saved one, else on
    if [[ -z "${GLOBALPING}" ]]; then GLOBALPING="${N_GLOBALPING:-1}"; fi
    [[ "${GLOBALPING}" == "0" || "${GLOBALPING}" == "1" ]] || GLOBALPING=1
    # PANEL_VPN: explicit setting, else the saved one, else on
    if [[ -z "${PANEL_VPN}" ]]; then PANEL_VPN="${N_PANEL_VPN:-1}"; fi
    [[ "${PANEL_VPN}" == "0" || "${PANEL_VPN}" == "1" ]] || PANEL_VPN=1
    # STANDBY_HOSTS: explicit setting ("none" clears), else the saved list, else none
    if [[ -n "${STANDBY_HOSTS}" ]]; then N_STANDBY="${STANDBY_HOSTS}"; fi
    standby_parse "${N_STANDBY}" || die "${STANDBY_ERR}"
    N_STANDBY="$(IFS=,; printf '%s' "${STANDBY[*]:-}")"
    return 0
}

# Parses a STANDBY_HOSTS list ("none" or empty = no standby servers). Sets STANDBY (array),
# or returns 1 with STANDBY_ERR. $2 = this server's address (optional, may not be a standby).
standby_parse() {
    local list="$1" h seen=","
    local -a items
    STANDBY=(); STANDBY_ERR=""
    list="${list// /}"
    if [[ -z "${list}" || "${list}" == "none" ]]; then return 0; fi
    IFS=, read -r -a items <<<"${list}"
    for h in "${items[@]}"; do
        if ! is_public_ipv4 "${h}"; then
            STANDBY_ERR="STANDBY_HOSTS: '${h}' is not a public IPv4 address (use a comma-separated list, or none)."
            STANDBY=(); return 1
        fi
        if [[ "${seen}" == *",${h},"* ]]; then STANDBY_ERR="STANDBY_HOSTS: ${h} is listed twice."; STANDBY=(); return 1; fi
        if [[ -n "${2:-}" && "${h}" == "$2" ]]; then
            STANDBY_ERR="STANDBY_HOSTS: ${h} is this server's own address."
            STANDBY=(); return 1
        fi
        seen+="${h},"
        STANDBY+=("${h}")
    done
    if (( ${#STANDBY[@]} > 3 )); then
        STANDBY_ERR="STANDBY_HOSTS: at most 3 standby servers (got ${#STANDBY[@]})."
        STANDBY=(); return 1
    fi
    return 0
}

# The server's country code as Cloudflare sees its address (e.g. PL); empty if unknown.
detect_country() {
    local cc
    cc="$(curl -4 -fsS --max-time 8 --max-filesize 4096 https://www.cloudflare.com/cdn-cgi/trace 2>/dev/null \
        | sed -n 's/^loc=\([A-Z][A-Z]\)$/\1/p' | head -n 1 || true)"
    case "${cc}" in XX|T1|"") cc="" ;; esac
    printf '%s' "${cc}"
    return 0
}

save_node_name() {   # $1 = 1: the name is a choice (explicit, detected or "none"); 0: lookup failed, keep trying
    install -d -m 700 "${SCANNER_DIR}"
    install -m 600 /dev/null "${NODE_ENV}.new"
    {
        printf '# veiltrium: node name in client apps (Veiltrium-<N_NAME>); checks from Russia (Globalping)\n'
        if [[ "${1:-1}" == "1" ]]; then printf 'N_NAME=%q\n' "${N_NAME}"; fi
        printf 'N_GLOBALPING=%q\n' "${GLOBALPING}"
        if [[ -n "${N_STANDBY}" ]]; then printf 'N_STANDBY=%q\n' "${N_STANDBY}"; fi
        printf 'N_PANEL_VPN=%q\n' "${PANEL_VPN:-1}"
    } > "${NODE_ENV}.new"
    mv -f "${NODE_ENV}.new" "${NODE_ENV}"
    LABEL="Veiltrium${N_NAME:+-${N_NAME}}"
}

# Added clients, sorted by name (C locale: the configs are the same text on every run).
# Sets CL_NAMES, CL_UUID, CL_HPASS, CL_TPASS, CL_CREATED and the limit arrays (CL_LIMIT ...).
# A damaged file stops the run.
load_clients() {
    local f C_NAME C_UUID C_HY2_PASS C_TT_PASS C_CREATED C_LIMIT C_EXPIRES C_RESET C_STATE C_REASON
    CL_NAMES=(); CL_UUID=(); CL_HPASS=(); CL_TPASS=(); CL_CREATED=()
    CL_LIMIT=(); CL_EXPIRES=(); CL_RESET=(); CL_STATE=(); CL_REASON=()
    [[ -d "${CLIENTS_DIR}" ]] || return 0
    while IFS= read -r f; do
        [[ -f "${f}" ]] || continue
        C_NAME=""; C_UUID=""; C_HY2_PASS=""; C_TT_PASS=""; C_CREATED=""
        C_LIMIT=""; C_EXPIRES=""; C_RESET=""; C_STATE=""; C_REASON=""
        # shellcheck disable=SC1090
        source "${f}"
        if [[ "${C_NAME}.env" != "${f##*/}" || ! "${C_NAME}" =~ ${CLIENT_RE} || "${C_NAME}" == "main" || \
              ! "${C_UUID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ || \
              ! "${C_HY2_PASS}" =~ ^[0-9a-f]{48}$ || ! "${C_TT_PASS}" =~ ^[0-9a-f]{48}$ ]] || \
           ! client_limit_fields_ok "${C_LIMIT}" "${C_EXPIRES}" "${C_RESET}" "${C_STATE}" "${C_REASON}"; then
            die "the client file ${f} is damaged; nothing was changed. Fix or delete it, then run again."
        fi
        CL_NAMES+=("${C_NAME}"); CL_UUID+=("${C_UUID}"); CL_HPASS+=("${C_HY2_PASS}")
        CL_TPASS+=("${C_TT_PASS}"); CL_CREATED+=("${C_CREATED:-?}")
        CL_LIMIT+=("${C_LIMIT}"); CL_EXPIRES+=("${C_EXPIRES}"); CL_RESET+=("${C_RESET:-none}")
        CL_STATE+=("${C_STATE:-active}")
        if [[ "${C_STATE}" == "disabled" ]]; then CL_REASON+=("${C_REASON:-manual}"); else CL_REASON+=(""); fi
    done < <(printf '%s\n' "${CLIENTS_DIR}"/*.env | LC_ALL=C sort)
    return 0
}

# $1 = file, then name, UUID, Hysteria password, TrustTunnel password, created and, optional,
# limit (bytes), expires (date), reset, state, reason. A key is written only when it is set, so
# a client without limits gets exactly the file earlier versions wrote.
write_client_env() {
    install -m 600 /dev/null "$1.new"
    {
        printf 'C_NAME=%q\nC_UUID=%q\nC_HY2_PASS=%q\nC_TT_PASS=%q\nC_CREATED=%q\n' "$2" "$3" "$4" "$5" "$6"
        if [[ -n "${7:-}" && "${7}" != "0" ]]; then printf 'C_LIMIT=%q\n' "$7"; fi
        if [[ -n "${8:-}" ]]; then printf 'C_EXPIRES=%q\n' "$8"; fi
        if [[ -n "${9:-}" && "${9}" != "none" ]]; then printf 'C_RESET=%q\n' "$9"; fi
        if [[ "${10:-}" == "disabled" ]]; then printf 'C_STATE=disabled\nC_REASON=%q\n' "${11:-manual}"; fi
    } > "$1.new"
    mv -f "$1.new" "$1"
}

# A real calendar date, YYYY-MM-DD.
date_ok() {
    [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || return 1
    [[ "$(date -u -d "$1" +%F 2>/dev/null || true)" == "$1" ]]
}

# Are the optional limit fields of a client file valid? (limit, expires, reset, state, reason)
client_limit_fields_ok() {
    local l="$1" e="$2" r="$3" s="$4" w="$5"
    if [[ -n "${l}" ]]; then
        [[ "${l}" =~ ^[1-9][0-9]{0,15}$ ]] && (( 10#${l} <= CLIENT_LIMIT_MAX )) || return 1
    fi
    if [[ -n "${e}" ]]; then date_ok "${e}" || return 1; fi
    case "${r}" in ""|none|daily|weekly|monthly) ;; *) return 1 ;; esac
    case "${s}" in ""|active|disabled) ;; *) return 1 ;; esac
    case "${w}" in ""|manual|quota|expired) ;; *) return 1 ;; esac
    return 0
}

# Rewrites the file of the added client at index $1 with its own credentials, but a new
# state ($2, $3 = reason) and/or new limits ($4 limit, $5 expires, $6 reset; "-" keeps the current).
# $7 = the target file.
write_client_env_i() {
    local i="$1" st="$2" rs="$3" lim="$4" ex="$5" rst="$6"
    [[ "${lim}" != "-" ]] || lim="${CL_LIMIT[i]}"
    [[ "${ex}" != "-" ]] || ex="${CL_EXPIRES[i]}"
    [[ "${rst}" != "-" ]] || rst="${CL_RESET[i]}"
    write_client_env "$7" "${CL_NAMES[i]}" "${CL_UUID[i]}" "${CL_HPASS[i]}" "${CL_TPASS[i]}" "${CL_CREATED[i]}" \
        "${lim}" "${ex}" "${rst}" "${st}" "${rs}"
}

# VT_RECONFIGURE=1: the added clients get new secrets too (names, dates, limits and state stay).
renew_client_secrets() {
    local i
    for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
        write_client_env "${CLIENTS_DIR}/${CL_NAMES[i]}.env" "${CL_NAMES[i]}" "$(cat /proc/sys/kernel/random/uuid)" \
            "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" "${CL_CREATED[i]}" \
            "${CL_LIMIT[i]}" "${CL_EXPIRES[i]}" "${CL_RESET[i]}" "${CL_STATE[i]}" "${CL_REASON[i]}"
    done
    load_clients
    return 0
}

# Number of added clients without reading them (a damaged file must not stop --diagnose).
count_clients() {
    local f n=0
    for f in "${CLIENTS_DIR}"/*.env; do
        if [[ -f "${f}" ]]; then n=$((n + 1)); fi
    done
    printf '%s' "${n}"
}

client_index() {   # $1 = name -> prints the index in CL_NAMES, or nothing
    local i
    for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
        if [[ "${CL_NAMES[i]}" == "$1" ]]; then printf '%s' "${i}"; return 0; fi
    done
    return 0
}

# TrustTunnel credentials ($1 = file): the main client first, then the added ones.
tt_credentials_toml() {
    local i
    {
        printf '[[client]]\nusername = "%s"\npassword = "%s"\n' "${T_USER}" "${T_PASS}"
        for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
            if [[ "${CL_STATE[i]:-}" == "disabled" ]]; then continue; fi
            printf '\n[[client]]\nusername = "%s"\npassword = "%s"\n' "${CL_NAMES[i]}" "${CL_TPASS[i]}"
        done
    } > "$1"
}

# tt:// link of TrustTunnel user $1, built by the endpoint itself (the certificate is
# embedded). Prints nothing if the export failed (the reason is in ${TMPD}/tt-link.err).
# $2 = server address (default: this node), $3 = link name (default: the node name):
# a standby server gets its own link from the same endpoint.
tt_export_link() {
    "${TT_BIN}" "${TT_DIR}/vpn.toml" "${TT_DIR}/hosts.toml" -c "$1" -a "${2:-${PUBLIC_IP}}:${TT_PORT}" \
        --name "${3:-${LABEL}}" > "${TMPD}/tt-link.txt" 2>"${TMPD}/tt-link.err" || true
    grep -m1 -oE 'tt://[^[:space:]]+' "${TMPD}/tt-link.txt" || true
    rm -f "${TMPD}/tt-link.txt"
    return 0
}

# Reality keys and site from a previous run. Sets R_UUID, R_PRIV, R_PUB, R_SID, R_SITE.
load_reality_state() {
    R_UUID=""; R_PRIV=""; R_PUB=""; R_SID=""; R_SITE=""; R_STATS_PORT=""; R_ADMIN_UUID=""
    if [[ "${VT_RECONFIGURE}" != "1" && -s "${XRAY_STATE}" ]]; then
        # shellcheck disable=SC1090
        source "${XRAY_STATE}"
    fi
    if [[ ! "${R_UUID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ || \
          ! "${R_PRIV}" =~ ^[A-Za-z0-9_-]{43}$ || ! "${R_PUB}" =~ ^[A-Za-z0-9_-]{43}$ || \
          ! "${R_SID}" =~ ^[0-9a-f]{16}$ ]]; then
        if [[ "${VT_RECONFIGURE}" != "1" && -e "${XRAY_STATE}" && -e "${CLIENT_FILE}" ]]; then
            die "${XRAY_STATE} is damaged; nothing was changed. New keys (clients must be updated): VT_RECONFIGURE=1 bash $0"
        fi
        R_UUID=""; R_PRIV=""; R_PUB=""; R_SID=""; R_SITE=""; R_STATS_PORT=""; R_ADMIN_UUID=""
    fi
    [[ -z "${R_SITE}" || "${R_SITE}" =~ ${DOMAIN_RE} ]] || R_SITE=""
    [[ "${R_STATS_PORT}" =~ ^[0-9]{1,5}$ ]] || R_STATS_PORT=""   # empty: a node from before the traffic counters
    [[ "${R_ADMIN_UUID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || R_ADMIN_UUID=""
    return 0
}

load_tt_state() {
    T_USER=""; T_PASS=""; T_SNI=""; T_IPV6=""; T_STATS_PORT=""
    if [[ "${VT_RECONFIGURE}" != "1" && -e "${TT_STATE}" ]]; then
        # shellcheck disable=SC1090
        source "${TT_STATE}"
        if [[ -z "${T_USER}" || -z "${T_PASS}" || ! -s "${TT_DIR}/cert.pem" || ! -s "${TT_DIR}/key.pem" ]] || \
           [[ "$(openssl x509 -in "${TT_DIR}/cert.pem" -noout -pubkey 2>/dev/null)" != "$(openssl pkey -in "${TT_DIR}/key.pem" -pubout 2>/dev/null)" ]]; then
            if [[ -e "${CLIENT_FILE}" ]]; then
                die "the TrustTunnel endpoint is damaged (${TT_STATE}, cert.pem/key.pem); nothing was changed. New credentials: VT_RECONFIGURE=1 bash $0"
            fi
            T_USER=""; T_PASS=""; T_SNI=""; T_IPV6=""; T_STATS_PORT=""   # a first install that never finished: start over
        fi
    fi
    [[ -z "${T_SNI}" || "${T_SNI}" =~ ${DOMAIN_RE} ]] || T_SNI=""
    [[ "${T_STATS_PORT}" =~ ^[0-9]{1,5}$ ]] || T_STATS_PORT=""   # empty: a node from before the traffic counters
    return 0
}

# Key for the home-network probe results; created once, never shown in a report.
load_probe_env() {
    PROBE_KEY=""; PROBE_SERVER=""
    if [[ -s "${PROBE_ENV}" ]]; then
        # shellcheck disable=SC1090
        source "${PROBE_ENV}"
    fi
    [[ "${PROBE_KEY}" =~ ^[0-9a-f]{64}$ ]] || PROBE_KEY=""
    return 0
}

# The Reality and TrustTunnel ports of an existing node are kept on a re-run unless
# REALITY_PORT / TT_PORT are given explicitly (the Hysteria port is kept via node.env).
# They are read from the running configs, so nothing new is stored.
load_ports() {
    local p
    if [[ -z "${REALITY_PORT_GIVEN}" && -s "${XRAY_DIR}/config.json" ]]; then
        p="$(sed -n 's/^    "port": \([0-9]\{1,5\}\),$/\1/p' "${XRAY_DIR}/config.json" | head -n 1 || true)"
        if [[ -n "${p}" ]]; then REALITY_PORT="${p}"; fi
    fi
    if [[ -z "${TT_PORT_GIVEN}" && -s "${TT_DIR}/vpn.toml" ]]; then
        p="$(sed -n 's/^listen_address = "0\.0\.0\.0:\([0-9]\{1,5\}\)"$/\1/p' "${TT_DIR}/vpn.toml" | head -n 1 || true)"
        if [[ -n "${p}" ]]; then TT_PORT="${p}"; fi
    fi
    if [[ -z "${PANEL_PORT_GIVEN}" && -s /etc/systemd/system/veiltrium-panel.service ]]; then
        p="$(sed -n 's/^ExecStart=.* --listen 127\.0\.0\.1:\([0-9]\{1,5\}\) .*$/\1/p' /etc/systemd/system/veiltrium-panel.service | head -n 1 || true)"
        if [[ -n "${p}" ]]; then PANEL_PORT="${p}"; fi
    fi
    return 0
}

# Reality candidates: explicit setting (saved), else the saved list, else the built-in one.
load_candidates() {
    local list="" s
    if [[ "${REALITY_CANDIDATES}" == "default" ]]; then
        CAND_SOURCE="default"; list="${DEFAULT_CANDIDATES}"
    elif [[ -n "${REALITY_CANDIDATES}" ]]; then
        CAND_SOURCE="explicit"; list="${REALITY_CANDIDATES}"
    elif [[ -s "${CANDIDATES_FILE}" ]]; then
        CAND_SOURCE="saved"; list="$(grep -vE '^[[:space:]]*(#|$)' "${CANDIDATES_FILE}" | tr '\n' ' ' || true)"
    else
        CAND_SOURCE="default"; list="${DEFAULT_CANDIDATES}"
    fi
    read -r -a CAND_LIST <<<"${list}"
    (( ${#CAND_LIST[@]} )) || die "the Reality candidate list is empty."
    for s in "${CAND_LIST[@]}"; do
        [[ "${s}" =~ ${DOMAIN_RE} ]] || die "the Reality candidate list contains something that is not a domain name: ${s}"
    done
}

save_candidates() {
    if [[ "${CAND_SOURCE}" == "explicit" ]]; then
        install -d -m 700 "${SCANNER_DIR}"
        printf '# veiltrium: Reality mask site candidates (REALITY_CANDIDATES), one per line\n%s\n' \
            "$(printf '%s\n' "${CAND_LIST[@]}")" > "${CANDIDATES_FILE}.new"
        chmod 600 "${CANDIDATES_FILE}.new"
        mv -f "${CANDIDATES_FILE}.new" "${CANDIDATES_FILE}"
    elif [[ "${REALITY_CANDIDATES}" == "default" ]]; then
        rm -f "${CANDIDATES_FILE}"
    fi
    return 0
}

cert_sha256() {   # hex SHA-256 of the certificate (pinSHA256 for Hysteria clients)
    local fp
    fp="$(openssl x509 -in "$1" -noout -fingerprint -sha256)"
    fp="${fp#*=}"; fp="${fp//:/}"
    printf '%s' "${fp,,}"
}
cert_pubkey_sha256() {   # base64 SHA-256 of the public key (sing-box certificate_public_key_sha256)
    openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform der \
        | openssl dgst -sha256 -binary | openssl enc -base64 -A
}
cert_not_after() { openssl x509 -in "$1" -noout -enddate 2>/dev/null | cut -d= -f2 || true; }

wait_listening() {   # $1 = ss filter (-Hulpn / -Htlpn), $2 = port, $3 = process name
    local _
    for _ in $(seq 1 30); do
        [[ "$(ss "$1" "sport = :$2" 2>/dev/null || true)" == *"\"$3\""* ]] && return 0
        sleep 0.5
    done
    return 1
}
wait_tcp_port() {   # $1 = port on loopback
    local _
    for _ in $(seq 1 30); do
        [[ -n "$(ss -Htln "sport = :$1" 2>/dev/null || true)" ]] && return 0
        sleep 0.3
    done
    return 1
}
free_port() {   # a TCP/UDP port nobody listens on
    local p _
    for _ in $(seq 1 50); do
        p=$(( 20000 + RANDOM % 30000 ))
        if [[ -z "$(ss -Htuln "sport = :${p}" 2>/dev/null || true)" ]]; then printf '%s' "${p}"; return 0; fi
    done
    printf '%s' 39871
}
# Loopback port of a proxy's statistics endpoint: $1 = the saved one (kept if nothing else uses
# it: free, or held by the process $2), else a new free port. $3... = ports to avoid.
stats_port_pick() {
    local saved="$1" proc="$2" p listener _
    shift 2
    if [[ "${saved}" =~ ^[0-9]{1,5}$ && " $* " != *" ${saved} "* ]]; then
        listener="$(ss -Htlnp "sport = :${saved}" 2>/dev/null || true)"
        if [[ -z "${listener}" || "${listener}" == *"\"${proc}\""* ]]; then printf '%s' "${saved}"; return 0; fi
    fi
    p=""
    for _ in $(seq 1 50); do
        p="$(free_port)"
        if [[ " $* " != *" ${p} "* ]]; then break; fi
    done
    printf '%s' "${p}"
    return 0
}
stop_pid() {   # $1 = pid (may be empty)
    if [[ -n "${1:-}" ]]; then
        kill "$1" 2>/dev/null || true
        wait "$1" 2>/dev/null || true
    fi
    return 0
}

# Through a local SOCKS proxy ($1 = port): $2 requests, each to gstatic and, if that
# fails, to Cloudflare (one site being down must not fail the check).
# Sets TP_OK, TP_FAIL and TP_MED (median time of the successful requests, ms).
tunnel_probe() {
    local i url out code t done_one
    local -a times=()
    TP_OK=0; TP_FAIL=0; TP_MED=0
    for (( i = 0; i < $2; i++ )); do
        done_one=0
        for url in https://www.gstatic.com/generate_204 https://cp.cloudflare.com/generate_204; do
            out="$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 12 \
                --socks5-hostname "127.0.0.1:$1" "${url}" 2>/dev/null || true)"
            code="${out%% *}"; t="${out#* }"
            if [[ "${code}" == "204" ]]; then times+=("$(ms "${t}")"); done_one=1; break; fi
        done
        if (( done_one == 1 )); then TP_OK=$((TP_OK + 1)); else TP_FAIL=$((TP_FAIL + 1)); fi
    done
    if (( ${#times[@]} )); then TP_MED="$(median "${times[@]}")"; fi
    return 0
}

# ---- VLESS Reality ----------------------------------------------------------
# Server config. $1 = file, $2 = listen address ("" = all), $3 = port, $4 = target
# site, $5... = extra server names (a trial). Without extras and listen address
# the text is exactly what earlier versions wrote, so updates do not restart Xray.
reality_server_json() {
    local out="$1" listen="$2" port="$3" site="$4" names n listen_line="" clients i stats_lines="" main_email=""
    local routing_lines="" panel_outbound=""
    shift 4
    names="\"${site}\""
    for n in "$@"; do names+=", \"${n}\""; done
    if [[ -n "${listen}" ]]; then listen_line="    \"listen\": \"${listen}\","$'\n'; fi
    # Traffic counters (production and trial configs only: a test server must not take the port):
    # per-user statistics (email = the client name) and the gRPC StatsService on 127.0.0.1
    # (Xray v26.3.27: api.listen). Nodes without R_STATS_PORT keep the text earlier versions wrote.
    if [[ -n "${R_STATS_PORT}" && -z "${listen}" ]]; then
        stats_lines='  "stats": {},'$'\n'
        stats_lines+="  \"api\": {\"tag\": \"api\", \"listen\": \"127.0.0.1:${R_STATS_PORT}\", \"services\": [\"StatsService\"]},"$'\n'
        stats_lines+='  "policy": {"levels": {"0": {"statsUserUplink": true, "statsUserDownlink": true}}},'$'\n'
        main_email=", \"email\": \"main\""
    fi
    # the main client first (as earlier versions wrote it), then the added ones by name
    clients="{\"id\": \"${R_UUID}\", \"flow\": \"xtls-rprx-vision\"${main_email}}"
    for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
        if [[ "${CL_STATE[i]:-}" == "disabled" ]]; then continue; fi
        clients+=", {\"id\": \"${CL_UUID[i]}\", \"flow\": \"xtls-rprx-vision\", \"email\": \"${CL_NAMES[i]}\"}"
    done
    # The panel profile (production and trial configs only): its TCP connections to the panel's port, whatever
    # the address, go to the panel on 127.0.0.1 from PANEL_VPN_SRC. The firewall lets Xray reach the panel
    # from that source address only, so no other user (and no other outbound) gets there.
    if [[ -n "${R_ADMIN_UUID}" && -z "${listen}" ]]; then
        clients+=", {\"id\": \"${R_ADMIN_UUID}\", \"flow\": \"xtls-rprx-vision\", \"email\": \"${PANEL_VPN_EMAIL}\"}"
        routing_lines="  \"routing\": {\"rules\": [{\"type\": \"field\", \"user\": [\"${PANEL_VPN_EMAIL}\"], \"network\": \"tcp\", \"port\": \"${PANEL_PORT}\", \"outboundTag\": \"panel\"}]},"$'\n'
        panel_outbound=", {\"protocol\": \"freedom\", \"tag\": \"panel\", \"sendThrough\": \"${PANEL_VPN_SRC}\", \"settings\": {\"redirect\": \"127.0.0.1:${PANEL_PORT}\"}}"
    fi
    cat > "${out}" <<EOF
{
  "log": {"loglevel": "warning"},
${stats_lines}  "inbounds": [{
${listen_line}    "port": ${port},
    "protocol": "vless",
    "settings": {"clients": [${clients}], "decryption": "none"},
    "streamSettings": {
      "network": "tcp",
      "security": "reality",
      "realitySettings": {
        "target": "${site}:443",
        "serverNames": [${names}],
        "privateKey": "${R_PRIV}",
        "shortIds": ["${R_SID}"]
      }
    }
  }],
${routing_lines}  "outbounds": [{"protocol": "freedom", "tag": "direct"}${panel_outbound}]
}
EOF
}

# A real Reality client with a local SOCKS port. $1 = SNI, $2 = address, $3 = port, $4 = SOCKS port.
# RC_UUID: another client's UUID (default: the main client).
reality_client_start() {
    install -m 600 /dev/null "${TMPD}/reality-client.json"
    cat > "${TMPD}/reality-client.json" <<EOF
{"log": {"loglevel": "warning"},
 "inbounds": [{"listen": "127.0.0.1", "port": $4, "protocol": "socks", "settings": {"udp": false}}],
 "outbounds": [{"protocol": "vless",
   "settings": {"vnext": [{"address": "$2", "port": $3,
     "users": [{"id": "${RC_UUID:-${R_UUID}}", "encryption": "none", "flow": "xtls-rprx-vision"}]}]},
   "streamSettings": {"network": "tcp", "security": "reality",
     "realitySettings": {"serverName": "$1", "fingerprint": "${REALITY_FP}",
       "publicKey": "${R_PUB}", "shortId": "${R_SID}"}}}]}
EOF
    setpriv --pdeathsig KILL -- "${XRAY_BIN}" run -c "${TMPD}/reality-client.json" >"${TMPD}/reality-client.log" 2>&1 7>&- 9>&- &
    CLIENT_PID=$!
    wait_tcp_port "$4" || true
}
reality_client_stop() { stop_pid "${CLIENT_PID}"; CLIENT_PID=""; rm -f "${TMPD}/reality-client.json"; }

# The panel through VLESS Reality, with a real client of the panel's profile: the panel answers on the
# server's address (401: sign in first), and the main client does not get there. PV_STATUS = ok | fail.
panel_vpn_check() {
    local cport code main
    PV_STATUS="fail"
    cport="$(free_port)"
    RC_UUID="${R_ADMIN_UUID}" reality_client_start "${R_SITE}" 127.0.0.1 "${REALITY_PORT}" "${cport}"
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 --socks5-hostname "127.0.0.1:${cport}" \
        "http://${PUBLIC_IP}:${PANEL_PORT}/api/session" 2>/dev/null || true)"
    reality_client_stop
    cport="$(free_port)"
    reality_client_start "${R_SITE}" 127.0.0.1 "${REALITY_PORT}" "${cport}"
    main="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 --socks5-hostname "127.0.0.1:${cport}" \
        "http://${PUBLIC_IP}:${PANEL_PORT}/api/session" 2>/dev/null || true)"
    reality_client_stop
    if [[ "${code}" == "401" && "${main}" != "401" ]]; then PV_STATUS="ok"; fi
    return 0
}

# What a prober without the key sees on $1:$2 with SNI $3: the real, valid certificate?
fallback_ok() {
    local out
    out="$(timeout 15 openssl s_client -connect "$1:$2" -servername "$3" -verify_hostname "$3" \
        -verify_return_error </dev/null 2>/dev/null || true)"
    [[ "${out}" == *"Verify return code: 0 (ok)"* ]]
}

# Direct checks of a candidate site from this server, before any Reality test.
# Hard gates: IPv4 addresses (all public), on every address (up to 4: CDNs have
# many, and Xray may use any of them) TLS 1.3 with X25519, ALPN h2 and a
# certificate valid for the name; then at least 2 of 3 HTTPS handshakes over h2.
# The HTTP status (200, 202, 301, 403...) is recorded, it is not an error.
# Sets PS_GATE (pass|fail), PS_REASON, PS_IPS, PS_N6, PS_TLS_MED, PS_TLS_SPREAD, PS_TLS_FAIL, PS_HTTP.
prescreen_site() {
    local site="$1" ip out t code ver i
    local -a ips=() times=()
    PS_GATE="fail"; PS_REASON=""; PS_IPS=""; PS_N6=0; PS_TLS_MED=0; PS_TLS_SPREAD=0; PS_TLS_FAIL=0; PS_HTTP=""
    mapfile -t ips < <(getent ahostsv4 "${site}" 2>/dev/null | awk '{print $1}' | sort -u | head -n 4 || true)
    PS_N6="$(getent ahostsv6 "${site}" 2>/dev/null | awk '$1 !~ /^::ffff:/ {print $1}' | sort -u | wc -l || true)"
    if (( ${#ips[@]} == 0 )); then PS_REASON="dns: no IPv4 address"; return 0; fi
    PS_IPS="${ips[*]}"
    for ip in "${ips[@]}"; do
        if ! is_public_ipv4 "${ip}"; then PS_REASON="dns: non-public address ${ip}"; return 0; fi
    done
    for ip in "${ips[@]}"; do
        out="$(timeout 8 openssl s_client -connect "${ip}:443" -servername "${site}" -tls1_3 -groups X25519 \
            -alpn h2 -verify_hostname "${site}" -verify_return_error </dev/null 2>&1 || true)"
        if [[ "${out}" != *"Verify return code: 0 (ok)"* ]]; then
            if [[ "${out}" == *"verify error"* || "${out}" == *"certificate verify failed"* ]]; then
                PS_REASON="certificate is not valid for ${site} at ${ip}"
            elif [[ "${out}" == *CONNECTED* ]]; then
                PS_REASON="no TLS 1.3 with X25519 at ${ip}"
            else
                PS_REASON="no TCP connection to ${ip}:443"
            fi
            return 0
        fi
        if [[ "${out}" != *"ALPN protocol: h2"* ]]; then PS_REASON="no HTTP/2 (ALPN h2) at ${ip}"; return 0; fi
    done
    for i in 1 2 3; do
        out="$(curl -s -o /dev/null --tlsv1.3 --http2 -A 'Mozilla/5.0' --connect-timeout 5 --max-time 8 \
            -w '%{time_appconnect} %{http_code} %{http_version}' "https://${site}/" 2>/dev/null || true)"
        t=""; code=""; ver=""
        read -r t code ver <<<"${out}" || true
        if [[ "${ver}" == "2" ]] && awk -v t="${t:-0}" 'BEGIN { exit !(t > 0) }'; then
            times+=("$(ms "${t}")"); PS_HTTP="${code}"
        else
            PS_TLS_FAIL=$((PS_TLS_FAIL + 1))
        fi
        [[ "${i}" == 3 ]] || sleep 0.2
    done
    if (( ${#times[@]} < 2 )); then PS_REASON="unstable: ${#times[@]} of 3 HTTPS handshakes over h2 succeeded"; return 0; fi
    PS_TLS_MED="$(median "${times[@]}")"
    PS_TLS_SPREAD=$(( $(printf '%s\n' "${times[@]}" | sort -n | tail -n 1) - $(printf '%s\n' "${times[@]}" | sort -n | head -n 1) ))
    PS_GATE="pass"
}

# A throwaway Reality server with the node's own keys and the candidate as target:
# loopback only, unprivileged (nobody), the config with the private key comes
# through stdin. The production service on port ${REALITY_PORT} is not touched.
# Gates: at least 2 of 3 requests through the tunnel, and a prober without the
# key gets the real certificate of the site (fallback).
# Sets RT_STATUS (ok|fail), RT_MED, RT_FAIL, RT_FALLBACK (ok|fail), RT_REASON.
reality_isolated_test() {
    local site="$1" sport cport
    RT_STATUS="fail"; RT_MED=0; RT_FAIL=0; RT_FALLBACK="fail"; RT_REASON=""
    sport="$(free_port)"
    install -m 600 /dev/null "${TMPD}/rt-server.json"
    reality_server_json "${TMPD}/rt-server.json" 127.0.0.1 "${sport}" "${site}"
    if ! "${XRAY_BIN}" run -test -c "${TMPD}/rt-server.json" >"${TMPD}/rt-test.log" 2>&1; then
        RT_REASON="Xray rejected the test config"; rm -f "${TMPD}/rt-server.json"; return 0
    fi
    setpriv --reuid=65534 --regid=65534 --clear-groups --no-new-privs --pdeathsig KILL \
        "${XRAY_BIN}" run -c stdin: < "${TMPD}/rt-server.json" > "${TMPD}/rt-server.log" 2>&1 7>&- 9>&- &
    SERVER_PID=$!
    if ! wait_tcp_port "${sport}"; then
        stop_pid "${SERVER_PID}"; SERVER_PID=""; rm -f "${TMPD}/rt-server.json"
        RT_REASON="the test Reality server did not start"; return 0
    fi
    rm -f "${TMPD}/rt-server.json"
    cport="$(free_port)"
    reality_client_start "${site}" 127.0.0.1 "${sport}" "${cport}"
    tunnel_probe "${cport}" 3
    reality_client_stop
    RT_MED="${TP_MED}"; RT_FAIL="${TP_FAIL}"
    if fallback_ok 127.0.0.1 "${sport}" "${site}"; then RT_FALLBACK="ok"; fi
    stop_pid "${SERVER_PID}"; SERVER_PID=""
    if (( TP_OK < 2 )); then
        RT_REASON="Reality client: ${TP_OK} of 3 requests through the tunnel succeeded"
    elif [[ "${RT_FALLBACK}" != "ok" ]]; then
        RT_REASON="a prober without the key does not get the real certificate of ${site}"
    else
        RT_STATUS="ok"
    fi
    return 0
}

# The production service: a real client on port ${REALITY_PORT}, the SSH of the
# server must stay unreachable through it, and the fallback must show the real site.
# Sets RP_STATUS (ok|fail), RP_MED, RP_FALLBACK, REALITY_SSH_BANNER.
reality_verify_production() {
    local cport
    RP_STATUS="fail"; RP_MED=0; RP_FALLBACK="fail"; REALITY_SSH_BANNER=""
    wait_listening -Htlpn "${REALITY_PORT}" xray || true
    cport="$(free_port)"
    reality_client_start "$1" 127.0.0.1 "${REALITY_PORT}" "${cport}"
    tunnel_probe "${cport}" "${RP_TRIES:-3}"
    # Xray's socks inbound reports success before connecting, so look for the SSH banner instead.
    REALITY_SSH_BANNER="$(curl -s --http0.9 --max-time 6 --socks5-hostname "127.0.0.1:${cport}" \
        "http://127.0.0.1:${SSH_PORTS[0]}/" 2>/dev/null | head -c 64 || true)"
    reality_client_stop
    RP_MED="${TP_MED}"
    if fallback_ok 127.0.0.1 "${REALITY_PORT}" "$1"; then RP_FALLBACK="ok"; fi
    if (( TP_OK >= 1 )); then RP_STATUS="ok"; fi
    return 0
}

# Lower is better. Inputs: TLS median, TLS spread, failed TLS handshakes,
# Reality median, failed Reality requests (all ms or counts), home-network status.
# A verified home-network success is a bonus, a verified failure a penalty (not an
# exclusion: it may be the route or the provider, not the site).
reality_cost() {
    local c=$(( $1 + $2 + 250 * $3 + $4 + 250 * $5 ))
    case "$6" in
        ok) c=$(( c - 200 )) ;;
        fail|degraded|stalled) c=$(( c + 600 )) ;;
    esac
    (( c >= 0 )) || c=0
    printf '%s' "${c}"
}

# Evaluates the sites ($@) one by one; one TSV line per site in ${TMPD}/selection.tsv:
# site order gate reason ipv4 n_ipv6 tls_med tls_spread tls_fail http reality rt_med rt_fail fallback mts cost
reality_evaluate() {
    local site order=0 gate reason mts cost
    : > "${TMPD}/selection.tsv"
    for site in "$@"; do
        order=$((order + 1))
        prescreen_site "${site}"
        if [[ "${PS_GATE}" == "pass" ]] && ru_blocked "${site}"; then
            PS_GATE="fail"; PS_REASON="blocked in Russia (RKN block list)"
        fi
        RT_STATUS="untested"; RT_MED=0; RT_FAIL=0; RT_FALLBACK="untested"; RT_REASON=""
        if [[ "${PS_GATE}" == "pass" && -n "${R_PRIV}" && -x "${XRAY_BIN}" ]]; then reality_isolated_test "${site}"; fi
        mts="$(mts_status reality "${site}")"
        gate="fail"; reason="${PS_REASON}"; cost=-1
        if [[ "${PS_GATE}" == "pass" && "${RT_STATUS}" == "ok" ]]; then
            gate="pass"
            cost="$(reality_cost "${PS_TLS_MED}" "${PS_TLS_SPREAD}" "${PS_TLS_FAIL}" "${RT_MED}" "${RT_FAIL}" "${mts}")"
            info "${site}: pass; TLS ${PS_TLS_MED} ms (spread ${PS_TLS_SPREAD}), Reality ${RT_MED} ms, home network: ${mts}, score ${cost}"
        elif [[ "${PS_GATE}" == "pass" && "${RT_STATUS}" == "untested" ]]; then
            reason="Reality not tested (no Xray keys yet)"
            info "${site}: direct checks pass; TLS ${PS_TLS_MED} ms; ${reason}"
        else
            [[ -n "${reason}" ]] || reason="${RT_REASON}"
            info "${site}: fail; ${reason}"
        fi
        printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
            "${site}" "${order}" "${gate}" "${reason}" "${PS_IPS}" "${PS_N6}" "${PS_TLS_MED}" \
            "${PS_TLS_SPREAD}" "${PS_TLS_FAIL}" "${PS_HTTP}" "${RT_STATUS}" "${RT_MED}" "${RT_FAIL}" \
            "${RT_FALLBACK}" "${mts}" "${cost}" >> "${TMPD}/selection.tsv"
    done
}

# The sites a re-selection evaluates: the candidate list plus the current site, minus
# the names Hysteria and TrustTunnel use (unless one is the current Reality site, as on
# nodes from before 2026-10-09): the three TLS identities stay apart. Sets SITES.
reality_sites() {   # $1 = current site, $2... = names of the other protocols
    local cur="$1" s
    shift
    SITES=()
    if [[ -n "${cur}" && " ${CAND_LIST[*]} " != *" ${cur} "* ]]; then SITES=("${cur}"); fi
    for s in "${CAND_LIST[@]}"; do
        if [[ "${s}" != "${cur}" && " $* " == *" ${s} "* ]]; then continue; fi
        SITES+=("${s}")
    done
    return 0
}

# Chooses from ${TMPD}/selection.tsv. $1 = current site (may be empty).
# The best score wins, the list order breaks ties; the current site stays while
# it passes and is within 25% (at least 50 points) of the best: no pointless rotation.
# Sets R_CHOSEN (empty if nothing passed), R_DECISION and R_TOP3.
reality_choose() {
    local cur="$1" best_site="" best_cost="" cur_cost="" margin
    R_CHOSEN=""; R_DECISION=""; R_TOP3=""
    read -r best_site best_cost < <(awk -F'\t' '$3 == "pass" { print $16, $2, $1 }' "${TMPD}/selection.tsv" \
        | sort -n -k1,1 -k2,2 | awk 'NR == 1 { print $3, $1 }') || true
    R_TOP3="$(awk -F'\t' '$3 == "pass" { print $16, $2, $1 }' "${TMPD}/selection.tsv" | sort -n -k1,1 -k2,2 \
        | awk 'NR <= 3 { printf "%s%s", (NR > 1 ? " " : ""), $3 }')"
    if [[ -n "${cur}" ]]; then
        cur_cost="$(awk -F'\t' -v s="${cur}" '$1 == s && $3 == "pass" { print $16 }' "${TMPD}/selection.tsv")"
    fi
    if [[ -z "${best_site}" ]]; then
        R_DECISION="no candidate passed the checks"
        return 0
    fi
    if [[ -n "${cur_cost}" ]]; then
        margin=$(( best_cost / 4 )); (( margin >= 50 )) || margin=50
        if (( cur_cost <= best_cost + margin )); then
            R_CHOSEN="${cur}"
            R_DECISION="kept ${cur} (score ${cur_cost}; best ${best_site} ${best_cost}, margin ${margin})"
            return 0
        fi
        R_CHOSEN="${best_site}"
        R_DECISION="switch ${cur} (score ${cur_cost}) -> ${best_site} (score ${best_cost}): better by more than ${margin}"
        return 0
    fi
    R_CHOSEN="${best_site}"
    if [[ -n "${cur}" ]] && awk -F'	' -v s="${cur}" '$1 == s { f = 1 } END { exit !f }' "${TMPD}/selection.tsv"; then
        R_DECISION="switch ${cur} (fails the checks) -> ${best_site} (score ${best_cost})"
    elif [[ -n "${cur}" ]]; then
        R_DECISION="switch ${cur} -> ${best_site} (score ${best_cost}), as requested"
    else
        R_DECISION="chose ${best_site} (score ${best_cost})"
    fi
    return 0
}

# ${TMPD}/selection.tsv -> JSON (no secrets) on stdout
selection_json() {
    jq -R -s --arg chosen "${R_CHOSEN:-}" --arg decision "${R_DECISION:-}" --arg now "$(date -u +%FT%TZ)" '
        split("\n") | map(select(length > 0) | split("\t")) | map({
            site: .[0], order: (.[1] | tonumber), gate: .[2], reason: .[3],
            ipv4: (.[4] | split(" ") | map(select(length > 0))), ipv6_count: (.[5] | tonumber),
            tls_ms_median: (.[6] | tonumber), tls_ms_spread: (.[7] | tonumber), tls_failures: (.[8] | tonumber),
            http_status: .[9], reality: .[10], reality_ms_median: (.[11] | tonumber),
            reality_failures: (.[12] | tonumber), fallback_real_certificate: .[13], home_network: .[14],
            score: (.[15] | tonumber)
        }) | {
            generated_at: $now,
            scoring: "score = tls_median + tls_spread + 250*tls_failures + reality_median + 250*reality_failures - 200 (home network ok) + 600 (home network fail); lower is better; ties: list order; current site kept within max(50, 25%) of the best",
            chosen: $chosen, decision: $decision,
            top3: (map(select(.gate == "pass")) | sort_by(.score, .order) | .[:3] | map(.site)),
            candidates: .
        }' "${TMPD}/selection.tsv"
}

# ---- Crash safety: every change of a working node is a transaction ---------
# Before a change, the files it may replace are copied to ${TXN_DIR}/<name> and
# a "pending" marker is set. The change is committed only after a real client
# check. Otherwise the previous files come back, without anyone running the
# installer again:
#   - error, Ctrl+C, SIGTERM: right away (EXIT trap);
#   - SIGKILL, a hung run: a systemd timer (${WATCHDOG_UNIT}) checks every 30 s and
#     restores as soon as the installer no longer holds its lock;
#   - power loss, reboot: veiltrium-recover.service, before the proxies start;
#   - and the next installer run, as a last resort.
RECOVER_SCRIPT='#!/usr/bin/env bash
# veiltrium: puts back the files of a change that did not finish.
#   --boot      at boot, before the proxy services start
#   --watchdog  from a timer while a change is pending (only if the installer is gone)
#   --now       from the installer itself
# A second argument limits it to one change (reality, hysteria, trusttunnel).
set -u
D=/var/lib/veiltrium/txn
mode="${1:---watchdog}"; only="${2:-}"
if [[ "${mode}" == --watchdog ]]; then
    exec 9>/run/veiltrium.lock
    flock -n 9 || exit 0
    tries=$(( $(cat "${D}/.tries" 2>/dev/null || echo 0) + 1 ))
    echo "${tries}" > "${D}/.tries"
    if (( tries > 20 )); then
        echo "veiltrium-recover: giving up after 20 attempts; the boot service or the next installer run retries" >&2
        systemctl stop veiltrium-watchdog.timer >/dev/null 2>&1
        exit 1
    fi
fi
shopt -s nullglob
for t in "${D}"/*/; do
    t="${t%/}"; name="${t##*/}"
    [[ -f "${t}/pending" ]] || continue
    [[ -z "${only}" || "${only}" == "${name}" ]] || continue
    n=0; failed=0
    while IFS= read -r path; do
        n=$((n + 1))
        if [[ -f "${t}/f${n}" ]]; then
            if cp -p "${t}/f${n}" "${path}.vt-restore" && cmp -s "${t}/f${n}" "${path}.vt-restore"; then
                mv -f "${path}.vt-restore" "${path}" || failed=1
            else
                rm -f "${path}.vt-restore"; failed=1
            fi
        else
            rm -f "${path}" || failed=1
        fi
    done < "${t}/files"
    sync
    if (( failed )); then
        echo "veiltrium-recover: could not restore all ${name} files (disk full?); will retry" >&2
        continue
    fi
    while IFS= read -r svc; do
        if [[ -f "${t}/disable" ]]; then
            systemctl disable "${svc}" >/dev/null 2>&1
            systemctl --no-block stop "${svc}" >/dev/null 2>&1
        elif [[ "${mode}" != --boot ]]; then
            systemctl reset-failed "${svc}" >/dev/null 2>&1
            systemctl restart "${svc}" >/dev/null 2>&1
        fi
    done < "${t}/services"
    rm -f "${t}/pending"
    sync
    logger -t veiltrium-recover "restored the previous ${name} settings after an interrupted change" 2>/dev/null
    echo "veiltrium-recover: restored the previous ${name} settings"
done
if [[ "${mode}" != --boot ]] && ! compgen -G "${D}/*/pending" >/dev/null; then
    systemctl stop veiltrium-watchdog.timer >/dev/null 2>&1
    rm -f "${D}/.tries"
fi
# temp dirs of a killed installer run (client configs with keys); none is running now
if [[ "${mode}" != --now ]]; then rm -rf /root/.veiltrium.* 2>/dev/null; fi
exit 0
'

install_recover() {
    printf '%s' "${RECOVER_SCRIPT}" > "${RECOVER_BIN}.new"
    chmod 700 "${RECOVER_BIN}.new"
    mv -f "${RECOVER_BIN}.new" "${RECOVER_BIN}"
    cat > /etc/systemd/system/veiltrium-recover.service.new <<EOF
# veiltrium: restore the settings of a change interrupted by a reboot or power loss
[Unit]
Description=Restore settings of an interrupted Veiltrium change
After=local-fs.target
Before=hysteria-server.service xray.service trusttunnel.service
ConditionPathExistsGlob=${TXN_DIR}/*/pending

[Service]
Type=oneshot
ExecStart=${RECOVER_BIN} --boot

[Install]
WantedBy=multi-user.target
EOF
    if ! cmp -s /etc/systemd/system/veiltrium-recover.service.new /etc/systemd/system/veiltrium-recover.service 2>/dev/null; then
        mv -f /etc/systemd/system/veiltrium-recover.service.new /etc/systemd/system/veiltrium-recover.service
        systemctl daemon-reload
    else
        rm -f /etc/systemd/system/veiltrium-recover.service.new
    fi
    systemctl enable veiltrium-recover.service >/dev/null 2>&1 || true
}

txn_pending() { compgen -G "${TXN_DIR}/*/pending" >/dev/null; }

txn_begin() {   # $1 name, $2 service, $3... files the change may replace
    local name="$1" svc="$2" d f n=0 had=0
    shift 2
    d="${TXN_DIR}/${name}"
    rm -rf -- "${d}"
    install -d -m 700 "${TXN_DIR}" "${d}"
    : > "${d}/files"
    for f in "$@"; do
        n=$((n + 1))
        printf '%s\n' "${f}" >> "${d}/files"
        if [[ -f "${f}" ]]; then
            cp -p -- "${f}" "${d}/f${n}" || die "could not back up ${f} (disk full?); nothing was changed."
            had=1
        fi
    done
    printf '%s\n' "${svc}" > "${d}/services"
    if (( had == 0 )); then : > "${d}/disable"; fi   # nothing existed before: restoring means "off"
    sync
    printf '%s\n' "$$" > "${d}/pending"
    sync
    TXN_OPEN+=("${name}")
    if ! systemctl is-active --quiet "${WATCHDOG_UNIT}.timer"; then
        systemctl reset-failed "${WATCHDOG_UNIT}.timer" "${WATCHDOG_UNIT}.service" >/dev/null 2>&1 || true
        systemd-run --quiet --unit="${WATCHDOG_UNIT}" --on-active=30s --on-unit-active=30s \
            --timer-property=AccuracySec=5s --description="Veiltrium: restore an interrupted change" \
            "${RECOVER_BIN}" --watchdog >/dev/null 2>&1 \
            || warn "could not arm the rollback timer; an interrupted change is restored at boot or by the next run"
    fi
    return 0
}
txn_close() {   # $1 name
    local -a keep=()
    local t
    rm -f "${TXN_DIR}/$1/pending"
    sync
    # the copies of the previous files are not needed any more (and may hold old secrets)
    rm -f "${TXN_DIR}/$1"/f[0-9]*
    for t in "${TXN_OPEN[@]+"${TXN_OPEN[@]}"}"; do [[ "${t}" == "$1" ]] || keep+=("${t}"); done
    TXN_OPEN=("${keep[@]+"${keep[@]}"}")
    if ! txn_pending; then systemctl stop "${WATCHDOG_UNIT}.timer" >/dev/null 2>&1 || true; fi
    return 0
}
txn_commit() { txn_close "$1"; }
txn_restore() {
    "${RECOVER_BIN}" --now "$1" || true
    if [[ -e "${TXN_DIR}/$1/pending" ]]; then
        # keep the marker and the backup: the watchdog, the boot service or the next run retries
        TXN_OPEN=()
        die "could not restore the previous $1 settings (disk full?); they are kept in ${TXN_DIR}/$1 and restored automatically later."
    fi
    txn_close "$1"
}
recover_interrupted() {
    if txn_pending && [[ -x "${RECOVER_BIN}" ]]; then
        warn "A previous run was interrupted while changing settings; restoring the settings from before it."
        "${RECOVER_BIN}" --now || true
        if txn_pending; then
            die "the settings of an interrupted change could not be restored yet (disk full?); nothing else was changed. See ${TXN_DIR}."
        fi
    fi
    return 0
}

# Writes the production config for site $1, restarts Xray and checks it with a
# real client. SWITCH_OK=1: works, state saved; 0: did not work, previous state
# restored. Called as a plain command (not in an "if"), so that any failure inside
# still stops the run and the EXIT trap restores the previous files.
reality_switch() {
    local site="$1"
    txn_begin reality xray.service "${XRAY_DIR}/config.json" "${XRAY_STATE}"
    reality_server_json "${XRAY_DIR}/config.new.json" "" "${REALITY_PORT}" "${site}"
    chown root:xray "${XRAY_DIR}/config.new.json"
    chmod 640 "${XRAY_DIR}/config.new.json"
    "${XRAY_BIN}" run -test -c "${XRAY_DIR}/config.new.json" >"${TMPD}/xray-test.log" 2>&1 \
        || { tail -5 "${TMPD}/xray-test.log"; die "Xray rejected its own config."; }
    mv -f "${XRAY_DIR}/config.new.json" "${XRAY_DIR}/config.json"
    systemctl enable xray.service >/dev/null 2>&1
    traffic_collect   # the restart resets Xray's counters
    systemctl restart xray.service || true
    reality_verify_production "${site}"
    SWITCH_OK=0
    if [[ "${RP_STATUS}" == "ok" && "${RP_FALLBACK}" == "ok" ]]; then
        R_SITE="${site}"
        save_reality_state
        txn_commit reality
        SWITCH_OK=1
        return 0
    fi
    txn_restore reality
    return 0
}

# Keeps the working site $1. The config text is the same as before, so Xray restarts
# only when its binary or unit changed or it is not running. Sets REALITY_OK.
reality_keep() {
    local site="$1"
    reality_server_json "${XRAY_DIR}/config.new.json" "" "${REALITY_PORT}" "${site}"
    chown root:xray "${XRAY_DIR}/config.new.json"
    chmod 640 "${XRAY_DIR}/config.new.json"
    if cmp -s "${XRAY_DIR}/config.new.json" "${XRAY_DIR}/config.json" 2>/dev/null; then
        rm -f "${XRAY_DIR}/config.new.json"
        if (( ${RESTART_XRAY:-0} == 1 )) || ! systemctl is-active --quiet xray.service; then
            systemctl restart xray.service || true
        fi
        reality_verify_production "${site}"
        R_SITE="${site}"
        if [[ "${RP_STATUS}" == "ok" ]]; then REALITY_OK=1; save_reality_state; fi
    else
        rm -f "${XRAY_DIR}/config.new.json"
        reality_switch "${site}"
        if (( SWITCH_OK == 1 )); then
            REALITY_OK=1
        else
            R_SITE="${site}"
            ROLLBACKS+=("reality: the rewritten config for ${site} failed its check; previous config restored")
        fi
    fi
    return 0
}

save_reality_state() {
    install -m 600 /dev/null "${XRAY_STATE}.new"
    printf 'R_UUID=%q\nR_PRIV=%q\nR_PUB=%q\nR_SID=%q\nR_SITE=%q\n' \
        "${R_UUID}" "${R_PRIV}" "${R_PUB}" "${R_SID}" "${R_SITE}" > "${XRAY_STATE}.new"
    if [[ -n "${R_STATS_PORT}" ]]; then printf 'R_STATS_PORT=%q\n' "${R_STATS_PORT}" >> "${XRAY_STATE}.new"; fi
    if [[ -n "${R_ADMIN_UUID}" ]]; then printf 'R_ADMIN_UUID=%q\n' "${R_ADMIN_UUID}" >> "${XRAY_STATE}.new"; fi
    mv -f "${XRAY_STATE}.new" "${XRAY_STATE}"
}

# ---- Home-network (MTS) probe results ---------------------------------------
# keenetic-vpn-probe.sh signs its results with HMAC-SHA256 (RFC 2104); the key is
# the 32-byte PROBE_KEY of this server's probe profile. Per server it sends one
# line per test and a run header that binds them (count and SHA-256 of all lines):
#   v2|epoch|run_id|server_ip|wan|test|sni|port|route|status|ok/attempts|median_ms|payload_bytes|error
#   v2run|epoch|run_id|server_ip|wan|count|sha256
# A run is taken whole or not at all, and only once (no replays, no dropped lines).
# Only these lines are used; the rest of the JSON is for people.
MTS_RECORD_RE='^v2\|[0-9]{9,11}\|[0-9a-f]{16}\|[0-9.]{7,15}\|[A-Za-z0-9_.-]{1,15}\|(reality|reality_trial|hysteria2|tt_h2|tt_h3)\|[A-Za-z0-9.-]{1,253}\|[0-9]{1,5}\|(verified|route_unverified)\|(ok|fail|degraded|skipped)\|[0-9]{1,3}/[0-9]{1,3}\|[0-9]{1,7}\|[0-9]{1,12}\|[a-z0-9_]{0,40}$'
MTS_HEADER_RE='^v2run\|[0-9]{9,11}\|[0-9a-f]{16}\|[0-9.]{7,15}\|[A-Za-z0-9_.-]{1,15}\|[0-9]{1,3}\|[0-9a-f]{64}$'

# HMAC-SHA256 with sha256sum only (the key never appears in a command line).
# $1 = key in hex (at most 64 bytes), $2 = message. Prints the hex digest.
hmac_sha256_hex() {
    local key="$1" ipad="" opad="" inner i b
    while (( ${#key} < 128 )); do key+="0"; done
    for (( i = 0; i < 128; i += 2 )); do
        b=$(( 16#${key:i:2} ))
        printf -v ipad '%s\\x%02x' "${ipad}" $(( b ^ 0x36 ))
        printf -v opad '%s\\x%02x' "${opad}" $(( b ^ 0x5c ))
    done
    inner="$({ printf '%b' "${ipad}"; printf '%s' "$2"; } | sha256sum | cut -c1-64)"
    { printf '%b' "${opad}"; printf '%b' "$(sed 's/../\\x&/g' <<<"${inner}")"; } | sha256sum | cut -c1-64
}

# $1 = test, $2 = SNI -> ok|fail|degraded|stalled|route_unverified|stale|untested
# The newest result counts ("skipped" is no result); on the same time the worse one wins.
# stalled = a degraded result whose error is payload_stalled_<N>kb: the tunnel connects, but
# transfers freeze after a few KB (the TSPU 16-20 KB cut-off). Older probes wrote
# payload_stalled_rc<N>; those stay plain "degraded".
mts_status() {
    local line ts route status err now
    if [[ ! -s "${MTS_RECORDS}" ]]; then printf 'untested'; return 0; fi
    line="$(awk -F'|' -v t="$1" -v s="$2" '
        $1 == "v2" && ($6 == t || (t == "reality" && $6 == "reality_trial")) && $7 == s && $10 != "skipped" {
            rank = ($10 == "ok" ? 0 : ($10 == "degraded" ? 1 : 2)) + ($9 == "verified" ? 0 : 3)
            print $2, rank, $9, $10, $14 }' "${MTS_RECORDS}" | sort -k1,1n -k2,2n | tail -n 1 || true)"
    if [[ -z "${line}" ]]; then printf 'untested'; return 0; fi
    read -r ts _ route status err <<<"${line}"
    now="$(date +%s)"
    if (( now - 10#${ts} > MTS_MAX_AGE_DAYS * 86400 )); then printf 'stale'
    elif [[ "${route}" != "verified" ]]; then printf 'route_unverified'
    elif [[ "${status}" == "degraded" && "${err:-}" =~ ^payload_stalled_[0-9]+kb$ ]]; then printf 'stalled'
    else printf '%s' "${status}"; fi
    return 0
}

# $1 = file or "-" (stdin)
mts_import() {
    local src="$1" i n hdr hmac f_ts f_run f_ip f_wan f_n f_hash rec mac now ok
    local acc=0 runs=0 manual=0 bad=0 other=0 stale=0 invalid=0 dup=0
    command -v jq >/dev/null 2>&1 || die "jq is missing: run the installer once (bash $0) first."
    load_probe_env
    [[ -n "${PROBE_KEY}" ]] || die "this server has no probe key yet: run the installer once (bash $0) first."
    if [[ "${src}" == "-" ]]; then cat > "${TMPD}/mts.json"; else cp -- "${src}" "${TMPD}/mts.json"; fi
    # tolerate a UTF-8 BOM and CRLF from Windows copies
    sed -i '1s/^\xEF\xBB\xBF//; s/\r$//' "${TMPD}/mts.json"
    jq -e '.schema == "veiltrium-probe/1" or .schema == "hy2-vpn-probe/1"' "${TMPD}/mts.json" >/dev/null 2>&1 \
        || die "not a keenetic-vpn-probe.sh result (schema veiltrium-probe/1 expected)."
    now="$(date +%s)"
    install -d -m 700 "${STATE_DIR}"
    touch "${MTS_RECORDS}" "${MTS_RUNS}"; chmod 600 "${MTS_RECORDS}" "${MTS_RUNS}"
    n="$(jq '.servers | length' "${TMPD}/mts.json" 2>/dev/null || echo 0)"
    [[ "${n}" =~ ^[0-9]+$ ]] || n=0
    for (( i = 0; i < n; i++ )); do
        hdr="$(jq -r ".servers[${i}].run.h // \"\"" "${TMPD}/mts.json")"
        hmac="$(jq -r ".servers[${i}].run.mac // \"\"" "${TMPD}/mts.json")"
        jq -r ".servers[${i}].records[]? | [(.r // \"\"), (.mac // \"\")] | @tsv" "${TMPD}/mts.json" > "${TMPD}/mts-run.tsv"
        if [[ ! "${hdr}" =~ ${MTS_HEADER_RE} ]]; then invalid=$((invalid + 1)); continue; fi
        IFS='|' read -r _ f_ts f_run f_ip f_wan f_n f_hash <<<"${hdr}"
        if [[ "${f_ip}" != "${PROBE_SERVER}" ]]; then other=$((other + 1)); continue; fi
        if [[ "${hmac}" == "none" ]]; then manual=$((manual + 1)); continue; fi
        if [[ ! "${hmac}" =~ ^[0-9a-f]{64}$ || "${hmac}" != "$(hmac_sha256_hex "${PROBE_KEY}" "${hdr}")" ]]; then
            bad=$((bad + 1)); continue
        fi
        if (( 10#${f_ts} < now - MTS_MAX_AGE_DAYS * 86400 || 10#${f_ts} > now + 3600 )); then stale=$((stale + 1)); continue; fi
        if awk -v r="${f_run}" '$1 == r { f = 1 } END { exit !f }' "${MTS_RUNS}"; then dup=$((dup + 1)); continue; fi
        # the lines must be exactly the ones the header was signed over, each signed and well-formed
        cut -f1 "${TMPD}/mts-run.tsv" > "${TMPD}/mts-run.txt"
        ok=1
        if [[ "$(wc -l < "${TMPD}/mts-run.txt")" != "$(( 10#${f_n} ))" || "$(sha256sum < "${TMPD}/mts-run.txt" | cut -c1-64)" != "${f_hash}" ]]; then
            ok=0
        else
            while IFS=$'\t' read -r rec mac; do
                if [[ ! "${rec}" =~ ${MTS_RECORD_RE} || "${rec}" != "v2|${f_ts}|${f_run}|${f_ip}|${f_wan}|"* || \
                      "${mac}" != "$(hmac_sha256_hex "${PROBE_KEY}" "${rec}")" ]]; then
                    ok=0; break
                fi
            done < "${TMPD}/mts-run.tsv"
        fi
        if (( ok == 0 )); then bad=$((bad + 1)); continue; fi
        cat "${TMPD}/mts-run.txt" >> "${MTS_RECORDS}"
        printf '%s %s\n' "${f_run}" "$(( 10#${f_ts} ))" >> "${MTS_RUNS}"
        acc=$((acc + 10#${f_n})); runs=$((runs + 1))
    done
    # keep the files small
    tail -n 500 "${MTS_RECORDS}" > "${MTS_RECORDS}.new"; mv -f "${MTS_RECORDS}.new" "${MTS_RECORDS}"; chmod 600 "${MTS_RECORDS}"
    # run ids are kept as long as their results could still be accepted (age window + 1 day)
    awk -v min="$(( now - (MTS_MAX_AGE_DAYS + 1) * 86400 ))" 'NF == 2 && $2 >= min' "${MTS_RUNS}" > "${MTS_RUNS}.new"
    mv -f "${MTS_RUNS}.new" "${MTS_RUNS}"; chmod 600 "${MTS_RUNS}"
    if (( runs > 0 )); then
        install -m 600 "${TMPD}/mts.json" "${MTS_LAST_IMPORT}"
    fi
    info "Home-network probe results for ${PROBE_SERVER}: ${runs} run(s), ${acc} result lines accepted (signed by this server's probe profile)"
    if (( other > 0 )); then info "${other} for other servers (import the same file on each server)"; fi
    if (( dup > 0 )); then info "${dup} run(s) imported before: ignored (no replays)"; fi
    if (( manual > 0 )); then warn "${manual} unsigned run(s): not used"; fi
    if (( bad > 0 )); then warn "${bad} run(s) with a wrong signature, or lines added, removed or changed: rejected"; fi
    if (( stale > 0 )); then warn "${stale} run(s) older than ${MTS_MAX_AGE_DAYS} days or from the future: rejected"; fi
    if (( invalid > 0 )); then warn "${invalid} malformed run(s) (or from an older probe version): rejected"; fi
    (( runs > 0 || dup > 0 ))
}

# ---- Reality trial (extra server names for a home-network probe) ------------
trial_active() { [[ -f "${TRIAL_DROPIN}" ]]; }

# Ends a trial now (also called by the timer, by the next installer run, and at boot nothing
# is left: the drop-in and the config live in /run).
trial_stop() {
    systemctl stop "${TRIAL_UNIT}.timer" >/dev/null 2>&1 || true
    if trial_active || [[ -f "${TRIAL_CONFIG}" ]]; then
        traffic_collect   # the restart resets Xray's counters
        rm -f "${TRIAL_DROPIN}" "${TRIAL_CONFIG}" "${TRIAL_ENV}"
        systemctl daemon-reload
        systemctl restart xray.service || true
        ok "Reality trial ended: the production settings are back."
    fi
    return 0
}

trial_start() {
    local sites="$1" site s
    local -a extra=()
    [[ "${TRIAL_MINUTES}" =~ ^[0-9]{1,3}$ ]] && (( TRIAL_MINUTES >= 5 && TRIAL_MINUTES <= 240 )) \
        || die "--trial-minutes must be 5..240."
    [[ -n "${R_SITE}" && -s "${XRAY_DIR}/config.json" ]] || die "VLESS Reality is not installed or has no site."
    systemctl is-active --quiet xray.service || die "the xray service is not running."
    IFS=',' read -r -a extra <<<"${sites}"
    (( ${#extra[@]} >= 1 && ${#extra[@]} <= 5 )) || die "give 1 to 5 sites: --trial-reality a.com,b.com"
    for s in "${extra[@]}"; do
        [[ "${s}" =~ ${DOMAIN_RE} ]] || die "not a domain name: ${s}"
        [[ "${s}" != "${R_SITE}" ]] || die "${s} is already the production site."
    done
    trial_stop
    TRIAL_STARTING=1
    info "Checking the sites on this server first (isolated, production untouched):"
    for site in "${extra[@]}"; do
        prescreen_site "${site}"
        [[ "${PS_GATE}" == "pass" ]] || die "${site}: ${PS_REASON}"
        reality_isolated_test "${site}"
        [[ "${RT_STATUS}" == "ok" ]] || die "${site}: ${RT_REASON}"
        ok "${site}: TLS ${PS_TLS_MED} ms, Reality ${RT_MED} ms"
    done
    install -d -m 750 -o root -g xray "${RUN_DIR}"
    install -m 640 -o root -g xray /dev/null "${TRIAL_CONFIG}"
    reality_server_json "${TRIAL_CONFIG}" "" "${REALITY_PORT}" "${R_SITE}" "${extra[@]}"
    "${XRAY_BIN}" run -test -c "${TRIAL_CONFIG}" >"${TMPD}/xray-test.log" 2>&1 \
        || { tail -5 "${TMPD}/xray-test.log"; rm -f "${TRIAL_CONFIG}"; die "Xray rejected the trial config."; }
    # The production config is not changed: the trial runs from /run through a runtime drop-in,
    # so a reboot ends it as well.
    cat > "${TRIAL_END}" <<EOF
#!/bin/sh
# veiltrium: end of a Reality trial
rm -f "${TRIAL_DROPIN}" "${TRIAL_CONFIG}" "${TRIAL_ENV}"
systemctl daemon-reload
systemctl restart xray.service
EOF
    chmod 700 "${TRIAL_END}"
    # The end is scheduled first: if this run is killed at any later point, the timer still
    # ends the trial (and a reboot ends it too: everything lives in /run).
    systemctl reset-failed "${TRIAL_UNIT}.timer" "${TRIAL_UNIT}.service" >/dev/null 2>&1 || true
    if ! systemd-run --quiet --unit="${TRIAL_UNIT}" --on-active="${TRIAL_MINUTES}m"             --timer-property=AccuracySec=10s --description="End of the Veiltrium Reality trial"             /bin/sh "${TRIAL_END}"; then
        rm -f "${TRIAL_CONFIG}"
        die "could not schedule the end of the trial; nothing was changed."
    fi
    install -d -m 755 "${TRIAL_DROPIN_DIR}"
    printf '# veiltrium: Reality trial (ends by itself)
[Service]
ExecStart=
ExecStart=%s run -c %s
'         "${XRAY_BIN}" "${TRIAL_CONFIG}" > "${TRIAL_DROPIN}.new"
    mv -f "${TRIAL_DROPIN}.new" "${TRIAL_DROPIN}"
    systemctl daemon-reload
    traffic_collect   # the restart resets Xray's counters
    systemctl restart xray.service || true
    for site in "${R_SITE}" "${extra[@]}"; do
        reality_verify_production "${site}"
        if [[ "${RP_STATUS}" != "ok" ]]; then
            trial_stop
            die "with the trial config, ${site} did not work on port ${REALITY_PORT}; trial ended, production restored."
        fi
    done
    printf 'TRIAL_SITES=%q\nTRIAL_UNTIL=%q\n' "${extra[*]}" "$(( $(date +%s) + TRIAL_MINUTES * 60 ))" > "${TRIAL_ENV}"
    TRIAL_STARTING=0
    ok "Trial running for ${TRIAL_MINUTES} min: port ${REALITY_PORT} also accepts SNI ${extra[*]}"
    info "Production SNI ${R_SITE} keeps working; the target stays ${R_SITE}, so during the trial a"
    info "prober using a trial SNI gets the certificate of ${R_SITE} (a mismatch). Keep trials short."
    info "On the router (home network):  sh keenetic-vpn-probe.sh --reality --trial-sni $(IFS=,; echo "${extra[*]}") --output /opt/tmp/vpn-probe.json"
    info "End it now:  bash $0 --trial-stop"
}

# A name for Hysteria or TrustTunnel that is NOT one of $@ (the Reality site, the
# other protocol's name): their certificates are self-signed, so the name only has to
# be a plausible, reachable, non-blocked site. Deterministic: the first candidate in
# list order that passed the direct checks in this run, else the first that passes
# them now, else the first one not avoided.
pick_independent_sni() {
    local s
    local -a order=()
    if [[ -s "${TMPD}/selection.tsv" ]]; then
        mapfile -t order < <(awk -F'\t' '$7 > 0 { print $2, $1 }' "${TMPD}/selection.tsv" | sort -n -k1,1 | awk '{ print $2 }')
        for s in "${order[@]+"${order[@]}"}"; do
            if ru_blocked "${s}"; then continue; fi
            [[ " $* " == *" ${s} "* ]] || { printf '%s' "${s}"; return 0; }
        done
    fi
    for s in "${CAND_LIST[@]}"; do
        [[ " $* " == *" ${s} "* ]] && continue
        if ru_blocked "${s}"; then continue; fi
        prescreen_site "${s}"
        if [[ "${PS_GATE}" == "pass" ]]; then printf '%s' "${s}"; return 0; fi
    done
    for s in "${CAND_LIST[@]}"; do
        [[ " $* " == *" ${s} "* ]] || { printf '%s' "${s}"; return 0; }
    done
    for s in "${CAND_LIST[@]}"; do
        [[ "${s}" == "${1:-}" ]] || { printf '%s' "${s}"; return 0; }
    done
    # a one-site list: nothing else to choose (reported in step 10/11)
    printf '%s' "${CAND_LIST[0]}"
    return 0
}

# ---- What Russia sees ----------------------------------------------------------
# Domains blocked by the RKN (public curated lists). Sets RU_BL_STATE (ok|unchecked);
# ${TMPD}/ru-blocked holds one lower-case domain per line.
load_ru_blocklist() {
    local u
    RU_BL_STATE="unchecked"
    : > "${TMPD}/ru-blocked"
    for u in ${RU_BLOCKLISTS}; do
        if curl -fsSL --proto '=https' --max-time 30 --max-filesize 20000000 "${u}" -o "${TMPD}/ru-list" 2>/dev/null; then
            tr 'A-Z' 'a-z' < "${TMPD}/ru-list" | sed 's/\r$//; s/^\.//; s/^[[:space:]]*//; s/[[:space:]]*$//' \
                | grep -E '^[a-z0-9.-]+$' >> "${TMPD}/ru-blocked" || true
        fi
    done
    rm -f "${TMPD}/ru-list"
    if [[ "$(wc -l < "${TMPD}/ru-blocked")" -ge 50 ]]; then RU_BL_STATE="ok"; else : > "${TMPD}/ru-blocked"; fi
    return 0
}

# $1 = domain: true if it or a parent domain is on the list (call it in an if).
ru_blocked() {
    local d="${1,,}"
    [[ -s "${TMPD}/ru-blocked" ]] || return 1
    while :; do
        if grep -qxF "${d}" "${TMPD}/ru-blocked"; then return 0; fi
        [[ "${d}" == *.* ]] || return 1
        d="${d#*.}"
    done
}

# Globalping (https://globalping.io): probes in Russian networks ping the server's address
# (ICMP) and connect to its TCP ports. Two probes at MTS, two at Rostelecom (home providers),
# four anywhere in Russia. A ban of the address shows as no answer at all. It says nothing
# about the protocols themselves (DPI): that shows only in a real client.
GLOBALPING_API="https://api.globalping.io/v1/measurements"
GP_LOCATIONS='[{"asn":8359,"limit":2},{"asn":12389,"limit":2},{"country":"RU","limit":4}]'

gp_start() {   # $1 = ICMP|TCP, $2 = port (TCP) -> prints the measurement id, nothing on failure
    local body
    body="$(jq -nc --arg ip "${PUBLIC_IP}" --argjson loc "${GP_LOCATIONS}" --arg proto "$1" --arg port "${2:-0}" \
        '{type: "ping", target: $ip, locations: $loc,
          measurementOptions: ({packets: 3} + (if $proto == "TCP" then {protocol: "TCP", port: ($port | tonumber)} else {} end))}')"
    curl -fsS --proto '=https' --connect-timeout 10 --max-time 20 -X POST -H 'Content-Type: application/json' -d "${body}" "${GLOBALPING_API}" 2>/dev/null \
        | jq -r '.id // empty' 2>/dev/null || true
    return 0
}

GP_DEADLINE=0   # SECONDS value by which all the waits of one check must be over
gp_wait() {   # $1 = id, $2 = file for the finished measurement (left absent if it never finishes)
    [[ "$1" =~ ^[A-Za-z0-9_-]{8,64}$ ]] || return 0
    while (( SECONDS < GP_DEADLINE )); do
        if curl -fsS --proto '=https' --connect-timeout 10 --max-time 15 "${GLOBALPING_API}/$1" -o "$2.tmp" 2>/dev/null \
            && jq -e '.status == "finished"' "$2.tmp" >/dev/null 2>&1; then
            mv -f "$2.tmp" "$2"
            return 0
        fi
        sleep 2
    done
    rm -f "$2.tmp"
    return 0
}

# The summary of the finished measurements (files; absent = not run) as JSON on stdout.
# $1 = ICMP, $2 = TCP to the Reality port, $3 = TCP to the TrustTunnel port, $4 / $5 = those ports.
russia_summary() {
    jq -n --arg now "$(date -u +%FT%TZ)" --arg server "${PUBLIC_IP}" --arg rport "${4:-0}" --arg tport "${5:-0}" \
        --argjson icmp "$(cat "$1" 2>/dev/null || echo null)" \
        --argjson tr "$(cat "$2" 2>/dev/null || echo null)" \
        --argjson tt "$(cat "$3" 2>/dev/null || echo null)" '
        def probes($m): if $m == null then [] else
            [$m.results[]? | {network: (.probe.network // "?"), asn: .probe.asn, city: (.probe.city // ""),
                              ok: ((.result.stats.rcv // 0) > 0)}] end;
        def tally($m): probes($m) | {ok: (map(select(.ok)) | length), total: length, probes: .};
        {schema: "veiltrium-russia/1", checked_at: $now, server: $server, source: "Globalping (globalping.io)",
         icmp: tally($icmp),
         tcp_reality: (if $tr == null then null else tally($tr) + {port: ($rport | tonumber)} end),
         tcp_trusttunnel: (if $tt == null then null else tally($tt) + {port: ($tport | tonumber)} end)}
        | ([.icmp, .tcp_reality, .tcp_trusttunnel] | map(select(. != null))) as $all
        | . + {networks: ([$all[].probes[].network] | unique),
               verdict: (if ($all | map(.total) | add // 0) == 0 then "unchecked"
                         elif ($all | map(.ok) | add) == 0 then "blocked"
                         elif ($all | all(.ok == .total)) then "reachable"
                         else "partly" end)}'
}

# $1 = the saved russia.json (may be absent), $2 = a new result -> the new result with
# previous_verdict and bad_streak: checks in a row that were partly or blocked (reachable
# resets it; unchecked, where Globalping did not answer, keeps it).
russia_streak_merge() {
    local old
    old="$(jq -c . "$1" 2>/dev/null || true)"
    jq --argjson old "${old:-null}" '
        . + {previous_verdict: ($old.verdict // null),
             bad_streak: (if .verdict == "reachable" then 0
                          elif .verdict == "unchecked" then ($old.bad_streak // 0)
                          else (($old.bad_streak // 0) + 1) end)}' "$2"
}

# Runs the check (GLOBALPING=1 or $1 = force), saves ${RUSSIA_FILE}, prints one line.
# Sets RU_VERDICT (reachable|partly|blocked|unchecked|off).
russia_check() {
    local id_i id_r="" id_t="" rport="" tport="" line
    RU_VERDICT="off"
    if [[ "${GLOBALPING}" != "1" && "${1:-}" != "force" ]]; then
        info "Reachability from Russia: not checked (GLOBALPING=0)"
        return 0
    fi
    rm -f "${TMPD}"/gp-*.json
    GP_DEADLINE=$(( SECONDS + 120 ))   # the probes answer within seconds; a stalled API does not hold the install
    id_i="$(gp_start ICMP)"
    if [[ -n "${R_SITE:-}" ]]; then rport="${REALITY_PORT}"; id_r="$(gp_start TCP "${rport}")"; fi
    if [[ -n "${T_SNI:-}" && "${TT_ENABLE}" == "1" ]]; then tport="${TT_PORT}"; id_t="$(gp_start TCP "${tport}")"; fi
    gp_wait "${id_i}" "${TMPD}/gp-icmp.json"
    if [[ -n "${id_r}" ]]; then gp_wait "${id_r}" "${TMPD}/gp-tcp-r.json"; fi
    if [[ -n "${id_t}" ]]; then gp_wait "${id_t}" "${TMPD}/gp-tcp-t.json"; fi
    russia_summary "${TMPD}/gp-icmp.json" "${TMPD}/gp-tcp-r.json" "${TMPD}/gp-tcp-t.json" "${rport}" "${tport}" \
        > "${TMPD}/russia.json" || true
    RU_VERDICT="$(jq -r '.verdict // "unchecked"' "${TMPD}/russia.json" 2>/dev/null || echo unchecked)"
    install -d -m 700 "${STATE_DIR}"
    # A check that got no answer from the API (down, rate limit) does not replace the last real result.
    if [[ -s "${TMPD}/russia.json" ]] && { [[ "${RU_VERDICT}" != "unchecked" ]] || [[ ! -s "${RUSSIA_FILE}" ]]; }; then
        if russia_streak_merge "${RUSSIA_FILE}" "${TMPD}/russia.json" > "${TMPD}/russia.merged" 2>/dev/null && [[ -s "${TMPD}/russia.merged" ]]; then
            mv -f "${TMPD}/russia.merged" "${TMPD}/russia.json"
        fi
        install -m 600 "${TMPD}/russia.json" "${RUSSIA_FILE}"
        if (( A_ENABLED == 1 )) && [[ "${RU_VERDICT}" != "unchecked" ]]; then
            alert_russia_eval "${RU_VERDICT}" "$(jq -r '.bad_streak // 0' "${RUSSIA_FILE}" 2>/dev/null || echo 0)" \
                "$(jq -r '(.networks // []) | join(", ")' "${RUSSIA_FILE}" 2>/dev/null || true)"
        fi
    fi
    line="$(jq -r '"ping \(.icmp.ok)/\(.icmp.total)"
        + (if .tcp_reality then ", TCP \(.tcp_reality.port) \(.tcp_reality.ok)/\(.tcp_reality.total)" else "" end)
        + (if .tcp_trusttunnel then ", TCP \(.tcp_trusttunnel.port) \(.tcp_trusttunnel.ok)/\(.tcp_trusttunnel.total)" else "" end)
        + " (" + (.networks | join(", ")) + ")"' "${TMPD}/russia.json" 2>/dev/null || true)"
    case "${RU_VERDICT}" in
        reachable) ok "Reachable from Russia (Globalping probes): ${line}" ;;
        partly) ok "Reachable from Russia, with some probes failing: ${line}" ;;
        blocked)
            warn "NOT reachable from any Russian network (Globalping): ${line}"
            warn "The server's address looks blocked in Russia: ask the hoster for another IP address." ;;
        *) info "Reachability from Russia: not checked (Globalping did not answer; try later: bash $0 --check-russia)" ;;
    esac
    return 0
}

# ---- Report (no secrets) ----------------------------------------------------
# Writes the report JSON to stdout from the global R_*/H_*/T_* results.
build_report() {
    local sel='null'
    if [[ -s "${TMPD}/selection.json" ]]; then sel="$(cat "${TMPD}/selection.json")"
    elif [[ -s "${SELECTION_FILE}" ]]; then sel="$(cat "${SELECTION_FILE}")"; fi
    jq -n --arg now "$(date -u +%FT%TZ)" --arg version "${SCRIPT_VERSION}" --arg mode "${MODE}" \
        --arg server "${PUBLIC_IP:-}" --arg label "${LABEL}" --arg n_clients "${#CL_NAMES[@]}" --arg standby "${N_STANDBY}" \
        --arg h_auth "${H_AUTH:-}" \
        --arg r_enabled "${REALITY_ENABLE}" --arg r_site "${R_SITE:-}" --arg r_port "${REALITY_PORT}" \
        --arg r_vps "${REALITY_VPS:-untested}" --arg r_fallback "${RP_FALLBACK:-untested}" \
        --arg r_mts "$(mts_status reality "${R_SITE:-none}")" --arg r_decision "${R_DECISION:-}" \
        --arg r_top3 "${R_TOP3:-}" --arg r_cand_source "${CAND_SOURCE:-}" \
        --arg h_sni "${HY2_SNI:-${H_SNI:-}}" --arg h_port "${HY2_PORT}" --arg h_masq "${HY2_MASQ_URL:-}" \
        --arg h_masq_mode "${H_MASQ:-}" --arg h_cert_sha "${CERT_SHA:-}" --arg h_spki "${PK_SHA:-}" \
        --arg h_not_after "${H_NOT_AFTER:-}" --arg h_vps "${HY2_VPS:-untested}" \
        --arg h_mts "$(mts_status hysteria2 "${HY2_SNI:-${H_SNI:-none}}")" \
        --arg t_enabled "${TT_ENABLE}" --arg t_sni "${T_SNI:-}" --arg t_port "${TT_PORT}" \
        --arg t_cert_sha "${TT_CERT_SHA:-}" --arg t_h2 "${TT_VPS_H2:-untested}" --arg t_h3 "${TT_VPS_H3:-untested}" \
        --arg t_mts_h2 "$(mts_status tt_h2 "${T_SNI:-none}")" --arg t_mts_h3 "$(mts_status tt_h3 "${T_SNI:-none}")" \
        --arg changes "$(printf '%s\n' "${CHANGES[@]+"${CHANGES[@]}"}")" \
        --arg links "$(printf '%s\n' "${LINKS_CHANGED[@]+"${LINKS_CHANGED[@]}"}")" \
        --arg rollbacks "$(printf '%s\n' "${ROLLBACKS[@]+"${ROLLBACKS[@]}"}")" \
        --argjson selection "${sel}"         --argjson russia "$(jq -c '{verdict, checked_at, networks, bad_streak: (.bad_streak // 0)}' "${RUSSIA_FILE}" 2>/dev/null || echo null)" '
        def lines: split("\n") | map(select(length > 0));
        def proof($vps; $mts): {vps_verified: ($vps == "verified" or $vps == "ok"), vps: $vps,
            mts_verified: ($mts == "ok"), mts: $mts};
        {
          schema: "veiltrium-report/1", generated_at: $now, script_version: $version, mode: $mode,
          server: $server, node_name: $label, standby: ($standby | split(",") | map(select(length > 0))),
          clients: {added: ($n_clients | tonumber), hysteria_auth: $h_auth},
          reality:(if $r_enabled == "1" then ({
              sni: $r_site, port: ($r_port | tonumber), candidates_source: $r_cand_source,
              decision: $r_decision, top3: ($r_top3 | split(" ") | map(select(length > 0))),
              fallback_real_certificate: $r_fallback, selection: $selection
            } + proof($r_vps; $r_mts)) else {enabled: false} end),
          hysteria2: ({
              sni: $h_sni, port: ($h_port | tonumber), tls_mode: "self_signed_pinned",
              certificate_sha256: $h_cert_sha, public_key_sha256_base64: $h_spki, certificate_not_after: $h_not_after,
              masquerade: {type: "proxy", url: $h_masq, mode: $h_masq_mode,
                note: "HTTP/3 masquerade behind a self-signed certificate: an active prober sees that the certificate is not the real one"},
              awg_manager_note: "AWG Manager ignores pinSHA256 in hysteria2:// links and connects without certificate verification; import the sing-box JSON (section 6 of the client file) instead"
            } + proof($h_vps; $h_mts)),
          trusttunnel: (if $t_enabled == "1" then {
              hostname: $t_sni, port: ($t_port | tonumber), tls_mode: "self_signed_embedded_in_link",
              certificate_sha256: $t_cert_sha,
              h2: proof($t_h2; $t_mts_h2), h3: proof($t_h3; $t_mts_h3)
            } else {enabled: false} end),
          reachable_from_russia: $russia,
          changes: ($changes | lines), links_to_update: ($links | lines), rollbacks: ($rollbacks | lines)
        }'
}

# ---- Hysteria and TrustTunnel checks (shared by the install and --diagnose) -
# A real Hysteria client with certificate pinning. Sets HY2_E2E (0 ok), PROXY_LOCAL_RC.
hy2_client_test() {   # $1 = SNI, $2 = pinSHA256 (hex), $3 = auth string (default: the main client)
    local sport
    sport="$(free_port)"
    install -m 600 /dev/null "${TMPD}/client.yaml"
    cat > "${TMPD}/client.yaml" <<EOF
server: 127.0.0.1:${HY2_PORT}
auth: $(yaml_sq "${3:-${HY2_AUTH_MAIN}}")
tls:
  sni: $1
  insecure: true
  pinSHA256: $2
socks5:
  listen: 127.0.0.1:${sport}
EOF
    HYSTERIA_DISABLE_UPDATE_CHECK=true setpriv --pdeathsig KILL -- "${HY2_BIN}" client -c "${TMPD}/client.yaml" >"${TMPD}/client.log" 2>&1 7>&- 9>&- &
    CLIENT_PID=$!
    wait_tcp_port "${sport}" || true
    HY2_E2E=0
    tunnel_probe "${sport}" 1
    (( TP_OK == 1 )) || HY2_E2E=1
    PROXY_LOCAL_RC=0
    curl -s -o /dev/null --max-time 8 --socks5-hostname "127.0.0.1:${sport}" \
        "http://127.0.0.1:${SSH_PORTS[0]}/" || PROXY_LOCAL_RC=$?
    stop_pid "${CLIENT_PID}"; CLIENT_PID=""
    rm -f "${TMPD}/client.yaml"
    return 0
}

# TrustTunnel must present exactly its pinned certificate: over TCP (HTTP/2) and,
# where OpenSSL can speak QUIC (3.5+, Ubuntu 26.04), over UDP (HTTP/3).
# Sets TT_VPS_H2 and TT_VPS_H3 (ok|fail|untested).
tt_checks() {
    local own peer
    TT_VPS_H2="fail"; TT_VPS_H3="untested"
    own="$(openssl x509 -in "${TT_DIR}/cert.pem" -noout -fingerprint -sha256 2>/dev/null || true)"
    peer="$(timeout 20 openssl s_client -connect "127.0.0.1:${TT_PORT}" -servername "${T_SNI}" -alpn h2 \
        </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)"
    if [[ -n "${peer}" && "${peer}" == "${own}" ]]; then TT_VPS_H2="ok"; fi
    if openssl s_client -help 2>&1 | grep -E '^[[:space:]]*-quic' >/dev/null; then
        peer="$(timeout 20 openssl s_client -quic -connect "127.0.0.1:${TT_PORT}" -servername "${T_SNI}" -alpn h3 \
            </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256 2>/dev/null || true)"
        if [[ -n "${peer}" && "${peer}" == "${own}" ]]; then TT_VPS_H3="ok"; else TT_VPS_H3="fail"; fi
    fi
    return 0
}

# ---- Connection details of the clients --------------------------------------
# Credentials of client $1 ("main" or an added one). Sets CC_USER (empty with one shared
# Hysteria password), CC_PASS, CC_AUTH (the Hysteria auth string), CC_UUID, CC_CREATED.
client_creds() {
    local i
    CC_USER=""; CC_CREATED=""
    if [[ "$1" == "main" ]]; then
        CC_PASS="${H_PASSWORD}"; CC_UUID="${R_UUID}"
        if [[ "${H_AUTH}" == "userpass" ]]; then CC_USER="main"; fi
    else
        i="$(client_index "$1")"
        [[ -n "${i}" ]] || die "no client $1."
        CC_USER="$1"; CC_PASS="${CL_HPASS[i]}"; CC_UUID="${CL_UUID[i]}"; CC_CREATED="${CL_CREATED[i]}"
    fi
    CC_AUTH="${CC_PASS}"
    if [[ -n "${CC_USER}" ]]; then CC_AUTH="${CC_USER}:${CC_PASS}"; fi
    return 0
}

vless_link() {   # $1 = UUID, $2 = server (default: this node), $3 = link name (default: the node name)
    printf 'vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=tcp#%s' \
        "$1" "${2:-${HOST}}" "${REALITY_PORT}" "${R_SITE}" "${REALITY_FP}" "${R_PUB}" "${R_SID}" "$(url_encode "${3:-${LABEL}}")"
}

# ---- sing-box outbound texts (one template each: the main server and every standby) -----
# $1 = server, $2 = tag, $3 = JSON-escaped Hysteria password.
hy2_outbound_text() {
    cat <<EOF
{
  "type": "hysteria2",
  "tag": "$2",
  "server": "$1",
  "server_port": ${HY2_PORT},
  "password": "$3",
  "tls": {
    "enabled": true,
    "server_name": "${HY2_SNI}",
    "insecure": false,
    "certificate_public_key_sha256": ["${PK_SHA}"]
  }
}
EOF
}

# $1 = server, $2 = tag, $3 = UUID.
vless_outbound_text() {
    cat <<EOF
{
  "type": "vless",
  "tag": "$2",
  "server": "$1",
  "server_port": ${REALITY_PORT},
  "uuid": "$3",
  "flow": "xtls-rprx-vision",
  "tls": {
    "enabled": true,
    "server_name": "${R_SITE}",
    "utls": {"enabled": true, "fingerprint": "${REALITY_FP}"},
    "reality": {"enabled": true, "public_key": "${R_PUB}", "short_id": "${R_SID}"}
  }
}
EOF
}

# One entry of the AWG Manager server group (section 6): $1 = server, $2 = tag, $3 = JSON-escaped password.
awg_entry_text() {
    cat <<EOF
  {
    "type": "hysteria2",
    "tag": "$2",
    "server": "$1",
    "server_port": ${HY2_PORT},
    "password": "$3",
    "tls": {
      "enabled": true,
      "server_name": "${HY2_SNI}",
      "certificate_public_key_sha256": ["${PK_SHA}"]
    }
  }
EOF
}

# sing-box urltest group: $1 = tag, the other arguments are the outbound tags it chooses from.
urltest_text() {
    local tag="$1" list="" t
    shift
    for t in "$@"; do list+="${list:+, }\"${t}\""; done
    cat <<EOF
{
  "type": "urltest",
  "tag": "${tag}",
  "outbounds": [${list}],
  "url": "https://www.gstatic.com/generate_204",
  "interval": "3m",
  "tolerance": 50
}
EOF
}

# A JSON array of the objects given as arguments (each one a multi-line text).
json_objects_text() {
    local it first=1
    printf '[\n'
    for it in "$@"; do
        if (( first == 0 )); then printf ',\n'; fi
        first=0
        printf '%s' "$(printf '%s\n' "${it}" | sed 's/^/  /')"
    done
    printf '\n]\n'
}

# The standby outbounds and the urltest group as a JSON array (client file, section 2 and 4).
standby_outbounds_text() {   # $1 = hy2 | reality, $2 = main tag, $3 = JSON-escaped password or UUID
    local i objs=() tags=("$2")
    for (( i = 0; i < ${#STANDBY[@]}; i++ )); do
        tags+=("$2-standby$(( i + 1 ))")
        if [[ "$1" == "hy2" ]]; then objs+=("$(hy2_outbound_text "${STANDBY[i]}" "$2-standby$(( i + 1 ))" "$3")")
        else objs+=("$(vless_outbound_text "${STANDBY[i]}" "$2-standby$(( i + 1 ))" "$3")"); fi
    done
    objs+=("$(urltest_text "Veiltrium-auto-$1" "${tags[@]}")")
    json_objects_text "${objs[@]}"
}

# ---- Subscription and sing-box profile of a client ---------------------------------
# True if client $1 is an added client that is disabled (it has no subscription or profile).
client_is_disabled() {
    local i
    i="$(client_index "$1")"
    [[ -n "${i}" && "${CL_STATE[i]:-}" == "disabled" ]]
}

# The share links of client $1 that a subscription carries, one per line: Hysteria 2 and
# VLESS Reality, the main server first, then the standby servers (TrustTunnel has no
# subscription format, its link stays in the client file).
client_sub_links() {
    local i
    client_creds "$1"
    hy2_link "${CC_USER}" "${CC_PASS}"; printf '\n'
    for (( i = 0; i < ${#STANDBY[@]}; i++ )); do
        hy2_link "${CC_USER}" "${CC_PASS}" "${STANDBY[i]}" "${LABEL}-standby$(( i + 1 ))"; printf '\n'
    done
    if [[ -n "${R_SITE}" ]]; then
        vless_link "${CC_UUID}"; printf '\n'
        for (( i = 0; i < ${#STANDBY[@]}; i++ )); do
            vless_link "${CC_UUID}" "${STANDBY[i]}" "${LABEL}-standby$(( i + 1 ))"; printf '\n'
        done
    fi
    return 0
}

# The subscription of client $1: the links joined by newlines (no trailing one), base64 on one line.
client_sub_b64() {
    printf '%s' "$(client_sub_links "$1")" | base64 -w0
}

# A complete sing-box profile (phones: TUN inbound) of client $1 as JSON (sing-box 1.12+):
# the Hysteria 2 and VLESS Reality outbounds with the standby ones, a urltest group "auto",
# a selector "proxy" (default auto), DNS over HTTPS through the proxy, sniffing and DNS hijack.
client_singbox_profile_json() {
    local jauth i objs=() tags=()
    client_creds "$1"
    jauth="$(json_escape "${CC_AUTH}")"
    objs+=("$(hy2_outbound_text "${HOST}" hy2 "${jauth}")"); tags+=(hy2)
    for (( i = 0; i < ${#STANDBY[@]}; i++ )); do
        objs+=("$(hy2_outbound_text "${STANDBY[i]}" "hy2-standby$(( i + 1 ))" "${jauth}")"); tags+=("hy2-standby$(( i + 1 ))")
    done
    if [[ -n "${R_SITE}" ]]; then
        objs+=("$(vless_outbound_text "${HOST}" reality "${CC_UUID}")"); tags+=(reality)
        for (( i = 0; i < ${#STANDBY[@]}; i++ )); do
            objs+=("$(vless_outbound_text "${STANDBY[i]}" "reality-standby$(( i + 1 ))" "${CC_UUID}")"); tags+=("reality-standby$(( i + 1 ))")
        done
    fi
    jq -n --argjson ob "$(json_objects_text "${objs[@]}")" '
        $ARGS.positional as $tags |
        {log: {level: "warn"},
         dns: {servers: [{type: "https", tag: "remote", server: "1.1.1.1", detour: "proxy"}], final: "remote"},
         inbounds: [{type: "tun", tag: "tun-in", address: ["172.19.0.1/30"], auto_route: true, strict_route: true, stack: "mixed"}],
         outbounds: ($ob + [
           {type: "urltest", tag: "auto", outbounds: $tags, url: "https://www.gstatic.com/generate_204", interval: "3m", tolerance: 50},
           {type: "selector", tag: "proxy", outbounds: (["auto"] + $tags), default: "auto"},
           {type: "direct", tag: "direct"}]),
         route: {rules: [{action: "sniff"}, {protocol: "dns", action: "hijack-dns"}, {ip_is_private: true, outbound: "direct"}],
                 final: "proxy", auto_detect_interface: true}}' --args "${tags[@]}"
}

# Writes $2 (plus $3, a suffix such as a newline) to file $1 (0600) only if it differs.
write_if_changed() {
    if [[ -f "$1" ]] && cmp -s "$1" <(printf '%s%s' "$2" "${3:-}"); then return 0; fi
    install -m 600 /dev/null "$1.new"
    printf '%s%s' "$2" "${3:-}" > "$1.new"
    mv -f "$1.new" "$1"
}

# The subscription ($1.sub) and the sing-box profile ($1.singbox.json) of client $2; a disabled
# client has neither (stale files are removed).
write_client_bundle() {
    if client_is_disabled "$2"; then
        rm -f "$1.sub" "$1.singbox.json"
        return 0
    fi
    write_if_changed "$1.sub" "$(client_sub_b64 "$2")"
    write_if_changed "$1.singbox.json" "$(client_singbox_profile_json "$2")" $'\n'
    return 0
}

# The "Phones and apps" section of a client file. $1 = file base path (details file without .txt), $2 = client.
phones_section_text() {
    local files num=7
    if (( ${#STANDBY[@]} )); then num=8; fi   # section 7 is the standby note
    if client_is_disabled "$2"; then
        files="   (This client is disabled: it has no subscription and no sing-box profile.)"
    else
        files="   Files: $1.singbox.json (sing-box profile), $1.sub (subscription)."
    fi
    cat <<EOF
${num}) Phones and apps
${files}
   - Apps built on sing-box (Hiddify, NekoBox, Karing, sing-box SFA/SFI): import the sing-box
     profile (sing-box 1.12 or newer); the Hysteria certificate pin is checked there.
   - Apps built on Xray (v2rayNG, v2rayN, Happ): paste the subscription (base64) or the links.
     Hysteria 2 support and its certificate pin vary by app: prefer VLESS Reality there.
   - Keenetic router (AWG Manager): VLESS and TrustTunnel by link; Hysteria only as the
     server-group JSON (section 6).
   - If the connection degrades after a few minutes in VPN (TUN) mode on a phone, try the
     app's proxy mode or turn off sniffing.
   - Reality: keep fp=chrome; do not enable TCP Fast Open; do not use fp=random.
EOF
}

# Globals: HOST, HY2_PORT, HY2_SNI, CERT_SHA, PK_SHA, H_AUTH, H_PASSWORD, R_* (R_SITE
# empty: no Reality), REALITY_PORT, REALITY_FP, T_SNI, TT_PORT, LABEL, the clients.
# $1 = client ("main" or an added one), $2 = its tt:// link ("" = none), $3 = its file.
client_details() {
    local name="$1" tt="$2" file="$3" hy_user hy_pass uuid auth jauth reality_text="" tt_text="" foot
    local hy2_obj vless_obj awg_entries hy2_sb_links="" vless_sb_links="" tt_sb_links="" awg_end="" i l dis_text=""
    local phones_text
    i="$(client_index "${name}")"
    if [[ -n "${i}" && "${CL_STATE[i]:-}" == "disabled" ]]; then
        dis_text="$(client_disabled_line "${name}" "${CL_REASON[i]}")"$'\n'
    fi
    client_creds "${name}"
    hy_user="${CC_USER}"; hy_pass="${CC_PASS}"; uuid="${CC_UUID}"; auth="${CC_AUTH}"
    jauth="$(json_escape "${auth}")"
    hy2_obj="$(hy2_outbound_text "${HOST}" hy2 "${jauth}")"
    awg_entries="$(awg_entry_text "${HOST}" Veiltrium "${jauth}")"
    if (( ${#STANDBY[@]} )); then
        hy2_obj+=$'\n\n'"   Standby servers (same ports and secrets): one outbound each and a urltest group that"$'\n'
        hy2_obj+="   picks the fastest working one (tested every 3 min). Add all of them:"$'\n'
        hy2_obj+="$(standby_outbounds_text hy2 hy2 "${jauth}")"
        hy2_sb_links=$'\n'"   Standby servers (same ports and secrets):"
        for (( i = 0; i < ${#STANDBY[@]}; i++ )); do
            hy2_sb_links+=$'\n'"$(hy2_link "${hy_user}" "${hy_pass}" "${STANDBY[i]}" "${LABEL}-standby$(( i + 1 ))")"
            awg_entries+=$',\n'"$(awg_entry_text "${STANDBY[i]}" "Veiltrium-standby$(( i + 1 ))" "${jauth}")"
        done
        awg_end=$'\n\n'"----------------------------------------------------------------------"$'\n'
        awg_end+="7) Standby servers: ${STANDBY[*]}"$'\n'
        awg_end+="   They are assumed to be copies of this node (same ports, passwords, keys and certificate"$'\n'
        awg_end+="   fingerprints; deploy them from an export of this node). The links and configs above include"$'\n'
        awg_end+="   them, so clients can switch if ${HOST} is blocked. After adding or removing clients here,"$'\n'
        awg_end+="   export the node again and re-import it on every standby server."
    fi
    if [[ -n "${R_SITE}" ]]; then   # also when the previous settings were restored: the link stays in the file
        vless_obj="$(vless_outbound_text "${HOST}" reality "${uuid}")"
        if (( ${#STANDBY[@]} )); then
            vless_sb_links=$'\n'"   Standby servers (same ports and secrets):"
            for (( i = 0; i < ${#STANDBY[@]}; i++ )); do
                vless_sb_links+=$'\n'"$(vless_link "${uuid}" "${STANDBY[i]}" "${LABEL}-standby$(( i + 1 ))")"
            done
            vless_obj+=$'\n\n'"   Standby servers: one outbound each and a urltest group (tested every 3 min). Add all of them:"$'\n'
            vless_obj+="$(standby_outbounds_text reality reality "${uuid}")"
        fi
        reality_text="$(cat <<EOF

----------------------------------------------------------------------
VLESS Reality: backup protocol (TCP), masked as ${R_SITE}
Port: ${REALITY_PORT}/TCP. A prober without the key sees the real site ${R_SITE}.
If the site ever changes (--reselect-reality), only sni / server_name changes.

3) VLESS Reality link (v2rayN, Hiddify, NekoBox, v2rayNG, sing-box, AWG Manager):
$(vless_link "${uuid}")${vless_sb_links}

4) VLESS Reality outbound for sing-box (router):
${vless_obj}
EOF
)"
    fi
    if [[ -n "${tt}" ]]; then
        if (( ${#TT_STANDBY_LINKS[@]} )); then
            tt_sb_links=$'\n'"   Standby servers (same ports and secrets):"
            for l in "${TT_STANDBY_LINKS[@]}"; do tt_sb_links+=$'\n'"${l}"; done
        fi
        tt_text="$(cat <<EOF

----------------------------------------------------------------------
TrustTunnel: port ${TT_PORT}/TCP+UDP, hostname ${T_SNI} (self-signed certificate,
embedded in the link; the client checks the server against it)

5) TrustTunnel link (TrustTunnel apps, AWG Manager on the router: HTTP/2 only there):
${tt}${tt_sb_links}
EOF
)"
    fi
    if [[ "${name}" == "main" ]]; then
        foot="$(cat <<EOF
On the server:
  systemctl status hysteria-server xray trusttunnel   service status
  journalctl -u hysteria-server -n 50       Hysteria log
  journalctl -u xray -n 50                  Xray log
  cat ${CLIENT_FILE}                 these details
  bash veiltrium.sh --diagnose     check everything, change nothing
  bash veiltrium.sh --dry-run      would another Reality site be better?
  bash veiltrium.sh --add-client NAME   credentials for one more person or device
  Re-run the script to update or repair the server; the links stay the same.
  VT_RECONFIGURE=1 issues new passwords, keys and certificates (clients must be updated).
EOF
)"
    else
        foot="Revoke this client on the server:  bash veiltrium.sh --remove-client ${name}"
    fi
    phones_text="$(phones_section_text "${file%.txt}" "${name}")"
    cat <<EOF
${dis_text}Veiltrium connection details: node ${LABEL}, client ${name} ($(date '+%Y-%m-%d %H:%M %Z'))
Keep this secret: the links and configs contain passwords and keys.

Server:   ${HOST}
Port:     ${HY2_PORT}/UDP
Password: ${auth}
SNI:      ${HY2_SNI}  (self-signed certificate, the client checks its fingerprint)
Certificate fingerprint (SHA-256):  ${CERT_SHA}
Public key fingerprint (sing-box, base64):  ${PK_SHA}

1) Hysteria 2 link for phone and PC (v2rayN, Hiddify, NekoBox, sing-box):
$(hy2_link "${hy_user}" "${hy_pass}")${hy2_sb_links}
   AWG Manager (Keenetic) ignores pinSHA256 in this link and then connects
   WITHOUT checking the certificate. On the router use section 6 instead.

2) Outbound for sing-box (router). No speed is set: sing-box adapts
   by itself (BBR), which is more reliable than a fixed speed.
${hy2_obj}
${reality_text}
${tt_text}

----------------------------------------------------------------------
6) AWG Manager: add Hysteria with key pinning as a server group
   (server group -> sing-box JSON), paste this whole block:
[
${awg_entries}
]${awg_end}

----------------------------------------------------------------------
${phones_text}

----------------------------------------------------------------------
Copy links without any chat app or Markdown in between (it breaks & and _):
  ssh root@${HOST} "grep -m1 '^vless://' ${file}" | Set-Clipboard     (PowerShell)

${foot}
EOF
}

# TrustTunnel links of the standby servers for user $1 (only if it has a link $2): the
# endpoint builds them for the other address. Sets TT_STANDBY_LINKS; a failed export is skipped.
TT_STANDBY_LINKS=()
tt_standby_links() {
    local i l
    TT_STANDBY_LINKS=()
    [[ -n "$2" ]] || return 0
    for (( i = 0; i < ${#STANDBY[@]}; i++ )); do
        l="$(tt_export_link "$1" "${STANDBY[i]}" "${LABEL}-standby$(( i + 1 ))")"
        if [[ -n "${l}" ]]; then TT_STANDBY_LINKS+=("${l}")
        else warn "TrustTunnel link for standby ${STANDBY[i]} (client $1) could not be built; it is left out."; fi
    done
    return 0
}

# Rewrites the details of every client (main: ${CLIENT_FILE}; the others in
# ${CLIENT_FILES_DIR}) and removes the files of clients that no longer exist.
# TT_URL = the main client's tt:// link ("" = no TrustTunnel).
write_client_files() {
    local i f n tt l
    install -d -m 700 "${VT_ROOT_DIR}"
    install -m 600 /dev/null "${CLIENT_FILE}.new"
    tt_standby_links "${T_USER}" "${TT_URL}"
    client_details main "${TT_URL}" "${CLIENT_FILE}" > "${CLIENT_FILE}.new"
    mv -f "${CLIENT_FILE}.new" "${CLIENT_FILE}"
    write_client_bundle "${CLIENT_FILE%.txt}" main
    if (( ${#CL_NAMES[@]} )); then install -d -m 700 "${CLIENT_FILES_DIR}"; fi
    for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
        tt=""
        f="${CLIENT_FILES_DIR}/${CL_NAMES[i]}.txt"
        if [[ "${CL_STATE[i]:-}" == "disabled" ]]; then
            # not in the TrustTunnel credentials: the endpoint cannot build its link; keep the old ones
            tt="$(grep -m1 '^tt://' "${f}" 2>/dev/null || true)"
            TT_STANDBY_LINKS=()
            if [[ -n "${tt}" ]]; then
                while IFS= read -r l; do TT_STANDBY_LINKS+=("${l}"); done < <(grep '^tt://' "${f}" | tail -n +2 || true)
            fi
        else
            if [[ -n "${TT_URL}" ]]; then
                tt="$(tt_export_link "${CL_NAMES[i]}")"
                if [[ -z "${tt}" ]]; then tt="$(grep -m1 '^tt://' "${f}" 2>/dev/null || true)"; fi
            fi
            tt_standby_links "${CL_NAMES[i]}" "${tt}"
        fi
        install -m 600 /dev/null "${f}.new"
        client_details "${CL_NAMES[i]}" "${tt}" "${f}" > "${f}.new"
        mv -f "${f}.new" "${f}"
        write_client_bundle "${f%.txt}" "${CL_NAMES[i]}"
    done
    for f in "${CLIENT_FILES_DIR}"/*.txt; do
        [[ -f "${f}" ]] || continue
        n="${f##*/}"; n="${n%.txt}"
        if [[ -z "$(client_index "${n}")" ]]; then rm -f "${f}"; fi
    done
    for f in "${CLIENT_FILES_DIR}"/*.sub "${CLIENT_FILES_DIR}"/*.singbox.json; do
        [[ -f "${f}" ]] || continue
        n="${f##*/}"; n="${n%.sub}"; n="${n%.singbox.json}"
        if [[ -z "$(client_index "${n}")" ]]; then rm -f "${f}"; fi
    done
    return 0
}

# Probe profile of the main client for keenetic-vpn-probe.sh (secret, 0600).
write_probe_profile() {
    install -d -m 700 "${VT_ROOT_DIR}"
    install -m 600 /dev/null "${PROBE_PROFILE}.new"
    {
        printf '# veiltrium probe profile for keenetic-vpn-probe.sh. SECRET: keep it 0600.\n'
        printf 'P_VERSION=1\nP_NAME=%s\nP_SERVER=%s\nP_KEY=%s\n' "${LABEL}" "${PUBLIC_IP}" "${PROBE_KEY}"
        printf 'P_HY2_PORT=%s\nP_HY2_SNI=%s\nP_HY2_PASSWORD=%s\nP_HY2_PIN_SPKI=%s\nP_HY2_PIN_CERT=%s\n' \
            "${HY2_PORT}" "${HY2_SNI}" "${HY2_AUTH_MAIN}" "${PK_SHA}" "${CERT_SHA}"
        if [[ -n "${R_SITE}" ]]; then
            printf 'P_REALITY_PORT=%s\nP_REALITY_SNI=%s\nP_REALITY_UUID=%s\nP_REALITY_PBK=%s\nP_REALITY_SID=%s\nP_REALITY_FP=%s\n' \
                "${REALITY_PORT}" "${R_SITE}" "${R_UUID}" "${R_PUB}" "${R_SID}" "${REALITY_FP}"
        fi
        if [[ -n "${TT_URL}" ]]; then
            printf 'P_TT_PORT=%s\nP_TT_SNI=%s\nP_TT_USER=%s\nP_TT_PASS=%s\nP_TT_CERT_B64=%s\n' \
                "${TT_PORT}" "${T_SNI}" "${T_USER}" "${T_PASS}" "$(base64 -w0 "${TT_DIR}/cert.pem")"
        fi
    } > "${PROBE_PROFILE}.new"
    mv -f "${PROBE_PROFILE}.new" "${PROBE_PROFILE}"
}

# ---- Move from the hy2-secure-install names ---------------------------------
# Nodes installed by hy2-secure-install.sh (up to 2026-10-13) keep their state under the old
# names. The first install run of veiltrium.sh moves it; the old system files (units,
# sysctl, SSH, fail2ban, needrestart, apt drop-ins) are removed once their new copies are
# written, at the end of the run. Keys, passwords, certificates and links stay as they are.
old_layout_present() {   # also a move that has begun but not finished (old units still there)
    [[ -d /etc/hy2-secure || -d /var/lib/hy2-secure || -e /root/hy2-client.txt || \
       -e /usr/local/sbin/hy2-secure-recover || -e /etc/systemd/system/hy2-scanner-block.timer ]] \
        || grep -qs 'inet hy2fw' /etc/nftables.conf
}

move_tree() {   # $1 = old directory, $2 = new one: what the new one lacks moves over, then the old one goes
    local e
    [[ -d "$1" ]] || return 0
    install -d -m 700 "$2"
    for e in "$1"/* "$1"/.[!.]*; do
        [[ -e "${e}" ]] || continue
        if [[ ! -e "$2/${e##*/}" ]]; then mv -f "${e}" "$2/"; fi
    done
    rm -rf -- "$1"
    return 0
}

migrate_old_layout() {
    local f
    old_layout_present || return 0
    # an old hy2-secure-install.sh still running (e.g. after a dropped SSH session) owns the node
    exec 6>/run/hy2-secure-install.lock
    flock -n 6 || die "hy2-secure-install.sh is still running on this server; wait for it to finish, then run veiltrium.sh again."
    info "This node was installed by hy2-secure-install.sh: moving it to the Veiltrium names"
    info "(keys, passwords, certificates and links stay; the old files are removed at the end)."
    # an interrupted change of the old version comes back first, by its own recover script
    if compgen -G "/var/lib/hy2-secure/txn/*/pending" >/dev/null; then
        [[ -x /usr/local/sbin/hy2-secure-recover ]] \
            || die "an interrupted change of the old version is pending and its recover script is missing; nothing was moved."
        /usr/local/sbin/hy2-secure-recover --now || true
        if compgen -G "/var/lib/hy2-secure/txn/*/pending" >/dev/null; then
            die "an interrupted change of the old version could not be restored yet; nothing was moved. Try again in a minute."
        fi
    fi
    rm -rf /root/.hy2-install.* 2>/dev/null || true    # temp folders of killed old runs (they may hold keys)
    systemctl stop hy2-secure-watchdog.timer hy2-reality-trial-end.timer >/dev/null 2>&1 || true
    # the old weekly refresh would write to the old directory; its replacement comes in step 6
    systemctl disable --now hy2-scanner-block.timer >/dev/null 2>&1 || true
    if [[ -e /run/systemd/system/xray.service.d/50-hy2-trial.conf ]]; then   # a running trial ends
        rm -f /run/systemd/system/xray.service.d/50-hy2-trial.conf
        rm -rf /run/hy2-secure
        systemctl daemon-reload
        systemctl restart xray.service >/dev/null 2>&1 || true    # back to the production config
    fi
    move_tree /etc/hy2-secure "${SCANNER_DIR}"
    move_tree /var/lib/hy2-secure "${STATE_DIR}"
    if [[ -f "${SCANNER_FILE}" ]]; then
        sed -i 's/inet hy2fw /inet veiltrium /g; s/^# hy2-scanner-block:/# veiltrium-scanner-block:/' "${SCANNER_FILE}"
    fi
    # The firewall file on disk must stay loadable at every moment (a reboot before step 6
    # rewrites it must not boot an open server): same rules, new table name and list path.
    if grep -qs 'inet hy2fw\|/etc/hy2-secure/' /etc/nftables.conf; then
        sed -e 's#/etc/hy2-secure/#/etc/veiltrium/#g' -e 's/inet hy2fw/inet veiltrium/g' \
            -e 's/^# hy2-secure-install:/# veiltrium:/' /etc/nftables.conf > /etc/nftables.conf.vt-new
        nft -c -f /etc/nftables.conf.vt-new >/dev/null 2>&1 \
            || { rm -f /etc/nftables.conf.vt-new; die "the renamed firewall file did not pass nft -c; nothing else was changed."; }
        chmod 700 /etc/nftables.conf.vt-new
        sync
        mv -f /etc/nftables.conf.vt-new /etc/nftables.conf
    fi
    if [[ -f /etc/nftables.conf.orig-hy2 && ! -e /etc/nftables.conf.orig-veiltrium ]]; then
        mv -f /etc/nftables.conf.orig-hy2 /etc/nftables.conf.orig-veiltrium
    fi
    install -d -m 700 "${VT_ROOT_DIR}"
    for f in client.txt probe.env; do
        if [[ -e "/root/hy2-${f}" && ! -e "${VT_ROOT_DIR}/${f}" ]]; then mv -f "/root/hy2-${f}" "${VT_ROOT_DIR}/${f}"; fi
        rm -f "/root/hy2-${f}"
    done
    if [[ -d /root/hy2-clients ]]; then move_tree /root/hy2-clients "${CLIENT_FILES_DIR}"; fi
    CHANGES+=("moved from the hy2-secure-install names to Veiltrium (root's files are now in ${VT_ROOT_DIR})")
    exec 6>&-    # nothing of the old version is left to protect; children must not inherit the lock
    return 0
}

# The old system files, once their Veiltrium copies exist (end of an install run).
remove_old_names() {
    local u old=0
    local -a files=(/etc/systemd/system/hy2-scanner-block.service /etc/systemd/system/hy2-scanner-block.timer
        /etc/systemd/system/hy2-secure-recover.service /usr/local/sbin/hy2-scanner-block /usr/local/sbin/hy2-secure-recover
        /etc/sysctl.d/99-zz-hy2-hardening.conf /etc/modules-load.d/hy2-bbr.conf /etc/needrestart/conf.d/50-hy2-secure.conf
        /etc/systemd/journald.conf.d/50-hy2.conf /etc/ssh/sshd_config.d/00-hy2-hardening.conf
        /etc/fail2ban/jail.d/hy2-sshd.local /etc/apt/apt.conf.d/52hy2-unattended-upgrades
        /var/log/hy2-secure-install.log /var/log/hy2-secure-install.log.1 /etc/nftables.conf.orig-hy2
        /etc/nftables.conf.hy2-new /etc/systemd/journald.conf.d/50-hy2.conf.new
        /etc/systemd/system/hy2-secure-recover.service.new /etc/fail2ban/jail.d/hy2-sshd.local.new
        /run/hy2-secure-install.lock /var/lib/systemd/timers/stamp-hy2-scanner-block.timer)
    for u in "${files[@]}"; do if [[ -e "${u}" ]]; then old=1; fi; done
    (( old == 1 )) || return 0
    for u in hy2-scanner-block.timer hy2-scanner-block.service hy2-secure-recover.service; do
        systemctl disable --now "${u}" >/dev/null 2>&1 || true
    done
    rm -f -- "${files[@]}"
    systemctl daemon-reload
    ok "Old hy2-secure-install files removed (their Veiltrium copies are in place)"
    return 0
}

# ---- Machine interface (--json -: JSON on stdout, for the panel) ------------
# With "--json -" the human output goes to stderr and the JSON document to fd 8 (stdout).
json_emit() {
    if [[ "${JSON_OUT}" == "-" ]]; then cat >&8; else cat > "${JSON_OUT}"; fi
}

# Machine-readable progress of a client change (VEILTRIUM_PROGRESS=1), on stderr.
step_mark() {
    if [[ "${VEILTRIUM_PROGRESS:-0}" == "1" ]]; then printf '::step %s\n' "$1" >&2; fi
    return 0
}

# ---- Traffic counters ---------------------------------------------------------
# The proxies count per client: Hysteria (GET /traffic?clear=1 on 127.0.0.1, secret header), Xray
# (api statsquery -reset, StatsService on 127.0.0.1) and TrustTunnel (per-user totals, /clients on
# 127.0.0.1: lifetime totals of the process). A restart resets them, so they are read every 5 minutes
# (veiltrium-traffic.timer) and right before a restart, and added to TRAFFIC_FILE (root only):
#   {schema, since, updated_at,
#    clients: {NAME: {up, down, last_seen, by_protocol: {hysteria2|vless|trusttunnel: {up, down}}}},
#    daily:   {YYYY-MM-DD: {NAME: {up, down}}}      (the last 90 days),
#    tt_raw:  {NAME: {up, down}}}                   (the last TrustTunnel totals, to get deltas)
# up = from the client, down = to the client. No secrets and no client addresses are stored.
TRAFFIC_KEEP_DAYS=90

# The names a counter may belong to: main and the added clients (from their files).
traffic_known_names() {
    local f n
    printf 'main\n'
    for f in "${CLIENTS_DIR}"/*.env; do
        [[ -f "${f}" ]] || continue
        n="${f##*/}"; n="${n%.env}"
        if [[ "${n}" =~ ${CLIENT_RE} && "${n}" != "main" ]]; then printf '%s\n' "${n}"; fi
    done | LC_ALL=C sort
    return 0
}

# Where the statistics endpoints are, from the saved state of the protocols (what is running).
# Sets TS_H_PORT, TS_H_SECRET, TS_H_AUTH, TS_R_PORT, TS_T_PORT, TS_T_USER; empty = no counter.
traffic_state() {
    local v
    TS_H_PORT=""; TS_H_SECRET=""; TS_H_AUTH=""; TS_R_PORT=""; TS_T_PORT=""; TS_T_USER=""
    if [[ -s "${HY2_STATE}" ]]; then
        v="$(env_get "${HY2_STATE}" H_STATS_PORT)"
        if [[ "${v}" =~ ^[0-9]{1,5}$ ]]; then TS_H_PORT="${v}"; fi
        v="$(env_get "${HY2_STATE}" H_STATS_SECRET)"
        if [[ "${v}" =~ ^[0-9a-f]{48}$ ]]; then TS_H_SECRET="${v}"; fi
        TS_H_AUTH="$(env_get "${HY2_STATE}" H_AUTH)"
    fi
    if [[ -z "${TS_H_PORT}" || -z "${TS_H_SECRET}" ]]; then TS_H_PORT=""; TS_H_SECRET=""; fi
    if [[ -s "${XRAY_STATE}" ]]; then
        v="$(env_get "${XRAY_STATE}" R_STATS_PORT)"
        if [[ "${v}" =~ ^[0-9]{1,5}$ ]]; then TS_R_PORT="${v}"; fi
    fi
    if [[ -s "${TT_STATE}" ]]; then
        v="$(env_get "${TT_STATE}" T_STATS_PORT)"
        if [[ "${v}" =~ ^[0-9]{1,5}$ ]]; then TS_T_PORT="${v}"; fi
        v="$(env_get "${TT_STATE}" T_USER)"
        if [[ "${v}" =~ ^[A-Za-z0-9_-]{1,32}$ ]]; then TS_T_USER="${v}"; fi
    fi
    return 0
}

# Each fetcher prints {"NAME": {"up": N, "down": N}} (bytes since its last reading, TrustTunnel:
# totals), or nothing if the endpoint did not answer. They never fail.
traffic_fetch_hysteria() {
    local out
    [[ -n "${TS_H_PORT}" ]] || return 0
    # the secret goes through stdin (-K -), not the command line
    out="$(printf 'header = "Authorization: %s"\n' "${TS_H_SECRET}" \
        | curl -fsS --max-time 8 -K - "http://127.0.0.1:${TS_H_PORT}/traffic?clear=1" 2>/dev/null || true)"
    # tx = received from the client (up), rx = sent to it (down); with one shared password the id is "user"
    jq -c --arg auth "${TS_H_AUTH}" 'if type == "object" then
            with_entries(select(.value | type == "object")
                | {key: (if $auth != "userpass" and .key == "user" then "main" else .key end),
                   value: {up: (.value.tx // 0), down: (.value.rx // 0)}})
        else empty end' <<<"${out}" 2>/dev/null || true
    return 0
}
traffic_fetch_xray() {
    local out
    [[ -n "${TS_R_PORT}" && -x "${XRAY_BIN}" ]] || return 0
    out="$("${XRAY_BIN}" api statsquery --server="127.0.0.1:${TS_R_PORT}" -pattern 'user>>>' -reset 2>/dev/null || true)"
    # {"stat": [{"name": "user>>>NAME>>>traffic>>>uplink", "value": "123"}]}; zero counters may be missing
    jq -c 'if type == "object" then
            [(.stat // [])[] | select((.name // "") | test("^user>>>[^>]+>>>traffic>>>(uplink|downlink)$"))
                | (.name | split(">>>")) as $n
                | {user: $n[1], dir: $n[3], v: (.value // 0)}]
            | group_by(.user)
            | map({key: .[0].user, value: {
                up: (map(select(.dir == "uplink") | .v) | add // 0),
                down: (map(select(.dir == "downlink") | .v) | add // 0)}})
            | from_entries
        else empty end' <<<"${out}" 2>/dev/null || true
    return 0
}
traffic_fetch_trusttunnel() {
    local out
    [[ -n "${TS_T_PORT}" ]] || return 0
    # /clients: per user, lifetime totals of the process (the addresses in it are not used). Seen from the
    # client: inbound = bytes toward the client (its download), outbound = from it (measured with the
    # v1.1.0 endpoint and client v1.1.11; METRICS.md describes the two the other way round).
    # The main client's login is T_USER.
    out="$(curl -fsS --max-time 8 "http://127.0.0.1:${TS_T_PORT}/clients" 2>/dev/null || true)"
    [[ -n "${out}" ]] || return 0
    jq -c --arg tuser "${TS_T_USER}" 'if type == "array" then
            map(select(.username | type == "string") | {key: (if .username == $tuser then "main" else .username end),
                value: {up: (.outbound // 0), down: (.inbound // 0)}}) | from_entries
        else empty end' <<<"${out}" 2>/dev/null || true
    return 0
}

# The merge: $cur = the file so far, $h / $x = deltas of Hysteria / Xray (or null), $t = TrustTunnel totals
# (or null), $known = the clients that exist, $now / $today / $cutoff = dates. Prints the new file.
# TrustTunnel totals become deltas against tt_raw (a lower total means a restart: it counts from zero).
# shellcheck disable=SC2016
TRAFFIC_MERGE_JQ='
def num: (if type == "number" then . elif type == "string" then (tonumber? // 0) else 0 end) | if . > 0 then floor else 0 end;
def ud($a; $b): {up: (($a.up | num) + ($b.up | num)), down: (($a.down | num) + ($b.down | num))};
def known: with_entries(select(.key | IN($known[])));
($cur | if type == "object" then . else {} end) as $c
| ($c.tt_raw // {}) as $raw
| (if $t == null then {} else
    ($t | known | with_entries(.value as $v | ($raw[.key] // {}) as $p
        | .value = {up: (if ($v.up | num) >= ($p.up | num) then ($v.up | num) - ($p.up | num) else ($v.up | num) end),
                    down: (if ($v.down | num) >= ($p.down | num) then ($v.down | num) - ($p.down | num) else ($v.down | num) end)}))
  end) as $tdelta
| (if $t == null then $raw else ($t | known | map_values({up: (.up | num), down: (.down | num)})) end) as $newraw
| {hysteria2: (($h // {}) | known), vless: (($x // {}) | known), trusttunnel: $tdelta} as $protos
| (reduce ($protos | to_entries[]) as $p ({};
    reduce ($p.value | to_entries[]) as $e (.;
        if ($e.value.up | num) + ($e.value.down | num) == 0 then . else .[$e.key] = ud(.[$e.key]; $e.value) end))) as $delta
| (reduce ($protos | to_entries[]) as $p (($c.clients // {} | known);
    reduce ($p.value | to_entries[]) as $e (.;
        ($e.value.up | num) as $u | ($e.value.down | num) as $d
        | if $u + $d == 0 then . else
            .[$e.key] = ((.[$e.key] // {}) as $cl | ($cl.by_protocol // {}) as $bp
                | $cl + {up: (($cl.up | num) + $u), down: (($cl.down | num) + $d), last_seen: $now,
                   by_protocol: ($bp + {($p.key): ud($bp[$p.key]; {up: $u, down: $d})})})
          end))) as $clients
| (reduce ($ARGS.named.periods // {} | to_entries[]) as $p ($clients;
    $p.key as $n | $p.value as $ps
    | (.[$n] // {up: 0, down: 0, last_seen: null, by_protocol: {}}) as $cl
    | ($delta[$n] // {up: 0, down: 0}) as $d
    | (($d.up | num) + ($d.down | num)) as $add
    | (if $ps != "" and ($cl.period_start // "") != $ps then 0 else ($cl.period_bytes | num) end) as $base
    | .[$n] = ($cl + {period_start: (if $ps == "" then ($cl.period_start // $today) else $ps end),
                      period_bytes: ($base + $add)}))) as $clients
| (($c.daily // {}) | map_values(known)
    | if ($delta | length) > 0 then .[$today] = (reduce ($delta | to_entries[]) as $e ((.[$today] // {}); .[$e.key] = ud(.[$e.key]; $e.value))) else . end
    | with_entries(select(.key >= $cutoff and (.value | length) > 0))) as $daily
| {schema: "veiltrium-traffic/1", since: ($c.since // $now), updated_at: $now,
   clients: $clients, daily: $daily, tt_raw: $newraw}'

# Reads the counters once and adds them to TRAFFIC_FILE. Under its own lock (the timer and an
# install may meet); never fails: a node without counters, or an endpoint that does not answer,
# is skipped.
traffic_collect() {
    command -v jq >/dev/null 2>&1 || return 0
    (
        flock -w 20 6 || exit 0
        traffic_collect_locked
    ) 6>"${TRAFFIC_LOCK}" || true
    return 0
}
traffic_collect_locked() {
    local h x t cur="{}" now today cutoff known new periods
    traffic_state
    [[ -n "${TS_H_PORT}${TS_R_PORT}${TS_T_PORT}" ]] || return 0
    h="$(traffic_fetch_hysteria)"; x="$(traffic_fetch_xray)"; t="$(traffic_fetch_trusttunnel)"
    [[ -n "${h}${x}${t}" ]] || return 0
    cur="$(traffic_read_file)"
    now="$(date -u +%FT%TZ)"; today="${now%%T*}"
    cutoff="$(date -u -d "${TRAFFIC_KEEP_DAYS} days ago" +%F)"
    known="$(traffic_known_names | jq -R -s -c 'split("\n") | map(select(length > 0))')"
    periods="$(client_periods_json "${today}")"
    new="$(jq -n --argjson cur "${cur}" --argjson h "${h:-null}" --argjson x "${x:-null}" --argjson t "${t:-null}" \
        --argjson known "${known}" --argjson periods "${periods}" --arg now "${now}" --arg today "${today}" --arg cutoff "${cutoff}" \
        "${TRAFFIC_MERGE_JQ}")" || return 0
    traffic_write_file "${new}"
    return 0
}

# The file as JSON; a damaged one is kept as .bad and counting starts again.
traffic_read_file() {
    if [[ -s "${TRAFFIC_FILE}" ]]; then
        if jq -e 'type == "object"' "${TRAFFIC_FILE}" >/dev/null 2>&1; then cat "${TRAFFIC_FILE}"; return 0; fi
        mv -f "${TRAFFIC_FILE}" "${TRAFFIC_FILE}.bad" 2>/dev/null || true
    fi
    printf '{}'
    return 0
}
traffic_write_file() {   # $1 = the document
    install -d -m 700 "$(dirname -- "${TRAFFIC_FILE}")"
    install -m 600 /dev/null "${TRAFFIC_FILE}.new"
    printf '%s\n' "$1" > "${TRAFFIC_FILE}.new"
    mv -f "${TRAFFIC_FILE}.new" "${TRAFFIC_FILE}"
    return 0
}

# Under the traffic lock: $1 = jq program, then its arguments; the file is replaced by the result.
traffic_edit() {
    command -v jq >/dev/null 2>&1 || return 0
    (
        flock -w 20 6 || exit 0
        [[ -s "${TRAFFIC_FILE}" ]] || exit 0
        new="$(jq "${@:2}" "$1" "${TRAFFIC_FILE}")" || exit 0
        traffic_write_file "${new}"
    ) 6>"${TRAFFIC_LOCK}" || true
    return 0
}
# A removed client's counters go with it (a new client of the same name starts at zero).
traffic_forget() {   # $1 = client name
    traffic_edit 'del(.clients[$n]) | .daily |= map_values(del(.[$n])) | .tt_raw |= del(.[$n])' --arg n "$1"
}
# All counters to zero (the TrustTunnel baseline stays, or its lifetime totals would count again).
traffic_reset() {
    traffic_collect
    traffic_edit '.clients = {} | .daily = {} | .since = $now | .updated_at = $now' --arg now "$(date -u +%FT%TZ)"
}

# The counters as one JSON document, no secrets: every client that exists is listed (zeros if unseen).
traffic_doc() {
    local known cur
    known="$(traffic_known_names | jq -R -s -c 'split("\n") | map(select(length > 0))')"
    cur="$(traffic_read_file)"
    jq -n --argjson cur "${cur}" --argjson known "${known}" '
        ($cur.clients // {}) as $c
        | ($known | map({key: ., value: ($c[.] // {up: 0, down: 0, last_seen: null, by_protocol: {}})}) | from_entries) as $clients
        | {schema: "veiltrium-traffic/1", since: ($cur.since // null), updated_at: ($cur.updated_at // null),
           totals: {up: ([$clients[].up] | add // 0), down: ([$clients[].down] | add // 0)},
           clients: $clients, daily: ($cur.daily // {})}'
}
traffic_client_json() {   # $1 = client name -> {up, down, last_seen, by_protocol}
    traffic_doc | jq -c --arg n "$1" '.clients[$n] // {up: 0, down: 0, last_seen: null, by_protocol: {}}'
}
traffic_totals_json() {   # for --status
    traffic_doc | jq -c '{up: .totals.up, down: .totals.down, since, updated_at}'
}

# 1536 -> "1.5 KiB"
bytes_h() {
    awk -v b="${1:-0}" 'BEGIN { split("B KiB MiB GiB TiB PiB", u, " "); i = 1
        while (b >= 1024 && i < 6) { b /= 1024; i++ }
        if (i == 1) printf "%d %s", b, u[i]; else printf "%.1f %s", b, u[i] }'
}

# --traffic: take the counters now, then show them.
traffic_show() {
    local doc name up down seen
    traffic_collect
    doc="$(traffic_doc)"
    if [[ -n "${JSON_OUT}" ]]; then printf '%s\n' "${doc}" | json_emit; return 0; fi
    traffic_state
    printf '\nTraffic of %s since %s (up = from the client, down = to the client):\n' "${LABEL}" \
        "$(jq -r '.since // "the first reading"' <<<"${doc}")"
    printf '  %-24s %-12s %-12s %s\n' client up down "last seen"
    while IFS=$'\t' read -r name up down seen; do
        printf '  %-24s %-12s %-12s %s\n' "${name}" "$(bytes_h "${up}")" "$(bytes_h "${down}")" "${seen}"
    done < <(jq -r '.clients | to_entries | sort_by(.key) | .[] | [.key, .value.up, .value.down, (.value.last_seen // "-")] | @tsv' <<<"${doc}")
    printf '  %-24s %-12s %-12s\n' total "$(bytes_h "$(jq -r '.totals.up' <<<"${doc}")")" "$(bytes_h "$(jq -r '.totals.down' <<<"${doc}")")"
    if [[ -z "${TS_H_PORT}" && -z "${TS_R_PORT}" && -z "${TS_T_PORT}" ]]; then
        info "No counters are running on this node yet: run the installer once (bash $0) to enable them."
    else
        info "Counters: Hysteria $([[ -n "${TS_H_PORT}" ]] && echo on || echo off), VLESS Reality $([[ -n "${TS_R_PORT}" ]] && echo on || echo off), TrustTunnel $([[ -n "${TS_T_PORT}" ]] && echo on || echo off); read every 5 minutes."
    fi
    return 0
}

# The statistics endpoints of the installed node answer (the install check). Warnings only.
traffic_endpoints_check() {
    local out
    traffic_state
    if [[ -n "${TS_H_PORT}" ]]; then
        out="$(printf 'header = "Authorization: %s"\n' "${TS_H_SECRET}" \
            | curl -fsS --max-time 8 -K - "http://127.0.0.1:${TS_H_PORT}/traffic" 2>/dev/null || true)"
        if jq -e 'type == "object"' <<<"${out}" >/dev/null 2>&1; then ok "Traffic counters: Hysteria"
        else warn "Traffic counters: the Hysteria statistics endpoint did not answer"; fi
    fi
    if [[ -n "${TS_R_PORT}" ]]; then
        if "${XRAY_BIN}" api statsquery --server="127.0.0.1:${TS_R_PORT}" -pattern 'user>>>' >/dev/null 2>&1; then ok "Traffic counters: VLESS Reality"
        else warn "Traffic counters: the Xray statistics endpoint did not answer"; fi
    fi
    if [[ -n "${TS_T_PORT}" ]]; then
        if curl -fsS --max-time 8 -o /dev/null "http://127.0.0.1:${TS_T_PORT}/clients" 2>/dev/null; then ok "Traffic counters: TrustTunnel"
        else warn "Traffic counters: the TrustTunnel metrics endpoint did not answer"; fi
    fi
    return 0
}

# Connection details of client $1 as JSON; secrets included (root and the panel only).
# $2 = its tt:// link ("" = none), $3 = the tt:// links of the standby servers (one per line).
# With standby servers the document gains "standby" (the addresses) and per protocol
# standby_links, standby_outbounds (outbounds + a urltest group) and a longer awg_group.
# subscription_base64 (string) and singbox_profile (object) are null for a disabled client.
client_json() {
    local vless="" i hy_sb='[]' vless_sb='[]' tt_sb='[]' sb='[]' sub_b64="" profile=null
    if ! client_is_disabled "$1"; then
        sub_b64="$(client_sub_b64 "$1")"
        profile="$(client_singbox_profile_json "$1" | jq -c .)"
    fi
    client_creds "$1"
    if [[ -n "${R_SITE}" ]]; then vless="$(vless_link "${CC_UUID}")"; fi
    if (( ${#STANDBY[@]} )); then
        sb="$(jq -nc '$ARGS.positional' --args "${STANDBY[@]}")"
        hy_sb="$(for (( i = 0; i < ${#STANDBY[@]}; i++ )); do
            hy2_link "${CC_USER}" "${CC_PASS}" "${STANDBY[i]}" "${LABEL}-standby$(( i + 1 ))"; printf '\n'; done \
            | jq -R -s -c 'split("\n") | map(select(length > 0))')"
        if [[ -n "${vless}" ]]; then
            vless_sb="$(for (( i = 0; i < ${#STANDBY[@]}; i++ )); do
                vless_link "${CC_UUID}" "${STANDBY[i]}" "${LABEL}-standby$(( i + 1 ))"; printf '\n'; done \
                | jq -R -s -c 'split("\n") | map(select(length > 0))')"
        fi
        if [[ -n "${3:-}" ]]; then tt_sb="$(printf '%s\n' "$3" | jq -R -s -c 'split("\n") | map(select(length > 0))')"; fi
    fi
    jq -n --arg name "$1" --arg created "${CC_CREATED}" --arg label "${LABEL}" --arg server "${HOST}" \
        --arg hy_link "$(hy2_link "${CC_USER}" "${CC_PASS}")" --arg auth "${CC_AUTH}" --arg hy_sni "${HY2_SNI}" \
        --argjson hy_port "${HY2_PORT}" --arg pk "${PK_SHA}" --arg cert "${CERT_SHA}" \
        --arg vless "${vless}" --arg uuid "${CC_UUID}" --arg r_site "${R_SITE}" --argjson r_port "${REALITY_PORT}" \
        --arg fp "${REALITY_FP}" --arg pbk "${R_PUB}" --arg sid "${R_SID}" --arg tt "$2" \
        --arg sub_b64 "${sub_b64}" --argjson profile "${profile}" \
        --argjson sb "${sb}" --argjson hy_sb "${hy_sb}" --argjson vless_sb "${vless_sb}" --argjson tt_sb "${tt_sb}" \
        --argjson lim "$(client_limits_json "$1")" \
        --argjson traffic "$(traffic_client_json "$1")" '
        def hy_out($s; $tag): {type: "hysteria2", tag: $tag, server: $s, server_port: $hy_port, password: $auth,
            tls: {enabled: true, server_name: $hy_sni, insecure: false, certificate_public_key_sha256: [$pk]}};
        def awg($s; $tag): {type: "hysteria2", tag: $tag, server: $s, server_port: $hy_port, password: $auth,
            tls: {enabled: true, server_name: $hy_sni, certificate_public_key_sha256: [$pk]}};
        def vless_out($s; $tag): {type: "vless", tag: $tag, server: $s, server_port: $r_port, uuid: $uuid,
            flow: "xtls-rprx-vision", tls: {enabled: true, server_name: $r_site,
              utls: {enabled: true, fingerprint: $fp},
              reality: {enabled: true, public_key: $pbk, short_id: $sid}}};
        def urltest($tag; $tags): {type: "urltest", tag: $tag, outbounds: $tags,
            url: "https://www.gstatic.com/generate_204", interval: "3m", tolerance: 50};
        def numbered($tag): [range(0; $sb | length)] | map($tag + "-standby" + (. + 1 | tostring));
        {schema: "veiltrium-client/1", name: $name, main: ($name == "main"),
         created: (if $created == "" then null else $created end), node_name: $label, server: $server}
         + (if ($sb | length) > 0 then {standby: $sb} else {} end)
         + $lim
         + {hysteria2: ({link: $hy_link, auth: $auth, sni: $hy_sni, port: $hy_port, pin_sha256: $cert,
           outbound: hy_out($server; "hy2"),
           awg_group: ([awg($server; "Veiltrium")]
             + [range(0; $sb | length) as $i | awg($sb[$i]; "Veiltrium-standby" + ($i + 1 | tostring))])}
           + (if ($sb | length) > 0 then {standby_links: $hy_sb,
               standby_outbounds: ([range(0; $sb | length) as $i | hy_out($sb[$i]; "hy2-standby" + ($i + 1 | tostring))]
                 + [urltest("Veiltrium-auto-hy2"; ["hy2"] + numbered("hy2"))])} else {} end)),
         vless: (if $vless == "" then null else ({link: $vless, sni: $r_site, port: $r_port,
           outbound: vless_out($server; "reality")}
           + (if ($sb | length) > 0 then {standby_links: $vless_sb,
               standby_outbounds: ([range(0; $sb | length) as $i | vless_out($sb[$i]; "reality-standby" + ($i + 1 | tostring))]
                 + [urltest("Veiltrium-auto-reality"; ["reality"] + numbered("reality"))])} else {} end)) end),
         trusttunnel: (if $tt == "" then null else ({link: $tt}
           + (if ($tt_sb | length) > 0 then {standby_links: $tt_sb} else {} end)) end),
         subscription_base64: (if $sub_b64 == "" then null else $sub_b64 end),
         singbox_profile: $profile,
         traffic: $traffic}'
}

# The clients of the node as JSON (no secrets).
clients_json() {
    local i trc
    trc="$(traffic_doc | jq -c '.clients')"
    {
        printf 'main\t\t%s\n' "$(client_limits_json main "${trc}")"
        for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
            printf '%s\t%s\t%s\n' "${CL_NAMES[i]}" "${CL_CREATED[i]}" "$(client_limits_json "${CL_NAMES[i]}" "${trc}")"
        done
    } | jq -R -s --arg label "${LABEL}" --arg server "${PUBLIC_IP}" --arg auth "${H_AUTH}" \
        --argjson tr "${trc}" '
        split("\n") | map(select(length > 0) | split("\t")) |
        {schema: "veiltrium-clients/1", node_name: $label, server: $server, hysteria_auth: $auth,
         clients: map({name: .[0], main: (.[0] == "main"), created: (if (.[1] // "") == "" then null else .[1] end),
            traffic: ($tr[.[0]] // {up: 0, down: 0, last_seen: null, by_protocol: {}})} + (.[2] | fromjson))}'
}

# State and limits of client $1 as JSON (no secrets): state, reason, limit (bytes), expires,
# reset, period_start and period_bytes (null without a limit or reset). $2 = the "clients" object
# of the traffic document, if the caller has it. "main" is always active and has none.
client_limits_json() {
    local i st="active" rs="" lim="" ex="" rst="none" trc="${2:-}"
    i="$(client_index "$1")"
    if [[ -n "${i}" ]]; then st="${CL_STATE[i]:-active}"; rs="${CL_REASON[i]:-}"; lim="${CL_LIMIT[i]:-}"; ex="${CL_EXPIRES[i]:-}"; rst="${CL_RESET[i]:-none}"; fi
    if [[ -z "${trc}" ]]; then trc="$(traffic_doc | jq -c '.clients')"; fi
    jq -nc --argjson tr "${trc}" --arg n "$1" --arg st "${st}" --arg rs "${rs}" --arg lim "${lim}" --arg ex "${ex}" --arg rst "${rst}" '
        {state: $st, reason: (if $rs == "" then null else $rs end), limit: (if $lim == "" then null else ($lim | tonumber) end),
         expires: (if $ex == "" then null else $ex end), reset: $rst,
         period_start: (if $lim != "" or $rst != "none" then ($tr[$n].period_start // null) else null end),
         period_bytes: (if $lim != "" or $rst != "none" then ($tr[$n].period_bytes // 0) else null end)}'
}

# Server load as a JSON object: load averages (1/5/15 min) and CPU count, memory and the
# disk of / in MiB. Plain /proc and df; a value that cannot be read is 0.
server_load_json() {
    local l1=0 l5=0 l15=0 cpus mt=0 ma=0 dt=0 du=0
    read -r l1 l5 l15 _ < /proc/loadavg 2>/dev/null || true
    cpus="$(nproc 2>/dev/null || echo 1)"
    mt="$(awk '/^MemTotal:/ { print int($2 / 1024) }' /proc/meminfo 2>/dev/null || true)"
    ma="$(awk '/^MemAvailable:/ { print int($2 / 1024) }' /proc/meminfo 2>/dev/null || true)"
    read -r dt du < <(df -Pm / 2>/dev/null | awk 'NR == 2 { print $2, $3 }' || true) || true
    [[ "${l1}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || l1=0
    [[ "${l5}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || l5=0
    [[ "${l15}" =~ ^[0-9]+(\.[0-9]+)?$ ]] || l15=0
    [[ "${cpus}" =~ ^[0-9]+$ ]] || cpus=1
    [[ "${mt:-}" =~ ^[0-9]+$ ]] || mt=0
    [[ "${ma:-}" =~ ^[0-9]+$ ]] || ma=0
    [[ "${dt:-}" =~ ^[0-9]+$ ]] || dt=0
    [[ "${du:-}" =~ ^[0-9]+$ ]] || du=0
    jq -nc --argjson l1 "${l1}" --argjson l5 "${l5}" --argjson l15 "${l15}" --argjson cpus "${cpus}" \
        --argjson mt "${mt}" --argjson ma "${ma}" --argjson dt "${dt}" --argjson du "${du}" \
        '{cpus: $cpus, load: {m1: $l1, m5: $l5, m15: $l15},
          memory_mb: {total: $mt, used: (if $mt > $ma then $mt - $ma else 0 end)},
          disk_mb: {total: $dt, used: $du}}'
}

# A fast overview of the node: no network tests, no secrets.
status_json() {
    local svc st="" vh vx vt os report n scan ru tr
    for svc in hysteria-server xray trusttunnel; do
        st+="${svc}=$(systemctl is-active "${svc}" 2>/dev/null || true)"$'\n'
    done
    vh="$("${HY2_BIN}" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)"
    vx="$("${XRAY_BIN}" version 2>/dev/null | awk 'NR == 1 { print "v" $2 }' || true)"
    vt="$("${TT_BIN}" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)"
    os="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-}" || true)"
    report="$(jq -c '{generated_at, mode, reality: .reality.vps, hysteria2: .hysteria2.vps,
        trusttunnel_h2: .trusttunnel.h2.vps, trusttunnel_h3: .trusttunnel.h3.vps}' "${REPORT_FILE}" 2>/dev/null || true)"
    tr="$(traffic_totals_json 2>/dev/null || true)"
    n="$(count_clients)"
    ru="$(jq -c '{verdict, checked_at, networks, bad_streak: (.bad_streak // 0), previous_verdict, icmp: (.icmp | {ok, total}),
        tcp_reality: (.tcp_reality | if . then {ok, total, port} else null end),
        tcp_trusttunnel: (.tcp_trusttunnel | if . then {ok, total, port} else null end)}' "${RUSSIA_FILE}" 2>/dev/null || true)"
    scan="$(nft -j list set inet veiltrium scanners4 2>/dev/null \
        | jq '[.nftables[] | select(.set) | (.set.elem // []) | length] | add // 0' 2>/dev/null || echo 0)"
    jq -n --arg now "$(date -u +%FT%TZ)" --arg version "${SCRIPT_VERSION}" --arg label "${LABEL}" \
        --arg ssh "${SSH_PORTS[*]}" --arg scan "${scan:-0}" \
        --arg f2b "$(systemctl is-active fail2ban 2>/dev/null || true)" \
        --arg fw "$(nft list table inet veiltrium >/dev/null 2>&1 && echo 1 || echo 0)" \
        --arg server "${PUBLIC_IP}" --arg os "${os}" --arg uptime "$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)" \
        --arg reboot "$([[ -f /run/reboot-required ]] && echo 1 || echo 0)" --arg st "${st}" \
        --arg vh "${vh}" --arg vx "${vx}" --arg vt "${vt:+v${vt}}" --arg n "${n}" --arg h_auth "${H_AUTH}" \
        --arg r_site "${R_SITE}" --arg r_port "${REALITY_PORT}" --arg r_mts "$(mts_status reality "${R_SITE:-none}")" \
        --arg h_sni "${H_SNI}" --arg h_port "${HY2_PORT}" --arg h_mts "$(mts_status hysteria2 "${H_SNI:-none}")" \
        --arg t_sni "${T_SNI}" --arg t_port "${TT_PORT}" --arg t2 "$(mts_status tt_h2 "${T_SNI:-none}")" \
        --arg t3 "$(mts_status tt_h3 "${T_SNI:-none}")" --argjson report "${report:-null}" --argjson ru "${ru:-null}" \
        --arg globalping "${GLOBALPING}" --arg standby "${N_STANDBY}" --argjson resources "$(server_load_json)" --argjson traffic "${tr:-null}" '
        {schema: "veiltrium-status/1", generated_at: $now, script_version: $version, node_name: $label,
         server: $server, standby: ($standby | split(",") | map(select(length > 0))),
         os: $os, uptime_seconds: ($uptime | tonumber), reboot_required: ($reboot == "1"),
         resources: $resources,
         services: ($st | split("\n") | map(select(length > 0) | split("=") | {key: .[0], value: .[1]}) | from_entries),
         versions: {hysteria: $vh, xray: $vx, trusttunnel: $vt},
         clients: {added: ($n | tonumber), hysteria_auth: $h_auth},
         reality: (if $r_site == "" then null else {sni: $r_site, port: ($r_port | tonumber), home_network: $r_mts} end),
         hysteria2: {sni: $h_sni, port: ($h_port | tonumber), home_network: $h_mts},
         trusttunnel: (if $t_sni == "" then null else
           {hostname: $t_sni, port: ($t_port | tonumber), home_network_h2: $t2, home_network_h3: $t3} end),
         protection: {firewall: ($fw == "1"), ssh_ports: ($ssh | split(" ") | map(select(length > 0) | tonumber)),
           scanner_networks: ($scan | tonumber), fail2ban: $f2b},
         last_install_check: $report, russia: $ru, globalping: ($globalping == "1"), traffic: $traffic}'
}

# ---- Adding and removing clients ---------------------------------------------
# What runs on an installed node (maintenance modes). Sets HOST, HY2_SNI, HY2_MASQ_URL,
# CERT_SHA, PK_SHA, H_NOT_AFTER, HAVE_REALITY, HAVE_TT.
node_context() {
    HOST="${PUBLIC_IP}"
    HY2_SNI="${H_SNI}"
    if [[ "${H_MASQ}" == "auto" ]]; then HY2_MASQ_URL="https://${H_SNI}"; else HY2_MASQ_URL="${H_MASQ}"; fi
    CERT_SHA=""; PK_SHA=""; H_NOT_AFTER=""
    if [[ -s "${HY2_CERT}" ]]; then
        CERT_SHA="$(cert_sha256 "${HY2_CERT}")"; PK_SHA="$(cert_pubkey_sha256 "${HY2_CERT}")"; H_NOT_AFTER="$(cert_not_after "${HY2_CERT}")"
    fi
    HAVE_REALITY=0; HAVE_TT=0
    if [[ -n "${R_SITE}" && -s "${XRAY_DIR}/config.json" ]] && systemctl is-enabled --quiet xray.service 2>/dev/null; then
        HAVE_REALITY=1
    fi
    if [[ -n "${T_USER}" && -s "${TT_DIR}/credentials.toml" ]] && systemctl is-enabled --quiet trusttunnel.service 2>/dev/null; then
        HAVE_TT=1
    fi
    return 0
}

# One indented line under a client in --list-clients: its state and limits (nothing for a plain client).
client_limits_line() {   # $1 = index
    local i="$1" txt=""
    if [[ "${CL_STATE[i]:-}" == "disabled" ]]; then txt="DISABLED (${CL_REASON[i]:-manual}); "; fi
    if [[ -n "${CL_LIMIT[i]:-}" ]]; then txt+="limit $(size_dec "${CL_LIMIT[i]}"); "; fi
    if [[ -n "${CL_EXPIRES[i]:-}" ]]; then txt+="expires ${CL_EXPIRES[i]}; "; fi
    if [[ "${CL_RESET[i]:-none}" != "none" ]]; then txt+="resets ${CL_RESET[i]}; "; fi
    if [[ -n "${txt}" ]]; then printf '    %s\n' "${txt%; }"; fi
    return 0
}

clients_list() {
    local i
    printf '\nClients of %s (%s):\n' "${LABEL}" "${PUBLIC_IP}"
    printf '  %-24s %-18s %s\n' main "first client" "${CLIENT_FILE}"
    for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
        printf '  %-24s %-18s %s\n' "${CL_NAMES[i]}" "added ${CL_CREATED[i]}" "${CLIENT_FILES_DIR}/${CL_NAMES[i]}.txt"
        client_limits_line "${i}"
    done
    if [[ "${H_AUTH}" == "userpass" ]]; then
        info "Hysteria: a password per client (user:password)."
    else
        info "Hysteria: one shared password; the first --add-client changes the main Hysteria link (user:password)."
    fi
    return 0
}

# Adds (credentials in ${TMPD}/client.env), removes or resets client $2 ($1 = add|remove|reset;
# a reset replaces the credentials with the ones in ${TMPD}/client.env). All protocol configs
# change as one: the services restart (connected clients reconnect within seconds), real
# clients check the result, and on any failure the previous files come back.
clients_change() {
    local mode="$1" name="$2" reg="${CLIENTS_DIR}/$2.env" old_auth="${H_AUTH}" i j k f a u ok=1
    local -a new_auths=() new_uuids=() gone_auths=() gone_uuids=() regs=("${reg}") staged=() old_st=()
    if [[ "${mode}" == "remove" || "${mode}" == "reset" ]]; then
        i="$(client_index "${name}")"
        [[ -n "${i}" ]] || die "no client ${name}."
        gone_auths+=("${name}:${CL_HPASS[i]}"); gone_uuids+=("${CL_UUID[i]}")
    fi
    if [[ "${mode}" == "apply" ]]; then
        # ${TMPD}/apply/NAME.env: the new files of the clients whose state changes (see clients_apply_plan)
        regs=()
        for f in "${TMPD}/apply"/*.env; do
            [[ -f "${f}" ]] || continue
            staged+=("${f##*/}"); regs+=("${CLIENTS_DIR}/${f##*/}")
            a="${f##*/}"; j="$(client_index "${a%.env}")"
            [[ -n "${j}" ]] || die "no client ${a%.env}."
            old_st+=("${CL_STATE[j]}")
        done
        (( ${#staged[@]} )) || die "nothing to apply."
    fi
    install -d -m 700 "${CLIENTS_DIR}"
    traffic_collect   # the services restart below and lose their counters
    txn_begin hysteria hysteria-server.service "${HY2_CONFIG}" "${HY2_STATE}" "${regs[@]}"
    if (( HAVE_REALITY == 1 )); then txn_begin reality xray.service "${XRAY_DIR}/config.json"; fi
    if (( HAVE_TT == 1 )); then txn_begin trusttunnel trusttunnel.service "${TT_DIR}/credentials.toml"; fi
    case "${mode}" in
        add|reset) mv -f "${TMPD}/client.env" "${reg}" ;;
        apply) for f in "${staged[@]}"; do mv -f "${TMPD}/apply/${f}" "${CLIENTS_DIR}/${f}"; done ;;
        *) rm -f "${reg}" ;;
    esac
    load_clients
    H_AUTH="userpass"; set_hy2_auth_main
    if [[ "${mode}" == "add" || "${mode}" == "reset" ]]; then
        i="$(client_index "${name}")"
        [[ -n "${i}" ]] || die "the new client ${name} was not saved."
        if [[ "${CL_STATE[i]:-}" == "disabled" ]]; then   # a reset client that is disabled stays out
            gone_auths+=("${name}:${CL_HPASS[i]}"); gone_uuids+=("${CL_UUID[i]}")
        else
            new_auths+=("${name}:${CL_HPASS[i]}"); new_uuids+=("${CL_UUID[i]}")
        fi
    fi
    if [[ "${mode}" == "apply" ]]; then
        for (( k = 0; k < ${#staged[@]}; k++ )); do
            j="$(client_index "${staged[k]%.env}")"
            [[ -n "${j}" ]] || die "the client ${staged[k]%.env} was not saved."
            if [[ "${CL_STATE[j]}" == "${old_st[k]}" ]]; then continue; fi
            if [[ "${CL_STATE[j]}" == "disabled" ]]; then
                gone_auths+=("${CL_NAMES[j]}:${CL_HPASS[j]}"); gone_uuids+=("${CL_UUID[j]}")
            else
                new_auths+=("${CL_NAMES[j]}:${CL_HPASS[j]}"); new_uuids+=("${CL_UUID[j]}")
            fi
        done
    fi
    step_mark write
    install -m 640 -o root -g hysteria /dev/null "${HY2_CONFIG}.new"
    hy2_server_yaml "${HY2_CONFIG}.new"
    mv -f "${HY2_CONFIG}.new" "${HY2_CONFIG}"
    save_hy2_state
    if (( HAVE_REALITY == 1 )); then
        reality_server_json "${XRAY_DIR}/config.new.json" "" "${REALITY_PORT}" "${R_SITE}"
        chown root:xray "${XRAY_DIR}/config.new.json"
        chmod 640 "${XRAY_DIR}/config.new.json"
        "${XRAY_BIN}" run -test -c "${XRAY_DIR}/config.new.json" >"${TMPD}/xray-test.log" 2>&1 \
            || { tail -5 "${TMPD}/xray-test.log"; die "Xray rejected its own config."; }
        mv -f "${XRAY_DIR}/config.new.json" "${XRAY_DIR}/config.json"
    fi
    if (( HAVE_TT == 1 )); then
        install -m 640 -o root -g trusttunnel /dev/null "${TT_DIR}/credentials.toml.new"
        tt_credentials_toml "${TT_DIR}/credentials.toml.new"
        mv -f "${TT_DIR}/credentials.toml.new" "${TT_DIR}/credentials.toml"
    fi
    step_mark restart
    info "Restarting the services: connected clients reconnect within a few seconds."
    systemctl restart hysteria-server.service || true
    if (( HAVE_REALITY == 1 )); then systemctl restart xray.service || true; fi
    if (( HAVE_TT == 1 )); then systemctl restart trusttunnel.service || true; fi

    # Real clients: the main client still works, every client that should work does, every
    # client that should not (removed, disabled, the previous credentials of a reset one) does not.
    step_mark check-hysteria
    if ! wait_listening -Hulpn "${HY2_PORT}" hysteria; then ok=0; warn "Hysteria did not start"; fi
    if (( ok == 1 )); then
        hy2_client_test "${HY2_SNI}" "${CERT_SHA}"
        if (( HY2_E2E != 0 )); then ok=0; warn "Hysteria: the main client does not work"; fi
    fi
    for a in "${new_auths[@]+"${new_auths[@]}"}"; do
        (( ok == 1 )) || break
        hy2_client_test "${HY2_SNI}" "${CERT_SHA}" "${a}"
        if (( HY2_E2E != 0 )); then ok=0; warn "Hysteria: the client ${a%%:*} does not work"; fi
    done
    for a in "${gone_auths[@]+"${gone_auths[@]}"}"; do
        (( ok == 1 )) || break
        hy2_client_test "${HY2_SNI}" "${CERT_SHA}" "${a}"
        if (( HY2_E2E == 0 )); then ok=0; warn "Hysteria: the client ${a%%:*} (removed or disabled) still connects"; fi
    done
    if (( ok == 1 && HAVE_REALITY == 1 )); then
        step_mark check-reality
        reality_verify_production "${R_SITE}"
        if [[ "${RP_STATUS}" != "ok" ]]; then ok=0; warn "VLESS Reality: the main client does not work"; fi
        for u in "${new_uuids[@]+"${new_uuids[@]}"}"; do
            (( ok == 1 )) || break
            RC_UUID="${u}" reality_verify_production "${R_SITE}"
            if [[ "${RP_STATUS}" != "ok" ]]; then ok=0; warn "VLESS Reality: a client that should work does not"; fi
        done
        for u in "${gone_uuids[@]+"${gone_uuids[@]}"}"; do
            (( ok == 1 )) || break
            RC_UUID="${u}" RP_TRIES=1 reality_verify_production "${R_SITE}"
            if [[ "${RP_STATUS}" == "ok" ]]; then ok=0; warn "VLESS Reality: a removed or disabled client still connects"; fi
        done
    fi
    if (( ok == 1 && HAVE_TT == 1 )); then
        step_mark check-trusttunnel
        if wait_listening -Htlpn "${TT_PORT}" trusttunnel_end && wait_listening -Hulpn "${TT_PORT}" trusttunnel_end; then
            tt_checks
            if [[ "${TT_VPS_H2}" != "ok" ]]; then ok=0; warn "TrustTunnel: no answer with its certificate"; fi
        else
            ok=0; warn "TrustTunnel did not start"
        fi
    fi
    if (( ok == 0 )); then
        journalctl -u hysteria-server -u xray -u trusttunnel --no-pager -n 20 || true
        txn_restore hysteria
        if (( HAVE_REALITY == 1 )); then txn_restore reality; fi
        if (( HAVE_TT == 1 )); then txn_restore trusttunnel; fi
        alert_notify rollback "a client change did not pass the checks; the previous clients and settings were restored."
        AUDIT_ROLLBACK=1
        die "the change did not pass the checks; the previous clients and settings were restored."
    fi
    # The registry entry belongs to the Hysteria change, committed last: if the run is cut
    # off between the commits, the registry and Hysteria agree and a re-run rebuilds the rest.
    step_mark commit
    CLIENT_FILES_STALE=1
    if (( HAVE_REALITY == 1 )); then txn_commit reality; fi
    if (( HAVE_TT == 1 )); then txn_commit trusttunnel; fi
    txn_commit hysteria
    if [[ "${mode}" == "remove" ]]; then traffic_forget "${name}"; fi

    TT_URL=""
    if (( HAVE_TT == 1 )); then
        TT_URL="$(tt_export_link "${T_USER}")"
        # the endpoint's certificate and hostname did not change: the existing link stays valid
        if [[ -z "${TT_URL}" ]]; then TT_URL="$(grep -m1 '^tt://' "${CLIENT_FILE}" 2>/dev/null || true)"; fi
    fi
    write_client_files
    write_probe_profile
    CLIENT_FILES_STALE=0
    # the report keeps its checks; only the client numbers change
    if [[ -s "${REPORT_FILE}" ]] && command -v jq >/dev/null 2>&1; then
        jq --argjson n "${#CL_NAMES[@]}" --arg a "${H_AUTH}" '.clients = {added: $n, hysteria_auth: $a}' \
            "${REPORT_FILE}" > "${TMPD}/report.json" && install -m 600 "${TMPD}/report.json" "${REPORT_FILE}" || true
    fi
    if [[ "${mode}" == "add" ]]; then
        local checked="Hysteria"
        if (( HAVE_REALITY == 1 )); then checked+=", VLESS Reality"; fi
        if (( HAVE_TT == 1 )); then checked+=", TrustTunnel (certificate)"; fi
        ok "Client ${name} added; checked with real clients: ${checked}."
    elif [[ "${mode}" == "reset" ]]; then
        local checked="Hysteria"
        if (( HAVE_REALITY == 1 )); then checked+=", VLESS Reality"; fi
        ok "Client ${name} reset: new credentials work, the previous ones no longer do (checked with real clients: ${checked}; TrustTunnel: its password list was rewritten and the service answers)."
        info "Send ${name} the new details: ${CLIENT_FILES_DIR}/${name}.txt  (bash $0 --show-client ${name})"
    elif [[ "${mode}" == "apply" ]]; then
        local checked="Hysteria"
        if (( HAVE_REALITY == 1 )); then checked+=", VLESS Reality"; fi
        ok "Client changes applied: ${#new_auths[@]} now accepted, ${#gone_auths[@]} now refused (checked with real clients: ${checked}; TrustTunnel: its password list was rewritten and the service answers)."
    else
        ok "Client ${name} removed: its credentials no longer work."
    fi
    if [[ "${old_auth}" != "userpass" ]]; then
        warn "Hysteria now has a password per client. The MAIN client's Hysteria link and JSON changed"
        warn "(password -> main:<password>): update them on its devices (on the router: section 6 of"
        warn "${CLIENT_FILE}; a copy of ${PROBE_PROFILE} on the router too). VLESS Reality and TrustTunnel"
        warn "links of the main client stay the same."
    fi
    return 0
}

# ---- Client limits: traffic quota, expiry, periodic reset, disable / enable -----------
# Only added clients have them (never "main"). State of a client lives in its env file
# (C_LIMIT, C_EXPIRES, C_RESET, C_STATE, C_REASON); the usage of the current period in
# TRAFFIC_FILE (period_start, period_bytes per client, kept by traffic_collect). A disabled
# client is left out of all three proxy configs; --enforce (also run by the traffic timer
# when something changes) moves clients between active and disabled in ONE clients_change.
# Weeks start on Monday, months on the 1st, days at 00:00, all UTC; an expiry date is valid
# through the end of that day.

# SIZE: plain bytes or a K/M/G/T suffix (decimal: 1G = 10^9). Prints the bytes; fails if invalid
# (not a positive integer, or more than CLIENT_LIMIT_MAX = 10^15): nothing is printed, and it
# still returns 0 (it runs inside $( ), where a failing status would fire the ERR trap).
parse_size() {
    local n mult=1
    [[ "$1" =~ ^([1-9][0-9]{0,15})([KkMmGgTt]?)$ ]] || return 0
    n="${BASH_REMATCH[1]}"
    case "${BASH_REMATCH[2]}" in
        K|k) mult=1000 ;; M|m) mult=1000000 ;; G|g) mult=1000000000 ;; T|t) mult=1000000000000 ;;
    esac
    (( 10#${n} <= CLIENT_LIMIT_MAX / mult )) || return 0
    printf '%s' "$(( 10#${n} * mult ))"
}

# 50000000000 -> "50 GB" (decimal units, as the limit is given)
size_dec() {
    awk -v b="${1:-0}" 'BEGIN { split("B KB MB GB TB PB", u, " "); i = 1
        while (b >= 1000 && i < 6) { b /= 1000; i++ }
        if (b == int(b)) printf "%d %s", b, u[i]; else printf "%.1f %s", b, u[i] }'
}

# First day of the period that contains day $2 (YYYY-MM-DD) for the reset mode $1; nothing for none.
period_start_of() {
    local dow
    case "$1" in
        daily) printf '%s' "$2" ;;
        weekly) dow="$(date -u -d "$2" +%u)"; date -u -d "$2 -$(( dow - 1 )) days" +%F ;;
        monthly) printf '%s-01' "${2:0:7}" ;;
    esac
    return 0
}

# {name: period start or ""} of the added clients that have a limit or a reset (for the traffic
# merge). Reads the client files itself: the caller may not have loaded them.
client_periods_json() {   # $1 = today
    local out
    out="$( (
        load_clients
        for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
            if [[ -n "${CL_LIMIT[i]}" || "${CL_RESET[i]}" != "none" ]]; then
                printf '%s\t%s\n' "${CL_NAMES[i]}" "$(period_start_of "${CL_RESET[i]}" "$1")"
            fi
        done
    ) 2>/dev/null | jq -R -s -c 'split("\n") | map(select(length > 0) | split("\t"))
        | map({key: .[0], value: (.[1] // "")}) | from_entries' 2>/dev/null || true)"
    if [[ "${out}" == "{"* ]]; then printf '%s' "${out}"; else printf '{}'; fi
    return 0
}

# The usage of the current period, by client name (from TRAFFIC_FILE). "-" = no period recorded.
declare -A PU_START=() PU_BYTES=()
PU_OK=0   # 1: the counters were read (a missing or unreadable file proves nothing: no quota is lifted by it)
traffic_load_period_usage() {
    local name st b
    PU_START=(); PU_BYTES=(); PU_OK=0
    [[ -s "${TRAFFIC_FILE}" ]] && command -v jq >/dev/null 2>&1 || return 0
    jq -e 'type == "object"' "${TRAFFIC_FILE}" >/dev/null 2>&1 || return 0
    PU_OK=1
    while IFS=$'\t' read -r name st b; do
        PU_START["${name}"]="${st}"; PU_BYTES["${name}"]="${b}"
    done < <(jq -r '(.clients // {}) | to_entries[]
        | [.key, (.value.period_start // "-"), (.value.period_bytes | if type == "number" and . > 0 then floor else 0 end | tostring)] | @tsv' \
        "${TRAFFIC_FILE}" 2>/dev/null || true)
    return 0
}

# Bytes counted against the limit of client $1 (reset mode $2) on day $3: the recorded usage,
# or 0 when the record is of an earlier period (the collector has not rolled it over yet).
# Sets PB_NOW.
client_period_bytes() {
    local s="${PU_START[$1]:--}" b="${PU_BYTES[$1]:-0}" want
    PB_NOW=0
    [[ "${b}" =~ ^[0-9]{1,16}$ ]] || return 0
    if [[ -n "$2" && "$2" != "none" ]]; then
        want="$(period_start_of "$2" "$3")"
        [[ "${s}" == "${want}" ]] || return 0
    fi
    PB_NOW="${b}"
    return 0
}

# What a client should be, given: state, reason, limit, expires, bytes of the period, today.
# Prints "active" or "disabled <manual|quota|expired>". A manual disable stays until it is
# lifted by hand; a quota or expiry disable lasts only while the condition holds.
client_decision() {
    local st="$1" rs="$2" lim="$3" ex="$4" pb="$5" today="$6" viol=""
    if [[ "${st}" == "disabled" && ( "${rs}" == "manual" || -z "${rs}" ) ]]; then
        printf 'disabled manual'; return 0
    fi
    if [[ -n "${ex}" ]] && (( 10#${today//-/} > 10#${ex//-/} )); then viol="expired"
    elif [[ -n "${lim}" ]] && (( 10#${pb:-0} >= 10#${lim} )); then viol="quota"; fi
    if [[ -n "${viol}" ]]; then printf 'disabled %s' "${viol}"; else printf 'active'; fi
    return 0
}

# The changes to make: parallel arrays; PLAN_LIMIT / PLAN_EXPIRES / PLAN_RESET hold the new
# settings ("-" = keep); PLAN_TEXT is the message for a change of state ("" = settings only).
PLAN_NAMES=(); PLAN_STATE=(); PLAN_REASON=(); PLAN_LIMIT=(); PLAN_EXPIRES=(); PLAN_RESET=(); PLAN_TEXT=()
plan_reset() {
    PLAN_NAMES=(); PLAN_STATE=(); PLAN_REASON=(); PLAN_LIMIT=(); PLAN_EXPIRES=(); PLAN_RESET=(); PLAN_TEXT=()
    return 0
}
plan_add() {   # name, state, reason, limit, expires, reset, text
    PLAN_NAMES+=("$1"); PLAN_STATE+=("$2"); PLAN_REASON+=("$3"); PLAN_LIMIT+=("$4")
    PLAN_EXPIRES+=("$5"); PLAN_RESET+=("$6"); PLAN_TEXT+=("$7")
    return 0
}

# The message of a change of client $1 to state $2 (reason $3); limit $4 and expiry $5 in force.
client_change_text() {
    if [[ "$2" == "active" ]]; then printf 'client %s re-enabled' "$1"; return 0; fi
    case "$3" in
        quota) printf 'client %s disabled: quota %s reached' "$1" "$(size_dec "$4")" ;;
        expired) printf 'client %s disabled: expired on %s' "$1" "$5" ;;
        *) printf 'client %s disabled manually' "$1" ;;
    esac
    return 0
}

# Fills PLAN_* with the clients whose state or reason must change now (CL_* loaded, counters
# current). $1 = today (YYYY-MM-DD, default: today UTC).
enforce_plan() {
    local today="${1:-$(date -u +%F)}" i dec want rs
    plan_reset
    traffic_load_period_usage
    for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
        client_period_bytes "${CL_NAMES[i]}" "${CL_RESET[i]}" "${today}"
        dec="$(client_decision "${CL_STATE[i]}" "${CL_REASON[i]}" "${CL_LIMIT[i]}" "${CL_EXPIRES[i]}" "${PB_NOW}" "${today}")"
        want="${dec%% *}"; rs=""
        if [[ "${dec}" == *" "* ]]; then rs="${dec#* }"; fi
        if [[ "${want}" == "${CL_STATE[i]}" && "${rs}" == "${CL_REASON[i]}" ]]; then continue; fi
        # no readable counters: a client stopped for its quota stays stopped
        if (( PU_OK == 0 )) && [[ "${want}" == "active" && "${CL_REASON[i]}" == "quota" ]]; then continue; fi
        if [[ "${want}" == "${CL_STATE[i]}" ]]; then
            plan_add "${CL_NAMES[i]}" "${want}" "${rs}" - - - ""
        else
            plan_add "${CL_NAMES[i]}" "${want}" "${rs}" - - - \
                "$(client_change_text "${CL_NAMES[i]}" "${want}" "${rs}" "${CL_LIMIT[i]}" "${CL_EXPIRES[i]}")"
        fi
    done
    return 0
}

# The traffic timer asks: does any client need a state change? (own subshell: a damaged
# client file only means "no")
enforce_needed() {
    ( load_clients; enforce_plan; (( ${#PLAN_NAMES[@]} > 0 )) ) 2>/dev/null
}

# After a failed (rolled back) run from the timer, it does not try again for an hour: every
# attempt restarts the proxies.
enforce_backoff_ok() {
    [[ ! -f "${ENFORCE_FAILED}" ]] || (( $(date +%s) - $(stat -c %Y "${ENFORCE_FAILED}" 2>/dev/null || echo 0) > 3600 ))
}

# The header line of a disabled client's details file.
client_disabled_line() {   # name, reason
    printf 'DISABLED (%s): the server does not accept this client until it is enabled again (bash veiltrium.sh --enable-client %s).' "$2" "$1"
}
# Puts the header on (or takes it off) the details file of client $1, without rewriting the rest.
client_file_mark() {
    local f="${CLIENT_FILES_DIR}/$1.txt" i
    i="$(client_index "$1")"
    [[ -f "${f}" && -n "${i}" ]] || return 0
    install -m 600 /dev/null "${f}.new"
    {
        if [[ "${CL_STATE[i]:-}" == "disabled" ]]; then client_disabled_line "$1" "${CL_REASON[i]}"; printf '\n'; fi
        sed '1{/^DISABLED (/d}' "${f}"
    } > "${f}.new"
    mv -f "${f}.new" "${f}"
    return 0
}

# Applies PLAN_*: the files of the changed clients are staged in ${TMPD}/apply; a change of
# state goes through clients_change apply (configs, restart, real-client checks, rollback);
# settings or reasons alone only rewrite the files (nothing restarts). Then, for every change of
# state: the message, an alert and, with $1 = audit, an audit line of its own.
clients_apply_plan() {
    local k i f cfg=0
    (( ${#PLAN_NAMES[@]} )) || return 0
    install -d -m 700 "${TMPD}/apply"
    rm -f "${TMPD}/apply"/*.env
    for (( k = 0; k < ${#PLAN_NAMES[@]}; k++ )); do
        i="$(client_index "${PLAN_NAMES[k]}")"
        [[ -n "${i}" ]] || die "no client ${PLAN_NAMES[k]}."
        write_client_env_i "${i}" "${PLAN_STATE[k]}" "${PLAN_REASON[k]}" "${PLAN_LIMIT[k]}" "${PLAN_EXPIRES[k]}" \
            "${PLAN_RESET[k]}" "${TMPD}/apply/${PLAN_NAMES[k]}.env"
        if [[ "${PLAN_STATE[k]}" != "${CL_STATE[i]}" ]]; then cfg=1; fi
    done
    if (( cfg == 1 )); then
        clients_change apply ""
    else
        for f in "${TMPD}/apply"/*.env; do mv -f "${f}" "${CLIENTS_DIR}/${f##*/}"; done
        load_clients
        for (( k = 0; k < ${#PLAN_NAMES[@]}; k++ )); do client_file_mark "${PLAN_NAMES[k]}"; done
    fi
    for (( k = 0; k < ${#PLAN_NAMES[@]}; k++ )); do
        [[ -n "${PLAN_TEXT[k]}" ]] || continue
        info "${PLAN_TEXT[k]}"
        alert_notify client "${PLAN_TEXT[k]}"
        if [[ "${1:-}" == "audit" ]]; then
            if [[ "${PLAN_STATE[k]}" == "active" ]]; then audit_append client-enabled "${PLAN_NAMES[k]}" ok
            else audit_append client-disabled "${PLAN_NAMES[k]}" ok; fi
        fi
    done
    return 0
}

# Forgets the period usage of client $1 (it starts again from zero when a limit or reset is set).
traffic_period_clear() {
    traffic_edit 'if .clients[$n] then .clients[$n] |= del(.period_start, .period_bytes) else . end' --arg n "$1"
}

# --set-client / --disable-client / --enable-client / --enforce (node_context done, clients loaded).
# $1 = mode, $2 = client name; SET_LIMIT / SET_EXPIRES / SET_RESET: what --set-client was given
# ("" = not given, "none", bytes / a date / a reset mode). Sets RESULT_EXTRA (JSON for --json).
client_limits_main() {
    local mode="$1" name="$2" i today lim ex rst old_had new_had dec want rs pb
    today="$(date -u +%F)"
    RESULT_EXTRA='{}'
    plan_reset
    traffic_collect
    if [[ "${mode}" == "enforce" ]]; then
        enforce_plan "${today}"
        if (( ${#PLAN_NAMES[@]} == 0 )); then info "No client needs a change."; return 0; fi
        if [[ -n "${VEILTRIUM_TIMER:-}" ]]; then install -d -m 700 "${STATE_DIR}"; : > "${ENFORCE_FAILED}"; fi
        clients_apply_plan audit
        rm -f "${ENFORCE_FAILED}"
        RESULT_EXTRA="$(jq -nc '$ARGS.positional' --args "${PLAN_NAMES[@]}" | jq -c '{changed: .}')"
        return 0
    fi
    i="$(client_index "${name}")"
    [[ -n "${i}" ]] || die "no client ${name} (see --list-clients)."
    lim="${CL_LIMIT[i]}"; ex="${CL_EXPIRES[i]}"; rst="${CL_RESET[i]}"
    case "${mode}" in
        set-client)
            case "${SET_LIMIT}" in "") ;; none) lim="" ;; *) lim="${SET_LIMIT}" ;; esac
            case "${SET_EXPIRES}" in "") ;; none) ex="" ;; *) ex="${SET_EXPIRES}" ;; esac
            if [[ -n "${SET_RESET}" ]]; then rst="${SET_RESET}"; fi
            old_had=0; new_had=0
            if [[ -n "${CL_LIMIT[i]}" || "${CL_RESET[i]}" != "none" ]]; then old_had=1; fi
            if [[ -n "${lim}" || "${rst}" != "none" ]]; then new_had=1; fi
            # counting starts when a limit or reset first appears, and stops when both are gone
            if (( old_had != new_had || new_had == 0 )); then traffic_period_clear "${name}"; fi
            traffic_load_period_usage
            client_period_bytes "${name}" "${rst}" "${today}"
            dec="$(client_decision "${CL_STATE[i]}" "${CL_REASON[i]}" "${lim}" "${ex}" "${PB_NOW}" "${today}")"
            want="${dec%% *}"; rs=""
            if [[ "${dec}" == *" "* ]]; then rs="${dec#* }"; fi
            if [[ "${want}" == "${CL_STATE[i]}" ]]; then
                plan_add "${name}" "${want}" "${rs}" "${lim}" "${ex}" "${rst}" ""
            else
                plan_add "${name}" "${want}" "${rs}" "${lim}" "${ex}" "${rst}" "$(client_change_text "${name}" "${want}" "${rs}" "${lim}" "${ex}")"
            fi
            clients_apply_plan audit
            ok "Client ${name}: limit $([[ -n "${lim}" ]] && size_dec "${lim}" || echo none), expires ${ex:-never}, reset ${rst}."
            ;;
        disable-client)
            if [[ "${CL_STATE[i]:-}" == "disabled" && "${CL_REASON[i]}" == "manual" ]]; then
                info "Client ${name} is already disabled."; return 0
            fi
            plan_add "${name}" disabled manual - - - "$(client_change_text "${name}" disabled manual 0 "")"
            clients_apply_plan
            ok "Client ${name} disabled: its credentials no longer work (--enable-client ${name} brings it back)."
            ;;
        enable-client)
            if [[ "${CL_STATE[i]}" != "disabled" ]]; then info "Client ${name} is already active."; return 0; fi
            traffic_load_period_usage
            client_period_bytes "${name}" "${rst}" "${today}"
            pb="${PB_NOW}"
            dec="$(client_decision active "" "${lim}" "${ex}" "${pb}" "${today}")"
            case "${dec}" in
                "disabled quota") die "client ${name} has used its quota ($(size_dec "${pb}") of $(size_dec "${lim}")); raise it first: bash $0 --set-client ${name} --limit SIZE" ;;
                "disabled expired") die "client ${name} expired on ${ex}; set a new date first: bash $0 --set-client ${name} --expires YYYY-MM-DD" ;;
            esac
            plan_add "${name}" active "" - - - "$(client_change_text "${name}" active "" 0 "")"
            clients_apply_plan
            ok "Client ${name} enabled: its credentials work again."
            ;;
    esac
    return 0
}

# ---- Web panel: root helper and password ----------------------------------------
# The panel (an unprivileged service) sends one request per connection to a unix socket;
# systemd starts this script with --helper for it. Only these requests exist, with checked
# names; the reply is ::step / ::log lines, then ::json <document> and ::exit <code>.
helper_relay() {
    local l
    while IFS= read -r l; do
        l="$(printf '%s' "${l}" | sed 's/\x1b\[[0-9;]*m//g' || true)"
        case "${l}" in
            "::step "*) printf '%s\n' "${l}" 2>/dev/null || true ;;
            *) printf '::log %s\n' "${l}" 2>/dev/null || true ;;
        esac
    done
    return 0
}

helper_main() {
    local line="" verb arg="" d rc=0 wait=90
    local -a cargs=()
    trap '' PIPE     # the panel going away must not cut a change short: it runs to the end
    IFS= read -r -t 10 line || true
    line="${line%$'\r'}"
    verb="${line%% *}"
    if [[ "${line}" == *" "* ]]; then arg="${line#* }"; fi
    case "${verb}" in
        status|list-clients|check-russia) [[ -z "${arg}" ]] || verb="" ;;
        audit) [[ -z "${arg}" ]] || verb=""; arg=20 ;;
        show-client) [[ "${arg}" == "main" || "${arg}" =~ ${CLIENT_RE} ]] || verb="" ;;
        add-client|remove-client|reset-client|disable-client|enable-client) [[ "${arg}" =~ ${CLIENT_RE} && "${arg}" != "main" ]] || verb="" ;;
        set-client)   # one line, checked as a whole: set-client NAME limit=<bytes|none> expires=<date|none> reset=<mode>
            if [[ "${line}" =~ ${HELPER_SET_RE} && "${BASH_REMATCH[1]}" != "main" ]]; then
                cargs=("${BASH_REMATCH[1]}" --limit "${BASH_REMATCH[2]}" --expires "${BASH_REMATCH[3]}" --reset "${BASH_REMATCH[4]}")
            else verb=""; fi ;;
        *) verb="" ;;
    esac
    if [[ -z "${verb}" ]]; then
        printf '::log ERROR: request refused\n::exit 2\n'
        return 0
    fi
    case "${verb}" in status|list-clients|show-client|check-russia|audit) wait=10 ;; esac
    if (( ${#cargs[@]} == 0 )) && [[ -n "${arg}" ]]; then cargs=("${arg}"); fi
    d="$(mktemp -d /run/veiltrium-helper.XXXXXX 2>/dev/null || mktemp -d)"   # /run: root-only tmpfs; tests run without root
    # stdout (the JSON) to the file, stderr (human text, progress) through the relay
    # stdin is the socket: the child must never wait on it
    # PIPE is ignored here and would stay ignored in the child: restore its default
    { env --default-signal=PIPE VEILTRIUM_PROGRESS=1 VEILTRIUM_SOURCE=panel VEILTRIUM_LOCK_WAIT="${wait}" NEEDRESTART_SUSPEND=1 \
        bash "${SCRIPT_PATH}" "--${verb}" "${cargs[@]+"${cargs[@]}"}" --json - \
        2>&1 > "${d}/out" </dev/null || printf '%s' "$?" > "${d}/rc"; } | helper_relay
    rc="$(cat "${d}/rc" 2>/dev/null || echo 0)"
    printf '::json %s\n' "$(jq -c . "${d}/out" 2>/dev/null || echo null)" 2>/dev/null || true
    rm -rf "${d}"
    printf '::exit %s\n' "${rc}" 2>/dev/null || true
    return 0
}

# A new panel password: stored as a PBKDF2 hash for the panel, in plain text for root.
# Old sessions end (the panel restarts). $1 = server address for the instructions.
panel_new_password() {
    local pw
    pw="$(openssl rand -base64 30 | tr -dc 'A-Za-z0-9' | cut -c1-24)"
    [[ ${#pw} -eq 24 ]] || die "could not generate a panel password."
    install -d -m 750 -o root -g veiltrium-panel "${PANEL_ETC}"
    install -m 640 -o root -g veiltrium-panel /dev/null "${PANEL_AUTH}.new"
    printf '%s\n' "${pw}" | "${PANEL_BIN}" hash-password > "${PANEL_AUTH}.new" || die "could not hash the panel password."
    mv -f "${PANEL_AUTH}.new" "${PANEL_AUTH}"
    panel_file_write "$1" "${pw}" "Veiltrium web panel ($(date '+%Y-%m-%d %H:%M %Z'))"
    systemctl try-restart veiltrium-panel.service >/dev/null 2>&1 || true
    return 0
}

# panel.txt: the password and both ways in. $1 = server address, $2 = password, $3 = the first line
# (when the password was set). Replaced only when the text changes.
panel_file_write() {
    install -d -m 700 "${VT_ROOT_DIR}"
    install -m 600 /dev/null "${PANEL_FILE}.new"
    {
        cat <<EOF
$3
Keep this secret.

Password: $2

The panel listens on 127.0.0.1 only: nothing new is open on the internet.
Open it through an SSH tunnel from your computer (PowerShell or a terminal):
  ssh -N -L ${PANEL_PORT}:127.0.0.1:${PANEL_PORT} root@$1
then in the browser:  http://localhost:${PANEL_PORT}/
EOF
        if [[ -n "${R_ADMIN_UUID}" && -n "${R_SITE}" ]] && panel_vpn_live; then
            cat <<EOF

Or through the VPN, without SSH (phone or computer):
1. Import this VLESS profile into a VPN app (v2rayN, Hiddify, NekoBox, sing-box) and connect with it.
   It is for you only: it opens the panel's page (the password is still asked) and is not a client's link.
  $(vless_link "${R_ADMIN_UUID}" "$1" "${LABEL}-panel")
2. While it is connected, open in the browser:  http://$1:${PANEL_PORT}/
   (Other profiles and the internet cannot reach this address: the port is not open.)
   Only with this profile connected: without it the browser goes to that address over the open
   network in plain HTTP, where anyone on the way could answer with a fake page. Never type the
   password into a page you opened without the profile.
Turn it off: PANEL_VPN=0 bash veiltrium.sh (turning it on again gives a new profile).
EOF
        fi
        printf 'New password (signs everybody out):  bash veiltrium.sh --panel-password\n'
    } > "${PANEL_FILE}.new"
    if cmp -s "${PANEL_FILE}.new" "${PANEL_FILE}"; then rm -f "${PANEL_FILE}.new"; else mv -f "${PANEL_FILE}.new" "${PANEL_FILE}"; fi
    return 0
}

# Does the installed panel accept the server's address as its host name (the VPN way works)?
panel_vpn_live() {
    grep -E '^ExecStart=.* --host [0-9.]+$' /etc/systemd/system/veiltrium-panel.service >/dev/null 2>&1
}

# Keeps panel.txt in step with the node (the VPN profile, the port) without a new password.
# $1 = server address. A file without the password line (deleted by hand) says how to get a new one.
panel_file_refresh() {
    local pw="" head=""
    if [[ -s "${PANEL_FILE}" ]]; then
        head="$(head -n 1 "${PANEL_FILE}")"
        pw="$(sed -n 's/^Password: \([A-Za-z0-9]\{12,256\}\)$/\1/p' "${PANEL_FILE}" | head -n 1 || true)"
    fi
    [[ "${head}" == "Veiltrium web panel ("*")" ]] || head="Veiltrium web panel"
    panel_file_write "$1" "${pw:-(not stored here; a new one: bash veiltrium.sh --panel-password)}" "${head}"
    return 0
}

# ---- Moving a node to a new server (--export / --import) ---------------------
# An export is a tar of a fixed list of state files, encrypted with a passphrase
# (openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -md sha256; the file is pure openssl
# output). It holds every secret of the node: on a new server the keys stay the same and
# the links differ only by the address. The import validates everything before a single
# file is placed.
EXPORT_FORMAT="veiltrium-export/1"
EXPORT_ITER=600000
EXPORT_DIRS="hysteria reality trusttunnel veiltrium clients"
EXPORT_COMMENT_RE='^# veiltrium: [A-Za-z0-9 ().,;<>_/-]{0,120}$'
VT_PASS=""
IMPORTED=0; IMPORT_FRESH=0; IMPORT_OLD_IP=""

# Is $1 (relative to the archive root) a name an export may contain?
export_name_ok() {
    local n
    case "$1" in
        meta|MANIFEST|hysteria/node.env|hysteria/server.crt|hysteria/server.key|reality/reality.env|\
        trusttunnel/node.env|trusttunnel/cert.pem|trusttunnel/key.pem|\
        veiltrium/node.env|veiltrium/probe.env|veiltrium/reality-candidates) return 0 ;;
        clients/*.env)
            n="${1#clients/}"; n="${n%.env}"
            if [[ "${n}" =~ ${CLIENT_RE} && "${n}" != "main" ]]; then return 0; fi ;;
    esac
    return 1
}

# Where the file with the relative name $1 lives on this server.
export_path() {
    case "$1" in
        hysteria/node.env) printf '%s' "${HY2_STATE}" ;;
        hysteria/server.crt) printf '%s' "${HY2_CERT}" ;;
        hysteria/server.key) printf '%s' "${HY2_KEY}" ;;
        reality/reality.env) printf '%s' "${XRAY_STATE}" ;;
        trusttunnel/node.env) printf '%s' "${TT_STATE}" ;;
        trusttunnel/cert.pem) printf '%s' "${TT_DIR}/cert.pem" ;;
        trusttunnel/key.pem) printf '%s' "${TT_DIR}/key.pem" ;;
        veiltrium/node.env) printf '%s' "${NODE_ENV}" ;;
        veiltrium/probe.env) printf '%s' "${PROBE_ENV}" ;;
        veiltrium/reality-candidates) printf '%s' "${CANDIDATES_FILE}" ;;
        clients/*.env) printf '%s' "${CLIENTS_DIR}/${1#clients/}" ;;
    esac
    return 0
}

# Passphrase: $1 = name of the environment variable that may hold it, $2 = new (asked
# twice, at least 12 characters) or old. Sets VT_PASS. Read from the terminal, never
# from a command line; the variable is removed from the environment at once.
read_passphrase() {
    local envname="$1" mode="$2" p1="" p2=""
    VT_PASS=""
    if [[ -n "${!envname:-}" ]]; then
        p1="${!envname}"
        unset "${envname}"
    else
        { : </dev/tty; } 2>/dev/null || die "no terminal to ask for the passphrase; set ${envname} instead."
        printf 'Passphrase: ' >/dev/tty
        read -rs p1 </dev/tty || die "no passphrase was entered."
        printf '\n' >/dev/tty
        if [[ "${mode}" == "new" ]]; then
            printf 'Again: ' >/dev/tty
            read -rs p2 </dev/tty || die "no passphrase was entered."
            printf '\n' >/dev/tty
            [[ "${p1}" == "${p2}" ]] || die "the two passphrases differ; nothing was written."
        fi
    fi
    [[ -n "${p1}" ]] || die "the passphrase is empty."
    if [[ "${mode}" == "new" ]] && (( ${#p1} < 12 )); then
        die "the passphrase is too short (12 characters at least); nothing was written."
    fi
    VT_PASS="${p1}"
    return 0
}

# Is the decoded value $2 acceptable for the key $1? These are the only keys the state files use.
env_value_ok() {
    local v="$2" p
    case "$1" in
        H_PASSWORD|T_PASS|C_HY2_PASS|C_TT_PASS|H_STATS_SECRET) [[ "${v}" =~ ^[0-9a-f]{48}$ ]] ;;
        H_STATS_PORT|R_STATS_PORT|T_STATS_PORT)   # loopback ports of the statistics endpoints
            [[ "${v}" =~ ^[0-9]{1,5}$ ]] || return 1
            p=$((10#${v})); (( p >= 1024 && p <= 65535 )) ;;
        H_SNI|T_SNI) [[ "${v}" =~ ${DOMAIN_RE} ]] ;;
        R_SITE) [[ -z "${v}" || "${v}" =~ ${DOMAIN_RE} ]] ;;
        H_PORT)
            [[ "${v}" =~ ^[0-9]{1,5}$ ]] || return 1
            p=$((10#${v})); (( p >= 1 && p <= 65535 )) ;;
        H_MASQ) [[ "${v}" == "auto" || "${v}" =~ ^https?://[A-Za-z0-9._~:/?#@\&+,=%-]+$ ]] ;;
        H_AUTH) [[ "${v}" == "password" || "${v}" == "userpass" ]] ;;
        R_UUID|R_ADMIN_UUID|C_UUID) [[ "${v}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] ;;
        R_PRIV|R_PUB) [[ "${v}" =~ ^[A-Za-z0-9_-]{43}$ ]] ;;
        R_SID) [[ "${v}" =~ ^[0-9a-f]{16}$ ]] ;;
        T_USER) [[ "${v}" =~ ^[A-Za-z0-9_-]{1,32}$ ]] ;;
        T_IPV6) [[ -z "${v}" || "${v}" == "true" || "${v}" == "false" ]] ;;
        N_NAME) [[ -z "${v}" || "${v}" =~ ${NAME_RE} ]] ;;
        N_GLOBALPING|N_PANEL_VPN) [[ "${v}" == "0" || "${v}" == "1" ]] ;;
        N_STANDBY)   # what save_node_name writes: 1-3 distinct public IPv4 addresses, comma-separated
            ( standby_parse "${v}" ) && [[ -n "${v}" && "${v}" != "none" && "${v}" =~ ^[0-9.]+(,[0-9.]+){0,2}$ ]] ;;
        PROBE_KEY) [[ "${v}" =~ ^[0-9a-f]{64}$ ]] ;;
        PROBE_SERVER) [[ -z "${v}" || "${v}" =~ ^[0-9.]{7,15}$ ]] ;;
        C_NAME) [[ "${v}" =~ ${CLIENT_RE} ]] ;;
        C_CREATED) [[ "${v}" =~ ^([0-9]{4}-[0-9]{2}-[0-9]{2}|\?)$ ]] ;;
        C_LIMIT) [[ "${v}" =~ ^[1-9][0-9]{0,15}$ ]] && (( 10#${v} <= CLIENT_LIMIT_MAX )) ;;
        C_EXPIRES) date_ok "${v}" ;;
        C_RESET) [[ "${v}" == "daily" || "${v}" == "weekly" || "${v}" == "monthly" ]] ;;
        C_STATE) [[ "${v}" == "disabled" ]] ;;
        C_REASON) [[ "${v}" == "manual" || "${v}" == "quota" || "${v}" == "expired" ]] ;;
        *) return 1 ;;
    esac
}

# $1 = file, $2 = required keys, $3 = optional keys (space-separated). The file is later
# sourced by root, so every line must be what the save_* functions write: KEY=value from
# printf %q, the value made of plain characters or backslash-escaped ones (never $'...',
# quotes, $( ), backticks or an unescaped ; or space), a key allowed for this file, once,
# with a value that is valid for the key. A "# veiltrium: ..." comment line is fine.
env_file_ok() {
    local f="$1" req="$2" opt="$3" line key raw val seen=" " k
    local re_val='^([A-Za-z0-9._:/@+=,%~-]|\\[^[:alnum:][:cntrl:]])+$'
    local LC_ALL=C
    [[ -f "${f}" && ! -L "${f}" && -s "${f}" ]] || return 1
    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ "${line}" =~ ${EXPORT_COMMENT_RE} ]]; then continue; fi
        [[ "${line}" =~ ^([A-Z][A-Z0-9_]*)=(.*)$ ]] || return 1
        key="${BASH_REMATCH[1]}"; raw="${BASH_REMATCH[2]}"
        [[ " ${req} ${opt} " == *" ${key} "* && "${seen}" != *" ${key} "* ]] || return 1
        seen+="${key} "
        if [[ "${raw}" == "''" ]]; then
            val=""
        else
            [[ "${raw}" =~ ${re_val} ]] || return 1
            val="$(printf '%s' "${raw}" | sed -E 's/\\(.)/\1/g')"
        fi
        env_value_ok "${key}" "${val}" || return 1
    done < "${f}"
    for k in ${req}; do
        [[ "${seen}" == *" ${k} "* ]] || return 1
    done
    return 0
}

# First value of KEY ($2) in the state file $1 (raw text; plain characters in a validated file).
env_get() { sed -n "s/^$2=//p" "$1" | head -n 1; }

# $1 = certificate, $2 = key, $3 = name the certificate must be valid for (optional).
cert_pair_ok() {
    local pub
    [[ -s "$1" && -s "$2" ]] || return 1
    pub="$(openssl x509 -in "$1" -noout -pubkey 2>/dev/null)" || return 1
    [[ -n "${pub}" && "${pub}" == "$(openssl pkey -in "$2" -pubout 2>/dev/null)" ]] || return 1
    if [[ -n "${3:-}" ]]; then
        [[ "$(openssl x509 -in "$1" -noout -checkhost "$3" 2>/dev/null)" == *"does match"* ]] || return 1
    fi
    return 0
}

# meta: exactly these lines, in this order.
export_meta_ok() {
    local f="$1" i=0 line k v p
    local -a keys=(format version created ip reality_port tt_port reality_enabled tt_enabled)
    local LC_ALL=C
    [[ -f "${f}" && ! -L "${f}" ]] || return 1
    while IFS= read -r line || [[ -n "${line}" ]]; do
        (( i < ${#keys[@]} )) || return 1
        k="${keys[i]}"
        [[ "${line}" == "${k}="* ]] || return 1
        v="${line#"${k}="}"
        case "${k}" in
            format) [[ "${v}" == "${EXPORT_FORMAT}" ]] || return 1 ;;
            version) [[ "${v}" =~ ^[0-9][0-9.-]{0,30}$ ]] || return 1 ;;
            created) [[ "${v}" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$ ]] || return 1 ;;
            ip) [[ "${v}" =~ ^([0-9]{1,3}(\.[0-9]{1,3}){3}|unknown)$ ]] || return 1 ;;
            reality_port|tt_port)
                [[ "${v}" =~ ^[0-9]{1,5}$ ]] || return 1
                p=$((10#${v})); (( p >= 1 && p <= 65535 )) || return 1 ;;
            *) [[ "${v}" == "0" || "${v}" == "1" ]] || return 1 ;;
        esac
        i=$((i + 1))
    done < "${f}"
    (( i == ${#keys[@]} ))
}

# Checks the files of an export tree ($1): each one for what it is, and the set as a whole.
# Used on the source before packing and on the target after unpacking. Prints the reason
# on failure.
export_tree_ok() {
    local d="$1" f rel n sni cnt line want
    local -a files=()
    while IFS= read -r -d '' f; do files+=("${f#"${d}/"}"); done < <(find "${d}" -type f -print0)
    for rel in "${files[@]}"; do
        export_name_ok "${rel}" || { echo "unexpected file ${rel}"; return 1; }
        f="${d}/${rel}"
        case "${rel}" in
            meta|MANIFEST) ;;
            hysteria/node.env) env_file_ok "${f}" "H_PASSWORD H_SNI H_PORT" "H_MASQ H_AUTH H_STATS_PORT H_STATS_SECRET" || { echo "bad ${rel}"; return 1; } ;;
            reality/reality.env) env_file_ok "${f}" "R_UUID R_PRIV R_PUB R_SID R_SITE" "R_STATS_PORT R_ADMIN_UUID" || { echo "bad ${rel}"; return 1; } ;;
            trusttunnel/node.env) env_file_ok "${f}" "T_USER T_PASS T_SNI" "T_IPV6 T_STATS_PORT" || { echo "bad ${rel}"; return 1; } ;;
            veiltrium/node.env) env_file_ok "${f}" "" "N_NAME N_GLOBALPING N_STANDBY N_PANEL_VPN" || { echo "bad ${rel}"; return 1; } ;;
            veiltrium/probe.env) env_file_ok "${f}" "PROBE_KEY PROBE_SERVER" "" || { echo "bad ${rel}"; return 1; } ;;
            veiltrium/reality-candidates)
                cnt=0
                while IFS= read -r line || [[ -n "${line}" ]]; do
                    if [[ -z "${line}" || "${line}" =~ ${EXPORT_COMMENT_RE} ]]; then continue; fi
                    [[ "${line}" =~ ${DOMAIN_RE} ]] || { echo "bad ${rel}"; return 1; }
                    cnt=$((cnt + 1))
                done < "${f}"
                (( cnt > 0 )) || { echo "bad ${rel}"; return 1; } ;;
            clients/*.env)
                env_file_ok "${f}" "C_NAME C_UUID C_HY2_PASS C_TT_PASS" "C_CREATED C_LIMIT C_EXPIRES C_RESET C_STATE C_REASON" || { echo "bad ${rel}"; return 1; }
                n="$(env_get "${f}" C_NAME)"
                [[ "clients/${n}.env" == "${rel}" ]] || { echo "the client name in ${rel} does not match its file name"; return 1; } ;;
        esac
    done
    for rel in hysteria/node.env hysteria/server.crt hysteria/server.key meta; do
        [[ -f "${d}/${rel}" ]] || { echo "${rel} is missing"; return 1; }
    done
    export_meta_ok "${d}/meta" || { echo "bad meta"; return 1; }
    sni="$(env_get "${d}/hysteria/node.env" H_SNI)"
    cert_pair_ok "${d}/hysteria/server.crt" "${d}/hysteria/server.key" "${sni}" \
        || { echo "the Hysteria certificate and key are not a pair for ${sni}"; return 1; }
    want=0
    if [[ -e "${d}/trusttunnel/node.env" || -e "${d}/trusttunnel/cert.pem" || -e "${d}/trusttunnel/key.pem" ]]; then
        want=1
        [[ -f "${d}/trusttunnel/node.env" ]] || { echo "trusttunnel/node.env is missing"; return 1; }
        sni="$(env_get "${d}/trusttunnel/node.env" T_SNI)"
        cert_pair_ok "${d}/trusttunnel/cert.pem" "${d}/trusttunnel/key.pem" "${sni}" \
            || { echo "the TrustTunnel certificate and key are not a pair for ${sni}"; return 1; }
    fi
    [[ "$(sed -n 's/^tt_enabled=//p' "${d}/meta")" == "${want}" ]] || { echo "meta and files disagree about TrustTunnel"; return 1; }
    want=0
    if [[ -e "${d}/reality/reality.env" ]]; then want=1; fi
    [[ "$(sed -n 's/^reality_enabled=//p' "${d}/meta")" == "${want}" ]] || { echo "meta and files disagree about Reality"; return 1; }
    return 0
}

# $1 = output file. Needs TMPD (a private directory).
export_node() {
    local out="$1" d="${TMPD}/export" rel f why
    local -a files=() sorted=()
    [[ -s "${HY2_STATE}" && -s "${HY2_CERT}" && -s "${HY2_KEY}" ]] \
        || die "no installed node found on this server; nothing to export."
    [[ ! -e "${out}" && ! -L "${out}" ]] || die "${out} already exists; choose a new file name (nothing was changed)."
    [[ -d "$(dirname -- "${out}")" ]] || die "the folder of ${out} does not exist."
    read_passphrase VT_EXPORT_PASSPHRASE new
    install -d -m 700 "${d}"
    for rel in hysteria/node.env hysteria/server.crt hysteria/server.key reality/reality.env \
               trusttunnel/node.env trusttunnel/cert.pem trusttunnel/key.pem \
               veiltrium/node.env veiltrium/probe.env veiltrium/reality-candidates; do
        if [[ -s "$(export_path "${rel}")" ]]; then files+=("${rel}"); fi
    done
    for f in "${CLIENTS_DIR}"/*.env; do
        [[ -f "${f}" ]] || continue
        rel="clients/${f##*/}"
        export_name_ok "${rel}" || die "the client file ${f} has an unexpected name; nothing was exported."
        files+=("${rel}")
    done
    for rel in "${files[@]}"; do
        install -d -m 700 "${d}/${rel%/*}"
        install -m 600 "$(export_path "${rel}")" "${d}/${rel}"
    done
    printf 'format=%s\nversion=%s\ncreated=%s\nip=%s\nreality_port=%s\ntt_port=%s\nreality_enabled=%s\ntt_enabled=%s\n' \
        "${EXPORT_FORMAT}" "${SCRIPT_VERSION}" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${PUBLIC_IP:-unknown}" \
        "${REALITY_PORT}" "${TT_PORT}" "$([[ -s "${XRAY_STATE}" ]] && echo 1 || echo 0)" \
        "$([[ -s "${TT_STATE}" ]] && echo 1 || echo 0)" > "${d}/meta"
    chmod 600 "${d}/meta"
    why="$(export_tree_ok "${d}")" || die "the node's files did not pass the check (${why}); nothing was exported."
    files+=(meta)
    mapfile -t sorted < <(printf '%s\n' "${files[@]}" | LC_ALL=C sort)
    (cd "${d}" && sha256sum -- "${sorted[@]}" > MANIFEST)
    chmod 600 "${d}/MANIFEST"
    LC_ALL=C tar --format=ustar --owner=0 --group=0 --numeric-owner --mtime='UTC 1970-01-01' \
        -cf "${TMPD}/export.tar" -C "${d}" MANIFEST "${sorted[@]}" || die "could not pack the files."
    # The file is created exclusively and for root only before anything is written to it.
    ( set -C; umask 077; : > "${out}" ) 2>/dev/null || die "could not create ${out} (it may exist already)."
    if ! openssl enc -aes-256-cbc -pbkdf2 -iter "${EXPORT_ITER}" -salt -md sha256 -pass fd:3 \
            -in "${TMPD}/export.tar" -out "${out}" 3< <(printf '%s\n' "${VT_PASS}") 2>/dev/null; then
        rm -f -- "${out}"
        die "encryption failed; nothing was written."
    fi
    chmod 600 "${out}"
    VT_PASS=""
    rm -rf -- "${d}" "${TMPD}/export.tar"
    printf '\nExported this node to %s (%s bytes, mode 600; AES-256-CBC, PBKDF2).\n' "${out}" "$(stat -c %s -- "${out}")"
    printf '  Hysteria%s: keys, passwords, server names, certificates, %s added client(s).\n' \
        "$([[ -s "${XRAY_STATE}" ]] && echo ", Reality")$([[ -s "${TT_STATE}" ]] && echo ", TrustTunnel")" "$(count_clients)"
    printf '\nNext:\n'
    printf '  1. copy the file to the new server, e.g.  scp %s root@NEW_IP:/root/\n' "${out}"
    printf '  2. on the new server, as root:  bash veiltrium.sh --import /root/%s\n' "${out##*/}"
    printf '  3. the links stay the same except the server address. Delete the file afterwards.\n'
    printf '  The passphrase is the only protection of this file: keep the two apart.\n'
    return 0
}

# Decrypts $1 into $2 with VT_PASS. A wrong passphrase and a damaged file look the same.
export_decrypt() {
    local in="$1" out="$2" size
    [[ -f "${in}" && ! -L "${in}" ]] || die "${in} is not a readable file; nothing was changed."
    size="$(stat -c %s -- "${in}")"
    (( size > 0 && size <= 20000000 )) || die "${in} has an unexpected size; nothing was changed."
    if ! openssl enc -d -aes-256-cbc -pbkdf2 -iter "${EXPORT_ITER}" -md sha256 -pass fd:3 \
            -in "${in}" -out "${out}" 3< <(printf '%s\n' "${VT_PASS}") 2>/dev/null; then
        rm -f -- "${out}"
        die "could not decrypt ${in}: wrong passphrase or a damaged file; nothing was changed."
    fi
    return 0
}

# Lists the tar $1 first: only plain files, names from the fixed list, sane sizes. Then
# unpacks it into the new directory $2 and checks the manifest and every file.
export_unpack() {
    local tarf="$1" dest="$2" line n=0 size name seen=" " mlist=" " f rel why
    local re='^-[-rwxsStT]{9} [^[:space:]/]+/[^[:space:]/]+ +([0-9]+) [0-9-]+ [0-9:]+ (.+)$'
    local LC_ALL=C
    tar -tvf "${tarf}" --quoting-style=literal > "${dest}.list" 2>/dev/null \
        || die "this is not a valid export (or the passphrase was wrong); nothing was changed."
    while IFS= read -r line; do
        [[ "${line}" =~ ${re} ]] || die "the export contains something that is not a plain file; nothing was changed."
        size="${BASH_REMATCH[1]}"; name="${BASH_REMATCH[2]}"
        export_name_ok "${name}" || die "the export contains an unexpected file name; nothing was changed."
        [[ "${seen}" != *" ${name} "* ]] || die "the export lists a file twice; nothing was changed."
        seen+="${name} "
        (( 10#${size} <= 65536 )) || die "the export contains an oversized file; nothing was changed."
        n=$((n + 1))
        (( n <= 300 )) || die "the export contains too many files; nothing was changed."
    done < "${dest}.list"
    rm -f "${dest}.list"
    (( n >= 5 )) || die "the export is incomplete; nothing was changed."
    install -d -m 700 "${dest}"
    ( umask 077; tar -xf "${tarf}" -C "${dest}" --no-same-owner --no-same-permissions ) 2>/dev/null \
        || die "could not unpack the export; nothing was changed."
    # what was really unpacked: the listed plain files and the fixed folders, nothing else
    while IFS= read -r -d '' f; do
        rel="${f#"${dest}/"}"
        if [[ -L "${f}" ]]; then
            die "the export unpacked a link; nothing was changed."
        elif [[ -d "${f}" ]]; then
            [[ " ${EXPORT_DIRS} " == *" ${rel} "* ]] || die "the export unpacked an unexpected folder; nothing was changed."
        elif [[ -f "${f}" ]]; then
            [[ "${seen}" == *" ${rel} "* ]] || die "the export unpacked an unexpected file; nothing was changed."
        else
            die "the export unpacked something that is not a plain file; nothing was changed."
        fi
    done < <(find "${dest}" -mindepth 1 -print0)
    # manifest: a sha256 of every file except itself, and no file missing from it
    [[ -f "${dest}/MANIFEST" ]] || die "the export has no manifest; nothing was changed."
    while IFS= read -r line; do
        [[ "${line}" =~ ^[0-9a-f]{64}\ \ (.+)$ ]] || die "the export manifest is damaged; nothing was changed."
        name="${BASH_REMATCH[1]}"
        [[ "${name}" != "MANIFEST" && "${seen}" == *" ${name} "* && "${mlist}" != *" ${name} "* ]] \
            || die "the export manifest does not match its files; nothing was changed."
        mlist+="${name} "
    done < "${dest}/MANIFEST"
    for name in ${seen}; do
        [[ "${name}" == "MANIFEST" || "${mlist}" == *" ${name} "* ]] \
            || die "the export manifest does not match its files; nothing was changed."
    done
    (cd "${dest}" && sha256sum -c --quiet --strict MANIFEST >/dev/null 2>&1) \
        || die "a file of the export was changed (checksum mismatch); nothing was changed."
    why="$(export_tree_ok "${dest}")" || die "the export did not pass the check (${why}); nothing was changed."
    return 0
}

# The export in $1 may replace the state here only if this server has no node, or runs the
# same one (same Hysteria password, same Reality UUID): a standby copy being refreshed.
# Sets IMPORT_FRESH (1: no node here).
import_identity_ok() {
    local d="$1" have=0 f
    for f in "${HY2_STATE}" "${XRAY_STATE}" "${TT_STATE}" "${HY2_CONFIG}"; do
        if [[ -e "${f}" ]]; then have=1; fi
    done
    IMPORT_FRESH=1
    if (( have == 0 )); then return 0; fi
    IMPORT_FRESH=0
    if [[ -s "${HY2_STATE}" && "$(env_get "${HY2_STATE}" H_PASSWORD)" == "$(env_get "${d}/hysteria/node.env" H_PASSWORD)" ]]; then
        if [[ -e "${XRAY_STATE}" ]]; then
            if [[ ! -f "${d}/reality/reality.env" || "$(env_get "${XRAY_STATE}" R_UUID)" != "$(env_get "${d}/reality/reality.env" R_UUID)" ]]; then
                die "this server already runs a different node; nothing was changed."
            fi
        fi
        return 0
    fi
    die "this server already runs a different node; nothing was changed."
}

# Installs one file: $1 source, $2 target, $3 final mode, $4 group (used once that group
# exists; before that the file is root-only and the normal install steps set the final owner).
import_put() {
    local mode=600
    local -a own=()
    if (( EUID == 0 )) && [[ -n "${4:-}" ]] && getent group "$4" >/dev/null 2>&1; then own=(-o root -g "$4"); mode="$3"; fi
    install -m "${mode}" "${own[@]+"${own[@]}"}" "$1" "$2.new"
    mv -f "$2.new" "$2"
}

# Places the validated tree $1. The N_NAME of the old server is dropped (the country is
# detected again here); no panel password is part of an export.
import_place() {
    local d="$1" f
    for f in "${HY2_DIR}" "${XRAY_DIR}" "${TT_DIR}" "${SCANNER_DIR}" "${CLIENTS_DIR}"; do
        [[ -d "${f}" ]] || install -d -m 700 "${f}"
    done
    import_put "${d}/hysteria/node.env" "${HY2_STATE}" 600 ""
    import_put "${d}/hysteria/server.crt" "${HY2_CERT}" 644 hysteria
    import_put "${d}/hysteria/server.key" "${HY2_KEY}" 640 hysteria
    if [[ -f "${d}/reality/reality.env" ]]; then import_put "${d}/reality/reality.env" "${XRAY_STATE}" 600 ""; fi
    if [[ -f "${d}/trusttunnel/node.env" ]]; then
        import_put "${d}/trusttunnel/node.env" "${TT_STATE}" 600 ""
        import_put "${d}/trusttunnel/cert.pem" "${TT_DIR}/cert.pem" 644 trusttunnel
        import_put "${d}/trusttunnel/key.pem" "${TT_DIR}/key.pem" 640 trusttunnel
    fi
    if [[ -f "${d}/veiltrium/node.env" ]]; then
        grep -v '^N_NAME=' "${d}/veiltrium/node.env" > "${d}/node.env.tmp" || true
        import_put "${d}/node.env.tmp" "${NODE_ENV}" 600 ""
    fi
    if [[ -f "${d}/veiltrium/probe.env" ]]; then import_put "${d}/veiltrium/probe.env" "${PROBE_ENV}" 600 ""; fi
    if [[ -f "${d}/veiltrium/reality-candidates" ]]; then import_put "${d}/veiltrium/reality-candidates" "${CANDIDATES_FILE}" 600 ""; fi
    # the clients of the export are the clients: a refreshed copy drops those that were removed
    for f in "${CLIENTS_DIR}"/*.env; do
        if [[ -f "${f}" && ! -e "${d}/clients/${f##*/}" ]]; then rm -f -- "${f}"; fi
    done
    for f in "${d}"/clients/*.env; do
        [[ -f "${f}" ]] || continue
        import_put "${f}" "${CLIENTS_DIR}/${f##*/}" 600 ""
    done
    return 0
}

# Install mode with --import FILE: unpack, validate, place; before any state is read.
import_node() {
    local file="$1" imp="${TMPD}/import" v
    [[ -f "${file}" && ! -L "${file}" ]] || die "${file} is not a readable file; nothing was changed."
    read_passphrase VT_IMPORT_PASSPHRASE old
    install -d -m 700 "${imp}"
    export_decrypt "${file}" "${imp}/export.tar"
    VT_PASS=""
    export_unpack "${imp}/export.tar" "${imp}/tree"
    import_identity_ok "${imp}/tree"
    import_place "${imp}/tree"
    IMPORTED=1
    IMPORT_OLD_IP="$(sed -n 's/^ip=//p' "${imp}/tree/meta")"
    # the ports and switches of the old node, unless they are given explicitly
    v="$(sed -n 's/^reality_port=//p' "${imp}/tree/meta")"
    if [[ -z "${REALITY_PORT_GIVEN}" ]]; then REALITY_PORT="${v}"; REALITY_PORT_GIVEN=1; fi
    v="$(sed -n 's/^tt_port=//p' "${imp}/tree/meta")"
    if [[ -z "${TT_PORT_GIVEN}" ]]; then TT_PORT="${v}"; TT_PORT_GIVEN=1; fi
    if [[ -z "${REALITY_ENABLE_GIVEN}" ]]; then REALITY_ENABLE="$(sed -n 's/^reality_enabled=//p' "${imp}/tree/meta")"; fi
    if [[ -z "${TT_ENABLE_GIVEN}" ]]; then TT_ENABLE="$(sed -n 's/^tt_enabled=//p' "${imp}/tree/meta")"; fi
    rm -rf -- "${imp}"
    ok "Imported the node of ${IMPORT_OLD_IP} (keys, passwords, server names and clients kept; the node name is detected again)"
    return 0
}

# ---- Short command: /usr/local/bin/veiltrium --------------------------------
# A small wrapper over the installed copy of this script. The text comes from here so a test
# can generate it with a stub script path ($1). To add a command, add one line to its case.
cli_wrapper_text() {
    printf '#!/bin/bash\n# veiltrium: short command (written by the installer)\nVT_SCRIPT=%q\n' "$1"
    cat <<'EOF'
if [[ ! -f "${VT_SCRIPT}" ]]; then
    echo "veiltrium: ${VT_SCRIPT} is missing; run the installer once (bash veiltrium.sh)." >&2
    exit 1
fi
cli_usage() {
    cat <<'USAGE'
Usage: veiltrium COMMAND [NAME|FILE]

  status           overview of the node (no tests)
  clients          list the clients
  add NAME         add a client (own credentials for all protocols)
  remove NAME      revoke a client
  reset NAME       new credentials for a client (the old ones stop working)
  limit NAME ...   traffic limit, expiry and reset of a client: --limit 50G --expires 2027-01-31 --reset monthly
  disable NAME     stop accepting a client (kept; enable brings it back)
  enable NAME      accept a disabled client again
  show NAME        connection details of a client (main: the first one)
  qr NAME          QR codes of a client's links
  traffic          traffic per client
  export FILE      pack this node for a new server (encrypted with a passphrase)
  russia           can Russian networks reach this server?
  audit [N]        the last N lines of the audit log (default 50)
  test-alert       send a test message to the alert channels
  check-update     is a newer release out?
  update           download the newest release and install it
  diagnose         check the node; no changes
  panel-password   a new web panel password
  install          run the installer again (update or repair)
  uninstall        remove Veiltrium from this server (asks first)
  help             all modes and settings

Any option of the installer also works:  veiltrium --dry-run
USAGE
}
cmd="${1:-help}"
[[ $# -eq 0 ]] || shift
case "${cmd}" in
    -*)             exec bash "${VT_SCRIPT}" "${cmd}" "$@" ;;
    status)         set -- --status "$@" ;;
    clients)        set -- --list-clients "$@" ;;
    add)            set -- --add-client "$@" ;;
    remove)         set -- --remove-client "$@" ;;
    reset)          set -- --reset-client "$@" ;;
    limit)          set -- --set-client "$@" ;;
    disable)        set -- --disable-client "$@" ;;
    enable)         set -- --enable-client "$@" ;;
    show)           set -- --show-client "$@" ;;
    qr)             set -- --qr "$@" ;;
    traffic)        set -- --traffic "$@" ;;
    export)         set -- --export "$@" ;;
    russia)         set -- --check-russia "$@" ;;
    audit)          set -- --audit "$@" ;;
    test-alert)     set -- --test-alert "$@" ;;
    check-update)   set -- --check-update "$@" ;;
    update)         set -- --update "$@" ;;
    diagnose)       set -- --diagnose "$@" ;;
    panel-password) set -- --panel-password "$@" ;;
    uninstall)      set -- --uninstall "$@" ;;
    install)        set -- "$@" ;;
    help)           set -- --help ;;
    *)              echo "veiltrium: unknown command: ${cmd}" >&2; cli_usage >&2; exit 2 ;;
esac
exec bash "${VT_SCRIPT}" "$@"
EOF
}

# Rewritten only when the text differs (no needless writes on a re-run).
# The tests pass a destination; the installer uses the default.
# shellcheck disable=SC2120
write_cli_wrapper() {
    local dest="${1:-${CLI_BIN}}"
    cli_wrapper_text "${PANEL_LIB}/veiltrium.sh" > "${dest}.new"
    if cmp -s "${dest}.new" "${dest}"; then
        rm -f "${dest}.new"
    else
        chmod 755 "${dest}.new"
        mv -f "${dest}.new" "${dest}"
    fi
}

# The links of a client's details file: one per line (a standby link is a line of its own).
qr_links() {
    grep -E '^(hysteria2|vless|tt)://' "$1" 2>/dev/null | awk '!seen[$0]++' || true
}

# Terminal QR codes (the output carries secrets: terminal only, never a log).
qr_show() {
    local file="$1" link proto frag cap n=0
    command -v qrencode >/dev/null 2>&1 || die "qrencode is missing: run the installer once (bash $0) first."
    while IFS= read -r link; do
        [[ -n "${link}" ]] || continue
        case "${link}" in
            hysteria2://*) proto="Hysteria 2" ;;
            vless://*)     proto="VLESS Reality" ;;
            *)             proto="TrustTunnel" ;;
        esac
        frag=""; [[ "${link}" == *'#'* ]] && frag="${link##*#}"
        cap="${proto}${frag:+ (${frag})}"
        n=$(( n + 1 ))
        printf '\n%s\n' "${cap}"
        if ! printf '%s' "${link}" | qrencode -t ansiutf8; then
            printf '(this link is too long for a QR code: copy it from --show-client)\n'
        fi
    done < <(qr_links "${file}")
    (( n > 0 )) || die "no links found in ${file}."
    if [[ -s "${file%.txt}.sub" ]]; then
        printf '\nSubscription (base64)\n'
        if ! qrencode -t ansiutf8 < "${file%.txt}.sub"; then
            printf '(the subscription is too long for a QR code: copy it from %s)\n' "${file%.txt}.sub"
        fi
    fi
}

# ---- Alerts (outbound only, opt-in) -------------------------------------------
# Telegram bot (ALERT_TG_TOKEN + ALERT_TG_CHAT) and/or a webhook (ALERT_WEBHOOK, https; POST JSON).
# Saved in ${ALERTS_ENV} (600). "none" clears. The token is never printed or logged, and goes to
# curl through its config on stdin, so it is not on a command line.
ALERTS_ENV="${SCANNER_DIR}/alerts.env"
ALERT_STATE="${STATE_DIR}/alert-state"
A_TOKEN=""; A_CHAT=""; A_HOOK=""; A_ENABLED=0; A_DIRTY=0
A_RES_TG="off"; A_RES_HOOK="off"
ALERT_TOKEN_RE='^[0-9]{5,12}:[A-Za-z0-9_-]{30,64}$'
ALERT_CHAT_RE='^(-?[0-9]{1,20}|@[A-Za-z0-9_]{5,32})$'
ALERT_HOOK_RE='^https://[A-Za-z0-9.-]+(:[0-9]{1,5})?(/[A-Za-z0-9._~%&=+:@/-]*)?(\?[A-Za-z0-9._~%&=+:@/?-]*)?$'

alert_valid_token() { [[ "$1" =~ ${ALERT_TOKEN_RE} ]]; }
alert_valid_chat() { [[ "$1" =~ ${ALERT_CHAT_RE} ]]; }
alert_valid_hook() { (( ${#1} <= 512 )) && [[ "$1" =~ ${ALERT_HOOK_RE} ]]; }
alert_mask_token() { printf '%s:****' "${1%%:*}"; }
alert_hook_host() { local h="${1#https://}"; h="${h%%[/?]*}"; printf '%s' "${h}"; }

# Reads the saved settings (only values that pass the validation).
alert_load_saved() {
    local k v
    A_TOKEN=""; A_CHAT=""; A_HOOK=""
    [[ -f "${ALERTS_ENV}" ]] || return 0
    while IFS='=' read -r k v || [[ -n "${k}" ]]; do
        case "${k}" in
            ALERT_TG_TOKEN) if alert_valid_token "${v}"; then A_TOKEN="${v}"; fi ;;
            ALERT_TG_CHAT) if alert_valid_chat "${v}"; then A_CHAT="${v}"; fi ;;
            ALERT_WEBHOOK) if alert_valid_hook "${v}"; then A_HOOK="${v}"; fi ;;
        esac
    done < "${ALERTS_ENV}"
    return 0
}

# Settings: the variables given now, else the saved ones. Sets A_TOKEN, A_CHAT, A_HOOK,
# A_ENABLED, A_DIRTY (1: something was given and must be saved). Dies on an invalid value.
alert_prepare() {
    local t="${ALERT_TG_TOKEN:-}" c="${ALERT_TG_CHAT:-}" w="${ALERT_WEBHOOK:-}"
    alert_load_saved
    A_DIRTY=0
    if [[ "${t}" == "none" || "${c}" == "none" ]]; then
        A_TOKEN=""; A_CHAT=""; A_DIRTY=1
    else
        if [[ -n "${t}" ]]; then
            alert_valid_token "${t}" || die "ALERT_TG_TOKEN is not a Telegram bot token (like 123456789:AAH..., from @BotFather)."
            A_TOKEN="${t}"; A_DIRTY=1
        fi
        if [[ -n "${c}" ]]; then
            alert_valid_chat "${c}" || die "ALERT_TG_CHAT must be a numeric chat id (like 123456789 or -100123456789) or @channelname."
            A_CHAT="${c}"; A_DIRTY=1
        fi
    fi
    if [[ "${w}" == "none" ]]; then A_HOOK=""; A_DIRTY=1
    elif [[ -n "${w}" ]]; then
        alert_valid_hook "${w}" || die "ALERT_WEBHOOK must be an https:// URL without spaces or quotes (up to 512 characters)."
        A_HOOK="${w}"; A_DIRTY=1
    fi
    if { [[ -n "${A_TOKEN}" && -z "${A_CHAT}" ]] || [[ -z "${A_TOKEN}" && -n "${A_CHAT}" ]]; }; then
        if (( A_DIRTY == 1 )); then die "Telegram alerts need both ALERT_TG_TOKEN and ALERT_TG_CHAT."; fi
        A_TOKEN=""; A_CHAT=""
    fi
    A_ENABLED=0
    if [[ -n "${A_TOKEN}" || -n "${A_HOOK}" ]]; then A_ENABLED=1; fi
    return 0
}

# Writes the settings given in this run (nothing given: no change). No channel left: the file and the state go.
alert_save() {
    (( A_DIRTY == 1 )) || return 0
    if (( A_ENABLED == 0 )); then
        rm -f "${ALERTS_ENV}" "${ALERT_STATE}"
        return 0
    fi
    install -d -m 700 "${SCANNER_DIR}"
    install -m 600 /dev/null "${ALERTS_ENV}.new"
    {
        printf '# veiltrium: alert channels (secret: root only)\n'
        if [[ -n "${A_TOKEN}" ]]; then printf 'ALERT_TG_TOKEN=%s\nALERT_TG_CHAT=%s\n' "${A_TOKEN}" "${A_CHAT}"; fi
        if [[ -n "${A_HOOK}" ]]; then printf 'ALERT_WEBHOOK=%s\n' "${A_HOOK}"; fi
    } > "${ALERTS_ENV}.new"
    mv -f "${ALERTS_ENV}.new" "${ALERTS_ENV}"
    return 0
}

alert_describe() {   # one line, no secrets
    local s=()
    if [[ -n "${A_TOKEN}" ]]; then s+=("Telegram (bot $(alert_mask_token "${A_TOKEN}"), chat ${A_CHAT})"); fi
    if [[ -n "${A_HOOK}" ]]; then s+=("webhook ($(alert_hook_host "${A_HOOK}"))"); fi
    (IFS=';'; printf '%s' "${s[*]}")
}

# Sends $1 (text) for the event $2 to every channel. Sets A_RES_TG and A_RES_HOOK
# (off | ok | failed: ...). Never fails; failures go to the journal.
alert_send() {
    local text="$1" event="${2:-info}" code rc json why
    A_RES_TG="off"; A_RES_HOOK="off"
    if [[ -n "${A_TOKEN}" ]]; then
        rc=0
        code="$(printf 'url = "https://api.telegram.org/bot%s/sendMessage"\n' "${A_TOKEN}" \
            | curl -K - --proto '=https' --tlsv1.2 --max-time 10 -sS -o /dev/null -w '%{http_code}' \
                --data-urlencode "chat_id=${A_CHAT}" --data-urlencode "text=${text}" 2>/dev/null)" || rc=$?
        if (( rc == 0 )) && [[ "${code}" == "200" ]]; then A_RES_TG="ok"
        else
            if (( rc != 0 )); then why="curl exit ${rc}"; else why="HTTP ${code}"; fi
            A_RES_TG="failed: ${why}"
        fi
    fi
    if [[ -n "${A_HOOK}" ]]; then
        rc=0
        if ! command -v jq >/dev/null 2>&1; then A_RES_HOOK="failed: jq is missing"
        else
            json="$(jq -nc --arg node "${LABEL}" --arg server "${PUBLIC_IP:-unknown}" --arg event "${event}" \
                --arg text "${text}" --arg time "$(date -u +%FT%TZ)" \
                '{node: $node, server: $server, event: $event, text: $text, time: $time}')"
            code="$(printf 'url = "%s"\n' "${A_HOOK}" \
                | curl -K - --proto '=https' --tlsv1.2 --max-time 10 -sS -o /dev/null -w '%{http_code}' \
                    -H 'Content-Type: application/json' --data-binary "${json}" 2>/dev/null)" || rc=$?
            if (( rc == 0 )) && [[ "${code}" == 2* ]]; then A_RES_HOOK="ok"
            else
                if (( rc != 0 )); then why="curl exit ${rc}"; else why="HTTP ${code}"; fi
                A_RES_HOOK="failed: ${why}"
            fi
        fi
    fi
    if [[ "${A_RES_TG}" == failed* || "${A_RES_HOOK}" == failed* ]]; then
        logger -t veiltrium-alert "alert '${event}' not delivered: telegram ${A_RES_TG}; webhook ${A_RES_HOOK}" 2>/dev/null || true
    fi
    return 0
}

# An event for the owner: the text starts with the node name and address. A no-op without channels.
alert_notify() {   # event, text
    (( A_ENABLED == 1 )) || return 0
    alert_send "${LABEL} (${PUBLIC_IP:-unknown}): $2" "$1"
    return 0
}

# State between runs (${ALERT_STATE}: key=value lines) so that each change alerts once.
astate_get() {   # key -> value, 0 if unset
    local v=""
    if [[ -f "${ALERT_STATE}" ]]; then v="$(sed -n "s/^$1=//p" "${ALERT_STATE}" | tail -n 1 || true)"; fi
    printf '%s' "${v:-0}"
}
astate_set() {   # key value
    local tmp="${ALERT_STATE}.new"
    install -d -m 700 "$(dirname "${ALERT_STATE}")"
    install -m 600 /dev/null "${tmp}"
    { if [[ -f "${ALERT_STATE}" ]]; then grep -v "^$1=" "${ALERT_STATE}" || true; fi; printf '%s=%s\n' "$1" "$2"; } > "${tmp}"
    mv -f "${tmp}" "${ALERT_STATE}"
    return 0
}

svc_is_active() { systemctl is-active --quiet "$1"; }

# One check of the given services: "down" after 2 checks in a row without "active", "recovered" once.
alert_watch_services() {
    local svc key bad
    for svc in "$@"; do
        key="${svc//-/_}"
        if svc_is_active "${svc}"; then
            if [[ "$(astate_get "svc_${key}_down")" == "1" ]]; then
                alert_notify recovered "${svc} is running again."
                astate_set "svc_${key}_down" 0
            fi
            if [[ "$(astate_get "svc_${key}_bad")" != "0" ]]; then astate_set "svc_${key}_bad" 0; fi
        else
            bad=$(( $(astate_get "svc_${key}_bad") + 1 ))
            astate_set "svc_${key}_bad" "${bad}"
            if (( bad >= 2 )) && [[ "$(astate_get "svc_${key}_down")" != "1" ]]; then
                alert_notify down "${svc} is down (not active in ${bad} checks in a row). Look at: journalctl -u ${svc} -n 50"
                astate_set "svc_${key}_down" 1
            fi
        fi
    done
    return 0
}

# The check from Russia: $1 = verdict, $2 = bad_streak, $3 = networks. Alerts when the streak reaches 2 and
# when it is reachable again after that alert.
alert_russia_eval() {
    if (( $2 >= 2 )) && [[ "$(astate_get russia_alerted)" != "1" ]]; then
        alert_notify russia "not reachable from Russia in $2 checks in a row: $1 (${3:-no networks}). Move to a new server (--export / --import) or switch the clients to a standby address."
        astate_set russia_alerted 1
    elif [[ "$1" == "reachable" && "$(astate_get russia_alerted)" == "1" ]]; then
        alert_notify recovered "reachable from Russia again."
        astate_set russia_alerted 0
    fi
    return 0
}

# ---- Updates ----------------------------------------------------------------
UPD_REPO="Vanilla-SilQ-HD/Veiltrium"
UPD_TAG=""; UPD_ERR=""; UPD_DIR="/root"

# A number to compare versions by: "2026-10-20.2" or "v2026.10.20.2" (no .N means 0); fails on other text.
ver_key() {
    local vs="${1#v}" y m d n
    vs="${vs//-/.}"
    [[ "${vs}" =~ ^([0-9]{4})\.([0-9]{2})\.([0-9]{2})(\.([0-9]{1,3}))?$ ]] || return 1
    y="${BASH_REMATCH[1]}"; m="${BASH_REMATCH[2]}"; d="${BASH_REMATCH[3]}"; n="${BASH_REMATCH[5]:-0}"
    printf '%d' $(( ((10#${y} * 100 + 10#${m}) * 100 + 10#${d}) * 1000 + 10#${n} ))
}
ver_to_tag() { local vs="${1#v}"; printf 'v%s' "${vs//-/.}"; }

# Installer release tags (vYYYY.MM.DD[.N]) found in an atom feed or the tags API (stdin); one per line.
update_tags_from_text() {
    { grep -oE '(/tag/|"name": ?")v[0-9]{4}\.[0-9]{2}\.[0-9]{2}(\.[0-9]{1,3})?"' || true; } | sed -E 's/.*(v[0-9.]+)"$/\1/'
    return 0
}
update_max_tag() {   # tags on stdin -> the newest
    local t k best="" bk=-1
    while read -r t; do
        k="$(ver_key "${t}")" || continue
        if (( k > bk )); then bk="${k}"; best="${t}"; fi
    done
    printf '%s' "${best}"
    return 0
}
# Sets UPD_TAG to the newest release tag; fails if no source answers.
update_latest() {
    local src txt tag
    UPD_TAG=""
    for src in "https://github.com/${UPD_REPO}/releases.atom" "https://github.com/${UPD_REPO}/tags.atom" \
               "https://api.github.com/repos/${UPD_REPO}/tags?per_page=100"; do
        txt="$(curl -fsSL --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 10 --max-time 30 --max-filesize 2000000 "${src}" 2>/dev/null || true)"
        tag="$(printf '%s\n' "${txt}" | update_tags_from_text | update_max_tag)"
        if [[ -n "${tag}" ]]; then UPD_TAG="${tag}"; return 0; fi
    done
    return 1
}
# $1 = a downloaded script, $2 = its release tag: is it a bash installer of exactly that version?
update_verify() {
    local f="$1" tag="$2" line v
    UPD_ERR=""
    if [[ ! -s "${f}" ]] || (( $(stat -c %s "${f}") > 5000000 )); then UPD_ERR="the download is empty or too big"; return 1; fi
    if [[ "$(head -n 1 "${f}")" != "#!/usr/bin/env bash" ]]; then UPD_ERR="the download is not a bash script"; return 1; fi
    if ! grep -q '^# ==== VEILTRIUM END ====$' "${f}"; then UPD_ERR="the download is incomplete"; return 1; fi
    line="$(grep -m1 '^SCRIPT_VERSION="' "${f}" || true)"
    if [[ ! "${line}" =~ ^SCRIPT_VERSION=\"([0-9.-]+)\"$ ]]; then UPD_ERR="the download has no SCRIPT_VERSION"; return 1; fi
    v="${BASH_REMATCH[1]}"
    if [[ "$(ver_to_tag "${v}")" != "${tag}" ]]; then UPD_ERR="the script says version ${v}, not ${tag#v}"; return 1; fi
    if ! bash -n "${f}" 2>/dev/null; then UPD_ERR="the download does not pass bash -n"; return 1; fi
    return 0
}

update_check_main() {
    local cur_key new_key state="up_to_date"
    if [[ "${JSON_OUT}" == "-" ]]; then exec 8>&1 1>&2; fi
    update_latest || die "could not read the latest release of ${UPD_REPO} from GitHub (no network?)."
    cur_key="$(ver_key "${SCRIPT_VERSION}")"; new_key="$(ver_key "${UPD_TAG}")"
    if (( new_key > cur_key )); then
        state="update_available"
        printf 'New version %s available (installed: %s): run veiltrium --update (or bash %s --update)\n' "${UPD_TAG#v}" "${SCRIPT_VERSION}" "$0"
    else
        printf 'Up to date (%s; latest release %s)\n' "${SCRIPT_VERSION}" "${UPD_TAG#v}"
    fi
    if [[ -n "${JSON_OUT}" ]]; then
        printf '{"schema":"veiltrium-update/1","installed":"%s","latest":"%s","status":"%s"}\n' \
            "${SCRIPT_VERSION}" "${UPD_TAG#v}" "${state}" | json_emit
    fi
    return 0
}

update_main() {
    local f old ans="" cur_key new_key
    update_latest || die "could not read the latest release of ${UPD_REPO} from GitHub (no network?)."
    cur_key="$(ver_key "${SCRIPT_VERSION}")"; new_key="$(ver_key "${UPD_TAG}")"
    if (( new_key <= cur_key )); then
        printf 'Up to date (%s; latest release %s). Nothing to do.\n' "${SCRIPT_VERSION}" "${UPD_TAG#v}"
        return 0
    fi
    for old in "${UPD_DIR}"/veiltrium-update.*; do
        if [[ -f "${old}" && "$(readlink -f -- "${old}")" != "$(readlink -f -- "$0" 2>/dev/null || true)" ]]; then rm -f -- "${old}"; fi
    done
    f="$(mktemp --suffix=.sh "${UPD_DIR}/veiltrium-update.XXXXXX")"
    chmod 700 "${f}"
    if ! curl -fsSL --proto '=https' --tlsv1.2 --retry 3 --connect-timeout 15 --max-time 120 --max-filesize 5000000 \
            -o "${f}" "https://raw.githubusercontent.com/${UPD_REPO}/${UPD_TAG}/veiltrium.sh"; then
        rm -f -- "${f}"; die "could not download veiltrium.sh ${UPD_TAG} from GitHub."
    fi
    if ! update_verify "${f}" "${UPD_TAG}"; then rm -f -- "${f}"; die "refusing to update: ${UPD_ERR}."; fi
    printf 'Veiltrium %s -> %s (https://github.com/%s/releases/tag/%s)\n' "${SCRIPT_VERSION}" "${UPD_TAG#v}" "${UPD_REPO}" "${UPD_TAG}"
    printf 'The new script runs as a normal install: it keeps your keys, passwords and clients.\n'
    printf 'Trust: GitHub over HTTPS (the same as the curl one-liner); there is no signature yet.\n'
    if [[ "${VT_YES:-0}" != "1" ]]; then
        printf 'Type yes to continue: ' >&2
        read -r ans < /dev/tty 2>/dev/null || ans=""
        if [[ "${ans}" != "yes" ]]; then
            rm -f -- "${f}"
            printf 'Cancelled (to run without a question: VT_YES=1).\n'
            return 0
        fi
    fi
    exec bash "${f}"
}

# ---- Audit log ----------------------------------------------------------------
# One line per action that changes the node (add-client, remove-client, reset-client,
# export, import, install, uninstall, panel-password, traffic-reset): time, source (cli, or panel when
# the panel's root helper runs it), action, target, result (ok, rolled-back, failed).
# Never a secret: the target is a client name or the base name of a file.
audit_line() {   # $1 = action, $2 = target ("" = none), $3 = ok | rolled-back | failed
    local src="${VEILTRIUM_SOURCE:-cli}" target="${2:-}" result="${3:-failed}"
    [[ "${src}" == "cli" || "${src}" == "panel" ]] || src="cli"
    [[ "$1" =~ ^[a-z][a-z-]{0,30}$ ]] || return 1
    [[ "${target}" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || target="-"
    [[ "${result}" == "ok" || "${result}" == "rolled-back" ]] || result="failed"
    printf '%s source=%s action=%s target=%s result=%s\n' "$(date -u +%FT%TZ)" "${src}" "$1" "${target}" "${result}"
}

audit_append() {   # the same arguments; a log that cannot be written never fails the action
    local line
    line="$(audit_line "$@")" || return 0
    install -d -m 750 "${AUDIT_DIR}" 2>/dev/null || return 0
    if [[ ! -e "${AUDIT_LOG}" ]]; then install -m 640 /dev/null "${AUDIT_LOG}" 2>/dev/null || return 0; fi
    printf '%s\n' "${line}" >> "${AUDIT_LOG}" 2>/dev/null || true
    return 0
}

# The directory, the file and the monthly rotation (6 kept), if logrotate is installed.
audit_setup() {
    install -d -m 750 "${AUDIT_DIR}"
    if [[ ! -e "${AUDIT_LOG}" ]]; then install -m 640 /dev/null "${AUDIT_LOG}"; fi
    if [[ -d "$(dirname "${LOGROTATE_FILE}")" ]] && command -v logrotate >/dev/null 2>&1; then
        cat > "${LOGROTATE_FILE}.new" <<EOF
# veiltrium: the audit log of the actions on this node
${AUDIT_LOG} {
    monthly
    rotate 6
    missingok
    notifempty
    compress
    delaycompress
    create 640 root root
}
EOF
        if cmp -s "${LOGROTATE_FILE}.new" "${LOGROTATE_FILE}" 2>/dev/null; then rm -f "${LOGROTATE_FILE}.new"
        else mv -f "${LOGROTATE_FILE}.new" "${LOGROTATE_FILE}"; fi
    fi
    return 0
}

audit_show() {   # $1 = how many lines; JSON_OUT set: a JSON array
    local n="$1"
    if [[ -n "${JSON_OUT}" ]]; then
        { tail -n "${n}" "${AUDIT_LOG}" 2>/dev/null || true; } | jq -R -s -c '
            split("\n") | map(select(length > 0) | split(" ") |
                {time: .[0]} + (.[1:] | map(capture("^(?<k>[a-z]+)=(?<v>.*)$") | {(.k): .v}) | add // {}))' | json_emit
    elif [[ -s "${AUDIT_LOG}" ]]; then
        tail -n "${n}" "${AUDIT_LOG}"
    else
        info "The audit log is empty (${AUDIT_LOG})."
    fi
    return 0
}

# ---- Uninstall (--uninstall) -------------------------------------------------
# Removes what Veiltrium created for the VPN. Fixed lists only: nothing is found by a
# pattern. SSH settings, fail2ban, automatic updates, journald and the kernel hardening
# stay (uninstall_kept_paths); so does the audit log.
UNINSTALL_UNITS=(hysteria-server.service xray.service trusttunnel.service
    veiltrium-panel.service veiltrium-helper.socket veiltrium-helper@.service
    veiltrium-recover.service veiltrium-scanner-block.service veiltrium-scanner-block.timer
    veiltrium-russia-check.service veiltrium-russia-check.timer
    veiltrium-watch.service veiltrium-watch.timer veiltrium-traffic.service veiltrium-traffic.timer)
# created by systemd-run (a change in progress, a Reality trial): gone after a stop
UNINSTALL_RUNTIME_UNITS=(veiltrium-watchdog.timer veiltrium-watchdog.service
    veiltrium-trial-end.timer veiltrium-trial-end.service)
UNINSTALL_USERS=(hysteria xray trusttunnel veiltrium-panel)

# Every path that is removed, one per line (files, directories, binaries, unit files).
uninstall_paths() {
    local u
    for u in "${UNINSTALL_UNITS[@]}"; do printf '/etc/systemd/system/%s\n' "${u}"; done
    printf '%s\n' /etc/systemd/system/veiltrium-recover.service.new \
        "${TRIAL_DROPIN}" "${RUN_DIR}" "${HELPER_SOCK%/*}" \
        /var/lib/systemd/timers/stamp-veiltrium-scanner-block.timer \
        /var/lib/systemd/timers/stamp-veiltrium-russia-check.timer \
        /var/lib/systemd/timers/stamp-veiltrium-watch.timer /var/lib/systemd/timers/stamp-veiltrium-traffic.timer \
        "${CLI_BIN}" "${CLI_BIN}.new" "${TRAFFIC_LOCK}" \
        "${HY2_BIN}" "${XRAY_BIN}" "${TT_BIN}" "${PANEL_BIN}" "${SCANNER_BIN}" "${RECOVER_BIN}" \
        "${HY2_DIR}" "${XRAY_DIR}" "${TT_DIR}" "${SCANNER_DIR}" "${PANEL_ETC}" "${STATE_DIR}" "${PANEL_LIB}" \
        /var/lib/hysteria "${VT_ROOT_DIR}" \
        /etc/needrestart/conf.d/50-veiltrium.conf /etc/nftables.conf.vt-new \
        "${LOG_FILE}" "${LOG_FILE}.1"
}

# What stays, one per line: settings that protect the server whatever runs on it.
uninstall_kept_paths() {
    printf '%s\n' /etc/ssh/sshd_config.d/00-veiltrium-hardening.conf \
        /etc/fail2ban/jail.d/veiltrium-sshd.local \
        /etc/apt/apt.conf.d/52veiltrium-unattended-upgrades /etc/apt/apt.conf.d/20auto-upgrades \
        /etc/systemd/journald.conf.d/50-veiltrium.conf \
        /etc/sysctl.d/99-zz-veiltrium-hardening.conf /etc/modules-load.d/veiltrium-bbr.conf \
        "${AUDIT_DIR}" "${LOGROTATE_FILE}" /etc/nftables.conf /etc/nftables.conf.orig-veiltrium
}

# True for paths the uninstall must never remove.
uninstall_protected() {
    case "$1" in
        /etc/ssh|/etc/ssh/*|/etc/fail2ban|/etc/fail2ban/*|/etc/apt|/etc/apt/*|/etc/sysctl.d|/etc/sysctl.d/*) return 0 ;;
        /etc/modules-load.d|/etc/modules-load.d/*|/etc/systemd/journald.conf.d|/etc/systemd/journald.conf.d/*) return 0 ;;
        /etc/default|/etc/default/*|/etc/logrotate.d|/etc/logrotate.d/*|/etc/nftables.conf|/etc/nftables.conf.orig-*) return 0 ;;
        /var/log|/var/log/veiltrium|/var/log/veiltrium/*|/root|/root/.ssh|/root/.ssh/*) return 0 ;;
    esac
    return 1
}

# Removes one path of the fixed list: absolute, at least two components, not protected.
uninstall_rm() {
    local p="$1"
    if [[ "${p}" != /*/* || "${p}" == *..* || "${p}" == *[[:space:]]* ]] || uninstall_protected "${p}"; then
        warn "Refusing to remove '${p}'."
        return 0
    fi
    if [[ -e "${p}" || -L "${p}" ]]; then rm -rf -- "${p}"; info "removed ${p}"; fi
    return 0
}

# A system account that looks like the one this installer made (system uid, no login shell).
uninstall_user_ours() {
    local ent uid shell
    ent="$(getent passwd "$1" 2>/dev/null || true)"
    [[ -n "${ent}" ]] || return 1
    uid="$(cut -d: -f3 <<<"${ent}")"; shell="$(cut -d: -f7 <<<"${ent}")"
    [[ "${uid}" =~ ^[0-9]+$ ]] && (( uid < 1000 )) && [[ "${shell}" == "/usr/sbin/nologin" ]]
}

# stdin: /etc/nftables.conf; stdout: the same without what Veiltrium wrote (its table, the
# include of the scanner list and its comment lines). Every other line stays.
nft_conf_strip() {
    awk -v inc="include \"${SCANNER_FILE}\"" '
        skip { if ($0 ~ /^}/) skip = 0; next }
        /^table inet veiltrium[ \t]*\{/ { skip = 1; next }
        /^table inet veiltrium[ \t]*$/ || /^delete table inet veiltrium[ \t]*$/ { next }
        /^# veiltrium:/ || /^# Only our own table is recreated/ { next }
        $0 == inc { next }
        { print }'
}

# The live table goes; /etc/nftables.conf loses our parts and is checked with nft -c
# before it replaces the file. If nothing else was in it, the original saved at install
# time (if there is one) comes back. The nftables service is not reloaded here.
uninstall_firewall() {
    local conf="/etc/nftables.conf" new="/etc/nftables.conf.vt-new" orig="/etc/nftables.conf.orig-veiltrium" restored=0
    nft delete table inet veiltrium >/dev/null 2>&1 || true
    [[ -f "${conf}" ]] || return 0
    grep -qE 'veiltrium' "${conf}" || return 0
    nft_conf_strip < "${conf}" > "${new}"
    if ! grep -qvE '^[[:space:]]*(#.*)?$' "${new}" && [[ -f "${orig}" ]]; then
        cp -p "${orig}" "${new}"; restored=1
    else
        chmod --reference="${conf}" "${new}" 2>/dev/null || chmod 600 "${new}"
    fi
    if ! nft -c -f "${new}" >/dev/null 2>&1; then
        rm -f "${new}"
        warn "The firewall file ${conf} was not changed (the edited copy did not pass nft -c); remove the veiltrium table and the include line by hand."
        return 0
    fi
    mv -f "${new}" "${conf}"
    if (( restored == 1 )); then
        rm -f "${orig}"
        info "restored the original ${conf} (saved at install time)"
    else
        info "removed the veiltrium table and the scanner list include from ${conf}"
    fi
    return 0
}

uninstall_present() {
    local p u
    while IFS= read -r p; do
        if [[ -e "${p}" || -L "${p}" ]]; then return 0; fi
    done < <(uninstall_paths)
    for u in "${UNINSTALL_USERS[@]}"; do
        if uninstall_user_ours "${u}"; then return 0; fi
    done
    if nft list table inet veiltrium >/dev/null 2>&1; then return 0; fi
    if grep -qs 'veiltrium' /etc/nftables.conf; then return 0; fi
    return 1
}

uninstall_confirm() {
    local ans=""
    if [[ "${VT_YES:-}" == "uninstall" ]]; then return 0; fi
    printf '    Type "uninstall" to remove everything listed above: ' >&2
    if ! read -r ans 2>/dev/null </dev/tty; then
        printf '\n' >&2
        die "no terminal to confirm on; nothing was removed. Run it in a terminal, or set VT_YES=uninstall."
    fi
    [[ "${ans}" == "uninstall" ]] || die "not confirmed; nothing was removed."
    return 0
}

uninstall_kept_report() {
    local p any=0
    while IFS= read -r p; do
        if [[ -e "${p}" ]]; then
            if (( any == 0 )); then info "Left in place (remove by hand if you want):"; any=1; fi
            info "  ${p}"
        fi
    done < <(uninstall_kept_paths)
    if (( any == 1 )); then
        info "Also unchanged: the packages (fail2ban, nftables, jq, unattended-upgrades, ...), the service"
        info "state of ufw/apport (disabled by the installer), SSH logins and root."
    fi
    return 0
}

uninstall_main() {
    local p u svc
    if ! uninstall_present; then
        ok "Nothing to remove: no Veiltrium files, services or firewall rules found."
        uninstall_kept_report
        return 0
    fi
    printf '\nThis removes Veiltrium from this server:\n'
    info "services: hysteria-server, xray, trusttunnel, veiltrium-panel, the panel helper, the timers and recovery units"
    info "programs: ${HY2_BIN}, ${XRAY_BIN}, ${TT_BIN}, ${PANEL_BIN}, ${SCANNER_BIN}, ${RECOVER_BIN}"
    info "settings and state: ${HY2_DIR}, ${XRAY_DIR}, ${TT_DIR}, ${SCANNER_DIR}, ${PANEL_ETC}, ${STATE_DIR}, ${PANEL_LIB}"
    info "the firewall table inet veiltrium and its lines in /etc/nftables.conf (everything but SSH becomes reachable"
    info "again unless another firewall is in place), the service users ${UNINSTALL_USERS[*]}"
    if [[ -d "${VT_ROOT_DIR}" ]]; then
        warn "${VT_ROOT_DIR} holds the client connection details, the probe profile and the panel password."
        warn "Anything not saved elsewhere is lost: every client stops working."
    fi
    info "It does NOT touch SSH, fail2ban, automatic updates, journald, the kernel hardening or the audit log."
    printf '\n'
    uninstall_confirm
    step_mark stop
    for svc in "${UNINSTALL_RUNTIME_UNITS[@]}"; do systemctl stop "${svc}" >/dev/null 2>&1 || true; done
    systemctl stop 'veiltrium-helper@*.service' >/dev/null 2>&1 || true
    for u in veiltrium-panel.service veiltrium-helper.socket veiltrium-russia-check.timer veiltrium-scanner-block.timer veiltrium-watch.timer veiltrium-traffic.timer \
             hysteria-server.service xray.service trusttunnel.service veiltrium-recover.service; do
        systemctl disable --now "${u}" >/dev/null 2>&1 || true
    done
    for u in "${UNINSTALL_UNITS[@]}"; do systemctl disable "${u}" >/dev/null 2>&1 || true; done
    step_mark remove
    uninstall_firewall
    while IFS= read -r p; do uninstall_rm "${p}"; done < <(uninstall_paths)
    rmdir "${TRIAL_DROPIN_DIR}" 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true
    for u in "${UNINSTALL_UNITS[@]}" "${UNINSTALL_RUNTIME_UNITS[@]}"; do systemctl reset-failed "${u}" >/dev/null 2>&1 || true; done
    for u in "${UNINSTALL_USERS[@]}"; do
        if uninstall_user_ours "${u}"; then
            userdel "${u}" >/dev/null 2>&1 || warn "could not remove the user ${u} (is a process of it still running?)"
            if getent group "${u}" >/dev/null 2>&1; then groupdel "${u}" >/dev/null 2>&1 || true; fi
            info "removed the user ${u}"
        fi
    done
    ok "Veiltrium removed."
    uninstall_kept_report
    return 0
}

usage() {
    banner
    printf '\n'
    sed -n '/^#  Modes:/,/^#  Without VLESS/p' "$0" | sed -e 's/^#$//' -e 's/^#  \{0,1\}//'
    cat <<'EOF'

Settings (environment variables, saved where noted):
  REALITY_CANDIDATES="a.com b.com"  Reality candidates (saved; "default" = built-in list)
  REALITY_SNI=a.com                 use exactly this Reality site (checked first)
  HY2_SNI=name | auto               Hysteria SNI and certificate name (saved)
  HY2_MASQUERADE_URL=url | auto     Hysteria masquerade page (saved)
  TT_SNI=name | auto                TrustTunnel hostname and certificate name (saved)
  PANEL_ENABLE=0                    no web panel (it listens on 127.0.0.1 only; SSH tunnel)
  PANEL_PORT=2096                   the panel's port on 127.0.0.1 (saved)
  PANEL_VPN=0                       the panel through the SSH tunnel only (default 1: also through
                                    VLESS Reality with a separate admin profile, see panel.txt; saved)
  GLOBALPING=0                      no check from Russian networks (it sends the server's address
                                    to Globalping probes, also every 6 hours; saved; default 1)
  STANDBY_HOSTS=1.2.3.4[,...] | none   standby servers (max 3, same ports) added to every client
                                    link and config, so clients switch if this address is blocked (saved)
  NODE_NAME=PL | auto | none        node name in client apps: Veiltrium-PL (saved; default:
                                    the server's country, detected once)
  VT_EXPORT_PASSPHRASE / VT_IMPORT_PASSPHRASE   passphrase for --export / --import without a
                                    terminal (otherwise it is asked for; 12+ characters on export)

Alerts and updates (outbound only; a service down, no reach from Russia, a rollback):
  ALERT_TG_TOKEN + ALERT_TG_CHAT    Telegram bot token and chat id for alerts (saved in
                                    /etc/veiltrium/alerts.env, root only; "none" clears)
  ALERT_WEBHOOK=https://...         a URL that gets a JSON POST on every alert (saved; "none" clears)
  VT_YES=1                          --update without the question (--uninstall: VT_YES=uninstall)

Ports and protocols:
  HY2_PORT=443                      Hysteria UDP port (an existing node keeps its port)
  REALITY_PORT=443                  Reality TCP port (an existing node keeps its port unless given)
  TT_PORT=8443                      TrustTunnel TCP+UDP port (kept the same way)
  REALITY_ENABLE=0                  no VLESS Reality
  TT_ENABLE=0                       no TrustTunnel
  REALITY_FP=chrome                 TLS client fingerprint in the VLESS link (default chrome)
  REALITY_RESELECT=1                same as --reselect-reality
  PUBLIC_IP=1.2.3.4                 the server's address for the links (behind NAT; default: detected)

Protection and checks:
  SCANNER_BLOCK=0                   no scanner blocklist on the proxy ports
  RU_BLOCKLISTS="url ..."           URLs of RKN block lists (domains, one per line); such names are
                                    never chosen as server names
  MTS_MAX_AGE_DAYS=14               home-network probe results older than this are ignored

Reboots and regeneration:
  VT_AUTO_REBOOT=0                  a new node does not reboot by itself when updates need it
  AUTO_REBOOT_TIME=01:30            time of the nightly reboot for updates (server time)
  VT_RECONFIGURE=1                  new passwords, keys and certificates (every client must be updated)
  TRIAL_MINUTES=30                  default trial length (same as --trial-minutes)

Every variable can be written before the command:  VAR=value bash veiltrium.sh
Short command on an installed node:  veiltrium help

Options:
  --trial-minutes N                 trial length, 5..240 (default 30)
  --json FILE | -                   with --diagnose, --dry-run, --status and the client modes:
                                    write a JSON document there ("-": stdout, human text to stderr)
EOF
}

# Sourced (CI unit tests): functions only.
if [[ "${BASH_SOURCE[0]}" != "$0" ]]; then return 0; fi

trap 'die "command failed (line ${LINENO}): ${BASH_COMMAND}"' ERR
trap 'die "interrupted"' INT TERM
# A dropped interactive SSH session must not kill the install halfway through.
trap '' HUP

cleanup() {
    local rc=$? audit_result="ok"
    trap '' INT TERM
    if (( rc != 0 )); then
        audit_result="failed"
        if (( AUDIT_ROLLBACK == 1 || ${#TXN_OPEN[@]} > 0 )); then audit_result="rolled-back"; fi
    fi
    stop_pid "${CLIENT_PID}"
    stop_pid "${SERVER_PID}"
    if (( ${#TXN_OPEN[@]} )); then
        printf '    ! interrupted while changing %s: restoring the previous settings\n' "${TXN_OPEN[*]}"
        "${RECOVER_BIN}" --now || true
        if ! txn_pending; then systemctl stop "${WATCHDOG_UNIT}.timer" >/dev/null 2>&1 || true; fi
    fi
    if (( TRIAL_STARTING == 1 )); then trial_stop || true; fi
    if (( rc != 0 && CLIENT_FILES_STALE == 1 )); then
        printf '    ! the clients were changed, but their connection details were not rewritten:\n'
        printf '      run the installer again (bash %s) to rewrite %s and %s.\n' "$0" "${CLIENT_FILE}" "${CLIENT_FILES_DIR}"
    fi
    if (( rc != 0 && LIGHT == 0 && ${#CHANGES[@]} > 0 )); then
        printf '    ! the run stopped after these changes were made: %s\n' "${CHANGES[*]}"
        printf '      %s may be out of date: run the script again to rewrite it.\n' "${CLIENT_FILE}"
    fi
    if [[ -n "${AUDIT_ACTION}" ]]; then audit_append "${AUDIT_ACTION}" "${AUDIT_TARGET}" "${audit_result}"; fi
    [[ -n "${TMPD}" && -d "${TMPD}" ]] && rm -rf -- "${TMPD}"
    if [[ -n "${TEE_PID}" ]]; then
        exec 1>&- 2>&-
        wait "${TEE_PID}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ---- Command line -----------------------------------------------------------
MODE="install"
CLIENT_ARG=""
IMPORT_FILE=""
EXPORT_FILE=""
NODE_IMPORT_FILE=""
TRIAL_SITES=""
JSON_OUT=""
AUDIT_N=50
SET_LIMIT=""; SET_EXPIRES=""; SET_RESET=""; RESULT_EXTRA="{}"
while (( $# )); do
    case "$1" in
        --diagnose) MODE="diagnose" ;;
        --dry-run) MODE="dry-run" ;;
        --reselect-reality) REALITY_RESELECT=1 ;;
        --import-mts) MODE="import-mts"; IMPORT_FILE="${2:-}"; [[ -n "${IMPORT_FILE}" ]] || die "--import-mts needs a file (or - for stdin)"; shift ;;
        --trial-reality) MODE="trial"; TRIAL_SITES="${2:-}"; [[ -n "${TRIAL_SITES}" ]] || die "--trial-reality needs site names"; shift ;;
        --trial-minutes) TRIAL_MINUTES="${2:-}"; shift ;;
        --trial-stop) MODE="trial-stop" ;;
        --json) JSON_OUT="${2:-}"; [[ -n "${JSON_OUT}" ]] || die "--json needs a file name"; shift ;;
        --add-client|--remove-client|--show-client|--reset-client|--qr|--set-client|--disable-client|--enable-client)
            MODE="${1#--}"; CLIENT_ARG="${2:-}"; [[ -n "${CLIENT_ARG}" ]] || die "$1 needs a client name"; shift ;;
        --enforce) MODE="enforce" ;;
        --limit)
            [[ -n "${2:-}" ]] || die "--limit needs a size (for example 50G, or none)"
            if [[ "$2" == "none" ]]; then SET_LIMIT="none"
            else SET_LIMIT="$(parse_size "$2")"
                [[ -n "${SET_LIMIT}" ]] || die "--limit: '$2' is not a size: whole bytes or a number with K, M, G or T (1G = 10^9), at most 10^15, or none."; fi
            shift ;;
        --expires)
            [[ -n "${2:-}" ]] || die "--expires needs a date YYYY-MM-DD (or none)"
            if [[ "$2" != "none" ]] && ! date_ok "$2"; then die "--expires: '$2' is not a date (YYYY-MM-DD, or none)."; fi
            SET_EXPIRES="$2"; shift ;;
        --reset)
            case "${2:-}" in none|daily|weekly|monthly) SET_RESET="$2" ;; *) die "--reset needs none, daily, weekly or monthly." ;; esac
            shift ;;
        --audit) MODE="audit"; if [[ "${2:-}" =~ ^[0-9]{1,5}$ ]]; then AUDIT_N="$2"; shift; fi ;;
        --uninstall) MODE="uninstall" ;;
        --list-clients) MODE="list-clients" ;;
        --status) MODE="status" ;;
        --traffic) MODE="traffic" ;;
        --traffic-reset) MODE="traffic-reset" ;;
        --collect-traffic) MODE="collect-traffic" ;;   # internal: veiltrium-traffic.timer
        --check-russia) MODE="check-russia" ;;
        --watch) MODE="watch" ;;
        --test-alert) MODE="test-alert" ;;
        --check-update) MODE="check-update" ;;
        --update) MODE="update" ;;
        --panel-password) MODE="panel-password" ;;
        --export) MODE="export"; EXPORT_FILE="${2:-}"; [[ -n "${EXPORT_FILE}" ]] || die "--export needs a file name"; shift ;;
        --import) NODE_IMPORT_FILE="${2:-}"; [[ -n "${NODE_IMPORT_FILE}" ]] || die "--import needs the file made by --export"; shift ;;
        --helper) MODE="helper" ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done
if [[ "${MODE}" == "reset-client" && "${CLIENT_ARG}" == "main" ]]; then
    die "the main client's credentials are the node's own: to replace them (and those of every added client) run  VT_RECONFIGURE=1 bash $0"
fi
case "${MODE}" in
    set-client|disable-client|enable-client)
        [[ "${CLIENT_ARG}" != "main" ]] || die "the main client has no limits and cannot be disabled; add a client for that (--add-client NAME)." ;;
esac
if [[ "${MODE}" == "set-client" ]]; then
    [[ -n "${SET_LIMIT}${SET_EXPIRES}${SET_RESET}" ]] || die "--set-client needs at least one of --limit SIZE|none, --expires YYYY-MM-DD|none, --reset none|daily|weekly|monthly."
elif [[ -n "${SET_LIMIT}${SET_EXPIRES}${SET_RESET}" ]]; then
    die "--limit, --expires and --reset belong to --set-client NAME."
fi
[[ "${REALITY_RESELECT}" == "0" || "${REALITY_RESELECT}" == "1" ]] || die "REALITY_RESELECT must be 0 or 1."
if [[ -n "${NODE_IMPORT_FILE}" ]]; then
    [[ "${MODE}" == "install" ]] || die "--import is an installation: it cannot be combined with another mode."
    [[ "${VT_RECONFIGURE}" != "1" ]] || die "--import keeps the secrets of the old node; it cannot be combined with VT_RECONFIGURE=1."
fi
[[ "${MTS_MAX_AGE_DAYS}" =~ ^[0-9]{1,3}$ ]] || die "MTS_MAX_AGE_DAYS must be a number of days."
if [[ "${MODE}" == "check-update" ]]; then LIGHT=1; update_check_main; exit 0; fi

# ---- Preliminary checks (before any changes) --------------------------------
[[ ${EUID} -eq 0 ]] || die "run as root (for example: sudo -i, then run again)."
alert_prepare

SCRIPT_PATH="$(readlink -f -- "$0" 2>/dev/null || true)"
if [[ -n "${SCRIPT_PATH}" && -f "${SCRIPT_PATH}" ]] && \
   ! grep -q '^# ==== VEILTRIUM END ====$' "${SCRIPT_PATH}"; then
    die "the script file is incomplete (truncated while pasting); paste the whole block again."
fi
# The panel's root helper: no lock here, the request it runs takes it.
if [[ "${MODE}" == "helper" ]]; then
    LIGHT=1
    helper_main
    exit 0
fi
# The traffic timer: its own lock only (never the installer lock), so it cannot hold up a change.
if [[ "${MODE}" == "collect-traffic" ]]; then
    LIGHT=1
    traffic_collect
    # a client over its quota or past its expiry (or back within it): the state change runs as a normal
    # maintenance mode under the installer lock, with a short wait (a busy lock: the next tick tries again)
    if enforce_needed && enforce_backoff_ok; then
        exec env VEILTRIUM_TIMER=1 VEILTRIUM_LOCK_WAIT=5 NEEDRESTART_SUSPEND=1 bash "${SCRIPT_PATH}" --enforce
    fi
    exit 0
fi

if [[ "${MODE}" == "update" ]]; then LIGHT=1; update_main; exit 0; fi

exec 9>/run/veiltrium.lock
if [[ "${MODE}" == "install" ]]; then
    flock -n 9 || die "the script is already running (perhaps a previous run is still going after a dropped connection); wait a couple of minutes and run it again."
elif [[ "${MODE}" == "watch" ]]; then
    # the timer's check: an install or a client change in progress restarts services on purpose
    flock -n 9 || exit 0
else
    # Maintenance modes are short: wait for a panel request or another command instead of failing.
    LOCK_WAIT="${VEILTRIUM_LOCK_WAIT:-90}"
    [[ "${LOCK_WAIT}" =~ ^[1-9][0-9]{0,2}$ ]] || LOCK_WAIT=90
    if ! flock -w "${LOCK_WAIT}" 9; then
        if [[ -n "${VEILTRIUM_TIMER:-}" ]]; then exit 0; fi
        DIE_CODE=75   # a busy lock, not a failure of the request
        die "the script is already running (an install, or a client change from the panel); wait for it to finish and try again."
    fi
fi
# Temp dirs of a run that was killed (they may hold client configs with keys): with the
# lock held, no other run is using them.
rm -rf /root/.veiltrium.* 2>/dev/null || true

# What goes into the audit log when this run ends (cleanup writes the line; the lock is ours).
case "${MODE}" in
    install)
        if [[ -n "${NODE_IMPORT_FILE}" ]]; then AUDIT_ACTION="import"; AUDIT_TARGET="${NODE_IMPORT_FILE##*/}"
        else AUDIT_ACTION="install"; fi ;;
    add-client|remove-client|reset-client|set-client|disable-client|enable-client) AUDIT_ACTION="${MODE}"; AUDIT_TARGET="${CLIENT_ARG}" ;;
    enforce) AUDIT_ACTION="enforce" ;;
    export) AUDIT_ACTION="export"; AUDIT_TARGET="${EXPORT_FILE##*/}" ;;
    panel-password|uninstall|traffic-reset) AUDIT_ACTION="${MODE}" ;;
esac

# =============================================================================
# Maintenance modes: no install log, no package changes.
# =============================================================================
if [[ "${MODE}" != "install" ]]; then
    LIGHT=1
    if [[ "${JSON_OUT}" == "-" ]]; then exec 8>&1 1>&2; fi
    if [[ "${MODE}" == "audit" ]]; then
        AUDIT_N=$((10#${AUDIT_N}))
        if (( AUDIT_N < 1 )); then AUDIT_N=1; fi
        if [[ -n "${JSON_OUT}" ]]; then command -v jq >/dev/null 2>&1 || die "jq is missing: run the installer once (bash $0) first."; fi
        audit_show "${AUDIT_N}"
        exit 0
    fi
    if old_layout_present; then
        die "this node was installed by hy2-secure-install.sh: run the installer once (bash veiltrium.sh) to move it to the Veiltrium names first."
    fi
    if [[ "${MODE}" == "uninstall" ]]; then
        banner
        uninstall_main
        exit 0
    fi
    TMPD="$(mktemp -d /root/.veiltrium.XXXXXX)"
    chmod 700 "${TMPD}"
    # An interrupted change first: its half-written files must not be read as "damaged".
    if txn_pending; then
        if [[ "${MODE}" == "watch" || -n "${VEILTRIUM_TIMER:-}" ]]; then exit 0; fi
        if [[ "${MODE}" == "diagnose" || "${MODE}" == "dry-run" || "${MODE}" == "status" ]]; then
            die "an interrupted change is pending; it is restored automatically within a minute (or by the next install run). Try again then."
        fi
        recover_interrupted
    fi
    detect_ssh_ports
    load_candidates
    load_reality_state
    load_hy2_state
    load_tt_state
    load_probe_env
    load_ports
    case "${MODE}" in list-clients|show-client|qr|add-client|remove-client|reset-client|set-client|disable-client|enable-client|enforce|trial) load_clients ;; esac
    load_node_name
    set_hy2_auth_main
    PUBLIC_IP="${PUBLIC_IP:-${PROBE_SERVER}}"
    if [[ -n "${H_PORT}" ]]; then HY2_PORT="${H_PORT}"; fi
    case "${MODE}" in
        export)
            export_node "${EXPORT_FILE}"
            exit 0 ;;
        import-mts)
            mts_import "${IMPORT_FILE}" || die "no usable results for this server in ${IMPORT_FILE}."
            exit 0 ;;
        watch)
            (( A_ENABLED == 1 )) || exit 0
            command -v jq >/dev/null 2>&1 || exit 0
            WATCH_SVCS=()
            if [[ -n "${H_PASSWORD}" ]]; then WATCH_SVCS+=(hysteria-server); fi
            if [[ -n "${R_SITE}" ]]; then WATCH_SVCS+=(xray); fi
            if [[ -n "${T_USER}" ]]; then WATCH_SVCS+=(trusttunnel); fi
            alert_watch_services "${WATCH_SVCS[@]+"${WATCH_SVCS[@]}"}"
            exit 0 ;;
        test-alert)
            (( A_ENABLED == 1 )) || die "no alert channel is set: give ALERT_TG_TOKEN and ALERT_TG_CHAT and/or ALERT_WEBHOOK."
            alert_save
            command -v jq >/dev/null 2>&1 || warn "jq is missing: the webhook cannot be tested (run the installer once)."
            info "Channels: $(alert_describe)"
            alert_send "${LABEL} (${PUBLIC_IP:-unknown}): test alert from veiltrium --test-alert. Alerts work." test
            TA_FAIL=0
            for TA_CH in "Telegram:${A_RES_TG}" "Webhook:${A_RES_HOOK}"; do
                case "${TA_CH#*:}" in
                    off) ;;
                    ok) ok "${TA_CH%%:*}: delivered" ;;
                    *) warn "${TA_CH%%:*}: ${TA_CH#*:}"; TA_FAIL=1 ;;
                esac
            done
            if (( TA_FAIL == 1 )); then DIE_CODE=1; die "a test alert was not delivered (see above)."; fi
            exit 0 ;;
        trial-stop)
            trial_stop
            exit 0 ;;
        trial)
            trial_start "${TRIAL_SITES}"
            exit 0 ;;
        panel-password)
            [[ -x "${PANEL_BIN}" ]] && id -u veiltrium-panel >/dev/null 2>&1 \
                || die "the web panel is not installed (run the installer; PANEL_ENABLE=0 turns it off)."
            panel_new_password "${PUBLIC_IP:-SERVER_IP}"
            cat "${PANEL_FILE}"
            exit 0 ;;
        check-russia)
            command -v jq >/dev/null 2>&1 || die "jq is missing: run the installer once (bash $0) first."
            [[ -n "${H_PASSWORD}" && -n "${PUBLIC_IP}" ]] || die "this server has no installed node yet: run the installer once (bash $0) first."
            russia_check force
            if [[ -n "${JSON_OUT}" ]]; then
                if [[ -s "${TMPD}/russia.json" ]]; then json_emit < "${TMPD}/russia.json"; else echo '{"verdict":"unchecked"}' | json_emit; fi
            fi
            exit 0 ;;
        traffic|traffic-reset)
            command -v jq >/dev/null 2>&1 || die "jq is missing: run the installer once (bash $0) first."
            [[ -n "${H_PASSWORD}" ]] || die "this server has no installed node yet: run the installer once (bash $0) first."
            if [[ "${MODE}" == "traffic" ]]; then
                traffic_show
            else
                traffic_reset
                ok "All traffic counters are zero now."
            fi
            exit 0 ;;
        status)
            command -v jq >/dev/null 2>&1 || die "jq is missing: run the installer once (bash $0) first."
            [[ -n "${H_PASSWORD}" ]] || die "this server has no installed node yet: run the installer once (bash $0) first."
            if [[ -n "${JSON_OUT}" ]]; then
                status_json | json_emit
            else
                status_json | jq -r '"\(.node_name) \(.server), \(.os); Veiltrium \(.script_version)",
                    (.services | to_entries[] | "  \(.key): \(.value)"),
                    "  clients: main + \(.clients.added) added; reboot required: \(.reboot_required)",
                    "  load \(.resources.load.m1) \(.resources.load.m5) \(.resources.load.m15) (\(.resources.cpus) CPU); memory \(.resources.memory_mb.used)/\(.resources.memory_mb.total) MiB; disk / \(.resources.disk_mb.used)/\(.resources.disk_mb.total) MiB; up \((.uptime_seconds / 86400) | floor) d \(((.uptime_seconds % 86400) / 3600) | floor) h",
                    (if (.standby | length) > 0 then "  standby servers: \(.standby | join(", "))" else empty end),
                    (if ((.russia.bad_streak // 0) >= 2) then
                        "  WARNING: not reachable from Russia in \(.russia.bad_streak) checks in a row: \(.russia.verdict) (\((.russia.networks // []) | join(", "))); consider moving to a new server or switching clients to a standby address"
                     else empty end)'
            fi
            exit 0 ;;
        list-clients|show-client|qr|add-client|remove-client|reset-client|set-client|disable-client|enable-client|enforce)
            [[ -n "${H_PASSWORD}" && -n "${PUBLIC_IP}" && -s "${CLIENT_FILE}" ]] \
                || die "this server has no installed node yet: run the installer once (bash $0) first."
            node_context
            case "${MODE}" in
                list-clients)
                    if [[ -n "${JSON_OUT}" ]]; then clients_json | json_emit; else clients_list; fi ;;
                show-client|qr)
                    if [[ "${CLIENT_ARG}" == "main" ]]; then CLIENT_TXT="${CLIENT_FILE}"
                    elif [[ "${CLIENT_ARG}" =~ ${CLIENT_RE} && -n "$(client_index "${CLIENT_ARG}")" && \
                            -s "${CLIENT_FILES_DIR}/${CLIENT_ARG}.txt" ]]; then
                        CLIENT_TXT="${CLIENT_FILES_DIR}/${CLIENT_ARG}.txt"
                    else
                        die "no client ${CLIENT_ARG} (see --list-clients)."
                    fi
                    if [[ "${MODE}" == "qr" ]]; then
                        [[ -z "${JSON_OUT}" ]] || die "--qr prints to the terminal only (no --json)."
                        qr_show "${CLIENT_TXT}"
                    elif [[ -n "${JSON_OUT}" ]]; then
                        client_json "${CLIENT_ARG}" "$(grep -m1 '^tt://' "${CLIENT_TXT}" 2>/dev/null || true)" \
                            "$(grep '^tt://' "${CLIENT_TXT}" 2>/dev/null | tail -n +2 || true)" | json_emit
                    else
                        cat "${CLIENT_TXT}"
                    fi ;;
                add-client|remove-client|reset-client)
                    [[ "${CLIENT_ARG}" =~ ${CLIENT_RE} && "${CLIENT_ARG}" != "main" ]] \
                        || die "a client name is 1-32 characters: a-z, 0-9, _ and - (not \"main\")."
                    [[ -x "${RECOVER_BIN}" ]] || die "run the installer once (bash $0) first."
                    if trial_active; then die "a Reality trial is running; end it first: bash $0 --trial-stop"; fi
                    banner
                    if [[ "${MODE}" == "add-client" ]]; then
                        [[ -z "$(client_index "${CLIENT_ARG}")" ]] || die "client ${CLIENT_ARG} already exists."
                        [[ "${CLIENT_ARG}" != "${T_USER}" ]] || die "this name is taken by the main client; choose another."
                        (( ${#CL_NAMES[@]} < 250 )) || die "too many clients (250)."
                        write_client_env "${TMPD}/client.env" "${CLIENT_ARG}" "$(cat /proc/sys/kernel/random/uuid)" \
                            "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" "$(date +%F)"
                        AUTH_BEFORE="${H_AUTH}"
                        clients_change add "${CLIENT_ARG}"
                        if [[ -z "${JSON_OUT}" ]]; then
                            printf '\n'
                            cat "${CLIENT_FILES_DIR}/${CLIENT_ARG}.txt"
                            printf '\n(Saved in %s, root only.)\n' "${CLIENT_FILES_DIR}/${CLIENT_ARG}.txt"
                        fi
                    else
                        [[ -n "$(client_index "${CLIENT_ARG}")" ]] || die "no client ${CLIENT_ARG} (see --list-clients)."
                        AUTH_BEFORE="${H_AUTH}"
                        if [[ "${MODE}" == "reset-client" ]]; then
                            i="$(client_index "${CLIENT_ARG}")"
                            write_client_env "${TMPD}/client.env" "${CLIENT_ARG}" "$(cat /proc/sys/kernel/random/uuid)" \
                                "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" "${CL_CREATED[i]}" \
                                "${CL_LIMIT[i]}" "${CL_EXPIRES[i]}" "${CL_RESET[i]}" "${CL_STATE[i]}" "${CL_REASON[i]}"
                            clients_change reset "${CLIENT_ARG}"
                            if [[ -z "${JSON_OUT}" ]]; then
                                printf '\n'
                                cat "${CLIENT_FILES_DIR}/${CLIENT_ARG}.txt"
                                printf '\n(Saved in %s, root only.)\n' "${CLIENT_FILES_DIR}/${CLIENT_ARG}.txt"
                            fi
                        else
                            clients_change remove "${CLIENT_ARG}"
                        fi
                    fi
                    step_mark finished
                    if [[ -n "${JSON_OUT}" ]]; then
                        jq -n --arg action "${MODE%-client}" --arg name "${CLIENT_ARG}" --arg before "${AUTH_BEFORE}" \
                            '{schema: "veiltrium-result/1", ok: true, action: $action, name: $name,
                              main_hysteria_link_changed: ($before != "userpass")}' | json_emit
                    fi ;;
                set-client|disable-client|enable-client|enforce)
                    if [[ "${MODE}" != "enforce" ]]; then
                        [[ "${CLIENT_ARG}" =~ ${CLIENT_RE} && "${CLIENT_ARG}" != "main" ]] \
                            || die "a client name is 1-32 characters: a-z, 0-9, _ and - (not \"main\")."
                    fi
                    [[ -x "${RECOVER_BIN}" ]] || die "run the installer once (bash $0) first."
                    if trial_active; then
                        if [[ -n "${VEILTRIUM_TIMER:-}" ]]; then exit 0; fi
                        die "a Reality trial is running; end it first: bash $0 --trial-stop"
                    fi
                    command -v jq >/dev/null 2>&1 || die "jq is missing: run the installer once (bash $0) first."
                    if [[ -z "${VEILTRIUM_TIMER:-}" ]]; then banner; fi
                    AUTH_BEFORE="${H_AUTH}"
                    client_limits_main "${MODE}" "${CLIENT_ARG}"
                    step_mark finished
                    if [[ -n "${JSON_OUT}" ]]; then
                        jq -n --arg action "${MODE%-client}" --arg name "${CLIENT_ARG}" --argjson extra "${RESULT_EXTRA}" \
                            '{schema: "veiltrium-result/1", ok: true, action: $action, name: $name,
                              main_hysteria_link_changed: false} + $extra' | json_emit
                    fi ;;
            esac
            exit 0 ;;
    esac
    command -v jq >/dev/null 2>&1 || die "jq is missing: run the installer once (bash $0) first."
    banner
    printf '\n%s: nothing on the server is changed\n' "${MODE}"
    if trial_active; then
        # shellcheck disable=SC1090
        source "${TRIAL_ENV}" 2>/dev/null || true
        warn "A Reality trial is running (${TRIAL_SITES:-?}); end: bash $0 --trial-stop"
    fi
    load_ru_blocklist
    if [[ "${MODE}" == "dry-run" ]]; then
        [[ -n "${R_PRIV}" ]] || warn "No Reality keys on this server yet: only the direct checks run."
        info "Candidates (${CAND_SOURCE}): ${CAND_LIST[*]}"
        reality_sites "${R_SITE}" "${H_SNI}" "${T_SNI}"
        reality_evaluate "${SITES[@]}"
        reality_choose "${R_SITE}"
        selection_json > "${TMPD}/selection.json"
        printf '\n'
        info "Current Reality site: ${R_SITE:-none}"
        info "--reselect-reality would: ${R_DECISION}"
        if [[ -n "${R_CHOSEN}" && "${R_CHOSEN}" != "${R_SITE}" ]]; then
            info "Clients would only change sni / server_name of the VLESS link to ${R_CHOSEN};"
            info "UUID, public key and shortId stay; Hysteria and TrustTunnel are not affected."
        fi
        if [[ -n "${JSON_OUT}" ]]; then
            build_report | json_emit
            if [[ "${JSON_OUT}" != "-" ]]; then ok "JSON report: ${JSON_OUT}"; fi
        fi
        exit 0
    fi
    # --diagnose
    DIAG_FAIL=0
    for svc in hysteria-server xray trusttunnel; do
        state="$(systemctl is-active "${svc}" 2>/dev/null || true)"
        if [[ "${state}" == "active" ]]; then ok "${svc}: active"; else warn "${svc}: ${state:-unknown}"; fi
    done
    info "Hysteria $("${HY2_BIN}" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo '?'), Xray $("${XRAY_BIN}" version 2>/dev/null | awk 'NR==1{print "v"$2}' || echo '?'), TrustTunnel v$("${TT_BIN}" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo '?')"
    info "Node ${LABEL}: clients main + $(count_clients) added (see --list-clients); the checks below use the main client"
    if [[ -n "${R_SITE}" ]]; then
        printf '\n'; info "VLESS Reality: SNI ${R_SITE}, port ${REALITY_PORT}/TCP; candidates (${CAND_SOURCE}): ${CAND_LIST[*]}"
        prescreen_site "${R_SITE}"
        if [[ "${PS_GATE}" == "pass" ]]; then ok "${R_SITE} from this server: TLS 1.3 + h2 + valid certificate, ${PS_TLS_MED} ms (HTTP ${PS_HTTP})"
        else warn "${R_SITE} from this server: ${PS_REASON}"; DIAG_FAIL=1; fi
        reality_verify_production "${R_SITE}"
        REALITY_VPS="failed"
        if [[ "${RP_STATUS}" == "ok" ]]; then REALITY_VPS="verified"; ok "A real Reality client works on port ${REALITY_PORT} (${RP_MED} ms)"
        else warn "The Reality client does not work on port ${REALITY_PORT}"; DIAG_FAIL=1; fi
        if [[ "${RP_FALLBACK}" == "ok" ]]; then ok "A prober without the key sees the real certificate of ${R_SITE}"
        else warn "A prober without the key does not get the certificate of ${R_SITE}"; DIAG_FAIL=1; fi
        info "Home network (MTS) for this SNI: $(mts_status reality "${R_SITE}")"
    else
        REALITY_VPS="off"; info "VLESS Reality: not configured"
    fi
    if [[ -n "${H_PASSWORD}" ]]; then
        HY2_SNI="${H_SNI}"
        CERT_SHA="$(cert_sha256 "${HY2_CERT}")"; PK_SHA="$(cert_pubkey_sha256 "${HY2_CERT}")"; H_NOT_AFTER="$(cert_not_after "${HY2_CERT}")"
        if [[ "${H_MASQ}" == "auto" ]]; then HY2_MASQ_URL="https://${H_SNI}"; else HY2_MASQ_URL="${H_MASQ}"; fi
        printf '\n'; info "Hysteria 2: SNI ${H_SNI}, port ${HY2_PORT}/UDP, self-signed certificate (pinned), valid until ${H_NOT_AFTER}"
        info "  pinSHA256 ${CERT_SHA}; sing-box key pin ${PK_SHA}; masquerade ${HY2_MASQ_URL}"
        hy2_client_test "${H_SNI}" "${CERT_SHA}"
        HY2_VPS="failed"
        if (( HY2_E2E == 0 )); then HY2_VPS="verified"; ok "A real Hysteria client with certificate pinning works"
        else warn "The Hysteria client does not work"; DIAG_FAIL=1; fi
        info "Home network (MTS) for this SNI: $(mts_status hysteria2 "${H_SNI}")"
    fi
    if [[ -n "${T_USER}" ]]; then
        TT_CERT_SHA="$(cert_sha256 "${TT_DIR}/cert.pem")"
        printf '\n'; info "TrustTunnel: hostname ${T_SNI}, port ${TT_PORT}/TCP+UDP, self-signed certificate embedded in the link"
        tt_checks
        if [[ "${TT_VPS_H2}" == "ok" ]]; then ok "HTTP/2 (TCP): the pinned certificate is presented"; else warn "HTTP/2 (TCP): unexpected certificate or no answer"; DIAG_FAIL=1; fi
        case "${TT_VPS_H3}" in
            ok) ok "HTTP/3 (QUIC): the pinned certificate is presented" ;;
            fail) warn "HTTP/3 (QUIC): no answer or unexpected certificate"; DIAG_FAIL=1 ;;
            *) info "HTTP/3 (QUIC): not checked (this OpenSSL has no QUIC client)" ;;
        esac
        info "Home network (MTS): HTTP/2 $(mts_status tt_h2 "${T_SNI}"), HTTP/3 $(mts_status tt_h3 "${T_SNI}")"
    fi
    printf '\n'
    for s in "${R_SITE}" "${H_SNI}" "${T_SNI}"; do
        if [[ -n "${s}" ]] && ru_blocked "${s}"; then
            warn "${s} is on the RKN block list: choose another name (--reselect-reality, HY2_SNI=auto, TT_SNI=auto)"; DIAG_FAIL=1
        fi
    done
    if [[ "${RU_BL_STATE}" == "ok" ]]; then ok "No server name of this node is on the RKN block list"; fi
    russia_check
    if [[ "${RU_VERDICT}" == "blocked" ]]; then DIAG_FAIL=1; fi
    if [[ -n "${JSON_OUT}" ]]; then
        build_report | json_emit
        if [[ "${JSON_OUT}" != "-" ]]; then printf '\n'; ok "JSON report: ${JSON_OUT}"; fi
    fi
    exit $(( DIAG_FAIL == 0 ? 0 : 2 ))
fi

# =============================================================================
# Install / update / repair
# =============================================================================
# One previous run is kept as .1; older logs are dropped. The connection details
# (passwords, keys) are printed to the terminal only, never into the log.
if [[ -f "${LOG_FILE}" ]]; then mv -f "${LOG_FILE}" "${LOG_FILE}.1"; fi
: > "${LOG_FILE}"
chmod 600 "${LOG_FILE}"
# tee -p: if SSH drops, tee does not die and keeps writing the log, so the
# install runs to the end; the result stays in the log and /root/veiltrium/client.txt.
TEE_ARGS=(-i -a)
if tee -p /dev/null </dev/null >/dev/null 2>&1; then TEE_ARGS=(-i -p -a); fi
exec 7>&1
# tee must not inherit the lock (fd 9): a killed installer has to release it at once.
exec > >(tee "${TEE_ARGS[@]}" "${LOG_FILE}" 7>&- 9>&-) 2>&1
TEE_PID=$!
banner
printf '\n===== Veiltrium %s (veiltrium.sh): %s =====\n' "${SCRIPT_VERSION}" "$(date -Is)"

TMPD="$(mktemp -d /root/.veiltrium.XXXXXX)"
chmod 700 "${TMPD}"

# nftables: own table only. $1 = 1 to open the VLESS Reality port.
apply_firewall() {
    local reality_on="$1" reality_in="" reality_out="" reality_egress=""
    local scan_rules="" scan_include=""
    if [[ "${reality_on}" == "1" ]]; then
        reality_in="        # VLESS Reality (TCP)"$'\n'"        tcp dport ${REALITY_PORT} accept"$'\n'
        if [[ "${PANEL_ENABLE}" == "1" && "${PANEL_VPN}" == "1" ]]; then
            # the panel through VLESS Reality: only Xray's panel outbound binds this source address
            reality_out="        meta skuid ${XRAY_UID} ip saddr ${PANEL_VPN_SRC} ip daddr 127.0.0.1 tcp dport ${PANEL_PORT} accept"$'\n'
        fi
        reality_out+="        meta skuid ${XRAY_UID} jump proxy_egress"$'\n'
        reality_egress="        tcp sport ${REALITY_PORT} accept"$'\n'
    fi
    if [[ "${TT_ENABLE}" == "1" ]]; then
        reality_in+="        # TrustTunnel (HTTP/2 over TCP, HTTP/3 over UDP)"$'\n'
        reality_in+="        meta l4proto { tcp, udp } th dport ${TT_PORT} accept"$'\n'
        reality_out+="        meta skuid ${TT_UID} jump proxy_egress"$'\n'
        reality_egress+="        meta l4proto { tcp, udp } th sport ${TT_PORT} accept"$'\n'
    fi
    if [[ "${SCANNER_BLOCK}" == "1" ]]; then
        # Proxy ports only: SSH stays reachable even if the list ever covers our own network.
        scan_rules="        # Known scanner networks: the proxy ports stay silent for them (SSH is not affected)"$'\n'
        scan_rules+="        ip saddr @scanners4 udp dport ${HY2_PORT} drop"$'\n'
        scan_rules+="        ip6 saddr @scanners6 udp dport ${HY2_PORT} drop"$'\n'
        if [[ "${reality_on}" == "1" ]]; then
            scan_rules+="        ip saddr @scanners4 tcp dport ${REALITY_PORT} drop"$'\n'
            scan_rules+="        ip6 saddr @scanners6 tcp dport ${REALITY_PORT} drop"$'\n'
        fi
        if [[ "${TT_ENABLE}" == "1" ]]; then
            scan_rules+="        ip saddr @scanners4 meta l4proto { tcp, udp } th dport ${TT_PORT} drop"$'\n'
            scan_rules+="        ip6 saddr @scanners6 meta l4proto { tcp, udp } th dport ${TT_PORT} drop"$'\n'
        fi
        scan_include="include \"${SCANNER_FILE}\""
    fi
    cat > /etc/nftables.conf.vt-new <<EOF
#!/usr/sbin/nft -f
# veiltrium: server firewall.
# Only our own table is recreated; rules of fail2ban and other services are left alone.

table inet veiltrium
delete table inet veiltrium

table inet veiltrium {
    set ssh_ports {
        type inet_service
        elements = { ${SSH_SET} }
    }

    set ssh_flood4 {
        type ipv4_addr
        size 65535
        flags dynamic,timeout
        timeout 2m
    }

    set ssh_flood6 {
        type ipv6_addr
        size 65535
        flags dynamic,timeout
        timeout 2m
    }

    # Filled from ${SCANNER_FILE} (veiltrium-scanner-block, refreshed weekly)
    set scanners4 {
        type ipv4_addr
        flags interval
        auto-merge
    }

    set scanners6 {
        type ipv6_addr
        flags interval
        auto-merge
    }

    chain input {
        type filter hook input priority filter; policy drop;

        ct state invalid drop
${scan_rules}        ct state { established, related } accept
        iif "lo" accept

        # ICMP: control messages, the network breaks without them (PMTU, IPv6)
        icmp type { destination-unreachable, time-exceeded, parameter-problem } accept
        icmp type echo-request limit rate 5/second burst 10 packets accept
        icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
        icmpv6 type echo-request limit rate 5/second burst 10 packets accept

        # DHCP: replies from the provider's address server
        udp sport 67 udp dport 68 accept
        ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept

        # SSH: at most 10 new connections per minute from one address
        tcp dport @ssh_ports ct state new add @ssh_flood4 { ip saddr limit rate over 10/minute burst 5 packets } drop
        tcp dport @ssh_ports ct state new add @ssh_flood6 { ip6 saddr limit rate over 10/minute burst 5 packets } drop
        tcp dport @ssh_ports accept

        # Hysteria 2 (QUIC)
        udp dport ${HY2_PORT} accept
${reality_in}    }

    chain forward {
        type filter hook forward priority filter; policy drop;
    }

    chain output {
        type filter hook output priority filter; policy accept;
        meta skuid ${HY2_UID} jump proxy_egress
${reality_out}    }

    # Where the Hysteria and Xray services, i.e. proxy clients, may connect:
    # the internet, yes; the server's own addresses and private networks, no.
    chain proxy_egress {
        # Replies on the loopback (the services' own statistics endpoints answer the traffic collector).
        # Only an established connection: a service still cannot open one to the server itself.
        oifname "lo" ct state established accept
        udp sport ${HY2_PORT} accept
${reality_egress}${DNS_RULES}        fib daddr type local reject
        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 } reject
        ip6 daddr { ::/127, ::ffff:0:0/96, 100::/64, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 } reject
        tcp dport 25 reject
    }
}
${scan_include}
EOF
    nft -c -f /etc/nftables.conf.vt-new || die "nftables rejected the rules; the firewall was not changed."
    chmod 700 /etc/nftables.conf.vt-new
    sync
    mv -f /etc/nftables.conf.vt-new /etc/nftables.conf
    systemctl enable nftables.service >/dev/null 2>&1
    # The nftables service applies /etc/nftables.conf (also on every boot).
    if systemctl is-active --quiet nftables.service; then
        systemctl reload nftables.service
    else
        systemctl start nftables.service
    fi
    nft list table inet veiltrium >/dev/null 2>&1 || die "the firewall rules did not load."
    nft delete table inet hy2fw >/dev/null 2>&1 || true      # the table of hy2-secure-install, if any
    OPEN_PORTS="SSH ${SSH_PORTS[*]}/TCP, ${HY2_PORT}/UDP (Hysteria)"
    if [[ "${reality_on}" == "1" ]]; then OPEN_PORTS+=", ${REALITY_PORT}/TCP (VLESS Reality)"; fi
    if [[ "${TT_ENABLE}" == "1" ]]; then OPEN_PORTS+=", ${TT_PORT}/TCP+UDP (TrustTunnel)"; fi
}

# =============================================================================
step 1 "System check"
OS_ID="$(. /etc/os-release && echo "${ID:-}")"
OS_VER="$(. /etc/os-release && echo "${VERSION_ID:-}")"
OS_NAME="$(. /etc/os-release && echo "${PRETTY_NAME:-}")"
[[ "${OS_ID}" == "ubuntu" ]] || die "this script is for Ubuntu, but this is: ${OS_NAME:-unknown system}."
[[ "${OS_VER}" == "26.04" || "${OS_VER}" == "24.04" ]] \
    || warn "Tested on Ubuntu 26.04 and 24.04, this is ${OS_NAME}; continuing."
command -v systemctl >/dev/null 2>&1 || die "systemd is required."
ARCH="$(dpkg --print-architecture)"
case "${ARCH}" in
    amd64) HY2_SHA256="${HY2_SHA256_AMD64}"; XRAY_ZIP="Xray-linux-64.zip"; XRAY_SHA256="${XRAY_SHA256_AMD64}"
           TT_ARCH="x86_64"; TT_SHA256="${TT_SHA256_AMD64}" ;;
    arm64) HY2_SHA256="${HY2_SHA256_ARM64}"; XRAY_ZIP="Xray-linux-arm64-v8a.zip"; XRAY_SHA256="${XRAY_SHA256_ARM64}"
           TT_ARCH="aarch64"; TT_SHA256="${TT_SHA256_ARM64}" ;;
    *) die "architecture ${ARCH} is not supported (amd64 or arm64 required)." ;;
esac
migrate_old_layout
# --import: the state of the old server is validated and put in place here, before any
# state is read below (a new server then continues as a new node with the same secrets).
if [[ -n "${NODE_IMPORT_FILE}" ]]; then import_node "${NODE_IMPORT_FILE}"; fi
load_ports
[[ "${HY2_PORT}" =~ ^[0-9]{1,5}$ ]] && (( HY2_PORT >= 1 && HY2_PORT <= 65535 )) \
    || die "HY2_PORT must be a number from 1 to 65535."
[[ "${REALITY_PORT}" =~ ^[0-9]{1,5}$ ]] && (( REALITY_PORT >= 1 && REALITY_PORT <= 65535 )) \
    || die "REALITY_PORT must be a number from 1 to 65535."
[[ "${REALITY_ENABLE}" == "0" || "${REALITY_ENABLE}" == "1" ]] || die "REALITY_ENABLE must be 0 or 1."
[[ "${SCANNER_BLOCK}" == "0" || "${SCANNER_BLOCK}" == "1" ]] || die "SCANNER_BLOCK must be 0 or 1."
[[ "${TT_ENABLE}" == "0" || "${TT_ENABLE}" == "1" ]] || die "TT_ENABLE must be 0 or 1."
[[ "${TT_PORT}" =~ ^[0-9]{1,5}$ ]] && (( TT_PORT >= 1 && TT_PORT <= 65535 )) \
    || die "TT_PORT must be a number from 1 to 65535."
[[ "${PANEL_PORT}" =~ ^[0-9]{1,5}$ ]] && (( PANEL_PORT >= 1 && PANEL_PORT <= 65535 )) \
    || die "PANEL_PORT must be a number from 1 to 65535."
[[ -z "${PANEL_VPN}" || "${PANEL_VPN}" == "0" || "${PANEL_VPN}" == "1" ]] || die "PANEL_VPN must be 0 or 1."
if [[ "${TT_ENABLE}" == "1" ]] && (( TT_PORT == HY2_PORT || TT_PORT == REALITY_PORT )); then
    die "TT_PORT must differ from HY2_PORT and REALITY_PORT (TrustTunnel uses both TCP and UDP)."
fi
[[ "${REALITY_FP}" =~ ^[a-z0-9]+$ ]] || die "REALITY_FP must be a fingerprint name, for example chrome or firefox."
load_candidates
[[ -z "${REALITY_SNI}" || "${REALITY_SNI}" =~ ${DOMAIN_RE} ]] || die "REALITY_SNI must be a domain name."
[[ -z "${HY2_SNI}" || "${HY2_SNI}" == "auto" || "${HY2_SNI}" =~ ${DOMAIN_RE} ]] || die "HY2_SNI must be a domain name or auto."
[[ -z "${TT_SNI}" || "${TT_SNI}" == "auto" || "${TT_SNI}" =~ ${DOMAIN_RE} ]] || die "TT_SNI must be a domain name or auto."
[[ -z "${HY2_MASQUERADE_URL}" || "${HY2_MASQUERADE_URL}" == "auto" || "${HY2_MASQUERADE_URL}" =~ ${URL_RE} ]] \
    || die "HY2_MASQUERADE_URL must start with http:// or https:// (or be auto)."
[[ -z "${PUBLIC_IP}" ]] || is_public_ipv4 "${PUBLIC_IP}" || die "PUBLIC_IP must be a public IPv4 address."
[[ "${AUTO_REBOOT_TIME}" =~ ^([01][0-9]|2[0-3]):[0-5][0-9]$ ]] || die "AUTO_REBOOT_TIME must be in HH:MM format."
[[ -z "${GLOBALPING}" || "${GLOBALPING}" == "0" || "${GLOBALPING}" == "1" ]] || die "GLOBALPING must be 0 or 1."
[[ -z "${NODE_NAME}" || "${NODE_NAME}" == "auto" || "${NODE_NAME}" == "none" || "${NODE_NAME}" =~ ${NAME_RE} ]] \
    || die "NODE_NAME must be 1-16 letters, digits or - (e.g. PL), auto or none."

detect_ssh_ports
ok "${OS_NAME}, ${ARCH}; SSH listens on port(s): ${SSH_PORTS[*]}"
install_recover
recover_interrupted
if trial_active; then
    info "A Reality trial was running; ending it before the update."
    trial_stop
fi
load_hy2_state
load_clients
if [[ "${VT_RECONFIGURE}" == "1" ]] && (( ${#CL_NAMES[@]} )); then
    renew_client_secrets
    info "VT_RECONFIGURE=1: the added clients get new credentials too (${CL_NAMES[*]})."
fi
load_node_name
# A node that already works is never rebooted by a re-run (clients would drop).
NODE_EXISTED=0
if [[ -s "${HY2_STATE}" || -s "${XRAY_STATE}" || -s "${TT_STATE}" ]]; then NODE_EXISTED=1; fi
# A server that only received an imported node is a new server (no clients are connected to it).
if (( IMPORT_FRESH == 1 )); then NODE_EXISTED=0; fi
if [[ -n "${H_PORT}" && "${H_PORT}" != "${HY2_PORT}" ]]; then
    info "The node is already configured on port ${H_PORT}/UDP; using it."
    HY2_PORT="${H_PORT}"
fi
PORT_BUSY=""
while IFS= read -r line; do
    if [[ -n "${line}" && "${line}" != *'"hysteria"'* ]]; then PORT_BUSY="${line}"; fi
done < <(ss -Hulpn "sport = :${HY2_PORT}" 2>/dev/null || true)
[[ -z "${PORT_BUSY}" ]] || die "UDP port ${HY2_PORT} is already used by another program: ${PORT_BUSY}"
ok "UDP port ${HY2_PORT} is free for Hysteria"
if [[ "${REALITY_ENABLE}" == "1" ]]; then
    PORT_BUSY=""
    while IFS= read -r line; do
        if [[ -n "${line}" && "${line}" != *'"xray"'* ]]; then PORT_BUSY="${line}"; fi
    done < <(ss -Htlpn "sport = :${REALITY_PORT}" 2>/dev/null || true)
    [[ -z "${PORT_BUSY}" ]] || die "TCP port ${REALITY_PORT} is already used by another program: ${PORT_BUSY}
  Free it, or install without VLESS Reality:  REALITY_ENABLE=0 bash $0"
    ok "TCP port ${REALITY_PORT} is free for VLESS Reality"
fi
if [[ "${TT_ENABLE}" == "1" ]]; then
    PORT_BUSY=""
    while IFS= read -r line; do
        if [[ -n "${line}" && "${line}" != *'"trusttunnel_end'* ]]; then PORT_BUSY="${line}"; fi
    done < <(ss -Htulpn "sport = :${TT_PORT}" 2>/dev/null || true)
    [[ -z "${PORT_BUSY}" ]] || die "port ${TT_PORT} (TCP/UDP) is already used by another program: ${PORT_BUSY}
  Free it, pick another one (TT_PORT=...), or install without TrustTunnel:  TT_ENABLE=0 bash $0"
    ok "Port ${TT_PORT} TCP+UDP is free for TrustTunnel"
fi

# =============================================================================
step 2 "System upgrade and packages"
export DEBIAN_FRONTEND=noninteractive
export NEEDRESTART_MODE="${NEEDRESTART_MODE:-a}"
# needrestart must not restart the proxies after library updates (that drops every
# client connection); they pick up new libraries at the next (nightly) reboot.
install -d -m 755 /etc/needrestart/conf.d
cat > /etc/needrestart/conf.d/50-veiltrium.conf <<'EOF'
# veiltrium: do not restart the proxies automatically (clients would drop)
$nrconf{override_rc}->{qr(^(hysteria-server|xray|trusttunnel)\.service$)} = 0;
EOF
audit_setup
APT_GET=(apt-get -q -o DPkg::Lock::Timeout=900
         -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
# DPkg::Lock::Timeout waits for the dpkg locks only, not for the archives/lists locks that a
# running unattended-upgrades or apt-daily holds: retry while such a process is there.
apt_run() {
    local i
    for i in 1 2 3 4 5 6 7 8 9 10; do
        if "${APT_GET[@]}" "$@"; then return 0; fi
        pgrep -x 'apt-get|apt|dpkg|unattended-upgr' >/dev/null 2>&1 || return 1
        warn "apt is busy with another process (attempt ${i}), retrying in 30 s..."
        sleep 30
    done
    return 1
}
# If a previous run was cut off in the middle of package installation, finish it.
dpkg --force-confdef --force-confold --configure -a </dev/null || true
apt_updated=0
for attempt in 1 2 3 4 5 6; do
    if "${APT_GET[@]}" update; then apt_updated=1; break; fi
    warn "Package lists did not update (attempt ${attempt}), retrying in 15 s..."
    sleep 15
done
(( apt_updated == 1 )) || die "could not update package lists (check the server's internet connection)."
apt_run -y full-upgrade || die "the system upgrade (apt-get full-upgrade) failed; see ${LOG_FILE}."
apt_run -y install curl ca-certificates openssl nftables unattended-upgrades iproute2 util-linux unzip jq qrencode \
    || die "could not install the required packages; see ${LOG_FILE}."
if apt_run -y install fail2ban python3-systemd; then
    HAVE_FAIL2BAN=1
else
    HAVE_FAIL2BAN=0
    warn "fail2ban did not install (universe repository missing?); SSH is still protected by nftables and OpenSSH."
fi
"${APT_GET[@]}" -y autoremove --purge
ok "System upgraded"

# =============================================================================
step 3 "Automatic security updates"
cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
cat > /etc/apt/apt.conf.d/52veiltrium-unattended-upgrades <<EOF
// veiltrium: security updates install automatically;
// if needed, the server reboots at night at ${AUTO_REBOOT_TIME} (server time).
Unattended-Upgrade::Remove-Unused-Kernel-Packages "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "true";
Unattended-Upgrade::Automatic-Reboot-WithUsers "true";
Unattended-Upgrade::Automatic-Reboot-Time "${AUTO_REBOOT_TIME}";
EOF
systemctl enable --now unattended-upgrades.service apt-daily.timer apt-daily-upgrade.timer >/dev/null 2>&1 || true
ok "Enabled; reboot when needed at ${AUTO_REBOOT_TIME} server time ($(date +%Z))"
if [[ "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)" == "yes" ]]; then
    ok "Clock is synchronized (NTP)"
else
    warn "Clock is not synchronized yet; check later with: timedatectl"
fi

# =============================================================================
step 4 "Kernel: hardening and QUIC buffers"
SYSCTL_FILE="/etc/sysctl.d/99-zz-veiltrium-hardening.conf"
cat > "${SYSCTL_FILE}" <<'EOF'
# veiltrium
# --- network: protection against route spoofing and junk packets ---
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_rfc1337 = 1
# --- kernel: less information for an attacker ---
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
fs.suid_dumpable = 0
fs.protected_fifos = 2
fs.protected_regular = 2
# --- Hysteria/QUIC: UDP buffers as recommended by the Hysteria developers ---
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
# --- TCP to websites: modern queue management ---
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
echo tcp_bbr > /etc/modules-load.d/veiltrium-bbr.conf
modprobe tcp_bbr 2>/dev/null || true
sysctl -q --system >/dev/null 2>&1 || true
# Our file goes last: otherwise a file applied later overrides the values.
sysctl -q -p "${SYSCTL_FILE}" >/dev/null 2>&1 || warn "some kernel settings were not applied (see sysctl -p ${SYSCTL_FILE})"
if [[ "$(sysctl -n net.core.rmem_max)" == "16777216" ]]; then
    ok "Kernel settings applied"
else
    warn "net.core.rmem_max was not applied"
fi

# Crash dumps may contain passwords: disable the crash reporter.
if systemctl cat apport.service >/dev/null 2>&1; then
    systemctl disable --now apport.service >/dev/null 2>&1 || true
fi
if [[ -f /etc/default/apport ]]; then sed -i 's/^enabled=1/enabled=0/' /etc/default/apport; fi
install -d -m 755 /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/50-veiltrium.conf.new <<'EOF'
[Journal]
SystemMaxUse=200M
MaxRetentionSec=1month
EOF
if cmp -s /etc/systemd/journald.conf.d/50-veiltrium.conf.new /etc/systemd/journald.conf.d/50-veiltrium.conf; then
    rm -f /etc/systemd/journald.conf.d/50-veiltrium.conf.new
else
    mv -f /etc/systemd/journald.conf.d/50-veiltrium.conf.new /etc/systemd/journald.conf.d/50-veiltrium.conf
    systemctl restart systemd-journald
fi
ok "Crash dumps disabled, journal limited to 200 MB / 1 month"

# =============================================================================
step 5 "SSH hardening (password login is kept)"
if command -v sshd >/dev/null 2>&1; then
    install -d -m 755 /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/00-veiltrium-hardening.conf <<'EOF'
# veiltrium: SSH hardening.
# Login methods (password, root) are NOT changed, as the server owner requested.
# MaxAuthTries stays at the OpenSSH default: an ssh-agent offering several keys
# uses up tries before the password prompt; brute force is handled by fail2ban.
MaxAuthTries 6
LoginGraceTime 30
MaxStartups 10:30:60
PermitEmptyPasswords no
X11Forwarding no
ClientAliveInterval 300
ClientAliveCountMax 3
LogLevel VERBOSE
EOF
    # sshd -t needs its privilege separation directory; with socket activation (Ubuntu 26.04)
    # it is missing while no sshd process runs, e.g. right after openssh-server was upgraded.
    [[ -d /run/sshd ]] || install -d -m 755 /run/sshd
    if sshd -t; then
        systemctl reload ssh.service >/dev/null 2>&1 || true
        SSH_PASSWORD_AUTH="$(sshd -T 2>/dev/null | awk '$1=="passwordauthentication"{print $2}')"
        SSH_ROOT_LOGIN="$(sshd -T 2>/dev/null | awk '$1=="permitrootlogin"{print $2}')"
        ok "Applied. Password login: ${SSH_PASSWORD_AUTH:-?}, root login: ${SSH_ROOT_LOGIN:-?} (unchanged)"
        PSP="$(sshd -T 2>/dev/null | awk '$1=="persourcepenalties"{print $2}' || true)"
        if [[ -n "${PSP}" && "${PSP}" != "no" ]]; then
            HAVE_PSP=1
            ok "OpenSSH built-in brute-force protection (PerSourcePenalties) is on"
        fi
    else
        rm -f /etc/ssh/sshd_config.d/00-veiltrium-hardening.conf
        warn "sshd rejected the settings; rolled back, SSH works as before."
    fi
else
    warn "OpenSSH not found; step skipped."
fi

# =============================================================================
step 6 "Service users and nftables firewall"
if ! id -u hysteria >/dev/null 2>&1; then
    useradd --system --home-dir /var/lib/hysteria --create-home --shell /usr/sbin/nologin hysteria
fi
install -d -m 750 -o hysteria -g hysteria /var/lib/hysteria
HY2_UID="$(id -u hysteria)"
XRAY_UID=""
if [[ "${REALITY_ENABLE}" == "1" ]]; then
    if ! id -u xray >/dev/null 2>&1; then
        useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin xray
    fi
    XRAY_UID="$(id -u xray)"
elif systemctl cat xray.service >/dev/null 2>&1; then
    # Stop Xray before its firewall rules disappear.
    systemctl disable --now xray.service >/dev/null 2>&1 || true
    warn "VLESS Reality is off (REALITY_ENABLE=0); the xray service was stopped."
fi
TT_UID=""
if [[ "${TT_ENABLE}" == "1" ]]; then
    if ! id -u trusttunnel >/dev/null 2>&1; then
        useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin trusttunnel
    fi
    TT_UID="$(id -u trusttunnel)"
elif systemctl cat trusttunnel.service >/dev/null 2>&1; then
    # Stop TrustTunnel before its firewall rules disappear.
    systemctl disable --now trusttunnel.service >/dev/null 2>&1 || true
    warn "TrustTunnel is off (TT_ENABLE=0); the trusttunnel service was stopped."
fi

mapfile -t DNS4 < <(awk '$1=="nameserver" && $2 ~ /^[0-9.]+$/ {print $2}' /etc/resolv.conf 2>/dev/null | sort -u || true)
mapfile -t DNS6 < <(awk '$1=="nameserver" && $2 ~ /:/ {sub(/%.*/, "", $2); print $2}' /etc/resolv.conf 2>/dev/null | sort -u || true)
DNS_RULES=""
if (( ${#DNS4[@]} )); then
    DNS_RULES+="        ip daddr { $(IFS=,; echo "${DNS4[*]}") } meta l4proto { tcp, udp } th dport 53 accept"$'\n'
fi
if (( ${#DNS6[@]} )); then
    DNS_RULES+="        ip6 daddr { $(IFS=,; echo "${DNS6[*]}") } meta l4proto { tcp, udp } th dport 53 accept"$'\n'
fi
SSH_SET="$(IFS=,; echo "${SSH_PORTS[*]}")"

if [[ -f /etc/nftables.conf && ! -f /etc/nftables.conf.orig-veiltrium ]] && ! grep -qE 'veiltrium|hy2-secure-install' /etc/nftables.conf; then
    cp -p /etc/nftables.conf /etc/nftables.conf.orig-veiltrium
fi
# The firewall includes the scanner list: it must exist (possibly empty) before the rules load.
install -d -m 700 "${SCANNER_DIR}"
if [[ ! -f "${SCANNER_FILE}" ]]; then
    printf '# veiltrium-scanner-block: no list downloaded yet\n' > "${SCANNER_FILE}"
    chmod 600 "${SCANNER_FILE}"
fi
apply_firewall "${REALITY_ENABLE}"
# UFW goes off only once our rules are loaded: the server is never left unfiltered.
if command -v ufw >/dev/null 2>&1 && [[ "$(ufw status 2>/dev/null || true)" == *"Status: active"* ]]; then
    ufw --force disable >/dev/null 2>&1 || true
    warn "UFW was enabled; turned it off, nftables does its job now."
fi
systemctl disable ufw.service >/dev/null 2>&1 || true
ok "Open from outside only: ${OPEN_PORTS}; IPv4 and IPv6"
ok "The proxies cannot reach the server's own addresses, private networks or port 25"

# Scanner blocklist: public lists of Russian state and affiliated networks
# (shadow-netlab/traffic-guard-lists, the source used by rkn-guard). Only the
# proxy ports are closed to them, so the server shows them nothing but SSH.
cat > "${SCANNER_BIN}" <<'EOS'
#!/usr/bin/env bash
# veiltrium: refresh the scanner blocklist (nftables sets scanners4/scanners6).
# A failed download or a list that looks wrong keeps the current list.
set -euo pipefail
umask 077
OUT="/etc/veiltrium/scanners.nft"
BASE="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public"
read -r -a URLS <<<"${SCANNER_URLS:-${BASE}/government_networks.list ${BASE}/antiscanner.list ${BASE}/skipa.list}"
MIN_ENTRIES=50          # fewer means a broken download
MAX_V4_ADDRS=2000000    # more means the list is not what it claims to be
TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

for url in "${URLS[@]}"; do
    if ! curl -fsSL --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 15 --max-time 120 \
            --max-filesize 8000000 "${url}" >> "${TMP}/raw"; then
        echo "veiltrium-scanner-block: could not download ${url}; keeping the current list" >&2
        exit 1
    fi
    echo >> "${TMP}/raw"
done

# IPv4: valid CIDR only, nothing broader than /16, host bits cleared.
awk -F/ '
    { sub(/#.*/, ""); gsub(/[[:space:]]/, "") }
    $0 == "" || $1 !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ { next }
    {
        p = ($2 == "" ? 32 : $2)
        if (p !~ /^[0-9]+$/ || p < 16 || p > 32) next
        split($1, o, ".")
        if (o[1] > 255 || o[2] > 255 || o[3] > 255 || o[4] > 255) next
        n = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]
        s = 2 ^ (32 - p); n -= n % s
        printf "%d.%d.%d.%d/%d\n", int(n / 16777216), int(n / 65536) % 256, int(n / 256) % 256, n % 256, p
    }' "${TMP}/raw" | sort -u > "${TMP}/v4"
# IPv6: valid CIDR only, nothing broader than /32.
awk -F/ '
    { sub(/#.*/, ""); gsub(/[[:space:]]/, "") }
    $1 ~ /^[0-9a-fA-F:]+$/ && $1 ~ /:/ && $2 ~ /^[0-9]+$/ && $2 >= 32 && $2 <= 128 { print tolower($0) }
' "${TMP}/raw" | sort -u > "${TMP}/v6"

entries=$(( $(wc -l < "${TMP}/v4") + $(wc -l < "${TMP}/v6") ))
v4_addrs="$(awk -F/ '{ s += 2 ^ (32 - $2) } END { printf "%d", s }' "${TMP}/v4")"
if (( entries < MIN_ENTRIES )); then
    echo "veiltrium-scanner-block: only ${entries} networks in the downloaded lists; keeping the current list" >&2
    exit 1
fi
if (( v4_addrs > MAX_V4_ADDRS )); then
    echo "veiltrium-scanner-block: the lists cover ${v4_addrs} IPv4 addresses, more than ${MAX_V4_ADDRS}; keeping the current list" >&2
    exit 1
fi

{
    echo "# veiltrium-scanner-block: ${entries} networks, $(date -u '+%Y-%m-%d %H:%M UTC')"
    if [[ -s "${TMP}/v4" ]]; then
        echo "add element inet veiltrium scanners4 { $(paste -sd, "${TMP}/v4") }"
    fi
    if [[ -s "${TMP}/v6" ]]; then
        echo "add element inet veiltrium scanners6 { $(paste -sd, "${TMP}/v6") }"
    fi
} > "${TMP}/scanners.nft"

# Swap the set contents in one transaction; the file on disk is replaced only if that worked.
printf 'flush set inet veiltrium scanners4\nflush set inet veiltrium scanners6\ninclude "%s"\n' \
    "${TMP}/scanners.nft" > "${TMP}/apply.nft"
if ! nft -f "${TMP}/apply.nft"; then
    echo "veiltrium-scanner-block: nftables rejected the new list; keeping the current list" >&2
    exit 1
fi
install -m 600 "${TMP}/scanners.nft" "${OUT}.new"
mv -f "${OUT}.new" "${OUT}"
echo "veiltrium-scanner-block: ${entries} networks loaded (${v4_addrs} IPv4 addresses)"
EOS
chmod 755 "${SCANNER_BIN}"
cat > /etc/systemd/system/veiltrium-scanner-block.service <<EOF
# veiltrium: refresh the scanner blocklist
[Unit]
Description=Refresh the scanner blocklist (Veiltrium)
After=network-online.target nftables.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${SCANNER_BIN}
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=${SCANNER_DIR}
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelModules=true
ProtectKernelLogs=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
EOF
cat > /etc/systemd/system/veiltrium-scanner-block.timer <<'EOF'
# veiltrium: refresh the scanner blocklist weekly
[Unit]
Description=Weekly scanner blocklist refresh (Veiltrium)

[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
if [[ "${SCANNER_BLOCK}" == "1" ]]; then
    systemctl enable veiltrium-scanner-block.timer >/dev/null 2>&1
    systemctl start veiltrium-scanner-block.timer >/dev/null 2>&1 || true
    SCANNER_RC=0
    if grep -q '^# veiltrium-scanner-block: [0-9]* networks' "${SCANNER_FILE}" && [[ -n "$(find "${SCANNER_FILE}" -mtime -6 2>/dev/null)" ]]; then
        # a list from the last days is already loaded (with the firewall above)
        printf 'veiltrium-scanner-block: %s (kept; refreshed weekly)\n' "$(head -n 1 "${SCANNER_FILE}" | sed 's/^# veiltrium-scanner-block: //')" > "${TMPD}/scanner.log"
    else
        "${SCANNER_BIN}" > "${TMPD}/scanner.log" 2>&1 || SCANNER_RC=$?
    fi
    SCANNER_MSG="$(tail -n 1 "${TMPD}/scanner.log")"
    if (( SCANNER_RC == 0 )); then
        ok "Scanner networks blocked on the proxy ports: ${SCANNER_MSG#veiltrium-scanner-block: }; refreshed weekly"
    else
        warn "${SCANNER_MSG#veiltrium-scanner-block: }"
        warn "The scanner blocklist will be retried by the weekly timer."
    fi
else
    systemctl disable --now veiltrium-scanner-block.timer >/dev/null 2>&1 || true
    info "Scanner blocklist is off (SCANNER_BLOCK=0)"
fi

# =============================================================================
step 7 "Fail2ban"
if (( HAVE_FAIL2BAN == 1 )); then
    cat > /etc/fail2ban/jail.d/veiltrium-sshd.local.new <<EOF
# veiltrium
[DEFAULT]
backend = systemd
banaction = nftables-multiport
banaction_allports = nftables-allports
bantime = 1h
bantime.increment = true
bantime.maxtime = 1w
findtime = 10m
maxretry = 5
ignoreip = 127.0.0.0/8 ::1

[sshd]
enabled = true
mode = aggressive
port = ${SSH_SET}
EOF
    systemctl enable fail2ban.service >/dev/null 2>&1 || true
    if cmp -s /etc/fail2ban/jail.d/veiltrium-sshd.local.new /etc/fail2ban/jail.d/veiltrium-sshd.local \
            && systemctl is-active --quiet fail2ban.service; then
        rm -f /etc/fail2ban/jail.d/veiltrium-sshd.local.new
    else
        mv -f /etc/fail2ban/jail.d/veiltrium-sshd.local.new /etc/fail2ban/jail.d/veiltrium-sshd.local
        systemctl restart fail2ban.service || warn "fail2ban did not restart"
    fi
    for _ in $(seq 1 30); do fail2ban-client ping >/dev/null 2>&1 && break; sleep 1; done
    if fail2ban-client status sshd >/dev/null 2>&1; then
        ok "Running: 5 failed logins in 10 minutes means a 1-hour ban, longer for repeat offenders (up to a week)"
    else
        warn "fail2ban did not start SSH protection; see: journalctl -u fail2ban"
    fi
else
    warn "Skipped (fail2ban is not installed)."
fi

# =============================================================================
step 8 "Hysteria ${HY2_VERSION} and Xray ${XRAY_VERSION} (pinned, SHA-256 verified)"
# A service restarts only when its binary, unit, config or certificate changed
# (or it is not running): a re-run does not drop the clients' connections.
# A restart resets the proxies' traffic counters: take them now, before anything changes.
traffic_collect
RESTART_HY2=0; RESTART_XRAY=0; RESTART_TT=0
unit_sum() { sha256sum "/etc/systemd/system/$1.service" 2>/dev/null | cut -c1-64 || true; }
UNIT_HY2_BEFORE="$(unit_sum hysteria-server)"
UNIT_XRAY_BEFORE="$(unit_sum xray)"
UNIT_TT_BEFORE="$(unit_sum trusttunnel)"
CURRENT_HY2="$("${HY2_BIN}" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
if [[ "${CURRENT_HY2}" != "${HY2_VERSION}" ]]; then
    fetch "https://github.com/HyNetworks/hysteria/releases/download/app/${HY2_VERSION}/hysteria-linux-${ARCH}" "${TMPD}/hysteria"
    sha_ok "${TMPD}/hysteria" "${HY2_SHA256}" || die "Hysteria checksum mismatch; installation stopped."
    install -m 755 "${TMPD}/hysteria" "${HY2_BIN}.new" && sync && mv -f "${HY2_BIN}.new" "${HY2_BIN}"
    ok "Hysteria ${HY2_VERSION} installed"; RESTART_HY2=1
else
    ok "Hysteria ${HY2_VERSION} is already installed"
fi

SANDBOX="$(cat <<'EOF'
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RemoveIPC=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX
UMask=0077
LimitCORE=0
LimitNOFILE=1048576
Restart=on-failure
RestartSec=3
EOF
)"
cat > /etc/systemd/system/hysteria-server.service <<EOF
# veiltrium: Hysteria 2 in a systemd sandbox
[Unit]
Description=Hysteria 2 server (Veiltrium)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=10

[Service]
User=hysteria
Group=hysteria
WorkingDirectory=/var/lib/hysteria
ReadWritePaths=/var/lib/hysteria
Environment=HYSTERIA_LOG_LEVEL=info
Environment=HYSTERIA_DISABLE_UPDATE_CHECK=true
ExecStart=${HY2_BIN} server --config ${HY2_CONFIG}
${SANDBOX}

[Install]
WantedBy=multi-user.target
EOF

if [[ "${REALITY_ENABLE}" == "1" ]]; then
    CURRENT_XRAY="$("${XRAY_BIN}" version 2>/dev/null | awk 'NR==1{print "v"$2}' || true)"
    if [[ "${CURRENT_XRAY}" != "${XRAY_VERSION}" ]]; then
        fetch "https://github.com/XTLS/Xray-core/releases/download/${XRAY_VERSION}/${XRAY_ZIP}" "${TMPD}/xray.zip"
        sha_ok "${TMPD}/xray.zip" "${XRAY_SHA256}" || die "Xray checksum mismatch; installation stopped."
        unzip -oq "${TMPD}/xray.zip" xray -d "${TMPD}/xray"
        install -m 755 "${TMPD}/xray/xray" "${XRAY_BIN}.new" && sync && mv -f "${XRAY_BIN}.new" "${XRAY_BIN}"
        ok "Xray ${XRAY_VERSION} installed"; RESTART_XRAY=1
    else
        ok "Xray ${XRAY_VERSION} is already installed"
    fi
    install -d -m 750 -o root -g xray "${XRAY_DIR}"
    cat > /etc/systemd/system/xray.service <<EOF
# veiltrium: VLESS Reality (Xray) in a systemd sandbox
[Unit]
Description=Xray VLESS Reality (Veiltrium)
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=10

[Service]
User=xray
Group=xray
ExecStart=${XRAY_BIN} run -c ${XRAY_DIR}/config.json
${SANDBOX}

[Install]
WantedBy=multi-user.target
EOF
fi

if [[ "${TT_ENABLE}" == "1" ]]; then
    CURRENT_TT="$("${TT_BIN}" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
    if [[ "v${CURRENT_TT}" != "${TT_VERSION}" ]]; then
        TT_TGZ="trusttunnel-${TT_VERSION}-linux-${TT_ARCH}.tar.gz"
        fetch "https://github.com/TrustTunnel/TrustTunnel/releases/download/${TT_VERSION}/${TT_TGZ}" "${TMPD}/${TT_TGZ}"
        sha_ok "${TMPD}/${TT_TGZ}" "${TT_SHA256}" || die "TrustTunnel checksum mismatch; installation stopped."
        tar -xzf "${TMPD}/${TT_TGZ}" -C "${TMPD}"
        install -m 755 "${TMPD}/trusttunnel-${TT_VERSION}-linux-${TT_ARCH}/trusttunnel_endpoint" "${TT_BIN}.new" \
            && sync && mv -f "${TT_BIN}.new" "${TT_BIN}"
        ok "TrustTunnel ${TT_VERSION} installed"; RESTART_TT=1
    else
        ok "TrustTunnel ${TT_VERSION} is already installed"
    fi
    install -d -m 750 -o root -g trusttunnel "${TT_DIR}"
    cat > /etc/systemd/system/trusttunnel.service <<EOF
# veiltrium: TrustTunnel endpoint in a systemd sandbox
[Unit]
Description=TrustTunnel endpoint (Veiltrium)
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=120
StartLimitBurst=10

[Service]
User=trusttunnel
Group=trusttunnel
WorkingDirectory=${TT_DIR}
ExecStart=${TT_BIN} ${TT_DIR}/vpn.toml ${TT_DIR}/hosts.toml
${SANDBOX}

[Install]
WantedBy=multi-user.target
EOF
fi
systemctl daemon-reload
[[ "$(unit_sum hysteria-server)" == "${UNIT_HY2_BEFORE}" ]] || RESTART_HY2=1
[[ "$(unit_sum xray)" == "${UNIT_XRAY_BEFORE}" ]] || RESTART_XRAY=1
[[ "$(unit_sum trusttunnel)" == "${UNIT_TT_BEFORE}" ]] || RESTART_TT=1
ok "Services run as separate users in a systemd sandbox"

# =============================================================================
step 9 "VLESS Reality mask site"
# Normal runs keep the working site (links do not change). The site is chosen by
# measurements only on a fresh node, with --reselect-reality, or with REALITY_SNI.
REALITY_OK=0
REALITY_VPS="off"
R_SITE=""
R_DECISION=""
R_TOP3=""
REALITY_SSH_BANNER=""
RP_FALLBACK="untested"
install -d -m 700 "${STATE_DIR}"
save_candidates
load_ru_blocklist
if [[ "${RU_BL_STATE}" == "ok" ]]; then
    info "RKN block list: $(wc -l < "${TMPD}/ru-blocked") domains; a site on it is never chosen"
else
    warn "The RKN block list could not be downloaded; the site choice runs without it."
fi
if [[ "${REALITY_ENABLE}" == "1" ]]; then
    load_reality_state
    PREV_SITE="${R_SITE}"
    if [[ -n "${R_UUID}" ]]; then
        ok "Reality keys kept from the previous run (new ones: VT_RECONFIGURE=1)"
    else
        PREV_SITE=""
        R_UUID="$("${XRAY_BIN}" uuid)"
        KEYS="$("${XRAY_BIN}" x25519)"
        R_PRIV="$(awk -F': ' 'NR==1{print $2}' <<<"${KEYS}")"
        R_PUB="$(awk -F': ' 'NR==2{print $2}' <<<"${KEYS}")"
        unset KEYS
        R_SID="$(openssl rand -hex 8)"
        R_SITE=""
    fi
    [[ "${R_UUID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ && \
       "${R_PRIV}" =~ ^[A-Za-z0-9_-]{43}$ && "${R_PUB}" =~ ^[A-Za-z0-9_-]{43}$ && \
       "${R_SID}" =~ ^[0-9a-f]{16}$ ]] || die "Xray produced keys in an unexpected format."
    # The panel's own VLESS profile (PANEL_VPN=1): kept between runs; turning it off removes it, and
    # turning it on again gives a new one.
    PREV_ADMIN="${R_ADMIN_UUID}"
    if [[ "${PANEL_ENABLE}" == "1" && "${PANEL_VPN}" == "1" ]]; then
        if [[ -z "${R_ADMIN_UUID}" ]]; then R_ADMIN_UUID="$("${XRAY_BIN}" uuid)"; fi
        [[ "${R_ADMIN_UUID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] \
            || die "Xray produced a UUID in an unexpected format."
    else
        R_ADMIN_UUID=""
    fi
    if [[ -n "${PREV_SITE}" && "${PREV_ADMIN}" != "${R_ADMIN_UUID}" ]]; then
        if [[ -n "${R_ADMIN_UUID}" && -n "${PREV_ADMIN}" ]]; then
            CHANGES+=("panel: a new VLESS profile for the panel (see ${PANEL_FILE}); the old one no longer works")
        elif [[ -n "${R_ADMIN_UUID}" ]]; then
            CHANGES+=("panel: also reachable through VLESS Reality with its own profile (see ${PANEL_FILE}; off: PANEL_VPN=0)")
        else
            CHANGES+=("panel: no longer reachable through VLESS Reality (its profile was removed)")
        fi
    fi
    # Traffic counters: the statistics API listens on a loopback port of its own (kept between runs).
    R_STATS_PORT="$(stats_port_pick "${R_STATS_PORT}" xray "${REALITY_PORT}" "${HY2_PORT}" "${TT_PORT}" "${PANEL_PORT}" "${H_STATS_PORT}")"
    systemctl enable xray.service >/dev/null 2>&1

    if [[ -n "${PREV_SITE}" && "${REALITY_RESELECT}" != "1" && ( -z "${REALITY_SNI}" || "${REALITY_SNI}" == "${PREV_SITE}" ) ]]; then
        info "Site ${PREV_SITE} kept (re-evaluate: --reselect-reality)"
        reality_keep "${PREV_SITE}"
        R_DECISION="kept ${PREV_SITE} (normal run: no re-selection)"
        if (( REALITY_OK == 1 )); then
            REALITY_VPS="verified"
            ok "VLESS Reality works on ${REALITY_PORT}/TCP, masked as ${R_SITE}"
        else
            REALITY_VPS="failed"
            warn "The VLESS Reality check failed; kept the previous settings (${R_SITE}). Run the script again later,"
            warn "or let it pick another site: bash $0 --reselect-reality"
        fi
    else
        if [[ -n "${REALITY_SNI}" ]]; then
            SITES=("${REALITY_SNI}")
            info "Checking the requested site ${REALITY_SNI}:"
        else
            # the current site competes too, even if it is no longer in the list;
            # the names of Hysteria and TrustTunnel are left out (separate identities)
            load_tt_state
            reality_sites "${PREV_SITE}" "${H_SNI}" "${T_SNI}"
            info "Evaluating ${#SITES[@]} candidates (${CAND_SOURCE} list): direct TLS checks, then a real Reality client on a"
            info "separate loopback instance (the running service is not touched):"
        fi
        reality_evaluate "${SITES[@]}"
        reality_choose "${PREV_SITE}"
        selection_json > "${TMPD}/selection.json"
        install -m 600 "${TMPD}/selection.json" "${SELECTION_FILE}"
        info "Decision: ${R_DECISION}"
        if [[ -n "${R_TOP3}" ]]; then info "Top 3: ${R_TOP3}"; fi
        if [[ -n "${R_CHOSEN}" && "${R_CHOSEN}" == "${PREV_SITE}" ]]; then
            reality_keep "${PREV_SITE}"
            if (( REALITY_OK == 1 )); then
                REALITY_VPS="verified"; ok "VLESS Reality works on ${REALITY_PORT}/TCP, masked as ${R_SITE}"
            else
                REALITY_VPS="failed"; warn "The VLESS Reality check failed; kept the previous settings (${R_SITE})."
            fi
        elif [[ -n "${R_CHOSEN}" ]]; then
            # A node that already works tries only the chosen site; a fresh node may fall back to the next best.
            TRY=("${R_CHOSEN}")
            if [[ -z "${PREV_SITE}" ]]; then
                for s in ${R_TOP3}; do [[ " ${TRY[*]} " == *" ${s} "* ]] || TRY+=("${s}"); done
            fi
            for s in "${TRY[@]}"; do
                reality_switch "${s}"
                if (( SWITCH_OK == 1 )); then REALITY_OK=1; break; fi
                ROLLBACKS+=("reality: ${s} passed the isolated test but failed on the production port; previous state restored")
                warn "${s} did not work on the production port ${REALITY_PORT}; previous state restored."
            done
            if (( REALITY_OK == 1 )); then
                REALITY_VPS="verified"
                ok "VLESS Reality works on ${REALITY_PORT}/TCP, masked as ${R_SITE}"
                if [[ -n "${PREV_SITE}" && "${R_SITE}" != "${PREV_SITE}" ]]; then
                    CHANGES+=("reality: SNI ${PREV_SITE} -> ${R_SITE} (UUID, keys and shortId unchanged)")
                    LINKS_CHANGED+=("vless: only sni / server_name changes to ${R_SITE}")
                    warn "Reality site changed: ${PREV_SITE} -> ${R_SITE}. On the clients change only sni (server_name) of"
                    warn "the VLESS link; UUID, public key and shortId stay. Hysteria and TrustTunnel are not affected."
                elif [[ -z "${PREV_SITE}" ]]; then
                    CHANGES+=("reality: new node on ${R_SITE}")
                fi
            elif [[ -n "${PREV_SITE}" ]]; then
                R_SITE="${PREV_SITE}"
                reality_verify_production "${R_SITE}"
                if [[ "${RP_STATUS}" == "ok" ]]; then REALITY_OK=1; REALITY_VPS="verified"; else REALITY_VPS="failed"; fi
                warn "The VLESS Reality check failed; kept the previous settings (${R_SITE})."
            elif [[ -s "${XRAY_STATE}" && -s "${XRAY_DIR}/config.json" ]]; then
                # VT_RECONFIGURE=1 on a working node: the old node came back, keep it on
                SAVED_RECONF="${VT_RECONFIGURE}"; VT_RECONFIGURE=0; load_reality_state; VT_RECONFIGURE="${SAVED_RECONF}"
                REALITY_VPS="failed"
                warn "The new Reality settings did not work; the previous node (${R_SITE}, old keys) was restored."
            else
                R_SITE=""; REALITY_VPS="failed"
            fi
        elif [[ -n "${PREV_SITE}" ]]; then
            R_SITE="${PREV_SITE}"
            reality_verify_production "${R_SITE}"
            if [[ "${RP_STATUS}" == "ok" ]]; then REALITY_OK=1; REALITY_VPS="verified"; else REALITY_VPS="failed"; fi
            warn "No candidate passed; kept the previous settings (${R_SITE})."
            if [[ -n "${REALITY_SNI}" ]]; then
                ROLLBACKS+=("reality: the requested site ${REALITY_SNI} did not pass the checks; ${PREV_SITE} kept")
            fi
        fi
        if [[ -z "${R_SITE}" ]]; then
            systemctl disable --now xray.service >/dev/null 2>&1 || true
            apply_firewall 0
            warn "VLESS Reality did not work with any site (${SITES[*]}); the service was stopped and TCP ${REALITY_PORT} closed, continuing with Hysteria."
        fi
    fi
fi

# =============================================================================
step 10 "Hysteria node"
# Hysteria's TLS identity is its own: kept between runs and never copied from the
# Reality site. A new node (or HY2_SNI=auto) gets its own name from the candidates.
if [[ "${HY2_SNI}" == "auto" || ( -z "${HY2_SNI}" && -z "${H_SNI}" ) ]]; then
    HY2_SNI="$(pick_independent_sni "${R_SITE}" "$(sed -n "s/^T_SNI=//p" "${TT_STATE}" 2>/dev/null | head -n 1 || true)")"
    info "Hysteria SNI: ${HY2_SNI} (chosen separately from the Reality site)"
elif [[ -z "${HY2_SNI}" ]]; then
    HY2_SNI="${H_SNI}"
fi
if [[ -n "${R_SITE}" && "${HY2_SNI}" == "${R_SITE}" ]]; then
    info "Note: Hysteria uses the same SNI as Reality (${R_SITE}), as nodes from before 2026-10-09 do."
    info "      A separate name: HY2_SNI=auto (new certificate, same password; update the hysteria2 link)."
fi
if [[ "${HY2_MASQUERADE_URL}" == "auto" ]]; then H_MASQ="auto"
elif [[ -n "${HY2_MASQUERADE_URL}" ]]; then H_MASQ="${HY2_MASQUERADE_URL}"
elif [[ -z "${H_MASQ}" ]]; then H_MASQ="auto"; fi
if [[ "${H_MASQ}" == "auto" ]]; then HY2_MASQ_URL="https://${HY2_SNI}"; else HY2_MASQ_URL="${H_MASQ}"; fi
if [[ -z "${PUBLIC_IP}" ]]; then
    PUBLIC_IP="$(detect_public_ip)"
    [[ -n "${PUBLIC_IP}" ]] || die "could not detect the server's public IPv4; set it manually: PUBLIC_IP=x.x.x.x bash $0"
    is_public_ipv4 "${PUBLIC_IP}" || warn "The server has no public IPv4 of its own (${PUBLIC_IP}); if it is behind NAT, set PUBLIC_IP."
fi
# A saved list may name this server itself (a standby deployed from an export of the
# main node): drop it quietly; an explicit STANDBY_HOSTS with our own address stays an error.
if [[ -z "${STANDBY_HOSTS}" && ",${N_STANDBY}," == *",${PUBLIC_IP},"* ]]; then
    N_STANDBY="$(tr ',' '\n' <<<"${N_STANDBY}" | grep -vxF -- "${PUBLIC_IP}" | paste -sd, - || true)"
    info "This server (${PUBLIC_IP}) is not its own standby: removed from the saved standby list"
fi
standby_parse "${N_STANDBY}" "${PUBLIC_IP}" || die "${STANDBY_ERR}"
if (( ${#STANDBY[@]} )); then info "Standby servers in the client links and configs: ${STANDBY[*]} (assumed to use the same ports)"; fi
# The node name in client apps (Veiltrium-<name>): explicit setting, else the saved one,
# else the server's country code (detected once, then saved).
N_KNOWN=1
if [[ "${NODE_NAME}" == "auto" || ( -z "${NODE_NAME}" && "${N_SAVED}" == "0" ) ]]; then
    N_NAME="$(detect_country)"
    if [[ -z "${N_NAME}" ]]; then
        N_KNOWN=0
        info "Could not detect the server's country (tried again on the next run); a node name can be set with NODE_NAME=XX."
    fi
elif [[ "${NODE_NAME}" == "none" ]]; then
    N_NAME=""
elif [[ -n "${NODE_NAME}" ]]; then
    N_NAME="${NODE_NAME}"
fi
save_node_name "${N_KNOWN}"
ok "Node name in client apps: ${LABEL}"
install -d -m 750 -o root -g hysteria "${HY2_DIR}"
# A node that exists on disk is changed as a transaction: if the new settings do not
# work (or the run is cut off), the previous files come back.
HY2_TXN=0
if (( IMPORT_FRESH == 0 )) && [[ -e "${HY2_CONFIG}" || -e "${HY2_CERT}" ]]; then
    txn_begin hysteria hysteria-server.service "${HY2_CERT}" "${HY2_KEY}" "${HY2_CONFIG}" "${HY2_STATE}"
    HY2_TXN=1
fi
NEW_CERT=1
if [[ -n "${H_PASSWORD}" ]]; then
    if [[ "${H_SNI}" == "${HY2_SNI}" && \
          "$(openssl x509 -in "${HY2_CERT}" -noout -checkhost "${HY2_SNI}" 2>/dev/null || true)" == *"does match"* ]]; then
        NEW_CERT=0
        ok "The node is already configured; password and certificate kept (new ones: VT_RECONFIGURE=1)"
    else
        warn "Hysteria SNI changes: ${H_SNI} -> ${HY2_SNI}. Same password, new certificate: update the link on your clients."
        CHANGES+=("hysteria2: SNI ${H_SNI} -> ${HY2_SNI}, new certificate (password unchanged)")
        LINKS_CHANGED+=("hysteria2: new link (sni and certificate pin)")
    fi
else
    H_PASSWORD="$(openssl rand -hex 24)"
    H_AUTH="userpass"          # a new node: a password per client from the start
fi
if (( ${#CL_NAMES[@]} )); then H_AUTH="userpass"; fi
set_hy2_auth_main
if (( NEW_CERT == 1 )); then
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "${HY2_KEY}.new" -out "${HY2_CERT}.new" -days 3650 -subj "/CN=${HY2_SNI}" \
        -addext "subjectAltName=DNS:${HY2_SNI}" -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature" -addext "extendedKeyUsage=serverAuth" \
        >/dev/null 2>&1 || die "could not create the certificate."
    mv -f "${HY2_KEY}.new" "${HY2_KEY}"
    mv -f "${HY2_CERT}.new" "${HY2_CERT}"
    ok "Self-signed certificate created for ${HY2_SNI} (clients pin its fingerprint)"
fi
chown root:hysteria "${HY2_KEY}" "${HY2_CERT}"
chmod 640 "${HY2_KEY}"
chmod 644 "${HY2_CERT}"

# Traffic counters: the statistics API on a loopback port with a secret, both kept between runs.
H_STATS_PORT="$(stats_port_pick "${H_STATS_PORT}" hysteria "${HY2_PORT}" "${REALITY_PORT}" "${TT_PORT}" "${PANEL_PORT}" "${R_STATS_PORT}")"
[[ "${H_STATS_SECRET}" =~ ^[0-9a-f]{48}$ ]] || H_STATS_SECRET="$(openssl rand -hex 24)"
install -m 640 -o root -g hysteria /dev/null "${HY2_CONFIG}.new"
hy2_server_yaml "${HY2_CONFIG}.new"
HY2_RESTART=1
if cmp -s "${HY2_CONFIG}.new" "${HY2_CONFIG}" 2>/dev/null && (( NEW_CERT == 0 )); then HY2_RESTART=0; fi
mv -f "${HY2_CONFIG}.new" "${HY2_CONFIG}"

save_hy2_state

CERT_SHA="$(cert_sha256 "${HY2_CERT}")"
PK_SHA="$(cert_pubkey_sha256 "${HY2_CERT}")"
H_NOT_AFTER="$(cert_not_after "${HY2_CERT}")"
[[ "${CERT_SHA}" =~ ^[0-9a-f]{64}$ && "${PK_SHA}" =~ ^[A-Za-z0-9+/]{43}=$ ]] \
    || die "could not compute the certificate fingerprints."

systemctl enable hysteria-server.service >/dev/null 2>&1
HY2_RESTARTED=0
if (( HY2_RESTART == 1 || RESTART_HY2 == 1 )) || ! systemctl is-active --quiet hysteria-server.service; then
    systemctl restart hysteria-server.service || true
    HY2_RESTARTED=1
fi
HY2_UP=0
if wait_listening -Hulpn "${HY2_PORT}" hysteria; then HY2_UP=1; fi
if (( HY2_TXN == 1 && HY2_RESTART == 1 )); then
    # Changed settings must pass a real client check before they are kept.
    if (( HY2_UP == 1 && HY2_RESTARTED == 1 )); then
        hy2_client_test "${HY2_SNI}" "${CERT_SHA}"
        if (( HY2_E2E != 0 )); then HY2_UP=0; fi
    fi
    if (( HY2_UP == 1 )); then
        txn_commit hysteria
    else
        journalctl -u hysteria-server --no-pager -n 30 || true
        txn_restore hysteria
        alert_notify rollback "the new Hysteria settings did not work; the previous settings were restored."
        die "the new Hysteria settings did not work; the previous settings (password, certificate, link) were restored."
    fi
else
    # unchanged files (a binary update or a stopped service only): nothing to roll back
    if (( HY2_TXN == 1 )); then txn_commit hysteria; fi
fi
if (( HY2_UP == 0 )); then
    journalctl -u hysteria-server --no-pager -n 30 || true
    die "the hysteria-server service did not start."
fi
ok "Hysteria: port ${HY2_PORT}/UDP, SNI ${HY2_SNI}, masquerade ${HY2_MASQ_URL}"
HOST="${PUBLIC_IP}"

# =============================================================================
step 11 "TrustTunnel"
TT_URL=""
TT_OK=0
TT_VPS_H2="off"; TT_VPS_H3="off"
if [[ "${TT_ENABLE}" == "1" ]]; then
    load_tt_state
    # An existing endpoint is changed as a transaction, like Hysteria.
    TT_TXN=0
    if (( IMPORT_FRESH == 0 )) && [[ -e "${TT_DIR}/vpn.toml" || -e "${TT_DIR}/cert.pem" ]]; then
        txn_begin trusttunnel trusttunnel.service "${TT_DIR}/cert.pem" "${TT_DIR}/key.pem" "${TT_DIR}/vpn.toml" \
            "${TT_DIR}/hosts.toml" "${TT_DIR}/credentials.toml" "${TT_STATE}"
        TT_TXN=1
    fi
    # State before any change (the certificate below may be regenerated for the same name).
    TT_SUM_BEFORE="$(cat "${TT_DIR}/vpn.toml" "${TT_DIR}/hosts.toml" "${TT_DIR}/credentials.toml" "${TT_DIR}/cert.pem" "${TT_DIR}/key.pem" 2>/dev/null | sha256sum || true)"
    if [[ -z "${T_USER}" || -z "${T_PASS}" ]]; then
        T_USER="u$(openssl rand -hex 4)"
        T_PASS="$(openssl rand -hex 24)"
        T_SNI=""
    else
        ok "TrustTunnel credentials kept from the previous run (new ones: VT_RECONFIGURE=1)"
    fi
    # TrustTunnel's TLS identity is its own too: kept between runs, never copied from
    # Reality; a new node (or TT_SNI=auto) gets a name of its own.
    if [[ "${TT_SNI}" == "auto" || ( -z "${TT_SNI}" && -z "${T_SNI}" ) ]]; then
        TT_SNI="$(pick_independent_sni "${R_SITE}" "${HY2_SNI}")"
        info "TrustTunnel hostname: ${TT_SNI} (chosen separately from the Reality site)"
    elif [[ -z "${TT_SNI}" ]]; then
        TT_SNI="${T_SNI}"
    fi
    if [[ -n "${R_SITE}" && "${TT_SNI}" == "${R_SITE}" ]]; then
        info "Note: TrustTunnel uses the same name as Reality (${R_SITE}); a separate one: TT_SNI=auto (new certificate, same credentials)."
    fi
    if [[ "${T_SNI}" != "${TT_SNI}" || \
          "$(openssl x509 -in "${TT_DIR}/cert.pem" -noout -checkhost "${TT_SNI}" 2>/dev/null || true)" != *"does match"* ]]; then
        if [[ -n "${T_SNI}" ]]; then
            warn "TrustTunnel hostname changes: ${T_SNI} -> ${TT_SNI}. Same credentials, new certificate: update the link on your clients."
            CHANGES+=("trusttunnel: hostname ${T_SNI} -> ${TT_SNI}, new certificate (credentials unchanged)")
            LINKS_CHANGED+=("trusttunnel: new tt:// link (hostname and embedded certificate)")
        fi
        # TrustTunnel clients trust the embedded certificate as its own root: it must be
        # allowed to sign certificates (keyCertSign), otherwise strict TLS libraries
        # reject it with "unable to get local issuer certificate".
        openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
            -keyout "${TT_DIR}/key.pem.new" -out "${TT_DIR}/cert.pem.new" -days 3650 -subj "/CN=${TT_SNI}" \
            -addext "subjectAltName=DNS:${TT_SNI}" -addext "basicConstraints=critical,CA:TRUE" \
            -addext "keyUsage=critical,digitalSignature,keyCertSign" -addext "extendedKeyUsage=serverAuth" \
            >/dev/null 2>&1 || die "could not create the TrustTunnel certificate."
        mv -f "${TT_DIR}/key.pem.new" "${TT_DIR}/key.pem"
        mv -f "${TT_DIR}/cert.pem.new" "${TT_DIR}/cert.pem"
    fi
    T_SNI="${TT_SNI}"
    chown root:trusttunnel "${TT_DIR}/key.pem" "${TT_DIR}/cert.pem"
    chmod 640 "${TT_DIR}/key.pem"
    chmod 644 "${TT_DIR}/cert.pem"
    T_STATS_PORT="$(stats_port_pick "${T_STATS_PORT}" trusttunnel_end "${TT_PORT}" "${HY2_PORT}" "${REALITY_PORT}" "${PANEL_PORT}" "${R_STATS_PORT}" "${H_STATS_PORT}")"
    TT_IPV6="${T_IPV6:-}"
    if [[ "${TT_IPV6}" != "true" && "${TT_IPV6}" != "false" ]]; then
        TT_IPV6=false
        if ip -6 route get 2001:4860:4860::8888 >/dev/null 2>&1; then TT_IPV6=true; fi
    fi

    install -m 640 -o root -g trusttunnel /dev/null "${TT_DIR}/vpn.toml.new"
    cat > "${TT_DIR}/vpn.toml.new" <<EOF
# veiltrium: TrustTunnel endpoint
listen_address = "0.0.0.0:${TT_PORT}"
ipv6_available = ${TT_IPV6}
allow_private_network_connections = false
tls_handshake_timeout_secs = 10
client_listener_timeout_secs = 600
connection_establishment_timeout_secs = 30
tcp_connections_timeout_secs = 604800
udp_connections_timeout_secs = 300
credentials_file = "${TT_DIR}/credentials.toml"

[listen_protocols]

[listen_protocols.http1]
upload_buffer_size = 32768

[listen_protocols.http2]
initial_connection_window_size = 8388608
initial_stream_window_size = 131072
max_concurrent_streams = 1000
max_frame_size = 16384
header_table_size = 65536

[listen_protocols.quic]
recv_udp_payload_size = 1350
send_udp_payload_size = 1350
initial_max_data = 104857600
initial_max_stream_data_bidi_local = 1048576
initial_max_stream_data_bidi_remote = 1048576
initial_max_stream_data_uni = 1048576
initial_max_streams_bidi = 4096
initial_max_streams_uni = 4096
max_connection_window = 25165824
max_stream_window = 16777216
disable_active_migration = true
enable_early_data = true
message_queue_capacity = 4096

[forward_protocol]
direct = {}
EOF
    if [[ -n "${T_STATS_PORT}" ]]; then
        # per-user counters (TrustTunnel v1.1.0: /clients with per_client_metrics), loopback only
        printf '\n[metrics]\naddress = "127.0.0.1:%s"\nper_client_metrics = true\n' "${T_STATS_PORT}" >> "${TT_DIR}/vpn.toml.new"
    fi
    mv -f "${TT_DIR}/vpn.toml.new" "${TT_DIR}/vpn.toml"
    install -m 640 -o root -g trusttunnel /dev/null "${TT_DIR}/hosts.toml.new"
    cat > "${TT_DIR}/hosts.toml.new" <<EOF
# veiltrium: TrustTunnel TLS host (self-signed, embedded in the client link)
[[main_hosts]]
hostname = "${T_SNI}"
cert_chain_path = "${TT_DIR}/cert.pem"
private_key_path = "${TT_DIR}/key.pem"
EOF
    mv -f "${TT_DIR}/hosts.toml.new" "${TT_DIR}/hosts.toml"
    install -m 640 -o root -g trusttunnel /dev/null "${TT_DIR}/credentials.toml.new"
    tt_credentials_toml "${TT_DIR}/credentials.toml.new"
    mv -f "${TT_DIR}/credentials.toml.new" "${TT_DIR}/credentials.toml"
    install -m 600 /dev/null "${TT_STATE}.new"
    printf 'T_USER=%q\nT_PASS=%q\nT_SNI=%q\nT_IPV6=%q\n' "${T_USER}" "${T_PASS}" "${T_SNI}" "${TT_IPV6}" > "${TT_STATE}.new"
    if [[ -n "${T_STATS_PORT}" ]]; then printf 'T_STATS_PORT=%q\n' "${T_STATS_PORT}" >> "${TT_STATE}.new"; fi
    mv -f "${TT_STATE}.new" "${TT_STATE}"
    TT_SUM_AFTER="$(cat "${TT_DIR}/vpn.toml" "${TT_DIR}/hosts.toml" "${TT_DIR}/credentials.toml" "${TT_DIR}/cert.pem" "${TT_DIR}/key.pem" | sha256sum)"

    systemctl enable trusttunnel.service >/dev/null 2>&1
    TT_RESTARTED=0
    if [[ "${TT_SUM_BEFORE}" != "${TT_SUM_AFTER}" ]] || (( RESTART_TT == 1 )) || ! systemctl is-active --quiet trusttunnel.service; then
        systemctl restart trusttunnel.service || true
        TT_RESTARTED=1
    fi
    TT_UP=0
    if wait_listening -Htlpn "${TT_PORT}" trusttunnel_end && wait_listening -Hulpn "${TT_PORT}" trusttunnel_end; then
        TT_UP=1
        # changed settings: the endpoint must present exactly its (new) certificate
        if (( TT_TXN == 1 && TT_RESTARTED == 1 )) && [[ "${TT_SUM_BEFORE}" != "${TT_SUM_AFTER}" ]]; then
            tt_checks
            if [[ "${TT_VPS_H2}" != "ok" ]]; then TT_UP=0; fi
        fi
    fi
    if (( TT_TXN == 1 )) && [[ "${TT_SUM_BEFORE}" == "${TT_SUM_AFTER}" ]]; then
        txn_commit trusttunnel      # unchanged files: nothing to roll back
    elif (( TT_TXN == 1 )); then
        if (( TT_UP == 1 )); then
            txn_commit trusttunnel
        else
            journalctl -u trusttunnel --no-pager -n 20 || true
            txn_restore trusttunnel
            load_tt_state
            ROLLBACKS+=("trusttunnel: the new settings did not work; the previous settings were restored")
            warn "The new TrustTunnel settings did not work; the previous settings were restored."
            if wait_listening -Htlpn "${TT_PORT}" trusttunnel_end; then TT_UP=1; fi
        fi
    fi
    if (( TT_UP == 1 )); then
        TT_OK=1
        # The endpoint itself builds the client link (tt://, the self-signed certificate is embedded).
        TT_URL="$(tt_export_link "${T_USER}")"
        if [[ -z "${TT_URL}" && "${TT_SUM_BEFORE}" == "${TT_SUM_AFTER}" ]]; then
            TT_URL="$(grep -m1 '^tt://' "${CLIENT_FILE}" 2>/dev/null || true)"   # unchanged endpoint: same link
        fi
        if [[ -n "${TT_URL}" ]]; then
            ok "TrustTunnel: port ${TT_PORT}/TCP+UDP, hostname ${T_SNI}"
        else
            warn "TrustTunnel runs, but the client link could not be exported:"
            sed 's/^/      /' "${TMPD}/tt-link.err" | tail -5
        fi
    else
        journalctl -u trusttunnel --no-pager -n 20 || true
        warn "The trusttunnel service did not start; continuing without it."
    fi
else
    info "TrustTunnel is off (TT_ENABLE=0)"
fi

# =============================================================================
step 12 "Verification"
CHECK_FAIL=0
if (( ${#ROLLBACKS[@]} )); then CHECK_FAIL=1; fi   # a requested change did not happen
ok "Hysteria listens on ${HY2_PORT}/UDP"
traffic_endpoints_check

# Isolation: root can reach SSH, the proxy services cannot
PROXY_USERS=(hysteria)
[[ -n "${R_SITE}" ]] && PROXY_USERS+=(xray)   # xray is running: verified, or the previous config restored
(( TT_OK == 0 )) || PROXY_USERS+=(trusttunnel)
if timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/${SSH_PORTS[0]}" 2>/dev/null; then
    for u in "${PROXY_USERS[@]}"; do
        if timeout 5 runuser -u "${u}" -- bash -c "exec 3<>/dev/tcp/127.0.0.1/${SSH_PORTS[0]}" 2>/dev/null; then
            warn "Isolation does NOT work: service ${u} reached the server's SSH"; CHECK_FAIL=1
        else
            ok "Isolation works: service ${u} cannot connect to the server itself"
        fi
    done
else
    info "SSH does not listen on 127.0.0.1; skipping the direct isolation check"
fi

# End-to-end check: a real Hysteria client with certificate pinning
hy2_client_test "${HY2_SNI}" "${CERT_SHA}"
HY2_VPS="failed"
if (( HY2_E2E == 0 )); then
    HY2_VPS="verified"
    ok "The client connected with certificate pinning and opened a website through the proxy"
else
    warn "End-to-end check failed (no answer from the test sites through the proxy). Client log:"
    sed 's/^/      /' "${TMPD}/client.log" | tail -15
    CHECK_FAIL=1
fi
if [[ "${PROXY_LOCAL_RC}" == "97" ]]; then
    ok "SSH on the server itself cannot be reached through the proxy (connection refused)"
else
    warn "The server itself was reachable through the proxy (curl rc=${PROXY_LOCAL_RC})"; CHECK_FAIL=1
fi
SECURITY_SCORE="$(systemd-analyze security hysteria-server.service --no-pager 2>/dev/null | tail -1 | grep -oE '[0-9]+\.[0-9]+ [A-Z_]+' || true)"
if [[ -n "${SECURITY_SCORE}" ]]; then ok "systemd sandbox score for Hysteria: ${SECURITY_SCORE} (lower is better)"; fi

if [[ "${REALITY_ENABLE}" == "1" ]]; then
    if (( REALITY_OK == 1 )); then
        ok "The VLESS Reality client connected and opened a website through the proxy"
        if [[ "${REALITY_SSH_BANNER}" == *SSH-* ]]; then
            warn "SSH on the server itself was reachable through VLESS Reality"; CHECK_FAIL=1
        else
            ok "SSH on the server itself cannot be reached through VLESS Reality"
        fi
        # What a prober without the key sees: the real certificate of the mask site
        if [[ "${RP_FALLBACK}" == "ok" ]]; then
            ok "A probe without the key on ${REALITY_PORT}/TCP sees the real certificate of ${R_SITE}"
        else
            warn "A probe without the key on ${REALITY_PORT}/TCP did not get the certificate of ${R_SITE}"; CHECK_FAIL=1
        fi
        SECURITY_SCORE="$(systemd-analyze security xray.service --no-pager 2>/dev/null | tail -1 | grep -oE '[0-9]+\.[0-9]+ [A-Z_]+' || true)"
        if [[ -n "${SECURITY_SCORE}" ]]; then ok "systemd sandbox score for Xray: ${SECURITY_SCORE}"; fi
    else
        warn "VLESS Reality does not work (see step 9)"; CHECK_FAIL=1
    fi
fi

TT_CERT_SHA=""
if [[ "${TT_ENABLE}" == "1" ]]; then
    if (( TT_OK == 1 )) && [[ -n "${TT_URL}" ]]; then
        TT_CERT_SHA="$(cert_sha256 "${TT_DIR}/cert.pem")"
        # The endpoint must present exactly the certificate embedded in the client link.
        tt_checks
        if [[ "${TT_VPS_H2}" == "ok" ]]; then
            ok "TrustTunnel answers on ${TT_PORT}/TCP with its pinned certificate"
        else
            warn "TrustTunnel on ${TT_PORT}/TCP did not present the expected certificate"; CHECK_FAIL=1
        fi
        case "${TT_VPS_H3}" in
            ok) ok "TrustTunnel answers on ${TT_PORT}/UDP (HTTP/3) with its pinned certificate" ;;
            fail) warn "TrustTunnel on ${TT_PORT}/UDP (HTTP/3) did not present the expected certificate"; CHECK_FAIL=1 ;;
            *) info "TrustTunnel HTTP/3 not checked here (this OpenSSL has no QUIC client)" ;;
        esac
        SECURITY_SCORE="$(systemd-analyze security trusttunnel.service --no-pager 2>/dev/null | tail -1 | grep -oE '[0-9]+\.[0-9]+ [A-Z_]+' || true)"
        if [[ -n "${SECURITY_SCORE}" ]]; then ok "systemd sandbox score for TrustTunnel: ${SECURITY_SCORE}"; fi
    else
        TT_VPS_H2="failed"
        warn "TrustTunnel does not work (see step 11)"; CHECK_FAIL=1
    fi
fi

russia_check

# ---- Home-network probe profile ----------------------------------------------
load_probe_env
# a new key with new passwords: a leaked old profile can no longer sign results
if [[ -z "${PROBE_KEY}" || "${VT_RECONFIGURE}" == "1" ]]; then PROBE_KEY="$(openssl rand -hex 32)"; fi
PROBE_SERVER="${PUBLIC_IP}"
install -m 600 /dev/null "${PROBE_ENV}.new"
printf 'PROBE_KEY=%q\nPROBE_SERVER=%q\n' "${PROBE_KEY}" "${PROBE_SERVER}" > "${PROBE_ENV}.new"
mv -f "${PROBE_ENV}.new" "${PROBE_ENV}"
write_probe_profile

# ---- Connection details -----------------------------------------------------
write_client_files

# ---- Periodic check from Russia (every 6 hours, with GLOBALPING on) -----------
# Runs the installed copy of this script (the same one the panel helper uses).
install -d -m 755 "${PANEL_LIB}"
if ! cmp -s "${SCRIPT_PATH}" "${PANEL_LIB}/veiltrium.sh"; then
    install -m 755 "${SCRIPT_PATH}" "${PANEL_LIB}/veiltrium.sh.new"
    mv -f "${PANEL_LIB}/veiltrium.sh.new" "${PANEL_LIB}/veiltrium.sh"
fi
write_cli_wrapper   # /usr/local/bin/veiltrium
cat > "${TMPD}/russia-check.service" <<EOF
# veiltrium: periodic check from Russian networks
[Unit]
Description=Check from Russian networks that the server answers (Veiltrium)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash ${PANEL_LIB}/veiltrium.sh --check-russia
EOF
cat > "${TMPD}/russia-check.timer" <<'EOF'
# veiltrium: periodic check from Russian networks
[Unit]
Description=Check from Russian networks every 6 hours (Veiltrium)

[Timer]
OnBootSec=20min
OnUnitActiveSec=6h
RandomizedDelaySec=30min
Persistent=false

[Install]
WantedBy=timers.target
EOF
RC_CHANGED=0
for u in service timer; do
    if ! cmp -s "${TMPD}/russia-check.${u}" "/etc/systemd/system/veiltrium-russia-check.${u}"; then
        install -m 644 "${TMPD}/russia-check.${u}" "/etc/systemd/system/veiltrium-russia-check.${u}"
        RC_CHANGED=1
    fi
done
(( RC_CHANGED == 0 )) || systemctl daemon-reload
if [[ "${GLOBALPING}" == "1" ]]; then
    systemctl enable veiltrium-russia-check.timer >/dev/null 2>&1 || true
    if (( RC_CHANGED == 1 )); then systemctl restart veiltrium-russia-check.timer >/dev/null 2>&1 || true
    else systemctl start veiltrium-russia-check.timer >/dev/null 2>&1 || true; fi
    info "The check from Russia repeats every 6 hours (GLOBALPING=0 turns it off)"
else
    systemctl disable --now veiltrium-russia-check.timer >/dev/null 2>&1 || true
fi

# ---- Alerts: the watch timer exists only while a channel is set -----------------
alert_save
cat > "${TMPD}/watch.service" <<EOF
# veiltrium: service watch for alerts
[Unit]
Description=Alert if a proxy service is down (Veiltrium)

[Service]
Type=oneshot
ExecStart=/bin/bash ${PANEL_LIB}/veiltrium.sh --watch
EOF
cat > "${TMPD}/watch.timer" <<'EOF'
# veiltrium: service watch for alerts
[Unit]
Description=Check the proxy services every 5 minutes (Veiltrium)

[Timer]
OnBootSec=5min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=false

[Install]
WantedBy=timers.target
EOF
WT_CHANGED=0
for u in service timer; do
    if ! cmp -s "${TMPD}/watch.${u}" "/etc/systemd/system/veiltrium-watch.${u}"; then
        install -m 644 "${TMPD}/watch.${u}" "/etc/systemd/system/veiltrium-watch.${u}"
        WT_CHANGED=1
    fi
done
(( WT_CHANGED == 0 )) || systemctl daemon-reload
if (( A_ENABLED == 1 )); then
    systemctl enable veiltrium-watch.timer >/dev/null 2>&1 || true
    if (( WT_CHANGED == 1 )); then systemctl restart veiltrium-watch.timer >/dev/null 2>&1 || true
    else systemctl start veiltrium-watch.timer >/dev/null 2>&1 || true; fi
    info "Alerts on: $(alert_describe); services are checked every 5 minutes (test: bash $0 --test-alert)"
else
    systemctl disable --now veiltrium-watch.timer >/dev/null 2>&1 || true
fi

# ---- Traffic counters: read every 5 minutes (the installed copy, its own lock) ------
cat > "${TMPD}/traffic.service" <<EOF
# veiltrium: read the per-client traffic counters of the proxies
[Unit]
Description=Read the traffic counters of the proxies (Veiltrium)
After=network-online.target

[Service]
Type=oneshot
Nice=10
ExecStart=/bin/bash ${PANEL_LIB}/veiltrium.sh --collect-traffic
EOF
cat > "${TMPD}/traffic.timer" <<'EOF'
# veiltrium: read the per-client traffic counters of the proxies
[Unit]
Description=Read the traffic counters every 5 minutes (Veiltrium)

[Timer]
OnBootSec=3min
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=false

[Install]
WantedBy=timers.target
EOF
TC_CHANGED=0
for u in service timer; do
    if ! cmp -s "${TMPD}/traffic.${u}" "/etc/systemd/system/veiltrium-traffic.${u}"; then
        install -m 644 "${TMPD}/traffic.${u}" "/etc/systemd/system/veiltrium-traffic.${u}"
        TC_CHANGED=1
    fi
done
(( TC_CHANGED == 0 )) || systemctl daemon-reload
systemctl enable veiltrium-traffic.timer >/dev/null 2>&1 || true
if (( TC_CHANGED == 1 )); then systemctl restart veiltrium-traffic.timer >/dev/null 2>&1 || true
else systemctl start veiltrium-traffic.timer >/dev/null 2>&1 || true; fi
info "Traffic per client is counted (read every 5 minutes): bash $0 --traffic"

# =============================================================================
step 13 "Web panel"
PANEL_UP=0
# The panel's VLESS profile only if Xray runs with it (a rolled-back Reality change keeps the previous config;
# Reality that works with no site is stopped).
if [[ -n "${R_ADMIN_UUID}" ]] && { [[ -z "${R_SITE}" ]] || ! grep -F -- "\"${R_ADMIN_UUID}\"" "${XRAY_DIR}/config.json" >/dev/null 2>&1; }; then
    R_ADMIN_UUID=""
fi
PANEL_SKIPPED=0
if [[ "${PANEL_ENABLE}" != "1" ]]; then
    if systemctl cat veiltrium-panel.service >/dev/null 2>&1; then
        systemctl disable --now veiltrium-panel.service veiltrium-helper.socket >/dev/null 2>&1 || true
        info "The web panel was turned off (PANEL_ENABLE=0)."
        if [[ -s "${PANEL_FILE}" ]]; then panel_file_refresh "${PUBLIC_IP}"; fi   # no VPN profile in it any more
    else
        info "The web panel is off (PANEL_ENABLE=0)."
    fi
elif [[ -z "${SCRIPT_PATH}" || ! -f "${SCRIPT_PATH}" ]]; then
    warn "The web panel needs this script as a file (bash veiltrium.sh); skipped."
else
    case "${ARCH}" in
        amd64) PANEL_SHA="${PANEL_SHA256_AMD64}" ;;
        *) PANEL_SHA="${PANEL_SHA256_ARM64}" ;;
    esac
    PANEL_NEW=""
    if [[ -n "${PANEL_BINARY}" ]]; then
        [[ -f "${PANEL_BINARY}" ]] || die "PANEL_BINARY: no such file: ${PANEL_BINARY}"
        PANEL_NEW="${PANEL_BINARY}"
        warn "Web panel from a local file (PANEL_BINARY), not from a checksum-pinned release."
    elif [[ "${PANEL_SHA}" =~ ^[0-9a-f]{64}$ ]]; then
        # a matching version is not enough: the file itself must be the pinned one
        if [[ "$("${PANEL_BIN}" version 2>/dev/null || true)" != "${PANEL_VERSION#panel-v}" ]] \
            || ! sha_ok "${PANEL_BIN}" "${PANEL_SHA}"; then
            # The VPN is complete at this point: a failed download skips the panel, it does not fail the run.
            if fetch "https://github.com/Vanilla-SilQ-HD/Veiltrium/releases/download/${PANEL_VERSION}/veiltrium-panel-linux-${ARCH}" \
                "${TMPD}/veiltrium-panel"; then
                sha_ok "${TMPD}/veiltrium-panel" "${PANEL_SHA}" || die "web panel checksum mismatch; installation stopped."
                PANEL_NEW="${TMPD}/veiltrium-panel"
            else
                warn "Could not download the web panel (${PANEL_VERSION}) from GitHub: the VPN is not affected;"
                warn "run the script again later to install the panel."
                PANEL_SKIPPED=1
            fi
        fi
    fi
    if [[ -n "${PANEL_NEW}" || -x "${PANEL_BIN}" ]]; then
        if ! id -u veiltrium-panel >/dev/null 2>&1; then
            useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin veiltrium-panel
        fi
        RESTART_PANEL=0
        if [[ -n "${PANEL_NEW}" ]] && ! cmp -s "${PANEL_NEW}" "${PANEL_BIN}"; then
            install -m 755 "${PANEL_NEW}" "${PANEL_BIN}.new" && sync && mv -f "${PANEL_BIN}.new" "${PANEL_BIN}"
            RESTART_PANEL=1
        fi
        # the helper runs the copy of this script that installed the node
        install -d -m 755 "${PANEL_LIB}"
        if ! cmp -s "${SCRIPT_PATH}" "${PANEL_LIB}/veiltrium.sh"; then
            install -m 755 "${SCRIPT_PATH}" "${PANEL_LIB}/veiltrium.sh.new"
            mv -f "${PANEL_LIB}/veiltrium.sh.new" "${PANEL_LIB}/veiltrium.sh"
        fi
        PANEL_UNITS_BEFORE="$(cat /etc/systemd/system/veiltrium-helper.socket /etc/systemd/system/veiltrium-helper@.service \
            /etc/systemd/system/veiltrium-panel.service 2>/dev/null | sha256sum || true)"
        cat > /etc/systemd/system/veiltrium-helper.socket <<EOF
# veiltrium: root helper of the Veiltrium web panel (one request per connection)
[Unit]
Description=Veiltrium panel helper socket

[Socket]
ListenStream=${HELPER_SOCK}
SocketUser=root
SocketGroup=veiltrium-panel
SocketMode=0660
DirectoryMode=0755
Accept=yes
MaxConnections=8

[Install]
WantedBy=sockets.target
EOF
        cat > /etc/systemd/system/veiltrium-helper@.service <<EOF
# veiltrium: root helper of the Veiltrium web panel: runs only the requests it knows
[Unit]
Description=Veiltrium panel helper

[Service]
ExecStart=/bin/bash ${PANEL_LIB}/veiltrium.sh --helper
StandardInput=socket
StandardOutput=socket
StandardError=journal
TimeoutStopSec=6min
EOF
        # Through VLESS Reality the browser names the server's address: the panel accepts that host name too.
        # (Only a panel that knows the option: an older one would not start with it.)
        PANEL_HOST_ARG=""
        if [[ -n "${R_ADMIN_UUID}" && "$("${PANEL_BIN}" 2>&1 || true)" == *"[--host IP]"* ]]; then
            PANEL_HOST_ARG=" --host ${PUBLIC_IP}"
        elif [[ -n "${R_ADMIN_UUID}" ]]; then
            warn "This web panel is too old for the way through the VPN; the SSH tunnel works. Run the script again later."
        fi
        cat > /etc/systemd/system/veiltrium-panel.service <<EOF
# veiltrium: Veiltrium web panel; 127.0.0.1 only, reached through an SSH tunnel or the panel's VLESS profile
[Unit]
Description=Veiltrium web panel
After=network.target veiltrium-helper.socket
Wants=veiltrium-helper.socket

[Service]
User=veiltrium-panel
Group=veiltrium-panel
ExecStart=${PANEL_BIN} serve --listen 127.0.0.1:${PANEL_PORT} --helper ${HELPER_SOCK} --auth ${PANEL_AUTH}${PANEL_HOST_ARG}
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
ProtectClock=true
ProtectHostname=true
ProtectProc=invisible
ProcSubset=pid
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
MemoryDenyWriteExecute=true
RemoveIPC=true
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallFilter=~@privileged @resources
SystemCallErrorNumber=EPERM
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=localhost
UMask=0077
LimitCORE=0
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF
        if [[ "$(cat /etc/systemd/system/veiltrium-helper.socket /etc/systemd/system/veiltrium-helper@.service \
                /etc/systemd/system/veiltrium-panel.service | sha256sum)" != "${PANEL_UNITS_BEFORE}" ]]; then
            systemctl daemon-reload
            RESTART_PANEL=1
        fi
        if [[ ! -s "${PANEL_AUTH}" ]]; then
            panel_new_password "${PUBLIC_IP}"
            CHANGES+=("panel: installed; its password is in ${PANEL_FILE}")
        else
            panel_file_refresh "${PUBLIC_IP}"
        fi
        chown root:veiltrium-panel "${PANEL_ETC}" "${PANEL_AUTH}"
        chmod 750 "${PANEL_ETC}"; chmod 640 "${PANEL_AUTH}"
        systemctl enable --now veiltrium-helper.socket >/dev/null 2>&1 || true
        systemctl enable veiltrium-panel.service >/dev/null 2>&1 || true
        if (( RESTART_PANEL == 1 )) || ! systemctl is-active --quiet veiltrium-panel.service; then
            systemctl restart veiltrium-helper.socket veiltrium-panel.service || true
        fi
        for _ in $(seq 1 20); do
            if [[ -n "$(ss -Htln "sport = :${PANEL_PORT}" 2>/dev/null | grep -F '127.0.0.1' || true)" ]]; then PANEL_UP=1; break; fi
            sleep 0.5
        done
        if (( PANEL_UP == 1 )) && [[ -S "${HELPER_SOCK}" ]]; then
            ok "Web panel $("${PANEL_BIN}" version 2>/dev/null || echo '?') on 127.0.0.1:${PANEL_PORT} (not reachable from outside; SSH tunnel)"
            if [[ -n "${R_ADMIN_UUID}" ]] && panel_vpn_live; then
                panel_vpn_check
                if [[ "${PV_STATUS}" == "ok" ]]; then
                    ok "The panel is also reachable through VLESS Reality with its own profile (in ${PANEL_FILE}; checked)"
                else
                    warn "The panel's VLESS profile did not reach the panel in a check; the SSH tunnel works as before."
                fi
            fi
            SECURITY_SCORE="$(systemd-analyze security veiltrium-panel.service --no-pager 2>/dev/null | tail -1 | grep -oE '[0-9]+\.[0-9]+ [A-Z_]+' || true)"
            if [[ -n "${SECURITY_SCORE}" ]]; then ok "systemd sandbox score for the panel: ${SECURITY_SCORE}"; fi
        else
            PANEL_UP=0
            journalctl -u veiltrium-panel --no-pager -n 15 || true
            warn "The web panel did not start; the VPN is not affected."
        fi
    elif (( PANEL_SKIPPED == 0 )); then
        info "No web panel release is pinned in this version yet; skipped."
    fi
fi

remove_old_names

# ---- Report (no secrets) ------------------------------------------------------
build_report > "${TMPD}/report.json"
install -m 600 "${TMPD}/report.json" "${REPORT_FILE}"

REBOOT_NOTE=""
[[ -f /run/reboot-required ]] && REBOOT_NOTE="yes"

printf '\n\033[1;32m================== DONE ==================\033[0m\n'
# The details go to the terminal only (not into the log). A dropped session is fine:
# everything is in the file.
trap '' PIPE
cat "${CLIENT_FILE}" >&7 2>/dev/null || true
printf '\n(The connection details above are not in the log; they are in %s.)\n' "${CLIENT_FILE}"
if (( PANEL_UP == 1 )) && [[ -s "${PANEL_FILE}" ]]; then
    printf '\n----------------------------------------------------------------------\n' >&7 2>/dev/null || true
    cat "${PANEL_FILE}" >&7 2>/dev/null || true
    printf '(The panel password is not in the log; it is in %s.)\n' "${PANEL_FILE}"
fi
printf '\n\033[1mTLS identities and proof:\033[0m\n'
if [[ -n "${R_SITE}" ]]; then
    info "VLESS Reality: SNI ${R_SITE}; server check: ${REALITY_VPS}; home network: $(mts_status reality "${R_SITE}")"
    if [[ -n "${R_DECISION}" ]]; then info "  ${R_DECISION}"; fi
fi
info "Hysteria 2: SNI ${HY2_SNI}, own self-signed certificate (pinned); server check: ${HY2_VPS}; home network: $(mts_status hysteria2 "${HY2_SNI}")"
info "  masquerade (HTTP/3 page for probers): ${HY2_MASQ_URL}"
if [[ "${TT_ENABLE}" == "1" ]]; then
    info "TrustTunnel: hostname ${T_SNI}, own self-signed certificate (in the link); server check: HTTP/2 ${TT_VPS_H2}, HTTP/3 ${TT_VPS_H3}"
fi
if (( IMPORTED == 1 )); then
    printf '\n\033[1mImported from the node at %s:\033[0m\n' "${IMPORT_OLD_IP}"
    info "same keys, passwords, UUIDs, certificates and server names: every link differs from the old one only by the"
    info "server address (${IMPORT_OLD_IP} -> ${PUBLIC_IP}); the name in the apps may differ if the country differs."
    info "The web panel password is new (the old one is not part of an export)."
fi
if (( ${#CHANGES[@]} )); then
    printf '\n\033[1mChanged in this run:\033[0m\n'
    for c in "${CHANGES[@]}"; do info "${c}"; done
fi
if (( ${#LINKS_CHANGED[@]} )); then
    printf '\n\033[33mUpdate on the clients:\033[0m\n'
    for c in "${LINKS_CHANGED[@]}"; do info "${c}"; done
fi
if (( ${#ROLLBACKS[@]} )); then
    printf '\n\033[33mRolled back:\033[0m\n'
    for c in "${ROLLBACKS[@]}"; do info "${c}"; done
    alert_notify rollback "an install run rolled back: $(printf '%s; ' "${ROLLBACKS[@]}")"
fi
info "Report without secrets: ${REPORT_FILE}"
printf '\n\033[1mServer protection:\033[0m\n'
info "firewall: open from outside only ${OPEN_PORTS}"
if [[ "${SCANNER_BLOCK}" == "1" ]]; then
    info "known scanner networks (Russian state and affiliated) see only SSH; list refreshed weekly"
fi
SSH_NOTE="attempt limits"
if (( HAVE_PSP == 1 )); then SSH_NOTE+=", PerSourcePenalties"; fi
if (( HAVE_FAIL2BAN == 1 )); then SSH_NOTE+=", fail2ban"; fi
info "SSH: password login kept; ${SSH_NOTE}"
info "Hysteria, Xray and TrustTunnel: separate users, systemd sandbox, no access to the server itself or private networks"
info "security updates install automatically; install log: ${LOG_FILE}"
info "everything above is saved in ${CLIENT_FILE} (root only)"
info "short command on this server: veiltrium help   (veiltrium qr main: QR codes of the links)"
info "Tip: since SSH password login stays on, make the password long: 16+ characters."
if (( CHECK_FAIL != 0 )); then
    printf '\n\033[1;33m! Some checks failed; send the output above.\033[0m\n'
    if [[ -n "${REBOOT_NOTE}" ]]; then info "Updates require a reboot: once this is sorted out, reboot the server (reboot)."; fi
    exit 2
fi
if [[ -n "${REBOOT_NOTE}" && "${VT_AUTO_REBOOT}" == "1" && "${NODE_EXISTED}" == "0" ]]; then
    shutdown -r +1 "Veiltrium: reboot after updates" >/dev/null 2>&1 || true
    printf '\n\033[33m! Updates require a reboot: the server will reboot in 1 minute, the services will start on their own.\033[0m\n'
    info "To cancel: shutdown -c   (then the reboot happens at night at ${AUTO_REBOOT_TIME})"
elif [[ -n "${REBOOT_NOTE}" ]]; then
    # a working node: no reboot in the middle of the day (clients would drop)
    printf '\n\033[33m! Updates require a reboot: reboot the server (reboot) or it will do so at night at %s.\033[0m\n' "${AUTO_REBOOT_TIME}"
fi
exit 0
# ==== VEILTRIUM END ====
