#!/usr/bin/env bash
# =============================================================================
#  Veiltrium - Secure Multi-Protocol VPN Deployment
#  https://github.com/Vanilla-SilQ-HD/Veiltrium
#
#  hy2-secure-install.sh: self-contained, hardened installer for Hysteria 2,
#  VLESS Reality (Xray) and TrustTunnel on a fresh Ubuntu 26.04 server. No
#  third-party panels or install scripts: only the official release binaries,
#  SHA-256 pinned.
#
#  The file name, paths, service names, variables and state files keep their
#  original "hy2-secure-install" / "hy2" names on purpose: servers installed by
#  earlier versions update in place, and existing commands keep working.
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
#  HY2_RECONFIGURE=1 is given.
#
#  Re-running is safe: passwords, keys, certificates and the chosen sites are
#  kept. Settings given as variables (HY2_SNI, TT_SNI, HY2_MASQUERADE_URL,
#  REALITY_CANDIDATES) are saved and stay in effect on later runs.
#
#  Modes:
#    bash hy2-secure-install.sh                     install / update / repair
#    bash hy2-secure-install.sh --reselect-reality  re-evaluate the Reality site
#                                                   (only the VLESS sni changes)
#    bash hy2-secure-install.sh --dry-run           what --reselect-reality would do; no changes
#    bash hy2-secure-install.sh --diagnose          check the node; no changes
#    bash hy2-secure-install.sh --import-mts FILE   import keenetic-vpn-probe.sh results
#    bash hy2-secure-install.sh --trial-reality SITE[,SITE]   temporary extra Reality
#                                                   names for a probe from home; auto-revert
#    bash hy2-secure-install.sh --add-client NAME   a new client: own credentials for all protocols
#    bash hy2-secure-install.sh --remove-client NAME   revoke a client
#    bash hy2-secure-install.sh --list-clients      the clients of this node
#    bash hy2-secure-install.sh --show-client NAME  connection details of a client (main: the first one)
#    bash hy2-secure-install.sh --status --json -   a fast overview as JSON (no tests, no secrets)
#    bash hy2-secure-install.sh --help
#
#  To regenerate everything:  HY2_RECONFIGURE=1 bash hy2-secure-install.sh
#  Without VLESS Reality:     REALITY_ENABLE=0 bash hy2-secure-install.sh
# =============================================================================
if [ -z "${BASH_VERSION:-}" ]; then
    echo "Run it with bash:  bash $0"
    exit 1
fi
set -Eeuo pipefail
umask 022

SCRIPT_VERSION="2026-10-13.1"

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
REALITY_ENABLE="${REALITY_ENABLE:-1}"          # 0: no VLESS Reality
REALITY_PORT_GIVEN="${REALITY_PORT:+1}"       # given explicitly: change the port; else keep the node's
REALITY_PORT="${REALITY_PORT:-443}"
REALITY_FP="${REALITY_FP:-chrome}"             # TLS client fingerprint (uTLS)
TT_ENABLE="${TT_ENABLE:-1}"                    # 0: no TrustTunnel
TT_PORT_GIVEN="${TT_PORT:+1}"
TT_PORT="${TT_PORT:-8443}"                     # TrustTunnel listens on TCP and UDP on this port
PUBLIC_IP="${PUBLIC_IP:-}"                     # empty: detected automatically
# Node name in client apps: "Veiltrium-<NODE_NAME>". Saved; empty on a new node: the
# server's country code (e.g. PL); "auto": detect again; "none": just "Veiltrium".
NODE_NAME="${NODE_NAME:-}"
SCANNER_BLOCK="${SCANNER_BLOCK:-1}"            # 1: proxy ports stay silent for known scanner networks
HY2_RECONFIGURE="${HY2_RECONFIGURE:-0}"        # 1: new passwords, keys and certificates
HY2_AUTO_REBOOT="${HY2_AUTO_REBOOT:-1}"        # 1: a NEW node reboots in a minute if updates require it
AUTO_REBOOT_TIME="${AUTO_REBOOT_TIME:-01:30}"
MTS_MAX_AGE_DAYS="${MTS_MAX_AGE_DAYS:-14}"     # older home-network probe results are ignored
TRIAL_MINUTES="${TRIAL_MINUTES:-30}"

LOG_FILE="/var/log/hy2-secure-install.log"
CLIENT_FILE="/root/hy2-client.txt"
PROBE_PROFILE="/root/hy2-probe.env"
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
SCANNER_DIR="/etc/hy2-secure"
SCANNER_FILE="${SCANNER_DIR}/scanners.nft"
SCANNER_BIN="/usr/local/sbin/hy2-scanner-block"
CANDIDATES_FILE="${SCANNER_DIR}/reality-candidates"
PROBE_ENV="${SCANNER_DIR}/probe.env"           # key that authenticates home-network probe results
NODE_ENV="${SCANNER_DIR}/node.env"             # N_NAME: the saved node name
CLIENTS_DIR="${SCANNER_DIR}/clients"           # added clients: <name>.env with their credentials
CLIENT_FILES_DIR="/root/hy2-clients"           # their connection details: <name>.txt
STATE_DIR="/var/lib/hy2-secure"
REPORT_FILE="${STATE_DIR}/report.json"
SELECTION_FILE="${STATE_DIR}/reality-selection.json"
MTS_RECORDS="${STATE_DIR}/mts-records"
MTS_LAST_IMPORT="${STATE_DIR}/mts-last-import.json"
MTS_RUNS="${STATE_DIR}/mts-runs"
TXN_DIR="${STATE_DIR}/txn"                     # backups of changes in progress (see txn_begin)
RECOVER_BIN="/usr/local/sbin/hy2-secure-recover"
WATCHDOG_UNIT="hy2-secure-watchdog"
RUN_DIR="/run/hy2-secure"
TRIAL_CONFIG="${RUN_DIR}/xray-trial.json"
TRIAL_ENV="${RUN_DIR}/trial.env"
TRIAL_END="${RUN_DIR}/trial-end.sh"
TRIAL_DROPIN_DIR="/run/systemd/system/xray.service.d"
TRIAL_DROPIN="${TRIAL_DROPIN_DIR}/50-hy2-trial.conf"
TRIAL_UNIT="hy2-reality-trial-end"
TOTAL_STEPS=12

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
    exit 1
}

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
H_AUTH=""; HY2_AUTH_MAIN=""
N_NAME=""; LABEL="Veiltrium"

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
    H_PASSWORD=""; H_SNI=""; H_PORT=""; H_MASQ=""; H_AUTH=""
    [[ "${HY2_RECONFIGURE}" != "1" ]] || return 0
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
        damaged=""; H_PASSWORD=""; H_SNI=""; H_PORT=""; H_MASQ=""; H_AUTH=""   # a first install that never finished: start over
    fi
    if [[ -n "${damaged}" ]]; then
        die "the Hysteria node is damaged (${damaged}); nothing was changed. New password and certificate (clients must be updated): HY2_RECONFIGURE=1 bash $0"
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
    mv -f "${HY2_STATE}.new" "${HY2_STATE}"
}

# Hysteria server config ($1 = file) from H_AUTH, H_PASSWORD, the clients, HY2_PORT and
# HY2_MASQ_URL. With one shared password the text is exactly what earlier versions wrote.
hy2_server_yaml() {
    local auth i
    if [[ "${H_AUTH}" == "userpass" ]]; then
        auth="  type: userpass"$'\n'"  userpass:"$'\n'"    main: $(yaml_sq "${H_PASSWORD}")"
        for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
            auth+=$'\n'"    $(yaml_sq "${CL_NAMES[i]}"): $(yaml_sq "${CL_HPASS[i]}")"
        done
    else
        auth="  type: password"$'\n'"  password: $(yaml_sq "${H_PASSWORD}")"
    fi
    cat > "$1" <<EOF
# hy2-secure-install: Hysteria 2 server
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
}

# hysteria2:// share link. $1 = user ("" with one shared password), $2 = password.
# A user is written as user:password, as the Hysteria URI scheme defines it.
hy2_link() {
    local auth
    auth="$(url_encode "$2")"
    if [[ -n "$1" ]]; then auth="$(url_encode "$1"):${auth}"; fi
    printf 'hysteria2://%s@%s:%s/?sni=%s&insecure=1&pinSHA256=%s&pcs=%s#%s' "${auth}" "${HOST}" "${HY2_PORT}" \
        "$(url_encode "${HY2_SNI}")" "${CERT_SHA}" "${CERT_SHA}" "$(url_encode "${LABEL}")"
}

# ---- Node name and added clients ----------------------------------------------
NAME_RE='^[A-Za-z0-9]([A-Za-z0-9-]{0,14}[A-Za-z0-9])?$'
CLIENT_RE='^[a-z0-9][a-z0-9_-]{0,31}$'

# The saved node name. Sets N_NAME (may be empty), N_SAVED (1: a choice was saved) and LABEL.
load_node_name() {
    N_NAME=""; N_SAVED=0
    if [[ -s "${NODE_ENV}" ]]; then
        # shellcheck disable=SC1090
        source "${NODE_ENV}"
        N_SAVED=1
    fi
    [[ -z "${N_NAME}" || "${N_NAME}" =~ ${NAME_RE} ]] || N_NAME=""
    LABEL="Veiltrium${N_NAME:+-${N_NAME}}"
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

save_node_name() {
    install -d -m 700 "${SCANNER_DIR}"
    install -m 600 /dev/null "${NODE_ENV}.new"
    printf '# hy2-secure-install: node name in client apps (Veiltrium-<N_NAME>)\nN_NAME=%q\n' "${N_NAME}" > "${NODE_ENV}.new"
    mv -f "${NODE_ENV}.new" "${NODE_ENV}"
    LABEL="Veiltrium${N_NAME:+-${N_NAME}}"
}

# Added clients, sorted by name (C locale: the configs are the same text on every run).
# Sets CL_NAMES, CL_UUID, CL_HPASS, CL_TPASS, CL_CREATED. A damaged file stops the run.
load_clients() {
    local f C_NAME C_UUID C_HY2_PASS C_TT_PASS C_CREATED
    CL_NAMES=(); CL_UUID=(); CL_HPASS=(); CL_TPASS=(); CL_CREATED=()
    [[ -d "${CLIENTS_DIR}" ]] || return 0
    while IFS= read -r f; do
        [[ -f "${f}" ]] || continue
        C_NAME=""; C_UUID=""; C_HY2_PASS=""; C_TT_PASS=""; C_CREATED=""
        # shellcheck disable=SC1090
        source "${f}"
        if [[ "${C_NAME}.env" != "${f##*/}" || ! "${C_NAME}" =~ ${CLIENT_RE} || "${C_NAME}" == "main" || \
              ! "${C_UUID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ || \
              ! "${C_HY2_PASS}" =~ ^[0-9a-f]{48}$ || ! "${C_TT_PASS}" =~ ^[0-9a-f]{48}$ ]]; then
            die "the client file ${f} is damaged; nothing was changed. Fix or delete it, then run again."
        fi
        CL_NAMES+=("${C_NAME}"); CL_UUID+=("${C_UUID}"); CL_HPASS+=("${C_HY2_PASS}")
        CL_TPASS+=("${C_TT_PASS}"); CL_CREATED+=("${C_CREATED:-?}")
    done < <(printf '%s\n' "${CLIENTS_DIR}"/*.env | LC_ALL=C sort)
    return 0
}

write_client_env() {   # $1 = file, then name, UUID, Hysteria password, TrustTunnel password, created
    install -m 600 /dev/null "$1.new"
    printf 'C_NAME=%q\nC_UUID=%q\nC_HY2_PASS=%q\nC_TT_PASS=%q\nC_CREATED=%q\n' "$2" "$3" "$4" "$5" "$6" > "$1.new"
    mv -f "$1.new" "$1"
}

# HY2_RECONFIGURE=1: the added clients get new secrets too (names and dates stay).
renew_client_secrets() {
    local i
    for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
        write_client_env "${CLIENTS_DIR}/${CL_NAMES[i]}.env" "${CL_NAMES[i]}" "$(cat /proc/sys/kernel/random/uuid)" \
            "$(openssl rand -hex 24)" "$(openssl rand -hex 24)" "${CL_CREATED[i]}"
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
            printf '\n[[client]]\nusername = "%s"\npassword = "%s"\n' "${CL_NAMES[i]}" "${CL_TPASS[i]}"
        done
    } > "$1"
}

# tt:// link of TrustTunnel user $1, built by the endpoint itself (the certificate is
# embedded). Prints nothing if the export failed (the reason is in ${TMPD}/tt-link.err).
tt_export_link() {
    "${TT_BIN}" "${TT_DIR}/vpn.toml" "${TT_DIR}/hosts.toml" -c "$1" -a "${PUBLIC_IP}:${TT_PORT}" \
        --name "${LABEL}" > "${TMPD}/tt-link.txt" 2>"${TMPD}/tt-link.err" || true
    grep -m1 -oE 'tt://[^[:space:]]+' "${TMPD}/tt-link.txt" || true
    rm -f "${TMPD}/tt-link.txt"
    return 0
}

# Reality keys and site from a previous run. Sets R_UUID, R_PRIV, R_PUB, R_SID, R_SITE.
load_reality_state() {
    R_UUID=""; R_PRIV=""; R_PUB=""; R_SID=""; R_SITE=""
    if [[ "${HY2_RECONFIGURE}" != "1" && -s "${XRAY_STATE}" ]]; then
        # shellcheck disable=SC1090
        source "${XRAY_STATE}"
    fi
    if [[ ! "${R_UUID}" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ || \
          ! "${R_PRIV}" =~ ^[A-Za-z0-9_-]{43}$ || ! "${R_PUB}" =~ ^[A-Za-z0-9_-]{43}$ || \
          ! "${R_SID}" =~ ^[0-9a-f]{16}$ ]]; then
        if [[ "${HY2_RECONFIGURE}" != "1" && -s "${XRAY_STATE}" && -e "${CLIENT_FILE}" ]]; then
            die "${XRAY_STATE} is damaged; nothing was changed. New keys (clients must be updated): HY2_RECONFIGURE=1 bash $0"
        fi
        R_UUID=""; R_PRIV=""; R_PUB=""; R_SID=""; R_SITE=""
    fi
    [[ -z "${R_SITE}" || "${R_SITE}" =~ ${DOMAIN_RE} ]] || R_SITE=""
    return 0
}

load_tt_state() {
    T_USER=""; T_PASS=""; T_SNI=""; T_IPV6=""
    if [[ "${HY2_RECONFIGURE}" != "1" && -e "${TT_STATE}" ]]; then
        # shellcheck disable=SC1090
        source "${TT_STATE}"
        if [[ -z "${T_USER}" || -z "${T_PASS}" || ! -s "${TT_DIR}/cert.pem" || ! -s "${TT_DIR}/key.pem" ]] || \
           [[ "$(openssl x509 -in "${TT_DIR}/cert.pem" -noout -pubkey 2>/dev/null)" != "$(openssl pkey -in "${TT_DIR}/key.pem" -pubout 2>/dev/null)" ]]; then
            if [[ -e "${CLIENT_FILE}" ]]; then
                die "the TrustTunnel endpoint is damaged (${TT_STATE}, cert.pem/key.pem); nothing was changed. New credentials: HY2_RECONFIGURE=1 bash $0"
            fi
            T_USER=""; T_PASS=""; T_SNI=""; T_IPV6=""   # a first install that never finished: start over
        fi
    fi
    [[ -z "${T_SNI}" || "${T_SNI}" =~ ${DOMAIN_RE} ]] || T_SNI=""
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
        printf '# hy2-secure-install: Reality mask site candidates (REALITY_CANDIDATES), one per line\n%s\n' \
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
    local out="$1" listen="$2" port="$3" site="$4" names n listen_line="" clients i
    shift 4
    names="\"${site}\""
    for n in "$@"; do names+=", \"${n}\""; done
    if [[ -n "${listen}" ]]; then listen_line="    \"listen\": \"${listen}\","$'\n'; fi
    # the main client first (as earlier versions wrote it), then the added ones by name
    clients="{\"id\": \"${R_UUID}\", \"flow\": \"xtls-rprx-vision\"}"
    for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
        clients+=", {\"id\": \"${CL_UUID[i]}\", \"flow\": \"xtls-rprx-vision\", \"email\": \"${CL_NAMES[i]}\"}"
    done
    cat > "${out}" <<EOF
{
  "log": {"loglevel": "warning"},
  "inbounds": [{
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
  "outbounds": [{"protocol": "freedom", "tag": "direct"}]
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
        fail|degraded) c=$(( c + 600 )) ;;
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
#   - power loss, reboot: hy2-secure-recover.service, before the proxies start;
#   - and the next installer run, as a last resort.
RECOVER_SCRIPT='#!/usr/bin/env bash
# hy2-secure-install: puts back the files of a change that did not finish.
#   --boot      at boot, before the proxy services start
#   --watchdog  from a timer while a change is pending (only if the installer is gone)
#   --now       from the installer itself
# A second argument limits it to one change (reality, hysteria, trusttunnel).
set -u
D=/var/lib/hy2-secure/txn
mode="${1:---watchdog}"; only="${2:-}"
if [[ "${mode}" == --watchdog ]]; then
    exec 9>/run/hy2-secure-install.lock
    flock -n 9 || exit 0
    tries=$(( $(cat "${D}/.tries" 2>/dev/null || echo 0) + 1 ))
    echo "${tries}" > "${D}/.tries"
    if (( tries > 20 )); then
        echo "hy2-secure-recover: giving up after 20 attempts; the boot service or the next installer run retries" >&2
        systemctl stop hy2-secure-watchdog.timer >/dev/null 2>&1
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
            if cp -p "${t}/f${n}" "${path}.hy2-restore" && cmp -s "${t}/f${n}" "${path}.hy2-restore"; then
                mv -f "${path}.hy2-restore" "${path}" || failed=1
            else
                rm -f "${path}.hy2-restore"; failed=1
            fi
        else
            rm -f "${path}" || failed=1
        fi
    done < "${t}/files"
    sync
    if (( failed )); then
        echo "hy2-secure-recover: could not restore all ${name} files (disk full?); will retry" >&2
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
    logger -t hy2-secure-recover "restored the previous ${name} settings after an interrupted change" 2>/dev/null
    echo "hy2-secure-recover: restored the previous ${name} settings"
done
if [[ "${mode}" != --boot ]] && ! compgen -G "${D}/*/pending" >/dev/null; then
    systemctl stop hy2-secure-watchdog.timer >/dev/null 2>&1
    rm -f "${D}/.tries"
fi
# temp dirs of a killed installer run (client configs with keys); none is running now
if [[ "${mode}" != --now ]]; then rm -rf /root/.hy2-install.* 2>/dev/null; fi
exit 0
'

install_recover() {
    printf '%s' "${RECOVER_SCRIPT}" > "${RECOVER_BIN}.new"
    chmod 700 "${RECOVER_BIN}.new"
    mv -f "${RECOVER_BIN}.new" "${RECOVER_BIN}"
    cat > /etc/systemd/system/hy2-secure-recover.service.new <<EOF
# hy2-secure-install: restore the settings of a change interrupted by a reboot or power loss
[Unit]
Description=Restore settings of an interrupted hy2-secure-install change
After=local-fs.target
Before=hysteria-server.service xray.service trusttunnel.service
ConditionPathExistsGlob=${TXN_DIR}/*/pending

[Service]
Type=oneshot
ExecStart=${RECOVER_BIN} --boot

[Install]
WantedBy=multi-user.target
EOF
    if ! cmp -s /etc/systemd/system/hy2-secure-recover.service.new /etc/systemd/system/hy2-secure-recover.service 2>/dev/null; then
        mv -f /etc/systemd/system/hy2-secure-recover.service.new /etc/systemd/system/hy2-secure-recover.service
        systemctl daemon-reload
    else
        rm -f /etc/systemd/system/hy2-secure-recover.service.new
    fi
    systemctl enable hy2-secure-recover.service >/dev/null 2>&1 || true
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
            --timer-property=AccuracySec=5s --description="hy2-secure-install: restore an interrupted change" \
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

# $1 = test, $2 = SNI -> ok|fail|degraded|route_unverified|stale|untested
# The newest result counts ("skipped" is no result); on the same time the worse one wins.
mts_status() {
    local line ts route status now
    if [[ ! -s "${MTS_RECORDS}" ]]; then printf 'untested'; return 0; fi
    line="$(awk -F'|' -v t="$1" -v s="$2" '
        $1 == "v2" && ($6 == t || (t == "reality" && $6 == "reality_trial")) && $7 == s && $10 != "skipped" {
            rank = ($10 == "ok" ? 0 : ($10 == "degraded" ? 1 : 2)) + ($9 == "verified" ? 0 : 3)
            print $2, rank, $9, $10 }' "${MTS_RECORDS}" | sort -k1,1n -k2,2n | tail -n 1 || true)"
    if [[ -z "${line}" ]]; then printf 'untested'; return 0; fi
    read -r ts _ route status <<<"${line}"
    now="$(date +%s)"
    if (( now - 10#${ts} > MTS_MAX_AGE_DAYS * 86400 )); then printf 'stale'
    elif [[ "${route}" != "verified" ]]; then printf 'route_unverified'
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
    jq -e '.schema == "hy2-vpn-probe/1"' "${TMPD}/mts.json" >/dev/null 2>&1 \
        || die "not a keenetic-vpn-probe.sh result (schema hy2-vpn-probe/1 expected)."
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
# hy2-secure-install: end of a Reality trial
rm -f "${TRIAL_DROPIN}" "${TRIAL_CONFIG}" "${TRIAL_ENV}"
systemctl daemon-reload
systemctl restart xray.service
EOF
    chmod 700 "${TRIAL_END}"
    # The end is scheduled first: if this run is killed at any later point, the timer still
    # ends the trial (and a reboot ends it too: everything lives in /run).
    systemctl reset-failed "${TRIAL_UNIT}.timer" "${TRIAL_UNIT}.service" >/dev/null 2>&1 || true
    if ! systemd-run --quiet --unit="${TRIAL_UNIT}" --on-active="${TRIAL_MINUTES}m"             --timer-property=AccuracySec=10s --description="End of the hy2-secure-install Reality trial"             /bin/sh "${TRIAL_END}"; then
        rm -f "${TRIAL_CONFIG}"
        die "could not schedule the end of the trial; nothing was changed."
    fi
    install -d -m 755 "${TRIAL_DROPIN_DIR}"
    printf '# hy2-secure-install: Reality trial (ends by itself)
[Service]
ExecStart=
ExecStart=%s run -c %s
'         "${XRAY_BIN}" "${TRIAL_CONFIG}" > "${TRIAL_DROPIN}.new"
    mv -f "${TRIAL_DROPIN}.new" "${TRIAL_DROPIN}"
    systemctl daemon-reload
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
            [[ " $* " == *" ${s} "* ]] || { printf '%s' "${s}"; return 0; }
        done
    fi
    for s in "${CAND_LIST[@]}"; do
        [[ " $* " == *" ${s} "* ]] && continue
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

# ---- Report (no secrets) ----------------------------------------------------
# Writes the report JSON to stdout from the global R_*/H_*/T_* results.
build_report() {
    local sel='null'
    if [[ -s "${TMPD}/selection.json" ]]; then sel="$(cat "${TMPD}/selection.json")"
    elif [[ -s "${SELECTION_FILE}" ]]; then sel="$(cat "${SELECTION_FILE}")"; fi
    jq -n --arg now "$(date -u +%FT%TZ)" --arg version "${SCRIPT_VERSION}" --arg mode "${MODE}" \
        --arg server "${PUBLIC_IP:-}" --arg label "${LABEL}" --arg n_clients "${#CL_NAMES[@]}" \
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
        --argjson selection "${sel}" '
        def lines: split("\n") | map(select(length > 0));
        def proof($vps; $mts): {vps_verified: ($vps == "verified" or $vps == "ok"), vps: $vps,
            mts_verified: ($mts == "ok"), mts: $mts};
        {
          schema: "hy2-secure-install-report/1", generated_at: $now, script_version: $version, mode: $mode,
          server: $server, node_name: $label,
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

vless_link() {   # $1 = UUID
    printf 'vless://%s@%s:%s?encryption=none&flow=xtls-rprx-vision&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=tcp#%s' \
        "$1" "${HOST}" "${REALITY_PORT}" "${R_SITE}" "${REALITY_FP}" "${R_PUB}" "${R_SID}" "$(url_encode "${LABEL}")"
}

# Globals: HOST, HY2_PORT, HY2_SNI, CERT_SHA, PK_SHA, H_AUTH, H_PASSWORD, R_* (R_SITE
# empty: no Reality), REALITY_PORT, REALITY_FP, T_SNI, TT_PORT, LABEL, the clients.
# $1 = client ("main" or an added one), $2 = its tt:// link ("" = none), $3 = its file.
client_details() {
    local name="$1" tt="$2" file="$3" hy_user hy_pass uuid auth jauth reality_text="" tt_text="" foot
    client_creds "${name}"
    hy_user="${CC_USER}"; hy_pass="${CC_PASS}"; uuid="${CC_UUID}"; auth="${CC_AUTH}"
    jauth="$(json_escape "${auth}")"
    if [[ -n "${R_SITE}" ]]; then   # also when the previous settings were restored: the link stays in the file
        reality_text="$(cat <<EOF

----------------------------------------------------------------------
VLESS Reality: backup protocol (TCP), masked as ${R_SITE}
Port: ${REALITY_PORT}/TCP. A prober without the key sees the real site ${R_SITE}.
If the site ever changes (--reselect-reality), only sni / server_name changes.

3) VLESS Reality link (v2rayN, Hiddify, NekoBox, v2rayNG, sing-box, AWG Manager):
$(vless_link "${uuid}")

4) VLESS Reality outbound for sing-box (router):
{
  "type": "vless",
  "tag": "reality",
  "server": "${HOST}",
  "server_port": ${REALITY_PORT},
  "uuid": "${uuid}",
  "flow": "xtls-rprx-vision",
  "tls": {
    "enabled": true,
    "server_name": "${R_SITE}",
    "utls": {"enabled": true, "fingerprint": "${REALITY_FP}"},
    "reality": {"enabled": true, "public_key": "${R_PUB}", "short_id": "${R_SID}"}
  }
}
EOF
)"
    fi
    if [[ -n "${tt}" ]]; then
        tt_text="$(cat <<EOF

----------------------------------------------------------------------
TrustTunnel: port ${TT_PORT}/TCP+UDP, hostname ${T_SNI} (self-signed certificate,
embedded in the link; the client checks the server against it)

5) TrustTunnel link (TrustTunnel apps, AWG Manager on the router: HTTP/2 only there):
${tt}
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
  bash hy2-secure-install.sh --diagnose     check everything, change nothing
  bash hy2-secure-install.sh --dry-run      would another Reality site be better?
  bash hy2-secure-install.sh --add-client NAME   credentials for one more person or device
  Re-run the script to update or repair the server; the links stay the same.
  HY2_RECONFIGURE=1 issues new passwords, keys and certificates (clients must be updated).
Home-network test from the router: ${PROBE_PROFILE} (secret) + keenetic-vpn-probe.sh
EOF
)"
    else
        foot="Revoke this client on the server:  bash hy2-secure-install.sh --remove-client ${name}"
    fi
    cat <<EOF
Veiltrium connection details: node ${LABEL}, client ${name} ($(date '+%Y-%m-%d %H:%M %Z'))
Keep this secret: the links and configs contain passwords and keys.

Server:   ${HOST}
Port:     ${HY2_PORT}/UDP
Password: ${auth}
SNI:      ${HY2_SNI}  (self-signed certificate, the client checks its fingerprint)
Certificate fingerprint (SHA-256):  ${CERT_SHA}
Public key fingerprint (sing-box, base64):  ${PK_SHA}

1) Hysteria 2 link for phone and PC (v2rayN, Hiddify, NekoBox, sing-box):
$(hy2_link "${hy_user}" "${hy_pass}")
   AWG Manager (Keenetic) ignores pinSHA256 in this link and then connects
   WITHOUT checking the certificate. On the router use section 6 instead.

2) Outbound for sing-box (router). No speed is set: sing-box adapts
   by itself (BBR), which is more reliable than a fixed speed.
{
  "type": "hysteria2",
  "tag": "hy2",
  "server": "${HOST}",
  "server_port": ${HY2_PORT},
  "password": "${jauth}",
  "tls": {
    "enabled": true,
    "server_name": "${HY2_SNI}",
    "insecure": false,
    "certificate_public_key_sha256": ["${PK_SHA}"]
  }
}
${reality_text}
${tt_text}

----------------------------------------------------------------------
6) AWG Manager: add Hysteria with key pinning as a server group
   (server group -> sing-box JSON), paste this whole block:
[
  {
    "type": "hysteria2",
    "tag": "Veiltrium",
    "server": "${HOST}",
    "server_port": ${HY2_PORT},
    "password": "${jauth}",
    "tls": {
      "enabled": true,
      "server_name": "${HY2_SNI}",
      "certificate_public_key_sha256": ["${PK_SHA}"]
    }
  }
]
   Then check on the router: sh keenetic-vpn-probe.sh --check-awg

----------------------------------------------------------------------
Copy links without any chat app or Markdown in between (it breaks & and _):
  ssh root@${HOST} "grep -m1 '^vless://' ${file}" | Set-Clipboard     (PowerShell)

${foot}
EOF
}

# Rewrites the details of every client (main: ${CLIENT_FILE}; the others in
# ${CLIENT_FILES_DIR}) and removes the files of clients that no longer exist.
# TT_URL = the main client's tt:// link ("" = no TrustTunnel).
write_client_files() {
    local i f n tt
    install -m 600 /dev/null "${CLIENT_FILE}.new"
    client_details main "${TT_URL}" "${CLIENT_FILE}" > "${CLIENT_FILE}.new"
    mv -f "${CLIENT_FILE}.new" "${CLIENT_FILE}"
    if (( ${#CL_NAMES[@]} )); then install -d -m 700 "${CLIENT_FILES_DIR}"; fi
    for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
        tt=""
        f="${CLIENT_FILES_DIR}/${CL_NAMES[i]}.txt"
        if [[ -n "${TT_URL}" ]]; then
            tt="$(tt_export_link "${CL_NAMES[i]}")"
            if [[ -z "${tt}" ]]; then tt="$(grep -m1 '^tt://' "${f}" 2>/dev/null || true)"; fi
        fi
        install -m 600 /dev/null "${f}.new"
        client_details "${CL_NAMES[i]}" "${tt}" "${f}" > "${f}.new"
        mv -f "${f}.new" "${f}"
    done
    for f in "${CLIENT_FILES_DIR}"/*.txt; do
        [[ -f "${f}" ]] || continue
        n="${f##*/}"; n="${n%.txt}"
        if [[ -z "$(client_index "${n}")" ]]; then rm -f "${f}"; fi
    done
    return 0
}

# Probe profile of the main client for keenetic-vpn-probe.sh (secret, 0600).
write_probe_profile() {
    install -m 600 /dev/null "${PROBE_PROFILE}.new"
    {
        printf '# hy2-secure-install probe profile for keenetic-vpn-probe.sh. SECRET: keep it 0600.\n'
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

# Connection details of client $1 as JSON; secrets included (root and the panel only).
# $2 = its tt:// link ("" = none).
client_json() {
    local vless=""
    client_creds "$1"
    if [[ -n "${R_SITE}" ]]; then vless="$(vless_link "${CC_UUID}")"; fi
    jq -n --arg name "$1" --arg created "${CC_CREATED}" --arg label "${LABEL}" --arg server "${HOST}" \
        --arg hy_link "$(hy2_link "${CC_USER}" "${CC_PASS}")" --arg auth "${CC_AUTH}" --arg hy_sni "${HY2_SNI}" \
        --argjson hy_port "${HY2_PORT}" --arg pk "${PK_SHA}" --arg cert "${CERT_SHA}" \
        --arg vless "${vless}" --arg uuid "${CC_UUID}" --arg r_site "${R_SITE}" --argjson r_port "${REALITY_PORT}" \
        --arg fp "${REALITY_FP}" --arg pbk "${R_PUB}" --arg sid "${R_SID}" --arg tt "$2" '
        {schema: "veiltrium-client/1", name: $name, main: ($name == "main"),
         created: (if $created == "" then null else $created end), node_name: $label, server: $server,
         hysteria2: {link: $hy_link, auth: $auth, sni: $hy_sni, port: $hy_port, pin_sha256: $cert,
           outbound: {type: "hysteria2", tag: "hy2", server: $server, server_port: $hy_port, password: $auth,
             tls: {enabled: true, server_name: $hy_sni, insecure: false, certificate_public_key_sha256: [$pk]}},
           awg_group: [{type: "hysteria2", tag: "Veiltrium", server: $server, server_port: $hy_port, password: $auth,
             tls: {enabled: true, server_name: $hy_sni, certificate_public_key_sha256: [$pk]}}]},
         vless: (if $vless == "" then null else {link: $vless, sni: $r_site, port: $r_port,
           outbound: {type: "vless", tag: "reality", server: $server, server_port: $r_port, uuid: $uuid,
             flow: "xtls-rprx-vision", tls: {enabled: true, server_name: $r_site,
               utls: {enabled: true, fingerprint: $fp},
               reality: {enabled: true, public_key: $pbk, short_id: $sid}}}} end),
         trusttunnel: (if $tt == "" then null else {link: $tt} end)}'
}

# The clients of the node as JSON (no secrets).
clients_json() {
    local i
    {
        printf 'main\t\n'
        for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do printf '%s\t%s\n' "${CL_NAMES[i]}" "${CL_CREATED[i]}"; done
    } | jq -R -s --arg label "${LABEL}" --arg server "${PUBLIC_IP}" --arg auth "${H_AUTH}" '
        split("\n") | map(select(length > 0) | split("\t")) |
        {schema: "veiltrium-clients/1", node_name: $label, server: $server, hysteria_auth: $auth,
         clients: map({name: .[0], main: (.[0] == "main"), created: (if (.[1] // "") == "" then null else .[1] end)})}'
}

# A fast overview of the node: no network tests, no secrets.
status_json() {
    local svc st="" vh vx vt os report n
    for svc in hysteria-server xray trusttunnel; do
        st+="${svc}=$(systemctl is-active "${svc}" 2>/dev/null || true)"$'\n'
    done
    vh="$("${HY2_BIN}" version 2>/dev/null | grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)"
    vx="$("${XRAY_BIN}" version 2>/dev/null | awk 'NR == 1 { print "v" $2 }' || true)"
    vt="$("${TT_BIN}" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n 1 || true)"
    os="$(. /etc/os-release 2>/dev/null && printf '%s' "${PRETTY_NAME:-}" || true)"
    report="$(jq -c '{generated_at, mode, reality: .reality.vps, hysteria2: .hysteria2.vps,
        trusttunnel_h2: .trusttunnel.h2.vps, trusttunnel_h3: .trusttunnel.h3.vps}' "${REPORT_FILE}" 2>/dev/null || true)"
    n="$(count_clients)"
    jq -n --arg now "$(date -u +%FT%TZ)" --arg version "${SCRIPT_VERSION}" --arg label "${LABEL}" \
        --arg server "${PUBLIC_IP}" --arg os "${os}" --arg uptime "$(cut -d. -f1 /proc/uptime 2>/dev/null || echo 0)" \
        --arg reboot "$([[ -f /run/reboot-required ]] && echo 1 || echo 0)" --arg st "${st}" \
        --arg vh "${vh}" --arg vx "${vx}" --arg vt "${vt:+v${vt}}" --arg n "${n}" --arg h_auth "${H_AUTH}" \
        --arg r_site "${R_SITE}" --arg r_port "${REALITY_PORT}" --arg r_mts "$(mts_status reality "${R_SITE:-none}")" \
        --arg h_sni "${H_SNI}" --arg h_port "${HY2_PORT}" --arg h_mts "$(mts_status hysteria2 "${H_SNI:-none}")" \
        --arg t_sni "${T_SNI}" --arg t_port "${TT_PORT}" --arg t2 "$(mts_status tt_h2 "${T_SNI:-none}")" \
        --arg t3 "$(mts_status tt_h3 "${T_SNI:-none}")" --argjson report "${report:-null}" '
        {schema: "veiltrium-status/1", generated_at: $now, script_version: $version, node_name: $label,
         server: $server, os: $os, uptime_seconds: ($uptime | tonumber), reboot_required: ($reboot == "1"),
         services: ($st | split("\n") | map(select(length > 0) | split("=") | {key: .[0], value: .[1]}) | from_entries),
         versions: {hysteria: $vh, xray: $vx, trusttunnel: $vt},
         clients: {added: ($n | tonumber), hysteria_auth: $h_auth},
         reality: (if $r_site == "" then null else {sni: $r_site, port: ($r_port | tonumber), home_network: $r_mts} end),
         hysteria2: {sni: $h_sni, port: ($h_port | tonumber), home_network: $h_mts},
         trusttunnel: (if $t_sni == "" then null else
           {hostname: $t_sni, port: ($t_port | tonumber), home_network_h2: $t2, home_network_h3: $t3} end),
         last_install_check: $report}'
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

clients_list() {
    local i
    printf '\nClients of %s (%s):\n' "${LABEL}" "${PUBLIC_IP}"
    printf '  %-24s %-18s %s\n' main "first client" "${CLIENT_FILE}"
    for (( i = 0; i < ${#CL_NAMES[@]}; i++ )); do
        printf '  %-24s %-18s %s\n' "${CL_NAMES[i]}" "added ${CL_CREATED[i]}" "${CLIENT_FILES_DIR}/${CL_NAMES[i]}.txt"
    done
    if [[ "${H_AUTH}" == "userpass" ]]; then
        info "Hysteria: a password per client (user:password)."
    else
        info "Hysteria: one shared password; the first --add-client changes the main Hysteria link (user:password)."
    fi
    return 0
}

# Adds (credentials in ${TMPD}/client.env) or removes client $2 ($1 = add|remove). All
# protocol configs change as one: the services restart (connected clients reconnect
# within seconds), real clients check the result, and on any failure the previous
# files come back.
clients_change() {
    local mode="$1" name="$2" reg="${CLIENTS_DIR}/$2.env" old_auth="${H_AUTH}" i ok=1
    local new_auth="" new_uuid="" gone_auth="" gone_uuid=""
    if [[ "${mode}" == "remove" ]]; then
        i="$(client_index "${name}")"
        [[ -n "${i}" ]] || die "no client ${name}."
        gone_auth="${name}:${CL_HPASS[i]}"; gone_uuid="${CL_UUID[i]}"
    fi
    install -d -m 700 "${CLIENTS_DIR}"
    txn_begin hysteria hysteria-server.service "${HY2_CONFIG}" "${HY2_STATE}" "${reg}"
    if (( HAVE_REALITY == 1 )); then txn_begin reality xray.service "${XRAY_DIR}/config.json"; fi
    if (( HAVE_TT == 1 )); then txn_begin trusttunnel trusttunnel.service "${TT_DIR}/credentials.toml"; fi
    if [[ "${mode}" == "add" ]]; then mv -f "${TMPD}/client.env" "${reg}"; else rm -f "${reg}"; fi
    load_clients
    H_AUTH="userpass"; set_hy2_auth_main
    if [[ "${mode}" == "add" ]]; then
        i="$(client_index "${name}")"
        [[ -n "${i}" ]] || die "the new client ${name} was not saved."
        new_auth="${name}:${CL_HPASS[i]}"; new_uuid="${CL_UUID[i]}"
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

    # Real clients: the main client still works, the new one works, a removed one does not.
    step_mark check-hysteria
    if ! wait_listening -Hulpn "${HY2_PORT}" hysteria; then ok=0; warn "Hysteria did not start"; fi
    if (( ok == 1 )); then
        hy2_client_test "${HY2_SNI}" "${CERT_SHA}"
        if (( HY2_E2E != 0 )); then ok=0; warn "Hysteria: the main client does not work"; fi
    fi
    if (( ok == 1 )) && [[ -n "${new_auth}" ]]; then
        hy2_client_test "${HY2_SNI}" "${CERT_SHA}" "${new_auth}"
        if (( HY2_E2E != 0 )); then ok=0; warn "Hysteria: the new client does not work"; fi
    fi
    if (( ok == 1 )) && [[ -n "${gone_auth}" ]]; then
        hy2_client_test "${HY2_SNI}" "${CERT_SHA}" "${gone_auth}"
        if (( HY2_E2E == 0 )); then ok=0; warn "Hysteria: the removed client still connects"; fi
    fi
    if (( ok == 1 && HAVE_REALITY == 1 )); then
        step_mark check-reality
        reality_verify_production "${R_SITE}"
        if [[ "${RP_STATUS}" != "ok" ]]; then ok=0; warn "VLESS Reality: the main client does not work"; fi
        if (( ok == 1 )) && [[ -n "${new_uuid}" ]]; then
            RC_UUID="${new_uuid}" reality_verify_production "${R_SITE}"
            if [[ "${RP_STATUS}" != "ok" ]]; then ok=0; warn "VLESS Reality: the new client does not work"; fi
        fi
        if (( ok == 1 )) && [[ -n "${gone_uuid}" ]]; then
            RC_UUID="${gone_uuid}" RP_TRIES=1 reality_verify_production "${R_SITE}"
            if [[ "${RP_STATUS}" == "ok" ]]; then ok=0; warn "VLESS Reality: the removed client still connects"; fi
        fi
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
        die "the change did not pass the checks; the previous clients and settings were restored."
    fi
    # The registry entry belongs to the Hysteria change, committed last: if the run is cut
    # off between the commits, the registry and Hysteria agree and a re-run rebuilds the rest.
    step_mark commit
    CLIENT_FILES_STALE=1
    if (( HAVE_REALITY == 1 )); then txn_commit reality; fi
    if (( HAVE_TT == 1 )); then txn_commit trusttunnel; fi
    txn_commit hysteria

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
    else
        ok "Client ${name} removed: its credentials no longer work."
    fi
    if [[ "${old_auth}" != "userpass" ]]; then
        warn "Hysteria now has a password per client. The MAIN client's Hysteria link and JSON changed"
        warn "(password -> main:<password>): update them on its devices (on the router: section 6 of"
        warn "${CLIENT_FILE}). VLESS Reality and TrustTunnel links of the main client stay the same."
    fi
    return 0
}

usage() {
    banner
    printf '\n'
    sed -n '/^#  Modes:/,/^#  Without VLESS/p' "$0" | sed 's/^#  \{0,1\}//'
    cat <<'EOF'

Settings (environment variables, saved where noted):
  REALITY_CANDIDATES="a.com b.com"  Reality candidates (saved; "default" = built-in list)
  REALITY_SNI=a.com                 use exactly this Reality site (checked first)
  HY2_SNI=name | auto               Hysteria SNI and certificate name (saved)
  HY2_MASQUERADE_URL=url | auto     Hysteria masquerade page (saved)
  TT_SNI=name | auto                TrustTunnel hostname and certificate name (saved)
  NODE_NAME=PL | auto | none        node name in client apps: Veiltrium-PL (saved; default:
                                    the server's country, detected once)
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
    local rc=$?
    trap '' INT TERM
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
TRIAL_SITES=""
JSON_OUT=""
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
        --add-client|--remove-client|--show-client)
            MODE="${1#--}"; CLIENT_ARG="${2:-}"; [[ -n "${CLIENT_ARG}" ]] || die "$1 needs a client name"; shift ;;
        --list-clients) MODE="list-clients" ;;
        --status) MODE="status" ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done
[[ "${REALITY_RESELECT}" == "0" || "${REALITY_RESELECT}" == "1" ]] || die "REALITY_RESELECT must be 0 or 1."
[[ "${MTS_MAX_AGE_DAYS}" =~ ^[0-9]{1,3}$ ]] || die "MTS_MAX_AGE_DAYS must be a number of days."

# ---- Preliminary checks (before any changes) --------------------------------
[[ ${EUID} -eq 0 ]] || die "run as root (for example: sudo -i, then run again)."

SCRIPT_PATH="$(readlink -f -- "$0" 2>/dev/null || true)"
if [[ -n "${SCRIPT_PATH}" && -f "${SCRIPT_PATH}" ]] && \
   ! grep -q '^# ==== HY2-SECURE-INSTALL END ====$' "${SCRIPT_PATH}"; then
    die "the script file is incomplete (truncated while pasting); paste the whole block again."
fi

exec 9>/run/hy2-secure-install.lock
flock -n 9 || die "the script is already running (perhaps a previous run is still going after a dropped connection); wait a couple of minutes and run it again."
# Temp dirs of a run that was killed (they may hold client configs with keys): with the
# lock held, no other run is using them.
rm -rf /root/.hy2-install.* 2>/dev/null || true

# =============================================================================
# Maintenance modes: no install log, no package changes.
# =============================================================================
if [[ "${MODE}" != "install" ]]; then
    LIGHT=1
    if [[ "${JSON_OUT}" == "-" ]]; then exec 8>&1 1>&2; fi
    TMPD="$(mktemp -d /root/.hy2-install.XXXXXX)"
    chmod 700 "${TMPD}"
    # An interrupted change first: its half-written files must not be read as "damaged".
    if txn_pending; then
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
    case "${MODE}" in list-clients|show-client|add-client|remove-client|trial) load_clients ;; esac
    load_node_name
    set_hy2_auth_main
    PUBLIC_IP="${PUBLIC_IP:-${PROBE_SERVER}}"
    if [[ -n "${H_PORT}" ]]; then HY2_PORT="${H_PORT}"; fi
    case "${MODE}" in
        import-mts)
            mts_import "${IMPORT_FILE}" || die "no usable results for this server in ${IMPORT_FILE}."
            exit 0 ;;
        trial-stop)
            trial_stop
            exit 0 ;;
        trial)
            trial_start "${TRIAL_SITES}"
            exit 0 ;;
        status)
            command -v jq >/dev/null 2>&1 || die "jq is missing: run the installer once (bash $0) first."
            [[ -n "${H_PASSWORD}" ]] || die "this server has no installed node yet: run the installer once (bash $0) first."
            if [[ -n "${JSON_OUT}" ]]; then
                status_json | json_emit
            else
                status_json | jq -r '"\(.node_name) \(.server), \(.os); Veiltrium \(.script_version)",
                    (.services | to_entries[] | "  \(.key): \(.value)"),
                    "  clients: main + \(.clients.added) added; reboot required: \(.reboot_required)"'
            fi
            exit 0 ;;
        list-clients|show-client|add-client|remove-client)
            [[ -n "${H_PASSWORD}" && -n "${PUBLIC_IP}" && -s "${CLIENT_FILE}" ]] \
                || die "this server has no installed node yet: run the installer once (bash $0) first."
            node_context
            case "${MODE}" in
                list-clients)
                    if [[ -n "${JSON_OUT}" ]]; then clients_json | json_emit; else clients_list; fi ;;
                show-client)
                    if [[ "${CLIENT_ARG}" == "main" ]]; then CLIENT_TXT="${CLIENT_FILE}"
                    elif [[ "${CLIENT_ARG}" =~ ${CLIENT_RE} && -n "$(client_index "${CLIENT_ARG}")" && \
                            -s "${CLIENT_FILES_DIR}/${CLIENT_ARG}.txt" ]]; then
                        CLIENT_TXT="${CLIENT_FILES_DIR}/${CLIENT_ARG}.txt"
                    else
                        die "no client ${CLIENT_ARG} (see --list-clients)."
                    fi
                    if [[ -n "${JSON_OUT}" ]]; then
                        client_json "${CLIENT_ARG}" "$(grep -m1 '^tt://' "${CLIENT_TXT}" 2>/dev/null || true)" | json_emit
                    else
                        cat "${CLIENT_TXT}"
                    fi ;;
                add-client|remove-client)
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
                        clients_change remove "${CLIENT_ARG}"
                    fi
                    step_mark finished
                    if [[ -n "${JSON_OUT}" ]]; then
                        jq -n --arg action "${MODE%-client}" --arg name "${CLIENT_ARG}" --arg before "${AUTH_BEFORE}" \
                            '{schema: "veiltrium-result/1", ok: true, action: $action, name: $name,
                              main_hysteria_link_changed: ($before != "userpass")}' | json_emit
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
# install runs to the end; the result stays in the log and /root/hy2-client.txt.
TEE_ARGS=(-i -a)
if tee -p /dev/null </dev/null >/dev/null 2>&1; then TEE_ARGS=(-i -p -a); fi
exec 7>&1
# tee must not inherit the lock (fd 9): a killed installer has to release it at once.
exec > >(tee "${TEE_ARGS[@]}" "${LOG_FILE}" 7>&- 9>&-) 2>&1
TEE_PID=$!
banner
printf '\n===== Veiltrium %s (hy2-secure-install.sh): %s =====\n' "${SCRIPT_VERSION}" "$(date -Is)"

TMPD="$(mktemp -d /root/.hy2-install.XXXXXX)"
chmod 700 "${TMPD}"

# nftables: own table only. $1 = 1 to open the VLESS Reality port.
apply_firewall() {
    local reality_on="$1" reality_in="" reality_out="" reality_egress=""
    local scan_rules="" scan_include=""
    if [[ "${reality_on}" == "1" ]]; then
        reality_in="        # VLESS Reality (TCP)"$'\n'"        tcp dport ${REALITY_PORT} accept"$'\n'
        reality_out="        meta skuid ${XRAY_UID} jump proxy_egress"$'\n'
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
    cat > /etc/nftables.conf.hy2-new <<EOF
#!/usr/sbin/nft -f
# hy2-secure-install: server firewall.
# Only our own table is recreated; rules of fail2ban and other services are left alone.

table inet hy2fw
delete table inet hy2fw

table inet hy2fw {
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

    # Filled from ${SCANNER_FILE} (hy2-scanner-block, refreshed weekly)
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
        udp sport ${HY2_PORT} accept
${reality_egress}${DNS_RULES}        fib daddr type local reject
        ip daddr { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.168.0.0/16, 198.18.0.0/15, 224.0.0.0/3 } reject
        ip6 daddr { ::/127, ::ffff:0:0/96, 100::/64, 2001:db8::/32, fc00::/7, fe80::/10, ff00::/8 } reject
        tcp dport 25 reject
    }
}
${scan_include}
EOF
    nft -c -f /etc/nftables.conf.hy2-new || die "nftables rejected the rules; the firewall was not changed."
    chmod 700 /etc/nftables.conf.hy2-new
    sync
    mv -f /etc/nftables.conf.hy2-new /etc/nftables.conf
    systemctl enable nftables.service >/dev/null 2>&1
    # The nftables service applies /etc/nftables.conf (also on every boot).
    if systemctl is-active --quiet nftables.service; then
        systemctl reload nftables.service
    else
        systemctl start nftables.service
    fi
    nft list table inet hy2fw >/dev/null 2>&1 || die "the firewall rules did not load."
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
if [[ "${HY2_RECONFIGURE}" == "1" ]] && (( ${#CL_NAMES[@]} )); then
    renew_client_secrets
    info "HY2_RECONFIGURE=1: the added clients get new credentials too (${CL_NAMES[*]})."
fi
load_node_name
# A node that already works is never rebooted by a re-run (clients would drop).
NODE_EXISTED=0
if [[ -s "${HY2_STATE}" || -s "${XRAY_STATE}" || -s "${TT_STATE}" ]]; then NODE_EXISTED=1; fi
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
cat > /etc/needrestart/conf.d/50-hy2-secure.conf <<'EOF'
# hy2-secure-install: do not restart the proxies automatically (clients would drop)
$nrconf{override_rc}->{qr(^(hysteria-server|xray|trusttunnel)\.service$)} = 0;
EOF
APT_GET=(apt-get -q -o DPkg::Lock::Timeout=900
         -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
# If a previous run was cut off in the middle of package installation, finish it.
dpkg --force-confdef --force-confold --configure -a </dev/null || true
apt_updated=0
for attempt in 1 2 3 4 5 6; do
    if "${APT_GET[@]}" update; then apt_updated=1; break; fi
    warn "Package lists did not update (attempt ${attempt}), retrying in 15 s..."
    sleep 15
done
(( apt_updated == 1 )) || die "could not update package lists (check the server's internet connection)."
"${APT_GET[@]}" -y full-upgrade
"${APT_GET[@]}" -y install curl ca-certificates openssl nftables unattended-upgrades iproute2 util-linux unzip jq
if "${APT_GET[@]}" -y install fail2ban python3-systemd; then
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
cat > /etc/apt/apt.conf.d/52hy2-unattended-upgrades <<EOF
// hy2-secure-install: security updates install automatically;
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
SYSCTL_FILE="/etc/sysctl.d/99-zz-hy2-hardening.conf"
cat > "${SYSCTL_FILE}" <<'EOF'
# hy2-secure-install
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
echo tcp_bbr > /etc/modules-load.d/hy2-bbr.conf
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
cat > /etc/systemd/journald.conf.d/50-hy2.conf.new <<'EOF'
[Journal]
SystemMaxUse=200M
MaxRetentionSec=1month
EOF
if cmp -s /etc/systemd/journald.conf.d/50-hy2.conf.new /etc/systemd/journald.conf.d/50-hy2.conf; then
    rm -f /etc/systemd/journald.conf.d/50-hy2.conf.new
else
    mv -f /etc/systemd/journald.conf.d/50-hy2.conf.new /etc/systemd/journald.conf.d/50-hy2.conf
    systemctl restart systemd-journald
fi
ok "Crash dumps disabled, journal limited to 200 MB / 1 month"

# =============================================================================
step 5 "SSH hardening (password login is kept)"
if command -v sshd >/dev/null 2>&1; then
    install -d -m 755 /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/00-hy2-hardening.conf <<'EOF'
# hy2-secure-install: SSH hardening.
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
        rm -f /etc/ssh/sshd_config.d/00-hy2-hardening.conf
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

if [[ -f /etc/nftables.conf && ! -f /etc/nftables.conf.orig-hy2 ]] && ! grep -q 'hy2-secure-install' /etc/nftables.conf; then
    cp -p /etc/nftables.conf /etc/nftables.conf.orig-hy2
fi
# The firewall includes the scanner list: it must exist (possibly empty) before the rules load.
install -d -m 700 "${SCANNER_DIR}"
if [[ ! -f "${SCANNER_FILE}" ]]; then
    printf '# hy2-scanner-block: no list downloaded yet\n' > "${SCANNER_FILE}"
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
# hy2-secure-install: refresh the scanner blocklist (nftables sets scanners4/scanners6).
# A failed download or a list that looks wrong keeps the current list.
set -euo pipefail
umask 077
OUT="/etc/hy2-secure/scanners.nft"
BASE="https://raw.githubusercontent.com/shadow-netlab/traffic-guard-lists/refs/heads/main/public"
read -r -a URLS <<<"${SCANNER_URLS:-${BASE}/government_networks.list ${BASE}/antiscanner.list ${BASE}/skipa.list}"
MIN_ENTRIES=50          # fewer means a broken download
MAX_V4_ADDRS=2000000    # more means the list is not what it claims to be
TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

for url in "${URLS[@]}"; do
    if ! curl -fsSL --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 15 --max-time 120 \
            --max-filesize 8000000 "${url}" >> "${TMP}/raw"; then
        echo "hy2-scanner-block: could not download ${url}; keeping the current list" >&2
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
    echo "hy2-scanner-block: only ${entries} networks in the downloaded lists; keeping the current list" >&2
    exit 1
fi
if (( v4_addrs > MAX_V4_ADDRS )); then
    echo "hy2-scanner-block: the lists cover ${v4_addrs} IPv4 addresses, more than ${MAX_V4_ADDRS}; keeping the current list" >&2
    exit 1
fi

{
    echo "# hy2-scanner-block: ${entries} networks, $(date -u '+%Y-%m-%d %H:%M UTC')"
    if [[ -s "${TMP}/v4" ]]; then
        echo "add element inet hy2fw scanners4 { $(paste -sd, "${TMP}/v4") }"
    fi
    if [[ -s "${TMP}/v6" ]]; then
        echo "add element inet hy2fw scanners6 { $(paste -sd, "${TMP}/v6") }"
    fi
} > "${TMP}/scanners.nft"

# Swap the set contents in one transaction; the file on disk is replaced only if that worked.
printf 'flush set inet hy2fw scanners4\nflush set inet hy2fw scanners6\ninclude "%s"\n' \
    "${TMP}/scanners.nft" > "${TMP}/apply.nft"
if ! nft -f "${TMP}/apply.nft"; then
    echo "hy2-scanner-block: nftables rejected the new list; keeping the current list" >&2
    exit 1
fi
install -m 600 "${TMP}/scanners.nft" "${OUT}.new"
mv -f "${OUT}.new" "${OUT}"
echo "hy2-scanner-block: ${entries} networks loaded (${v4_addrs} IPv4 addresses)"
EOS
chmod 755 "${SCANNER_BIN}"
cat > /etc/systemd/system/hy2-scanner-block.service <<EOF
# hy2-secure-install: refresh the scanner blocklist
[Unit]
Description=Refresh the scanner blocklist (hy2-secure-install)
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
cat > /etc/systemd/system/hy2-scanner-block.timer <<'EOF'
# hy2-secure-install: refresh the scanner blocklist weekly
[Unit]
Description=Weekly scanner blocklist refresh (hy2-secure-install)

[Timer]
OnCalendar=weekly
RandomizedDelaySec=6h
Persistent=true

[Install]
WantedBy=timers.target
EOF
systemctl daemon-reload
if [[ "${SCANNER_BLOCK}" == "1" ]]; then
    systemctl enable hy2-scanner-block.timer >/dev/null 2>&1
    systemctl start hy2-scanner-block.timer >/dev/null 2>&1 || true
    SCANNER_RC=0
    if grep -q '^# hy2-scanner-block: [0-9]* networks' "${SCANNER_FILE}" && [[ -n "$(find "${SCANNER_FILE}" -mtime -6 2>/dev/null)" ]]; then
        # a list from the last days is already loaded (with the firewall above)
        printf 'hy2-scanner-block: %s (kept; refreshed weekly)\n' "$(head -n 1 "${SCANNER_FILE}" | sed 's/^# hy2-scanner-block: //')" > "${TMPD}/scanner.log"
    else
        "${SCANNER_BIN}" > "${TMPD}/scanner.log" 2>&1 || SCANNER_RC=$?
    fi
    SCANNER_MSG="$(tail -n 1 "${TMPD}/scanner.log")"
    if (( SCANNER_RC == 0 )); then
        ok "Scanner networks blocked on the proxy ports: ${SCANNER_MSG#hy2-scanner-block: }; refreshed weekly"
    else
        warn "${SCANNER_MSG#hy2-scanner-block: }"
        warn "The scanner blocklist will be retried by the weekly timer."
    fi
else
    systemctl disable --now hy2-scanner-block.timer >/dev/null 2>&1 || true
    info "Scanner blocklist is off (SCANNER_BLOCK=0)"
fi

# =============================================================================
step 7 "Fail2ban"
if (( HAVE_FAIL2BAN == 1 )); then
    cat > /etc/fail2ban/jail.d/hy2-sshd.local.new <<EOF
# hy2-secure-install
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
    if cmp -s /etc/fail2ban/jail.d/hy2-sshd.local.new /etc/fail2ban/jail.d/hy2-sshd.local \
            && systemctl is-active --quiet fail2ban.service; then
        rm -f /etc/fail2ban/jail.d/hy2-sshd.local.new
    else
        mv -f /etc/fail2ban/jail.d/hy2-sshd.local.new /etc/fail2ban/jail.d/hy2-sshd.local
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
# hy2-secure-install: Hysteria 2 in a systemd sandbox
[Unit]
Description=Hysteria 2 server (hy2-secure-install)
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
# hy2-secure-install: VLESS Reality (Xray) in a systemd sandbox
[Unit]
Description=Xray VLESS Reality (hy2-secure-install)
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
# hy2-secure-install: TrustTunnel endpoint in a systemd sandbox
[Unit]
Description=TrustTunnel endpoint (hy2-secure-install)
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
if [[ "${REALITY_ENABLE}" == "1" ]]; then
    load_reality_state
    PREV_SITE="${R_SITE}"
    if [[ -n "${R_UUID}" ]]; then
        ok "Reality keys kept from the previous run (new ones: HY2_RECONFIGURE=1)"
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
                # HY2_RECONFIGURE=1 on a working node: the old node came back, keep it on
                SAVED_RECONF="${HY2_RECONFIGURE}"; HY2_RECONFIGURE=0; load_reality_state; HY2_RECONFIGURE="${SAVED_RECONF}"
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
# The node name in client apps (Veiltrium-<name>): explicit setting, else the saved one,
# else the server's country code (detected once, then saved).
if [[ "${NODE_NAME}" == "auto" || ( -z "${NODE_NAME}" && "${N_SAVED}" == "0" ) ]]; then
    N_NAME="$(detect_country)"
    if [[ -z "${N_NAME}" ]]; then info "Could not detect the server's country; a node name can be set with NODE_NAME=XX."; fi
elif [[ "${NODE_NAME}" == "none" ]]; then
    N_NAME=""
elif [[ -n "${NODE_NAME}" ]]; then
    N_NAME="${NODE_NAME}"
fi
save_node_name
ok "Node name in client apps: ${LABEL}"
install -d -m 750 -o root -g hysteria "${HY2_DIR}"
# A node that exists on disk is changed as a transaction: if the new settings do not
# work (or the run is cut off), the previous files come back.
HY2_TXN=0
if [[ -e "${HY2_CONFIG}" || -e "${HY2_CERT}" ]]; then
    txn_begin hysteria hysteria-server.service "${HY2_CERT}" "${HY2_KEY}" "${HY2_CONFIG}" "${HY2_STATE}"
    HY2_TXN=1
fi
NEW_CERT=1
if [[ -n "${H_PASSWORD}" ]]; then
    if [[ "${H_SNI}" == "${HY2_SNI}" && \
          "$(openssl x509 -in "${HY2_CERT}" -noout -checkhost "${HY2_SNI}" 2>/dev/null || true)" == *"does match"* ]]; then
        NEW_CERT=0
        ok "The node is already configured; password and certificate kept (new ones: HY2_RECONFIGURE=1)"
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
    if [[ -e "${TT_DIR}/vpn.toml" || -e "${TT_DIR}/cert.pem" ]]; then
        txn_begin trusttunnel trusttunnel.service "${TT_DIR}/cert.pem" "${TT_DIR}/key.pem" "${TT_DIR}/vpn.toml" \
            "${TT_DIR}/hosts.toml" "${TT_DIR}/credentials.toml" "${TT_STATE}"
        TT_TXN=1
    fi
    if [[ -z "${T_USER}" || -z "${T_PASS}" ]]; then
        T_USER="u$(openssl rand -hex 4)"
        T_PASS="$(openssl rand -hex 24)"
        T_SNI=""
    else
        ok "TrustTunnel credentials kept from the previous run (new ones: HY2_RECONFIGURE=1)"
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
    TT_IPV6="${T_IPV6:-}"
    if [[ "${TT_IPV6}" != "true" && "${TT_IPV6}" != "false" ]]; then
        TT_IPV6=false
        if ip -6 route get 2001:4860:4860::8888 >/dev/null 2>&1; then TT_IPV6=true; fi
    fi

    TT_SUM_BEFORE="$(cat "${TT_DIR}/vpn.toml" "${TT_DIR}/hosts.toml" "${TT_DIR}/credentials.toml" "${TT_DIR}/cert.pem" "${TT_DIR}/key.pem" 2>/dev/null | sha256sum || true)"
    install -m 640 -o root -g trusttunnel /dev/null "${TT_DIR}/vpn.toml.new"
    cat > "${TT_DIR}/vpn.toml.new" <<EOF
# hy2-secure-install: TrustTunnel endpoint
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
    mv -f "${TT_DIR}/vpn.toml.new" "${TT_DIR}/vpn.toml"
    install -m 640 -o root -g trusttunnel /dev/null "${TT_DIR}/hosts.toml.new"
    cat > "${TT_DIR}/hosts.toml.new" <<EOF
# hy2-secure-install: TrustTunnel TLS host (self-signed, embedded in the client link)
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

# ---- Home-network probe profile ----------------------------------------------
load_probe_env
# a new key with new passwords: a leaked old profile can no longer sign results
if [[ -z "${PROBE_KEY}" || "${HY2_RECONFIGURE}" == "1" ]]; then PROBE_KEY="$(openssl rand -hex 32)"; fi
PROBE_SERVER="${PUBLIC_IP}"
install -m 600 /dev/null "${PROBE_ENV}.new"
printf 'PROBE_KEY=%q\nPROBE_SERVER=%q\n' "${PROBE_KEY}" "${PROBE_SERVER}" > "${PROBE_ENV}.new"
mv -f "${PROBE_ENV}.new" "${PROBE_ENV}"
write_probe_profile

# ---- Connection details -----------------------------------------------------
write_client_files

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
info "Tip: since SSH password login stays on, make the password long: 16+ characters."
if (( CHECK_FAIL != 0 )); then
    printf '\n\033[1;33m! Some checks failed; send the output above.\033[0m\n'
    if [[ -n "${REBOOT_NOTE}" ]]; then info "Updates require a reboot: once this is sorted out, reboot the server (reboot)."; fi
    exit 2
fi
if [[ -n "${REBOOT_NOTE}" && "${HY2_AUTO_REBOOT}" == "1" && "${NODE_EXISTED}" == "0" ]]; then
    shutdown -r +1 "Veiltrium: reboot after updates" >/dev/null 2>&1 || true
    printf '\n\033[33m! Updates require a reboot: the server will reboot in 1 minute, the services will start on their own.\033[0m\n'
    info "To cancel: shutdown -c   (then the reboot happens at night at ${AUTO_REBOOT_TIME})"
elif [[ -n "${REBOOT_NOTE}" ]]; then
    # a working node: no reboot in the middle of the day (clients would drop)
    printf '\n\033[33m! Updates require a reboot: reboot the server (reboot) or it will do so at night at %s.\033[0m\n' "${AUTO_REBOOT_TIME}"
fi
exit 0
# ==== HY2-SECURE-INSTALL END ====
