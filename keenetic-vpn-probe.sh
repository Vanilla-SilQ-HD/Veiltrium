#!/bin/sh
# =============================================================================
#  keenetic-vpn-probe.sh - Veiltrium home-network probe
#  https://github.com/Vanilla-SilQ-HD/Veiltrium
#  Checks Veiltrium servers (hy2-secure-install.sh) from a home network (e.g. MTS) on a Keenetic
#  router with Entware: VLESS Reality, Hysteria 2 and TrustTunnel with real
#  clients, payload downloads, retries and timings. Prints a JSON result
#  without secrets. The results are signed (HMAC-SHA256) with the server's probe
#  key, so the server accepts only results made with its own profile (--import-mts);
#  a signature shows who ran the probe, not where: the route checks below do that.
#
#  It does not touch the running VPN: no TUN, no routes, no firewall rules, AWG
#  Manager keeps running. Each test is a temporary sing-box (the one AWG Manager
#  installed) with a local SOCKS port only, its traffic bound to the WAN
#  interface. A result counts as home-network proof only when the route is
#  verified: the test packets were seen leaving through the WAN (tcpdump), or
#  conntrack shows the server answering the WAN address. Otherwise the result
#  is marked route_unverified.
#
#  Usage (on the router, as root):
#    sh keenetic-vpn-probe.sh --all --wan ppp0 --output /opt/tmp/vpn-probe.json
#    sh keenetic-vpn-probe.sh --reality            only VLESS Reality
#    sh keenetic-vpn-probe.sh --hysteria           only Hysteria 2
#    sh keenetic-vpn-probe.sh --trusttunnel        only TrustTunnel (HTTP/2 and HTTP/3)
#    sh keenetic-vpn-probe.sh --reality --trial-sni a.com,b.com   (after --trial-reality on the server)
#    sh keenetic-vpn-probe.sh --check-awg          does AWG Manager pin the Hysteria certificate?
#    sh keenetic-vpn-probe.sh --help
#
#  Server profiles: /opt/etc/vpn-probe/*.env (the server's /root/hy2-probe.env,
#  one file per server, mode 600; they contain passwords).
# =============================================================================
set -u
umask 077

PROBE_VERSION=2
PROFILE_DIR="/opt/etc/vpn-probe"
PROFILES=""
OUTPUT=""
DO_REALITY=0; DO_HY2=0; DO_TT=0; ANY_SELECTED=0
RUNS=3
PAYLOAD_BYTES=2000000
PAYLOAD_URL="https://speed.cloudflare.com/__down?bytes="
WAN=""
TRIAL_SNI=""
CHECK_AWG=0
SINGBOX="${SINGBOX:-}"
TT_CLIENT="${TT_CLIENT:-}"
AWG_CONFIG_DIR="/opt/etc/awg-manager/singbox/config.d"

log() { printf '%s\n' "$*" >&2; }
die() { printf 'keenetic-vpn-probe: %s\n' "$*" >&2; exit 3; }

usage() { sed -n '/^#  Usage/,/^#  Server profiles/p' "$0" | sed 's/^#  \{0,1\}//'
cat <<'EOF'
Options:
  --profile FILE     a server profile (repeatable; default: all of /opt/etc/vpn-probe/*.env)
  --wan IFACE        WAN interface (default: the default route's interface)
  --runs N           requests per test (1..10, default 3)
  --payload-bytes N  download size per test (0 = none, max 5000000, default 2000000)
  --payload-url URL  download URL prefix (the size is appended)
  --singbox PATH     sing-box binary (default: AWG Manager's, then sing-box in PATH)
  --tt-client PATH   TrustTunnel client binary (used if sing-box has no trusttunnel)
  --output FILE      write the JSON there (default: stdout)
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --all) DO_REALITY=1; DO_HY2=1; DO_TT=1; ANY_SELECTED=1 ;;
        --reality) DO_REALITY=1; ANY_SELECTED=1 ;;
        --hysteria) DO_HY2=1; ANY_SELECTED=1 ;;
        --trusttunnel) DO_TT=1; ANY_SELECTED=1 ;;
        --check-awg) CHECK_AWG=1 ;;
        --profile) [ $# -ge 2 ] || die "--profile needs a file"; PROFILES="${PROFILES} $2"; shift ;;
        --profile-dir) [ $# -ge 2 ] || die "--profile-dir needs a directory"; PROFILE_DIR="$2"; shift ;;
        --wan) [ $# -ge 2 ] || die "--wan needs an interface"; WAN="$2"; shift
               printf '%s\n' "${WAN}" | grep -Eq '^[A-Za-z0-9_.-]{1,15}$' || die "--wan: not an interface name" ;;
        --runs) [ $# -ge 2 ] || die "--runs needs a number"; RUNS="$2"; shift ;;
        --payload-bytes) [ $# -ge 2 ] || die "--payload-bytes needs a number"; PAYLOAD_BYTES="$2"; shift ;;
        --payload-url) [ $# -ge 2 ] || die "--payload-url needs a URL"; PAYLOAD_URL="$2"; shift ;;
        --trial-sni) [ $# -ge 2 ] || die "--trial-sni needs names"; TRIAL_SNI="$2"; shift ;;
        --singbox) [ $# -ge 2 ] || die "--singbox needs a path"; SINGBOX="$2"; shift ;;
        --tt-client) [ $# -ge 2 ] || die "--tt-client needs a path"; TT_CLIENT="$2"; shift ;;
        --output) [ $# -ge 2 ] || die "--output needs a file"; OUTPUT="$2"; shift ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done
if [ "${ANY_SELECTED}" = 0 ] && [ "${CHECK_AWG}" = 0 ]; then DO_REALITY=1; DO_HY2=1; DO_TT=1; fi
echo "${RUNS}" | grep -Eq '^([1-9]|10)$' || die "--runs must be 1..10"
echo "${PAYLOAD_BYTES}" | grep -Eq '^[0-9]{1,7}$' && [ "${PAYLOAD_BYTES}" -le 5000000 ] || die "--payload-bytes must be 0..5000000"
echo "${PAYLOAD_URL}" | grep -Eq '^https://[A-Za-z0-9./?=_&%-]+$' || die "--payload-url must be an https URL"
[ -z "${TRIAL_SNI}" ] || echo "${TRIAL_SNI}" | grep -Eq '^[A-Za-z0-9.-]+(,[A-Za-z0-9.-]+){0,4}$' || die "--trial-sni: up to 5 names, comma-separated"

for tool in curl ip awk sed grep readlink od; do
    command -v "${tool}" >/dev/null 2>&1 || die "${tool} is missing (opkg install ${tool})"
done
if command -v sha256sum >/dev/null 2>&1; then SHA="sha256sum"
elif command -v openssl >/dev/null 2>&1; then SHA="openssl dgst -sha256 -r"
else SHA=""; fi

if [ -z "${SINGBOX}" ]; then
    if [ -x /opt/etc/awg-manager/singbox/sing-box ]; then SINGBOX=/opt/etc/awg-manager/singbox/sing-box
    elif command -v sing-box >/dev/null 2>&1; then SINGBOX="$(command -v sing-box)"; fi
fi
SB_VERSION=""
if [ -n "${SINGBOX}" ] && [ -x "${SINGBOX}" ]; then
    SB_VERSION="$("${SINGBOX}" version 2>/dev/null | head -n 1 | sed 's/.*version //')"
else
    SINGBOX=""
fi

# ---- temp dir, lock, cleanup -------------------------------------------------
TMPBASE="${TMPDIR:-/tmp}"
LOCK="${TMPBASE}/keenetic-vpn-probe.lock"
if ! mkdir "${LOCK}" 2>/dev/null; then
    # a lock left by a probe that was killed (kill -9, power loss) does not block forever
    old="$(cat "${LOCK}/pid" 2>/dev/null)"
    if [ -n "${old}" ] && kill -0 "${old}" 2>/dev/null; then die "another probe is running (pid ${old})"; fi
    for c in $(cat "${LOCK}/children" 2>/dev/null); do
        case "$(tr '\0' ' ' < "/proc/${c}/cmdline" 2>/dev/null)" in
            *probe-sing-box*|*tcpdump*|*trusttunnel_client*|*curl*) kill "${c}" 2>/dev/null ;;
        esac
    done
    rm -rf "${LOCK}"
    mkdir "${LOCK}" 2>/dev/null || die "cannot create ${LOCK}"
fi
echo "$$" > "${LOCK}/pid"
# Leftovers of a killed probe: its temporary clients (they would keep a local SOCKS port
# open) and temp dirs (they hold configs with passwords).
for d in /proc/[0-9]*; do
    case "$(tr '\0' ' ' < "${d}/cmdline" 2>/dev/null)" in
        *"${TMPBASE}/vpn-probe."*/sb.json*|*"${TMPBASE}/vpn-probe."*/tt.toml*) kill "${d#/proc/}" 2>/dev/null ;;
    esac
done
rm -rf "${TMPBASE}"/vpn-probe.* 2>/dev/null
T="$(mktemp -d "${TMPBASE}/vpn-probe.XXXXXX")" || { rm -rf "${LOCK}"; die "mktemp failed"; }
chmod 700 "${T}"
PIDS=""
child() {   # remember a child (by pid) for cleanup, also across a kill -9 of this script
    PIDS="${PIDS} $1"
    echo "$1" >> "${LOCK}/children"
}
cleanup() {
    # only our own children: a pid that has been recycled since is not ours
    for p in ${PIDS}; do
        [ "$(awk '{ print $4 }' "/proc/${p}/stat" 2>/dev/null)" = "$$" ] && kill "${p}" 2>/dev/null
    done
    rm -rf "${T}"
    rm -rf "${LOCK}"
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP


# ---- small helpers -----------------------------------------------------------
json_str() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | tr -d '\n\r'; }
to_ms() { awk -v t="${1:-0}" 'BEGIN { printf "%d", t * 1000 + 0.5 }'; }
median() { tr ' ' '\n' | grep -E '^[0-9]+$' | sort -n | awk '{ a[NR] = $1 }
    END { if (NR == 0) print 0; else if (NR % 2) print a[(NR + 1) / 2]; else printf "%d\n", (a[NR / 2] + a[NR / 2 + 1]) / 2 }'; }
port_listening() {   # $1 = TCP port on this host (IPv4 or IPv6 listener)
    hex="$(printf '%04X' "$1")"
    for tbl in /proc/net/tcp /proc/net/tcp6; do
        [ -r "${tbl}" ] || continue
        awk -v p=":${hex}" '$2 ~ (p "$") && $4 == "0A" { f = 1 } END { exit !f }' "${tbl}" && return 0
    done
    return 1
}
free_port() {
    n=0
    while [ ${n} -lt 50 ]; do
        p=$(awk -v s="$$${n}" 'BEGIN { srand(s); printf "%d", 20000 + rand() * 9999 }')
        port_listening "${p}" || { echo "${p}"; return 0; }
        n=$((n + 1))
    done
    echo 41873
}
wait_port() {   # $1 port, $2 pid of the process that should open it (stop waiting if it died)
    n=0
    while [ ${n} -lt 40 ]; do
        port_listening "$1" && return 0
        if [ -n "${2:-}" ] && ! kill -0 "$2" 2>/dev/null; then return 1; fi
        sleep 1; n=$((n + 1))
    done
    return 1
}
stop_pid() {
    [ -n "${1:-}" ] || return 0
    kill "$1" 2>/dev/null
    k=0; while kill -0 "$1" 2>/dev/null && [ ${k} -lt 10 ]; do sleep 1; k=$((k + 1)); done
    kill -9 "$1" 2>/dev/null; wait "$1" 2>/dev/null
    PIDS="$(printf '%s\n' ${PIDS} | grep -vx "$1" | tr '\n' ' ')"
    return 0
}
# ---- HMAC-SHA256 (RFC 2104) with sha256sum and printf only -------------------
# The key never appears in a command line; NUL bytes go through printf "\000".
hex_to_octal() {   # hex string -> \NNN escapes for printf
    printf '%s' "$1" | awk '{ h = "0123456789abcdef"; s = tolower($0)
        for (i = 1; i < length(s); i += 2) printf "\\%03o", (index(h, substr(s, i, 1)) - 1) * 16 + index(h, substr(s, i + 1, 1)) - 1 }'
}
hmac_prepare() {   # $1 = key in hex (at most 64 bytes) -> HM_IPAD, HM_OPAD (printf escapes)
    pads="$(printf '%s' "$1" | awk '
        function bxor(a, b,   r, bit) { r = 0; bit = 1
            while (a > 0 || b > 0) { if ((a % 2) != (b % 2)) r += bit; a = int(a / 2); b = int(b / 2); bit *= 2 }
            return r }
        { h = "0123456789abcdef"; s = tolower($0); while (length(s) < 128) s = s "0"; ip = ""; op = ""
          for (i = 1; i <= 128; i += 2) { v = (index(h, substr(s, i, 1)) - 1) * 16 + index(h, substr(s, i + 1, 1)) - 1
              ip = ip sprintf("\\%03o", bxor(v, 54)); op = op sprintf("\\%03o", bxor(v, 92)) }
          print ip; print op }')"
    HM_IPAD="$(printf '%s\n' "${pads}" | sed -n 1p)"
    HM_OPAD="$(printf '%s\n' "${pads}" | sed -n 2p)"
}
hmac_hex() {   # $1 = message (uses HM_IPAD/HM_OPAD) -> hex digest
    inner="$({ printf "${HM_IPAD}"; printf '%s' "$1"; } | ${SHA} | cut -c1-64)"
    { printf "${HM_OPAD}"; printf "$(hex_to_octal "${inner}")"; } | ${SHA} | cut -c1-64
}
# Known answers (RFC 4231 case 2, and a key/message whose pads and inner hash contain
# NUL bytes). If this router's tools disagree, results go out unsigned (the server
# then ignores them) instead of with a wrong signature.
hmac_selftest() {
    [ -n "${SHA}" ] || return 1
    hmac_prepare 4a656665
    [ "$(hmac_hex 'what do ya want for nothing?')" = 5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843 ] || return 1
    hmac_prepare 363636363636363636363636363636365c5c5c5c5c5c5c5c5c5c5c5c5c5c5c5c
    [ "$(hmac_hex 'hy2 selftest 0')" = eceb5cdcb23ee5101e51ccbdbe4a03877839af8f604b388843917dc0b6871cd5 ] || return 1
    return 0
}
mac_of() {   # $1 record (HMAC key prepared per profile)
    if [ "${HMAC_OK}" = 1 ]; then hmac_hex "$1"; else echo none; fi
}
b64d() {
    if command -v base64 >/dev/null 2>&1; then base64 -d 2>/dev/null
    elif command -v openssl >/dev/null 2>&1; then openssl base64 -d -A 2>/dev/null
    else return 1; fi
}

# ---- WAN and route verification ----------------------------------------------
if [ -z "${WAN}" ]; then
    WAN="$(ip -4 route show default 2>/dev/null | awk '{ for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1) }' | head -n 1)"
fi
WAN_STATE="missing"; WAN_IP=""
if [ -n "${WAN}" ] && [ -d "/sys/class/net/${WAN}" ]; then
    WAN_STATE="$(cat "/sys/class/net/${WAN}/operstate" 2>/dev/null || echo unknown)"
    WAN_IP="$(ip -4 addr show dev "${WAN}" 2>/dev/null | awk '/inet / { split($2, a, "/"); print a[1]; exit }')"
fi
# Only an Ethernet (1) or PPP (512) device can be the provider's line: WireGuard, TUN and
# the like (type 65534) never are. A PPP VPN client (L2TP/PPTP) is also type 512, so the
# name is checked too, and it goes into the signed result.
WAN_TYPE="$(cat "/sys/class/net/${WAN}/type" 2>/dev/null || echo none)"
case "${WAN}" in
    nwg*|wg*|awg*|tun*|t2s*|opkgtun*|sb*|singbox*|ovpn*|ipsec*|l2tp*|pptp*|sstp*) WAN_STATE="not_physical" ;;
esac
case "${WAN_TYPE}" in 1|512) ;; *) [ "${WAN_STATE}" = "missing" ] || WAN_STATE="not_physical" ;; esac
[ "${WAN_STATE}" = "not_physical" ] && log "WARNING: ${WAN} (type ${WAN_TYPE}) is not a physical WAN; the tests are skipped. Pass it with --wan (e.g. ppp0)."
printf '%s\n' "${WAN:-none}" | grep -Eq '^[A-Za-z0-9_.-]{1,15}$' || WAN="none"
# Without a working physical WAN the tests would follow some other route (maybe the VPN): skip them.
wan_ok() { [ "${WAN_STATE}" != "missing" ] && [ "${WAN_STATE}" != "down" ] && [ "${WAN_STATE}" != "not_physical" ] && [ -n "${WAN_IP}" ]; }
HAVE_TCPDUMP=0; command -v tcpdump >/dev/null 2>&1 && HAVE_TCPDUMP=1
HAVE_CT=0
if command -v conntrack >/dev/null 2>&1 || [ -r /proc/net/nf_conntrack ]; then HAVE_CT=1; fi

# iptables -S with a lock wait: "-w N" (iptables 1.6+), a plain "-w" (1.4.21, as on
# Keenetic, tried after no wait at all, with a time limit).
ipt_s() {
    iptables -w 5 "$@" 2>/dev/null && return 0
    iptables "$@" 2>/dev/null && return 0
    # 1.4.21 with the lock held: wait for it, but never forever
    command -v timeout >/dev/null 2>&1 && timeout 10 iptables -w "$@" 2>/dev/null
}

# The rules of table $1 that router-originated packets pass: OUTPUT and the chains it
# jumps to (4 levels; Keenetic jumps to its own _NDM_* chains). Returns 1 if OUTPUT
# cannot be read.
ipt_output_tree() {
    it_chains="OUTPUT"; it_seen=""; it_depth=0
    while [ -n "${it_chains}" ] && [ ${it_depth} -lt 4 ]; do
        it_next=""
        for it_c in ${it_chains}; do
            case " ${it_seen} " in *" ${it_c} "*) continue ;; esac
            it_seen="${it_seen} ${it_c}"
            if ! it_rules="$(ipt_s -t "$1" -S "${it_c}")"; then
                [ "${it_c}" = "OUTPUT" ] && return 1
                continue
            fi
            printf '%s\n' "${it_rules}"
            it_next="${it_next} $(printf '%s\n' "${it_rules}" | sed -n 's/.*-j \([A-Za-z0-9_-]*\).*/\1/p' \
                | grep -Ev '^(ACCEPT|RETURN|DROP|REJECT|MASQUERADE|SNAT|DNAT|REDIRECT|LOG|MARK|CONNMARK|TPROXY|TCPMSS|CT|NOTRACK)$')"
        done
        it_chains="${it_next}"; it_depth=$((it_depth + 1))
    done
    return 0
}

# Static checks for one server address. Sets RS_OK (1/0) and RS_REASONS.
route_static() {
    ip="$1"; RS_OK=1; RS_REASONS=""
    if [ "${WAN_STATE}" = "missing" ]; then RS_OK=0; RS_REASONS="wan_missing"; return 0; fi
    if [ "${WAN_STATE}" = "down" ] || [ -z "${WAN_IP}" ]; then RS_OK=0; RS_REASONS="wan_down"; return 0; fi
    dev="$(ip -4 route get "${ip}" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1)"
    if [ "${dev}" != "${WAN}" ]; then RS_OK=0; RS_REASONS="${RS_REASONS} main_route_via_${dev:-none}"; fi
    # Router-originated packets get a mark only from MARK/CONNMARK rules on their mangle
    # path (OUTPUT and the chains it jumps to); if there are any, every fwmark rule must
    # still lead to the WAN.
    mangle=""; nat=""
    if command -v iptables >/dev/null 2>&1; then
        if ! mangle="$(ipt_output_tree mangle)"; then
            RS_OK=0; RS_REASONS="${RS_REASONS} iptables_unreadable"      # fail closed
        fi
        # A REDIRECT/DNAT on router-originated traffic would send the test to a local proxy.
        if ! nat="$(ipt_output_tree nat)"; then
            RS_OK=0; RS_REASONS="${RS_REASONS} iptables_unreadable"
        elif printf '%s\n' "${nat}" | grep -Eq -- '-j (REDIRECT|DNAT|TPROXY)'; then
            RS_OK=0; RS_REASONS="${RS_REASONS} nat_output_redirect"
        fi
    fi
    if printf '%s\n' "${mangle}" | grep -Eq -- '-j (MARK|CONNMARK)'; then
        for m in $(ip -4 rule show 2>/dev/null | sed -n 's/.*fwmark \(0x[0-9a-fA-F]*\).*/\1/p' | sort -u); do
            mdev="$(ip -4 route get "${ip}" mark "${m}" 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n 1)"
            if [ -z "${mdev}" ]; then RS_OK=0; RS_REASONS="${RS_REASONS} mark_${m}_lookup_failed"
            elif [ "${mdev}" != "${WAN}" ]; then RS_OK=0; RS_REASONS="${RS_REASONS} mark_${m}_via_${mdev}"; fi
        done
    fi
    if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | awk '/hook output/ { o = 1 } o && /(redirect|dnat|tproxy)/ { f = 1 } /^\t}/ { o = 0 } END { exit !f }'; then
        RS_OK=0; RS_REASONS="${RS_REASONS} nft_output_redirect"
    fi
    return 0
}

# Evidence for one test flow. The router's own VPN (AWG Manager) may talk to the same
# server and port at the same time, so evidence must belong to the test client itself:
# the local ports of the test client's sockets (from /proc/PID/fd and /proc/net/*) are
# sampled while it runs, and only packets/conntrack entries from those ports count.
ip_hex() { echo "$1" | awk -F. '{ printf "%02X%02X%02X%02X", $4, $3, $2, $1 }'; }
capture_start() {   # $1 ip, $2 port, $3 tcp|udp
    CAP_PID=""; CAP_IP="$1"; CAP_PROTO="$3"; CAP_ACTIVE=1; SAMP_PID=""
    CAP_LOG="${T}/cap.log"; : > "${CAP_LOG}"; : > "${T}/ports.hex"; : > "${T}/client-tcp"
    [ "${HAVE_TCPDUMP}" = 1 ] && [ "${WAN_STATE}" != "missing" ] || return 0
    # TCP: SYNs only; UDP: QUIC long-header packets only (the handshake). So the log stays
    # small even when the router's own VPN carries heavy traffic to the same server.
    if [ "$3" = "tcp" ]; then f="tcp[tcpflags] & tcp-syn != 0"; else f="udp[8] & 0x80 != 0"; fi
    tcpdump -i "${WAN}" -p -n -l -q -s 96 "src host ${WAN_IP:-0.0.0.0} and dst host $1 and $3 dst port $2 and (${f})" >"${CAP_LOG}" 2>/dev/null &
    CAP_PID=$!
    child "${CAP_PID}"
    sleep 1
}
sampler_start() {   # $1 = pid of the test client
    [ "${CAP_ACTIVE:-0}" = 1 ] || return 0
    (
        hex="$(ip_hex "${CAP_IP}")"
        parent="$$"
        while kill -0 "$1" 2>/dev/null && kill -0 "${parent}" 2>/dev/null && [ -d "${T}" ]; do
            inodes="$(for fd in "/proc/$1/fd/"*; do readlink "${fd}" 2>/dev/null; done | sed -n 's/^socket:\[\([0-9]*\)\]$/\1/p' | tr '\n' ' ')"
            # TCP: sockets connected to the server; UDP (QUIC sockets are often unconnected): all of them.
            # Go opens dual-stack sockets: they are in the *6 tables, with an IPv4-mapped address.
            for table in "/proc/net/${CAP_PROTO}" "/proc/net/${CAP_PROTO}6"; do
                [ -r "${table}" ] || continue
                awk -v ino=" ${inodes} " -v h="${hex}" -v pr="${CAP_PROTO}" '
                    FNR > 1 && index(ino, " " $10 " ") {
                        split($3, r, ":")
                        if (pr == "udp" || r[1] == h || r[1] == ("0000000000000000FFFF0000" h)) { split($2, a, ":"); print a[2] }
                    }' "${table}" 2>/dev/null >> "${T}/ports.hex"
            done
            # any TCP connection of the client to the server (an HTTP/3 test must not have one)
            for table in /proc/net/tcp /proc/net/tcp6; do
                [ -r "${table}" ] || continue
                awk -v ino=" ${inodes} " -v h="${hex}" 'FNR > 1 && index(ino, " " $10 " ") {
                        split($3, r, ":"); if (r[1] == h || r[1] == ("0000000000000000FFFF0000" h)) print "tcp" }' \
                    "${table}" 2>/dev/null >> "${T}/client-tcp"
            done
            sleep 0.5 2>/dev/null || sleep 1
        done
    ) &
    SAMP_PID=$!
    child "${SAMP_PID}"
}
capture_stop() {   # sets EV ("tcpdump" when packets from the test client's ports left through the WAN), OURPORTS
    EV=""; CAP_ACTIVE=0
    stop_pid "${SAMP_PID}"; SAMP_PID=""
    OURPORTS=" $(sort -u "${T}/ports.hex" 2>/dev/null | while read -r h; do [ -n "${h}" ] && printf '%d ' "0x${h}"; done)"
    # NAT on the router may change the source port (masquerade --random-fully): conntrack
    # gives the port the packets really left with
    if [ "${HAVE_CT}" = 1 ] && [ -n "${OURPORTS# }" ]; then
        OURPORTS="${OURPORTS}$({ conntrack -L -d "${CAP_IP}" 2>/dev/null || cat /proc/net/nf_conntrack 2>/dev/null; } | awk -v ours="${OURPORTS} " -v s="${CAP_IP}" '
            { n = 0; m = 0; d1 = ""; sp = ""; dp2 = ""; for (i = 1; i <= NF; i++) {
                  if ($i ~ /^dst=/) { n++; if (n == 1) d1 = substr($i, 5) }
                  if ($i ~ /^sport=/ && m == 0) { sp = substr($i, 7); m = 1 }
                  if ($i ~ /^dport=/) dp2 = substr($i, 7) }
              if (d1 == s && index(ours, " " sp " ")) printf "%s ", dp2 }')"
    fi
    if [ "${PROBE_DEBUG:-0}" = 1 ]; then
        log "debug: test client ports:${OURPORTS}; WAN packets to the server: $(wc -l < "${CAP_LOG}" 2>/dev/null)"
        head -n 3 "${CAP_LOG}" >&2 2>/dev/null
    fi
    if [ -n "${CAP_PID}" ]; then
        stop_pid "${CAP_PID}"; CAP_PID=""
        # "12:00:00.000000 IP 10.0.0.2.54321 > 192.0.2.1.443: tcp 0" -> 54321
        for p in $(awk '{ for (i = 2; i <= NF; i++) if ($i == ">") { n = split($(i - 1), a, "."); print a[n] } }' "${CAP_LOG}" | sort -u); do
            case "${OURPORTS}" in *" ${p} "*) EV="tcpdump"; break ;; esac
        done
    fi
    return 0
}
# conntrack: an entry from one of the test client's ports at the WAN address to the server
# whose expected reply comes from the server itself (a local redirect would show
# 127.0.0.1): proof that the flow was not redirected and left with the WAN address.
conntrack_evidence() {   # $1 ip, $2 port, $3 tcp|udp
    [ "${HAVE_CT}" = 1 ] && [ -n "${WAN_IP}" ] && [ -n "${OURPORTS# }" ] || return 1
    { conntrack -L -p "$3" -d "$1" 2>/dev/null || cat /proc/net/nf_conntrack 2>/dev/null; } | awk -v w="${WAN_IP}" -v s="$1" -v p="$2" -v pr="$3" -v ours="${OURPORTS} " '
        { n = 0; dp = ""; sp = ""; proto = 0
          for (i = 1; i <= NF; i++) {
              if ($i == pr) proto = 1
              if ($i ~ /^(src|dst)=/) { n++; v[n] = substr($i, 5) }
              if ($i ~ /^dport=/ && dp == "") dp = substr($i, 7)
              if ($i ~ /^sport=/ && sp == "") sp = substr($i, 7)
          }
          if (proto && n >= 4 && v[1] == w && v[2] == s && v[3] == s && v[4] == w && dp == p && index(ours, " " sp " ")) f = 1 }
        END { exit !f }'
}
# Packets from the test client's own ports seen leaving through the WAN prove the physical
# path: a policy/mark rule or a local redirect would have sent them elsewhere.
# conntrack is weaker evidence, so it counts only when the static checks are clean too.
route_status() {   # $1 ip, $2 port, $3 tcp|udp -> ROUTE (verified|route_unverified), ROUTE_HOW
    if [ -n "${EV}" ]; then
        ROUTE="verified"; ROUTE_HOW="${EV}${RS_REASONS:+ (notes:${RS_REASONS})}"; return 0
    fi
    if [ "${RS_OK}" = 1 ] && conntrack_evidence "$1" "$2" "$3"; then ROUTE="verified"; ROUTE_HOW="conntrack"; return 0; fi
    ROUTE="route_unverified"
    if [ "${RS_OK}" != 1 ]; then ROUTE_HOW="static:${RS_REASONS# }"
    elif [ "${HAVE_TCPDUMP}" = 0 ] && [ "${HAVE_CT}" = 0 ]; then ROUTE_HOW="no_evidence_tool(opkg install tcpdump)"
    elif [ -z "${OURPORTS# }" ]; then ROUTE_HOW="test_client_sockets_not_seen"
    else ROUTE_HOW="no_packets_from_the_test_client_on_${WAN}"; fi
}

# ---- measurements through a local SOCKS port --------------------------------
measure() {   # $1 SOCKS port. Sets M_OK, M_MED, M_PAY (ok|stall_after_20kb|fail|skipped), M_BYTES, M_ERR
    M_OK=0; times=""; M_ERR=""
    # One slow download keeps a tunnel connection open for several seconds, so the
    # route evidence can always find the test client's socket (short requests may
    # come and go between two samples).
    curl -s -o /dev/null --max-time 20 --limit-rate 4000 --socks5-hostname "127.0.0.1:$1" \
        "${PAYLOAD_URL}24000" >/dev/null 2>&1 &
    KEEP_PID=$!
    child "${KEEP_PID}"
    sleep 2
    i=0
    while [ ${i} -lt "${RUNS}" ]; do
        got=0
        for url in https://www.gstatic.com/generate_204 https://cp.cloudflare.com/generate_204; do
            out="$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 15 \
                --socks5-hostname "127.0.0.1:$1" "${url}" 2>/dev/null)"
            if [ "${out%% *}" = "204" ]; then got=1; times="${times} $(to_ms "${out#* }")"; break; fi
        done
        [ ${got} = 1 ] && M_OK=$((M_OK + 1))
        i=$((i + 1))
    done
    M_MED="$(printf '%s\n' "${times}" | median)"
    M_PAY="skipped"; M_BYTES=0
    if [ "${PAYLOAD_BYTES}" -gt 0 ] && [ ${M_OK} -gt 0 ]; then
        out="$(curl -s -o /dev/null -w '%{http_code} %{size_download}' --max-time 60 \
            --socks5-hostname "127.0.0.1:$1" "${PAYLOAD_URL}${PAYLOAD_BYTES}" 2>/dev/null)"
        rc=$?
        M_BYTES="$(printf '%s\n' "${out}" | awk '{ printf "%d", $2 }')"
        if [ "${M_BYTES}" -ge "${PAYLOAD_BYTES}" ]; then M_PAY="ok"
        elif [ "${M_BYTES}" -gt 20000 ]; then M_PAY="stall_after_20kb"; M_ERR="payload_stalled_rc${rc}"
        else M_PAY="fail"; M_ERR="payload_failed_rc${rc}"; fi
    fi
    [ ${M_OK} -gt 0 ] || M_ERR="no_response"
    kill "${KEEP_PID}" 2>/dev/null; wait "${KEEP_PID}" 2>/dev/null
}
status_of() {   # -> ok | degraded | fail
    if [ "${M_OK}" -eq 0 ]; then echo fail
    elif [ "${M_OK}" -lt "${RUNS}" ] || [ "${M_PAY}" = "stall_after_20kb" ] || [ "${M_PAY}" = "fail" ]; then echo degraded
    else echo ok; fi
}
classify_log() {   # $1 log file -> short error token
    if grep -Eqi 'reality verification failed|processed invalid connection' "$1"; then echo reality_auth_failed
    elif grep -Eqi 'certificate|x509|pinned|public key|unknown authority' "$1"; then echo certificate_rejected
    elif grep -Eqi 'auth(entication)? (failed|error)|status code 40[0-9]|unauthorized' "$1"; then echo auth_failed
    elif grep -Eqi 'timeout|deadline|i/o timeout|no recent network activity' "$1"; then echo transport_timeout
    elif grep -Eqi 'refused' "$1"; then echo connection_refused
    elif grep -Eqi 'reset by peer|connection reset' "$1"; then echo connection_reset
    elif grep -Eqi 'no route|unreachable' "$1"; then echo unreachable
    else echo unknown; fi
}

# sing-box with one outbound ($1 = outbound JSON), a SOCKS inbound on $2; log to $3
sb_start() {
    printf '{"log":{"level":"warn","timestamp":false},"inbounds":[{"type":"socks","tag":"in","listen":"127.0.0.1","listen_port":%s}],"outbounds":[%s],"route":{"final":"probe"}}\n' \
        "$2" "$1" > "${T}/sb.json"
    chmod 600 "${T}/sb.json"
    if ! "${SINGBOX}" check -c "${T}/sb.json" >"$3" 2>&1; then SB_PID=""; return 1; fi
    # under its own name, so AWG Manager never mistakes it for its own sing-box
    ln -sf "${SINGBOX}" "${T}/probe-sing-box"
    "${T}/probe-sing-box" run -c "${T}/sb.json" >"$3" 2>&1 &
    SB_PID=$!
    child "${SB_PID}"
    wait_port "$2" "${SB_PID}" || { stop_pid "${SB_PID}"; SB_PID=""; return 1; }
    sampler_start "${SB_PID}"
    return 0
}
sb_stop() { stop_pid "${SB_PID}"; SB_PID=""; rm -f "${T}/sb.json"; }

# ---- results -----------------------------------------------------------------
RESULTS="${T}/results.json"; : > "${RESULTS}"
SUMMARY="${T}/summary.txt"; : > "${SUMMARY}"
NOW="$(date +%s)"
# One random id per run: the server imports a run once (no replays).
RUN_ID="$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')"
printf '%s' "${RUN_ID}" | grep -Eq '^[0-9a-f]{16}$' || RUN_ID="$(printf '%016x' "$$${NOW}" 2>/dev/null | cut -c1-16)"
HMAC_OK=0
if hmac_selftest; then HMAC_OK=1; else log "WARNING: HMAC self-test failed (sha256sum/printf on this router); results are not signed and the server will not use them"; fi
# The server ignores results with a wrong time: the router clock must be right (NTP).
[ "${NOW}" -gt 1780000000 ] || log "WARNING: the router clock looks wrong ($(date)); the server will reject these results"
emit_test() {   # test sni port status ok attempts median payload bytes error route route_how
    rec="v2|${NOW}|${RUN_ID}|${P_SERVER}|${WAN}|$1|$2|$3|${11}|$4|$5/$6|$7|$9|$(printf '%s\n' "${10}" | tr -c 'a-z0-9_\n' '_' | cut -c1-40)"
    mac="$(mac_of "${rec}")"
    printf '%s{"test":"%s","sni":"%s","port":%s,"status":"%s","ok":%s,"attempts":%s,"median_ms":%s,"payload":"%s","payload_bytes":%s,"error":"%s","route":"%s","route_evidence":"%s"}' \
        "${SEP_T}" "$1" "$2" "$3" "$4" "$5" "$6" "$7" "$8" "$9" "$(json_str "${10}")" "${11}" "$(json_str "${12}")" >> "${T}/tests.json"
    printf '%s{"r":"%s","mac":"%s"}' "${SEP_T}" "${rec}" "${mac}" >> "${T}/records.json"
    printf '%s\n' "${rec}" >> "${T}/records.txt"
    SEP_T=","
    printf '  %-12s %-28s %-8s %s/%s ok, median %s ms, payload %s (%s B)%s; route: %s %s\n' \
        "$1" "$2" "$4" "$5" "$6" "$7" "$8" "$9" "$([ -n "${10}" ] && echo ", ${10}")" "${11}" "${12}" >> "${SUMMARY}"
}

# ---- profiles ----------------------------------------------------------------
pget() { sed -n "s/^$2=//p" "$1" | head -n 1 | tr -d '\r'; }
valid() { printf '%s\n' "$1" | grep -Eq "^$2\$"; }
RE_IP='[0-9]{1,3}(\.[0-9]{1,3}){3}'
RE_DOM='[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?'
RE_PORT='[0-9]{1,5}'
load_profile() {   # $1 file -> P_* variables, returns 1 if invalid
    f="$1"
    case "$(ls -l "${f}" 2>/dev/null | cut -c5-10)" in
        ------) ;; *) log "WARNING: ${f} can be read by other users (it holds passwords): chmod 600 ${f}" ;;
    esac
    for k in NAME SERVER KEY HY2_PORT HY2_SNI HY2_PASSWORD HY2_PIN_SPKI REALITY_PORT REALITY_SNI REALITY_UUID REALITY_PBK REALITY_SID REALITY_FP TT_PORT TT_SNI TT_USER TT_PASS TT_CERT_B64; do
        eval "P_${k}=\$(pget \"\${f}\" P_${k})"
    done
    valid "${P_NAME}" '[A-Za-z0-9_-]{1,32}' || return 1
    valid "${P_SERVER}" "${RE_IP}" || return 1
    valid "${P_KEY}" '[0-9a-f]{64}' || return 1
    if [ -n "${P_HY2_PASSWORD}" ]; then
        valid "${P_HY2_PORT}" "${RE_PORT}" && valid "${P_HY2_SNI}" "${RE_DOM}" && valid "${P_HY2_PASSWORD}" '([a-z0-9_-]{1,32}:)?[A-Za-z0-9._~-]{8,128}' \
            && valid "${P_HY2_PIN_SPKI}" '[A-Za-z0-9+/]{43}=' || return 1
    fi
    if [ -n "${P_REALITY_UUID}" ]; then
        valid "${P_REALITY_PORT}" "${RE_PORT}" && valid "${P_REALITY_SNI}" "${RE_DOM}" \
            && valid "${P_REALITY_UUID}" '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' \
            && valid "${P_REALITY_PBK}" '[A-Za-z0-9_-]{43}' && valid "${P_REALITY_SID}" '[0-9a-f]{0,16}' \
            && valid "${P_REALITY_FP}" '[a-z0-9]{1,20}' || return 1
    fi
    if [ -n "${P_TT_USER}" ]; then
        valid "${P_TT_PORT}" "${RE_PORT}" && valid "${P_TT_SNI}" "${RE_DOM}" && valid "${P_TT_USER}" '[A-Za-z0-9._-]{1,64}' \
            && valid "${P_TT_PASS}" '[A-Za-z0-9._~-]{8,128}' && valid "${P_TT_CERT_B64}" '[A-Za-z0-9+/=]+' || return 1
        # (a length check outside the regex: musl and BusyBox allow repetition counts up to 255 only)
        [ "${#P_TT_CERT_B64}" -ge 100 ] && [ "${#P_TT_CERT_B64}" -le 20000 ] || return 1
    fi
    return 0
}

if [ -z "${PROFILES}" ]; then
    for f in "${PROFILE_DIR}"/*.env; do [ -f "${f}" ] && PROFILES="${PROFILES} ${f}"; done
fi
[ -n "${PROFILES# }" ] || die "no server profiles: copy each server's /root/hy2-probe.env to ${PROFILE_DIR}/NAME.env"

# ---- AWG Manager check: does the router pin the Hysteria certificate? -------
awg_check() {   # $1 server ip, $2 expected key pin -> AWG_JSON fragment, one summary line
    AWG_JSON='{"checked":false}'
    if [ ! -d "${AWG_CONFIG_DIR}" ]; then AWG_JSON='{"checked":false,"reason":"no AWG Manager config"}'; return 0; fi
    if ! command -v jq >/dev/null 2>&1; then AWG_JSON='{"checked":false,"reason":"jq missing (opkg install jq)"}'; return 0; fi
    if ! res="$(cat "${AWG_CONFIG_DIR}"/*.json 2>/dev/null | jq -s -r --arg ip "$1" --arg pin "$2" '
        [ .[] | .outbounds[]? | select(.type == "hysteria2" and .server == $ip) ] as $o
        | [ ($o | length),
            ($o | map(select((.tls.certificate_public_key_sha256 // []) | index($pin))) | length),
            ($o | map(select(((.tls.certificate_public_key_sha256 // []) | length) == 0 and ((.tls.certificate // []) | length) == 0 and .tls.insecure == true)) | length) ]
        | @tsv' 2>/dev/null)" || [ -z "${res}" ]; then
        AWG_JSON='{"checked":false,"reason":"jq could not read the AWG Manager config"}'; return 0
    fi
    set -- ${res}
    AWG_JSON="{\"checked\":true,\"hysteria2_outbounds\":$1,\"pinned_with_this_key\":$2,\"insecure_without_pin\":$3}"
    if [ "$1" = 0 ]; then echo "  AWG Manager: no Hysteria outbound for this server"
    elif [ "$3" -gt 0 ]; then echo "  AWG Manager: $3 Hysteria outbound(s) with insecure=true and NO pin: the certificate is not checked (import section 6 of the client file)"
    else echo "  AWG Manager: $2 of $1 Hysteria outbound(s) pin this server's key"; fi
}

# ---- tests -------------------------------------------------------------------
cert_json() {   # PEM from the profile, as a JSON string
    printf '%s' "${P_TT_CERT_B64}" | b64d | tr -d '\r' | sed 's/$/\\n/' | tr -d '\n'
}
test_reality() {   # $1 SNI, $2 test name
    if ! wan_ok; then emit_test "$2" "$1" "${P_REALITY_PORT}" skipped 0 0 0 skipped 0 "wan_${WAN_STATE}" route_unverified ""; return 0; fi
    if [ -z "${SINGBOX}" ]; then emit_test "$2" "$1" "${P_REALITY_PORT}" skipped 0 0 0 skipped 0 missing_singbox route_unverified ""; return 0; fi
    port="$(free_port)"
    ob="{\"type\":\"vless\",\"tag\":\"probe\",\"server\":\"${P_SERVER}\",\"server_port\":${P_REALITY_PORT},\"uuid\":\"${P_REALITY_UUID}\",\"flow\":\"xtls-rprx-vision\",\"bind_interface\":\"${WAN}\",\"tls\":{\"enabled\":true,\"server_name\":\"$1\",\"utls\":{\"enabled\":true,\"fingerprint\":\"${P_REALITY_FP}\"},\"reality\":{\"enabled\":true,\"public_key\":\"${P_REALITY_PBK}\",\"short_id\":\"${P_REALITY_SID}\"}}}"
    capture_start "${P_SERVER}" "${P_REALITY_PORT}" tcp
    if ! sb_start "${ob}" "${port}" "${T}/sb.log"; then
        capture_stop
        emit_test "$2" "$1" "${P_REALITY_PORT}" skipped 0 0 0 skipped 0 "singbox_rejected_config" route_unverified ""; return 0
    fi
    measure "${port}"
    sb_stop; capture_stop; route_status "${P_SERVER}" "${P_REALITY_PORT}" tcp
    st="$(status_of)"; err="${M_ERR}"
    [ "${st}" = "fail" ] && err="$(classify_log "${T}/sb.log")"
    emit_test "$2" "$1" "${P_REALITY_PORT}" "${st}" "${M_OK}" "${RUNS}" "${M_MED}" "${M_PAY}" "${M_BYTES}" "${err}" "${ROUTE}" "${ROUTE_HOW}"
}
hy2_outbound() {   # $1 pin (base64) or "" for insecure, $2 password (default: the real one)
    if [ -n "$1" ]; then tls="\"certificate_public_key_sha256\":[\"$1\"]"; else tls="\"insecure\":true"; fi
    echo "{\"type\":\"hysteria2\",\"tag\":\"probe\",\"server\":\"${P_SERVER}\",\"server_port\":${P_HY2_PORT},\"password\":\"${2:-${P_HY2_PASSWORD}}\",\"bind_interface\":\"${WAN}\",\"tls\":{\"enabled\":true,\"server_name\":\"${P_HY2_SNI}\",${tls}}}"
}
test_hysteria() {
    PIN_ENFORCED="untested"
    if ! wan_ok; then emit_test hysteria2 "${P_HY2_SNI}" "${P_HY2_PORT}" skipped 0 0 0 skipped 0 "wan_${WAN_STATE}" route_unverified ""; return 0; fi
    if [ -z "${SINGBOX}" ]; then emit_test hysteria2 "${P_HY2_SNI}" "${P_HY2_PORT}" skipped 0 0 0 skipped 0 missing_singbox route_unverified ""; return 0; fi
    port="$(free_port)"
    capture_start "${P_SERVER}" "${P_HY2_PORT}" udp
    if ! sb_start "$(hy2_outbound "${P_HY2_PIN_SPKI}")" "${port}" "${T}/sb.log"; then
        capture_stop
        emit_test hysteria2 "${P_HY2_SNI}" "${P_HY2_PORT}" skipped 0 0 0 skipped 0 singbox_rejected_config route_unverified ""; return 0
    fi
    measure "${port}"
    sb_stop; capture_stop; route_status "${P_SERVER}" "${P_HY2_PORT}" udp
    st="$(status_of)"; err="${M_ERR}"
    if [ "${st}" = "fail" ]; then
        err="$(classify_log "${T}/sb.log")"
        # Same server without the pin but with a throwaway password (the real one must never
        # go to a server whose key did not match): if TLS then gets as far as authentication,
        # the server presents a different certificate - a possible interception.
        if [ "${err}" = "certificate_rejected" ] && \
           sb_start "$(hy2_outbound "" "probe-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')")" "${port}" "${T}/sb2.log"; then
            curl -s -o /dev/null --max-time 10 --socks5-hostname "127.0.0.1:${port}" https://cp.cloudflare.com/generate_204 2>/dev/null
            sb_stop
            if grep -Eqi 'auth(entication)? (failed|error)|status code 40[0-9]|unauthorized' "${T}/sb2.log"; then
                err="certificate_mismatch_possible_mitm"
            fi
        fi
    else
        # Pinning must really be enforced by this sing-box: a wrong pin has to fail.
        case "${P_HY2_PIN_SPKI}" in A*) bad="B$(printf '%s' "${P_HY2_PIN_SPKI}" | cut -c2-)" ;; *) bad="A$(printf '%s' "${P_HY2_PIN_SPKI}" | cut -c2-)" ;; esac
        if sb_start "$(hy2_outbound "${bad}")" "${port}" "${T}/sb2.log"; then
            out="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 --socks5-hostname "127.0.0.1:${port}" https://cp.cloudflare.com/generate_204 2>/dev/null)"
            sb_stop
            if [ "${out}" = "204" ]; then PIN_ENFORCED="no"; else PIN_ENFORCED="yes"; fi
        fi
    fi
    emit_test hysteria2 "${P_HY2_SNI}" "${P_HY2_PORT}" "${st}" "${M_OK}" "${RUNS}" "${M_MED}" "${M_PAY}" "${M_BYTES}" "${err}" "${ROUTE}" "${ROUTE_HOW}"
}
TT_MODE=""
tt_detect() {   # sing-box with trusttunnel (AWG Manager's fork), else the TrustTunnel client
    [ -n "${TT_MODE}" ] && return 0
    TT_MODE="none"
    if [ -n "${SINGBOX}" ]; then
        printf '{"log":{"level":"error"},"outbounds":[{"type":"trusttunnel","tag":"t","server":"127.0.0.1","server_port":1,"username":"u","password":"p","tls":{"enabled":true,"server_name":"a.example"}}]}' > "${T}/ttcheck.json"
        if "${SINGBOX}" check -c "${T}/ttcheck.json" >/dev/null 2>&1; then TT_MODE="singbox"; fi
        rm -f "${T}/ttcheck.json"
    fi
    if [ "${TT_MODE}" = "none" ] && [ -n "${TT_CLIENT}" ] && [ -x "${TT_CLIENT}" ]; then TT_MODE="client"; fi
}
test_tt() {   # $1 = h2 | h3
    tt_detect
    proto=tcp; quic=false; up=http2
    if [ "$1" = "h3" ]; then proto=udp; quic=true; up=http3; fi
    if ! wan_ok; then emit_test "tt_$1" "${P_TT_SNI}" "${P_TT_PORT}" skipped 0 0 0 skipped 0 "wan_${WAN_STATE}" route_unverified ""; return 0; fi
    if [ "${TT_MODE}" = "none" ]; then
        emit_test "tt_$1" "${P_TT_SNI}" "${P_TT_PORT}" skipped 0 0 0 skipped 0 no_trusttunnel_client route_unverified ""; return 0
    fi
    port="$(free_port)"
    capture_start "${P_SERVER}" "${P_TT_PORT}" "${proto}"
    started=0
    if [ "${TT_MODE}" = "singbox" ]; then
        ob="{\"type\":\"trusttunnel\",\"tag\":\"probe\",\"server\":\"${P_SERVER}\",\"server_port\":${P_TT_PORT},\"username\":\"${P_TT_USER}\",\"password\":\"${P_TT_PASS}\",\"quic\":${quic},\"bind_interface\":\"${WAN}\",\"tls\":{\"enabled\":true,\"server_name\":\"${P_TT_SNI}\",\"certificate\":[\"$(cert_json)\"]}}"
        sb_start "${ob}" "${port}" "${T}/sb.log" && started=1
    else
        {
            printf 'loglevel = "info"\nvpn_mode = "general"\nkillswitch_enabled = false\n\n[endpoint]\n'
            printf 'hostname = "%s"\naddresses = ["%s:%s"]\nusername = "%s"\npassword = "%s"\n' "${P_TT_SNI}" "${P_SERVER}" "${P_TT_PORT}" "${P_TT_USER}" "${P_TT_PASS}"
            printf 'has_ipv6 = false\nskip_verification = false\nupstream_protocol = "%s"\n' "${up}"
            printf "certificate = '''\n%s\n'''\n" "$(printf '%s' "${P_TT_CERT_B64}" | b64d)"
            printf '\n[listener.socks]\naddress = "127.0.0.1:%s"\n' "${port}"
        } > "${T}/tt.toml"
        "${TT_CLIENT}" --config "${T}/tt.toml" > "${T}/sb.log" 2>&1 &
        SB_PID=$!; child "${SB_PID}"
        if wait_port "${port}" "${SB_PID}"; then started=1; sampler_start "${SB_PID}"; sleep 2; fi
    fi
    if [ ${started} = 0 ]; then
        stop_pid "${SB_PID}"; capture_stop; rm -f "${T}/tt.toml"
        emit_test "tt_$1" "${P_TT_SNI}" "${P_TT_PORT}" skipped 0 0 0 skipped 0 "${TT_MODE}_did_not_start" route_unverified ""; return 0
    fi
    measure "${port}"
    stop_pid "${SB_PID}"; SB_PID=""; rm -f "${T}/sb.json" "${T}/tt.toml"
    capture_stop; route_status "${P_SERVER}" "${P_TT_PORT}" "${proto}"
    st="$(status_of)"; err="${M_ERR}"
    [ "${st}" = "fail" ] && err="$(classify_log "${T}/sb.log")"
    # HTTP/3 must really be QUIC: the packets to the server have to be UDP. The TrustTunnel
    # client falls back to HTTP/2 by itself, which would look like an HTTP/3 success.
    if [ "$1" = "h3" ] && [ "${st}" != "fail" ] && [ -s "${T}/client-tcp" ]; then
        st="fail"; err="fell_back_to_http2"
    fi
    emit_test "tt_$1" "${P_TT_SNI}" "${P_TT_PORT}" "${st}" "${M_OK}" "${RUNS}" "${M_MED}" "${M_PAY}" "${M_BYTES}" "${err}" "${ROUTE}" "${ROUTE_HOW}"
}

# ---- run ---------------------------------------------------------------------
log "Veiltrium keenetic-vpn-probe ${PROBE_VERSION}: $(uname -m), sing-box ${SB_VERSION:-missing}, WAN ${WAN:-?} (${WAN_STATE}), evidence: tcpdump=${HAVE_TCPDUMP} conntrack=${HAVE_CT}"
SEP_S=""
printf '{"schema":"hy2-vpn-probe/1","generated_at":"%s","epoch":%s,' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "${NOW}" > "${RESULTS}"
printf '"probe":{"tool":"keenetic-vpn-probe","version":%s,"run_id":"%s","arch":"%s","singbox":"%s","tt_client":"%s","signed":"%s"},' \
    "${PROBE_VERSION}" "${RUN_ID}" "$(uname -m)" "$(json_str "${SB_VERSION}")" "$([ -n "${TT_CLIENT}" ] && echo present || echo none)" \
    "$([ "${HMAC_OK}" = 1 ] && echo hmac-sha256 || echo none)" >> "${RESULTS}"
printf '"wan":{"interface":"%s","type":"%s","state":"%s","has_ipv4":%s,"tcpdump":%s,"conntrack":%s},"servers":[' \
    "$(json_str "${WAN}")" "$(json_str "${WAN_TYPE}")" "$(json_str "${WAN_STATE}")" "$([ -n "${WAN_IP}" ] && echo true || echo false)" \
    "$([ ${HAVE_TCPDUMP} = 1 ] && echo true || echo false)" "$([ ${HAVE_CT} = 1 ] && echo true || echo false)" >> "${RESULTS}"
BAD_PROFILES=0
for f in ${PROFILES}; do
    if [ ! -r "${f}" ] || ! load_profile "${f}"; then
        log "invalid or unreadable profile: ${f}"; BAD_PROFILES=$((BAD_PROFILES + 1)); continue
    fi
    : > "${T}/tests.json"; : > "${T}/records.json"; : > "${T}/records.txt"; SEP_T=""; PIN_ENFORCED="untested"; AWG_JSON='{"checked":false}'
    if [ "${HMAC_OK}" = 1 ]; then hmac_prepare "${P_KEY}"; fi
    echo "${P_NAME} (${P_SERVER}):" >> "${SUMMARY}"
    route_static "${P_SERVER}"
    [ "${RS_OK}" = 1 ] || echo "  route: static checks failed: ${RS_REASONS# }" >> "${SUMMARY}"
    if [ "${DO_REALITY}" = 1 ] && [ -n "${P_REALITY_UUID}" ]; then
        test_reality "${P_REALITY_SNI}" reality
        for s in $(echo "${TRIAL_SNI}" | tr ',' ' '); do test_reality "${s}" reality_trial; done
    fi
    if [ "${DO_HY2}" = 1 ] && [ -n "${P_HY2_PASSWORD}" ]; then test_hysteria; echo "  hysteria2 key pinning enforced by this sing-box: ${PIN_ENFORCED}" >> "${SUMMARY}"; fi
    if [ "${DO_TT}" = 1 ] && [ -n "${P_TT_USER}" ]; then test_tt h2; test_tt h3; fi
    if [ "${CHECK_AWG}" = 1 ] && [ -n "${P_HY2_PIN_SPKI}" ]; then awg_check "${P_SERVER}" "${P_HY2_PIN_SPKI}" >> "${SUMMARY}"; fi
    # The run header binds all lines of this server together (count and hash): no line can
    # be dropped or added without breaking its signature.
    nrec="$(wc -l < "${T}/records.txt" | tr -d ' ')"
    hdr="v2run|${NOW}|${RUN_ID}|${P_SERVER}|${WAN}|${nrec}|$(${SHA:-sha256sum} < "${T}/records.txt" | cut -c1-64)"
    printf '%s{"name":"%s","server":"%s","route_static":{"ok":%s,"reasons":"%s"},"hysteria2_pin_enforced":"%s","awg_manager":%s,"tests":[%s],"run":{"h":"%s","mac":"%s"},"records":[%s]}' \
        "${SEP_S}" "${P_NAME}" "${P_SERVER}" "$([ "${RS_OK}" = 1 ] && echo true || echo false)" "$(json_str "${RS_REASONS# }")" \
        "${PIN_ENFORCED}" "${AWG_JSON}" "$(cat "${T}/tests.json")" "${hdr}" "$(mac_of "${hdr}")" "$(cat "${T}/records.json")" >> "${RESULTS}"
    SEP_S=","
done
printf '],"invalid_profiles":%s}\n' "${BAD_PROFILES}" >> "${RESULTS}"

cat "${SUMMARY}" >&2
log "Only results with route 'verified' count as home-network proof; a single success is not proof that DPI is bypassed."
[ "${HAVE_TCPDUMP}" = 1 ] || log "Without tcpdump the route can rarely be verified on Keenetic: opkg install tcpdump"
[ "${TT_MODE}" != "client" ] || log "Note: the TrustTunnel client is not bound to the WAN (unlike sing-box); its route is verified only by the packets seen there."
if [ -n "${OUTPUT}" ]; then
    cp "${RESULTS}" "${OUTPUT}" && chmod 600 "${OUTPUT}" && log "JSON (no secrets): ${OUTPUT}"
else
    cat "${RESULTS}"
fi
[ "${BAD_PROFILES}" = 0 ] || exit 3
exit 0
