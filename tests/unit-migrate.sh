#!/usr/bin/env bash
# Unit tests for moving a node (--export / --import): the round trip, a wrong passphrase,
# damaged and hostile archives, hostile state files, and the identity rule. No network, no
# root, no servers: the state lives in temporary directories (the path variables of
# veiltrium.sh are pointed at them).
# shellcheck disable=SC2034,SC2046,SC2164
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
PASS="correct horse battery staple"

setpaths() {   # $1 = root of one imaginary server
    HY2_DIR="$1/etc/hysteria"; HY2_CONFIG="${HY2_DIR}/config.yaml"; HY2_CERT="${HY2_DIR}/server.crt"
    HY2_KEY="${HY2_DIR}/server.key"; HY2_STATE="${HY2_DIR}/node.env"
    XRAY_DIR="$1/usr/local/etc/xray"; XRAY_STATE="${XRAY_DIR}/reality.env"
    TT_DIR="$1/etc/trusttunnel"; TT_STATE="${TT_DIR}/node.env"
    SCANNER_DIR="$1/etc/veiltrium"; CANDIDATES_FILE="${SCANNER_DIR}/reality-candidates"
    PROBE_ENV="${SCANNER_DIR}/probe.env"; NODE_ENV="${SCANNER_DIR}/node.env"; CLIENTS_DIR="${SCANNER_DIR}/clients"
}

a48="$(printf 'a%.0s' {1..48})"; b48="$(printf 'b%.0s' {1..48})"; c48="$(printf 'c%.0s' {1..48})"
key43="$(printf 'K%.0s' {1..43})"; pub43="$(printf 'P%.0s' {1..43})"
newcert() {   # $1 = cert, $2 = key, $3 = name
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -keyout "$2" -out "$1" -days 30 \
        -subj "/CN=$3" -addext "subjectAltName=DNS:$3" >/dev/null 2>&1
}

# A whole node, written with the installer's own save functions where there are any.
mknode() {   # $1 = root, $2 = Hysteria password
    setpaths "$1"
    install -d -m 700 "${HY2_DIR}" "${XRAY_DIR}" "${TT_DIR}" "${SCANNER_DIR}" "${CLIENTS_DIR}"
    H_PASSWORD="$2"; HY2_SNI="www.sony.com"; HY2_PORT=443; H_MASQ="https://www.sony.com/page?x=1&y=2"; H_AUTH=userpass
    save_hy2_state
    newcert "${HY2_CERT}" "${HY2_KEY}" www.sony.com
    R_UUID="11111111-2222-4333-8444-555555555551"; R_PRIV="${key43}"; R_PUB="${pub43}"; R_SID="0123456789abcdef"; R_SITE="www.amazon.com"
    save_reality_state
    T_USER="u1234abcd"; T_PASS="${c48}"; T_SNI="www.nvidia.com"; TT_IPV6=false
    printf 'T_USER=%q\nT_PASS=%q\nT_SNI=%q\nT_IPV6=%q\n' "${T_USER}" "${T_PASS}" "${T_SNI}" "${TT_IPV6}" > "${TT_STATE}"
    newcert "${TT_DIR}/cert.pem" "${TT_DIR}/key.pem" www.nvidia.com
    N_NAME=PL; GLOBALPING=1; save_node_name 1
    printf 'PROBE_KEY=%q\nPROBE_SERVER=%q\n' "$(printf 'd%.0s' {1..64})" "192.0.2.10" > "${PROBE_ENV}"
    printf '# veiltrium: Reality mask site candidates (REALITY_CANDIDATES), one per line\nwww.yahoo.com\nwww.sony.com\n' > "${CANDIDATES_FILE}"
    write_client_env "${CLIENTS_DIR}/anna.env" anna 11111111-2222-4333-8444-555555555552 "${a48}" "${b48}" 2026-10-13
    write_client_env "${CLIENTS_DIR}/bob_2.env" bob_2 11111111-2222-4333-8444-555555555553 "${b48}" "${a48}" '?'
    PUBLIC_IP="192.0.2.10"; REALITY_PORT=443; TT_PORT=8443
}

# Runs a command in a subshell; sets RC and OUT (the log of the run).
try() { ( "$@" ) > "${T}/out.txt" 2>&1; RC=$?; OUT="$(cat "${T}/out.txt")"; }

# ---- the state files the installer writes pass the validator -------------------------
mknode "${T}/src" "${a48}"
check "$(env_file_ok "${HY2_STATE}" "H_PASSWORD H_SNI H_PORT" "H_MASQ H_AUTH"; echo $?)" 0 "validator: the Hysteria state with a URL (printf %q escapes) passes"
check "$(grep -c '\\' "${HY2_STATE}")" 1 "the saved masquerade URL really contains escapes"
check "$(env_file_ok "${XRAY_STATE}" "R_UUID R_PRIV R_PUB R_SID R_SITE" ""; echo $?)" 0 "validator: reality.env passes"
check "$(env_file_ok "${NODE_ENV}" "" "N_NAME N_GLOBALPING"; echo $?)" 0 "validator: the node name file with its comment passes"
check "$(env_file_ok "${CLIENTS_DIR}/bob_2.env" "C_NAME C_UUID C_HY2_PASS C_TT_PASS" "C_CREATED"; echo $?)" 0 "validator: a client file passes"

bad() {   # name, content (a state file that must be refused)
    printf '%b' "$2" > "${T}/bad.env"
    if env_file_ok "${T}/bad.env" "H_PASSWORD H_SNI H_PORT" "H_MASQ H_AUTH"; then check accepted refused "validator refuses $1"; else check refused refused "validator refuses $1"; fi
}
good_head="H_PASSWORD=${a48}\nH_SNI=www.sony.com\nH_PORT=443\n"
bad "a command substitution in a value" "${good_head}H_MASQ=\$(id)\n"
bad "backticks in a value" "${good_head}H_MASQ=\`id\`\n"
bad "a command after a semicolon" "${good_head}H_AUTH=userpass;id\n"
bad "a second command line" "${good_head}id\n"
bad "a quoted value with a substitution" "${good_head}H_MASQ=\"\$(id)\"\n"
bad "\$'...' quoting" "${good_head}H_MASQ=\$'a'\n"
bad "an unescaped space" "${good_head}H_MASQ=https://a.example x\n"
bad "an escaped dollar sign (not a valid URL)" "${good_head}H_MASQ=https://a.example/\\\\\$x\n"
bad "an unknown key" "${good_head}PATH=/tmp\n"
bad "a repeated key" "${good_head}H_PORT=444\n"
bad "a missing key" "H_PASSWORD=${a48}\nH_SNI=www.sony.com\n"
bad "a bad value (port)" "H_PASSWORD=${a48}\nH_SNI=www.sony.com\nH_PORT=99999\n"
bad "a bad value (password)" "H_PASSWORD=short\nH_SNI=www.sony.com\nH_PORT=443\n"
bad "a carriage return" "${good_head}H_AUTH=userpass\r\n"
bad "a comment with a command" "${good_head}# veiltrium: \$(id)\n"
bad "an empty file" ""

# ---- round trip ---------------------------------------------------------------------
export VT_EXPORT_PASSPHRASE="${PASS}"
mkdir -p "${T}/w1"
TMPD="${T}/w1"; try export_node "${T}/node.vt"
check "${RC}" 0 "export: succeeds"
check "$(stat -c %a "${T}/node.vt")" 600 "export: the file is mode 600"
check "$(grep -c "${a48}" "${T}/node.vt")" 0 "export: no secret in clear text in the file"
check "$([[ "$(head -c 8 "${T}/node.vt")" == "Salted__" ]] && echo yes)" yes "export: pure openssl output (Salted__ header)"
check "$([[ -e "${T}/w1/export" || -e "${T}/w1/export.tar" ]] && echo left || echo clean)" clean "export: the staging files are removed"
case "${OUT}" in *"--import"*"NEW_IP"*|*"--import /root/node.vt"*) r=ok ;; *) r=missing ;; esac
check "${r}" ok "export: tells the next step"
try export_node "${T}/node.vt"
check "${RC}" 1 "export: refuses to overwrite an existing file"
TMPD="${T}/w1"; VT_EXPORT_PASSPHRASE="short" try export_node "${T}/other.vt"
check "$([[ ${RC} -ne 0 && ! -e "${T}/other.vt" ]] && echo refused)" refused "export: a passphrase under 12 characters is refused"
export VT_EXPORT_PASSPHRASE="${PASS}"
( setpaths "${T}/empty"; TMPD="${T}/w1"; export_node "${T}/none.vt" ) > "${T}/out.txt" 2>&1; RC=$?
check "$([[ ${RC} -ne 0 && ! -e "${T}/none.vt" ]] && echo refused)" refused "export: refuses when there is no node"

export VT_IMPORT_PASSPHRASE="${PASS}"
imp_run() {   # $1 = target root, $2 = file -> prints state of the run
    setpaths "$1"; REALITY_PORT_GIVEN=""; TT_PORT_GIVEN=""; REALITY_ENABLE_GIVEN=""; TT_ENABLE_GIVEN=""
    REALITY_PORT=443; TT_PORT=8443; REALITY_ENABLE=1; TT_ENABLE=1
    TMPD="${T}/w2"; rm -rf "${TMPD}"; mkdir -p "${TMPD}"
    import_node "$2"
    echo "FRESH=${IMPORT_FRESH} IMPORTED=${IMPORTED} OLD=${IMPORT_OLD_IP} RP=${REALITY_PORT} TP=${TT_PORT} RE=${REALITY_ENABLE} TE=${TT_ENABLE}"
}
try imp_run "${T}/dst" "${T}/node.vt"
check "${RC}" 0 "import onto an empty server: succeeds"
check "$(printf '%s\n' "${OUT}" | grep '^FRESH=')" "FRESH=1 IMPORTED=1 OLD=192.0.2.10 RP=443 TP=8443 RE=1 TE=1" "import: a new server, old address and ports noted"
same=1
for f in etc/hysteria/node.env etc/hysteria/server.crt etc/hysteria/server.key usr/local/etc/xray/reality.env etc/trusttunnel/node.env \
         etc/trusttunnel/cert.pem etc/trusttunnel/key.pem etc/veiltrium/probe.env etc/veiltrium/reality-candidates \
         etc/veiltrium/clients/anna.env etc/veiltrium/clients/bob_2.env; do
    cmp -s "${T}/src/${f}" "${T}/dst/${f}" || { same=0; echo "differs: ${f}"; }
done
check "${same}" 1 "round trip: every secret and name is identical"
check "$(grep -c '^N_NAME=' "${T}/dst/etc/veiltrium/node.env")" 0 "round trip: N_NAME is dropped (the country is detected again)"
check "$(grep -c '^N_GLOBALPING=1' "${T}/dst/etc/veiltrium/node.env")" 1 "round trip: the Globalping choice is kept"
check "$(stat -c %a "${T}/dst/etc/hysteria/server.key")" 600 "round trip: before the hysteria group exists the key is root-only"
check "$(ls "${T}/dst/etc/veiltrium" | tr '\n' ' ')" "clients node.env probe.env reality-candidates " "round trip: nothing else is placed (no panel password, no scanner list)"
check "$(ls -A "${T}/w2")" "" "import: the temporary files are removed"
# the placed files load with the installer's own loaders
( setpaths "${T}/dst"; VT_RECONFIGURE=0; CLIENT_FILE="${T}/none"; load_reality_state; load_hy2_state; load_tt_state; load_clients
  echo "${R_UUID} ${H_PASSWORD} ${H_SNI} ${H_PORT} ${T_USER} ${T_SNI} ${CL_NAMES[*]} ${H_MASQ}" ) > "${T}/out.txt" 2>&1
check "$(cat "${T}/out.txt")" "11111111-2222-4333-8444-555555555551 ${a48} www.sony.com 443 u1234abcd www.nvidia.com anna bob_2 https://www.sony.com/page?x=1&y=2" "the imported state loads with the installer's loaders"

# explicit settings win over the old node's ports and switches
imp_given() {
    setpaths "${T}/dst2"; REALITY_PORT_GIVEN=1; TT_PORT_GIVEN=1; REALITY_ENABLE_GIVEN=1; TT_ENABLE_GIVEN=1
    REALITY_PORT=4443; TT_PORT=9443; REALITY_ENABLE=1; TT_ENABLE=1
    TMPD="${T}/w2"; rm -rf "${TMPD}"; mkdir -p "${TMPD}"
    import_node "${T}/node.vt" >/dev/null
    echo "RP=${REALITY_PORT} TP=${TT_PORT}"
}
try imp_given
check "$(printf '%s\n' "${OUT}" | grep '^RP=')" "RP=4443 TP=9443" "import: REALITY_PORT / TT_PORT given explicitly win"

# a node on other ports without TrustTunnel and Reality
mknode "${T}/src2" "${b48}"
rm -rf "${T}/src2/etc/trusttunnel" "${T}/src2/usr/local/etc/xray/reality.env"
REALITY_PORT=8444; TT_PORT=9000
TMPD="${T}/w1"; try export_node "${T}/node2.vt"
check "${RC}" 0 "export: a node without Reality and TrustTunnel"
try imp_run "${T}/dst3" "${T}/node2.vt"
check "$(printf '%s\n' "${OUT}" | grep '^FRESH=')" "FRESH=1 IMPORTED=1 OLD=192.0.2.10 RP=8444 TP=9000 RE=0 TE=0" "import: the old node's ports and switches are applied"

# ---- wrong passphrase, damaged and hostile files ---------------------------------------------
( VT_IMPORT_PASSPHRASE="not the passphrase"; imp_run "${T}/dstw" "${T}/node.vt" ) > "${T}/out.txt" 2>&1; RC=$?
check "$([[ ${RC} -ne 0 && ! -e "${T}/dstw/etc/hysteria/node.env" ]] && echo refused)" refused "wrong passphrase: refused, nothing placed"
case "$(cat "${T}/out.txt")" in *"wrong passphrase or a damaged file"*) r=ok ;; *) r=unclear ;; esac
check "${r}" ok "wrong passphrase: a clear message"
size="$(stat -c %s "${T}/node.vt")"
for off in 40 $((size / 2)) $((size - 5)); do
    cp "${T}/node.vt" "${T}/tamper.vt"
    printf '\377\376' | dd of="${T}/tamper.vt" bs=1 seek="${off}" conv=notrunc 2>/dev/null
    try imp_run "${T}/dstt" "${T}/tamper.vt"
    check "$([[ ${RC} -ne 0 && ! -e "${T}/dstt/etc/hysteria/node.env" ]] && echo refused)" refused "tampered ciphertext (byte ${off}): refused, nothing placed"
done
head -c $((size - 100)) "${T}/node.vt" > "${T}/trunc.vt"
try imp_run "${T}/dstt" "${T}/trunc.vt"
check "$([[ ${RC} -ne 0 && ! -e "${T}/dstt/etc/hysteria/node.env" ]] && echo refused)" refused "truncated file: refused"
try imp_run "${T}/dstt" "${T}/does-not-exist.vt"
check "${RC}" 1 "a missing file: refused"
: > "${T}/empty.vt"
try imp_run "${T}/dstt" "${T}/empty.vt"
check "${RC}" 1 "an empty file: refused"

# archives built by hand around the valid tree (the manifest is made right, so only the defect is tested)
setpaths "${T}/src"
mkdir -p "${T}/base"
TMPD="${T}/w1"; mkdir -p "${TMPD}"; VT_PASS="${PASS}"
export_decrypt "${T}/node.vt" "${T}/base.tar"
tar -xf "${T}/base.tar" -C "${T}/base"
repack() {   # $1 = tree dir, $2 = output; $3.. = extra tar arguments (after the files)
    local tree="$1" out="$2" files
    shift 2
    files="$(cd "${tree}" && find . -type f ! -name MANIFEST | sed 's,^\./,,' | LC_ALL=C sort)"
    ( cd "${tree}" && xargs -d '\n' sha256sum -- <<<"${files}" > MANIFEST )
    # shellcheck disable=SC2046
    ( cd "${tree}" && tar --format=ustar --owner=0 --group=0 -cf "${T}/h.tar" MANIFEST $(printf '%s\n' "${files}") "$@" ) 2>/dev/null
    rm -f "${out}"
    openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -md sha256 -pass fd:3 -in "${T}/h.tar" -out "${out}" 3< <(printf '%s\n' "${PASS}")
}
attack() {   # name, expected message part; tree already prepared in ${T}/evil; $3.. extra tar args
    local name="$1" want="$2"
    shift 2
    repack "${T}/evil" "${T}/evil.vt" "$@"
    try imp_run "${T}/dste" "${T}/evil.vt"
    if [[ ${RC} -ne 0 && ! -e "${T}/dste/etc/hysteria/node.env" && "${OUT}" == *"${want}"* ]]; then check refused refused "refused: ${name}"
    else check "rc=${RC} ${OUT}" "refused with '${want}'" "refused: ${name}"; fi
}
fresh_evil() { rm -rf "${T}/evil" "${T}/dste"; cp -a "${T}/base" "${T}/evil"; rm -f "${T}/evil/MANIFEST"; }

fresh_evil; repack "${T}/evil" "${T}/ok.vt"
try imp_run "${T}/dste_ok" "${T}/ok.vt"
check "${RC}" 0 "control: the hand-made archive of the valid tree is accepted"

fresh_evil; echo x > "${T}/evil/zz"
attack "a path with .. (../x)" "unexpected file name" --transform='s,^zz$,../x,' zz
fresh_evil; echo x > "${T}/evil/zz"
attack "an absolute path" "unexpected file name" -P --transform='s,^zz$,/tmp/x,' zz
fresh_evil; ln -s /etc/passwd "${T}/evil/clients/evil.env"
attack "a symlink named like a client" "not a plain file" clients/evil.env
fresh_evil; ln "${T}/evil/hysteria/node.env" "${T}/evil/clients/hard.env"
attack "a hard link" "not a plain file" clients/hard.env
fresh_evil; echo x > "${T}/evil/extra.txt"
attack "an unknown file name" "unexpected file name" extra.txt
fresh_evil; echo x > "${T}/evil/clients/Bad_Name.env"
attack "a client file whose name breaks CLIENT_RE" "unexpected file name" clients/Bad_Name.env
fresh_evil; mkdir -p "${T}/evil/etc"; echo x > "${T}/evil/etc/passwd"
attack "a file in a folder that is not in the list" "unexpected file name" etc/passwd
fresh_evil; head -c 70000 /dev/zero | tr '\0' 'a' > "${T}/evil/clients/big.env"
attack "an oversized file" "oversized" clients/big.env
fresh_evil; for i in $(seq 1 300); do echo x > "${T}/evil/clients/c${i}.env"; done
attack "more than 300 files" "too many files" $(cd "${T}/evil" && printf 'clients/c%s.env ' $(seq 1 300))
fresh_evil; mkdir -p "${T}/evil/hysteria/sub"
attack "a folder entry" "not a plain file" hysteria/sub
fresh_evil
attack "a file added twice (tar stores the second as a link)" "not a plain file" meta
fresh_evil; : > "${T}/evil/clients/anna.env"; sed -i 's/^C_NAME=anna/C_NAME=bob_2/' "${T}/evil/clients/bob_2.env"
cp "${T}/base/clients/anna.env" "${T}/evil/clients/anna.env"; sed -i 's/^C_NAME=anna/C_NAME=carol/' "${T}/evil/clients/anna.env"
attack "a client file whose C_NAME differs from its file name" "does not match its file name"
fresh_evil; sed -i 's/^C_NAME=anna/C_NAME=Anna/' "${T}/evil/clients/anna.env"
attack "a client name that breaks CLIENT_RE inside the file" "bad clients/anna.env"
fresh_evil; sed -i 's/^C_NAME=bob_2/C_NAME=main/' "${T}/evil/clients/bob_2.env"
attack "a client called main inside a client file" "does not match its file name"
fresh_evil; printf 'H_PASSWORD=%s\nH_SNI=www.sony.com\nH_PORT=443\nH_MASQ=$(touch %s/pwned)\n' "${a48}" "${T}" > "${T}/evil/hysteria/node.env"
attack "a state file with \$(...)" "bad hysteria/node.env"
fresh_evil; printf 'R_UUID=11111111-2222-4333-8444-555555555551\nR_PRIV=%s\nR_PUB=%s\nR_SID=0123456789abcdef\nR_SITE=`touch %s/pwned`\n' "${key43}" "${pub43}" "${T}" > "${T}/evil/reality/reality.env"
attack "a state file with backticks" "bad reality/reality.env"
fresh_evil; echo 'T_USER=u;id' >> "${T}/evil/trusttunnel/node.env"
attack "a state file with a semicolon and an extra key" "bad trusttunnel/node.env"
fresh_evil; printf 'junk\n' > "${T}/evil/veiltrium/probe.env"
attack "a state file with a stray line" "bad veiltrium/probe.env"
fresh_evil; printf 'www.yahoo.com; id\n' > "${T}/evil/veiltrium/reality-candidates"
attack "a candidates file with a non-domain" "bad veiltrium/reality-candidates"
fresh_evil; newcert "${T}/evil/hysteria/server.crt" "${T}/other.key" www.sony.com
attack "a certificate that does not match its key" "not a pair"
fresh_evil; newcert "${T}/evil/hysteria/server.crt" "${T}/evil/hysteria/server.key" www.other.example
attack "a certificate for another name than H_SNI" "not a pair"
fresh_evil; echo "not a key" > "${T}/evil/hysteria/server.key"
attack "a key that is not a key" "not a pair"
fresh_evil; sed -i 's/^reality_port=.*/reality_port=99999/' "${T}/evil/meta"
attack "a bad meta" "bad meta"
fresh_evil; sed -i 's/^format=.*/format=other\/1/' "${T}/evil/meta"
attack "another format" "bad meta"
fresh_evil; rm -f "${T}/evil/reality/reality.env"
attack "meta and files disagreeing" "disagree about Reality"

# manifest games on a valid tree
fresh_evil; repack "${T}/evil" "${T}/m.vt"
echo "x" >> "${T}/evil/clients/anna.env"      # the content changes, the manifest stays (it is re-made by repack, so rebuild by hand)
( cd "${T}/evil" && tar --format=ustar --owner=0 --group=0 -cf "${T}/h.tar" MANIFEST $(find . -type f ! -name MANIFEST | sed 's,^\./,,' | sort) )
rm -f "${T}/m.vt"; openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -md sha256 -pass fd:3 -in "${T}/h.tar" -out "${T}/m.vt" 3< <(printf '%s\n' "${PASS}")
try imp_run "${T}/dstm" "${T}/m.vt"
check "$([[ ${RC} -ne 0 && "${OUT}" == *"manifest"* || "${OUT}" == *"checksum mismatch"* || "${OUT}" == *"bad clients"* ]] && echo refused)" refused "a file changed after the manifest was made: refused"
fresh_evil; repack "${T}/evil" "${T}/m.vt"
sed -i '$d' "${T}/evil/MANIFEST"
( cd "${T}/evil" && tar --format=ustar --owner=0 --group=0 -cf "${T}/h.tar" MANIFEST $(find . -type f ! -name MANIFEST | sed 's,^\./,,' | sort) )
rm -f "${T}/m.vt"; openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt -md sha256 -pass fd:3 -in "${T}/h.tar" -out "${T}/m.vt" 3< <(printf '%s\n' "${PASS}")
try imp_run "${T}/dstm" "${T}/m.vt"
check "$([[ ${RC} -ne 0 && "${OUT}" == *"manifest does not match"* ]] && echo refused)" refused "a file missing from the manifest: refused"
check "$([[ -e "${T}/pwned" ]] && echo EXECUTED || echo never)" never "nothing from a hostile file was ever executed"

# ---- identity rule -------------------------------------------------------------------------
# the same node already there (a standby copy): allowed, and a removed client is dropped
rm -rf "${T}/stby"; cp -a "${T}/dst" "${T}/stby"
write_client_env "${T}/stby/etc/veiltrium/clients/old.env" old 11111111-2222-4333-8444-555555555559 "${a48}" "${b48}" 2026-10-01
printf 'N_NAME=XX\nN_GLOBALPING=0\n' > "${T}/stby/etc/veiltrium/node.env"
try imp_run "${T}/stby" "${T}/node.vt"
check "${RC}" 0 "the same node on this server: allowed"
check "$(printf '%s\n' "${OUT}" | grep '^FRESH=' | cut -c1-9)" "FRESH=0 I" "the same node: not treated as a fresh server"
check "$(ls "${T}/stby/etc/veiltrium/clients" | tr '\n' ' ')" "anna.env bob_2.env " "the same node: the export's clients replace the old set"
check "$(grep -c '^N_GLOBALPING=1' "${T}/stby/etc/veiltrium/node.env")" 1 "the same node: the exported settings replace the old ones"
# a different node: refused, nothing changed
mknode "${T}/other" "${c48}"
sum_before="$(find "${T}/other" -type f -exec sha256sum {} + | sort | sha256sum)"
try imp_run "${T}/other" "${T}/node.vt"
check "${RC}" 1 "a different node (other Hysteria password): refused"
case "${OUT}" in *"already runs a different node"*) r=ok ;; *) r=unclear ;; esac
check "${r}" ok "a different node: the message says so"
check "$(find "${T}/other" -type f -exec sha256sum {} + | sort | sha256sum)" "${sum_before}" "a different node: nothing was changed"
mknode "${T}/other2" "${a48}"
sed -i 's/^R_UUID=.*/R_UUID=99999999-2222-4333-8444-555555555551/' "${T}/other2/usr/local/etc/xray/reality.env"
try imp_run "${T}/other2" "${T}/node.vt"
check "${RC}" 1 "same Hysteria password but another Reality UUID: refused"
rm -rf "${T}/other3"; setpaths "${T}/other3"; install -d -m 700 "${HY2_DIR}"; : > "${HY2_CONFIG}"
try imp_run "${T}/other3" "${T}/node.vt"
check "${RC}" 1 "leftovers of an unknown Hysteria config: refused"

# ---- whitelist ---------------------------------------------------------------------------
for n in meta MANIFEST hysteria/node.env clients/anna.env clients/a_b-1.env; do
    export_name_ok "${n}"; check $? 0 "name allowed: ${n}"
done
for n in ../meta /meta hysteria/ hysteria/config.yaml clients/.env clients/Anna.env clients/main.env clients/a/b.env "clients/a b.env" ./meta ""; do
    export_name_ok "${n}"; check $? 1 "name refused: '${n}'"
done

if (( FAIL )); then echo "UNIT-MIGRATE TESTS FAILED"; exit 1; fi
echo "all migrate unit tests passed"
