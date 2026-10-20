#!/usr/bin/env bash
# FAST checks (seconds, no root, no network services): syntax, lint, POSIX/BusyBox,
# unit tests, HMAC agreement between the server (bash), the router (BusyBox sh) and
# OpenSSL. The same script runs locally and in .github/workflows/fast.yml.
# Missing tools are reported as SKIPPED (CI has all of them); FULL is e2e.yml.
set -u
cd "$(dirname "$0")/.." || exit 1
FAIL=0
SKIPPED=()
have() { command -v "$1" >/dev/null 2>&1; }
run() {
    local out
    if out="$("$@" 2>&1)"; then echo "ok    $*"; else echo "FAIL  $*"; printf '%s\n' "${out}" | tail -n 40; FAIL=1; fi
}

for f in veiltrium.sh tests/*.sh; do run bash -n "${f}"; done
if have shellcheck && [[ "${SKIP_SHELLCHECK:-0}" != 1 ]]; then
    run shellcheck -S warning veiltrium.sh
    run shellcheck -s sh -S warning tools/keenetic-vpn-probe.sh
else
    SKIPPED+=(shellcheck)
fi
if have dash; then run dash -n tools/keenetic-vpn-probe.sh; fi
if have busybox; then
    run busybox sh -n tools/keenetic-vpn-probe.sh
else
    SKIPPED+=("busybox (POSIX syntax and router HMAC)")
fi

# HMAC-SHA256 of the router (BusyBox sh + sha256sum + printf) against OpenSSL
hmac_router() {
    local tmp k m want got i
    tmp="$(mktemp)"
    sed -n '/^hex_to_octal() {/,/^mac_of() {/p' tools/keenetic-vpn-probe.sh | sed '$d' > "${tmp}"
    busybox sh -c ". ${tmp}; SHA=sha256sum; hmac_selftest" || { echo "router HMAC self-test failed"; rm -f "${tmp}"; return 1; }
    for i in 1 2 3 4 5 6 7 8; do
        k="$(openssl rand -hex 32)"
        m="v2run|$(date +%s)|$(openssl rand -hex 8)|192.0.2.1|ppp0|${i}|$(openssl rand -hex 32)"
        want="$(printf '%s' "${m}" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${k}" | awk '{print $NF}')"
        got="$(busybox sh -c ". ${tmp}; SHA=sha256sum; hmac_prepare ${k}; hmac_hex '${m}'")"
        [[ "${got}" == "${want}" ]] || { echo "key ${i}: router ${got} != openssl ${want}"; rm -f "${tmp}"; return 1; }
    done
    rm -f "${tmp}"
}
if have busybox && have openssl; then run hmac_router; fi

# the web panel: Go tests and a full build (web interface embedded), when the tools exist
if have go && have npm; then
    panel_check() {
        local tmp
        tmp="$(mktemp -d)"
        bash panel/build.sh "${tmp}/veiltrium-panel" amd64 dev >/dev/null             && (cd panel && test -z "$(gofmt -l .)" && go vet ./... && go test -count=1 ./...)             && node panel/web/scripts/check-locales.mjs             && test "$("${tmp}/veiltrium-panel" version)" = dev
        local rc=$?
        rm -rf "${tmp}"
        return "${rc}"
    }
    run panel_check
else
    SKIPPED+=("web panel (needs go and npm)")
fi

if have jq && have openssl; then
    run bash tests/unit.sh
    run bash tests/unit-migrate.sh
    run bash tests/unit-standby.sh
    run bash tests/unit-stall.sh
    run bash tests/unit-cli.sh
    run bash tests/unit-alerts.sh
    run bash tests/unit-maint.sh
    run bash tests/unit-traffic.sh
    run bash tests/unit-limits.sh
    run bash tests/unit-bundle.sh
else
    SKIPPED+=("unit tests (need jq and openssl)")
fi

if (( ${#SKIPPED[@]} )); then printf 'SKIPPED: %s\n' "${SKIPPED[@]}"; fi
if (( FAIL )); then echo "FAST CHECKS FAILED"; exit 1; fi
echo "fast checks passed"
