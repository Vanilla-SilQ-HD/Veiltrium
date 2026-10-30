#!/usr/bin/env bash
# Release gate on an installed CI node: exercise the normal download/pin path.
set -euo pipefail
cd "$(dirname "$0")/.."
test -z "${PANEL_BINARY:-}"
version="$(sed -n 's/^PANEL_VERSION="panel-v\([^"]*\)"$/\1/p' veiltrium.sh)"
arch="$(dpkg --print-architecture)"
case "$arch" in
    amd64) sum="$(sed -n 's/^PANEL_SHA256_AMD64="\([0-9a-f]*\)"$/\1/p' veiltrium.sh)" ;;
    arm64) sum="$(sed -n 's/^PANEL_SHA256_ARM64="\([0-9a-f]*\)"$/\1/p' veiltrium.sh)" ;;
    *) echo "unsupported architecture: $arch"; exit 1 ;;
esac
[[ "$sum" =~ ^[0-9a-f]{64}$ && -n "$version" ]]
test "$(/usr/local/bin/veiltrium-panel version)" = "$version"
printf '%s  /usr/local/bin/veiltrium-panel\n' "$sum" | sha256sum -c -
systemctl is-active veiltrium-panel veiltrium-helper.socket
test "$(sha256sum veiltrium.sh | cut -c1-64)" = "$(sudo sha256sum /usr/local/lib/veiltrium/veiltrium.sh | cut -c1-64)"
sudo bash /usr/local/lib/veiltrium/veiltrium.sh --status --json - | jq -e '
    .schema == "veiltrium-status/1" and .standby_sync.schema == "veiltrium-standby/1"
    and .home_max_age_days == 14 and (.hysteria2 | has("home_checked_at"))' > /dev/null
echo "published panel $version ($arch), checksum and installed helper verified"
