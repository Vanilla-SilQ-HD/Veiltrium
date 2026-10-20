#!/usr/bin/env bash
# Builds the Veiltrium web panel: the web interface from the exact lockfile (no install
# scripts run), then one static Go binary with it embedded.
# Usage: panel/build.sh OUT [GOARCH] [VERSION]      (CI, releases and local builds)
set -euo pipefail
out="$(realpath -m "$1")"
arch="${2:-amd64}"
version="${3:-dev}"
cd "$(dirname "$0")"
(cd web && npm ci --no-audit --no-fund --ignore-scripts && ./node_modules/.bin/vite build)
CGO_ENABLED=0 GOOS=linux GOARCH="${arch}" go build -trimpath -buildvcs=false \
    -ldflags="-s -w -X main.version=${version}" -o "${out}" .
echo "built ${out} (${arch}, ${version})"
