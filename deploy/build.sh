#!/usr/bin/env bash
# Build the idp-mcp-bridge image offline: a static binary on the host, then docker build --network none.
# Usage: bash deploy/build.sh [TAG]     (default idp-mcp-bridge:<commit or dev>)
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION="$(git rev-parse --short HEAD 2>/dev/null || echo dev)"
[[ -z "$(git status --porcelain --untracked-files=no 2>/dev/null)" ]] || VERSION="$VERSION-dirty"
TAG="${1:-idp-mcp-bridge:$VERSION}"
OUT=build/image
umask 022
rm -rf "$OUT" && mkdir -p "$OUT"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o "$OUT/idp-mcp-bridge" ./cmd/idp-mcp-bridge
cp deploy/Dockerfile "$OUT/"
docker build --network none -q -t "$TAG" "$OUT" >/dev/null
echo "OK: $TAG $(docker image inspect --format '{{.Id}}' "$TAG" | cut -c1-19)… idp-mcp-bridge sha256 $(sha256sum "$OUT/idp-mcp-bridge" | cut -c1-12)…"
