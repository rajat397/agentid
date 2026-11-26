#!/usr/bin/env bash
set -euo pipefail

version="${1:-dev}"
go_bin="${GO:-go}"

"$go_bin" test ./...
"$go_bin" vet ./...
bash scripts/build-release.sh "$version" dist/release

(
  cd dist/release
  sha256sum -c SHA256SUMS
)

"$go_bin" run ./cmd/agentid version
echo "release check passed for ${version}"
