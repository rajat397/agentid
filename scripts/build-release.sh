#!/usr/bin/env bash
set -euo pipefail

version="${1:-dev}"
out="${2:-dist/release}"
go_bin="${GO:-go}"

mkdir -p "$out"
rm -f "$out"/SHA256SUMS "$out"/agentid_*

targets=(
  "linux amd64"
  "linux arm64"
  "darwin amd64"
  "darwin arm64"
  "windows amd64"
)

for target in "${targets[@]}"; do
  read -r os arch <<< "$target"
  ext=""
  if [ "$os" = "windows" ]; then ext=".exe"; fi
  name="agentid_${version}_${os}_${arch}${ext}"
  echo "building $name"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" "$go_bin" build \
    -trimpath \
    -ldflags "-s -w -X github.com/rajat397/agentid/internal/agentid.BuildVersion=${version}" \
    -o "$out/$name" ./cmd/agentid
done

(
  cd "$out"
  sha256sum agentid_* > SHA256SUMS
)

echo "wrote $out/SHA256SUMS"
