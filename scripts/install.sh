#!/usr/bin/env bash
set -euo pipefail

version="${AGENTID_VERSION:-}"
if [ -z "$version" ]; then
  echo "AGENTID_VERSION is required" >&2
  exit 2
fi

os="${AGENTID_OS:-$(uname -s | tr '[:upper:]' '[:lower:]')}"
arch="${AGENTID_ARCH:-$(uname -m)}"
case "$arch" in
  x86_64|amd64) arch="amd64" ;;
  aarch64|arm64) arch="arm64" ;;
esac

case "$os" in
  linux|darwin|windows) ;;
  *) echo "unsupported OS: $os" >&2; exit 2 ;;
esac
case "$arch" in
  amd64|arm64) ;;
  *) echo "unsupported architecture: $arch" >&2; exit 2 ;;
esac

base="${AGENTID_RELEASE_BASE:-https://github.com/rajat397/agentid/releases/download/${version}}"
install_dir="${INSTALL_DIR:-${HOME}/.agentid/bin}"
ext=""
target="agentid"
if [ "$os" = "windows" ]; then ext=".exe"; target="agentid.exe"; fi
artifact="agentid_${version}_${os}_${arch}${ext}"

if ! command -v cosign >/dev/null 2>&1; then
  echo "cosign is required to verify agentid releases" >&2
  exit 2
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"

curl -fsSLO "${base}/SHA256SUMS"
curl -fsSLO "${base}/SHA256SUMS.sigstore.json"

cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "^https://github.com/rajat397/agentid/.github/workflows/release.yml@refs/tags/${version}$" \
  SHA256SUMS

curl -fsSLO "${base}/${artifact}"
sha256sum --check --ignore-missing SHA256SUMS

mkdir -p "$install_dir"
install -m 0755 "$artifact" "${install_dir}/${target}"
echo "installed ${install_dir}/${target}"
"${install_dir}/${target}" version
