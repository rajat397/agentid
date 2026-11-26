# Install and verify

Supported release artifact: a versioned binary plus a checksum manifest and Sigstore signature bundle.

## Verify the checksum manifest

Set the release tag you want:

```bash
VERSION=v1.2.3
BASE="https://github.com/rajat397/agentid/releases/download/${VERSION}"
curl -fsSLO "${BASE}/SHA256SUMS"
curl -fsSLO "${BASE}/SHA256SUMS.sigstore.json"
```

Verify that the manifest itself was signed by the release workflow:

```bash
cosign verify-blob \
  --bundle SHA256SUMS.sigstore.json \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "^https://github.com/rajat397/agentid/.github/workflows/release.yml@refs/tags/${VERSION}$" \
  SHA256SUMS
```

## Download and verify a binary

```bash
OS=linux
ARCH=amd64
NAME="agentid_${VERSION}_${OS}_${ARCH}"
curl -fsSLO "${BASE}/${NAME}"
sha256sum --check --ignore-missing SHA256SUMS
chmod +x "${NAME}"
./"${NAME}" version
```

Supported initial targets: `linux/amd64`, `linux/arm64`, `darwin/amd64`, `darwin/arm64`, `windows/amd64`.

## Container image

Container images are published to `ghcr.io/rajat397/agentid` on each release tag. Verify by digest, not by mutable tag:

```bash
VERSION=v1.2.3
IMAGE="ghcr.io/rajat397/agentid:${VERSION}"
docker pull "${IMAGE}"
DIGEST="$(docker image inspect --format '{{index .RepoDigests 0}}' "${IMAGE}")"

cosign verify "${DIGEST}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp "^https://github.com/rajat397/agentid/.github/workflows/release.yml@refs/tags/${VERSION}$"

docker run --rm "${DIGEST}" version
```

Deploy the digest you verified. Tags are convenience only.

## Convenience installer

With `cosign` installed, the installer verifies the signed checksum manifest before installing the binary:

```bash
AGENTID_VERSION=v1.2.3 INSTALL_DIR="$HOME/.agentid/bin" bash scripts/install.sh
```

Set `AGENTID_OS` and `AGENTID_ARCH` to override detection. Set `AGENTID_RELEASE_BASE` only for mirrors or local testing; the default is the GitHub release for the chosen tag.

## Build locally

```bash
GO=/path/to/go1.27/bin/go bash scripts/build-release.sh dev dist/release
cd dist/release && sha256sum -c SHA256SUMS
```

The build sets `agentid.BuildVersion` through linker flags, so `agentid version` reports the release tag.

## Planned surfaces

Release binaries are the canonical artifact. The convenience installer, signed container images, package-manager formulas, Helm chart and upgrade matrix are derived from these artifacts and are tracked in `agent-identity/docs/INSTALL-ARTIFACT-STRATEGY.md`. Do not treat a planned surface as shipped.
