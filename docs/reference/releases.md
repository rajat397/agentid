# Releases

**Status:** release process for signed binaries and container images.

## Semantic versioning

Releases use `MAJOR.MINOR.PATCH` with a leading `v` tag.

- `MAJOR`: incompatible config schema, receipt format or deployment contract.
- `MINOR`: backward-compatible product capability; may add config fields with defaults.
- `PATCH`: fixes and security updates that do not change the contract.

Config schema `v1` is the current operator contract. Legacy configs without `version` or `mode` normalize to `v1` and `enforce`.

## Release checklist

The release checklist below is mandatory before tagging.

1. Update release notes and `UPGRADING.md` if the contract changed.
2. Run `bash scripts/release-check.sh`.
3. Tag `vX.Y.Z` and push the tag.
4. Confirm the release workflow builds binaries, checksums, signature bundle and container image.
5. Confirm the container signature verifies by digest.
6. Publish release notes with the verified artifact list.

## Security release

A security release must name the affected versions, the fixed version and the exposure window. Security release notes must instruct operators to upgrade and redeploy by digest; rebuilding from a mutable tag is not evidence.

## Redeploy

Binary users replace the verified binary and restart the gate. Container users pull the new image, verify the digest and redeploy that digest. Key rotation follows `docs/reference/key-lifecycle.md`.
