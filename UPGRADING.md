# Upgrading agentid

**Status:** current for config schema `v1` and release artifacts `v*`.

## Compatibility matrix

| agentid release | Config schema | Container tag | Upgrade note |
|---|---|---|---|
| v0.x | legacy JSON | v0.x | Config without `version` and `mode` is normalized to `v1` and `enforce`. |
| v1.x | v1 | v1.x | Stable operator config and signed release artifacts. |
| future minor | v1 | compatible | Config migrations must be added here before release. |

## Upgrade procedure

1. Verify the target release by signature and SHA-256 before deploying.
2. Record the currently deployed version, image digest and config hash.
3. Back up signer keys, delegation files and receipt ledgers.
4. Run `agentid config check --config <file>` against the new config.
5. Start the new version in `shadow` mode and observe proposed verdicts.
6. Switch to `enforce` only after the shadow receipts match expectations.
7. Keep the previous binary or container digest available until the new version is verified in production.

## Verify before rollback

A rollback target must also be verified. Always verify the digest or signature before rollback. Do not roll back to an unverified digest or unsigned binary.

## Rollback

1. Stop routing new tool calls through the new gate instance.
2. Redeploy the previous verified binary or container digest.
3. Restore the previous config and signer keys if key state changed.
4. Confirm `agentid version`, `agentid config check` and `/health` behavior.
5. Verify that new receipts use a key still present in the published key set.
6. Record the rollback reason in the incident log.
