# SCIM propagation — directory lifecycle into revocation status

A status list is only as fresh as the events it receives. SCIM 2.0 is where
enterprise offboarding and entitlement changes happen; this adapter turns
those changes into `0x01` revocations without importing directory PII.

## Client

`SCIMClient{BaseURL, Token, HTTPClient}` fetches `/Users` and `/Groups` with
SCIM paging (`startIndex`/`count`, `Accept: application/scim+json`, bearer
token from the deployment). Tokens are never written to receipts, bundles or
logs. HTTP errors fail the sync; `max_status_age` (D26) then fails the PEP
closed until a fresh sync succeeds.

## Mapping

`SCIMRevocations(users, requiredGroup, previous)` emits raw-directory IDs whose
state changed since the last sync: `active == false`, or loss of membership in
the configured required group. `ApplySCIMSync` maps those IDs to status-list
indices via a deployment-owned `subjectIndex`, returns the updated status
array, and a `SCIMSyncResult` containing **only pseudonymous IDs**
(`subj_<sha256-prefix>`), counts and a timestamp. Raw user names, emails and
directory IDs never enter our artifacts.

After a sync, rebuild the `statuslist+jwt` with the returned statuses and
republish it; the bundle verification and `/v1/keys` surfaces carry the key
material needed to check it.

## Webhook

`NewSCIMWebhookHandler(secret, onEvent)` accepts SCIM push events. The shared
secret is compared in constant time; only pseudonymous IDs reach the callback
and the HTTP response. Mount it in caller-owned infrastructure — we do not
host a directory bridge.

## Limits

- No vendor-specific schema extensions; standard SCIM core resources only.
- Reactivation resets status to `0x00` but does not reissue expired
  delegations; the normal delegation expiry and attenuation still apply.
- The subject→index mapping is deployment-owned; a missing mapping is reported
  as `skipped_count`, not silently ignored.

## Falsifier

A deprovisioned user's delegation still resolves to `0x00` after a sync, or raw
directory data appears in our artifacts — `scim_test.go` checks both.
