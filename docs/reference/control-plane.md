# Control plane — one owner for policy, revocation and anchors

C13's topology: the validator stays embedded in the PEP (no per-action network
hop), while a single caller-owned control plane owns the three things that
must be consistent across fleets.

## Components

- **Policy store** — `PublishPolicy(profile)` activates a content-addressed
  profile; `PolicyBundle()` emits a signed `{profile, digest, issued_at}`
  snapshot. PEPs verify the signature with published key material and install
  it into `PolicyCache`.
- **Revocation feed** — `PublishStatus()` renders the registry into a signed
  status list; freshness remains bounded by `max_status_age`.
- **Anchor orchestration** — `ObserveAnchors(ledger)` delegates cadence and
  queued retries to the anchor manager (RFC 3161 or customer bucket).

`Snapshot()` exposes active digest, published policy count and registry size.
The control plane never authorsizes an individual action.

## PEP cache and failure mode

`PolicyCache.Profile()` returns the last verified profile only while it is
within `maxAge`; a stale or absent cache returns an error. The MCP wrapper's
`PolicyProvider` fails the tool call closed with a receipt rather than
enforcing an old policy when the control plane is unavailable.

## Integration scenario (test-first)

`integration/control_plane_test.go` went RED (static policy) → GREEN: a
published stage-allowlist change reached the PEP on refresh, the next call was
denied, and expiring the cache produced another denial with a valid chain.

## Falsifier

A published policy change never reaches the PEP, a stale cache still permits,
or a tampered policy bundle is accepted — scenario and unit tests attack all
three.

## Limits

The control plane is a library component hosted by the customer; no managed
service is claimed. It does not replace split validation: PEP decisions remain
local and re-derivable.
