# Agent versioning — `actor.version` in signed authority

Each delegation hop can carry `actor.version {build, engine, model?}`, signed
as part of the actor object. Receipts copy the leaf version into `actor`, so an
incident can answer which build produced an action.

When a sub-agent's version differs from its parent's, validation does **not**
deny — it emits an `agent_version_drift` obligation noting the `from`/`to`
versions. Drift is evidence, not a policy failure: upgrades are normal, but
they must be visible in the audit trail. Stable versions emit no obligation.

SPIFFE/SPIRE-style attestation of the workload remains a separate boundary
(`docs/reference/attestation.md`); this field identifies the software that ran.
The obligation set is canonicalized, so version drift cannot change artifact
digests by ordering alone.

Falsifier: a version change is absent from the receipt/obligations, or a stable
version emits drift — attacked in `version_test.go`.
