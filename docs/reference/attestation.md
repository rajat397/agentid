# Workload attestation — binding SPIFFE IDs to verified workloads

A `spiffe://` string in a receipt is only a claim. Attestation makes it a
verified fact by binding it to a credential issued after workload inspection.

## Boundary

```go
type Attestor interface { Attest() (Attestation, error) }
type Attestation struct {
    SPIFFEID, CredentialDigest, TrustDomain, ValidUntil, Evidence string
}
```

`CreateDelegation` accepts an `Attestor`, signs the attestation into the
delegation body, and overrides `actor.spiffe_id` with the attested identity.
The validator checks, before any action:

1. attested SPIFFE ID equals the actor's SPIFFE ID;
2. attestation has not expired;
3. credential digest equals the actor key's SHA-256 (the key pinned by the
   parent, or the caller's root key for hop 1).

Receipts record `actor.attestation_digest`, so audits can distinguish an
attested agent from a self-labeled one.

## Implementations

- `attest.DevAttestor` — local, deterministic, labeled **NOT FOR PRODUCTION**:
  it binds an ID + key for demos and cold clones but verifies no workload.
- `optional/spire` — separate Go module importing `go-spiffe/v2`; its
  `Attestor` fetches an X509-SVID from a SPIRE agent's Workload API, checks
  the expected trust domain, and projects the certificate's public key and
  `NotAfter` into an attestation. The core module stays stdlib-only; this
  adapter is opt-in and requires a running SPIRE agent.

## Limits

Dev attestations assert, they do not verify. SPIRE adapter builds are not part
of the core CI target; they live in `optional/spire` with their own `go.mod`.
This does not yet provide continuous re-attestation mid-delegation — the
attestation is checked at validation time and expires with its declared
`ValidUntil`.

## Falsifier

A delegation claiming a SPIFFE ID it was never attested for passes validation,
or an expired/wrong-key attestation is accepted — covered by Go attestation
tests.
