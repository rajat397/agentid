# PDP combining — deny-overrides as an artifact property

`ValidationProfile.combining` pins the algorithm; only `deny-overrides` is
supported in V1. Any other value fails closed before evaluation.

## Algorithm

`EvaluatePolicySet` evaluates every supplied profile and combines results:

1. any `invalid` ⇒ `invalid` (reason from the first invalid decision);
2. otherwise any `indeterminate` ⇒ `indeterminate`;
3. otherwise no `valid` ⇒ `invalid` ("implicit deny: no policy permits");
4. otherwise `valid`.

Obligations from all decisions are unioned, de-duplicated and sorted by their
canonical JSON bytes, so profile order cannot change the artifact. Receipts
name `PolicySetDigest(profiles)` — the SHA-256 of the canonical profile set —
rather than any single profile digest. Evidence bundles can carry the full
profile set in `profiles[]`; verification accepts either the single-profile
digest or the set digest.

## Scope / limit

Within a single profile the validator still short-circuits on the first
violation for safety. Deny-overrides is the combining property **across
profiles**; that is where multiple relying-party policies meet.

## Falsifier

A permit from one profile overrides a deny from another, an empty policy set
permits, or obligation ordering changes with profile order — attacked in
`combine_test.go`.

## Compatibility

`combining` defaults to `deny-overrides` and is part of the profile digest;
older profile documents without the field remain valid.
