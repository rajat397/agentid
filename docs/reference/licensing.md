# Licensing and open-core boundary

`agentid` uses a Stripe-style boundary: the interface layer is permissive and inspectable; the operator layer is commercial source-not-available.

## Open core: Apache-2.0

The following are licensed under [Apache-2.0](../../LICENSE):

- the canonical action envelope, profile and predicate engine;
- delegation issuance and verification primitives;
- receipt format, hash chain and offline verification;
- evidence bundle export and verification;
- the local CLI and the MCP stdio adapter needed to wrap one tool path;
- adapter contracts and the reference adapter implementations currently in this repository;
- documentation and examples needed to run the core.

Reason: platform engineers and security reviewers need to inspect the verifier, receipt format and enforcement path before they will wire a live tool call. A permissive license supports that trust and the product-led motion.

The default build (`go test ./...`, `go build ./cmd/agentid`) contains only Apache-2.0 code. The interface layer includes the receipt format, verifier, envelope, validator, delegation primitives, evidence bundle, MCP proxy, adapter contracts and the CLI commands needed to inspect and verify locally.

## Commercial layer: separate license

Files marked `// SPDX-License-Identifier: LicenseRef-agentid-commercial` and included only by the Go build tag `enterprise` are licensed under [LICENSE-COMMERCIAL](../../LICENSE-COMMERCIAL). They are for operator burden, not for the verifier:

- operator config validation and health commands;
- local key lifecycle, rotation and public-key publishing commands;
- hosted or managed control plane and policy distribution;
- KMS/HSM adapters and rotation automation;
- anchor management service, dashboards and gap alerting;
- erasure and retention connectors for real downstream systems;
- audit export, evidence directory and signer-key directory;
- reconciliation dashboards, OEM/embedded licensing, certified channels and support.

Build with `-tags enterprise` only under a commercial license. The default binary does not contain these commands.

## Contributions

Contributions to the open core are accepted under Apache-2.0 and require a Developer Certificate of Origin sign-off. See [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Trademarks

The Apache-2.0 license does not grant permission to use the `agentid` name or marks for endorsement. Use the name only to describe compatibility or origin.
