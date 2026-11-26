# Licensing and open-core boundary

`agentid` uses an open-core model.

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

Some operator-layer features already present in this repository, including the embedded control plane, anchoring, erasure, retention, OTel reconciliation and registry helpers, remain Apache-2.0 for now. They are grandfathered into the open core to avoid retroactively changing the terms under which contributors and early users received them. Their commercial successors will be separate modules.

## Commercial layer: separate license

Modules, binaries or services explicitly marked Commercial, Enterprise, Regulated or OEM are licensed under [LICENSE-COMMERCIAL](../../LICENSE-COMMERCIAL). The commercial layer is for operator burden, not for the verifier:

- hosted or managed control plane and policy distribution;
- key lifecycle service, KMS/HSM adapters and rotation automation;
- anchor management service, dashboards and gap alerting;
- erasure and retention connectors for real downstream systems;
- audit export, evidence directory and signer-key directory;
- observability pack, alert templates and reconciliation dashboards;
- OEM/embedded licensing for gateways and platforms;
- certified release channels and support.

None of these commercial artifacts are shipped in this repository today. Do not treat planned features as licensed or available.

## Contributions

Contributions to the open core are accepted under Apache-2.0 and require a Developer Certificate of Origin sign-off. See [CONTRIBUTING.md](../../CONTRIBUTING.md).

## Trademarks

The Apache-2.0 license does not grant permission to use the `agentid` name or marks for endorsement. Use the name only to describe compatibility or origin.
