"""Freeze the Python reference's observable behavior as JSON vectors.

Run from the repo root: python3 tools/py-reference/generate_vectors.py
The Go port must reproduce every decision, digest and encoding in testdata/vectors.json.
"""

import base64
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from agentid.constraints import normalize  # noqa: E402
from agentid.crypto import (  # noqa: E402
    b64url_digest_sha256, canonical_json, digest_sha256, generate_keypair, sign, verify,
)
from agentid.delegation import create_delegation  # noqa: E402
from agentid.envelope import build as build_envelope, digest as envelope_digest  # noqa: E402
from agentid.ledger import Ledger  # noqa: E402
from agentid.profile import ValidationProfile  # noqa: E402
from agentid.receipt import Receipt  # noqa: E402
from agentid.signing import DevSigner  # noqa: E402
from agentid.status import build_status_token, check_status, encode_status_list  # noqa: E402
from agentid.validator import validate  # noqa: E402

PROFILE = ValidationProfile.example()
HUMAN = {"type": "human", "id": "oidc|acme-retail|usr_8842"}
NOW = 1800000000
EXPIRY = "2030-01-01T00:00:00Z"


def _iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def dlg_json(d):
    out = {
        "id": d.id, "subject": d.subject, "actor": d.actor,
        "parent_delegation_id": d.parent_delegation_id,
        "chain_depth": d.chain_depth, "constraints": d.constraints,
        "issued_at": d.issued_at, "expires_at": d.expires_at,
        "signature": d.signature,
    }
    if d.issuer is not None:
        out["issuer"] = d.issuer
    if d.status_list is not None:
        out["status_list"] = d.status_list
    return out


def grant(priv, actor, constraints, parent=None, actor_pub=None, signer=None,
          status_idx=None, issuer_id=None):
    return create_delegation(
        priv if signer is None else "", HUMAN, actor, constraints, EXPIRY,
        parent=parent, actor_public_pem=actor_pub, signer=signer,
        status_idx=status_idx, issuer_id=issuer_id,
    )


def case(name, chain, root_pub, action, expect, reason_contains=None,
         approval=None, status_lookup=None, seeds=None, profile=None):
    ledger = Ledger()
    for attrs, issued in seeds or []:
        prev = ledger.receipts[-1].hash if ledger.receipts else "0" * 64
        r = Receipt(
            id="", issued_at=issued, fleet="v", actor={}, delegation_id="seed",
            action="seed", resource={"type": "t", "id": "i", "attributes": attrs},
            decision={"result": "allowed"}, outcome={}, action_type="observed",
            prev_hash=prev,
        )
        ledger.append(r)
    lookup = None
    if status_lookup is not None:
        lookup = lambda uri, idx: status_lookup
    result = validate(
        chain, action, profile or PROFILE, root_pub,
        ledger=ledger, approval=approval, status_lookup=lookup,
        at="2026-11-20T00:00:00Z",
    )
    return {
        "name": name,
        "profile": (profile or PROFILE).document(),
        "chain": [dlg_json(d) for d in chain],
        "root_pub": root_pub,
        "action": action,
        "approval": approval,
        "status_lookup": status_lookup,
        "seeds": [{"attributes": a, "issued_at": t} for a, t in seeds or []],
        "expect": {"outcome": result.outcome, "reason_contains": reason_contains or []},
        "observed_reason": result.reason,
    }


def main():
    vectors = {"canon": [], "envelopes": [], "decisions": [], "status": []}

    # Canonical JSON — exact digests of Python canonicalization.
    canon_values = [
        {"a": 1, "b": "2", "c": [3, "4", True, None]},
        {"z": {"y": "x", "a": "b"}, "nested": [{"k": "v"}]},
        {"amount": "2000.00", "currency": "USD", "region": "eu"},
    ]
    vectors["canon"] = [
        {"value": v, "hex": digest_sha256(canonical_json(v)),
         "b64url": b64url_digest_sha256(canonical_json(v))}
        for v in canon_values
    ]

    # Envelope digests.
    requests = [
        {"action": "support.ticket.resolve", "system": "zendesk",
         "resource_type": "ticket", "resource_id": "t1",
         "region": "eu", "count": "5", "personal_data_refs": ["cust_4471"]},
        {"action": "ad.credit.purchase", "system": "meta-ads",
         "amount": "2000.00", "currency": "USD", "budget_key": "ads_q4"},
    ]
    vectors["envelopes"] = [{"request": r, "digest": envelope_digest(r),
                             "envelope": build_envelope(r)} for r in requests]

    # Signature cross-check: Go must verify this Python-produced ES256 signature.
    priv, pub = generate_keypair()
    payload = {"action": "support.ticket.resolve", "count": "1"}
    vectors["crypto"] = {
        "private_pem": priv, "public_pem": pub, "payload": payload,
        "signature": sign(priv, payload), "verifies": verify(pub, payload, sign(priv, payload)),
    }

    # Status-list encodings and signed tokens.
    statuses_sets = [[0x00, 0x01, 0x02, 0x00], [0x00], [0x01, 0x00, 0x02, 0x00, 0x01]]
    for statuses in statuses_sets:
        vectors["status"].append({
            "statuses": statuses, "encoded": encode_status_list(statuses),
        })
    s_priv, s_pub = generate_keypair()
    s_signer = DevSigner(s_priv, s_pub, kid="vector_status_key", warn=False)
    fresh = build_status_token("https://example.invalid/status", [0x00, 0x01, 0x02],
                               s_signer, iat=NOW, exp=NOW + 600, ttl=300)
    stale = build_status_token("https://example.invalid/status", [0x00, 0x01, 0x02],
                               s_signer, iat=NOW - 1000, exp=NOW + 600, ttl=300)
    vectors["status_tokens"] = {
        "public_keys": s_signer.public_keys(), "now": NOW, "max_status_age": 300,
        "fresh": fresh, "stale": stale,
        "status_at_1": check_status(fresh, 1, s_signer.public_keys(), 300, NOW),
    }

    # Decision vectors — legacy money path.
    p, pub = generate_keypair()
    legacy = {"permissions": [{"action": "ad.credit.purchase", "system": "meta-ads"}],
              "max_amount": {"value": "2000.00", "currency": "USD"},
              "requires_human_approval_above": {"value": "500.00", "currency": "USD"}}
    d = grant(p, "marketing-agent", legacy)
    money_action = {"action": "ad.credit.purchase", "system": "meta-ads",
                    "amount": "2000.00", "currency": "USD", "resource_type": "ad_credit_account",
                    "resource_id": "acme", "external_ref": "order_1"}

    vectors["decisions"].append(case("legacy_amount_under_threshold", [d], pub,
                                     {**money_action, "amount": "100.00"}, "valid"))
    vectors["decisions"].append(case(
        "legacy_approval_valid", [d], pub, money_action, "valid",
        approval={"id": "apr_v", "delegation_id": d.id, "action": "ad.credit.purchase",
                  "amount": "2000.00", "approver": HUMAN["id"], "nonce": "n1"}))
    vectors["decisions"].append(case(
        "legacy_approval_too_small", [d], pub, money_action, "invalid", ["approval"],
        approval={"id": "apr_bad", "delegation_id": d.id, "action": "ad.credit.purchase",
                  "amount": "100.00", "approver": HUMAN["id"], "nonce": "n2"}))
    vectors["decisions"].append(case(
        "legacy_cap_exceeded", [d], pub, {**money_action, "amount": "5000.00"},
        "invalid", ["max"], approval={"id": "apr_x", "delegation_id": d.id,
                                      "action": "ad.credit.purchase", "amount": "5000.00",
                                      "approver": HUMAN["id"], "nonce": "n3"}))
    vectors["decisions"].append(case(
        "legacy_over_threshold_no_approval", [d], pub, money_action,
        "indeterminate", ["no approval supplied"]))

    budget_constraint = {**legacy, "budget": {"key": "ads_q4", "value": "2000.00",
                                              "currency": "USD", "period_seconds": 2592000}}
    bd = grant(p, "budget-agent", budget_constraint)
    budget_action = {**money_action, "amount": "500.00", "budget_key": "ads_q4"}
    seed = [({"budget_key": "ads_q4", "amount": "1000.00", "currency": "USD"}, "2026-11-01T00:00:00Z"),
            ({"budget_key": "ads_q4", "amount": "800.00", "currency": "USD"}, "2026-11-02T00:00:00Z")]
    vectors["decisions"].append(case("legacy_budget_exhausted", [bd], pub, budget_action,
                                     "invalid", ["budget exhausted"], seeds=seed,
                                     approval={"id": "apr_s", "delegation_id": bd.id,
                                               "action": "ad.credit.purchase", "amount": "500.00",
                                               "approver": HUMAN["id"], "nonce": "n4"}))

    # Universal predicates.
    u_priv, u_pub = generate_keypair()
    u_constraints = {
        "permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}],
        "predicates": [
            {"type": "in", "path": "/attributes/region", "values": ["eu", "us"]},
            {"type": "max", "path": "/attributes/count", "value": "50"},
            {"type": "min", "path": "/attributes/count", "value": "1"},
        ],
    }
    ud = grant(u_priv, "support-agent", u_constraints)
    u_action = {"action": "support.ticket.resolve", "system": "zendesk",
                "resource_type": "ticket", "resource_id": "t1", "region": "eu", "count": "5"}
    vectors["decisions"].append(case("in_valid", [ud], u_pub, u_action, "valid"))
    vectors["decisions"].append(case("in_invalid", [ud], u_pub, {**u_action, "region": "apac"},
                                     "invalid", ["region"]))
    vectors["decisions"].append(case("max_invalid", [ud], u_pub, {**u_action, "count": "51"},
                                     "invalid", ["count"]))
    vectors["decisions"].append(case("min_invalid", [ud], u_pub, {**u_action, "count": "0"},
                                     "invalid", ["count"]))

    rows_constraints = {
        "permissions": [{"action": "support.ticket.purge", "system": "zendesk"}],
        "predicates": [{"type": "sum_max", "path": "/attributes/rows", "key": "purge_q4",
                        "max": "100"}],
    }
    rd = grant(u_priv, "purge-agent", rows_constraints)
    rows_action = {"action": "support.ticket.purge", "system": "zendesk",
                   "rows": "20", "budget_key": "purge_q4"}
    rows_seed = [({"budget_key": "purge_q4", "rows": "60"}, "2026-11-01T00:00:00Z"),
                 ({"budget_key": "purge_q4", "rows": "30"}, "2026-11-02T00:00:00Z")]
    vectors["decisions"].append(case("sum_rows_valid", [rd], u_pub,
                                     {**rows_action, "rows": "10"}, "valid", seeds=rows_seed))
    vectors["decisions"].append(case("sum_rows_exhausted", [rd], u_pub,
                                     {**rows_action, "rows": "20"}, "invalid", ["budget exhausted"],
                                     seeds=[({"budget_key": "purge_q4", "rows": "90"},
                                             "2026-11-01T00:00:00Z")]))

    window_constraints = {
        "permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}],
        "predicates": [{"type": "window", "start": "2026-12-01T00:00:00Z",
                        "end": "2027-01-01T00:00:00Z"}],
    }
    wd = grant(u_priv, "window-agent", window_constraints)
    vectors["decisions"].append(case("window_invalid", [wd], u_pub, u_action,
                                     "invalid", ["window"]))

    cosign_constraints = {
        "permissions": [{"action": "support.ticket.purge", "system": "zendesk"}],
        "predicates": [{"type": "cosign_above", "path": "/attributes/rows", "value": "50"}],
    }
    cd = grant(u_priv, "cosign-agent", cosign_constraints)
    cosign_action = {"action": "support.ticket.purge", "system": "zendesk", "rows": "80"}
    vectors["decisions"].append(case("cosign_no_approval", [cd], u_pub, cosign_action,
                                     "indeterminate", ["no approval supplied"]))
    vectors["decisions"].append(case(
        "cosign_digest_wrong", [cd], u_pub, cosign_action, "invalid", ["digest"],
        approval={"id": "apr_w", "delegation_id": cd.id, "action": "support.ticket.purge",
                  "envelope_digest": envelope_digest({**cosign_action, "rows": "10"}),
                  "approver": HUMAN["id"], "nonce": "n5"}))
    vectors["decisions"].append(case(
        "cosign_digest_right", [cd], u_pub, cosign_action, "valid",
        approval={"id": "apr_r", "delegation_id": cd.id, "action": "support.ticket.purge",
                  "envelope_digest": envelope_digest(cosign_action),
                  "approver": HUMAN["id"], "nonce": "n6"}))

    # Status-list enforcement.
    sd = grant(u_priv, "status-agent", u_constraints, status_idx=0)
    vectors["decisions"].append(case("status_valid", [sd], u_pub, u_action, "valid",
                                     status_lookup=0x00))
    vectors["decisions"].append(case("status_revoked", [sd], u_pub, u_action, "invalid",
                                     ["revoked"], status_lookup=0x01))
    vectors["decisions"].append(case("status_suspended", [sd], u_pub, u_action, "invalid",
                                     ["suspended"], status_lookup=0x02))
    vectors["decisions"].append(case("status_missing_lookup", [sd], u_pub, u_action,
                                     "invalid", ["lookup"]))

    # Multi-hop with per-issuer keys.
    a_priv, a_pub = generate_keypair()
    sub_priv, sub_pub = generate_keypair()
    root = grant(u_priv, "agent-a", u_constraints, actor_pub=a_pub)
    child = grant(a_priv, "agent-b", u_constraints, parent=root, actor_pub=sub_pub)
    grandchild = grant(sub_priv, "agent-c", u_constraints, parent=child)
    vectors["decisions"].append(case("three_hop_chain", [root, child, grandchild], u_pub,
                                     u_action, "valid"))
    four = grant(sub_priv, "agent-d", u_constraints, parent=grandchild)
    vectors["decisions"].append(case("chain_depth_exceeded", [root, child, grandchild, four],
                                     u_pub, u_action, "invalid", ["chain depth"]))

    # Profile predicate allowlist.
    restricted = ValidationProfile.from_dict({**PROFILE.document(), "predicates": ["max"]})
    eqd = grant(u_priv, "eq-agent", {
        "permissions": [{"action": "support.ticket.resolve", "system": "zendesk"}],
        "predicates": [{"type": "eq", "path": "/attributes/status", "value": "open"}],
    })
    vectors["decisions"].append(case(
        "profile_predicate_not_allowed", [eqd], u_pub,
        {**u_action, "status": "open"}, "invalid", ["profile"], profile=restricted))

    out = HERE.parent.parent / "testdata" / "vectors.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(vectors, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {out} ({len(vectors['decisions'])} decisions)")


if __name__ == "__main__":
    main()
