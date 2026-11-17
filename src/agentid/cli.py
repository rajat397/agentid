"""agentid command line.

Commands:
  version                        print version
  demo                           run the full lifecycle end to end and print it
  erasure <subject> [--demo]     enumerate receipts touching a personal-data subject and plan erasure
  profile                        print the example Validation Profile and its digest
"""

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .crypto import generate_keypair, b64url
from .delegation import create_delegation
from .flow import act, new_keys
from .erasure import build_erasure_plan
from .ledger import Ledger
from .profile import ValidationProfile
from .validator import validate

PROFILE = ValidationProfile.example()


def _banner(text: str) -> None:
    print()
    print(text)
    print("=" * len(text))


def _iso(minutes_from_now: int) -> str:
    from datetime import datetime, timedelta, timezone
    return (datetime.now(timezone.utc) + timedelta(minutes=minutes_from_now)).strftime("%Y-%m-%dT%H:%M:%SZ")


def cmd_version() -> int:
    print(f"agentid {__version__}")
    return 0


def cmd_demo() -> int:
    _banner("agentid — the full lifecycle, running against real code")

    from .profile import ValidationProfile
    profile = ValidationProfile.example()
    priv, pub = new_keys()
    ledger = Ledger()

    _banner("1. A human grants authority — signed, scoped, expiring")
    print(
        """   constrain: ad.credit.purchase on meta-ads, hard cap $2,000,
              approval required above $500, expires in 30 minutes.
   The agent never holds the downstream credential. The enforcement point does."""
    )
    delegation = create_delegation(
        priv,
        subject={"type": "human", "id": "oidc|acme-retail|usr_8842"},
        actor_id="marketing-agent",
        constraints={
            "permissions": [{"action": "ad.credit.purchase", "system": "meta-ads"}],
            "max_amount": {"value": "2000.00", "currency": "USD"},
            "requires_human_approval_above": {"value": "500.00", "currency": "USD"},
        },
        expires_at=_iso(30),
    )
    print(f"   delegation_id = {delegation.id}")
    print(f"   signature     = valid (ES256, kid {delegation.signature['kid']})")

    _banner("2. The agent attempts an action that exceeds its authority — and is stopped")
    denied, result = act(
        ledger, [delegation],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "4500.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta", "external_ref": "meta_ad_order_993812",
         "personal_data_refs": ["cust_4471"]},
        PROFILE, pub,
    )
    print(f"   outcome   = {result.outcome}")
    print(f"   reason    = {result.reason}")
    print(f"   receipt   = {denied.id}  (action={denied.action}, result={denied.decision['result']})")
    print("   The agent may not exceed its authorized cap. The denial itself is logged.")

    _banner("3. Within authority — executed, chained, verifiable")
    approval = {
        "id": "apr_01DEMO",
        "delegation_id": delegation.id,
        "action": "ad.credit.purchase",
        "amount": "2000.00",
        "approver": "oidc|acme-retail|usr_8842",
        "nonce": "nonce-demo",
        "method": "oidc_consent",
        "acr": "urn:mace:incommon:iap:silver",
    }
    approval_marker = f"(approval {approval['id']})"
    allowed, result2 = act(
        ledger, [delegation],
        {"action": "ad.credit.purchase", "system": "meta-ads", "amount": "2000.00",
         "currency": "USD", "resource_type": "ad_credit_account",
         "resource_id": "acme_retail_meta", "external_ref": "meta_ad_order_993813",
         "personal_data_refs": ["cust_4471"]},
        PROFILE, pub, approval=approval,
    )
    print(f"   outcome   = {result2.outcome}   {approval_marker}")
    print(f"   receipt   = {allowed.id}")

    _banner("4. The four questions, answered from receipts alone")
    print(f"   1. Which agent?      {allowed.actor['spiffe_id']}")
    print(f"   2. Acting for whom?  {delegation.subject['id']}")
    print(f"   3. Which credential? {allowed.actor['credential_kid']}")
    print(f"   4. Under which approval? {approval['id']}")

    _banner("5. Tamper with history — the chain catches it")
    ledger.receipts[0].action = "social.post.publish"
    ok, problems = ledger.verify_chain()
    print(f"   hash chain verifies: {'NO' if problems else 'YES'}")
    if problems:
        print(f"   broken at: {problems[0]}")
    return 0


def cmd_erasure(subject: str, demo: bool) -> int:
    priv, pub = new_keys()
    ledger = Ledger()

    if demo:
        d = create_delegation(
            priv,
            subject={"type": "human", "id": "oidc|acme-retail|usr_9011"},
            actor_id="support-agent",
            constraints={
                "permissions": [{"action": "support.reply", "system": "zendesk"}],
                "max_amount": {"value": "0.00", "currency": "USD"},
                "requires_human_approval_above": {"value": "0.00", "currency": "USD"},
            },
            expires_at=_iso(60),
        )
        for i in range(2):
            act(ledger, [d],
                {"action": "support.reply", "system": "zendesk", "amount": "0.00",
                 "currency": "USD", "resource_type": "ticket",
                 "resource_id": f"ticket_{1000 + i}",
                 "personal_data_refs": [subject]},
                PROFILE, pub, fleet="support")

    registry = {
        subject: [
            {"system": "zendesk", "records": 2, "method": "customer_connector"},
            {"system": "internal_crm", "records": 14, "method": "customer_connector"},
        ],
    }
    artifacts = [{"artifact": "support_outcomes_model", "owner": "support-analytics",
                  "action_required": "customer_action"}]
    plan = build_erasure_plan(ledger, subject, registry, artifacts)

    _banner(f"erasure plan — subject {subject}")
    print(json.dumps(plan.to_dict(), indent=2, ensure_ascii=False))
    return 0


def cmd_profile() -> int:
    print(json.dumps(PROFILE.document(), indent=2))
    return 0


PROFILE = ValidationProfile.example()

def main(argv=None):
    p = argparse.ArgumentParser(prog="agentid")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("version")
    sub.add_parser("demo")
    e = sub.add_parser("erasure")
    e.add_argument("subject")
    e.add_argument("--demo", action="store_true", help="seed a two-ticket demo ledger")
    sub.add_parser("profile")
    args = p.parse_args(argv)
    if args.cmd == "version":
        return cmd_version()
    if args.cmd == "demo":
        return cmd_demo()
    if args.cmd == "erasure":
        return cmd_erasure(args.subject, args.demo)
    if args.cmd == "profile":
        return cmd_profile()
    return 1


if __name__ == "__main__":
    sys.exit(main())
