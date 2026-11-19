"""Long-horizon evidence: RFC 3161 timestamp anchoring over the ledger head.

The chain head commits to every earlier receipt; anchoring it with an
independent TSA makes existence and integrity over time rest on the TSA and
the hash — not on any one signing algorithm. All tests run offline: they use
a real FreeTSA response captured as a fixture.
"""

import base64
import json
from pathlib import Path

import pytest

from agentid.anchor import (
    DEFAULT_TSA,
    build_timestampreq,
    chain_head,
    load_anchors,
    parse_timestampresp,
    verify_anchor,
)
from agentid.ledger import Ledger
from agentid.receipt import Receipt

FIXTURES = Path(__file__).parent / "fixtures"
ANCHOR_FILE = FIXTURES / "demo-anchor.jsonl"
LEDGER_FILE = FIXTURES / "demo-anchor.jsonl.ledger.jsonl"


def load_fixture_ledger() -> Ledger:
    receipts = [Receipt(**json.loads(line)) for line in LEDGER_FILE.read_text().splitlines() if line.strip()]
    return Ledger(receipts=receipts)


def fixture_head() -> str:
    return json.loads(ANCHOR_FILE.read_text().splitlines()[0])["head_hash"]


def test_chain_head_rejects_empty_ledger():
    with pytest.raises(ValueError, match="empty ledger"):
        chain_head(Ledger())


def test_chain_head_rejects_tampered_ledger():
    ledger = load_fixture_ledger()
    ledger.receipts[0].action = "social.post.publish"
    with pytest.raises(ValueError):
        chain_head(ledger)


def test_timestampreq_carries_sha256_imprint():
    head = fixture_head()
    der = build_timestampreq(head)
    # hashedMessage must appear verbatim in the request DER
    assert bytes.fromhex(head) in der


def test_fixture_anchor_verifies_offline():
    ledger = load_fixture_ledger()
    anchor = load_anchors(str(ANCHOR_FILE))[0]
    ok, problems = verify_anchor(anchor, ledger)
    assert ok, problems


def test_fixture_response_parses_and_binding_matches():
    ledger = load_fixture_ledger()
    anchor = load_anchors(str(ANCHOR_FILE))[0]
    info = parse_timestampresp(base64.b64decode(anchor["response_der_b64"]))
    assert info["message_imprint"] == chain_head(ledger)
    assert info["gen_time"] == anchor["gen_time"]


def test_anchor_rejects_head_mismatch():
    ledger = load_fixture_ledger()
    anchor = load_anchors(str(ANCHOR_FILE))[0]
    anchor["head_hash"] = "0" * 64
    ok, problems = verify_anchor(anchor, ledger)
    assert not ok
    assert any("chain head" in p or "anchor binds" in p for p in problems)


def test_anchor_rejects_imprint_tamper():
    ledger = load_fixture_ledger()
    anchor = load_anchors(str(ANCHOR_FILE))[0]
    der = bytearray(base64.b64decode(anchor["response_der_b64"]))
    imprint = bytes.fromhex(anchor["head_hash"])
    at = der.find(imprint)
    assert at != -1, "fixture imprint must appear verbatim in the TSTInfo"
    der[at] ^= 0x01
    anchor["response_der_b64"] = base64.b64encode(bytes(der)).decode("ascii")
    ok, problems = verify_anchor(anchor, ledger)
    assert not ok


def test_anchor_rejects_request_mismatch():
    ledger = load_fixture_ledger()
    anchor = load_anchors(str(ANCHOR_FILE))[0]
    anchor["request_der_b64"] = base64.b64encode(build_timestampreq("0" * 64)).decode("ascii")
    ok, problems = verify_anchor(anchor, ledger)
    assert not ok


def test_anchor_rejects_ledger_tamper():
    ledger = load_fixture_ledger()
    ledger.receipts[0].action = "social.post.publish"
    anchor = load_anchors(str(ANCHOR_FILE))[0]
    ok, problems = verify_anchor(anchor, ledger)
    assert not ok


def test_load_anchors_skips_blank_lines(tmp_path):
    p = tmp_path / "a.jsonl"
    p.write_text('{"head_hash": "x"}\n\n   \n{"head_hash": "y"}\n')
    assert [a["head_hash"] for a in load_anchors(str(p))] == ["x", "y"]


def test_default_tsa_is_freetsa():
    assert DEFAULT_TSA == "https://freetsa.org/tsr"
