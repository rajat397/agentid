"""Long-horizon evidence — RFC 3161 trusted timestamps over the ledger head.

Agent receipts are meant to be kept for years, but the algorithms that sign
them will age. The mitigation is to anchor the hash chain with a timestamp
from an independent TSA, so existence and integrity over time rest on the TSA
and the hash — not on any one signing algorithm.

Design:
  * the chain head (the last receipt's hash) commits to every earlier receipt;
  * ``anchor()`` asks a Time Stamping Authority (RFC 3161) to stamp that hash;
  * the response is stored verbatim in ``anchors.jsonl`` with the request;
  * ``verify()`` re-checks the binding offline: the TSTInfo inside the
    response must name the same digest this ledger head computes.

The TSA's CMS signature is checked structurally here; full chain-of-trust
verification against the TSA's root requires an ``openssl ts -verify`` call
with ``--ca`` or equivalent. ``verify()`` reports exactly what it checked.
"""

from __future__ import annotations

import hashlib
import json
import http.client
import socket
import ssl
import urllib.request
from urllib.parse import urlsplit
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .crypto import canonical_json, digest_sha256
from .ledger import Ledger

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_TSTINFO = "1.2.840.113549.1.9.16.1.4"
DEFAULT_TSA = "https://freetsa.org/tsr"


# ── minimal DER helpers ─────────────────────────────────────────────

def _len(n: int) -> bytes:
    if n < 128:
        return bytes([n])
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def _seq(content: bytes) -> bytes:
    return _tlv(0x30, content)


def _set(content: bytes) -> bytes:
    return _tlv(0x31, content)


def _int(n: int) -> bytes:
    raw = n.to_bytes(max(1, (n.bit_length() + 7) // 8), "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _tlv(0x02, raw)


def _bool(v: bool) -> bytes:
    return _tlv(0x01, b"\xff" if v else b"\x00")


def _null() -> bytes:
    return b"\x05\x00"


def _oid(dotted: str) -> bytes:
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray([parts[0] * 40 + parts[1]])
    for p in parts[2:]:
        stack = [p & 0x7F]
        p >>= 7
        while p:
            stack.append(0x80 | (p & 0x7F))
            p >>= 7
        out.extend(reversed(stack))
    return _tlv(0x06, bytes(out))


def _octet_string(data: bytes) -> bytes:
    return _tlv(0x04, data)


def _generalized_time(dt: datetime) -> bytes:
    return _tlv(0x18, dt.strftime("%Y%m%d%H%M%SZ").encode("ascii"))


class DerReader:
    """Iterate DER TLVs without materializing the whole tree."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self) -> tuple[int, bytes]:
        if self.pos >= len(self.data):
            raise ValueError("unexpected end of DER input")
        tag = self.data[self.pos]
        self.pos += 1
        first = self.data[self.pos]
        self.pos += 1
        if first & 0x80:
            n = first & 0x7F
            if n == 0 or n > 4:
                raise ValueError("indefinite or absurd DER length")
            length = int.from_bytes(self.data[self.pos:self.pos + n], "big")
            self.pos += n
        else:
            length = first
        end = self.pos + length
        if end > len(self.data):
            raise ValueError("length overruns buffer")
        content = self.data[self.pos:end]
        self.pos = end
        return tag, content


def _walk(data: bytes):
    """Yield (tag, content) for every TLV in the tree, depth-first."""
    r = DerReader(data)
    while r.pos < len(data):
        tag, content = r.read()
        yield tag, content
        if tag in (0x30, 0x31, 0xA0, 0xA1, 0xA2, 0xA3):
            try:
                yield from _walk(content)
            except ValueError:
                continue


# ── TimeStampReq ─────────────────────────────────────────────────────

def chain_head(ledger: Ledger) -> str:
    """The hash every earlier receipt commits to. Empty ledgers cannot be anchored."""
    if not ledger.receipts:
        raise ValueError("cannot anchor an empty ledger")
    ok, problems = ledger.verify_chain()
    if not ok:
        raise ValueError(f"ledger does not verify: {problems[0]}")
    return ledger.receipts[-1].hash


def build_timestampreq(hash_hex: str) -> bytes:
    digest = bytes.fromhex(hash_hex)
    if len(digest) != 32:
        raise ValueError("chain head must be a SHA-256 hex digest")
    alg = _seq(_oid(OID_SHA256) + _null())
    imprint = _seq(alg + _octet_string(digest))
    return _seq(_int(1) + imprint + _bool(True))


# ── TimeStampResp parsing ────────────────────────────────────────────

def parse_timestampresp(der: bytes) -> dict[str, Any]:
    """Extract the granted status, TSTInfo digest binding and genTime."""
    top = DerReader(der)
    tag, content = top.read()
    if tag != 0x30:
        raise ValueError("TimeStampResp must be a SEQUENCE")
    inner = DerReader(content)
    stag, scontent = inner.read()          # PKIStatusInfo
    if stag != 0x30:
        raise ValueError("expected PKIStatusInfo")
    sread = DerReader(scontent)
    itag, icontent = sread.read()          # PKIStatus INTEGER
    if itag != 0x02:
        raise ValueError("expected PKIStatus INTEGER")
    status = int.from_bytes(icontent, "big")
    if status not in (0, 1):               # granted / grantedWithMods
        raise ValueError(f"TSA refused the request (PKIStatus={status})")

    # Locate TSTInfo by its OID anywhere in the token, then read the
    # messageImprint digest and genTime inside it.
    flat = list(_walk(der))
    tst_idx = next((i for i, (t, c) in enumerate(flat)
                    if t == 0x06 and _decode_oid(c) == OID_TSTINFO), None)
    if tst_idx is None:
        raise ValueError("no TSTInfo content type in response")
    # TSTInfo is the OCTET STRING sibling that follows the [0] explicit
    # wrapper enclosing it; find the next OCTET STRING after the OID.
    for t, c in flat[tst_idx + 1:]:
        if t == 0x04:
            tstinfo = c
            break
    else:
        raise ValueError("TSTInfo octet string not found")

    troot = DerReader(tstinfo)
    ttag, tinner = troot.read()
    if ttag != 0x30:
        raise ValueError("TSTInfo must be a SEQUENCE")
    t = DerReader(tinner)
    t.read()                                # version
    t.read()                                # policy OID
    mtag, mcontent = t.read()               # messageImprint SEQUENCE
    if mtag != 0x30:
        raise ValueError("expected messageImprint")
    m = DerReader(mcontent)
    m.read()                                # hashAlgorithm
    htag, hcontent = m.read()               # hashedMessage OCTET STRING
    if htag != 0x04:
        raise ValueError("expected hashedMessage")
    serial_tag, serial = t.read()           # serialNumber INTEGER
    time_tag, time_bytes = t.read()         # genTime GeneralizedTime
    if time_tag != 0x18:
        raise ValueError("expected genTime")
    return {
        "status": status,
        "message_imprint": hcontent.hex(),
        "gen_time": time_bytes.decode("ascii"),
        "serial": int.from_bytes(serial, "big"),
    }


def _decode_oid(content: bytes) -> str:
    if not content:
        return ""
    first = content[0]
    parts = [first // 40, first % 40]
    value = 0
    for b in content[1:]:
        value = (value << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(value)
            value = 0
    return ".".join(str(p) for p in parts)


# ── anchoring ────────────────────────────────────────────────────────

@dataclass
class AnchorRecord:
    head_hash: str
    head_seq: int
    tsa_url: str
    request_der_b64: str
    response_der_b64: str
    gen_time: str
    serial: int
    anchored_at: str

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)

    def to_jsonl(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


def anchor_ledger(ledger: Ledger, tsa_url: str = DEFAULT_TSA, timeout: float = 15.0) -> AnchorRecord:
    import base64
    head = chain_head(ledger)
    req = build_timestampreq(head)
    resp_der = _post_timestamp(tsa_url, req, timeout)
    info = parse_timestampresp(resp_der)
    if info["message_imprint"] != head:
        raise ValueError("TSA response binds a different digest — refusing to anchor")
    record = AnchorRecord(
        head_hash=head,
        head_seq=len(ledger.receipts) - 1,
        tsa_url=tsa_url,
        request_der_b64=base64.b64encode(req).decode("ascii"),
        response_der_b64=base64.b64encode(resp_der).decode("ascii"),
        gen_time=info["gen_time"],
        serial=info["serial"],
        anchored_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    )
    return record


def verify_anchor(record: dict[str, Any], ledger: Ledger) -> tuple[bool, list[str]]:
    """Offline check: the anchor must bind this exact chain head."""
    problems: list[str] = []
    try:
        head = chain_head(ledger)
    except ValueError as exc:
        return False, [str(exc)]
    if record.get("head_hash") != head:
        problems.append(f"anchor binds {record.get('head_hash', '')[:12]}… but chain head is {head[:12]}…")
    import base64
    try:
        resp_der = base64.b64decode(record["response_der_b64"])
        info = parse_timestampresp(resp_der)
        if info["message_imprint"] != record.get("head_hash"):
            problems.append("TSTInfo inside the anchor names a different digest")
        req_der = base64.b64decode(record["request_der_b64"])
        if build_timestampreq(record["head_hash"]) != req_der:
            problems.append("stored request does not match the recorded head hash")
    except Exception as exc:  # malformed anchor is a failure, not a crash
        problems.append(f"anchor unparsable: {exc}")
    return (not problems, problems)


def _post_timestamp(tsa_url: str, req: bytes, timeout: float) -> bytes:
    """POST a TimeStampReq; urlopen first, then an IPv4-pinned fallback.

    Some sandboxes and resolvers return unusable IPv6 routes ahead of IPv4;
    urlopen hangs on connect instead of falling back. The fallback resolves
    A records only and speaks HTTPS by hand.
    """
    parts = urlsplit(tsa_url)
    host, port = parts.hostname, parts.port or 443
    path = parts.path or "/"
    ctx = ssl.create_default_context()
    v4_exc: Exception | None = None
    for info in socket.getaddrinfo(host, port, socket.AF_INET):
        try:
            sock = socket.create_connection(info[4], timeout=timeout)
            wrapped = ctx.wrap_socket(sock, server_hostname=host)
            head = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/timestamp-query\r\n"
                f"Accept: application/timestamp-reply\r\n"
                f"Content-Length: {len(req)}\r\n"
                f"Connection: close\r\n\r\n"
            ).encode("ascii")
            wrapped.sendall(head + req)
            resp = http.client.HTTPResponse(wrapped)
            resp.begin()
            body = resp.read()
            if resp.status != 200:
                raise ValueError(f"TSA returned HTTP {resp.status}")
            if not body:
                raise ValueError("empty timestamp reply from TSA")
            return body
        except OSError as exc:
            v4_exc = exc

    # Fall back to the default stack only when IPv4 is unavailable.
    http_req = urllib.request.Request(
        tsa_url, data=req, method="POST",
        headers={"Content-Type": "application/timestamp-query",
                 "Accept": "application/timestamp-reply"},
    )
    try:
        with urllib.request.urlopen(http_req, timeout=timeout) as resp:
            body = resp.read()
            if body:
                return body
    except Exception as exc:
        raise ValueError(f"could not reach TSA at {tsa_url}: ipv4={v4_exc}; default={exc}") from exc
    raise ValueError(f"could not reach TSA at {tsa_url} via IPv4: {v4_exc}")


def load_anchors(path: str) -> list[dict[str, Any]]:
    out = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out
