"""Verify Go-produced signed artifacts using the frozen Python reference.

Usage: python3 tools/py-reference/verify_cross.py <artifacts.json>
Artifacts are emitted by `go run ./tools/crosstest`.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from agentid.crypto import verify  # noqa: E402
from agentid.status import check_status  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: verify_cross.py <artifacts.json>", file=sys.stderr)
        return 2
    data = json.loads(Path(sys.argv[1]).read_text())
    pem = data["public_pem"]
    if not verify(pem, data["delegation_body"], data["delegation_sig"]):
        print("FAILED: delegation signature", file=sys.stderr)
        return 1
    if not verify(pem, data["receipt_body"], data["receipt_sig"]):
        print("FAILED: receipt signature", file=sys.stderr)
        return 1
    status = check_status(
        data["status_token"], 1, data["status_public_keys"], 300, 1800000000
    )
    if status != 0x01:
        print(f"FAILED: status token resolved to {status}", file=sys.stderr)
        return 1
    print("Go-signed delegation, receipt and status token verified by Python reference")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
