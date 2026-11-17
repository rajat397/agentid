#!/usr/bin/env bash
# Regenerate the real-CLI-output sections of the playground from the live code.
# Run from repo root: bash scripts/sync-playground-captures.sh
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
AG="$REPO/.venv/bin/agentid"
[ -x "$AG" ] || AG="$(command -v agentid)"

demo_html="$("$AG" demo | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"
erasure_html="$("$AG" erasure cust_4471 --demo | sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g')"

python3 - "$REPO/playground/index.html" "$demo_html" "$erasure_html" <<'PYEOF'
import sys, re
path, demo, erasure = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path, encoding="utf-8").read()
s = re.sub(
    r"(<!-- DEMO_CAPTURE_START -->).*?(<!-- DEMO_CAPTURE_END -->)",
    lambda m: m.group(1) + "\n" + demo + "\n" + m.group(2),
    s, flags=re.S)
s = re.sub(
    r"(<!-- ERASURE_CAPTURE_START -->).*?(<!-- ERASURE_CAPTURE_END -->)",
    lambda m: m.group(1) + "\n" + erasure + "\n" + m.group(2),
    s, flags=re.S)
open(path, "w", encoding="utf-8").write(s)
print("captures synced into", path)
PYEOF
