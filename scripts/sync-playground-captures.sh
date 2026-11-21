#!/usr/bin/env bash
# Regenerate every real-CLI artifact shown on the playground.
# Run from repo root: bash scripts/sync-playground-captures.sh
set -euo pipefail
REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"
GO_BIN="${GO:-go}"
SUBJECT="${ERASURE_SUBJECT:-cust_4471}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

escape() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

demo_html="$("$GO_BIN" run ./cmd/agentid demo 2>/dev/null | escape)"
"$GO_BIN" run ./cmd/agentid evidence export --demo --out "$TMP/bundle.json" >/dev/null 2>&1
evidence_html="$("$GO_BIN" run ./cmd/agentid evidence verify --file "$TMP/bundle.json" 2>/dev/null | escape)"
"$GO_BIN" run ./tools/crosstest > "$TMP/cross.json" 2>/dev/null
pq_html="$("$GO_BIN" run ./cmd/agentid verify-signed --artifact "$TMP/cross.json" 2>/dev/null | escape)"
otel_html="$("$GO_BIN" run ./cmd/agentid otel-demo --summary 2>/dev/null | escape)"
"$GO_BIN" run ./cmd/agentid erasure "$SUBJECT" --demo > "$TMP/erasure.json" 2>/dev/null
erasure_text="$(python3 - "$TMP/erasure.json" <<'PYEOF'
import json, sys
plan = json.load(open(sys.argv[1], encoding="utf-8"))
systems = ", ".join(
    f"{row['system']} ({row['records']} records)"
    for row in plan.get("downstream_systems", [])
) or "none"
print(f"erasure plan — subject {plan['subject_id']}")
print(f"receipts: {plan['total_receipts']} · delegations: {len(plan['delegations'])}")
print(f"deadline: {plan['deadline']} ({plan['days_remaining']} days)")
print(f"systems: {systems}")
PYEOF
)"
erasure_html="$(printf '%s
' "$erasure_text" | escape)"

flow_allow="$("$GO_BIN" run ./cmd/agentid flow-demo --mode allow 2>/dev/null)"
flow_deny="$("$GO_BIN" run ./cmd/agentid flow-demo --mode deny 2>/dev/null)"

python3 - "$REPO/playground/index.html" "$demo_html" "$evidence_html" "$pq_html" "$otel_html" "$erasure_html" "$flow_allow" "$flow_deny" <<'PYEOF'
import sys, re
path, demo, evidence, pq, otel, erasure, flow_allow, flow_deny = sys.argv[1:9]
s = open(path, encoding="utf-8").read()
markers = {
    "DEMO_CAPTURE": demo,
    "EVIDENCE_CAPTURE": evidence,
    "PQ_CAPTURE": pq,
    "OTEL_CAPTURE": otel,
    "ERASURE_CAPTURE": erasure,
    "FLOW_ALLOW_DATA": flow_allow,
    "FLOW_DENY_DATA": flow_deny,
}
for name, body in markers.items():
    pattern = rf"(<!-- {name}_START -->).*?(<!-- {name}_END -->)"
    s = re.sub(pattern, lambda m: m.group(1) + "\n" + body + "\n" + m.group(2),
               s, flags=re.S)
open(path, "w", encoding="utf-8").write(s)
print("captures synced into", path)
PYEOF
