#!/usr/bin/env python3
"""Generate the static playground page from real CLI output.

Regenerate: python3 scripts/generate_playground.py > playground/index.html

The page shows exactly what `agentid demo` and `agentid erasure --demo` print.
No simulation, no animation, no fiction.
"""

import html
import subprocess
import sys

DEMO = subprocess.run(["agentid", "demo"], capture_output=True, text=True, check=True).stdout
ERASURE = subprocess.run(["agentid", "erasure", "cust_4471", "--demo"], capture_output=True, text=True, check=True).stdout
PROFILE = subprocess.run(["agentid", "profile"], capture_output=True, text=True, check=True).stdout
VERSION = subprocess.run(["agentid", "version"], capture_output=True, text=True, check=True).stdout.strip()

def esc(s: str) -> str:
    return html.escape(s)

html_out = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentid — a reference implementation for agent identity</title>
<meta name="description" content="Identity, guardrails, reliability and traceability for software agents. A real, runnable reference implementation — not a slide deck.">
<style>
  :root {{
    --bg: #0d1117; --panel: #161b22; --panel-2: #1c2129;
    --ink: #e6edf3; --dim: #8b949e; --line: #30363d;
    --green: #3fb950; --red: #f85149; --amber: #d29922; --blue: #58a6ff; --accent: #7ee787;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--ink);
    font: 16px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}
  code, pre {{ font-family: ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace; }}
  a {{ color: var(--blue); }}
  .wrap {{ max-width: 980px; margin: 0 auto; padding: 0 1.25rem; }}
  header {{
    border-bottom: 1px solid var(--line); padding: 1.1rem 0;
    position: sticky; top: 0; background: rgba(13,17,23,.92); backdrop-filter: blur(8px); z-index: 10;
  }}
  .hbar {{ display: flex; justify-content: space-between; align-items: center; gap: 1rem; flex-wrap: wrap; }}
  .logo {{ font-weight: 700; font-size: 1.05rem; letter-spacing: .02em; }}
  .logo span {{ color: var(--accent); }}
  nav {{ display: flex; gap: 1.25rem; font-size: .9rem; }}
  nav a {{ color: var(--dim); text-decoration: none; }}
  nav a:hover {{ color: var(--ink); }}
  .hero {{ padding: 3.5rem 0 2.5rem; border-bottom: 1px solid var(--line); }}
  h1 {{ font-size: 2.4rem; line-height: 1.15; margin: 0 0 1rem; letter-spacing: -0.02em; }}
  h1 .g {{ color: var(--accent); }}
  .sub {{ font-size: 1.12rem; color: var(--dim); max-width: 46ch; }}
  .pillrow {{ margin: 1.5rem 0 0; display: flex; gap: .6rem; flex-wrap: wrap; }}
  .pill {{ border: 1px solid var(--line); border-radius: 999px; padding: .25rem .8rem; font-size: .8rem; color: var(--dim); background: var(--panel); }}
  .pill.live {{ border-color: var(--green); color: var(--green); }}
  .banner {{
    margin: 2rem 0; border: 1px solid var(--amber); border-left: 4px solid var(--amber);
    background: rgba(210,153,34,.07); border-radius: 8px; padding: .9rem 1.1rem; font-size: .92rem; color: var(--ink);
  }}
  .banner b {{ color: var(--amber); }}
  h2 {{ font-size: 1.5rem; margin: 2.5rem 0 1rem; padding-top: 1rem; letter-spacing: -0.01em; }}
  h3 {{ font-size: 1.1rem; margin: 1.75rem 0 .6rem; }}
  figure {{
    margin: 1rem 0 0; background: var(--panel); border: 1px solid var(--line);
    border-radius: 10px; overflow: hidden;
  }}
  figcaption {{
    display: flex; justify-content: space-between; gap: .5rem; flex-wrap: wrap;
    padding: .55rem .9rem; border-bottom: 1px solid var(--line);
    font-size: .78rem; color: var(--dim); background: var(--panel-2);
  }}
  figcaption code {{ color: var(--accent); }}
  pre {{ margin: 0; padding: 1rem; overflow-x: auto; font-size: .78rem; line-height: 1.55; }}
  .c-dim {{ color: var(--dim); }} .c-green {{ color: var(--green); }} .c-red {{ color: var(--red); }}
  .c-amber {{ color: var(--amber); }} .c-blue {{ color: var(--blue); }}
  table {{ width: 100%; border-collapse: collapse; font-size: .92rem; margin: 1rem 0; }}
  th, td {{ text-align: left; padding: .6rem .75rem; border-bottom: 1px solid var(--line); }}
  th {{ color: var(--dim); font-weight: 600; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; }}
  .card {{ background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 1.1rem 1.2rem; }}
  .card h3 {{ margin-top: 0; }}
  .card p {{ color: var(--dim); margin: .3rem 0; font-size: .94rem; }}
  footer {{ border-top: 1px solid var(--line); padding: 2rem 0 3rem; color: var(--dim); font-size: .85rem; }}
  footer a {{ color: var(--blue); }}
  .btnrow {{ display: flex; gap: .75rem; flex-wrap: wrap; margin-top: 1.5rem; }}
  .btn {{ display: inline-block; padding: .6rem 1.1rem; border-radius: 8px; text-decoration: none;
         border: 1px solid var(--line); color: var(--ink); background: var(--panel); font-size: .92rem; }}
  .btn.primary {{ background: var(--green); border-color: var(--green); color: #062d16; font-weight: 700; }}
  .btn:hover {{ border-color: var(--dim); }}
</style>
</head>
<body>

<header>
  <div class="wrap hbar">
    <div class="logo">agent<span>id</span></div>
    <nav>
      <a href="#demo">Demo</a>
      <a href="#erasure">Erasure</a>
      <a href="#evidence">Evidence</a>
      <a href="#profile">Profile</a>
      <a href="https://github.com/rajat397/agentid">GitHub ↗</a>
    </nav>
  </div>
</header>

<div class="wrap">

  <section class="hero">
    <h1>Identity for <span class="g">software agents</span>.</h1>
    <p class="sub">
      One question governs every agent system: <em>who authorized this, under what authority, and can you prove it three years later?</em>
      agentid is a reference implementation that makes that question answerable — with signed delegations,
      hash-chained receipts, and a validation profile that travels with the decision.
    </p>
    <div class="pillrow">
      <span class="pill live">● runnable today</span>
      <span class="pill">MIT · zero heavy deps</span>
      <span class="pill">NIST-aligned</span>
      <span class="pill">experimental — not production</span>
    </div>
    <div class="btnrow">
      <a class="btn primary" href="#demo">See it run ↓</a>
      <a class="btn" href="https://github.com/rajat397/agentid">Get the code</a>
    </div>
    <div class="banner"><b>Honest status:</b> this is an experimental reference implementation, not a finished product. It exists so the rest of the ecosystem can build against a real artifact instead of a slide deck.</div>
  </section>

  <section id="demo">
    <h2>The 90-second lifecycle</h2>
    <p>Every terminal frame below is the literal output of <code>agentid demo</code>. Regenerate this page with <code>python3 scripts/generate_playground.py</code>. Nothing is simulated.</p>
    <figure>
      <figcaption><span>command</span><code>agentid demo</code></figcaption>
      <pre>{esc(DEMO)}</pre>
    </figure>
  </section>

  <section id="erasure">
    <h2>The GDPR right to erasure, for agents</h2>
    <p>A subject requests deletion. The plan enumerates every receipt that touched their data, identifies the downstream systems and derived artifacts, and tracks a 30-day deadline — without the control plane ever holding the subject's personal data.</p>
    <figure>
      <figcaption><span>command</span><code>agentid erasure cust_4471 --demo</code></figcaption>
      <pre>{esc(ERASURE)}</pre>
    </figure>
  </section>

  <section id="profile">
    <h2>One content-addressed decision rule</h2>
    <p>Every receipt names the Validation Profile under which it was produced. Anyone can re-derive the decision from the inputs — no vendor trust required.</p>
    <figure>
      <figcaption><span>command</span><code>agentid profile</code></figcaption>
      <pre>{esc(PROFILE)}</pre>
    </figure>
  </section>

  <section id="evidence">
    <h2>Run it yourself</h2>
    <pre class="card">git clone https://github.com/rajat397/agentid
cd agentid
python3 -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pytest          # 10 tests, all passing
agentid demo    # the same output as this page</pre>
    <div class="grid">
      <div class="card"><h3>What it does</h3><p>Signed human→agent delegations, scoped and expiring powers, budget-enforced constraints, approval thresholds, hash-chained receipts, an erasure plan for agent-collected data.</p></div>
      <div class="card"><h3>What it does not do</h3><p>Stop prompt injection. Replace your security review. Claim NIST certification. Serve as an enforcement proxy in production today. Read the threat model first.</p></div>
      <div class="card"><h3>What it aligns with</h3><p>NIST NCCoE agent identity direction, RFC 8693 delegation semantics, OAuth 2.1 as drafted, OpenTelemetry GenAI agent spans, and the emerging SP-1800 practice guide.</p></div>
    </div>
  </section>

</div>

<footer>
  <div class="wrap">
    agentid {VERSION} · MIT · Rajat Srivastava · <a href="https://github.com/rajat397/agentid">github.com/rajat397/agentid</a><br>
    This page was generated from real CLI output. If it ever diverges from <code>agentid demo</code>, the CLI is correct and this page is stale.
  </div>
</footer>

</body>
</html>
"""

print(html_out)
