import { validate, issueDelegation, type Delegation, type Approval } from "./validator";

function fmt(n: number): string {
  return "$" + n.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}

interface State {
  amount: number; cap: number; threshold: number; spent: number;
  approval: boolean; revoked: boolean;
}
const state: State = { amount: 1000, cap: 2000, threshold: 500, spent: 800, approval: true, revoked: false };
let runs = 0;

function el<T extends HTMLElement>(id: string): T {
  const e = document.getElementById(id);
  if (!e) throw new Error(`missing #${id}`);
  return e as T;
}

function readUI(): void {
  state.amount = Number(el<HTMLInputElement>("amount").value);
  state.cap = Number(el<HTMLInputElement>("cap").value);
  state.threshold = Number(el<HTMLInputElement>("threshold").value);
  state.spent = Number(el<HTMLInputElement>("spent").value);
  state.approval = el("approval-toggle").getAttribute("aria-checked") === "true";
  state.revoked = el("revoke-toggle").getAttribute("aria-checked") === "true";
}
function writeUI(): void {
  el("amount").setAttribute("value", String(state.amount));
  el("cap").setAttribute("value", String(state.cap));
  el("threshold").setAttribute("value", String(state.threshold));
  el("spent").setAttribute("value", String(state.spent));
  el("amount-out").textContent = fmt(state.amount);
  el("cap-out").textContent = fmt(state.cap);
  el("threshold-out").textContent = fmt(state.threshold);
  el("spent-out").textContent = fmt(state.spent);
  el("approval-toggle").setAttribute("aria-checked", String(state.approval));
  el("revoke-toggle").setAttribute("aria-checked", String(state.revoked));
}

function buildDelegation(): Delegation {
  return issueDelegation(
    "dlg_c3cafb8c0e3ca0b0",
    { type: "human", id: "oidc|acme-retail|usr_8842" },
    { type: "agent", id: "marketing-agent", spiffe_id: "spiffe://example.trust/agent/marketing-agent" },
    {
      permissions: [{ action: "ad.credit.purchase", system: "meta-ads" }],
      maxAmount: { value: state.cap.toFixed(2), currency: "USD" },
      requiresHumanApprovalAbove: { value: state.threshold.toFixed(2), currency: "USD" },
      budget: { key: "ads_q4", value: "2000.00", currency: "USD", periodSeconds: 7776000 },
    },
    1800,
    new Date(),
  );
}

function run(): void {
  runs += 1;
  const out = el("tryit-out");
  out.classList.remove("flash");
  // force reflow so the class re-adds and the animation re-triggers
  void out.offsetWidth;
  out.classList.add("flash");
  readUI();
  const dlg = buildDelegation();
  const action = { action: "ad.credit.purchase", system: "meta-ads", amount: state.amount.toFixed(2), currency: "USD", budgetKey: "ads_q4" };
  const approval: Approval | null = state.approval
    ? { id: "apr_01DEMO", delegation_id: dlg.id, action: action.action, amount: action.amount, approver: "oidc|acme-retail|usr_8842", nonce: "nonce-demo" }
    : null;

  const result = validate([dlg], action, approval, state.spent);

  // Reflection: revocation override (the validator handles it via a revoked set in production)
  if (state.revoked) {
    result.outcome = "invalid";
    result.reason = "leaf delegation has been revoked";
    result.obligations = [];
  }

  const verdict = el("verdict");
  verdict.textContent = result.outcome;
  verdict.className = `verdict ${result.outcome}`;
  el("reason").textContent = result.reason;

  const obEl = el("obligations");
  obEl.innerHTML = "";
  if (result.obligations.length === 0) {
    obEl.innerHTML = '<div class="ob" style="border-color:var(--line-2);background:transparent;color:var(--dim)">no obligations produced</div>';
  } else {
    for (const o of result.obligations) {
      const div = document.createElement("div");
      div.className = `ob${o.status === "discharged" ? " discharged" : ""}`;
      div.textContent = `${o.type} · ${o.status} · observed ${o.observed ?? "—"}`;
      obEl.appendChild(div);
    }
  }

  const receipt = {
    delegation_id: dlg.id,
    action: action.action,
    system: action.system,
    amount: action.amount,
    currency: action.currency,
    outcome: result.outcome,
    reason: result.reason,
    validated_at: new Date().toISOString().replace(/\.\d{3}Z$/, "Z"),
    run: runs,
    obligations: result.obligations.map((o) => `${o.type}:${o.status}`),
    constraints_evaluated: result.constraintsEvaluated.map((c) => `${c.constraint}=${c.satisfied}`),
  };
  el("receipt-box").textContent = JSON.stringify(receipt, null, 2);

  const lbl = document.getElementById("run-count");
  if (lbl) lbl.textContent = `run #${runs}`;
}

export function mountTryIt(): void {
  const ids = ["amount", "cap", "threshold", "spent"] as const;
  for (const id of ids) el(id).addEventListener("input", run);
  for (const id of ["approval-toggle", "revoke-toggle"] as const) {
    el(id).addEventListener("click", () => {
      const cur = el(id).getAttribute("aria-checked") === "true";
      el(id).setAttribute("aria-checked", String(!cur));
      run();
    });
  }
  el("run-validation").addEventListener("click", run);
  el("reset-validation").addEventListener("click", () => {
    Object.assign(state, { amount: 1000, cap: 2000, threshold: 500, spent: 800, approval: true, revoked: false });
    writeUI();
    run();
  });
  writeUI();
  run();
}
