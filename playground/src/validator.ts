export type Outcome = "valid" | "invalid" | "indeterminate";

export interface Permission {
  action: string;
  system: string;
}
export interface Delegation {
  id: string;
  subject: { type: string; id: string };
  actor: { type: string; id: string; spiffe_id: string };
  parentDelegationId: string | null;
  chainDepth: number;
  constraints: {
    permissions: Permission[];
    maxAmount: { value: string; currency: string };
    requiresHumanApprovalAbove: { value: string; currency: string };
    budget?: { key: string; value: string; currency: string; periodSeconds?: number };
  };
  issuedAt: string;
  expiresAt: string;
}
export interface ActionRequest {
  action: string;
  system: string;
  amount: string;
  currency: string;
  budgetKey?: string;
}
export interface Approval {
  id: string;
  delegation_id: string;
  action: string;
  amount: string;
  approver: string;
  nonce: string;
}
export interface Evaluation {
  constraint: string;
  satisfied: boolean;
  [k: string]: unknown;
}
export interface Obligation {
  type: string;
  value?: string;
  observed?: string;
  status: string;
  approval_id?: string;
}
export interface ValidationResult {
  outcome: Outcome;
  reason: string;
  obligations: Obligation[];
  constraintsEvaluated: Evaluation[];
}

function dec(v: string): number {
  const n = Number(v);
  if (Number.isNaN(n)) throw new Error(`not a decimal string: ${v}`);
  return n;
}
function iso(d: Date): string {
  return d.toISOString().replace(/\.\d{3}Z$/, "Z");
}
function parseIso(s: string): Date {
  const d = new Date(s);
  if (Number.isNaN(d.getTime())) throw new Error(`bad ISO time: ${s}`);
  return d;
}

export const PROFILE = { maxChainLength: 3, maxTokenLifetimeSeconds: 900 };

export function validate(
  chain: Delegation[],
  action: ActionRequest,
  approval: Approval | null = null,
  budgetSpent: number = 0,
  now: Date = new Date(),
): ValidationResult {
  if (chain.length === 0) {
    return { outcome: "invalid", reason: "empty delegation chain", obligations: [], constraintsEvaluated: [] };
  }
  if (chain.length > PROFILE.maxChainLength) {
    return {
      outcome: "invalid",
      reason: `chain depth ${chain.length} exceeds profile max_chain_length ${PROFILE.maxChainLength}`,
      obligations: [],
      constraintsEvaluated: [],
    };
  }
  for (let i = 0; i + 1 < chain.length; i++) {
    const parent = chain[i]!, child = chain[i + 1]!;
    const pPerms = new Set(parent.constraints.permissions.map((p) => `${p.action}@${p.system}`));
    const cPerms = new Set(child.constraints.permissions.map((p) => `${p.action}@${p.system}`));
    for (const p of cPerms) {
      if (!pPerms.has(p)) {
        return { outcome: "invalid", reason: "attenuation violated: child permissions exceed parent", obligations: [], constraintsEvaluated: [] };
      }
    }
    if (dec(child.constraints.maxAmount.value) > dec(parent.constraints.maxAmount.value)) {
      return { outcome: "invalid", reason: "attenuation violated: child max_amount exceeds parent", obligations: [], constraintsEvaluated: [] };
    }
    if (parseIso(child.expiresAt) > parseIso(parent.expiresAt)) {
      return { outcome: "invalid", reason: "attenuation violated: child expiry exceeds parent", obligations: [], constraintsEvaluated: [] };
    }
  }
  const leaf = chain[chain.length - 1]!;
  if (parseIso(leaf.expiresAt) < now) {
    return { outcome: "invalid", reason: "delegation expired", obligations: [], constraintsEvaluated: [] };
  }
  const want = `${action.action}@${action.system}`;
  const perms = leaf.constraints.permissions.map((p) => `${p.action}@${p.system}`);
  const permissionOk = perms.includes(want);
  const evaluated: Evaluation[] = [{ constraint: "permission", pair: [action.action, action.system], satisfied: permissionOk }];
  if (!permissionOk) {
    return { outcome: "invalid", reason: "action/system not permitted by delegation", obligations: [], constraintsEvaluated: evaluated };
  }
  const amount = dec(action.amount);
  const budget = leaf.constraints.budget;
  if (budget) {
    const cap = dec(budget.value);
    const remaining = cap - budgetSpent;
    const satisfied = amount <= remaining;
    evaluated.push({ constraint: "sum_max", budget: budget.key, cap: budget.value, spent: String(budgetSpent), remaining: String(remaining), satisfied });
    if (!satisfied) {
      return { outcome: "invalid", reason: `budget exhausted: ${budgetSpent + amount} exceeds cap ${cap} for ${budget.key}`, obligations: [], constraintsEvaluated: evaluated };
    }
  }
  const cap = dec(leaf.constraints.maxAmount.value);
  const capOk = amount <= cap;
  evaluated.push({ constraint: "max_amount", bound: leaf.constraints.maxAmount.value, observed: action.amount, satisfied: capOk });
  if (!capOk) {
    return { outcome: "invalid", reason: `amount ${amount} exceeds cap ${cap}`, obligations: [], constraintsEvaluated: evaluated };
  }
  const threshold = dec(leaf.constraints.requiresHumanApprovalAbove.value);
  const approvalNeeded = amount > threshold;
  evaluated.push({ constraint: "requires_human_approval_above", bound: leaf.constraints.requiresHumanApprovalAbove.value, observed: action.amount, satisfied: !approvalNeeded });
  if (approvalNeeded) {
    if (!approval) {
      return { outcome: "indeterminate", reason: `amount ${amount} exceeds approval threshold ${threshold}; no approval supplied`, obligations: [{ type: "cosign_above", value: leaf.constraints.requiresHumanApprovalAbove.value, observed: action.amount, status: "required" }], constraintsEvaluated: evaluated };
    }
    const ok =
      approval.delegation_id === leaf.id &&
      approval.action === action.action &&
      dec(approval.amount) >= amount &&
      !!approval.approver &&
      !!approval.nonce;
    evaluated.push({ constraint: "approval", approval_id: approval.id, satisfied: ok });
    if (!ok) {
      return { outcome: "invalid", reason: "approval does not satisfy the cosign_above obligation", obligations: [], constraintsEvaluated: evaluated };
    }
    return { outcome: "valid", reason: "within constraints", obligations: [{ type: "cosign_above", value: leaf.constraints.requiresHumanApprovalAbove.value, observed: action.amount, status: "discharged", approval_id: approval.id }], constraintsEvaluated: evaluated };
  }
  return { outcome: "valid", reason: "within constraints", obligations: [], constraintsEvaluated: evaluated };
}

export function issueDelegation(
  id: string,
  subject: Delegation["subject"],
  actor: Delegation["actor"],
  constraints: Delegation["constraints"],
  ttlSeconds = 1800,
  now: Date = new Date(),
  parentDelegationId: string | null = null,
  chainDepth = 1,
): Delegation {
  return {
    id, subject, actor,
    parentDelegationId,
    chainDepth,
    constraints,
    issuedAt: iso(now),
    expiresAt: iso(addSeconds(now, ttlSeconds)),
  };
}

function addSeconds(d: Date, s: number): Date {
  return new Date(d.getTime() + s * 1000);
}
