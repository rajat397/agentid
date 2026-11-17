import { test, expect } from "vitest";
import { validate, issueDelegation, type Approval } from "./validator";

const NOW = new Date("2026-11-17T20:00:00Z");
const sub = { type: "human", id: "oidc|acme-retail|usr_8842" };
const actor = { type: "agent" as const, id: "marketing-agent", spiffe_id: "spiffe://example.trust/agent/marketing-agent" };
const baseConstraints = {
  permissions: [{ action: "ad.credit.purchase", system: "meta-ads" }],
  maxAmount: { value: "2000.00", currency: "USD" },
  requiresHumanApprovalAbove: { value: "500.00", currency: "USD" },
};
const dlg = () => issueDelegation("dlg_test", sub, actor, baseConstraints, 1800, NOW);

test("within cap, no approval required", () => {
  const r = validate([dlg()], { action: "ad.credit.purchase", system: "meta-ads", amount: "400.00", currency: "USD" }, null, 0, NOW);
  expect(r.outcome).toBe("valid");
});
test("over cap denied", () => {
  const r = validate([dlg()], { action: "ad.credit.purchase", system: "meta-ads", amount: "4500.00", currency: "USD" }, null, 0, NOW);
  expect(r.outcome).toBe("invalid");
  expect(r.reason).toContain("exceeds cap");
});
test("over approval threshold without approval is indeterminate", () => {
  const r = validate([dlg()], { action: "ad.credit.purchase", system: "meta-ads", amount: "1000.00", currency: "USD" }, null, 0, NOW);
  expect(r.outcome).toBe("indeterminate");
  expect(r.obligations[0]?.type).toBe("cosign_above");
});
const approval: Approval = { id: "apr_1", delegation_id: "dlg_test", action: "ad.credit.purchase", amount: "1000.00", approver: "usr_8842", nonce: "n1" };
test("over approval threshold with approval is valid", () => {
  const r = validate([dlg()], { action: "ad.credit.purchase", system: "meta-ads", amount: "1000.00", currency: "USD" }, approval, 0, NOW);
  expect(r.outcome).toBe("valid");
  expect(r.obligations[0]?.status).toBe("discharged");
});
test("approval with wrong delegation id rejected", () => {
  const a = { ...approval, delegation_id: "dlg_other" };
  const r = validate([dlg()], { action: "ad.credit.purchase", system: "meta-ads", amount: "1000.00", currency: "USD" }, a, 0, NOW);
  expect(r.outcome).toBe("invalid");
});
test("budget exhausted denied", () => {
  const d = issueDelegation("dlg_b", sub, actor, {
    ...baseConstraints,
    maxAmount: { value: "5000.00", currency: "USD" },
    budget: { key: "ads_q4", value: "2000.00", currency: "USD" },
  }, 1800, NOW);
  const r = validate([d], { action: "ad.credit.purchase", system: "meta-ads", amount: "500.00", currency: "USD", budgetKey: "ads_q4" }, null, 1900, NOW);
  expect(r.outcome).toBe("invalid");
  expect(r.reason).toContain("budget exhausted");
});
test("child exceeding parent cap rejected (attenuation)", () => {
  const parent = issueDelegation("dlg_p", sub, actor, baseConstraints, 1800, NOW, null, 1);
  const child = issueDelegation("dlg_c", sub, actor, {
    ...baseConstraints,
    maxAmount: { value: "3000.00", currency: "USD" },
  }, 900, NOW, "dlg_p", 2);
  const r = validate([parent, child], { action: "ad.credit.purchase", system: "meta-ads", amount: "500.00", currency: "USD" }, null, 0, NOW);
  expect(r.outcome).toBe("invalid");
  expect(r.reason).toContain("attenuation");
});
test("expired delegation denied", () => {
  const d = issueDelegation("dlg_exp", sub, actor, baseConstraints, 0, new Date(NOW.getTime() - 10000));
  const r = validate([d], { action: "ad.credit.purchase", system: "meta-ads", amount: "10.00", currency: "USD" }, null, 0, NOW);
  expect(r.outcome).toBe("invalid");
  expect(r.reason).toBe("delegation expired");
});
test("chain depth > profile max rejected", () => {
  const a = issueDelegation("d1", sub, actor, baseConstraints, 1800, NOW, null, 1);
  const b = issueDelegation("d2", sub, actor, baseConstraints, 1800, NOW, "d1", 2);
  const c = issueDelegation("d3", sub, actor, baseConstraints, 1800, NOW, "d2", 3);
  const d4 = issueDelegation("d4", sub, actor, baseConstraints, 1800, NOW, "d3", 4);
  const r = validate([a, b, c, d4], { action: "ad.credit.purchase", system: "meta-ads", amount: "10.00", currency: "USD" }, null, 0, NOW);
  expect(r.outcome).toBe("invalid");
});
test("no permission for action/system", () => {
  const r = validate([dlg()], { action: "social.post.publish", system: "meta-ads", amount: "10.00", currency: "USD" }, null, 0, NOW);
  expect(r.outcome).toBe("invalid");
});
