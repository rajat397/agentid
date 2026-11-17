export type GateVerdict = "valid" | "invalid" | "indeterminate";
export interface GateState { amount: number; cap: number; threshold: number; approval: boolean; }

export function computeVerdict(amount: number, cap: number, threshold: number, approval: boolean): GateVerdict {
  if (amount > cap) return "invalid";
  if (amount > threshold && !approval) return "indeterminate";
  return "valid";
}
