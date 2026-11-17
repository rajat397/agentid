import { mountTree as mountHeroTree } from "./tree";
import { TreeScene } from "./tree3d";
import { GateScene, computeVerdict, type GateVerdict } from "./gate";

/* ── hero tree (ambient, full-bleed) ─────────────────────────── */
const heroCanvas = document.getElementById("hero-canvas") as HTMLCanvasElement | null;
try {
  const stage = heroCanvas?.parentElement;
  if (stage) mountHeroTree(stage);
} catch (err) {
  console.warn("[agentid] hero tree failed; page still works:", err);
}

/* ── tree-section interactive scene ───────────────────────────── */
const treeStage = document.getElementById("tree-stage");
try {
  if (treeStage) new TreeScene(treeStage).init();
} catch (err) {
  console.warn("[agentid] tree scene failed:", err);
  if (treeStage) treeStage.innerHTML = '<div style="display:grid;place-items:center;height:100%;color:#8B94A3;font-family:monospace;font-size:.8rem">3D unavailable — <a href="https://github.com/rajat397/agentid" style="color:#2DD4BF">see the code</a></div>';
}

/* ── gate scene + sliders ─────────────────────────────────────── */
const gateStage = document.getElementById("gate-stage");
const ids = ["g-amount", "g-cap", "g-threshold"] as const;
const outputs = { amount: "g-amount-out", cap: "g-cap-out", threshold: "g-threshold-out" } as const;
const gateVerdictEl = document.getElementById("gate-verdict");
const gateReasonEl = document.getElementById("gate-reason");
const gateVerdictWrap = document.querySelector<HTMLElement>(".gate-verdict");

const state = { amount: 1000, cap: 2000, threshold: 500, approval: true };

function fmt(n: number): string {
  return "$" + n.toFixed(2).replace(/\B(?=(\d{3})+(?!\d))/g, ",");
}
function readSliders(): void {
  state.amount = Number((document.getElementById("g-amount") as HTMLInputElement)?.value ?? 1000);
  state.cap = Number((document.getElementById("g-cap") as HTMLInputElement)?.value ?? 2000);
  state.threshold = Number((document.getElementById("g-threshold") as HTMLInputElement)?.value ?? 500);
  state.approval = document.getElementById("g-approval")?.getAttribute("aria-checked") === "true";
}
function renderVerdict(): void {
  readSliders();
  const v: GateVerdict = computeVerdict(state.amount, state.cap, state.threshold, state.approval);
  if (gateVerdictEl) {
    gateVerdictEl.textContent = v === "valid" ? "VALID" : v === "invalid" ? "REJECTED" : "NEEDS APPROVAL";
    gateVerdictEl.className = `gv-value ${v}`;
  }
  if (gateReasonEl) {
    gateReasonEl.textContent =
      v === "valid" ? "within constraints — amount under cap, approval on file"
      : v === "invalid" ? (state.amount > state.cap ? `amount ${fmt(state.amount)} exceeds the ${fmt(state.cap)} cap` : "authority revoked")
      : `amount exceeds the ${fmt(state.threshold)} co-sign threshold — a human must approve or it does not happen`;
  }
  if (gateVerdictWrap) gateVerdictWrap.className = `gate-verdict ${v}`;
  document.getElementById("g-amount-out")!.textContent = fmt(state.amount);
  document.getElementById("g-cap-out")!.textContent = fmt(state.cap);
  document.getElementById("g-threshold-out")!.textContent = fmt(state.threshold);

  const fallback = document.getElementById("gate-fallback");
  if (fallback && !fallback.hidden) {
    const ring = document.getElementById("gf-ring");
    const caption = document.getElementById("gf-caption");
    if (ring) { ring.className = `gf-ring ${v === "valid" ? "" : v}`; }
    if (caption) caption.textContent = v === "valid" ? "ALLOWED" : v === "invalid" ? "REJECTED" : "NEEDS APPROVAL";
  }
  gateSceneRef?.setVerdict(v);
}
const gateSceneRef = gateStage ? safeInitGate(gateStage) : null;
function safeInitGate(stage: HTMLElement): GateScene | null {
  try {
    const s = new GateScene(stage);
    s.init();
    return s;
  } catch (err) {
    console.warn("[agentid] gate scene failed; fallback engaged:", err);
    stage.innerHTML = `<div class="gate-fallback" id="gate-fallback"><div class="gf-ring" id="gf-ring"></div><div class="gf-caption mono" id="gf-caption">ALLOWED</div></div>`;
    return null;
  }
}
for (const id of ids) document.getElementById(id)?.addEventListener("input", renderVerdict);
document.getElementById("g-approval")?.addEventListener("click", () => {
  const btn = document.getElementById("g-approval")!;
  btn.setAttribute("aria-checked", btn.getAttribute("aria-checked") === "true" ? "false" : "true");
  renderVerdict();
});
renderVerdict();

/* ── scrollytelling: highlight the active step ────────────────── */
const steps = document.querySelectorAll<HTMLElement>(".step");
if (steps.length && "IntersectionObserver" in window) {
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) e.target.classList.toggle("active", e.isIntersecting);
  }, { threshold: 0.45 });
  steps.forEach((s) => io.observe(s));
}

/* ── terminal: reveal lines on scroll ─────────────────────────── */
const demoPre = document.getElementById("demo-capture");
if (demoPre) {
  // Wrap each line in a reveal span while preserving raw text
  const lines = demoPre.textContent?.split("\n") ?? [];
  demoPre.innerHTML = lines.map((l) => `<div class="line">${escapeHtml(l) || "&nbsp;"}</div>`).join("");
  const io = new IntersectionObserver((entries) => {
    for (const e of entries) {
      if (e.isIntersecting) {
        demoPre.querySelectorAll<HTMLElement>(".line").forEach((line, i) => {
          window.setTimeout(() => line.classList.add("on"), i * 18);
        });
        io.disconnect();
      }
    }
  }, { threshold: 0.05 });
  io.observe(demoPre);
}
function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

/* ── header scroll state ───────────────────────────────────────── */
const header = document.getElementById("site-header");
const onScroll = () => header?.classList.toggle("scrolled", window.scrollY > 24);
window.addEventListener("scroll", onScroll, { passive: true });
onScroll();
