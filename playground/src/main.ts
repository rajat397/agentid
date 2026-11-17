import { computeVerdict, type GateVerdict } from "./gate-core";

/* ── gate: 2D fallback is the default visual; 3D is opt-in ───── */
const gateStage = document.getElementById("gate-stage");
const toggleBtn = document.getElementById("gate-3d-toggle") as HTMLButtonElement | null;
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

type GateSceneLike = { setVerdict(v: GateVerdict): void } | null;
let gateSceneRef: GateSceneLike = null;

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

  const ring = document.getElementById("gf-ring");
  const caption = document.getElementById("gf-caption");
  if (ring) ring.className = `gf-ring ${v === "valid" ? "" : v}`;
  if (caption) caption.textContent = v === "valid" ? "ALLOWED" : v === "invalid" ? "REJECTED" : "NEEDS APPROVAL";
  gateSceneRef?.setVerdict(v);
}
for (const id of ["g-amount", "g-cap", "g-threshold"]) document.getElementById(id)?.addEventListener("input", renderVerdict);
document.getElementById("g-approval")?.addEventListener("click", () => {
  const btn = document.getElementById("g-approval")!;
  btn.setAttribute("aria-checked", btn.getAttribute("aria-checked") === "true" ? "false" : "true");
  renderVerdict();
});
renderVerdict();

/* ── 3D gate: lazy-loaded, opt-in ────────────────────────────── */
let threeMounted = false;
toggleBtn?.addEventListener("click", async () => {
  if (!gateStage) return;
  if (!threeMounted) {
    toggleBtn.disabled = true;
    toggleBtn.textContent = "loading 3D…";
    try {
      const { GateScene } = await import("./gate");
      const scene = new GateScene(gateStage);
      scene.init();
      gateSceneRef = scene;
      gateSceneRef.setVerdict(computeVerdict(state.amount, state.cap, state.threshold, state.approval));
      gateStage.classList.add("show3d");
      threeMounted = true;
      toggleBtn.textContent = "show 2D";
      toggleBtn.classList.add("on");
    } catch (err) {
      console.warn("[agentid] 3D gate unavailable; staying on 2D:", err);
      toggleBtn.textContent = "3D unavailable";
    } finally {
      toggleBtn.disabled = false;
    }
  } else {
    gateStage.classList.toggle("show3d");
    toggleBtn.textContent = gateStage.classList.contains("show3d") ? "show 2D" : "show in 3D →";
    toggleBtn.classList.toggle("on", gateStage.classList.contains("show3d"));
  }
});

/* ── terminal: reveal lines on scroll ─────────────────────────── */
const demoPre = document.getElementById("demo-capture");
if (demoPre) {
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
