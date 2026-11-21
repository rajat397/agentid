/* ── end-to-end flow: real traces captured from the Go CLI ─────── */
type FlowStep = { id: string; actor: string; title: string; detail: string; artifact: string };
type FlowTrace = { mode: string; outcome: string; steps: FlowStep[] };

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function loadFlow(id: string): FlowTrace | null {
  const raw = document.getElementById(id)?.textContent?.replace(/<!--.*?-->/g, "") ?? "";
  try {
    return JSON.parse(raw) as FlowTrace;
  } catch {
    return null;
  }
}

const flows: Record<string, FlowTrace | null> = {
  allow: loadFlow("flow-allow-data"),
  deny: loadFlow("flow-deny-data"),
};
const sequenceEl = document.getElementById("flow-sequence");
const outcomeEl = document.getElementById("flow-outcome");
const actorEl = document.getElementById("flow-actor");
const titleEl = document.getElementById("flow-step-title");
const detailEl = document.getElementById("flow-step-detail");
const artifactEl = document.getElementById("flow-step-artifact");
const flowButtons = Array.from(document.querySelectorAll<HTMLButtonElement>(".flow-btn"));
let flowMode = "allow";
let activeStep = 0;
let playTimers: number[] = [];

function renderFlow(): void {
  const trace = flows[flowMode];
  if (!sequenceEl || !trace || !Array.isArray(trace.steps)) {
    if (detailEl) detailEl.textContent = "Flow capture is unavailable in this build.";
    return;
  }
  playTimers.forEach(window.clearTimeout);
  playTimers = [];
  sequenceEl.innerHTML = trace.steps
    .map((step, i) => `
      <button type="button" class="sequence-step${i === 0 ? " active" : ""}" data-step="${i}">
        <span class="seq-actor mono">${escapeHtml(step.actor)}</span>
        <span class="seq-track"><span class="seq-node"></span><span class="seq-line"></span></span>
        <span class="seq-body"><span class="seq-title">${escapeHtml(step.title)}</span><span class="seq-detail">${escapeHtml(step.detail)}</span></span>
        <span class="seq-index mono">${String(i + 1).padStart(2, "0")}</span>
      </button>`)
    .join("");
  sequenceEl.querySelectorAll<HTMLButtonElement>(".sequence-step").forEach((btn) => {
    btn.addEventListener("click", () => selectStep(Number(btn.dataset.step)));
  });
  activeStep = 0;
  selectStep(0);
}

function selectStep(index: number): void {
  const trace = flows[flowMode];
  if (!trace || !trace.steps[index]) return;
  activeStep = index;
  const step = trace.steps[index];
  sequenceEl?.querySelectorAll<HTMLElement>(".sequence-step").forEach((row, i) => {
    row.classList.toggle("active", i === index);
    row.classList.toggle("done", i < index);
  });
  if (outcomeEl) {
    outcomeEl.textContent = trace.outcome;
    outcomeEl.className = `fd-outcome mono ${trace.outcome.toLowerCase()}`;
  }
  if (actorEl) actorEl.textContent = step.actor.toUpperCase();
  if (titleEl) titleEl.textContent = step.title;
  if (detailEl) detailEl.textContent = step.detail;
  if (artifactEl) {
    try {
      artifactEl.textContent = JSON.stringify(JSON.parse(step.artifact), null, 2);
    } catch {
      artifactEl.textContent = step.artifact;
    }
  }
}

function playFlow(): void {
  const trace = flows[flowMode];
  if (!trace) return;
  playTimers.forEach(window.clearTimeout);
  playTimers = [];
  const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  trace.steps.forEach((_, i) => {
    playTimers.push(window.setTimeout(() => selectStep(i), reduced ? 0 : i * 420));
  });
}

flowButtons.forEach((btn) => {
  btn.addEventListener("click", () => {
    flowMode = btn.dataset.flow ?? "allow";
    flowButtons.forEach((b) => b.classList.toggle("active", b === btn));
    renderFlow();
    playFlow();
  });
});
renderFlow();

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

/* ── header scroll state ───────────────────────────────────────── */
const header = document.getElementById("site-header");
const onScroll = () => header?.classList.toggle("scrolled", window.scrollY > 24);
window.addEventListener("scroll", onScroll, { passive: true });
onScroll();
