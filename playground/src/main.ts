import { gsap } from "gsap";
import type { JourneyScene } from "./journey3d";

type Artifact = { label: string; value: unknown };
type Step = { id: string; actor: string; node: string; title: string; detail: string; artifacts: Artifact[] };
type Branch = { title: string; detail: string; artifacts: Artifact[] };
type Journey = { mode: string; outcome: string; steps: Step[]; branch: Branch };

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function loadJourney(): Journey | null {
  const raw = document.getElementById("flow-allow-data")?.textContent?.replace(/<!--.*?-->/g, "") ?? "";
  try {
    return JSON.parse(raw) as Journey;
  } catch {
    return null;
  }
}

const journey = loadJourney();
const steps = journey?.steps ?? [];
const sequenceEl = document.getElementById("flow-sequence");
const progressEl = document.getElementById("journey-progress");
const countEl = document.getElementById("journey-count");
const outcomeEl = document.getElementById("flow-outcome");
const actorEl = document.getElementById("flow-actor");
const titleEl = document.getElementById("flow-step-title");
const detailEl = document.getElementById("flow-step-detail");
const artifactLabelEl = document.getElementById("flow-artifact-label");
const artifactEl = document.getElementById("flow-step-artifact");
const branchBtn = document.getElementById("flow-branch") as HTMLButtonElement | null;
const returnBtn = document.getElementById("flow-return") as HTMLButtonElement | null;
const beginBtn = document.getElementById("journey-begin") as HTMLButtonElement | null;
const backBtn = document.getElementById("journey-back") as HTMLButtonElement | null;
const nextBtn = document.getElementById("journey-next") as HTMLButtonElement | null;
const replayBtn = document.getElementById("journey-replay") as HTMLButtonElement | null;
const pauseBtn = document.getElementById("journey-pause") as HTMLButtonElement | null;
const mount3d = document.getElementById("journey-3d");
const certCard = document.getElementById("cert-card");
const certTitle = document.getElementById("cert-title");
const certActor = document.getElementById("cert-actor");
const certBody = document.getElementById("cert-body");
let scene: JourneyScene | null = null;
let current = -1;
let artifactIndex = 0;
let branchOpen = false;
let autoTimer: number | null = null;
let started = false;
const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

function pretty(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2);
  } catch {
    return String(value);
  }
}

function summaryFor(step: Step | Branch): string {
  const first = step.artifacts[0];
  return first ? pretty(first.value).slice(0, 1400) : step.detail;
}

async function init3d(): Promise<void> {
  if (!mount3d || steps.length === 0) return;
  try {
    const { JourneyScene: Scene } = await import("./journey3d");
    scene = new Scene(mount3d, steps.map((s) => ({
      id: s.id, actor: s.actor, title: s.title, summary: summaryFor(s),
    })));
    scene.init();
    document.body.classList.add("has-3d");
  } catch {
    mount3d.style.display = "none";
    document.body.classList.remove("has-3d");
  }
}

function renderSequence(): void {
  if (!sequenceEl) return;
  sequenceEl.innerHTML = steps.map((step, i) => `
    <button type="button" class="sequence-step" data-step="${i}">
      <span class="seq-actor mono">${escapeHtml(step.actor)}</span>
      <span class="seq-track"><span class="seq-node"></span><span class="seq-line"></span></span>
      <span class="seq-body"><span class="seq-title">${escapeHtml(step.title)}</span><span class="seq-detail">${escapeHtml(step.detail)}</span></span>
      <span class="seq-index mono">${String(i + 1).padStart(2, "0")}</span>
    </button>`).join("");
  sequenceEl.querySelectorAll<HTMLButtonElement>(".sequence-step").forEach((row) => {
    row.addEventListener("click", () => {
      stopAuto();
      branchOpen = false;
      setStep(Number(row.dataset.step));
    });
  });
}

function renderProgress(): void {
  if (!progressEl) return;
  progressEl.innerHTML = steps.map((_, i) => `<span class="progress-dot" data-dot="${i}"></span>`).join("");
}

function certSummary(value: unknown): string {
  const priority = ["id", "subject", "issuer", "actor", "audience", "body", "delegation_id",
    "envelope", "decision", "constraints", "signature", "additional_signatures", "digest",
    "sha256", "hash", "kid", "alg", "status", "expires_at", "trace_id"];
  const abbreviate = (input: unknown): unknown => {
    if (typeof input === "string") {
      return input.length > 72 ? `${input.slice(0, 24)}…${input.slice(-10)}` : input;
    }
    if (Array.isArray(input)) return input.map(abbreviate);
    if (input && typeof input === "object") {
      return Object.fromEntries(Object.entries(input as Record<string, unknown>)
        .map(([k, v]) => [k, abbreviate(v)]));
    }
    return input;
  };
  const clone = abbreviate(value) as Record<string, unknown>;
  const ordered: Record<string, unknown> = {};
  priority.forEach((key) => { if (key in clone) ordered[key] = clone[key]; });
  Object.keys(clone).forEach((key) => { if (!(key in ordered)) ordered[key] = clone[key]; });
  return pretty(ordered).slice(0, 1600);
}

function updateCertificate(step: Step | Branch, actor?: string): void {
  const artifact = step.artifacts[0];
  if (!artifact) return;
  if (certTitle) certTitle.textContent = artifact.label;
  if (certActor) certActor.textContent = (actor ?? (step as Step).actor ?? "artifact").toUpperCase();
  if (certBody) certBody.textContent = certSummary(artifact.value);
  if (certCard && !reduced) {
    gsap.fromTo(certCard,
      { opacity: 0, rotateY: -14, x: 18 },
      { opacity: 1, rotateY: 0, x: 0, duration: 0.7, ease: "power2.out" });
  }
}

function showArtifact(index: number, animate = true): void {
  const source = branchOpen ? journey?.branch : steps[current];
  const artifact = source?.artifacts[index];
  if (!artifact) return;
  artifactIndex = index;
  if (artifactLabelEl) artifactLabelEl.textContent = artifact.label;
  if (artifactEl) artifactEl.textContent = pretty(artifact.value);
  if (animate && !reduced && artifactEl) {
    gsap.fromTo(artifactEl, { opacity: 0, y: 8 }, { opacity: 1, y: 0, duration: 0.4 });
  }
}

function setStep(index: number): void {
  if (index < 0 || index >= steps.length) return;
  branchOpen = false;
  current = index;
  const step = steps[index];
  if (outcomeEl) {
    outcomeEl.textContent = journey?.outcome ?? "ALLOWED";
    outcomeEl.className = `fd-outcome mono ${(journey?.outcome ?? "").toLowerCase()}`;
  }
  if (actorEl) actorEl.textContent = step.actor.toUpperCase();
  if (titleEl) titleEl.textContent = step.title;
  if (detailEl) detailEl.textContent = step.detail;
  showArtifact(0, false);
  updateCertificate(step);
  if (countEl) countEl.textContent = `${String(index + 1).padStart(2, "0")} / ${String(steps.length).padStart(2, "0")}`;
  sequenceEl?.querySelectorAll<HTMLElement>(".sequence-step").forEach((row, i) => {
    row.classList.toggle("active", i === index);
    row.classList.toggle("done", i < index);
  });
  progressEl?.querySelectorAll<HTMLElement>(".progress-dot").forEach((dot, i) => {
    dot.classList.toggle("active", i === index);
    dot.classList.toggle("done", i < index);
  });
  if (branchBtn) branchBtn.hidden = step.id !== "validate";
  if (returnBtn) returnBtn.hidden = true;
  if (backBtn) backBtn.disabled = index === 0;
  if (nextBtn) nextBtn.disabled = index === steps.length - 1;
  if (beginBtn) beginBtn.hidden = true;
  if (replayBtn) replayBtn.disabled = false;
  updatePauseButton();
  scene?.setStep(index);
  if (!reduced) {
    gsap.fromTo([titleEl, detailEl].filter(Boolean),
      { opacity: 0, y: 10 }, { opacity: 1, y: 0, duration: 0.5, stagger: 0.07 });
  }
}

function openBranch(): void {
  if (!journey?.branch) return;
  branchOpen = true;
  if (outcomeEl) {
    outcomeEl.textContent = "NEEDS APPROVAL";
    outcomeEl.className = "fd-outcome mono blocked";
  }
  if (actorEl) actorEl.textContent = "REVIEWER QUEUE";
  if (titleEl) titleEl.textContent = journey.branch.title;
  if (detailEl) detailEl.textContent = journey.branch.detail;
  showArtifact(0, false);
  if (journey) updateCertificate(journey.branch, "Approval workflow");
  if (branchBtn) branchBtn.hidden = true;
  if (returnBtn) returnBtn.hidden = false;
}

function stopAuto(): void {
  if (autoTimer !== null) {
    window.clearInterval(autoTimer);
    autoTimer = null;
  }
}

function updatePauseButton(): void {
  if (!pauseBtn) return;
  if (reduced) {
    pauseBtn.hidden = true;
    return;
  }
  pauseBtn.hidden = false;
  const atEnd = current >= steps.length - 1;
  pauseBtn.disabled = !started || atEnd;
  pauseBtn.textContent = autoTimer === null ? "Resume" : "Pause";
}

function startAuto(): void {
  if (reduced || started === false || current >= steps.length - 1) return;
  stopAuto();
  autoTimer = window.setInterval(() => {
    if (current >= steps.length - 1) {
      stopAuto();
      updatePauseButton();
      return;
    }
    setStep(current + 1);
  }, 2600);
  updatePauseButton();
}

function begin(): void {
  if (steps.length === 0) return;
  started = true;
  document.body.classList.add("journey-started");
  setStep(0);
  startAuto();
}

void init3d();
renderSequence();
renderProgress();
beginBtn?.addEventListener("click", begin);
backBtn?.addEventListener("click", () => { stopAuto(); setStep(Math.max(0, current - 1)); });
nextBtn?.addEventListener("click", () => { stopAuto(); setStep(Math.min(steps.length - 1, current + 1)); });
replayBtn?.addEventListener("click", () => { stopAuto(); setStep(0); startAuto(); });
branchBtn?.addEventListener("click", () => { stopAuto(); openBranch(); });
pauseBtn?.addEventListener("click", () => {
  if (autoTimer !== null) {
    stopAuto();
    updatePauseButton();
    return;
  }
  startAuto();
});
returnBtn?.addEventListener("click", () => setStep(Math.max(0, current)));

/* ── terminal reveal on scroll ─────────────────────────────────── */
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
