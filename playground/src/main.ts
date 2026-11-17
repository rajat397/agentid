import { mountTree } from "./tree";
import { mountTryIt } from "./tryit";

// ── Tree (WebGL) ────────────────────────────────────────────────
// If WebGL is unavailable (old GPU, headless browser, blocked GPU),
// the page must still work perfectly — the 3D scene is a garnish,
// not a dependency. Fall back to a static caption and move on.
const hero = document.getElementById("stage-hero");
if (hero) {
  try {
    mountTree(hero);
  } catch (err) {
    console.warn("[agentid] WebGL unavailable — showing static fallback:", err);
    hero.classList.add("stage-fallback");
    hero.innerHTML = `<div class="fallback-tree" aria-label="Delegation tree: human root delegates to three agents, each narrowing authority downward">
      <svg viewBox="0 0 400 300" role="img" aria-label="Delegation tree diagram">
        <line x1="200" y1="40" x2="80" y2="160" stroke="#55688A" stroke-width="3"/>
        <line x1="200" y1="40" x2="200" y2="165" stroke="#55688A" stroke-width="3"/>
        <line x1="200" y1="40" x2="320" y2="160" stroke="#55688A" stroke-width="3"/>
        <line x1="80" y1="160" x2="40" y2="275" stroke="#2B3648" stroke-width="2"/>
        <line x1="80" y1="160" x2="130" y2="275" stroke="#2B3648" stroke-width="2"/>
        <line x1="200" y1="165" x2="200" y2="275" stroke="#2B3648" stroke-width="2"/>
        <line x1="320" y1="160" x2="270" y2="275" stroke="#2B3648" stroke-width="2"/>
        <line x1="320" y1="160" x2="360" y2="275" stroke="#2B3648" stroke-width="2"/>
        <circle cx="200" cy="40" r="26" fill="#60A5FA" opacity="0.95"/>
        <circle cx="80" cy="160" r="19" fill="#2DD4BF" opacity="0.95"/>
        <circle cx="200" cy="165" r="19" fill="#2DD4BF" opacity="0.95"/>
        <circle cx="320" cy="160" r="19" fill="#2DD4BF" opacity="0.95"/>
        <circle cx="40" cy="275" r="13" fill="#FBBF24" opacity="0.95"/>
        <circle cx="130" cy="275" r="13" fill="#FBBF24" opacity="0.95"/>
        <circle cx="200" cy="275" r="13" fill="#FBBF24" opacity="0.95"/>
        <circle cx="270" cy="275" r="13" fill="#FBBF24" opacity="0.95"/>
        <circle cx="360" cy="275" r="13" fill="#FBBF24" opacity="0.95"/>
      </svg>
      <div class="stage-label mono">DELEGATION TREE</div>
    </div>`;
  }
}

// ── Try-it panel ────────────────────────────────────────────────
try {
  mountTryIt();
} catch (err) {
  console.error("[agentid] try-it failed to mount:", err);
  const el = document.getElementById("tryit-out");
  if (el) el.innerHTML = '<h3>Validation result</h3><p class="reason">Could not load the validator. Check the <a href="https://github.com/rajat397/agentid">repository</a>.</p>';
}

// ── Header scroll state ─────────────────────────────────────────
const header = document.getElementById("site-header");
const onScroll = () => header?.classList.toggle("scrolled", window.scrollY > 24);
window.addEventListener("scroll", onScroll, { passive: true });
onScroll();
