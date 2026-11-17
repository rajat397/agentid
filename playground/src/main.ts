import { mountTree } from "./tree";
import { mountTryIt } from "./tryit";

const hero = document.getElementById("stage-hero");
if (hero) mountTree(hero);

mountTryIt();

const header = document.getElementById("site-header");
const onScroll = () => header?.classList.toggle("scrolled", window.scrollY > 24);
window.addEventListener("scroll", onScroll, { passive: true });
onScroll();
