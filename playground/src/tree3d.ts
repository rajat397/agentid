import * as THREE from "three";

/**
 * The delegation tree as an interactive 3D artifact.
 * Nodes are selectable (click) — selecting an agent highlights its path
 * from the human root and dims everything else.
 */
export interface TreeNodeInfo { id: string; label: string; kind: "human" | "agent" | "sub"; detail: string }

export const NODES: TreeNodeInfo[] = [
  { id: "root", label: "usr_8842", kind: "human", detail: "human principal · acme-retail · marketing-manager" },
  { id: "marketing", label: "marketing", kind: "agent", detail: "ad spend · meta-ads · cap $2,000 · 30 min · cosign > $500" },
  { id: "ops", label: "ops-agent", kind: "agent", detail: "tickets · zendesk · scope: support.reply · no spend" },
  { id: "support", label: "support", kind: "agent", detail: "social · linkedin-ads · scope: social.post.publish" },
  { id: "creative", label: "creative-writer", kind: "sub", detail: "sub-agent of marketing · write only · no spend · $0 cap" },
  { id: "analyst", label: "analyst", kind: "sub", detail: "sub-agent of marketing · read-only → ad snapshot · no publish" },
  { id: "incident", label: "incident", kind: "sub", detail: "sub-agent of ops · read-only · cannot reply or refund" },
  { id: "router", label: "router", kind: "sub", detail: "sub-agent of support · routes drafts, cannot post" },
];

const NODE_POS: Record<string, [number, number, number]> = {
  root: [0, 2.7, 0], marketing: [-2.6, 0.7, 0.4], ops: [0, 0.5, -0.9], support: [2.6, 0.7, 0.4],
  creative: [-3.6, -1.6, 1.3], analyst: [-1.5, -1.9, -0.6], incident: [1.5, -1.9, 0.7], router: [3.7, -1.6, -0.8],
};
const EDGES: Array<[string, string]> = [
  ["root", "marketing"], ["root", "ops"], ["root", "support"],
  ["marketing", "creative"], ["marketing", "analyst"], ["ops", "incident"], ["support", "router"],
];
const COL = { human: 0x60A5FA, agent: 0x2DD4BF, sub: 0xFBBF24 };
const R = { human: 0.55, agent: 0.4, sub: 0.27 };

export class TreeScene {
  private renderer: THREE.WebGLRenderer | null = null;
  private scene = new THREE.Scene();
  private camera: THREE.PerspectiveCamera;
  private container: HTMLElement;
  private raf = 0;
  private clock = new THREE.Clock();
  private meshes = new Map<string, THREE.Mesh>();
  private edgeLines = new Map<string, THREE.Mesh>();
  private group = new THREE.Group();
  private raycaster = new THREE.Raycaster();
  private pointer = new THREE.Vector2();
  private selected: string | null = null;
  private reduced = false;

  constructor(container: HTMLElement) {
    this.container = container;
    this.camera = new THREE.PerspectiveCamera(42, 1, 0.1, 60);
    this.camera.position.set(0, 0.4, 8.6);
    this.reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  }

  init(): void {
    const w = this.container.clientWidth, h = this.container.clientHeight;
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();

    this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.setSize(w, h);
    this.renderer.setClearColor(0x000000, 0);
    this.renderer.domElement.style.position = "absolute";
    this.renderer.domElement.style.inset = "0";
    this.renderer.domElement.style.width = "100%";
    this.renderer.domElement.style.height = "100%";
    this.container.appendChild(this.renderer.domElement);

    this.scene.fog = new THREE.FogExp2(0x0A0E14, 0.10);
    this.scene.add(new THREE.AmbientLight(0x8899bb, 2.2));
    const key = new THREE.DirectionalLight(0x9ff0d8, 3.0); key.position.set(4, 5, 6); this.scene.add(key);
    const rim = new THREE.DirectionalLight(0x3b82f6, 2.0); rim.position.set(-4, -1, -4); this.scene.add(rim);
    this.scene.add(this.group);

    for (const n of NODES) {
      const [x, y, z] = NODE_POS[n.id]!;
      const mesh = new THREE.Mesh(
        new THREE.SphereGeometry(R[n.kind], 40, 40),
        new THREE.MeshStandardMaterial({
          color: COL[n.kind], emissive: COL[n.kind], emissiveIntensity: 0.9,
          roughness: 0.3, metalness: 0.08,
        })
      );
      mesh.position.set(x, y, z);
      mesh.userData.id = n.id;
      this.group.add(mesh);
      this.meshes.set(n.id, mesh);
    }

    for (const [a, b] of EDGES) {
      const pa = new THREE.Vector3(...NODE_POS[a]!), pb = new THREE.Vector3(...NODE_POS[b]!);
      const dir = pb.clone().sub(pa); const len = dir.length();
      const link = new THREE.Mesh(
        new THREE.CylinderGeometry(0.035, 0.02, len, 8, 1, true),
        new THREE.MeshBasicMaterial({ color: 0x55688A, transparent: true, opacity: 0.9 })
      );
      link.position.copy(pa).addScaledVector(dir, 0.5);
      link.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), dir.normalize());
      this.group.add(link);
      this.edgeLines.set(`${a}->${b}`, link);
    }

    // soft dust
    const dust = new THREE.BufferGeometry();
    const N = 240; const dp = new Float32Array(N * 3);
    for (let i = 0; i < N; i++) { dp[i * 3] = (Math.random() - 0.5) * 16; dp[i * 3 + 1] = (Math.random() - 0.5) * 10; dp[i * 3 + 2] = (Math.random() - 0.5) * 10; }
    dust.setAttribute("position", new THREE.BufferAttribute(dp, 3));
    this.scene.add(new THREE.Points(dust, new THREE.PointsMaterial({ color: 0x3d4a61, size: 0.04, transparent: true, opacity: 0.9 })));

    const onClick = (e: MouseEvent) => this.pick(e);
    this.container.addEventListener("click", onClick);
    this.container.addEventListener("pointermove", (e) => {
      const r = this.container.getBoundingClientRect();
      this.pointer.set(((e.clientX - r.left) / r.width) * 2 - 1, -(((e.clientY - r.top) / r.height) * 2 - 1));
      this.container.style.cursor = this.hover() ? "pointer" : "default";
    });
    window.addEventListener("resize", () => this.resize());

    const tick = () => {
      const t = this.clock.getElapsedTime();
      if (!this.reduced) {
        this.group.rotation.y = Math.sin(t * 0.2) * 0.18;
        this.group.position.y = Math.sin(t * 0.32) * 0.14;
      }
      for (const m of this.meshes.values()) {
        const d = m.userData.id === this.selected ? 1 : 0;
        const mat = m.material as THREE.MeshStandardMaterial;
        const target = d ? 1.55 : 0.85;
        mat.emissiveIntensity += (target - mat.emissiveIntensity) * 0.12;
      }
      this.renderer?.render(this.scene, this.camera);
      this.raf = requestAnimationFrame(tick);
    };
    tick();
  }

  private pick(e: MouseEvent): void {
    const r = this.container.getBoundingClientRect();
    const p = new THREE.Vector2(((e.clientX - r.left) / r.width) * 2 - 1, -(((e.clientY - r.top) / r.height) * 2 - 1));
    this.raycaster.setFromCamera(p, this.camera);
    const hits = this.raycaster.intersectObjects([...this.meshes.values()]);
    if (hits.length > 0) {
      const id = hits[0]!.object.userData.id as string;
      this.select(this.selected === id ? null : id);
      return;
    }
    this.select(null);
  }

  private hover(): boolean {
    this.raycaster.setFromCamera(this.pointer, this.camera);
    return this.raycaster.intersectObjects([...this.meshes.values()]).length > 0;
  }

  select(id: string | null): void {
    this.selected = id;
    // highlight the path from root to selection
    for (const m of this.meshes.values()) {
      const mid = m.userData.id as string;
      const onPath = id === null || mid === "root" || mid === id;
      const mat = m.material as THREE.MeshStandardMaterial;
      mat.opacity = onPath ? 1 : 0.18;
      mat.transparent = true;
    }
    for (const [key, link] of this.edgeLines) {
      const [a, b] = key.split("->") as [string, string];
      const onPath = id === null || b === id || a === id;
      const mat = link.material as THREE.MeshBasicMaterial;
      mat.opacity = onPath ? 0.95 : 0.12;
    }
    const hint = this.container.querySelector<HTMLElement>(".selected-detail");
    if (hint) hint.textContent = id ? `${id} — ${detailOf(id)}` : "";
  }

  resize(): void {
    if (!this.renderer) return;
    const w = this.container.clientWidth, h = this.container.clientHeight;
    this.camera.aspect = w / h; this.camera.updateProjectionMatrix();
    this.renderer.setSize(w, h);
  }

  dispose(): void { cancelAnimationFrame(this.raf); this.renderer?.dispose(); }
}

export function detailOf(id: string): string {
  return NODES.find((n) => n.id === id)?.detail ?? "";
}
