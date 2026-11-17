import * as THREE from "three";

/**
 * The delegation tree as a 3D artifact.
 *
 * A single human grant at the top. Agents branch below it. Sub-agents branch
 * further. Every edge narrows. Scroll progress reveals the tree top-down.
 * Nothing simulated beyond the scroll reveal — the tree is a static 3D
 * arrangement, gently animated (slow drift + node pulses).
 */
export function mountTree(container: HTMLElement): void {
  const w = container.clientWidth, h = container.clientHeight;

  const scene = new THREE.Scene();
  scene.fog = new THREE.FogExp2(0x0A0E14, 0.28);

  const camera = new THREE.PerspectiveCamera(42, w / h, 0.1, 60);
  camera.position.set(0, 0.6, 9);

  const renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true, powerPreference: "high-performance" });
  renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
  renderer.setSize(w, h);
  renderer.setClearColor(0x000000, 0);
  container.appendChild(renderer.domElement);

  // Lights
  scene.add(new THREE.AmbientLight(0x2a3548, 1.6));
  const key = new THREE.DirectionalLight(0x8ef0d5, 2.2);
  key.position.set(3, 4, 5);
  scene.add(key);
  const rim = new THREE.DirectionalLight(0x3b82f6, 1.4);
  rim.position.set(-4, -2, -3);
  scene.add(rim);

  // Node layout: root (human) at top, then agents, then sub-agents.
  // Positions in a shallow tree fan, y = depth (root high).
  const nodes: { pos: THREE.Vector3; kind: "human" | "agent" | "sub"; label: string }[] = [
    { pos: new THREE.Vector3(0, 2.6, 0), kind: "human", label: "human" },
    { pos: new THREE.Vector3(-2.4, 0.6, 0.6), kind: "agent", label: "marketing" },
    { pos: new THREE.Vector3(0.0, 0.5, -0.8), kind: "agent", label: "ops" },
    { pos: new THREE.Vector3(2.4, 0.7, 0.5), kind: "agent", label: "support" },
    { pos: new THREE.Vector3(-3.4, -1.6, 1.6), kind: "sub", label: "creative" },
    { pos: new THREE.Vector3(-1.4, -1.7, -0.5), kind: "sub", label: "analyst" },
    { pos: new THREE.Vector3(1.5, -1.7, 0.7), kind: "sub", label: "incident" },
    { pos: new THREE.Vector3(3.5, -1.5, -0.9), kind: "sub", label: "router" },
  ];
  const edges: [number, number][] = [
    [0, 1], [0, 2], [0, 3],
    [1, 4], [1, 5], [2, 6], [3, 7],
  ];

  const nodeColor = { human: 0x60A5FA, agent: 0x2DD4BF, sub: 0xFBBF24 };
  const nodeRadius = { human: 0.5, agent: 0.36, sub: 0.26 };

  const group = new THREE.Group();
  scene.add(group);

  const meshes: THREE.Mesh[] = [];
  for (const n of nodes) {
    const geo = new THREE.SphereGeometry(nodeRadius[n.kind], 32, 32);
    const mat = new THREE.MeshStandardMaterial({
      color: nodeColor[n.kind],
      emissive: nodeColor[n.kind],
      emissiveIntensity: 0.55,
      roughness: 0.35,
      metalness: 0.1,
    });
    const mesh = new THREE.Mesh(geo, mat);
    mesh.position.copy(n.pos);
    mesh.userData.baseScale = 1;
    group.add(mesh);
    meshes.push(mesh);
  }

  // Edges — tubes narrowing slightly to suggest attenuation
  for (const [a, b] of edges) {
    const pa = nodes[a]!.pos, pb = nodes[b]!.pos;
    const dir = new THREE.Vector3().subVectors(pb, pa);
    const len = dir.length();
    const geo = new THREE.CylinderGeometry(0.035, 0.017, len, 8, 1, true);
    const mat = new THREE.MeshBasicMaterial({ color: 0x3B4A5F, transparent: true, opacity: 0.85 });
    const edge = new THREE.Mesh(geo, mat);
    edge.position.copy(pa).addScaledVector(dir, 0.5);
    edge.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), dir.clone().normalize());
    group.add(edge);
  }

  // A soft particle field for depth
  const particleCount = 220;
  const pGeo = new THREE.BufferGeometry();
  const pPos = new Float32Array(particleCount * 3);
  for (let i = 0; i < particleCount * 3; i++) {
    pPos[i] = (Math.random() - 0.5) * 14;
  }
  pGeo.setAttribute("position", new THREE.BufferAttribute(pPos, 3));
  const pMat = new THREE.PointsMaterial({ color: 0x334155, size: 0.035, transparent: true, opacity: 0.9 });
  scene.add(new THREE.Points(pGeo, pMat));

  // Scroll growth: nodes fade/grow in from root downward
  let reveal = 0;
  const targetReveal = () => {
    const el = container;
    const rect = el.getBoundingClientRect();
    const vh = window.innerHeight;
    const progress = 1 - rect.top / (vh + rect.height);
    return Math.max(0, Math.min(1, (progress - 0.12) / 0.55));
  };

  const clock = new THREE.Clock();
  let raf = 0;
  const prefersReduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  function frame(): void {
    const t = clock.getElapsedTime();
    reveal += (targetReveal() - reveal) * 0.06;

    // Nodes appear by depth index
    meshes.forEach((mesh, i) => {
      const order = i === 0 ? 0 : i <= 3 ? 1 + (i - 1) * 0.22 : 1.66 + (i - 4) * 0.22;
      const local = Math.max(0, Math.min(1, (reveal - order) / 0.22));
      const s = 0.001 + local * 1.05;
      mesh.scale.setScalar(s);
      const mat = mesh.material as THREE.MeshStandardMaterial;
      mat.emissiveIntensity = 0.15 + local * 0.5 + (prefersReduced ? 0 : Math.sin(t * 1.4 + i) * 0.06);
    });

    if (!prefersReduced) {
      group.rotation.y = Math.sin(t * 0.22) * 0.16;
      group.position.y = Math.sin(t * 0.35) * 0.12;
    }
    renderer.render(scene, camera);
    raf = requestAnimationFrame(frame);
  }
  frame();

  const onResize = () => {
    const w2 = container.clientWidth, h2 = container.clientHeight;
    camera.aspect = w2 / h2;
    camera.updateProjectionMatrix();
    renderer.setSize(w2, h2);
  };
  window.addEventListener("resize", onResize);
}
