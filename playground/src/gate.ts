import * as THREE from "three";

/**
 * The Gate — the whole enforcement model as one glowing aperture.
 *
 * A luminous torus gate that opens its aperture for authorized actions and
 * closes/flares for rejected ones. Driven by the same slider state the
 * try-it validator uses.
 */
export type GateVerdict = "valid" | "invalid" | "indeterminate";
export interface GateState { amount: number; cap: number; threshold: number; approval: boolean; }

const VERTEX = `
uniform float uTime;
varying vec3 vPos;
void main() {
  vPos = position;
  vec3 p = position;
  float wobble = sin(p.x * 6.0 + uTime * 1.7) * 0.015
               + sin(p.y * 9.0 - uTime * 2.3) * 0.01;
  p += normal * wobble;
  gl_Position = projectionMatrix * modelViewMatrix * vec4(p, 1.0);
}`;
const FRAGMENT = `
uniform vec3 uColor;
uniform float uIntensity;
uniform float uTime;
varying vec3 vPos;
void main() {
  float ring = length(vPos.xy);
  float edge = smoothstep(2.6, 1.5, ring) * smoothstep(0.9, 1.35, ring);
  float pulse = 0.72 + 0.28 * sin(uTime * 2.4);
  vec3 col = uColor * (edge * pulse * uIntensity + 0.08);
  gl_FragColor = vec4(col, edge);
}`;
const RING_VERT = `
varying vec2 vUv;
void main(){ vUv = uv; gl_Position = projectionMatrix * modelViewMatrix * vec4(position, 1.0); }`;
const RING_FRAG = `
uniform vec3 uColor;
uniform float uTime;
varying vec2 vUv;
void main(){
  float d = distance(vUv, vec2(0.5));
  float ring = smoothstep(0.42, 0.34, d) * smoothstep(0.10, 0.24, d);
  float pulse = 0.75 + 0.25 * sin(uTime * 3.0);
  gl_FragColor = vec4(uColor * ring * pulse * 1.6, ring);
}`;

export class GateScene {
  private renderer: THREE.WebGLRenderer | null = null;
  private scene = new THREE.Scene();
  private camera: THREE.PerspectiveCamera;
  private aperture!: THREE.Mesh;
  private core!: THREE.Mesh;
  private uniforms = {
    uTime: { value: 0 },
    uColor: { value: new THREE.Color(0x34d399) },
    uIntensity: { value: 1 },
  };
  private raycaster = new THREE.Raycaster();
  private pointer = new THREE.Vector2(0, 0);
  private container: HTMLElement;
  private raf = 0;
  private clock = new THREE.Clock();
  private verdict: GateVerdict = "valid";

  constructor(container: HTMLElement) {
    this.container = container;
    this.camera = new THREE.PerspectiveCamera(40, 1, 0.1, 100);
    this.camera.position.set(0, 0, 6.2);
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

    // Aperture ring (torus, ShaderMaterial)
    const geo = new THREE.TorusGeometry(1.35, 0.16, 32, 96);
    this.aperture = new THREE.Mesh(geo, new THREE.ShaderMaterial({
      vertexShader: VERTEX, fragmentShader: FRAGMENT,
      transparent: true, side: THREE.DoubleSide, depthWrite: false,
      uniforms: this.uniforms,
    }));
    this.scene.add(this.aperture);

    // Inner core disc
    this.core = new THREE.Mesh(
      new THREE.CircleGeometry(1.05, 48),
      new THREE.MeshBasicMaterial({ color: 0x34d399, transparent: true, opacity: 0.24, side: THREE.DoubleSide })
    );
    this.scene.add(this.core);

    // Orbiting specks
    const speckGeo = new THREE.BufferGeometry();
    const N = 90;
    const pos = new Float32Array(N * 3);
    for (let i = 0; i < N; i++) {
      const r = 2.6 + Math.random() * 1.7;
      const a = Math.random() * Math.PI * 2;
      const y = (Math.random() - 0.5) * 3.4;
      pos[i * 3] = Math.cos(a) * r;
      pos[i * 3 + 1] = y;
      pos[i * 3 + 2] = Math.sin(a) * r * 0.55;
    }
    speckGeo.setAttribute("position", new THREE.BufferAttribute(pos, 3));
    const specks = new THREE.Points(speckGeo, new THREE.PointsMaterial({ color: 0x2dd4bf, size: 0.045, transparent: true, opacity: 0.85 }));
    this.scene.add(specks);

    this.scene.add(new THREE.AmbientLight(0x8899bb, 1.8));

    this.container.addEventListener("pointermove", (e) => {
      const r = this.container.getBoundingClientRect();
      this.pointer.x = ((e.clientX - r.left) / r.width) * 2 - 1;
      this.pointer.y = -(((e.clientY - r.top) / r.height) * 2 - 1);
    });
    this.container.addEventListener("pointerleave", () => this.pointer.set(0, 0));

    const onResize = () => this.resize();
    window.addEventListener("resize", onResize);

    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const tick = () => {
      const t = this.clock.getElapsedTime();
      this.uniforms.uTime.value = t;
      if (!reduce) {
        this.aperture.rotation.z += 0.0021;
        this.aperture.rotation.x = Math.sin(t * 0.35) * 0.16 + this.pointer.y * 0.14;
        this.aperture.rotation.y = Math.cos(t * 0.3) * 0.16 + this.pointer.x * 0.2;
        this.core.rotation.y = this.aperture.rotation.y;
      }
      this.renderer?.render(this.scene, this.camera);
      this.raf = requestAnimationFrame(tick);
    };
    tick();
  }

  resize(): void {
    if (!this.renderer) return;
    const w = this.container.clientWidth, h = this.container.clientHeight;
    this.camera.aspect = w / h;
    this.camera.updateProjectionMatrix();
    this.renderer.setSize(w, h);
  }

  setVerdict(v: GateVerdict): void {
    this.verdict = v;
    const c = v === "valid" ? 0x2dd4bf : v === "invalid" ? 0xf87171 : 0xfbbf24;
    this.uniforms.uColor.value.setHex(c);
    this.uniforms.uIntensity.value = v === "valid" ? 1.25 : 1.6;
    const coreMat = this.core.material as THREE.MeshBasicMaterial;
    coreMat.color.setHex(c);
    coreMat.opacity = v === "valid" ? 0.28 : 0.42;
  }

  dispose(): void {
    cancelAnimationFrame(this.raf);
    this.renderer?.dispose();
  }
}

export function computeVerdict(amount: number, cap: number, threshold: number, approval: boolean): GateVerdict {
  if (amount > cap) return "invalid";
  if (amount > threshold && !approval) return "indeterminate";
  return "valid";
}
