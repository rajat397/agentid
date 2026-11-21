import * as THREE from "three";
import { gsap } from "gsap";

type SceneStep = { id: string; actor: string; title: string; summary: string };

export class JourneyScene {
  private container: HTMLElement;
  private steps: SceneStep[];
  private renderer: THREE.WebGLRenderer | null = null;
  private scene = new THREE.Scene();
  private camera = new THREE.PerspectiveCamera(46, 1, 0.1, 100);
  private nodes: THREE.Mesh[] = [];
  private rings: THREE.Mesh[] = [];
  private packet: THREE.Mesh | null = null;
  private frame = 0;
  private look = { x: 0, y: 0, z: 0 };
  private resizeObserver: ResizeObserver | null = null;
  private current = 0;

  constructor(container: HTMLElement, steps: SceneStep[]) {
    this.container = container;
    this.steps = steps;
  }

  init(): void {
    const width = this.container.clientWidth || 800;
    const height = this.container.clientHeight || 520;
    this.renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
    this.renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));
    this.renderer.setSize(width, height);
    this.renderer.domElement.style.width = "100%";
    this.renderer.domElement.style.height = "100%";
    this.renderer.domElement.style.display = "block";
    this.container.appendChild(this.renderer.domElement);

    this.scene.background = null;
    this.scene.fog = new THREE.FogExp2(0x0a0e14, 0.025);
    this.camera.position.set(0, 2.6, 11);
    this.camera.lookAt(0, 0, 0);

    this.scene.add(new THREE.AmbientLight(0x8ea6c4, 1.3));
    const key = new THREE.PointLight(0x2dd4bf, 55, 30);
    key.position.set(2, 6, 7);
    this.scene.add(key);
    const fill = new THREE.PointLight(0x60a5fa, 30, 30);
    fill.position.set(-6, 2, 5);
    this.scene.add(fill);

    const positions = this.steps.map((_, i) => {
      const t = i / Math.max(1, this.steps.length - 1);
      return new THREE.Vector3(-8 + t * 16, Math.sin(t * Math.PI * 3) * 0.9, -Math.sin(t * Math.PI) * 2.2);
    });

    positions.forEach((pos, i) => {
      const geometry = new THREE.IcosahedronGeometry(0.42, 2);
      const material = new THREE.MeshStandardMaterial({
        color: 0x12202c, emissive: 0x2dd4bf, emissiveIntensity: 0.12,
        metalness: 0.65, roughness: 0.3,
      });
      const node = new THREE.Mesh(geometry, material);
      node.position.copy(pos);
      node.userData.index = i;
      this.nodes.push(node);
      this.scene.add(node);

      const ring = new THREE.Mesh(
        new THREE.RingGeometry(0.62, 0.68, 48),
        new THREE.MeshBasicMaterial({ color: 0x2dd4bf, transparent: true, opacity: 0.25, side: THREE.DoubleSide }),
      );
      ring.position.copy(pos);
      ring.lookAt(this.camera.position);
      this.rings.push(ring);
      this.scene.add(ring);

      if (i > 0) {
        const from = positions[i - 1];
        const line = new THREE.Line(
          new THREE.BufferGeometry().setFromPoints([from, pos]),
          new THREE.LineBasicMaterial({ color: 0x30435c, transparent: true, opacity: 0.7 }),
        );
        this.scene.add(line);
      }
    });

    this.packet = new THREE.Mesh(
      new THREE.SphereGeometry(0.13, 16, 16),
      new THREE.MeshBasicMaterial({ color: 0x2dd4bf }),
    );
    this.packet.position.copy(positions[0]);
    this.scene.add(this.packet);

    this.resizeObserver = new ResizeObserver(() => this.resize());
    this.resizeObserver.observe(this.container);
    this.setStep(0, true);
    this.animate();
  }

  private resize(): void {
    if (!this.renderer) return;
    const width = this.container.clientWidth || 800;
    const height = this.container.clientHeight || 520;
    this.renderer.setSize(width, height, false);
    this.camera.aspect = width / height;
    this.camera.updateProjectionMatrix();
  }

  private drawCertificate(step: SceneStep): void {
    if (!this.certCanvas || !this.certTexture) return;
    const ctx = this.certCanvas.getContext("2d");
    if (!ctx) return;
    ctx.clearRect(0, 0, 1024, 560);
    const gradient = ctx.createLinearGradient(0, 0, 1024, 560);
    gradient.addColorStop(0, "#111b29");
    gradient.addColorStop(1, "#0b1119");
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 0, 1024, 560);
    ctx.strokeStyle = "#2dd4bf";
    ctx.lineWidth = 3;
    ctx.strokeRect(12, 12, 1000, 536);
    ctx.fillStyle = "#2dd4bf";
    ctx.font = "600 22px 'JetBrains Mono', monospace";
    ctx.fillText("SIGNED ARTIFACT", 48, 66);
    ctx.fillStyle = "#e6edf3";
    ctx.font = "600 38px 'IBM Plex Sans', sans-serif";
    ctx.fillText(step.title.slice(0, 44), 48, 124);
    ctx.fillStyle = "#8b94a3";
    ctx.font = "24px 'JetBrains Mono', monospace";
    ctx.fillText(step.actor, 48, 170);
    ctx.strokeStyle = "#1f2937";
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(48, 198);
    ctx.lineTo(976, 198);
    ctx.stroke();
    ctx.fillStyle = "#c7d2e0";
    ctx.font = "21px 'JetBrains Mono', monospace";
    const lines = step.summary.split("\n").slice(0, 12);
    lines.forEach((line, i) => ctx.fillText(line.slice(0, 86), 48, 244 + i * 26));
    ctx.fillStyle = "#5c6675";
    ctx.font = "18px 'JetBrains Mono', monospace";
    ctx.fillText("contents captured from the Go CLI on deploy", 48, 526);
    this.certTexture.needsUpdate = true;
  }

  setStep(index: number, immediate = false): void {
    if (!this.steps[index]) return;
    const previous = this.current;
    this.current = index;
    const node = this.nodes[index];
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches || immediate;
    this.nodes.forEach((n, i) => {
      const material = n.material as THREE.MeshStandardMaterial;
      gsap.to(material, { emissiveIntensity: i === index ? 0.85 : 0.12, duration: reduced ? 0 : 0.4 });
    });
    this.rings.forEach((ring, i) => {
      const material = ring.material as THREE.MeshBasicMaterial;
      gsap.to(material, { opacity: i === index ? 0.9 : 0.2, duration: reduced ? 0 : 0.4 });
    });
    gsap.to(this.look, {
      x: node.position.x, y: node.position.y, z: node.position.z,
      duration: reduced ? 0 : 1.15, ease: "power2.inOut",
    });
    gsap.to(this.camera.position, {
      x: node.position.x + 1.1, y: node.position.y + 1.7, z: node.position.z + 6.2,
      duration: reduced ? 0 : 1.15, ease: "power2.inOut",
    });
    if (this.packet && previous !== index && this.nodes[previous]) {
      this.packet.position.copy(this.nodes[previous].position);
      gsap.to(this.packet.position, {
        x: node.position.x, y: node.position.y, z: node.position.z,
        duration: reduced ? 0 : 0.9, ease: "power2.inOut",
      });
    }
  }

  private animate = (): void => {
    this.frame = requestAnimationFrame(this.animate);
    if (!this.renderer) return;
    this.camera.lookAt(this.look.x, this.look.y, this.look.z);
    this.nodes.forEach((node, i) => {
      node.rotation.y += i === this.current ? 0.012 : 0.003;
    });
    this.rings.forEach((ring) => ring.lookAt(this.camera.position));
    this.renderer.render(this.scene, this.camera);
  };

  dispose(): void {
    cancelAnimationFrame(this.frame);
    this.resizeObserver?.disconnect();
    this.renderer?.dispose();
    this.renderer?.domElement.remove();
  }
}
