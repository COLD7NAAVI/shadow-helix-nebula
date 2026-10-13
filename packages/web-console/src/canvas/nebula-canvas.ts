/**
 * Shadow : Helix Nebula (SHN) — Interactive Cosmic Canvas
 *
 * Implements signature Helix Nebula deep-space visual atmosphere:
 * - Multilayer starfield with luminosity scintillation
 * - Fluid cosmic gaseous nebula cloud filaments
 * - Subtle particle gravitation on operator mouse interaction
 * - Automatic pause and static fallback under reduced-motion preferences
 */

export interface NebulaCanvasOptions {
  canvas: HTMLCanvasElement;
  particleCount?: number;
  interactive?: boolean;
}

interface Star {
  x: number;
  y: number;
  size: number;
  baseAlpha: number;
  alpha: number;
  twinkleSpeed: number;
  twinklePhase: number;
}

interface DustParticle {
  x: number;
  y: number;
  vx: number;
  vy: number;
  size: number;
  color: string;
  alpha: number;
}

export class NebulaCanvas {
  private readonly canvas: HTMLCanvasElement;
  private readonly ctx: CanvasRenderingContext2D;
  private animFrameId: number | null = null;
  private isRunning: boolean = false;
  private reducedMotion: boolean = false;

  private width: number = 0;
  private height: number = 0;
  private stars: Star[] = [];
  private particles: DustParticle[] = [];

  private mouseX: number = -1000;
  private mouseY: number = -1000;

  constructor(options: NebulaCanvasOptions | HTMLCanvasElement) {
    this.canvas = options instanceof HTMLCanvasElement ? options : options.canvas;
    const context = this.canvas.getContext('2d');
    if (!context) {
      throw new Error('Canvas 2D context not available');
    }
    this.ctx = context;

    this.checkReducedMotion();
    this.resize();
    this.bindEvents();
    this.initParticles();
  }

  private checkReducedMotion(): void {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)');
    this.reducedMotion = media.matches || document.documentElement.getAttribute('data-reduced-motion') === 'true';
  }

  setReducedMotion(enabled: boolean): void {
    this.reducedMotion = enabled;
    if (this.reducedMotion) {
      this.drawStaticFrame();
    }
  }

  private resize(): void {
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    this.width = window.innerWidth;
    this.height = window.innerHeight;
    this.canvas.width = this.width * dpr;
    this.canvas.height = this.height * dpr;
    this.ctx.scale(dpr, dpr);
  }

  private bindEvents(): void {
    window.addEventListener('resize', () => {
      this.resize();
      this.initParticles();
      if (this.reducedMotion) this.drawStaticFrame();
    });

    window.addEventListener('mousemove', (e) => {
      this.mouseX = e.clientX;
      this.mouseY = e.clientY;
    });

    window.addEventListener('mouseleave', () => {
      this.mouseX = -1000;
      this.mouseY = -1000;
    });
  }

  private initParticles(): void {
    this.stars = [];
    this.particles = [];

    const starCount = Math.floor((this.width * this.height) / 8000);
    for (let i = 0; i < starCount; i++) {
      this.stars.push({
        x: Math.random() * this.width,
        y: Math.random() * this.height,
        size: Math.random() * 1.5 + 0.5,
        baseAlpha: Math.random() * 0.7 + 0.3,
        alpha: Math.random(),
        twinkleSpeed: Math.random() * 0.02 + 0.005,
        twinklePhase: Math.random() * Math.PI * 2,
      });
    }

    const particleCount = Math.min(Math.floor((this.width * this.height) / 25000), 50);
    const colors = ['#8b5cf6', '#06b6d4', '#ec4899', '#3b82f6'];

    for (let i = 0; i < particleCount; i++) {
      this.particles.push({
        x: Math.random() * this.width,
        y: Math.random() * this.height,
        vx: (Math.random() - 0.5) * 0.3,
        vy: (Math.random() - 0.5) * 0.3,
        size: Math.random() * 3 + 1,
        color: colors[Math.floor(Math.random() * colors.length)]!,
        alpha: Math.random() * 0.4 + 0.1,
      });
    }
  }

  start(): void {
    if (this.isRunning) return;
    this.isRunning = true;
    if (this.reducedMotion) {
      this.drawStaticFrame();
      return;
    }
    this.loop();
  }

  stop(): void {
    this.isRunning = false;
    if (this.animFrameId !== null) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }
  }

  private loop = (): void => {
    if (!this.isRunning || this.reducedMotion) return;
    this.render();
    this.animFrameId = requestAnimationFrame(this.loop);
  };

  private drawNebulaClouds(time: number): void {
    const ctx = this.ctx;
    const w = this.width;
    const h = this.height;

    // Core Nebula center 1 (Violet)
    const cx1 = w * 0.4 + Math.sin(time * 0.0003) * 60;
    const cy1 = h * 0.45 + Math.cos(time * 0.0004) * 40;
    const r1 = Math.max(w, h) * 0.45;

    const grad1 = ctx.createRadialGradient(cx1, cy1, 10, cx1, cy1, r1);
    grad1.addColorStop(0, 'rgba(139, 92, 246, 0.14)');
    grad1.addColorStop(0.4, 'rgba(99, 102, 241, 0.07)');
    grad1.addColorStop(1, 'rgba(0, 0, 0, 0)');

    ctx.fillStyle = grad1;
    ctx.fillRect(0, 0, w, h);

    // Nebula center 2 (Cosmic Cyan)
    const cx2 = w * 0.65 + Math.cos(time * 0.00035) * 50;
    const cy2 = h * 0.55 + Math.sin(time * 0.00025) * 50;
    const r2 = Math.max(w, h) * 0.4;

    const grad2 = ctx.createRadialGradient(cx2, cy2, 10, cx2, cy2, r2);
    grad2.addColorStop(0, 'rgba(6, 182, 212, 0.12)');
    grad2.addColorStop(0.5, 'rgba(14, 165, 233, 0.05)');
    grad2.addColorStop(1, 'rgba(0, 0, 0, 0)');

    ctx.fillStyle = grad2;
    ctx.fillRect(0, 0, w, h);

    // Deep Magenta Filament
    const cx3 = w * 0.3 + Math.sin(time * 0.0002) * 40;
    const cy3 = h * 0.75 + Math.cos(time * 0.0003) * 30;
    const r3 = Math.max(w, h) * 0.35;

    const grad3 = ctx.createRadialGradient(cx3, cy3, 5, cx3, cy3, r3);
    grad3.addColorStop(0, 'rgba(236, 72, 153, 0.08)');
    grad3.addColorStop(0.6, 'rgba(217, 70, 239, 0.03)');
    grad3.addColorStop(1, 'rgba(0, 0, 0, 0)');

    ctx.fillStyle = grad3;
    ctx.fillRect(0, 0, w, h);
  }

  private render(): void {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.width, this.height);

    const now = performance.now();
    this.drawNebulaClouds(now);

    // Draw twinkling stars
    for (const star of this.stars) {
      star.twinklePhase += star.twinkleSpeed;
      const alpha = star.baseAlpha + Math.sin(star.twinklePhase) * 0.3;
      ctx.fillStyle = `rgba(255, 255, 255, ${Math.max(0.1, Math.min(1, alpha))})`;
      ctx.beginPath();
      ctx.arc(star.x, star.y, star.size, 0, Math.PI * 2);
      ctx.fill();
    }

    // Draw and update dust particles with mouse gravity
    for (const p of this.particles) {
      p.x += p.vx;
      p.y += p.vy;

      if (p.x < 0) p.x = this.width;
      if (p.x > this.width) p.x = 0;
      if (p.y < 0) p.y = this.height;
      if (p.y > this.height) p.y = 0;

      // Mouse repulsion / attraction
      const dx = this.mouseX - p.x;
      const dy = this.mouseY - p.y;
      const dist = Math.sqrt(dx * dx + dy * dy);
      if (dist < 180 && dist > 5) {
        const force = (180 - dist) / 180;
        p.x -= (dx / dist) * force * 0.8;
        p.y -= (dy / dist) * force * 0.8;
      }

      ctx.fillStyle = p.color;
      ctx.globalAlpha = p.alpha;
      ctx.beginPath();
      ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
      ctx.fill();
    }
    ctx.globalAlpha = 1.0;
  }

  private drawStaticFrame(): void {
    const ctx = this.ctx;
    ctx.clearRect(0, 0, this.width, this.height);
    this.drawNebulaClouds(0);

    for (const star of this.stars) {
      ctx.fillStyle = `rgba(255, 255, 255, ${star.baseAlpha})`;
      ctx.beginPath();
      ctx.arc(star.x, star.y, star.size, 0, Math.PI * 2);
      ctx.fill();
    }
  }
}
