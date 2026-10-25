/**
 * Shadow : Helix Nebula (SHN) — Obsidian-Like Interactive Attack-Path & Graph Exploration View
 *
 * Implements interactive canvas-based graph visualization:
 * - Real nodes: Workspaces, Scopes, Assets, Services, Findings, Executions, and AI Hypotheses
 * - Spring/force layout simulation with drag, pan, zoom
 * - Detail panel for node inspection with evidence links, confidence, and prerequisites
 * - Search, filter by node type and severity, neighbor path highlighting
 * - Persistent layout saving and restoring via PostgreSQL (ui.graph_layouts)
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import type { GraphData, GraphNode, GraphEdge } from '../contracts.js';

interface SimulationNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
  radius: number;
  isDragging?: boolean;
}

export class GraphView {
  private container: HTMLElement | null = null;
  private canvas: HTMLCanvasElement | null = null;
  private ctx: CanvasRenderingContext2D | null = null;
  private animFrameId: number | null = null;

  private nodes: SimulationNode[] = [];
  private edges: GraphEdge[] = [];
  private selectedNode: SimulationNode | null = null;
  private hoveredNode: SimulationNode | null = null;

  // Viewport Transform (Pan & Zoom)
  private panX = 0;
  private panY = 0;
  private zoom = 1.0;
  private isPanning = false;
  private startPanX = 0;
  private startPanY = 0;

  // Dragging State
  private draggedNode: SimulationNode | null = null;

  // Filters & Search
  private searchQuery = '';
  private filterTypes = new Set<string>(['WORKSPACE', 'SCOPE', 'ASSET', 'SERVICE', 'FINDING', 'EXECUTION', 'HYPOTHESIS']);

  constructor(
    private readonly api: ApiClient,
    private readonly workspaceStore: WorkspaceStore,
    private readonly notify: NotificationStore
  ) {}

  mount(target: HTMLElement): void {
    this.container = target;
    this.renderShell();
    this.loadGraphData();
  }

  unmount(): void {
    if (this.animFrameId !== null) {
      cancelAnimationFrame(this.animFrameId);
      this.animFrameId = null;
    }
    this.container = null;
    this.canvas = null;
    this.ctx = null;
  }

  private renderShell(): void {
    if (!this.container) return;

    this.container.innerHTML = `
      <div style="width:100%;height:calc(100vh - 60px);display:flex;flex-direction:column;position:relative;overflow:hidden;">
        <!-- Top Toolbar -->
        <div style="padding:10px 18px;background:var(--bg-surface-elevated);border-bottom:1px solid var(--border-medium);display:flex;align-items:center;justify-content:space-between;z-index:20;flex-wrap:wrap;gap:10px;">
          <div style="display:flex;align-items:center;gap:12px;">
            <span style="font-weight:700;font-size:15px;color:var(--text-primary);letter-spacing:0.02em;">
              🕸️ Attack-Path & Relationship Graph
            </span>
            <span class="badge" style="background:rgba(0,240,255,0.15);color:#00f0ff;border:1px solid rgba(0,240,255,0.3);font-size:10px;">
              OBSIDIAN FORCE-DIRECTED
            </span>
          </div>

          <!-- Search & Filter Controls -->
          <div style="display:flex;align-items:center;gap:10px;">
            <div style="position:relative;width:200px;">
              <input
                id="graph-search-input"
                type="text"
                placeholder="Search nodes..."
                style="width:100%;padding:4px 8px 4px 24px;font-size:12px;background:var(--bg-input);border:1px solid var(--border-subtle);border-radius:var(--radius-sm);color:var(--text-primary);"
              />
              <span style="position:absolute;left:7px;top:5px;font-size:11px;color:var(--text-muted);">🔍</span>
            </div>

            <!-- Filter Dropdown Toggle -->
            <div style="display:flex;align-items:center;gap:6px;font-size:11px;color:var(--text-secondary);">
              <label style="cursor:pointer;display:flex;align-items:center;gap:3px;">
                <input type="checkbox" class="chk-filter" value="HYPOTHESIS" checked />
                <span style="color:#ec4899;font-weight:600;">Hypotheses</span>
              </label>
              <label style="cursor:pointer;display:flex;align-items:center;gap:3px;">
                <input type="checkbox" class="chk-filter" value="FINDING" checked />
                <span style="color:#f59e0b;font-weight:600;">Findings</span>
              </label>
              <label style="cursor:pointer;display:flex;align-items:center;gap:3px;">
                <input type="checkbox" class="chk-filter" value="ASSET" checked />
                <span style="color:#00f0ff;font-weight:600;">Assets</span>
              </label>
            </div>

            <button id="btn-zoom-in" class="btn btn-secondary btn-sm" style="padding:4px 8px;" title="Zoom In">+</button>
            <button id="btn-zoom-out" class="btn btn-secondary btn-sm" style="padding:4px 8px;" title="Zoom Out">−</button>
            <button id="btn-zoom-reset" class="btn btn-secondary btn-sm" style="padding:4px 8px;" title="Reset View">⊙</button>

            <button id="btn-save-layout" class="btn btn-primary btn-sm" style="padding:4px 12px;font-size:12px;">
              💾 Save View
            </button>
          </div>
        </div>

        <!-- Canvas Area -->
        <div style="flex:1;position:relative;overflow:hidden;background:#050814;" id="graph-wrapper">
          <canvas id="graph-canvas" style="display:block;width:100%;height:100%;"></canvas>

          <!-- Selected Node Detail Drawer -->
          <div id="graph-drawer" class="graph-detail-drawer" style="display:none;">
            <div style="padding:14px;border-bottom:1px solid var(--border-subtle);display:flex;justify-content:space-between;align-items:center;background:var(--bg-surface-elevated);">
              <div style="font-weight:700;font-size:13px;color:var(--text-primary);display:flex;align-items:center;gap:8px;">
                <span id="drawer-node-icon">🔵</span>
                <span id="drawer-node-title">Node Title</span>
              </div>
              <button id="btn-close-drawer" class="btn btn-ghost btn-sm" style="padding:2px 6px;">✕</button>
            </div>
            <div id="drawer-body" style="padding:16px;overflow-y:auto;display:flex;flex-direction:column;gap:12px;font-size:12px;"></div>
          </div>

          <!-- Bottom Legend -->
          <div style="position:absolute;bottom:14px;left:14px;background:var(--bg-surface-glass-heavy);backdrop-filter:blur(10px);border:1px solid var(--border-glass);border-radius:var(--radius-sm);padding:6px 12px;font-size:11px;display:flex;gap:14px;align-items:center;z-index:10;">
            <div style="display:flex;align-items:center;gap:4px;">
              <span style="width:8px;height:8px;border-radius:50%;background:#00f0ff;"></span>
              <span>Asset / Service</span>
            </div>
            <div style="display:flex;align-items:center;gap:4px;">
              <span style="width:8px;height:8px;border-radius:50%;background:#ef4444;"></span>
              <span>Finding / Risk</span>
            </div>
            <div style="display:flex;align-items:center;gap:4px;">
              <span style="width:8px;height:8px;border-radius:50%;background:#8b5cf6;"></span>
              <span>Execution</span>
            </div>
            <div style="display:flex;align-items:center;gap:4px;">
              <span style="width:8px;height:8px;border-radius:50%;border:1px dashed #ec4899;background:rgba(236,72,153,0.3);"></span>
              <span>AI Hypothesis</span>
            </div>
          </div>
        </div>
      </div>
    `;

    this.canvas = this.container.querySelector<HTMLCanvasElement>('#graph-canvas');
    if (this.canvas) {
      this.ctx = this.canvas.getContext('2d');
      this.resizeCanvas();
      window.addEventListener('resize', () => this.resizeCanvas());
      this.bindCanvasEvents();
    }

    this.bindControls();
  }

  private resizeCanvas(): void {
    if (!this.canvas) return;
    const rect = this.canvas.parentElement?.getBoundingClientRect();
    if (rect) {
      this.canvas.width = rect.width * window.devicePixelRatio;
      this.canvas.height = rect.height * window.devicePixelRatio;
    }
  }

  private async loadGraphData(): Promise<void> {
    const ws = this.workspaceStore.getActiveWorkspace();
    if (!ws) return;

    try {
      const data: GraphData = await this.api.getGraph(ws.id);
      this.initNodesAndEdges(data);
      this.startSimulation();
    } catch (err: any) {
      this.notify.error(err.message || 'Failed to load graph data');
    }
  }

  private initNodesAndEdges(data: GraphData): void {
    const { nodes = [], edges = [], savedLayout } = data;
    const width = (this.canvas?.width || 1200) / (window.devicePixelRatio || 1);
    const height = (this.canvas?.height || 800) / (window.devicePixelRatio || 1);
    const centerX = width / 2;
    const centerY = height / 2;

    this.panX = 0;
    this.panY = 0;
    this.zoom = 1.0;

    const savedPositions = savedLayout?.positions || {};

    this.nodes = nodes.map((n, i) => {
      const saved = savedPositions[n.id];
      const angle = (i / Math.max(nodes.length, 1)) * Math.PI * 2;
      const dist = 120 + Math.random() * 220;

      let radius = 18;
      if (n.type === 'WORKSPACE') radius = 26;
      else if (n.type === 'ASSET') radius = 20;
      else if (n.type === 'FINDING') radius = 16;
      else if (n.type === 'HYPOTHESIS') radius = 17;

      return {
        ...n,
        x: saved ? saved.x : centerX + Math.cos(angle) * dist,
        y: saved ? saved.y : centerY + Math.sin(angle) * dist,
        vx: 0,
        vy: 0,
        radius,
      };
    });

    this.edges = edges;
  }

  private startSimulation(): void {
    let tickCount = 0;

    const tick = () => {
      if (!this.canvas || !this.ctx) return;

      // Run physics for first 300 frames or while dragging
      if (tickCount < 300 || this.draggedNode) {
        this.stepSimulation();
        tickCount++;
      }

      this.renderCanvas();
      this.animFrameId = requestAnimationFrame(tick);
    };

    if (this.animFrameId !== null) {
      cancelAnimationFrame(this.animFrameId);
    }
    this.animFrameId = requestAnimationFrame(tick);
  }

  private stepSimulation(): void {
    const kRepel = 2400;
    const kAttract = 0.04;
    const damping = 0.85;

    // Repulsion between all nodes
    for (let i = 0; i < this.nodes.length; i++) {
      const n1 = this.nodes[i];
      if (!n1 || !this.filterTypes.has(n1.type)) continue;

      for (let j = i + 1; j < this.nodes.length; j++) {
        const n2 = this.nodes[j];
        if (!n2 || !this.filterTypes.has(n2.type)) continue;

        const dx = n2.x - n1.x;
        const dy = n2.y - n1.y;
        const distSq = dx * dx + dy * dy || 1;
        const dist = Math.sqrt(distSq);

        if (dist < 400) {
          const force = kRepel / distSq;
          const fx = (dx / dist) * force;
          const fy = (dy / dist) * force;

          if (!n1.isDragging) {
            n1.vx -= fx;
            n1.vy -= fy;
          }
          if (!n2.isDragging) {
            n2.vx += fx;
            n2.vy += fy;
          }
        }
      }
    }

    // Attraction along edges
    const nodeMap = new Map(this.nodes.map((n) => [n.id, n]));
    for (const e of this.edges) {
      const source = nodeMap.get(e.source);
      const target = nodeMap.get(e.target);
      if (!source || !target) continue;
      if (!this.filterTypes.has(source.type) || !this.filterTypes.has(target.type)) continue;

      const dx = target.x - source.x;
      const dy = target.y - source.y;
      const dist = Math.sqrt(dx * dx + dy * dy) || 1;
      const desiredDist = e.isHypothesis ? 140 : 100;
      const force = (dist - desiredDist) * kAttract;
      const fx = (dx / dist) * force;
      const fy = (dy / dist) * force;

      if (!source.isDragging) {
        source.vx += fx;
        source.vy += fy;
      }
      if (!target.isDragging) {
        target.vx -= fx;
        target.vy -= fy;
      }
    }

    // Apply velocities with damping
    for (const n of this.nodes) {
      if (n.isDragging) continue;
      n.vx *= damping;
      n.vy *= damping;
      n.x += n.vx;
      n.y += n.vy;
    }
  }

  private renderCanvas(): void {
    if (!this.canvas || !this.ctx) return;
    const ctx = this.ctx;
    const dpr = window.devicePixelRatio || 1;

    ctx.save();
    ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    // Apply viewport transform
    ctx.scale(dpr, dpr);
    ctx.translate(this.panX, this.panY);
    ctx.scale(this.zoom, this.zoom);

    const nodeMap = new Map(this.nodes.map((n) => [n.id, n]));

    // Draw Edges
    for (const e of this.edges) {
      const src = nodeMap.get(e.source);
      const tgt = nodeMap.get(e.target);
      if (!src || !tgt) continue;
      if (!this.filterTypes.has(src.type) || !this.filterTypes.has(tgt.type)) continue;

      const isConnected =
        (this.selectedNode && (src.id === this.selectedNode.id || tgt.id === this.selectedNode.id)) ||
        (this.hoveredNode && (src.id === this.hoveredNode.id || tgt.id === this.hoveredNode.id));

      ctx.beginPath();
      ctx.moveTo(src.x, src.y);
      ctx.lineTo(tgt.x, tgt.y);

      if (e.isHypothesis) {
        ctx.setLineDash([5, 5]);
        ctx.strokeStyle = isConnected ? '#ec4899' : 'rgba(236, 72, 153, 0.45)';
        ctx.lineWidth = isConnected ? 2.5 : 1.5;
      } else {
        ctx.setLineDash([]);
        ctx.strokeStyle = isConnected ? '#00f0ff' : 'rgba(0, 240, 255, 0.2)';
        ctx.lineWidth = isConnected ? 2 : 1;
      }

      ctx.stroke();
      ctx.setLineDash([]);
    }

    // Draw Nodes
    for (const n of this.nodes) {
      if (!this.filterTypes.has(n.type)) continue;

      const isSelected = this.selectedNode?.id === n.id;
      const isHovered = this.hoveredNode?.id === n.id;
      const matchesSearch = !this.searchQuery || n.label.toLowerCase().includes(this.searchQuery);

      ctx.save();
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);

      let fillColor = '#0a0f28';
      let strokeColor = '#00f0ff';

      if (n.type === 'WORKSPACE') {
        fillColor = '#06132d';
        strokeColor = '#00f0ff';
      } else if (n.type === 'SCOPE') {
        fillColor = '#06201b';
        strokeColor = '#10b981';
      } else if (n.type === 'ASSET') {
        fillColor = '#0d183d';
        strokeColor = '#3b82f6';
      } else if (n.type === 'FINDING') {
        fillColor = n.severity === 'CRITICAL' ? '#350a0a' : '#2b1b06';
        strokeColor = n.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b';
      } else if (n.type === 'EXECUTION') {
        fillColor = '#1c0e3a';
        strokeColor = '#8b5cf6';
      } else if (n.type === 'HYPOTHESIS') {
        fillColor = 'rgba(236, 72, 153, 0.2)';
        strokeColor = '#ec4899';
        ctx.setLineDash([3, 3]);
      }

      ctx.fillStyle = fillColor;
      ctx.fill();

      ctx.lineWidth = isSelected || isHovered ? 3 : 1.5;
      ctx.strokeStyle = strokeColor;

      if (isSelected || isHovered) {
        ctx.shadowColor = strokeColor;
        ctx.shadowBlur = 15;
      }

      ctx.stroke();
      ctx.restore();

      // Node Label
      ctx.fillStyle = matchesSearch ? (isSelected ? '#ffffff' : '#cbd5e1') : '#475569';
      ctx.font = `${isSelected ? 'bold ' : ''}11px 'JetBrains Mono', monospace`;
      ctx.textAlign = 'center';
      ctx.fillText(n.label, n.x, n.y + n.radius + 14);
    }

    ctx.restore();
  }

  private bindCanvasEvents(): void {
    if (!this.canvas) return;

    this.canvas.addEventListener('mousedown', (e) => {
      const { x, y } = this.screenToWorld(e.offsetX, e.offsetY);
      const clicked = this.findNodeAt(x, y);

      if (clicked) {
        this.draggedNode = clicked;
        clicked.isDragging = true;
      } else {
        this.isPanning = true;
        this.startPanX = e.clientX - this.panX;
        this.startPanY = e.clientY - this.panY;
      }
    });

    window.addEventListener('mousemove', (e) => {
      if (!this.canvas) return;
      const rect = this.canvas.getBoundingClientRect();
      const offsetX = e.clientX - rect.left;
      const offsetY = e.clientY - rect.top;

      if (this.draggedNode) {
        const { x, y } = this.screenToWorld(offsetX, offsetY);
        this.draggedNode.x = x;
        this.draggedNode.y = y;
      } else if (this.isPanning) {
        this.panX = e.clientX - this.startPanX;
        this.panY = e.clientY - this.startPanY;
      } else {
        const { x, y } = this.screenToWorld(offsetX, offsetY);
        const hovered = this.findNodeAt(x, y);
        this.hoveredNode = hovered;
        this.canvas.style.cursor = hovered ? 'pointer' : 'default';
      }
    });

    window.addEventListener('mouseup', () => {
      if (this.draggedNode) {
        this.draggedNode.isDragging = false;
        this.draggedNode = null;
      }
      this.isPanning = false;
    });

    this.canvas.addEventListener('click', (e) => {
      const { x, y } = this.screenToWorld(e.offsetX, e.offsetY);
      const clicked = this.findNodeAt(x, y);
      if (clicked) {
        this.selectNode(clicked);
      }
    });

    this.canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      const zoomFactor = e.deltaY < 0 ? 1.1 : 0.9;
      const newZoom = Math.max(0.2, Math.min(3.0, this.zoom * zoomFactor));

      const mouseX = e.offsetX;
      const mouseY = e.offsetY;

      this.panX = mouseX - (mouseX - this.panX) * (newZoom / this.zoom);
      this.panY = mouseY - (mouseY - this.panY) * (newZoom / this.zoom);
      this.zoom = newZoom;
    });
  }

  private screenToWorld(sx: number, sy: number): { x: number; y: number } {
    return {
      x: (sx - this.panX) / this.zoom,
      y: (sy - this.panY) / this.zoom,
    };
  }

  private findNodeAt(wx: number, wy: number): SimulationNode | null {
    for (let i = this.nodes.length - 1; i >= 0; i--) {
      const n = this.nodes[i];
      if (!n || !this.filterTypes.has(n.type)) continue;
      const dx = n.x - wx;
      const dy = n.y - wy;
      if (dx * dx + dy * dy <= n.radius * n.radius) {
        return n;
      }
    }
    return null;
  }

  private selectNode(node: SimulationNode): void {
    this.selectedNode = node;
    const drawer = this.container?.querySelector<HTMLElement>('#graph-drawer');
    const title = this.container?.querySelector<HTMLElement>('#drawer-node-title');
    const icon = this.container?.querySelector<HTMLElement>('#drawer-node-icon');
    const body = this.container?.querySelector<HTMLElement>('#drawer-body');

    if (drawer && title && icon && body) {
      drawer.style.display = 'flex';
      title.textContent = node.label;
      icon.textContent = node.type === 'HYPOTHESIS' ? '✨' : node.type === 'FINDING' ? '🛡️' : '🖥️';

      body.innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span style="color:var(--text-muted);">Node Type:</span>
          <span class="badge" style="background:var(--accent-subtle);color:var(--accent-primary);">${node.type}</span>
        </div>

        <div style="display:flex;justify-content:space-between;align-items:center;">
          <span style="color:var(--text-muted);">Unique Identifier:</span>
          <span style="font-family:var(--font-mono);font-size:10px;color:var(--text-primary);">${node.id}</span>
        </div>

        ${node.severity ? `
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span style="color:var(--text-muted);">Severity:</span>
            <span class="badge" style="background:${node.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b'};color:#fff;">${node.severity}</span>
          </div>
        ` : ''}

        ${node.confidence ? `
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <span style="color:var(--text-muted);">Confidence Score:</span>
            <span style="font-weight:600;color:#10b981;">${Math.round(node.confidence * 100)}%</span>
          </div>
        ` : ''}

        ${node.type === 'HYPOTHESIS' ? `
          <div style="padding:10px;background:rgba(236,72,153,0.12);border:1px dashed #ec4899;border-radius:var(--radius-sm);margin-top:6px;">
            <div style="font-weight:700;color:#ec4899;font-size:11px;margin-bottom:4px;">AI ATTACK-PATH HYPOTHESIS</div>
            <div style="font-size:11px;color:var(--text-secondary);line-height:1.5;">
              This relationship is an AI-generated deduction based on exposed service patterns and vulnerability correlation. Validated verification requires operator-approved capability dispatch.
            </div>
          </div>
        ` : ''}

        <div style="margin-top:8px;">
          <span style="font-weight:600;color:var(--text-primary);">Connected Relationships:</span>
          <div style="margin-top:6px;display:flex;flex-direction:column;gap:6px;">
            ${this.edges.filter((e) => e.source === node.id || e.target === node.id).map((e) => `
              <div style="padding:6px 8px;background:var(--bg-surface-sunken);border-radius:var(--radius-xs);font-size:11px;display:flex;justify-content:space-between;">
                <span>${e.relation}</span>
                <span style="font-family:var(--font-mono);color:var(--text-muted);">${e.source === node.id ? '➔ ' + e.target.substring(0, 8) : '⬅ ' + e.source.substring(0, 8)}</span>
              </div>
            `).join('')}
          </div>
        </div>
      `;
    }
  }

  private bindControls(): void {
    if (!this.container) return;

    this.container.querySelector('#btn-close-drawer')?.addEventListener('click', () => {
      const drawer = this.container?.querySelector<HTMLElement>('#graph-drawer');
      if (drawer) drawer.style.display = 'none';
      this.selectedNode = null;
    });

    this.container.querySelector('#btn-zoom-in')?.addEventListener('click', () => {
      this.zoom = Math.min(3.0, this.zoom * 1.25);
    });

    this.container.querySelector('#btn-zoom-out')?.addEventListener('click', () => {
      this.zoom = Math.max(0.2, this.zoom * 0.8);
    });

    this.container.querySelector('#btn-zoom-reset')?.addEventListener('click', () => {
      this.zoom = 1.0;
      this.panX = 0;
      this.panY = 0;
    });

    this.container.querySelector<HTMLInputElement>('#graph-search-input')?.addEventListener('input', (e) => {
      this.searchQuery = (e.target as HTMLInputElement).value.toLowerCase().trim();
    });

    this.container.querySelectorAll<HTMLInputElement>('.chk-filter').forEach((chk) => {
      chk.addEventListener('change', () => {
        if (chk.checked) {
          this.filterTypes.add(chk.value);
        } else {
          this.filterTypes.delete(chk.value);
        }
      });
    });

    this.container.querySelector('#btn-save-layout')?.addEventListener('click', async () => {
      const ws = this.workspaceStore.getActiveWorkspace();
      if (!ws) return;

      const positions: Record<string, { x: number; y: number }> = {};
      for (const n of this.nodes) {
        positions[n.id] = { x: Math.round(n.x), y: Math.round(n.y) };
      }

      try {
        await this.api.saveGraph(ws.id, {
          name: 'Default Graph View',
          positions,
          annotations: [],
        });
        this.notify.success('Graph view and node coordinates saved to PostgreSQL');
      } catch (err: any) {
        this.notify.error(err.message || 'Failed to persist graph view');
      }
    });
  }
}
