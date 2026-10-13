/**
 * Shadow : Helix Nebula (SHN) — Topological Cybersecurity Relationship Visualizer
 *
 * Renders an interactive topological graph linking Workspaces, Authorized Scopes,
 * Monitored Assets, Executed Capabilities, and Discovered Vulnerability Findings.
 */

import type { Asset, Finding, Execution, Scope, Workspace } from '../contracts.js';

export interface TopologyData {
  workspace: Workspace | null;
  scopes: Scope[];
  assets: Asset[];
  executions: Execution[];
  findings: Finding[];
}

export function renderTopologyGraph(data: TopologyData, width = 640, height = 360): string {
  if (!data.workspace) {
    return `<div class="empty-state"><div class="empty-state-title">No Active Workspace</div></div>`;
  }

  const cx = width / 2;
  const cy = height / 2;

  // Nodes: Center = Workspace
  // Ring 1 = Scopes & Capabilities
  // Ring 2 = Assets
  // Ring 3 = Findings & Executions
  const nodes: Array<{ id: string; label: string; type: string; color: string; x: number; y: number; count?: number }> = [];
  const edges: Array<{ from: string; to: string; color: string }> = [];

  // 1. Center Workspace Node
  nodes.push({
    id: 'wks-' + data.workspace.id,
    label: data.workspace.name.length > 16 ? data.workspace.name.substring(0, 14) + '...' : data.workspace.name,
    type: 'Workspace',
    color: 'var(--accent-primary)',
    x: cx,
    y: cy,
  });

  // 2. Scope Nodes
  const scopeCount = Math.min(data.scopes.length, 3);
  data.scopes.slice(0, 3).forEach((s, idx) => {
    const angle = (idx / Math.max(1, scopeCount)) * Math.PI - Math.PI / 2;
    const x = cx + Math.cos(angle) * 110;
    const y = cy + Math.sin(angle) * 90;
    const id = 'scope-' + s.id;
    nodes.push({ id, label: s.name.substring(0, 12), type: 'Scope', color: '#10b981', x, y });
    edges.push({ from: 'wks-' + data.workspace!.id, to: id, color: 'rgba(16, 185, 129, 0.4)' });
  });

  // 3. Asset Nodes
  const assetCount = Math.min(data.assets.length, 4);
  data.assets.slice(0, 4).forEach((a, idx) => {
    const angle = ((idx + 0.5) / Math.max(1, assetCount)) * Math.PI + Math.PI / 2;
    const x = cx + Math.cos(angle) * 150;
    const y = cy + Math.sin(angle) * 120;
    const id = 'asset-' + a.id;
    const label = a.canonicalValue || a.canonical_target || a.name || 'Asset';
    nodes.push({
      id,
      label: label.length > 12 ? label.substring(0, 10) + '..' : label,
      type: a.type,
      color: a.criticality === 'CRITICAL' ? 'var(--color-critical)' : 'var(--color-high)',
      x,
      y,
    });
    edges.push({ from: 'wks-' + data.workspace!.id, to: id, color: 'rgba(6, 182, 212, 0.4)' });

    // Link findings to this asset
    const relatedFinding = data.findings.find((f) => f.assetId === a.id || f.asset_id === a.id);
    if (relatedFinding) {
      const fAngle = angle + 0.2;
      const fx = cx + Math.cos(fAngle) * 230;
      const fy = cy + Math.sin(fAngle) * 160;
      const fId = 'finding-' + relatedFinding.id;
      nodes.push({
        id: fId,
        label: relatedFinding.cveId || relatedFinding.cve_id || 'Finding',
        type: relatedFinding.severity,
        color: relatedFinding.severity === 'CRITICAL' ? 'var(--color-critical)' : 'var(--color-high)',
        x: fx,
        y: fy,
      });
      edges.push({ from: id, to: fId, color: 'rgba(239, 68, 68, 0.5)' });
    }
  });

  // SVG Render
  const nodeMap = new Map(nodes.map((n) => [n.id, n]));
  const edgeSvg = edges.map((e) => {
    const from = nodeMap.get(e.from);
    const to = nodeMap.get(e.to);
    if (!from || !to) return '';
    return `
      <line
        x1="${from.x}"
        y1="${from.y}"
        x2="${to.x}"
        y2="${to.y}"
        stroke="${e.color}"
        stroke-width="1.5"
        stroke-dasharray="3,3"
      />
    `;
  }).join('');

  const nodeSvg = nodes.map((n) => {
    const isWks = n.type === 'Workspace';
    const r = isWks ? 20 : 12;
    return `
      <g class="topology-node" style="cursor: pointer;">
        <circle
          cx="${n.x}"
          cy="${n.y}"
          r="${r + 4}"
          fill="${n.color}"
          opacity="0.15"
        />
        <circle
          cx="${n.x}"
          cy="${n.y}"
          r="${r}"
          fill="${n.color}"
          stroke="rgba(255,255,255,0.4)"
          stroke-width="1.5"
        >
          <title>${n.type}: ${n.label}</title>
        </circle>
        <text
          x="${n.x}"
          y="${n.y + r + 14}"
          text-anchor="middle"
          fill="var(--text-primary)"
          font-size="10"
          font-family="var(--font-mono)"
          font-weight="500"
        >${n.label}</text>
      </g>
    `;
  }).join('');

  return `
    <div style="width: 100%; height: 100%; overflow: hidden; display: flex; align-items: center; justify-content: center;">
      <svg width="100%" height="100%" viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet">
        <g>${edgeSvg}</g>
        <g>${nodeSvg}</g>
      </svg>
    </div>
  `;
}
