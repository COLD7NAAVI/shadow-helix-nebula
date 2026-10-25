/**
 * Shadow : Helix Nebula (SHN) — Geographic Intelligence & World Map Visualizer
 *
 * Renders data-driven SVG world projection separating Authorized Assessment
 * Infrastructure from External Threat Intelligence.
 */

import type { GeoIntelData } from '../contracts.js';

export function projectCoordinates(lat: number, lng: number, width: number, height: number): { x: number; y: number } {
  // Equirectangular projection
  const x = Math.max(10, Math.min(width - 10, ((lng + 180) / 360) * width));
  const y = Math.max(10, Math.min(height - 10, ((90 - lat) / 180) * height));
  return { x, y };
}

export function renderGeoMap(
  data: GeoIntelData,
  width = 800,
  height = 360
): string {
  const { assessmentMarkers = [], externalThreatPoints = [] } = data;

  // Grid lines
  const parallels = [-60, -30, 0, 30, 60];
  const meridians = [-120, -60, 0, 60, 120];

  const gridSvg = `
    <!-- Parallels -->
    ${parallels.map(lat => {
      const { y } = projectCoordinates(lat, 0, width, height);
      return `<line x1="0" y1="${y}" x2="${width}" y2="${y}" class="geo-grid-line" />`;
    }).join('')}
    <!-- Meridians -->
    ${meridians.map(lng => {
      const { x } = projectCoordinates(0, lng, width, height);
      return `<line x1="${x}" y1="0" x2="${x}" y2="${height}" class="geo-grid-line" />`;
    }).join('')}
  `;

  // Simplified stylized landmass outlines (SVG paths representing continental masses)
  const landmasses = `
    <!-- North America -->
    <path class="geo-landmass" d="M ${width * 0.12} ${height * 0.18} Q ${width * 0.22} ${height * 0.12} ${width * 0.32} ${height * 0.16} T ${width * 0.28} ${height * 0.38} T ${width * 0.18} ${height * 0.45} Z" />
    <!-- South America -->
    <path class="geo-landmass" d="M ${width * 0.26} ${height * 0.48} Q ${width * 0.34} ${height * 0.52} ${width * 0.32} ${height * 0.72} T ${width * 0.28} ${height * 0.88} T ${width * 0.22} ${height * 0.60} Z" />
    <!-- Europe -->
    <path class="geo-landmass" d="M ${width * 0.45} ${height * 0.18} Q ${width * 0.54} ${height * 0.15} ${width * 0.58} ${height * 0.28} T ${width * 0.48} ${height * 0.34} T ${width * 0.42} ${height * 0.24} Z" />
    <!-- Africa -->
    <path class="geo-landmass" d="M ${width * 0.44} ${height * 0.36} Q ${width * 0.56} ${height * 0.38} ${width * 0.56} ${height * 0.62} T ${width * 0.50} ${height * 0.78} T ${width * 0.42} ${height * 0.52} Z" />
    <!-- Asia -->
    <path class="geo-landmass" d="M ${width * 0.56} ${height * 0.14} Q ${width * 0.78} ${height * 0.12} ${width * 0.86} ${height * 0.32} T ${width * 0.72} ${height * 0.50} T ${width * 0.58} ${height * 0.34} Z" />
    <!-- Australia -->
    <path class="geo-landmass" d="M ${width * 0.78} ${height * 0.65} Q ${width * 0.88} ${height * 0.64} ${width * 0.86} ${height * 0.82} T ${width * 0.76} ${height * 0.80} Z" />
  `;

  // Render assessment markers
  const assessmentSvg = assessmentMarkers.map((m, idx) => {
    const { x, y } = projectCoordinates(m.lat, m.lng, width, height);
    return `
      <g class="geo-marker-group" data-marker-idx="${idx}" data-marker-type="assessment" style="cursor: pointer;">
        <circle cx="${x}" cy="${y}" r="12" fill="none" stroke="#00f0ff" stroke-width="1.5" class="geo-marker-pulse" />
        <circle cx="${x}" cy="${y}" r="5" fill="#00f0ff" stroke="#030712" stroke-width="1.5" />
        <text x="${x + 8}" y="${y + 4}" fill="#00f0ff" font-size="10" font-family="'JetBrains Mono', monospace" font-weight="600">
          ${m.label}
        </text>
      </g>
    `;
  }).join('');

  // Render external threat points
  const threatSvg = externalThreatPoints.map((t, idx) => {
    const { x, y } = projectCoordinates(t.lat, t.lng, width, height);
    const color = t.severity === 'CRITICAL' ? '#ef4444' : '#f59e0b';
    return `
      <g class="geo-marker-group" data-marker-idx="${idx}" data-marker-type="threat" style="cursor: pointer;">
        <polygon points="${x},${y - 6} ${x + 6},${y + 4} ${x - 6},${y + 4}" fill="${color}" stroke="#030712" stroke-width="1" />
        <text x="${x + 8}" y="${y + 3}" fill="${color}" font-size="9" font-family="'JetBrains Mono', monospace">
          ${t.cveId}
        </text>
      </g>
    `;
  }).join('');

  return `
    <div class="geo-map-viewport" id="geo-map-container">
      <svg class="geo-map-svg" viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet">
        <defs>
          <radialGradient id="mapGlow" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="#00f0ff" stop-opacity="0.08" />
            <stop offset="100%" stop-color="#000000" stop-opacity="0" />
          </radialGradient>
        </defs>
        <rect width="${width}" height="${height}" fill="url(#mapGlow)" />
        ${gridSvg}
        ${landmasses}
        ${assessmentSvg}
        ${threatSvg}
      </svg>
      <div class="geo-legend">
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="width:8px;height:8px;border-radius:50%;background:#00f0ff;box-shadow:0 0 8px #00f0ff;display:inline-block;"></span>
          <span style="color:var(--text-primary);font-weight:600;">Authorized Target Infrastructure (${assessmentMarkers.length})</span>
        </div>
        <div style="display:flex;align-items:center;gap:6px;">
          <span style="width:0;height:0;border-left:5px solid transparent;border-right:5px solid transparent;border-bottom:8px solid #ef4444;display:inline-block;"></span>
          <span style="color:var(--text-secondary);">External Threat Intel (${externalThreatPoints.length})</span>
        </div>
        <div style="margin-left:auto;color:var(--text-muted);font-family:var(--font-mono);font-size:10px;">
          Source: Sovereign Telemetry & NVD Feed
        </div>
      </div>
    </div>
  `;
}
