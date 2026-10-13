/**
 * Shadow : Helix Nebula (SHN) — Interactive Severity Donut Chart
 *
 * Renders an SVG donut visualization for finding severity distribution
 * with center aggregate totals, glowing arcs, and interactive tooltips.
 */

export interface SeveritySlice {
  label: string;
  count: number;
  color: string;
}

export function renderSeverityDonut(slices: SeveritySlice[], size = 180): string {
  const total = slices.reduce((acc, s) => acc + s.count, 0);
  const strokeWidth = 22;
  const radius = (size - strokeWidth) / 2;
  const center = size / 2;
  const circumference = 2 * Math.PI * radius;

  if (total === 0) {
    return `
      <div style="display:flex;align-items:center;justify-content:center;flex-direction:column;gap:12px;width:100%;height:100%;">
        <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">
          <circle cx="${center}" cy="${center}" r="${radius}" fill="none" stroke="rgba(255,255,255,0.08)" stroke-width="${strokeWidth}" />
          <text x="${center}" y="${center + 5}" text-anchor="middle" fill="var(--text-muted)" font-size="13" font-family="var(--font-sans)">0 Findings</text>
        </svg>
      </div>
    `;
  }

  let accumulatedPercent = 0;
  const paths = slices.map((slice) => {
    if (slice.count === 0) return '';
    const percent = slice.count / total;
    const strokeDasharray = `${percent * circumference} ${circumference}`;
    const strokeDashoffset = -accumulatedPercent * circumference;
    accumulatedPercent += percent;

    return `
      <circle
        cx="${center}"
        cy="${center}"
        r="${radius}"
        fill="none"
        stroke="${slice.color}"
        stroke-width="${strokeWidth}"
        stroke-dasharray="${strokeDasharray}"
        stroke-dashoffset="${strokeDashoffset}"
        stroke-linecap="round"
        style="transition: stroke-width 0.2s ease, opacity 0.2s ease; cursor: pointer;"
        class="donut-segment"
        data-label="${slice.label}"
        data-count="${slice.count}"
      >
        <title>${slice.label}: ${slice.count} (${Math.round(percent * 100)}%)</title>
      </circle>
    `;
  }).join('');

  const legend = `
    <div style="display:flex;flex-wrap:wrap;gap:12px;justify-content:center;margin-top:16px;">
      ${slices.map((s) => `
        <div style="display:flex;align-items:center;gap:6px;font-size:12px;">
          <span style="width:8px;height:8px;border-radius:50%;background:${s.color};"></span>
          <span style="color:var(--text-secondary);">${s.label}:</span>
          <strong style="color:var(--text-primary);">${s.count}</strong>
        </div>
      `).join('')}
    </div>
  `;

  return `
    <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;width:100%;">
      <div style="position:relative;width:${size}px;height:${size}px;">
        <svg width="${size}" height="${size}" viewBox="0 0 ${size} ${size}" style="transform: rotate(-90deg);">
          <circle cx="${center}" cy="${center}" r="${radius}" fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="${strokeWidth}" />
          ${paths}
        </svg>
        <div style="position:absolute;top:0;left:0;width:100%;height:100%;display:flex;flex-direction:column;align-items:center;justify-content:center;pointer-events:none;">
          <span style="font-family:var(--font-display);font-size:26px;font-weight:700;color:var(--text-primary);line-height:1;">${total}</span>
          <span style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.04em;margin-top:2px;">Total</span>
        </div>
      </div>
      ${legend}
    </div>
  `;
}
