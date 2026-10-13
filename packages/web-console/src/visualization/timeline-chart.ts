/**
 * Shadow : Helix Nebula (SHN) — Execution Activity Timeline Chart
 */

import type { Execution } from '../contracts.js';

export function renderExecutionTimeline(executions: Execution[], width = 480, height = 140): string {
  if (executions.length === 0) {
    return `
      <div style="display:flex;align-items:center;justify-content:center;height:${height}px;color:var(--text-muted);font-size:13px;">
        No recent execution telemetry recorded
      </div>
    `;
  }

  const padding = { top: 20, right: 15, bottom: 25, left: 35 };
  const innerWidth = width - padding.left - padding.right;
  const innerHeight = height - padding.top - padding.bottom;

  const displayList = executions.slice(0, 15).reverse();
  const barWidth = Math.max(12, Math.floor(innerWidth / displayList.length) - 6);

  const bars = displayList.map((exec, idx) => {
    const x = padding.left + idx * (innerWidth / displayList.length) + (innerWidth / displayList.length - barWidth) / 2;
    const isSuccess = exec.state === 'COMPLETED';
    const isFailed = exec.state === 'FAILED';
    const isRunning = exec.state === 'RUNNING';

    const color = isSuccess ? 'var(--status-active)' : isFailed ? 'var(--status-failed)' : isRunning ? 'var(--status-running)' : 'var(--accent-primary)';
    const barHeight = Math.max(14, isSuccess ? innerHeight * 0.75 : isFailed ? innerHeight * 0.9 : innerHeight * 0.4);
    const y = padding.top + innerHeight - barHeight;

    const timeLabel = exec.created_at || exec.createdAt ? new Date(exec.created_at || exec.createdAt!).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : `#${idx + 1}`;

    return `
      <g class="timeline-bar" style="cursor: pointer;">
        <rect
          x="${x}"
          y="${y}"
          width="${barWidth}"
          height="${barHeight}"
          rx="3"
          fill="${color}"
          opacity="0.85"
        >
          <title>${exec.action} on ${exec.target} — ${exec.state}</title>
        </rect>
        <text
          x="${x + barWidth / 2}"
          y="${height - 6}"
          text-anchor="middle"
          fill="var(--text-muted)"
          font-size="9"
          font-family="var(--font-mono)"
        >${timeLabel}</text>
      </g>
    `;
  }).join('');

  return `
    <div style="width: 100%; overflow-x: auto;">
      <svg width="100%" height="${height}" viewBox="0 0 ${width} ${height}" preserveAspectRatio="xMidYMid meet">
        <!-- Baseline Axis -->
        <line
          x1="${padding.left}"
          y1="${padding.top + innerHeight}"
          x2="${width - padding.right}"
          y2="${padding.top + innerHeight}"
          stroke="rgba(255,255,255,0.1)"
          stroke-dasharray="2,2"
        />
        ${bars}
      </svg>
    </div>
  `;
}
