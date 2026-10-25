/**
 * Shadow : Helix Nebula (SHN) — Cyber Operations Live Operations Dashboard
 *
 * Implements Reference Image 1 & 2 layout:
 * - Geographic intelligence world map separating authorized assets from external threat intel
 * - System, Worker, and SSE telemetry
 * - Severity donut and finding distribution
 * - Real-time execution stream and terminal launcher
 * - Evidence-driven AI security recommendations with 1-click execution approvals
 * - Immutable audit ledger feed
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import { renderSeverityDonut, type SeveritySlice } from '../visualization/severity-donut.js';
import { renderExecutionTimeline } from '../visualization/timeline-chart.js';
import { renderGeoMap } from '../visualization/geo-map.js';
import type { Asset, Finding, Execution, Scope, AuditEvent, GeoIntelData, AiRecommendation } from '../contracts.js';

export function renderDashboardView(
  container: HTMLElement,
  deps: { api: ApiClient; workspaceStore: WorkspaceStore; notify: NotificationStore }
): void {
  let isLoading = true;
  let assets: Asset[] = [];
  let findings: Finding[] = [];
  let executions: Execution[] = [];
  let scopes: Scope[] = [];
  let auditEvents: AuditEvent[] = [];
  let geoIntel: GeoIntelData = { assessmentMarkers: [], externalThreatPoints: [], metadata: { legend: { assessment: '', external: '' }, generatedAt: '' } };
  let aiRecommendations: AiRecommendation[] = [];
  let selectedMarkerDetails: string | null = null;

  const activeWorkspace = deps.workspaceStore.getState().activeWorkspace;

  async function loadData() {
    if (!activeWorkspace) return;
    isLoading = true;
    render();

    try {
      const [aList, fList, eList, sList, auList, geoData, recs] = await Promise.all([
        deps.api.listAssets(activeWorkspace.id).catch(() => []),
        deps.api.listFindings(activeWorkspace.id).catch(() => []),
        deps.api.listExecutions(activeWorkspace.id).catch(() => []),
        deps.api.listScopes(activeWorkspace.id).catch(() => []),
        deps.api.listAuditEvents(activeWorkspace.id, 10).catch(() => []),
        deps.api.getGeoIntel(activeWorkspace.id).catch(() => ({
          assessmentMarkers: [],
          externalThreatPoints: [],
          metadata: { legend: { assessment: 'Authorized', external: 'Threats' }, generatedAt: new Date().toISOString() },
        })),
        deps.api.listAiRecommendations(activeWorkspace.id).catch(() => []),
      ]);

      assets = aList;
      findings = fList;
      executions = eList;
      scopes = sList;
      auditEvents = auList;
      geoIntel = geoData;
      aiRecommendations = recs;
    } catch (err: any) {
      deps.notify.error(err.message || 'Failed to load dashboard metrics');
    } finally {
      isLoading = false;
      render();
    }
  }

  async function approveRecommendation(recId: string) {
    if (!activeWorkspace) return;
    try {
      deps.notify.info('Approving recommendation and dispatching capability...');
      const res = await deps.api.approveAiRecommendation(activeWorkspace.id, recId);
      if (res.success) {
        deps.notify.success(`Capability dispatched! Execution ID: ${res.executionId || 'Active'}`);
        await loadData();
      }
    } catch (err: any) {
      deps.notify.error(err.message || 'Failed to approve recommendation');
    }
  }

  async function dismissRecommendation(recId: string) {
    if (!activeWorkspace) return;
    try {
      await deps.api.dismissAiRecommendation(activeWorkspace.id, recId);
      deps.notify.info('Recommendation dismissed');
      await loadData();
    } catch (err: any) {
      deps.notify.error(err.message || 'Failed to dismiss recommendation');
    }
  }

  async function generateAiRecommendations() {
    if (!activeWorkspace) return;
    try {
      deps.notify.info('AI security assistant analyzing workspace assets & findings...');
      const recs = await deps.api.generateAiRecommendations(activeWorkspace.id);
      deps.notify.success(`Generated ${recs.length} evidence-backed security recommendations`);
      aiRecommendations = recs;
      render();
    } catch (err: any) {
      deps.notify.error(err.message || 'Failed to generate recommendations');
    }
  }

  function render() {
    if (isLoading) {
      container.innerHTML = `
        <div style="display:flex;flex-direction:column;gap:20px;padding:24px;">
          <div class="skeleton-box" style="height:48px;width:320px;"></div>
          <div class="kpi-grid">
            <div class="skeleton-box" style="height:100px;"></div>
            <div class="skeleton-box" style="height:100px;"></div>
            <div class="skeleton-box" style="height:100px;"></div>
            <div class="skeleton-box" style="height:100px;"></div>
          </div>
          <div class="skeleton-box" style="height:360px;"></div>
          <div class="dashboard-grid-2col">
            <div class="skeleton-box" style="height:280px;"></div>
            <div class="skeleton-box" style="height:280px;"></div>
          </div>
        </div>
      `;
      return;
    }

    const criticalFindings = findings.filter((f) => f.severity === 'CRITICAL').length;
    const highFindings = findings.filter((f) => f.severity === 'HIGH').length;
    const mediumFindings = findings.filter((f) => f.severity === 'MEDIUM').length;
    const lowFindings = findings.filter((f) => f.severity === 'LOW').length;
    const infoFindings = findings.filter((f) => f.severity === 'INFORMATIONAL').length;

    const completedExecutions = executions.filter((e) => e.state === 'COMPLETED').length;
    const runningExecutions = executions.filter((e) => e.state === 'RUNNING').length;
    const failedExecutions = executions.filter((e) => e.state === 'FAILED').length;

    const pendingRecs = aiRecommendations.filter((r) => r.status === 'PENDING');

    const severitySlices: SeveritySlice[] = [
      { label: 'Critical', count: criticalFindings, color: 'var(--color-critical)' },
      { label: 'High', count: highFindings, color: 'var(--color-high)' },
      { label: 'Medium', count: mediumFindings, color: 'var(--color-medium)' },
      { label: 'Low', count: lowFindings, color: 'var(--color-low)' },
      { label: 'Info', count: infoFindings, color: 'var(--color-info)' },
    ];

    container.innerHTML = `
      <div class="content-viewport" style="display:flex;flex-direction:column;gap:20px;">
        <!-- Header -->
        <div class="page-header" style="margin-bottom:0;">
          <div class="page-title-group">
            <div style="display:flex;align-items:center;gap:12px;">
              <h2>Operations Command Center</h2>
              <span class="badge" style="background:rgba(0,240,255,0.15);color:#00f0ff;border:1px solid rgba(0,240,255,0.3);font-size:11px;">
                SOVEREIGN LEVEL 3
              </span>
            </div>
            <div class="page-subtitle">
              Active Authorized Workspace: <strong style="color:var(--text-primary);">${activeWorkspace?.name || 'Default Workspace'}</strong>
              <span style="margin-left:12px;color:var(--text-muted);font-family:var(--font-mono);font-size:11px;">[ID: ${activeWorkspace?.id}]</span>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            <button id="btn-refresh-dashboard" class="btn btn-secondary">
              <span>↻</span> Refresh Telemetry
            </button>
            <a href="#terminal" class="btn btn-primary" style="display:flex;align-items:center;gap:6px;">
              <span>⚡</span> Execution Terminal
            </a>
          </div>
        </div>

        <!-- Telemetry & KPI Strip -->
        <div class="kpi-grid">
          <div class="kpi-card" style="--card-accent: var(--accent-primary);">
            <div class="kpi-label">Monitored Assets</div>
            <div class="kpi-val">${assets.length}</div>
            <div class="kpi-subtext">${assets.filter((a) => a.criticality === 'CRITICAL').length} Critical Tier Targets</div>
          </div>

          <div class="kpi-card" style="--card-accent: #10b981;">
            <div class="kpi-label">Authorized Scope Policy</div>
            <div class="kpi-val">${scopes.length}</div>
            <div class="kpi-subtext">${scopes.reduce((acc, s) => acc + (s.inclusions?.length || 0), 0)} Targets In Scope</div>
          </div>

          <div class="kpi-card" style="--card-accent: ${criticalFindings > 0 ? 'var(--color-critical)' : 'var(--accent-primary)'};">
            <div class="kpi-label">Identified Vulnerabilities</div>
            <div class="kpi-val">${findings.length}</div>
            <div class="kpi-subtext">${criticalFindings} Critical · ${highFindings} High Risk</div>
          </div>

          <div class="kpi-card" style="--card-accent: #f59e0b;">
            <div class="kpi-label">Tool Executions</div>
            <div class="kpi-val">${executions.length}</div>
            <div class="kpi-subtext">${completedExecutions} Passed · ${failedExecutions} Failed · ${runningExecutions} Active</div>
          </div>
        </div>

        <!-- Geographic Intelligence Panel (World Map) -->
        <div class="card geo-intel-card" style="padding:0;border:1px solid var(--border-medium);">
          <div style="padding:14px 18px;border-bottom:1px solid var(--border-subtle);display:flex;align-items:center;justify-content:space-between;background:var(--bg-surface-elevated);">
            <div style="display:flex;align-items:center;gap:10px;">
              <span style="font-size:16px;">🌐</span>
              <div>
                <span style="font-weight:700;font-size:14px;color:var(--text-primary);letter-spacing:0.02em;">
                  Geographic Threat & Asset Intelligence
                </span>
                <span style="display:block;font-size:11px;color:var(--text-muted);">
                  Global Target Mapping & Verified Threat Intelligence Feeds
                </span>
              </div>
            </div>
            <div style="display:flex;align-items:center;gap:12px;font-size:11px;font-family:var(--font-mono);">
              <span style="color:#00f0ff;">● ${geoIntel.assessmentMarkers.length} Authorized Nodes</span>
              <span style="color:#ef4444;">▲ ${geoIntel.externalThreatPoints.length} External Advisories</span>
            </div>
          </div>
          ${renderGeoMap(geoIntel, 900, 340)}
          ${selectedMarkerDetails ? `
            <div style="padding:12px 18px;background:var(--bg-surface-glass-heavy);border-top:1px solid var(--border-subtle);display:flex;align-items:center;justify-content:space-between;">
              <div style="font-size:12px;color:var(--text-primary);">
                ${selectedMarkerDetails}
              </div>
              <button id="btn-close-marker-detail" class="btn btn-ghost btn-sm" style="font-size:11px;">Close</button>
            </div>
          ` : ''}
        </div>

        <!-- 2-Column: AI Security Recommendations & Severity Distribution -->
        <div class="dashboard-grid-2col">
          <!-- AI Recommendations Awaiting Review -->
          <div class="card" style="display:flex;flex-direction:column;gap:12px;">
            <div class="chart-header" style="margin-bottom:0;">
              <div style="display:flex;align-items:center;gap:8px;">
                <span style="color:#00f0ff;">🧠</span>
                <span class="chart-title">AI Security Assistant Recommendations</span>
              </div>
              <button id="btn-generate-ai-recs" class="btn btn-secondary btn-sm" style="font-size:11px;padding:4px 8px;">
                ⚡ Re-Analyze
              </button>
            </div>

            <div style="display:flex;flex-direction:column;gap:10px;max-height:360px;overflow-y:auto;">
              ${pendingRecs.length > 0 ? pendingRecs.map((rec) => `
                <div class="ai-rec-card ${rec.riskLevel === 'CRITICAL' || rec.riskLevel === 'HIGH' ? 'high-risk' : 'low-risk'}" style="padding:12px;">
                  <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:8px;">
                    <div>
                      <div style="font-weight:600;font-size:13px;color:var(--text-primary);">${rec.objective}</div>
                      <div style="font-size:11px;color:var(--text-secondary);margin-top:2px;">${rec.rationale}</div>
                    </div>
                    <span class="badge" style="font-size:10px;background:${rec.riskLevel === 'CRITICAL' ? 'rgba(239,68,68,0.2)' : 'rgba(0,240,255,0.2)'};color:${rec.riskLevel === 'CRITICAL' ? '#ef4444' : '#00f0ff'};">
                      ${rec.riskLevel}
                    </span>
                  </div>
                  <div style="display:flex;justify-content:space-between;align-items:center;margin-top:8px;font-size:11px;font-family:var(--font-mono);color:var(--text-muted);">
                    <span>Target: <strong style="color:var(--text-primary);">${rec.target}</strong></span>
                    <span>Confidence: <strong>${Math.round(rec.confidence * 100)}%</strong></span>
                  </div>
                  <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:8px;">
                    <button class="btn btn-ghost btn-sm btn-dismiss-rec" data-rec-id="${rec.id}" style="font-size:11px;padding:3px 8px;">
                      Dismiss
                    </button>
                    <button class="btn btn-primary btn-sm btn-approve-rec" data-rec-id="${rec.id}" style="font-size:11px;padding:3px 10px;">
                      ✓ Approve & Execute
                    </button>
                  </div>
                </div>
              `).join('') : `
                <div class="empty-state" style="padding:28px 14px;">
                  <div class="empty-state-icon">🤖</div>
                  <div class="empty-state-title">No Pending Recommendations</div>
                  <div class="empty-state-desc">Click "Re-Analyze" to have the sovereign AI engine inspect workspace assets and findings for next steps.</div>
                </div>
              `}
            </div>
          </div>

          <!-- Severity Donut & Findings -->
          <div class="card chart-card">
            <div class="chart-header">
              <span class="chart-title">Finding Severity Breakdown</span>
              <a href="#findings" class="btn btn-ghost btn-sm">All Findings →</a>
            </div>
            <div class="chart-canvas-area">
              ${renderSeverityDonut(severitySlices, 180)}
            </div>
          </div>
        </div>

        <!-- 2-Column: Execution Stream & Recent Audit Ledger -->
        <div class="dashboard-grid-2col">
          <!-- Execution Stream -->
          <div class="card chart-card">
            <div class="chart-header">
              <span class="chart-title">Recent Tool Executions</span>
              <a href="#terminal" class="btn btn-ghost btn-sm">Terminal →</a>
            </div>
            <div class="chart-canvas-area" style="flex-direction:column;justify-content:center;">
              ${renderExecutionTimeline(executions)}
            </div>
          </div>

          <!-- Recent Audit Events -->
          <div class="card">
            <div class="chart-header" style="margin-bottom:12px;">
              <span class="chart-title">Immutable Audit Events</span>
              <a href="#audit" class="btn btn-ghost btn-sm">Audit Ledger →</a>
            </div>
            <div class="data-table-container">
              <table class="data-table">
                <thead>
                  <tr>
                    <th>Event</th>
                    <th>Time</th>
                    <th>Correlation</th>
                  </tr>
                </thead>
                <tbody>
                  ${auditEvents.slice(0, 5).map((ev) => `
                    <tr>
                      <td><strong style="color:var(--accent-primary);font-size:11px;">${ev.event_type}</strong></td>
                      <td style="font-family:var(--font-mono);font-size:11px;">${new Date(ev.occurred_at).toLocaleTimeString()}</td>
                      <td style="font-family:var(--font-mono);font-size:10px;">${ev.correlation_id.substring(0, 16)}...</td>
                    </tr>
                  `).join('')}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    `;

    // Event Bindings
    container.querySelector('#btn-refresh-dashboard')?.addEventListener('click', () => loadData());
    container.querySelector('#btn-generate-ai-recs')?.addEventListener('click', () => generateAiRecommendations());

    container.querySelectorAll<HTMLButtonElement>('.btn-approve-rec').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.recId;
        if (id) approveRecommendation(id);
      });
    });

    container.querySelectorAll<HTMLButtonElement>('.btn-dismiss-rec').forEach((btn) => {
      btn.addEventListener('click', () => {
        const id = btn.dataset.recId;
        if (id) dismissRecommendation(id);
      });
    });

    container.querySelectorAll<SVGGElement>('.geo-marker-group').forEach((g) => {
      g.addEventListener('click', () => {
        const idx = Number(g.dataset.markerIdx);
        const type = g.dataset.markerType;
        if (type === 'assessment' && geoIntel.assessmentMarkers[idx]) {
          const m = geoIntel.assessmentMarkers[idx];
          selectedMarkerDetails = `<strong>Authorized Infrastructure:</strong> ${m.label} (${m.target}) · Lat: ${m.lat.toFixed(2)}, Lng: ${m.lng.toFixed(2)} · Criticality: ${m.criticality}`;
        } else if (type === 'threat' && geoIntel.externalThreatPoints[idx]) {
          const t = geoIntel.externalThreatPoints[idx];
          selectedMarkerDetails = `<strong>External Threat Intelligence:</strong> ${t.cveId} - ${t.title} · Provider: ${t.provider} · Observed: ${new Date(t.observedAt).toLocaleDateString()}`;
        }
        render();
      });
    });

    container.querySelector('#btn-close-marker-detail')?.addEventListener('click', () => {
      selectedMarkerDetails = null;
      render();
    });
  }

  loadData();
}
