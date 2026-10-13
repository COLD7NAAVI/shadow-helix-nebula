/**
 * Shadow : Helix Nebula (SHN) — Cybersecurity Operations Dashboard
 */

import type { ApiClient } from '../services/api-client.js';
import type { WorkspaceStore } from '../state/workspace-store.js';
import type { NotificationStore } from '../state/notification-store.js';
import { renderSeverityDonut, type SeveritySlice } from '../visualization/severity-donut.js';
import { renderExecutionTimeline } from '../visualization/timeline-chart.js';
import { renderTopologyGraph } from '../visualization/topology-graph.js';
import type { Asset, Finding, Execution, Scope, AuditEvent } from '../contracts.js';

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

  const activeWorkspace = deps.workspaceStore.getState().activeWorkspace;

  async function loadData() {
    if (!activeWorkspace) return;
    isLoading = true;
    render();

    try {
      const [aList, fList, eList, sList, auList] = await Promise.all([
        deps.api.listAssets(activeWorkspace.id).catch(() => []),
        deps.api.listFindings(activeWorkspace.id).catch(() => []),
        deps.api.listExecutions(activeWorkspace.id).catch(() => []),
        deps.api.listScopes(activeWorkspace.id).catch(() => []),
        deps.api.listAuditEvents(activeWorkspace.id, 10).catch(() => []),
      ]);

      assets = aList;
      findings = fList;
      executions = eList;
      scopes = sList;
      auditEvents = auList;
    } catch (err: any) {
      deps.notify.error(err.message || 'Failed to load dashboard metrics');
    } finally {
      isLoading = false;
      render();
    }
  }

  function render() {
    if (isLoading) {
      container.innerHTML = `
        <div style="display:flex;flex-direction:column;gap:24px;padding:24px;">
          <div class="skeleton-box" style="height:48px;width:320px;"></div>
          <div class="kpi-grid">
            <div class="skeleton-box" style="height:110px;"></div>
            <div class="skeleton-box" style="height:110px;"></div>
            <div class="skeleton-box" style="height:110px;"></div>
            <div class="skeleton-box" style="height:110px;"></div>
          </div>
          <div class="dashboard-grid-2col">
            <div class="skeleton-box" style="height:320px;"></div>
            <div class="skeleton-box" style="height:320px;"></div>
          </div>
        </div>
      `;
      return;
    }

    // Calculate Metrics
    const criticalFindings = findings.filter((f) => f.severity === 'CRITICAL').length;
    const highFindings = findings.filter((f) => f.severity === 'HIGH').length;
    const mediumFindings = findings.filter((f) => f.severity === 'MEDIUM').length;
    const lowFindings = findings.filter((f) => f.severity === 'LOW').length;
    const infoFindings = findings.filter((f) => f.severity === 'INFORMATIONAL').length;

    const completedExecutions = executions.filter((e) => e.state === 'COMPLETED').length;
    const runningExecutions = executions.filter((e) => e.state === 'RUNNING').length;
    const failedExecutions = executions.filter((e) => e.state === 'FAILED').length;

    const severitySlices: SeveritySlice[] = [
      { label: 'Critical', count: criticalFindings, color: 'var(--color-critical)' },
      { label: 'High', count: highFindings, color: 'var(--color-high)' },
      { label: 'Medium', count: mediumFindings, color: 'var(--color-medium)' },
      { label: 'Low', count: lowFindings, color: 'var(--color-low)' },
      { label: 'Info', count: infoFindings, color: 'var(--color-info)' },
    ];

    container.innerHTML = `
      <div class="content-viewport">
        <!-- Page Header -->
        <div class="page-header">
          <div class="page-title-group">
            <h2>Cybersecurity Operations Command</h2>
            <div class="page-subtitle">
              Sovereign workspace: <strong style="color:var(--text-primary);">${activeWorkspace?.name || 'Default Workspace'}</strong>
            </div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            <button id="btn-refresh-dashboard" class="btn btn-secondary">
              <span>↻</span> Refresh Telemetry
            </button>
            <a href="#executions" class="btn btn-primary">
              <span>⚡</span> Launch Capability
            </a>
          </div>
        </div>

        <!-- KPI Grid -->
        <div class="kpi-grid">
          <div class="kpi-card" style="--card-accent: var(--accent-primary);">
            <div class="kpi-label">Monitored Assets</div>
            <div class="kpi-val">${assets.length}</div>
            <div class="kpi-subtext">${assets.filter((a) => a.criticality === 'CRITICAL').length} Critical Tier Targets</div>
          </div>

          <div class="kpi-card" style="--card-accent: #10b981;">
            <div class="kpi-label">Authorized Scopes</div>
            <div class="kpi-val">${scopes.length}</div>
            <div class="kpi-subtext">${scopes.reduce((acc, s) => acc + (s.inclusions?.length || 0), 0)} Target Inclusions</div>
          </div>

          <div class="kpi-card" style="--card-accent: ${criticalFindings > 0 ? 'var(--color-critical)' : 'var(--accent-primary)'};">
            <div class="kpi-label">Open Vulnerabilities</div>
            <div class="kpi-val">${findings.length}</div>
            <div class="kpi-subtext">${criticalFindings} Critical · ${highFindings} High Risk</div>
          </div>

          <div class="kpi-card" style="--card-accent: #f59e0b;">
            <div class="kpi-label">Capability Executions</div>
            <div class="kpi-val">${executions.length}</div>
            <div class="kpi-subtext">${completedExecutions} Passed · ${failedExecutions} Failed · ${runningExecutions} Active</div>
          </div>
        </div>

        <!-- 2-Column Visualization Section -->
        <div class="dashboard-grid-2col">
          <!-- Severity Donut -->
          <div class="card chart-card">
            <div class="chart-header">
              <span class="chart-title">Finding Severity Distribution</span>
              <a href="#findings" class="btn btn-ghost btn-sm">View All →</a>
            </div>
            <div class="chart-canvas-area">
              ${renderSeverityDonut(severitySlices, 190)}
            </div>
          </div>

          <!-- Execution Timeline -->
          <div class="card chart-card">
            <div class="chart-header">
              <span class="chart-title">Execution Activity Stream</span>
              <a href="#executions" class="btn btn-ghost btn-sm">Inspect Runs →</a>
            </div>
            <div class="chart-canvas-area" style="flex-direction:column;justify-content:center;">
              ${renderExecutionTimeline(executions)}
            </div>
          </div>
        </div>

        <!-- Topological Relationship Graph -->
        <div class="card" style="min-height: 380px; display:flex; flex-direction:column;">
          <div class="chart-header" style="margin-bottom: 12px;">
            <span class="chart-title">Zero-Trust Operational Topology Map</span>
            <span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);">
              Workspaces ➔ Scopes ➔ Assets ➔ Findings
            </span>
          </div>
          <div style="flex:1;min-height:300px;background:rgba(0,0,0,0.15);border-radius:var(--radius-md);overflow:hidden;">
            ${renderTopologyGraph({ workspace: activeWorkspace, scopes, assets, executions, findings }, 680, 320)}
          </div>
        </div>

        <!-- Recent Audit Activity -->
        <div class="card">
          <div class="chart-header" style="margin-bottom: 16px;">
            <span class="chart-title">Recent Immutable Audit Ledger</span>
            <a href="#audit" class="btn btn-ghost btn-sm">Full Ledger →</a>
          </div>
          <div class="data-table-container">
            <table class="data-table">
              <thead>
                <tr>
                  <th>Event Type</th>
                  <th>Occurred At</th>
                  <th>Correlation ID</th>
                  <th>Producer Service</th>
                </tr>
              </thead>
              <tbody>
                ${auditEvents.length > 0 ? auditEvents.map((ev) => `
                  <tr>
                    <td><strong style="color:var(--accent-primary);">${ev.event_type}</strong></td>
                    <td style="font-family:var(--font-mono);font-size:11px;">${new Date(ev.occurred_at).toLocaleString()}</td>
                    <td style="font-family:var(--font-mono);font-size:11px;">${ev.correlation_id}</td>
                    <td>${(ev.producer as any)?.service || 'system'}</td>
                  </tr>
                `).join('') : `
                  <tr>
                    <td colspan="4" style="text-align:center;padding:24px;color:var(--text-muted);">
                      No recent audit events recorded
                    </td>
                  </tr>
                `}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;

    container.querySelector('#btn-refresh-dashboard')?.addEventListener('click', () => {
      loadData();
    });
  }

  loadData();
}
