/**
 * Shadow : Helix Nebula (SHN) — Interactive Graph Controller
 *
 * Persists Obsidian-like graph node positions, annotations, and view filters.
 */

import { ErrorCode, createProblemDetails } from '@shn/error-catalog';
import type { IngressRequest, IngressResponse } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface GraphControllerOptions {
  graphLayoutRepo?: any;
  assetRepo?: any;
  findingRepo?: any;
  executionRepo?: any;
  scopeRepo?: any;
  aiRecommendationRepo?: any;
}

export class GraphController {
  constructor(private readonly opts: GraphControllerOptions) {}

  async get(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId;
    if (!workspaceId) {
      res.status(400).json({ error: 'Missing workspaceId' });
      return;
    }

    // 1. Fetch saved layout if available
    let layout: any = null;
    if (this.opts.graphLayoutRepo) {
      try {
        layout = await this.opts.graphLayoutRepo.findByWorkspace(workspaceId);
      } catch {}
    }

    // 2. Fetch real domain entities for graph nodes & edges
    const nodes: any[] = [];
    const edges: any[] = [];

    // Add Workspace Root Node
    nodes.push({
      id: `wks_${workspaceId}`,
      label: 'Workspace Core',
      type: 'WORKSPACE',
      severity: 'INFORMATIONAL',
      data: { workspaceId },
    });

    try {
      if (this.opts.scopeRepo) {
        const scopes = await this.opts.scopeRepo.listByWorkspace(workspaceId);
        for (const s of scopes) {
          const scopeNodeId = `scope_${s.id}`;
          nodes.push({
            id: scopeNodeId,
            label: s.name,
            type: 'SCOPE',
            severity: 'INFORMATIONAL',
            data: s,
          });
          edges.push({
            id: `edge_wks_scope_${s.id}`,
            source: `wks_${workspaceId}`,
            target: scopeNodeId,
            label: 'ENFORCES',
            type: 'VALIDATED',
          });
        }
      }

      if (this.opts.assetRepo) {
        const assets = await this.opts.assetRepo.listByWorkspace(workspaceId);
        for (const a of assets) {
          const assetNodeId = `asset_${a.id}`;
          nodes.push({
            id: assetNodeId,
            label: a.name || a.canonical_value || a.canonicalValue,
            type: 'ASSET',
            subType: a.type,
            severity: a.criticality || 'MEDIUM',
            data: a,
          });
          edges.push({
            id: `edge_wks_asset_${a.id}`,
            source: `wks_${workspaceId}`,
            target: assetNodeId,
            label: 'MONITORS',
            type: 'VALIDATED',
          });
        }
      }

      if (this.opts.findingRepo) {
        const findings = await this.opts.findingRepo.listByWorkspace(workspaceId);
        for (const f of findings) {
          const findingNodeId = `finding_${f.id}`;
          nodes.push({
            id: findingNodeId,
            label: f.title,
            type: 'FINDING',
            severity: f.severity || 'MEDIUM',
            status: f.status,
            cveId: f.cve_id || f.cveId,
            data: f,
          });
          if (f.asset_id || f.assetId) {
            edges.push({
              id: `edge_asset_finding_${f.id}`,
              source: `asset_${f.asset_id || f.assetId}`,
              target: findingNodeId,
              label: 'AFFECTS',
              type: 'VALIDATED',
            });
          }
        }
      }

      if (this.opts.aiRecommendationRepo) {
        const recs = await this.opts.aiRecommendationRepo.listByWorkspace(workspaceId);
        for (const r of recs.filter((x: any) => x.status === 'PENDING' || x.status === 'APPROVED')) {
          const recNodeId = `rec_${r.id}`;
          nodes.push({
            id: recNodeId,
            label: `Hypothesis: ${r.objective.slice(0, 32)}...`,
            type: 'HYPOTHESIS',
            severity: r.riskLevel || 'LOW',
            confidence: r.confidence,
            data: r,
          });
          // Connect to workspace core or target asset
          edges.push({
            id: `edge_hypo_${r.id}`,
            source: `wks_${workspaceId}`,
            target: recNodeId,
            label: 'AI_PROPOSAL',
            type: 'HYPOTHESIS', // Distinct styling!
          });
        }
      }
    } catch (err: any) {
      console.warn('[Graph Controller] Error assembling graph elements:', err?.message);
    }

    res.status(200).json({
      nodes,
      edges,
      savedPositions: layout?.positions ?? {},
      annotations: layout?.annotations ?? [],
      filters: layout?.filters ?? {},
      updatedAt: layout?.updatedAt ?? new Date().toISOString(),
    });
  }

  async save(req: IngressRequest, res: IngressResponse): Promise<void> {
    const workspaceId = req.workspaceId;
    const userId = req.actor?.id ?? '01a14abf-c197-74f4-8bbd-555eefc2a4b6';
    const body = req.body ?? {};

    if (!workspaceId) {
      res.status(400).json({ error: 'Missing workspaceId' });
      return;
    }

    if (!this.opts.graphLayoutRepo) {
      res.status(200).json({ success: true, ...body });
      return;
    }

    try {
      const saved = await this.opts.graphLayoutRepo.saveLayout({
        workspaceId,
        positions: body.positions || {},
        annotations: body.annotations || [],
        filters: body.filters,
        createdBy: userId,
      });
      res.status(200).json(saved);
    } catch (err: any) {
      sendProblemDetails(
        res,
        createProblemDetails({
          errorCode: ErrorCode.INTERNAL_FAULT,
          detail: err?.message || 'Failed to save graph layout',
          instance: req.path,
          correlationId: req.correlationId,
        })
      );
    }
  }
}
