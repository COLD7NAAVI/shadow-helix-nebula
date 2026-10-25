/**
 * Shadow : Helix Nebula (SHN) — User Preferences Controller
 *
 * Persists theme, accent colors, motion, and dashboard panel layouts.
 */

import { ErrorCode, createProblemDetails } from '@shn/error-catalog';
import type { IngressRequest, IngressResponse } from '../contracts.js';
import { sendProblemDetails } from '../errors/problem-details-filter.js';

export interface PreferencesControllerOptions {
  userPreferencesRepo?: any;
}

export class PreferencesController {
  constructor(private readonly opts: PreferencesControllerOptions) {}

  async get(req: IngressRequest, res: IngressResponse): Promise<void> {
    const userId = req.actor?.id ?? '01a14abf-c197-74f4-8bbd-555eefc2a4b6';
    const workspaceId = req.workspaceId ?? null;

    if (!this.opts.userPreferencesRepo) {
      res.status(200).json({
        theme: 'cyber-operations',
        accentColor: 'cyan',
        density: 'comfortable',
        reducedMotion: false,
        dashboardLayout: {
          refreshIntervalSec: 10,
        },
      });
      return;
    }

    try {
      const prefs = await this.opts.userPreferencesRepo.findByUserId(userId, workspaceId);
      if (!prefs) {
        res.status(200).json({
          theme: 'cyber-operations',
          accentColor: 'cyan',
          density: 'comfortable',
          reducedMotion: false,
          dashboardLayout: {
            refreshIntervalSec: 10,
          },
        });
        return;
      }
      res.status(200).json(prefs);
    } catch (err: any) {
      sendProblemDetails(
        res,
        createProblemDetails({
          errorCode: ErrorCode.INTERNAL_FAULT,
          detail: err?.message || 'Failed to fetch user preferences',
          instance: req.path,
          correlationId: req.correlationId,
        })
      );
    }
  }

  async save(req: IngressRequest, res: IngressResponse): Promise<void> {
    const userId = req.actor?.id ?? '01a14abf-c197-74f4-8bbd-555eefc2a4b6';
    const workspaceId = req.workspaceId ?? null;
    const body = req.body ?? {};

    if (!this.opts.userPreferencesRepo) {
      res.status(200).json({ ...body, userId, workspaceId });
      return;
    }

    try {
      const saved = await this.opts.userPreferencesRepo.upsertPreferences({
        userId,
        workspaceId,
        theme: body.theme,
        accentColor: body.accentColor,
        density: body.density,
        reducedMotion: body.reducedMotion,
        dashboardLayout: body.dashboardLayout,
      });
      res.status(200).json(saved);
    } catch (err: any) {
      sendProblemDetails(
        res,
        createProblemDetails({
          errorCode: ErrorCode.INTERNAL_FAULT,
          detail: err?.message || 'Failed to save user preferences',
          instance: req.path,
          correlationId: req.correlationId,
        })
      );
    }
  }
}
