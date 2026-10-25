/**
 * Shadow : Helix Nebula (SHN) — User Preferences Repository
 *
 * Persists UI settings, theme, accents, motion preferences, and dashboard layouts.
 */

import type { DatabasePool, DatabaseClient } from '../pool.js';
import { generateUUIDv7 } from '@shn/shared-kernel';

export interface UserPreferencesRecord {
  readonly id: string;
  readonly userId: string;
  readonly workspaceId: string | null;
  readonly theme: 'cyber-operations' | 'light' | 'ambient';
  readonly accentColor: 'cyan' | 'emerald' | 'violet' | 'amber' | 'rose';
  readonly density: 'compact' | 'comfortable';
  readonly reducedMotion: boolean;
  readonly dashboardLayout: Record<string, unknown>;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface SaveUserPreferencesParams {
  readonly userId: string;
  readonly workspaceId?: string | null;
  readonly theme?: 'cyber-operations' | 'light' | 'ambient';
  readonly accentColor?: 'cyan' | 'emerald' | 'violet' | 'amber' | 'rose';
  readonly density?: 'compact' | 'comfortable';
  readonly reducedMotion?: boolean;
  readonly dashboardLayout?: Record<string, unknown>;
}

export class UserPreferencesRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async findByUserId(userId: string, workspaceId: string | null = null): Promise<UserPreferencesRecord | null> {
    const query = `
      SELECT id, user_id, workspace_id, theme, accent_color, density, reduced_motion,
             dashboard_layout, created_at, updated_at
      FROM ui.user_preferences
      WHERE user_id = $1 AND (workspace_id = $2 OR ($2 IS NULL AND workspace_id IS NULL))
      ORDER BY updated_at DESC
      LIMIT 1;
    `;
    const res = await this.db.query(query, [userId, workspaceId]);
    if (res.rows.length === 0) {
      if (workspaceId !== null) {
        return this.findByUserId(userId, null);
      }
      return null;
    }
    return this.mapRow(res.rows[0]);
  }

  async upsertPreferences(params: SaveUserPreferencesParams): Promise<UserPreferencesRecord> {
    const theme = params.theme ?? 'cyber-operations';
    const accent = params.accentColor ?? 'cyan';
    const density = params.density ?? 'comfortable';
    const reducedMotion = params.reducedMotion ?? false;
    const wksId = params.workspaceId ?? null;
    const layout = params.dashboardLayout ? JSON.stringify(params.dashboardLayout) : '{}';

    const existing = await this.findByUserId(params.userId, wksId);
    if (existing) {
      const updateQuery = `
        UPDATE ui.user_preferences SET
          theme = $2,
          accent_color = $3,
          density = $4,
          reduced_motion = $5,
          dashboard_layout = CASE WHEN $6::jsonb = '{}'::jsonb THEN dashboard_layout ELSE $6::jsonb END,
          updated_at = clock_timestamp()
        WHERE id = $1
        RETURNING id, user_id, workspace_id, theme, accent_color, density, reduced_motion,
                  dashboard_layout, created_at, updated_at;
      `;
      const res = await this.db.query(updateQuery, [
        existing.id,
        theme,
        accent,
        density,
        reducedMotion,
        layout,
      ]);
      return this.mapRow(res.rows[0]);
    }

    const query = `
      INSERT INTO ui.user_preferences (
        id, user_id, workspace_id, theme, accent_color, density, reduced_motion, dashboard_layout, updated_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, clock_timestamp())
      RETURNING id, user_id, workspace_id, theme, accent_color, density, reduced_motion,
                dashboard_layout, created_at, updated_at;
    `;

    const id = generateUUIDv7();
    const res = await this.db.query(query, [
      id,
      params.userId,
      wksId,
      theme,
      accent,
      density,
      reducedMotion,
      layout,
    ]);

    return this.mapRow(res.rows[0]);
  }

  private mapRow(row: any): UserPreferencesRecord {
    return {
      id: row.id,
      userId: row.user_id,
      workspaceId: row.workspace_id,
      theme: row.theme,
      accentColor: row.accent_color,
      density: row.density,
      reducedMotion: row.reduced_motion,
      dashboardLayout: typeof row.dashboard_layout === 'string' ? JSON.parse(row.dashboard_layout) : row.dashboard_layout,
      createdAt: new Date(row.created_at).toISOString(),
      updatedAt: new Date(row.updated_at).toISOString(),
    };
  }
}
