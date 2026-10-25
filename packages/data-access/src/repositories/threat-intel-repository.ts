/**
 * Shadow : Helix Nebula (SHN) — Threat Intelligence & Vulnerability Reference Repository
 *
 * Caches CVE, CWE, CVSS, and EPSS scores to cross-reference discovered assets and services.
 */

import type { DatabasePool, DatabaseClient } from '../pool.js';

export interface VulnerabilityRecord {
  readonly cveId: string;
  readonly title: string | null;
  readonly description: string;
  readonly cvssScore: number | null;
  readonly cvssVector: string | null;
  readonly epssScore: number | null;
  readonly cweId: string | null;
  readonly exploitStatus: string;
  readonly advisoryUrl: string | null;
  readonly publishedAt: string | null;
  readonly lastSyncedAt: string;
}

export class ThreatIntelRepository {
  constructor(private readonly db: DatabasePool | DatabaseClient) {}

  async findByCveId(cveId: string): Promise<VulnerabilityRecord | null> {
    const query = `
      SELECT cve_id, title, description, cvss_score, cvss_vector, epss_score,
             cwe_id, exploit_status, advisory_url, published_at, last_synced_at
      FROM threat_intel.vulnerabilities_cache
      WHERE cve_id = $1
      LIMIT 1;
    `;
    const res = await this.db.query(query, [cveId]);
    if (res.rows.length === 0) return null;
    return this.mapRow(res.rows[0]);
  }

  async listRecent(limit = 50): Promise<VulnerabilityRecord[]> {
    const query = `
      SELECT cve_id, title, description, cvss_score, cvss_vector, epss_score,
             cwe_id, exploit_status, advisory_url, published_at, last_synced_at
      FROM threat_intel.vulnerabilities_cache
      ORDER BY cvss_score DESC NULLS LAST, published_at DESC NULLS LAST
      LIMIT $1;
    `;
    const res = await this.db.query(query, [limit]);
    return res.rows.map((r: any) => this.mapRow(r));
  }

  async upsert(record: Omit<VulnerabilityRecord, 'lastSyncedAt'>): Promise<VulnerabilityRecord> {
    const query = `
      INSERT INTO threat_intel.vulnerabilities_cache (
        cve_id, title, description, cvss_score, cvss_vector, epss_score,
        cwe_id, exploit_status, advisory_url, published_at, last_synced_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, clock_timestamp())
      ON CONFLICT (cve_id) DO UPDATE SET
        title = EXCLUDED.title,
        description = EXCLUDED.description,
        cvss_score = EXCLUDED.cvss_score,
        cvss_vector = EXCLUDED.cvss_vector,
        epss_score = EXCLUDED.epss_score,
        cwe_id = EXCLUDED.cwe_id,
        exploit_status = EXCLUDED.exploit_status,
        advisory_url = EXCLUDED.advisory_url,
        last_synced_at = clock_timestamp()
      RETURNING cve_id, title, description, cvss_score, cvss_vector, epss_score,
                cwe_id, exploit_status, advisory_url, published_at, last_synced_at;
    `;
    const res = await this.db.query(query, [
      record.cveId,
      record.title ?? null,
      record.description,
      record.cvssScore ?? null,
      record.cvssVector ?? null,
      record.epssScore ?? null,
      record.cweId ?? null,
      record.exploitStatus ?? 'UNVERIFIED',
      record.advisoryUrl ?? null,
      record.publishedAt ?? null,
    ]);
    return this.mapRow(res.rows[0]);
  }

  private mapRow(row: any): VulnerabilityRecord {
    return {
      cveId: row.cve_id,
      title: row.title,
      description: row.description,
      cvssScore: row.cvss_score ? Number(row.cvss_score) : null,
      cvssVector: row.cvss_vector,
      epssScore: row.epss_score ? Number(row.epss_score) : null,
      cweId: row.cwe_id,
      exploitStatus: row.exploit_status,
      advisoryUrl: row.advisory_url,
      publishedAt: row.published_at ? new Date(row.published_at).toISOString() : null,
      lastSyncedAt: new Date(row.last_synced_at).toISOString(),
    };
  }
}
