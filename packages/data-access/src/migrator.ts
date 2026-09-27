/**
 * Shadow : Helix Nebula (SHN) — Deterministic Database Migration Engine
 *
 * Discovers, validates checksums, acquires advisory concurrency locks,
 * and executes versioned SQL migrations in atomic transactions, guaranteeing
 * deterministic and immutable database state (DATA-INV-01, DATA-INV-07).
 */

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import type { DatabasePool } from './pool.js';
import { runInTransaction } from './transaction.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// 64-bit integer advisory lock key for SHN migrations: crc64/hash of 'shn_migration_lock'
const SHN_MIGRATION_ADVISORY_LOCK_ID = 829104820194821;

export interface MigrationRecord {
  readonly version: string;
  readonly name: string;
  readonly checksum_sha256: string;
  readonly applied_at?: string;
}

export interface MigrationReport {
  readonly applied: MigrationRecord[];
  readonly alreadyApplied: MigrationRecord[];
  readonly totalAvailable: number;
}

export interface MigrationFile {
  readonly version: string;
  readonly name: string;
  readonly fullPath: string;
  readonly checksum: string;
  readonly sql: string;
}

export interface MigrationStatus {
  readonly totalAvailable: number;
  readonly appliedCount: number;
  readonly pendingCount: number;
  readonly records: Array<{
    readonly version: string;
    readonly name: string;
    readonly status: 'APPLIED' | 'PENDING';
    readonly checksumSha256: string;
    readonly appliedAt?: string | undefined;
  }>;
}

export function calculateChecksum(content: string): string {
  // Normalize CRLF to LF so checksums are deterministic across OS platforms
  const normalized = content.replace(/\r\n/g, '\n');
  return crypto.createHash('sha256').update(normalized, 'utf8').digest('hex');
}

export function loadMigrationFiles(migrationsDir: string): MigrationFile[] {
  if (!fs.existsSync(migrationsDir)) {
    throw new Error(`Migration directory not found: ${migrationsDir}`);
  }

  const entries = fs.readdirSync(migrationsDir, { withFileTypes: true });
  const migrationFiles: MigrationFile[] = [];
  const versionMap = new Map<string, string>();

  for (const entry of entries) {
    if (!entry.isFile() || !entry.name.endsWith('.sql')) {
      continue;
    }

    const match = entry.name.match(/^(\d{3})_([\w-]+)\.sql$/);
    if (!match) {
      throw new Error(
        `Invalid migration filename format: "${entry.name}". Must match "XXX_name.sql" where XXX is a 3-digit version.`
      );
    }

    const version = match[1]!;
    const name = match[2]!;

    if (versionMap.has(version)) {
      throw new Error(
        `Duplicate migration version detected: "${version}". Files: "${versionMap.get(version)}" and "${entry.name}".`
      );
    }
    versionMap.set(version, entry.name);

    const fullPath = path.join(migrationsDir, entry.name);
    const sql = fs.readFileSync(fullPath, 'utf8');
    const checksum = calculateChecksum(sql);

    migrationFiles.push({
      version,
      name,
      fullPath,
      checksum,
      sql,
    });
  }

  // Strictly deterministic order
  return migrationFiles.sort((a, b) => a.version.localeCompare(b.version));
}

export async function ensureMigrationTable(pool: DatabasePool): Promise<void> {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS public.schema_migrations (
      version VARCHAR(64) PRIMARY KEY,
      name VARCHAR(255) NOT NULL,
      checksum_sha256 VARCHAR(64) NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
    );
  `);
}

export async function getAppliedMigrations(pool: DatabasePool): Promise<MigrationRecord[]> {
  await ensureMigrationTable(pool);
  const result = await pool.query<{
    version: string;
    name: string;
    checksum_sha256: string;
    applied_at: string;
  }>('SELECT version, name, checksum_sha256, applied_at FROM public.schema_migrations ORDER BY version ASC;');

  return result.rows.map(row => ({
    version: row.version,
    name: row.name,
    checksum_sha256: row.checksum_sha256,
    applied_at: row.applied_at,
  }));
}

export function getDefaultMigrationsDir(): string {
  // If running from src or dist
  const candidate1 = path.resolve(__dirname, '../migrations');
  if (fs.existsSync(candidate1)) return candidate1;

  const candidate2 = path.resolve(__dirname, '../../migrations');
  if (fs.existsSync(candidate2)) return candidate2;

  return candidate1;
}

/**
 * Returns read-only status report comparing disk migration files to database records.
 */
export async function getMigrationStatus(
  pool: DatabasePool,
  migrationsDir: string = getDefaultMigrationsDir()
): Promise<MigrationStatus> {
  await ensureMigrationTable(pool);
  const appliedList = await getAppliedMigrations(pool);
  const appliedMap = new Map(appliedList.map(m => [m.version, m]));

  const diskMigrations = loadMigrationFiles(migrationsDir);
  const records: MigrationStatus['records'] = [];
  let appliedCount = 0;
  let pendingCount = 0;

  for (const disk of diskMigrations) {
    const existing = appliedMap.get(disk.version);
    if (existing) {
      appliedCount++;
      records.push({
        version: disk.version,
        name: disk.name,
        status: 'APPLIED',
        checksumSha256: existing.checksum_sha256,
        appliedAt: existing.applied_at,
      });
    } else {
      pendingCount++;
      records.push({
        version: disk.version,
        name: disk.name,
        status: 'PENDING',
        checksumSha256: disk.checksum,
      });
    }
  }

  return {
    totalAvailable: diskMigrations.length,
    appliedCount,
    pendingCount,
    records,
  };
}

/**
 * Executes pending database migrations under an advisory lock to prevent concurrent races.
 */
export async function runMigrations(
  pool: DatabasePool,
  migrationsDir: string = getDefaultMigrationsDir()
): Promise<MigrationReport> {
  const lockClient = await pool.connect();
  try {
    // Acquire session-level PostgreSQL advisory lock
    await lockClient.query('SELECT pg_advisory_lock($1);', [SHN_MIGRATION_ADVISORY_LOCK_ID]);

    await ensureMigrationTable(pool);
    const appliedList = await getAppliedMigrations(pool);
    const appliedMap = new Map(appliedList.map(m => [m.version, m]));

    const diskMigrations = loadMigrationFiles(migrationsDir);
    const applied: MigrationRecord[] = [];
    const alreadyApplied: MigrationRecord[] = [];

    // 1. Verify integrity of previously applied migrations
    for (const disk of diskMigrations) {
      const existing = appliedMap.get(disk.version);
      if (existing) {
        if (existing.checksum_sha256 !== disk.checksum) {
          throw new Error(
            `Checksum mismatch for migration ${disk.version}_${disk.name}! Recorded: ${existing.checksum_sha256}, Current: ${disk.checksum}. Migrations are immutable.`
          );
        }
        alreadyApplied.push(existing);
      }
    }

    // 2. Execute pending migrations in deterministic order inside individual transactions
    for (const disk of diskMigrations) {
      if (appliedMap.has(disk.version)) {
        continue;
      }

      await runInTransaction(pool, async client => {
        // Execute migration SQL
        await client.query(disk.sql);

        // Record migration in ledger
        await client.query(
          `INSERT INTO public.schema_migrations (version, name, checksum_sha256)
           VALUES ($1, $2, $3);`,
          [disk.version, disk.name, disk.checksum]
        );
      });

      applied.push({
        version: disk.version,
        name: disk.name,
        checksum_sha256: disk.checksum,
      });
    }

    return {
      applied,
      alreadyApplied,
      totalAvailable: diskMigrations.length,
    };
  } finally {
    // Release advisory lock safely
    try {
      await lockClient.query('SELECT pg_advisory_unlock($1);', [SHN_MIGRATION_ADVISORY_LOCK_ID]);
    } catch {
      // Ignore unlock failure on connection teardown
    }
    lockClient.release();
  }
}
