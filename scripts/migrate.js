#!/usr/bin/env node

/**
 * Shadow : Helix Nebula (SHN) — Deterministic Database Migration Runner CLI
 *
 * Discovers, acquires advisory transaction locks, and executes versioned SQL migrations.
 * Adheres strictly to DATA-INV-01 and DATA-INV-07.
 */

import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  createDatabasePool,
  runMigrations,
  getMigrationStatus,
} from '../packages/data-access/dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

async function main() {
  console.log('[*] SHADOW : HELIX NEBULA — Sovereign Migration Subsystem');

  const dbConfig = {
    host: process.env.SHN_DB_HOST || '127.0.0.1',
    port: parseInt(process.env.SHN_DB_PORT || (process.env.NODE_ENV === 'production' ? '5432' : '54329'), 10),
    database: process.env.SHN_DB_NAME || (process.env.NODE_ENV === 'production' ? 'shn_primary' : 'shn_test'),
    user: process.env.SHN_DB_USER || (process.env.NODE_ENV === 'production' ? 'shn_app' : 'postgres'),
    password: process.env.SHN_DB_PASSWORD || (process.env.NODE_ENV === 'production' ? undefined : 'postgres_test_password'),
    ssl: process.env.SHN_DB_SSL === 'true',
    maxConnections: 5,
    minConnections: 1,
    idleTimeoutMs: 5000,
    connectionTimeoutMs: 5000,
  };

  console.log(`[*] Connecting to PostgreSQL target at ${dbConfig.host}:${dbConfig.port}/${dbConfig.database} (user: ${dbConfig.user})...`);

  const pool = createDatabasePool(dbConfig);
  const migrationsDir = path.resolve(__dirname, '../packages/data-access/migrations');

  if (!fs.existsSync(migrationsDir)) {
    console.error(`[-] Fatal: Migrations directory not found at: ${migrationsDir}`);
    await pool.end();
    process.exit(1);
  }

  try {
    const report = await runMigrations(pool, migrationsDir);
    console.log(`[+] Migrations evaluated successfully:`);
    console.log(`    - Total Available:   ${report.totalAvailable}`);
    console.log(`    - Newly Applied:     ${report.applied.length}`);
    console.log(`    - Already Applied:   ${report.alreadyApplied.length}`);

    if (report.applied.length > 0) {
      console.log('[*] Newly executed migrations:');
      for (const m of report.applied) {
        console.log(`    + [${m.version}] ${m.name} (SHA-256: ${m.checksum_sha256.slice(0, 16)}...)`);
      }
    }

    const status = await getMigrationStatus(pool, migrationsDir);
    console.log(`[+] Final Database Schema State: ${status.appliedCount}/${status.totalAvailable} migrations active.`);

    await pool.end();
    console.log('[+] Migration process completed cleanly.\n');
    process.exit(0);
  } catch (err) {
    console.error('[-] Fatal migration error:', err);
    await pool.end().catch(() => {});
    process.exit(1);
  }
}

main();
