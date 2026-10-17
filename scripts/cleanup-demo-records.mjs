#!/usr/bin/env node
/**
 * Shadow : Helix Nebula (SHN) — Operational Truth Cleanup Subsystem
 *
 * Safely identifies and purges residual demonstration/synthetic test records
 * (e.g. 10.240.0.* target probes, fictional Perimeter Defense scopes, transient test executions)
 * while strictly preserving authentic organizations, users, credentials, RBAC,
 * capabilities, and platform audit history.
 *
 * Usage:
 *   node scripts/cleanup-demo-records.mjs            # Dry-run preview
 *   node scripts/cleanup-demo-records.mjs --confirm  # Execute cleanup transaction
 */

import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';

async function main() {
  const envFile = path.resolve(process.cwd(), '.env');
  if (fs.existsSync(envFile) && typeof process.loadEnvFile === 'function') {
    try {
      process.loadEnvFile(envFile);
    } catch {}
  }

  const isConfirmed = process.argv.includes('--confirm');

  console.log('========================================================================');
  console.log('SHADOW : HELIX NEBULA (SHN) — RESIDUAL DEMO RECORD CLEANUP UTILITY');
  console.log(`Mode: ${isConfirmed ? 'EXECUTE (Purge Confirmed)' : 'DRY-RUN (Preview Only)'}`);
  console.log('========================================================================\n');

  const pool = new pg.Pool({
    host: process.env.SHN_DB_HOST || '127.0.0.1',
    port: parseInt(process.env.SHN_DB_PORT || '54329', 10),
    database: process.env.SHN_DB_NAME || 'shn_test',
    user: process.env.SHN_DB_USER || 'postgres',
    password: process.env.SHN_DB_PASSWORD || 'postgres_test_password',
  });

  try {
    const client = await pool.connect();

    try {
      // 1. Scan for residual demo assets
      const demoAssetsRes = await client.query(`
        SELECT id, workspace_id, canonical_value, name, type, criticality, created_at
        FROM inventory.assets
        WHERE canonical_value LIKE '10.240.0.%'
           OR canonical_value IN ('192.168.100.1', 'api.sovereign.internal')
           OR name IN ('Sovereign Core Gateway', 'Zero-Trust Authentication Gateway', 'Verification Probe Node')
        ORDER BY created_at ASC;
      `);

      // 2. Scan for residual demo/test scopes
      const demoScopesRes = await client.query(`
        SELECT id, workspace_id, name, description, status, created_at
        FROM workspace.scopes
        WHERE name IN ('Perimeter Defense Zone Alpha', 'Development Sandbox Scope', 'WS1 Scope 1', 'WS1 Scope 2', 'WS2 Scope 1')
           OR name LIKE 'WS% Scope%'
           OR name LIKE '%Sandbox Scope%'
           OR name LIKE 'Verification%'
           OR description LIKE '%Integration test%'
           OR description LIKE '%verification%'
        ORDER BY created_at ASC;
      `);

      const scopeIds = demoScopesRes.rows.map((r) => r.id);

      // 3. Scan for any demo findings associated with those assets
      const assetIds = demoAssetsRes.rows.map((r) => r.id);
      let demoFindingsRes = { rows: [] };
      if (assetIds.length > 0) {
        demoFindingsRes = await client.query(`
          SELECT id, title, severity, cve_id, asset_id
          FROM findings.findings
          WHERE asset_id = ANY($1)
             OR cve_id IN ('CVE-2024-21626', 'CVE-2023-44487');
        `, [assetIds]);
      }

      // 4. Scan for test executions linked to demo targets or demo scopes
      const demoExecsRes = await client.query(`
        SELECT id, workspace_id, target, capability_uri, state, created_at
        FROM execution.executions
        WHERE target LIKE '10.240.0.%'
           OR target = '192.168.100.1'
           OR (scope_id = ANY($1::uuid[]))
        ORDER BY created_at ASC;
      `, [scopeIds.length > 0 ? scopeIds : ['00000000-0000-0000-0000-000000000000']]);

      console.log(`[+] Candidate Demo/Test Assets Found:     ${demoAssetsRes.rows.length}`);
      for (const a of demoAssetsRes.rows) {
        console.log(`    - [${a.type}] ${a.canonical_value.padEnd(20)} "${a.name}" (ID: ${a.id})`);
      }

      console.log(`\n[+] Candidate Demo/Test Scopes Found:     ${demoScopesRes.rows.length}`);
      for (const s of demoScopesRes.rows) {
        console.log(`    - Scope "${s.name}" (ID: ${s.id}, Workspace: ${s.workspace_id})`);
      }

      console.log(`\n[+] Candidate Demo Findings Found:        ${demoFindingsRes.rows.length}`);
      for (const f of demoFindingsRes.rows) {
        console.log(`    - Finding "${f.title}" (${f.cve_id || 'N/A'}, ID: ${f.id})`);
      }

      console.log(`\n[+] Candidate Demo Executions Found:      ${demoExecsRes.rows.length}`);
      for (const e of demoExecsRes.rows) {
        console.log(`    - Execution target "${e.target}" [${e.state}] (ID: ${e.id})`);
      }

      if (
        demoAssetsRes.rows.length === 0 &&
        demoScopesRes.rows.length === 0 &&
        demoFindingsRes.rows.length === 0 &&
        demoExecsRes.rows.length === 0
      ) {
        console.log('\n[*] Database is already clean. No residual demonstration records found.');
        return;
      }

      if (!isConfirmed) {
        console.log('\n------------------------------------------------------------------------');
        console.log('[!] DRY-RUN COMPLETE: No changes were written to the database.');
        console.log('[!] To purge these residual records and establish operational truth, run:');
        console.log('    node scripts/cleanup-demo-records.mjs --confirm');
        console.log('------------------------------------------------------------------------');
        return;
      }

      // Perform transaction
      await client.query('BEGIN');
      console.log('\n[*] Initiating atomic cleanup transaction...');

      if (demoExecsRes.rows.length > 0) {
        const execIds = demoExecsRes.rows.map((r) => r.id);
        await client.query(`DELETE FROM execution.execution_artifacts WHERE execution_id = ANY($1);`, [execIds]);
        await client.query(`DELETE FROM execution.execution_attempts WHERE execution_id = ANY($1);`, [execIds]);
        await client.query(`DELETE FROM execution.worker_leases WHERE execution_id = ANY($1);`, [execIds]);
        const delExec = await client.query(`DELETE FROM execution.executions WHERE id = ANY($1);`, [execIds]);
        console.log(`    ✓ Purged ${delExec.rowCount} transient test executions`);
      }

      if (demoFindingsRes.rows.length > 0) {
        const findingIds = demoFindingsRes.rows.map((r) => r.id);
        await client.query(`DELETE FROM findings.finding_status_transitions WHERE finding_id = ANY($1);`, [findingIds]);
        const delFind = await client.query(`DELETE FROM findings.findings WHERE id = ANY($1);`, [findingIds]);
        console.log(`    ✓ Purged ${delFind.rowCount} synthetic findings`);
      }

      if (assetIds.length > 0) {
        const delAssets = await client.query(`DELETE FROM inventory.assets WHERE id = ANY($1);`, [assetIds]);
        console.log(`    ✓ Purged ${delAssets.rowCount} residual test assets`);
      }

      if (scopeIds.length > 0) {
        const delScopes = await client.query(`DELETE FROM workspace.scopes WHERE id = ANY($1);`, [scopeIds]);
        console.log(`    ✓ Purged ${delScopes.rowCount} residual test scopes`);
      }

      await client.query('COMMIT');
      console.log('\n[✔] Transaction committed successfully. Operational database is now clean.');

    } catch (err) {
      await client.query('ROLLBACK');
      console.error('\n[✕] Cleanup transaction rolled back due to error:', err);
      process.exitCode = 1;
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

main().catch((err) => {
  console.error('[!] Fatal error running cleanup script:', err);
  process.exit(1);
});
