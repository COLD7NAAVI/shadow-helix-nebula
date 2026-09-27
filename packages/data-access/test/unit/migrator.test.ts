import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import {
  loadMigrationFiles,
  calculateChecksum,
} from '../../dist/index.js';

describe('Migration Engine (Pure Unit Tests)', () => {
  it('should discover and sort migration files lexicographically', () => {
    const migrationsDir = path.resolve(process.cwd(), 'packages/data-access/migrations');
    const files = loadMigrationFiles(migrationsDir);
    assert.ok(files.length >= 1);
    assert.equal(files[0]!.version, '001');
    assert.equal(files[0]!.name, 'initial_schema');
    assert.equal(files[0]!.checksum.length, 64);
  });

  it('should produce identical checksums for CRLF and LF content normalization', () => {
    const sqlLf = 'CREATE TABLE test (\n  id UUID PRIMARY KEY\n);\n';
    const sqlCrlf = 'CREATE TABLE test (\r\n  id UUID PRIMARY KEY\r\n);\r\n';

    const hashLf = calculateChecksum(sqlLf);
    const hashCrlf = calculateChecksum(sqlCrlf);

    assert.equal(hashLf, hashCrlf, 'Checksums must be deterministic regardless of line endings');
  });

  it('should reject invalid migration filename formatting', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shn-mig-test-'));
    try {
      // Missing 3-digit prefix
      fs.writeFileSync(path.join(tmpDir, 'invalid_name.sql'), 'SELECT 1;');
      assert.throws(
        () => loadMigrationFiles(tmpDir),
        (error: Error) => error.message.includes('Invalid migration filename format')
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('should reject duplicate migration version prefixes', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shn-mig-test-'));
    try {
      fs.writeFileSync(path.join(tmpDir, '001_first.sql'), 'SELECT 1;');
      fs.writeFileSync(path.join(tmpDir, '001_duplicate.sql'), 'SELECT 2;');

      assert.throws(
        () => loadMigrationFiles(tmpDir),
        (error: Error) => error.message.includes('Duplicate migration version detected: "001"')
      );
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
