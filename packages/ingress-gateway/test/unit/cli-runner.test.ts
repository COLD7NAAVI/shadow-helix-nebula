/**
 * Shadow : Helix Nebula (SHN) — CLI Runner Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { CliRunner } from '../../dist/index.js';

describe('CLI Runner (Unit Tests)', () => {
  const runner = new CliRunner();

  it('should display help text and exit with 0 on --help', async () => {
    const res = await runner.run({ argv: ['--help'] });
    assert.strictEqual(res.exitCode, 0);
    assert.match(res.output, /SHN — Sovereign Cybersecurity Architecture & Platform CLI/);
  });

  it('should display version information on --version', async () => {
    const res = await runner.run({ argv: ['--version'] });
    assert.strictEqual(res.exitCode, 0);
    assert.match(res.output, /shn 0\.1\.0/);
  });

  it('should return exit code 1 on unknown commands', async () => {
    const res = await runner.run({ argv: ['unknowncommand'] });
    assert.strictEqual(res.exitCode, 1);
    assert.strictEqual(res.error !== undefined, true);
  });

  it('should validate missing parameters on auth register command', async () => {
    const res = await runner.run({ argv: ['auth', 'register'] });
    assert.strictEqual(res.exitCode, 1);
    assert.match(res.error || '', /Missing required registration parameters/);
  });
});
