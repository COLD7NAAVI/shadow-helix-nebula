import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import { auditDependencies } from '../../../../scripts/check-deps.js';

describe('Architectural Dependency Boundary Linter (Pure Unit Tests)', () => {
  it('should pass audit for current repository workspace', () => {
    const violations = auditDependencies();
    assert.deepEqual(violations, []);
  });

  it('should detect unauthorized runtime dependencies in shared-kernel', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shn-dep-audit-'));
    try {
      const pkgDir = path.join(tmpDir, 'shared-kernel');
      fs.mkdirSync(pkgDir, { recursive: true });
      fs.writeFileSync(
        path.join(pkgDir, 'package.json'),
        JSON.stringify({
          name: '@shn/shared-kernel',
          dependencies: { lodash: '^4.17.21' },
        })
      );

      const violations = auditDependencies(tmpDir);
      assert.ok(violations.length >= 1);
      assert.ok(violations[0]!.includes('unauthorized runtime dependency: "lodash"'));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('should detect forbidden downstream workspace dependency', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shn-dep-audit-'));
    try {
      const pkgDir = path.join(tmpDir, 'shared-kernel');
      fs.mkdirSync(pkgDir, { recursive: true });
      fs.writeFileSync(
        path.join(pkgDir, 'package.json'),
        JSON.stringify({
          name: '@shn/shared-kernel',
          dependencies: {},
          devDependencies: { '@shn/data-access': '*' },
        })
      );

      const violations = auditDependencies(tmpDir);
      assert.ok(violations.length >= 1);
      assert.ok(violations[0]!.includes('violates module DAG hierarchy'));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it('should detect circular self-dependency', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shn-dep-audit-'));
    try {
      const pkgDir = path.join(tmpDir, 'data-access');
      fs.mkdirSync(pkgDir, { recursive: true });
      fs.writeFileSync(
        path.join(pkgDir, 'package.json'),
        JSON.stringify({
          name: '@shn/data-access',
          dependencies: {
            pg: '^8.13.3',
            '@shn/data-access': '*',
          },
        })
      );

      const violations = auditDependencies(tmpDir);
      assert.ok(violations.length >= 1);
      assert.ok(violations.some(v => v.includes('circular self-dependency')));
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  });
});
