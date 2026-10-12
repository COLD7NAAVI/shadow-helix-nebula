import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseSemVer,
  formatSemVer,
  compareSemVer,
  satisfiesVersion,
  evaluateCompatibility,
} from '../../dist/index.js';

describe('Strict SemVer Engine (Unit Tests)', () => {
  describe('parseSemVer', () => {
    it('should parse valid basic semver strings', () => {
      const res = parseSemVer('1.2.3');
      assert.strictEqual(res.isOk, true);
      if (res.isOk) {
        assert.strictEqual(res.value.major, 1);
        assert.strictEqual(res.value.minor, 2);
        assert.strictEqual(res.value.patch, 3);
        assert.strictEqual(res.value.prerelease, undefined);
        assert.strictEqual(res.value.build, undefined);
      }
    });

    it('should parse valid semver strings with prerelease and build metadata', () => {
      const res = parseSemVer('2.0.0-alpha.1+build.001');
      assert.strictEqual(res.isOk, true);
      if (res.isOk) {
        assert.strictEqual(res.value.major, 2);
        assert.strictEqual(res.value.minor, 0);
        assert.strictEqual(res.value.patch, 0);
        assert.strictEqual(res.value.prerelease, 'alpha.1');
        assert.strictEqual(res.value.build, 'build.001');
      }
    });

    it('should parse semver with leading "v"', () => {
      const res = parseSemVer('v3.14.15');
      assert.strictEqual(res.isOk, true);
      if (res.isOk) {
        assert.strictEqual(res.value.major, 3);
        assert.strictEqual(res.value.minor, 14);
        assert.strictEqual(res.value.patch, 15);
      }
    });

    it('should reject invalid or malformed semver strings', () => {
      const invalid = ['invalid', '', '1', '1.2', '1.2.3.4', '1.a.2', 'v', '1.2.-1', '-1.0.0'];
      for (const inv of invalid) {
        const res = parseSemVer(inv);
        assert.strictEqual(res.isErr, true, `Expected '${inv}' to be rejected`);
      }
    });
  });

  describe('formatSemVer', () => {
    it('should format parsed semver correctly', () => {
      assert.strictEqual(formatSemVer({ major: 1, minor: 2, patch: 3 }), '1.2.3');
      assert.strictEqual(
        formatSemVer({ major: 1, minor: 0, patch: 0, prerelease: 'rc.1' }),
        '1.0.0-rc.1'
      );
      assert.strictEqual(
        formatSemVer({ major: 1, minor: 0, patch: 0, prerelease: 'rc.1', build: 'sha.abc' }),
        '1.0.0-rc.1+sha.abc'
      );
    });
  });

  describe('compareSemVer', () => {
    it('should correctly compare major versions', () => {
      const v1 = parseSemVer('1.0.0').value;
      const v2 = parseSemVer('2.0.0').value;
      assert.strictEqual(compareSemVer(v1, v2) < 0, true);
      assert.strictEqual(compareSemVer(v2, v1) > 0, true);
    });

    it('should correctly compare minor and patch versions', () => {
      const v1 = parseSemVer('1.1.0').value;
      const v2 = parseSemVer('1.2.0').value;
      const v3 = parseSemVer('1.2.1').value;
      assert.strictEqual(compareSemVer(v1, v2) < 0, true);
      assert.strictEqual(compareSemVer(v2, v3) < 0, true);
      assert.strictEqual(compareSemVer(v3, v3), 0);
    });

    it('should rank versions with prereleases lower than normal versions', () => {
      const pre = parseSemVer('1.0.0-alpha').value;
      const norm = parseSemVer('1.0.0').value;
      assert.strictEqual(compareSemVer(pre, norm) < 0, true);
      assert.strictEqual(compareSemVer(norm, pre) > 0, true);
    });
  });

  describe('satisfiesVersion', () => {
    it('should handle exact match constraints', () => {
      assert.strictEqual(satisfiesVersion('1.2.3', '1.2.3'), true);
      assert.strictEqual(satisfiesVersion('1.2.3', '=1.2.3'), true);
      assert.strictEqual(satisfiesVersion('1.2.4', '1.2.3'), false);
    });

    it('should handle wildcard constraints', () => {
      assert.strictEqual(satisfiesVersion('1.2.3', '*'), true);
      assert.strictEqual(satisfiesVersion('2.0.0', '*'), true);
      assert.strictEqual(satisfiesVersion('1.2.3', 'x'), true);
    });

    it('should handle caret (^) constraints', () => {
      assert.strictEqual(satisfiesVersion('1.2.3', '^1.2.0'), true);
      assert.strictEqual(satisfiesVersion('1.9.9', '^1.2.0'), true);
      assert.strictEqual(satisfiesVersion('2.0.0', '^1.2.0'), false);
      assert.strictEqual(satisfiesVersion('0.2.3', '^0.2.0'), true);
      assert.strictEqual(satisfiesVersion('0.3.0', '^0.2.0'), false);
    });

    it('should handle tilde (~) constraints', () => {
      assert.strictEqual(satisfiesVersion('1.2.3', '~1.2.0'), true);
      assert.strictEqual(satisfiesVersion('1.2.9', '~1.2.0'), true);
      assert.strictEqual(satisfiesVersion('1.3.0', '~1.2.0'), false);
    });

    it('should handle range comparison constraints (>=, <=, >, <)', () => {
      assert.strictEqual(satisfiesVersion('1.5.0', '>=1.0.0 <2.0.0'), true);
      assert.strictEqual(satisfiesVersion('2.0.0', '>=1.0.0 <2.0.0'), false);
      assert.strictEqual(satisfiesVersion('0.9.9', '>=1.0.0 <2.0.0'), false);
    });

    it('should fail-closed on invalid constraint syntax or version strings', () => {
      assert.strictEqual(satisfiesVersion('invalid', '^1.0.0'), false);
      assert.strictEqual(satisfiesVersion('1.0.0', 'not-a-valid-constraint'), false);
    });
  });

  describe('evaluateCompatibility', () => {
    it('should evaluate EXACT and COMPATIBLE versions', () => {
      assert.strictEqual(evaluateCompatibility('1.0.0', '1.0.0'), 'EXACT');
      assert.strictEqual(evaluateCompatibility('1.1.0', '^1.0.0'), 'COMPATIBLE');
      assert.strictEqual(evaluateCompatibility('2.0.0', '^1.0.0'), 'INCOMPATIBLE');
    });

    it('should honor lifecycle states like REVOKED, DISABLED, and DEPRECATED', () => {
      assert.strictEqual(evaluateCompatibility('1.0.0', '1.0.0', 'REVOKED'), 'REVOKED');
      assert.strictEqual(evaluateCompatibility('1.0.0', '1.0.0', 'AVAILABLE', 'REVOKED'), 'REVOKED');
      assert.strictEqual(evaluateCompatibility('1.0.0', '1.0.0', 'DISABLED'), 'UNSUPPORTED');
      assert.strictEqual(evaluateCompatibility('1.0.0', '1.0.0', 'DEPRECATED'), 'DEPRECATED');
    });
  });
});
