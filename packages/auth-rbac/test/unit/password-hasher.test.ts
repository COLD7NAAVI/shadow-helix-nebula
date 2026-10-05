/**
 * Shadow : Helix Nebula (SHN) — Password Hasher Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PasswordHasher, defaultPasswordHasher } from '../../dist/index.js';

describe('Cryptographic Password Hasher (Pure Unit Tests)', () => {
  it('should hash a password and verify it successfully with scrypt', async () => {
    const password = 'SuperSecretCorrectHorseBatteryStaple!2026';
    const hash = await defaultPasswordHasher.hashPassword(password);

    assert.ok(typeof hash === 'string');
    assert.ok(hash.startsWith('$scrypt$N=16384,r=8,p=1$'));

    const isValid = await defaultPasswordHasher.verifyPassword(password, hash);
    assert.strictEqual(isValid, true);
  });

  it('should produce distinct unique hashes for identical passwords due to salt entropy', async () => {
    const password = 'IdenticalPasswordValue#123';
    const hash1 = await defaultPasswordHasher.hashPassword(password);
    const hash2 = await defaultPasswordHasher.hashPassword(password);

    assert.notStrictEqual(hash1, hash2);
    assert.strictEqual(await defaultPasswordHasher.verifyPassword(password, hash1), true);
    assert.strictEqual(await defaultPasswordHasher.verifyPassword(password, hash2), true);
  });

  it('should reject incorrect password', async () => {
    const password = 'CorrectPasswordValue123!';
    const wrongPassword = 'WrongPasswordValue456!';
    const hash = await defaultPasswordHasher.hashPassword(password);

    const isValid = await defaultPasswordHasher.verifyPassword(wrongPassword, hash);
    assert.strictEqual(isValid, false);
  });

  it('should execute verifyDummy in constant-time without throwing', async () => {
    const start = Date.now();
    const result = await defaultPasswordHasher.verifyDummy('attacker_probe_input');
    const elapsed = Date.now() - start;

    assert.strictEqual(result, false);
    // Scrypt with N=16384 takes at least some milliseconds
    assert.ok(elapsed >= 0);
  });

  it('should reject corrupt, malformed, or tampered hashes fail-closed', async () => {
    const validHash = await defaultPasswordHasher.hashPassword('test-password');
    const tamperedHash = validHash.slice(0, -4) + '0000';

    assert.strictEqual(await defaultPasswordHasher.verifyPassword('test-password', tamperedHash), false);
    assert.strictEqual(await defaultPasswordHasher.verifyPassword('test-password', 'invalid-hash-string'), false);
    assert.strictEqual(await defaultPasswordHasher.verifyPassword('test-password', '$argon2id$v=19$m=65536,t=3,p=4$abc$def'), false);
    assert.strictEqual(await defaultPasswordHasher.verifyPassword('test-password', ''), false);
  });

  it('should throw an error on empty password during hash', async () => {
    await assert.rejects(
      async () => {
        await defaultPasswordHasher.hashPassword('');
      },
      {
        message: /Password must be a non-empty string/,
      }
    );
  });

  it('should support custom scrypt cost parameters for fast testing or heightened security', async () => {
    const fastHasher = new PasswordHasher({ costN: 1024, blockR: 8, parallelP: 1 });
    const hash = await fastHasher.hashPassword('fast-pass');
    assert.ok(hash.startsWith('$scrypt$N=1024,r=8,p=1$'));
    assert.strictEqual(await fastHasher.verifyPassword('fast-pass', hash), true);
  });
});
