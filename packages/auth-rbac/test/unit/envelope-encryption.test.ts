/**
 * Shadow : Helix Nebula (SHN) — Secrets Envelope Encryption Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import {
  EnvelopeEncryptionEngine,
  deriveOrgKek,
  zeroizeMemory,
  GCM_NONCE_LENGTH,
  GCM_TAG_LENGTH,
  WRAPPED_DEK_LENGTH,
} from '../../dist/index.js';

const TEST_MASTER_KEY = randomBytes(32);
const ORG_A = '00000000-0000-7000-8000-00000000000a';
const ORG_B = '00000000-0000-7000-8000-00000000000b';

describe('Envelope Encryption Engine (Pure Unit Tests)', () => {
  const engine = new EnvelopeEncryptionEngine(TEST_MASTER_KEY);

  it('should encrypt and decrypt plaintext string under AES-256-GCM envelope', async () => {
    const secretPlaintext = 'target-db-password-very-secure-2026!';
    const encryptRes = await engine.encrypt(secretPlaintext, ORG_A);

    assert.strictEqual(encryptRes.isOk, true);
    if (!encryptRes.isOk) return;

    const envelope = encryptRes.value;
    assert.strictEqual(envelope.nonce.length, GCM_NONCE_LENGTH);
    assert.strictEqual(envelope.auth_tag.length, GCM_TAG_LENGTH);
    assert.strictEqual(envelope.encrypted_dek.length, WRAPPED_DEK_LENGTH);
    assert.strictEqual(envelope.algorithm, 'AES-256-GCM');
    assert.notStrictEqual(envelope.ciphertext.toString('utf8'), secretPlaintext);

    const decryptRes = await engine.decrypt(envelope, ORG_A);
    assert.strictEqual(decryptRes.isOk, true);
    if (!decryptRes.isOk) return;

    assert.strictEqual(decryptRes.value.toString('utf8'), secretPlaintext);
  });

  it('should encrypt and decrypt binary Buffer material (e.g. private keys)', async () => {
    const binarySecret = randomBytes(64);
    const encryptRes = await engine.encrypt(binarySecret, ORG_A);

    assert.strictEqual(encryptRes.isOk, true);
    if (!encryptRes.isOk) return;

    const decryptRes = await engine.decrypt(encryptRes.value, ORG_A);
    assert.strictEqual(decryptRes.isOk, true);
    if (!decryptRes.isOk) return;

    assert.ok(decryptRes.value.equals(binarySecret));
  });

  it('should strictly isolate Organizations: Org B cannot decrypt Org A envelope', async () => {
    const orgASecret = 'Secret belonging strictly to Organization Alpha';
    const encryptRes = await engine.encrypt(orgASecret, ORG_A);

    assert.strictEqual(encryptRes.isOk, true);
    if (!encryptRes.isOk) return;

    // Attempt decryption under Org B
    const decryptRes = await engine.decrypt(encryptRes.value, ORG_B);
    assert.strictEqual(decryptRes.isOk, false);
    if (!decryptRes.isOk) {
      assert.strictEqual(decryptRes.error.error_code, 'ERR_VAULT_DECRYPTION_FAILED');
      assert.strictEqual(decryptRes.error.status, 500);
    }
  });

  it('should fail-closed if ciphertext is tampered', async () => {
    const encryptRes = await engine.encrypt('Integrity Protected Secret', ORG_A);
    assert.strictEqual(encryptRes.isOk, true);
    if (!encryptRes.isOk) return;

    const tampered = {
      ...encryptRes.value,
      ciphertext: Buffer.from(encryptRes.value.ciphertext),
    };
    tampered.ciphertext[0] ^= 0xff; // Flip bits

    const decryptRes = await engine.decrypt(tampered, ORG_A);
    assert.strictEqual(decryptRes.isOk, false);
    if (!decryptRes.isOk) {
      assert.strictEqual(decryptRes.error.error_code, 'ERR_VAULT_DECRYPTION_FAILED');
    }
  });

  it('should fail-closed if auth tag is tampered', async () => {
    const encryptRes = await engine.encrypt('Auth Tag Protected Secret', ORG_A);
    assert.strictEqual(encryptRes.isOk, true);
    if (!encryptRes.isOk) return;

    const tampered = {
      ...encryptRes.value,
      auth_tag: Buffer.from(encryptRes.value.auth_tag),
    };
    tampered.auth_tag[0] ^= 0x01; // Tamper tag

    const decryptRes = await engine.decrypt(tampered, ORG_A);
    assert.strictEqual(decryptRes.isOk, false);
  });

  it('should derive distinct cryptographic KEKs per Organization ID', () => {
    const kekA = deriveOrgKek(TEST_MASTER_KEY, ORG_A);
    const kekB = deriveOrgKek(TEST_MASTER_KEY, ORG_B);

    assert.strictEqual(kekA.length, 32);
    assert.strictEqual(kekB.length, 32);
    assert.notStrictEqual(kekA.toString('hex'), kekB.toString('hex'));
  });

  it('should zeroize memory buffer in-place', () => {
    const sensitive = Buffer.from('ExtremelySensitivePlaintextValue123!');
    const originalHex = sensitive.toString('hex');
    assert.notStrictEqual(originalHex, '00'.repeat(sensitive.length));

    zeroizeMemory(sensitive);
    assert.strictEqual(sensitive.toString('hex'), '00'.repeat(sensitive.length));
  });
});
