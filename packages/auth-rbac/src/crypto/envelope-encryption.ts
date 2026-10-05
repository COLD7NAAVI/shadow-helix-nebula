/**
 * Shadow : Helix Nebula (SHN) — Secrets Envelope Encryption Engine
 *
 * Enforces SEC-CRY-001 & INV-15:
 * - AES-256-GCM envelope encryption with distinct 12-byte nonce & 16-byte auth tag.
 * - Master Root Key -> Organization KEK (HKDF-SHA256 compartmentalization) -> Ephemeral DEK.
 * - In-memory zeroization of sensitive plaintext and DEK buffers immediately post-use.
 */

import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  hkdfSync,
} from 'node:crypto';
import { ok, err, type Result } from '@shn/shared-kernel';
import { ErrorCode, type ProblemDetails } from '@shn/error-catalog';
import { makeAuthProblem } from '../errors.js';

export const GCM_NONCE_LENGTH = 12; // 96-bit nonce per NIST SP 800-38D
export const GCM_TAG_LENGTH = 16;   // 128-bit authentication tag
export const DEK_LENGTH = 32;        // 256-bit AES key
export const WRAPPED_DEK_LENGTH = GCM_NONCE_LENGTH + DEK_LENGTH + GCM_TAG_LENGTH; // 12 + 32 + 16 = 60 bytes

/**
 * Mechanically zeroizes memory buffer holding sensitive key material or plaintext.
 * Enforces Phase 0.11 Section 6.1 #5.
 */
export function zeroizeMemory(buffer: Buffer | Uint8Array): void {
  if (buffer && typeof buffer.fill === 'function') {
    buffer.fill(0);
  }
}

/**
 * Derives an Organization-specific Key Encryption Key (KEK) from Master Key using HKDF-SHA256.
 * Enforces: Compartmentalized per Organization (Phase 0.3 Section 3.24).
 */
export function deriveOrgKek(masterKey: Buffer, organizationId: string): Buffer {
  if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
    throw new Error('Master key must be a 32-byte Buffer');
  }
  if (typeof organizationId !== 'string' || organizationId.trim().length === 0) {
    throw new Error('OrganizationId must be a non-empty string for KEK derivation');
  }

  const salt = Buffer.alloc(0);
  const info = Buffer.from(`shn:kek:org:${organizationId.trim()}`, 'utf8');
  const derived = hkdfSync('sha256', masterKey, salt, info, 32);
  return Buffer.from(derived);
}

export interface EncryptedEnvelopeResult {
  readonly ciphertext: Buffer;
  readonly encrypted_dek: Buffer;
  readonly nonce: Buffer;
  readonly auth_tag: Buffer;
  readonly kek_id: string;
  readonly algorithm: string;
}

export class EnvelopeEncryptionEngine {
  constructor(private readonly masterKey: Buffer, private readonly defaultKekId = 'shn-root-kek-v1') {
    if (!Buffer.isBuffer(masterKey) || masterKey.length !== 32) {
      throw new Error('EnvelopeEncryptionEngine requires a 32-byte masterKey Buffer');
    }
  }

  /**
   * Encrypts plaintext under AES-256-GCM using an ephemeral DEK wrapped by the Org KEK.
   */
  async encrypt(
    plaintextInput: Buffer | string,
    organizationId: string,
    kekId = this.defaultKekId
  ): Promise<Result<EncryptedEnvelopeResult, ProblemDetails>> {
    let plaintextBuffer: Buffer | null = null;
    let dek: Buffer | null = null;
    let orgKek: Buffer | null = null;

    try {
      if (typeof plaintextInput === 'string') {
        plaintextBuffer = Buffer.from(plaintextInput, 'utf8');
      } else if (Buffer.isBuffer(plaintextInput)) {
        plaintextBuffer = Buffer.from(plaintextInput);
      } else {
        return err(
          makeAuthProblem(
            ErrorCode.INVALID_PAYLOAD_SCHEMA,
            'Plaintext input must be a string or Buffer',
            '/secrets/encrypt'
          )
        );
      }

      if (plaintextBuffer.length === 0) {
        return err(
          makeAuthProblem(
            ErrorCode.INVALID_PAYLOAD_SCHEMA,
            'Plaintext cannot be empty',
            '/secrets/encrypt'
          )
        );
      }

      // 1. Derive Organization KEK
      orgKek = deriveOrgKek(this.masterKey, organizationId);

      // 2. Generate ephemeral 256-bit DEK
      dek = randomBytes(DEK_LENGTH);

      // 3. Encrypt plaintext with DEK via AES-256-GCM
      const nonce = randomBytes(GCM_NONCE_LENGTH);
      const cipher = createCipheriv('aes-256-gcm', dek, nonce);
      const ciphertext = Buffer.concat([cipher.update(plaintextBuffer), cipher.final()]);
      const authTag = cipher.getAuthTag();

      // 4. Wrap DEK with Org KEK via AES-256-GCM
      const dekNonce = randomBytes(GCM_NONCE_LENGTH);
      const dekCipher = createCipheriv('aes-256-gcm', orgKek, dekNonce);
      const dekCiphertext = Buffer.concat([dekCipher.update(dek), dekCipher.final()]);
      const dekTag = dekCipher.getAuthTag();

      const encryptedDek = Buffer.concat([dekNonce, dekCiphertext, dekTag]);

      return ok({
        ciphertext,
        encrypted_dek: encryptedDek,
        nonce,
        auth_tag: authTag,
        kek_id: kekId,
        algorithm: 'AES-256-GCM',
      });
    } catch (error) {
      return err(
        makeAuthProblem(
          ErrorCode.VAULT_DECRYPTION_FAILED,
          `Envelope encryption failed: ${error instanceof Error ? error.message : String(error)}`,
          '/secrets/encrypt'
        )
      );
    } finally {
      // Mechanically zeroize sensitive temporary buffers
      if (dek) zeroizeMemory(dek);
      if (orgKek) zeroizeMemory(orgKek);
      if (plaintextBuffer) zeroizeMemory(plaintextBuffer);
    }
  }

  /**
   * Decrypts an encrypted envelope by unwrapping the DEK with Org KEK and decrypting ciphertext.
   */
  async decrypt(
    envelope: {
      ciphertext: Buffer;
      encrypted_dek: Buffer;
      nonce: Buffer;
      auth_tag: Buffer;
    },
    organizationId: string
  ): Promise<Result<Buffer, ProblemDetails>> {
    let orgKek: Buffer | null = null;
    let dek: Buffer | null = null;

    try {
      if (
        !Buffer.isBuffer(envelope.ciphertext) ||
        !Buffer.isBuffer(envelope.encrypted_dek) ||
        !Buffer.isBuffer(envelope.nonce) ||
        !Buffer.isBuffer(envelope.auth_tag)
      ) {
        return err(
          makeAuthProblem(
            ErrorCode.VAULT_DECRYPTION_FAILED,
            'Malformed secret version envelope: components must be Buffers',
            '/secrets/decrypt'
          )
        );
      }

      if (envelope.nonce.length !== GCM_NONCE_LENGTH) {
        return err(
          makeAuthProblem(
            ErrorCode.VAULT_DECRYPTION_FAILED,
            `Invalid nonce length: expected ${GCM_NONCE_LENGTH} bytes, got ${envelope.nonce.length}`,
            '/secrets/decrypt'
          )
        );
      }

      if (envelope.auth_tag.length !== GCM_TAG_LENGTH) {
        return err(
          makeAuthProblem(
            ErrorCode.VAULT_DECRYPTION_FAILED,
            `Invalid auth tag length: expected ${GCM_TAG_LENGTH} bytes, got ${envelope.auth_tag.length}`,
            '/secrets/decrypt'
          )
        );
      }

      if (envelope.encrypted_dek.length !== WRAPPED_DEK_LENGTH) {
        return err(
          makeAuthProblem(
            ErrorCode.VAULT_DECRYPTION_FAILED,
            `Invalid wrapped DEK length: expected ${WRAPPED_DEK_LENGTH} bytes, got ${envelope.encrypted_dek.length}`,
            '/secrets/decrypt'
          )
        );
      }

      // 1. Derive Org KEK
      orgKek = deriveOrgKek(this.masterKey, organizationId);

      // 2. Unwrap DEK
      const dekNonce = envelope.encrypted_dek.subarray(0, GCM_NONCE_LENGTH);
      const dekCiphertext = envelope.encrypted_dek.subarray(
        GCM_NONCE_LENGTH,
        GCM_NONCE_LENGTH + DEK_LENGTH
      );
      const dekTag = envelope.encrypted_dek.subarray(GCM_NONCE_LENGTH + DEK_LENGTH);

      const dekDecipher = createDecipheriv('aes-256-gcm', orgKek, dekNonce);
      dekDecipher.setAuthTag(dekTag);
      dek = Buffer.concat([dekDecipher.update(dekCiphertext), dekDecipher.final()]);

      // 3. Decrypt ciphertext with DEK
      const decipher = createDecipheriv('aes-256-gcm', dek, envelope.nonce);
      decipher.setAuthTag(envelope.auth_tag);
      const plaintext = Buffer.concat([decipher.update(envelope.ciphertext), decipher.final()]);

      return ok(plaintext);
    } catch (error) {
      return err(
        makeAuthProblem(
          ErrorCode.VAULT_DECRYPTION_FAILED,
          'Cryptographic envelope decryption failed: invalid ciphertext or authentication tag mismatch',
          '/secrets/decrypt'
        )
      );
    } finally {
      if (dek) zeroizeMemory(dek);
      if (orgKek) zeroizeMemory(orgKek);
    }
  }
}
