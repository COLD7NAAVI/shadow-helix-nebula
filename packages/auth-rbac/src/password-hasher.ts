/**
 * Shadow : Helix Nebula (SHN) — Cryptographic Password Hasher
 *
 * Enforces SEC-AUT-001, OWASP & NIST recommendations.
 * Uses native Node.js crypto.scrypt with unique salt, constant-time verification,
 * and dummy verification to defend against timing-based user enumeration.
 */

import { scrypt, randomBytes, timingSafeEqual } from 'node:crypto';

const SCRYPT_COST_N = 16384;
const SCRYPT_BLOCK_R = 8;
const SCRYPT_PARALLEL_P = 1;
const SCRYPT_KEYLEN = 64;
const SALT_BYTES = 16;

// Pre-computed static dummy salt used for constant-time dummy verification
const DUMMY_SALT_HEX = '0123456789abcdef0123456789abcdef';

function runScrypt(
  password: string | Buffer,
  salt: Buffer,
  keylen: number,
  options: { N: number; r: number; p: number; maxmem: number }
): Promise<Buffer> {
  return new Promise<Buffer>((resolve, reject) => {
    scrypt(password, salt, keylen, options, (err, derivedKey) => {
      if (err) {
        reject(err);
      } else {
        resolve(derivedKey as Buffer);
      }
    });
  });
}

export interface ScryptParams {
  readonly costN: number;
  readonly blockR: number;
  readonly parallelP: number;
  readonly keylen: number;
}

export class PasswordHasher {
  private readonly costN: number;
  private readonly blockR: number;
  private readonly parallelP: number;
  private readonly keylen: number;

  constructor(params?: Partial<ScryptParams>) {
    this.costN = params?.costN ?? SCRYPT_COST_N;
    this.blockR = params?.blockR ?? SCRYPT_BLOCK_R;
    this.parallelP = params?.parallelP ?? SCRYPT_PARALLEL_P;
    this.keylen = params?.keylen ?? SCRYPT_KEYLEN;
  }

  async hashPassword(password: string): Promise<string> {
    if (typeof password !== 'string' || password.length === 0) {
      throw new Error('Password must be a non-empty string');
    }

    const salt = randomBytes(SALT_BYTES);
    const derivedKey = await runScrypt(password, salt, this.keylen, {
      N: this.costN,
      r: this.blockR,
      p: this.parallelP,
      maxmem: 32 * 1024 * 1024,
    });

    const saltHex = salt.toString('hex');
    const hashHex = derivedKey.toString('hex');

    return `$scrypt$N=${this.costN},r=${this.blockR},p=${this.parallelP}$${saltHex}$${hashHex}`;
  }

  async verifyPassword(password: string, storedHash: string): Promise<boolean> {
    if (typeof password !== 'string' || password.length === 0) {
      return false;
    }
    if (typeof storedHash !== 'string' || !storedHash.startsWith('$scrypt$')) {
      return false;
    }

    try {
      const parts = storedHash.split('$');
      // Format: ["", "scrypt", "N=16384,r=8,p=1", "saltHex", "hashHex"]
      if (parts.length !== 5 || parts[1] !== 'scrypt') {
        return false;
      }

      const paramPart = parts[2]!;
      const saltHex = parts[3]!;
      const expectedHashHex = parts[4]!;

      // Parse parameters
      const paramsMatch = paramPart.match(/^N=(\d+),r=(\d+),p=(\d+)$/);
      if (!paramsMatch) {
        return false;
      }

      const n = parseInt(paramsMatch[1]!, 10);
      const r = parseInt(paramsMatch[2]!, 10);
      const p = parseInt(paramsMatch[3]!, 10);

      const salt = Buffer.from(saltHex, 'hex');
      const expectedHash = Buffer.from(expectedHashHex, 'hex');

      if (salt.length !== SALT_BYTES || expectedHash.length !== this.keylen) {
        return false;
      }

      const derivedKey = await runScrypt(password, salt, expectedHash.length, {
        N: n,
        r: r,
        p: p,
        maxmem: 32 * 1024 * 1024,
      });

      return timingSafeEqual(derivedKey, expectedHash);
    } catch {
      return false;
    }
  }

  /**
   * Performs a dummy scrypt verification with identical cost to defeat timing-based
   * user enumeration attacks when an email/user does not exist in the database.
   */
  async verifyDummy(password: string): Promise<boolean> {
    try {
      const salt = Buffer.from(DUMMY_SALT_HEX, 'hex');
      await runScrypt(password || 'dummy-password-value', salt, this.keylen, {
        N: this.costN,
        r: this.blockR,
        p: this.parallelP,
        maxmem: 32 * 1024 * 1024,
      });
    } catch {
      // Ignored
    }
    return false;
  }
}

export const defaultPasswordHasher = new PasswordHasher();
