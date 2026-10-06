/**
 * Shadow : Helix Nebula (SHN) — Bounded Output Tap & Cryptographic Evidence Tap
 *
 * Implements Phase 0.9 Sections 7 & 8:
 * - Strict byte ceiling on captured streams (prevents stdout/stderr flood DoS)
 * - Cryptographic SHA-256 digest over unmodified raw output stream (evidential integrity)
 * - Clean truncation indication
 */

import crypto from 'node:crypto';

export interface OutputTapOptions {
  readonly streamName: 'stdout' | 'stderr';
  readonly maxBytes: number;
  readonly onLimitExceeded?: ((streamName: string, totalBytes: number) => void) | undefined;
}

export class OutputTap {
  private readonly streamName: 'stdout' | 'stderr';
  private readonly maxBytes: number;
  private readonly onLimitExceeded?: ((streamName: string, totalBytes: number) => void) | undefined;
  private readonly hasher = crypto.createHash('sha256');

  private totalBytes = 0;
  private truncated = false;
  private readonly chunks: Buffer[] = [];
  private retainedBytes = 0;

  constructor(options: OutputTapOptions) {
    this.streamName = options.streamName;
    this.maxBytes = options.maxBytes;
    this.onLimitExceeded = options.onLimitExceeded;
  }

  write(data: Buffer | string): void {
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data, 'utf8');
    if (buf.length === 0) return;

    // 1. Hash ALL incoming raw bytes (even if truncated for storage)
    this.hasher.update(buf);
    this.totalBytes += buf.length;

    // 2. Check byte limits for retained buffer
    if (!this.truncated) {
      if (this.retainedBytes + buf.length <= this.maxBytes) {
        this.chunks.push(buf);
        this.retainedBytes += buf.length;
      } else {
        const remainingAllowed = this.maxBytes - this.retainedBytes;
        if (remainingAllowed > 0) {
          this.chunks.push(buf.subarray(0, remainingAllowed));
          this.retainedBytes += remainingAllowed;
        }
        this.truncated = true;
        if (this.onLimitExceeded) {
          this.onLimitExceeded(this.streamName, this.totalBytes);
        }
      }
    } else {
      // Already truncated, notify if needed
      if (this.onLimitExceeded) {
        this.onLimitExceeded(this.streamName, this.totalBytes);
      }
    }
  }

  isTruncated(): boolean {
    return this.truncated;
  }

  getTotalBytes(): number {
    return this.totalBytes;
  }

  getRetainedBytes(): number {
    return this.retainedBytes;
  }

  getText(): string {
    if (this.chunks.length === 0) return '';
    const full = Buffer.concat(this.chunks);
    return full.toString('utf8');
  }

  getSha256(): string {
    // Clone hash so getSha256 can be called multiple times
    const clone = this.hasher.copy();
    return clone.digest('hex');
  }
}
