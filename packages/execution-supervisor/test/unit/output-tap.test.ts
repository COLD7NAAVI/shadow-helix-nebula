import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { OutputTap } from '../../dist/index.js';

describe('OutputTap & Cryptographic Evidence Streamer (Unit Tests)', () => {
  it('should capture text within limit and compute accurate SHA-256', () => {
    let limitTriggered = false;
    const tap = new OutputTap({
      streamName: 'stdout',
      maxBytes: 1024,
      onLimitExceeded: () => {
        limitTriggered = true;
      },
    });

    const sampleText = 'Line 1: starting scan\nLine 2: host is up\n';
    tap.write(sampleText);

    assert.equal(tap.getText(), sampleText);
    assert.equal(tap.getTotalBytes(), Buffer.byteLength(sampleText, 'utf8'));
    assert.equal(tap.isTruncated(), false);
    assert.equal(limitTriggered, false);

    const expectedHash = createHash('sha256').update(sampleText, 'utf8').digest('hex');
    assert.equal(tap.getSha256(), expectedHash);
  });

  it('should enforce byte ceiling, mark truncated, and trigger callback', () => {
    let limitStreamName = '';
    const tap = new OutputTap({
      streamName: 'stderr',
      maxBytes: 20, // 20 byte limit
      onLimitExceeded: (streamName) => {
        limitStreamName = streamName;
      },
    });

    const chunk1 = '1234567890'; // 10 bytes
    const chunk2 = 'abcdefghij'; // 10 bytes (total 20 bytes)
    const chunk3 = 'EXTRA_OVERFLOW_DATA'; // exceeds limit

    tap.write(chunk1);
    assert.equal(tap.isTruncated(), false);

    tap.write(chunk2);
    assert.equal(tap.isTruncated(), false);

    tap.write(chunk3);
    assert.equal(tap.isTruncated(), true);
    assert.equal(limitStreamName, 'stderr');

    // Buffer should contain only up to maxBytes
    assert.equal(Buffer.byteLength(tap.getText(), 'utf8'), 20);
    assert.equal(tap.getText(), '1234567890abcdefghij');

    // Total bytes tracks the actual observed data volume
    assert.equal(tap.getTotalBytes(), 20 + chunk3.length);

    // Continuous SHA-256 seals the entire raw stream including overflow
    const fullContent = chunk1 + chunk2 + chunk3;
    const expectedHash = createHash('sha256').update(fullContent, 'utf8').digest('hex');
    assert.equal(tap.getSha256(), expectedHash);
  });

  it('should handle Buffer chunks and multibyte UTF-8 characters cleanly', () => {
    const tap = new OutputTap({
      streamName: 'stdout',
      maxBytes: 50,
    });

    const utf8Data = 'Shield 🛡️ and Helix 🧬\n';
    tap.write(Buffer.from(utf8Data, 'utf8'));

    assert.equal(tap.getText(), utf8Data);
    assert.equal(tap.isTruncated(), false);

    const expectedHash = createHash('sha256').update(utf8Data, 'utf8').digest('hex');
    assert.equal(tap.getSha256(), expectedHash);
  });
});
