/**
 * Shadow : Helix Nebula (SHN) — Finding State Machine Unit Tests
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  isValidFindingStateTransition,
  assertValidFindingStateTransition,
  ALLOWED_FINDING_TRANSITIONS,
} from '../../dist/index.js';

describe('Finding State Machine (Pure Unit Tests)', () => {
  it('should allow legal transitions according to the state matrix', () => {
    assert.strictEqual(isValidFindingStateTransition('DRAFT', 'UNDER_REVIEW'), true);
    assert.strictEqual(isValidFindingStateTransition('UNDER_REVIEW', 'CONFIRMED'), true);
    assert.strictEqual(isValidFindingStateTransition('UNDER_REVIEW', 'FALSE_POSITIVE'), true);
    assert.strictEqual(isValidFindingStateTransition('CONFIRMED', 'REMEDIATED'), true);
    assert.strictEqual(isValidFindingStateTransition('CONFIRMED', 'ACCEPTED_RISK'), true);
  });

  it('should allow idempotent transitions to identical state', () => {
    assert.strictEqual(isValidFindingStateTransition('DRAFT', 'DRAFT'), true);
    assert.strictEqual(isValidFindingStateTransition('CONFIRMED', 'CONFIRMED'), true);
  });

  it('should reject illegal transitions fail-closed', () => {
    // Cannot skip straight from DRAFT to REMEDIATED
    assert.strictEqual(isValidFindingStateTransition('DRAFT', 'REMEDIATED'), false);
    // Cannot skip straight from DRAFT to CONFIRMED without review
    assert.strictEqual(isValidFindingStateTransition('DRAFT', 'CONFIRMED'), false);
    // Cannot skip from FALSE_POSITIVE directly to REMEDIATED
    assert.strictEqual(isValidFindingStateTransition('FALSE_POSITIVE', 'REMEDIATED'), false);
  });

  it('assertValidFindingStateTransition should return informative Result error', () => {
    const legalRes = assertValidFindingStateTransition('DRAFT', 'UNDER_REVIEW');
    assert.strictEqual(legalRes.isOk, true);

    const illegalRes = assertValidFindingStateTransition('DRAFT', 'CONFIRMED');
    assert.strictEqual(illegalRes.isErr, true);
    assert.match(illegalRes.error, /Illegal finding status transition from "DRAFT" to "CONFIRMED"/);
  });
});
