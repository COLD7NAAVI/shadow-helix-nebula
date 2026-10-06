import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  type ExecutionState,
  TERMINAL_STATES,
  LEGAL_TRANSITIONS,
  isTerminalState,
  isValidStateTransition,
} from '../../dist/index.js';

describe('Execution State Machine (Unit Tests)', () => {
  it('should identify terminal states correctly', () => {
    const expectedTerminal: ExecutionState[] = [
      'SUCCEEDED',
      'FAILED',
      'TIMED_OUT',
      'CANCELLED',
      'TERMINATED',
      'REJECTED',
    ];

    for (const state of expectedTerminal) {
      assert.equal(isTerminalState(state), true, `Expected ${state} to be terminal`);
      assert.ok(TERMINAL_STATES.has(state));
    }

    const nonTerminal: ExecutionState[] = [
      'CREATED',
      'VALIDATING',
      'AUTHORIZED',
      'QUEUED',
      'STARTING',
      'RUNNING',
      'CANCELLING',
    ];

    for (const state of nonTerminal) {
      assert.equal(isTerminalState(state), false, `Expected ${state} to NOT be terminal`);
      assert.ok(!TERMINAL_STATES.has(state));
    }
  });

  it('should allow valid transitions according to specification', () => {
    // CREATED -> VALIDATING, REJECTED, CANCELLED
    assert.equal(isValidStateTransition('CREATED', 'VALIDATING'), true);
    assert.equal(isValidStateTransition('CREATED', 'REJECTED'), true);
    assert.equal(isValidStateTransition('CREATED', 'CANCELLED'), true);

    // VALIDATING -> AUTHORIZED, REJECTED, CANCELLED
    assert.equal(isValidStateTransition('VALIDATING', 'AUTHORIZED'), true);
    assert.equal(isValidStateTransition('VALIDATING', 'REJECTED'), true);

    // AUTHORIZED -> QUEUED, STARTING, REJECTED, CANCELLED
    assert.equal(isValidStateTransition('AUTHORIZED', 'QUEUED'), true);
    assert.equal(isValidStateTransition('AUTHORIZED', 'STARTING'), true);

    // QUEUED -> STARTING, CANCELLED, TIMED_OUT
    assert.equal(isValidStateTransition('QUEUED', 'STARTING'), true);
    assert.equal(isValidStateTransition('QUEUED', 'CANCELLED'), true);
    assert.equal(isValidStateTransition('QUEUED', 'TIMED_OUT'), true);

    // STARTING -> RUNNING, FAILED, TIMED_OUT, CANCELLING, TERMINATED
    assert.equal(isValidStateTransition('STARTING', 'RUNNING'), true);
    assert.equal(isValidStateTransition('STARTING', 'FAILED'), true);
    assert.equal(isValidStateTransition('STARTING', 'TIMED_OUT'), true);
    assert.equal(isValidStateTransition('STARTING', 'CANCELLING'), true);

    // RUNNING -> SUCCEEDED, FAILED, TIMED_OUT, CANCELLING, TERMINATED
    assert.equal(isValidStateTransition('RUNNING', 'SUCCEEDED'), true);
    assert.equal(isValidStateTransition('RUNNING', 'FAILED'), true);
    assert.equal(isValidStateTransition('RUNNING', 'TIMED_OUT'), true);
    assert.equal(isValidStateTransition('RUNNING', 'CANCELLING'), true);

    // CANCELLING -> CANCELLED, TERMINATED, FAILED, TIMED_OUT
    assert.equal(isValidStateTransition('CANCELLING', 'CANCELLED'), true);
    assert.equal(isValidStateTransition('CANCELLING', 'TERMINATED'), true);
    assert.equal(isValidStateTransition('CANCELLING', 'FAILED'), true);
  });

  it('should reject invalid state transitions fail-closed', () => {
    // Direct from CREATED to RUNNING or SUCCEEDED without authorization
    assert.equal(isValidStateTransition('CREATED', 'RUNNING'), false);
    assert.equal(isValidStateTransition('CREATED', 'SUCCEEDED'), false);
    assert.equal(isValidStateTransition('CREATED', 'AUTHORIZED'), false);

    // From terminal states to anything
    const terminalStates: ExecutionState[] = Array.from(TERMINAL_STATES);
    const allStates: ExecutionState[] = [
      'CREATED',
      'VALIDATING',
      'AUTHORIZED',
      'QUEUED',
      'STARTING',
      'RUNNING',
      'CANCELLING',
      ...terminalStates,
    ];

    for (const term of terminalStates) {
      for (const dest of allStates) {
        assert.equal(
          isValidStateTransition(term, dest),
          false,
          `Transition from terminal ${term} to ${dest} must be rejected`
        );
      }
    }
  });

  it('should have complete coverage of legal transitions map', () => {
    for (const [sourceState, targets] of LEGAL_TRANSITIONS.entries()) {
      if (TERMINAL_STATES.has(sourceState)) {
        assert.equal(targets.size, 0, `Terminal state ${sourceState} must have 0 outgoing transitions`);
      } else {
        assert.ok(targets.size > 0, `Non-terminal state ${sourceState} must have at least 1 transition`);
      }
    }
  });
});
