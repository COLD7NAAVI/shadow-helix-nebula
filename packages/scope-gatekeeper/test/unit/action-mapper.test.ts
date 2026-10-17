/**
 * Shadow : Helix Nebula (SHN) — Canonical Action Mapping Pure Unit Tests
 *
 * Enforces Phase 0.4 Invariants (INV-01, INV-06, SEC-INV-01, SEC-INV-05):
 * - Authoritative mapping between capability actions and canonical scope policy categories
 * - Cryptographic RBAC PermissionBit mapping
 * - Fail-closed authorization semantics
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { PermissionBit } from '@shn/auth-rbac';

import {
  CanonicalScopeAction,
  normalizeAction,
  actionsMatch,
  isActionAllowedByScope,
  isActionDisallowedByScope,
  mapActionToPermissionBit,
} from '../../dist/index.js';

describe('Canonical Action Mapper (Pure Unit Tests)', () => {
  describe('normalizeAction', () => {
    it('lowercases and trims action strings', () => {
      assert.strictEqual(normalizeAction('  HTTP:PROBE  '), 'http:probe');
      assert.strictEqual(normalizeAction('PROBING_ACTIVE'), 'probing_active');
      assert.strictEqual(normalizeAction('Port_Scan'), 'port_scan');
    });

    it('handles empty, null, or undefined values safely', () => {
      assert.strictEqual(normalizeAction(''), '');
      assert.strictEqual(normalizeAction(null as unknown as string), '');
      assert.strictEqual(normalizeAction(undefined as unknown as string), '');
    });
  });

  describe('actionsMatch', () => {
    it('matches identical actions case-insensitively', () => {
      assert.strictEqual(actionsMatch('http:probe', 'HTTP:PROBE'), true);
      assert.strictEqual(actionsMatch('network:scan', 'NETWORK:SCAN'), true);
      assert.strictEqual(actionsMatch('custom:action', 'CUSTOM:ACTION'), true);
    });

    it('matches HTTP/probing actions within the probing equivalence group', () => {
      assert.strictEqual(actionsMatch('http:probe', 'PROBING_ACTIVE'), true);
      assert.strictEqual(actionsMatch('http:probe', 'probe'), true);
      assert.strictEqual(actionsMatch('http:probe', 'probing'), true);
      assert.strictEqual(actionsMatch('web:probe', 'PROBING_ACTIVE'), true);
      assert.strictEqual(actionsMatch('http:discovery', 'PROBING_ACTIVE'), true);
      assert.strictEqual(actionsMatch('http_get', 'PROBING_ACTIVE'), true);
    });

    it('matches network/port scanning actions within the scanning equivalence group', () => {
      assert.strictEqual(actionsMatch('network:scan', 'PORT_SCAN'), true);
      assert.strictEqual(actionsMatch('network:scan', 'SCAN_INVASIVE'), true);
      assert.strictEqual(actionsMatch('network:scan', 'scan_tcp_port'), true);
      assert.strictEqual(actionsMatch('port:scan', 'PORT_SCAN'), true);
      assert.strictEqual(actionsMatch('scan', 'PORT_SCAN'), true);
    });

    it('matches passive recon actions within the recon equivalence group', () => {
      assert.strictEqual(actionsMatch('recon:passive', 'RECON_PASSIVE'), true);
      assert.strictEqual(actionsMatch('passive', 'RECON_PASSIVE'), true);
      assert.strictEqual(actionsMatch('recon', 'RECON_PASSIVE'), true);
    });

    it('matches workflow execution actions', () => {
      assert.strictEqual(actionsMatch('workflow:execute', 'WORKFLOW_EXECUTE'), true);
      assert.strictEqual(actionsMatch('execute', 'WORKFLOW_EXECUTE'), true);
    });

    it('rejects cross-category action matches fail-closed', () => {
      assert.strictEqual(actionsMatch('http:probe', 'PORT_SCAN'), false);
      assert.strictEqual(actionsMatch('http:probe', 'RECON_PASSIVE'), false);
      assert.strictEqual(actionsMatch('http:probe', 'WORKFLOW_EXECUTE'), false);
      assert.strictEqual(actionsMatch('network:scan', 'PROBING_ACTIVE'), false);
      assert.strictEqual(actionsMatch('network:scan', 'RECON_PASSIVE'), false);
    });

    it('rejects unknown or malicious actions fail-closed', () => {
      assert.strictEqual(actionsMatch('exploit:rce', 'PROBING_ACTIVE'), false);
      assert.strictEqual(actionsMatch('admin:override', 'SCOPE_ADMIN'), false);
      assert.strictEqual(actionsMatch('', 'PROBING_ACTIVE'), false);
      assert.strictEqual(actionsMatch('http:probe', ''), false);
    });
  });

  describe('isActionAllowedByScope', () => {
    const standardScopeActions = ['RECON_PASSIVE', 'PROBING_ACTIVE', 'PORT_SCAN'];

    it('authorizes http:probe when PROBING_ACTIVE is in scope allowedActions', () => {
      assert.strictEqual(isActionAllowedByScope('http:probe', standardScopeActions), true);
    });

    it('authorizes network:scan when PORT_SCAN is in scope allowedActions', () => {
      assert.strictEqual(isActionAllowedByScope('network:scan', standardScopeActions), true);
    });

    it('authorizes exact action matches', () => {
      assert.strictEqual(isActionAllowedByScope('http:probe', ['http:probe']), true);
      assert.strictEqual(isActionAllowedByScope('network:scan', ['network:scan']), true);
    });

    it('denies http:probe when scope only allows PORT_SCAN', () => {
      assert.strictEqual(isActionAllowedByScope('http:probe', ['PORT_SCAN']), false);
    });

    it('denies network:scan when scope only allows PROBING_ACTIVE', () => {
      assert.strictEqual(isActionAllowedByScope('network:scan', ['PROBING_ACTIVE']), false);
    });

    it('denies arbitrary or unauthorized actions fail-closed', () => {
      assert.strictEqual(isActionAllowedByScope('exploit:dos', standardScopeActions), false);
      assert.strictEqual(isActionAllowedByScope('system:shell', standardScopeActions), false);
      assert.strictEqual(isActionAllowedByScope('unauthorized', standardScopeActions), false);
    });

    it('permits all actions if allowedActions is empty (permissive default)', () => {
      assert.strictEqual(isActionAllowedByScope('http:probe', []), true);
    });
  });

  describe('isActionDisallowedByScope', () => {
    it('returns false when disallowedActions is empty or undefined', () => {
      assert.strictEqual(isActionDisallowedByScope('http:probe', undefined), false);
      assert.strictEqual(isActionDisallowedByScope('http:probe', []), false);
    });

    it('detects when action matches a disallowed canonical action', () => {
      assert.strictEqual(
        isActionDisallowedByScope('http:probe', ['EXPLOIT', 'PROBING_ACTIVE']),
        true
      );
      assert.strictEqual(
        isActionDisallowedByScope('web:probe', ['PROBING_ACTIVE']),
        true
      );
    });

    it('detects when action matches an explicit disallowed string', () => {
      assert.strictEqual(
        isActionDisallowedByScope('http:probe', ['http:probe', 'DENIAL_OF_SERVICE']),
        true
      );
    });

    it('returns false when action is not in disallowedActions', () => {
      assert.strictEqual(
        isActionDisallowedByScope('http:probe', ['EXPLOIT', 'DENIAL_OF_SERVICE', 'PORT_SCAN']),
        false
      );
    });
  });

  describe('mapActionToPermissionBit', () => {
    it('maps http:probe and probing actions to PermissionBit.PROBING_ACTIVE (64)', () => {
      assert.strictEqual(mapActionToPermissionBit('http:probe'), PermissionBit.PROBING_ACTIVE);
      assert.strictEqual(mapActionToPermissionBit('probing_active'), PermissionBit.PROBING_ACTIVE);
      assert.strictEqual(mapActionToPermissionBit('probe'), PermissionBit.PROBING_ACTIVE);
      assert.strictEqual(mapActionToPermissionBit('web:probe'), PermissionBit.PROBING_ACTIVE);
      assert.strictEqual(mapActionToPermissionBit('http:discovery'), PermissionBit.PROBING_ACTIVE);
      assert.strictEqual(mapActionToPermissionBit('http_get'), PermissionBit.PROBING_ACTIVE);
    });

    it('maps network:scan and port scanning actions to PermissionBit.SCAN_INVASIVE (128)', () => {
      assert.strictEqual(mapActionToPermissionBit('network:scan'), PermissionBit.SCAN_INVASIVE);
      assert.strictEqual(mapActionToPermissionBit('port_scan'), PermissionBit.SCAN_INVASIVE);
      assert.strictEqual(mapActionToPermissionBit('port:scan'), PermissionBit.SCAN_INVASIVE);
      assert.strictEqual(mapActionToPermissionBit('scan_invasive'), PermissionBit.SCAN_INVASIVE);
      assert.strictEqual(mapActionToPermissionBit('scan'), PermissionBit.SCAN_INVASIVE);
      assert.strictEqual(mapActionToPermissionBit('scan_tcp_port'), PermissionBit.SCAN_INVASIVE);
    });

    it('maps passive recon actions to PermissionBit.RECON_PASSIVE (32)', () => {
      assert.strictEqual(mapActionToPermissionBit('recon_passive'), PermissionBit.RECON_PASSIVE);
      assert.strictEqual(mapActionToPermissionBit('recon:passive'), PermissionBit.RECON_PASSIVE);
      assert.strictEqual(mapActionToPermissionBit('passive'), PermissionBit.RECON_PASSIVE);
      assert.strictEqual(mapActionToPermissionBit('recon'), PermissionBit.RECON_PASSIVE);
    });

    it('maps workflow execution actions to PermissionBit.WORKFLOW_EXECUTE (16)', () => {
      assert.strictEqual(mapActionToPermissionBit('workflow_execute'), PermissionBit.WORKFLOW_EXECUTE);
      assert.strictEqual(mapActionToPermissionBit('workflow:execute'), PermissionBit.WORKFLOW_EXECUTE);
      assert.strictEqual(mapActionToPermissionBit('execute'), PermissionBit.WORKFLOW_EXECUTE);
    });

    it('maps scope administrative actions to PermissionBit.SCOPE_ADMIN (4)', () => {
      assert.strictEqual(mapActionToPermissionBit('scope_admin'), PermissionBit.SCOPE_ADMIN);
      assert.strictEqual(mapActionToPermissionBit('create_scope'), PermissionBit.SCOPE_ADMIN);
      assert.strictEqual(mapActionToPermissionBit('update_scope'), PermissionBit.SCOPE_ADMIN);
      assert.strictEqual(mapActionToPermissionBit('admin'), PermissionBit.SCOPE_ADMIN);
    });

    it('maps scope read actions to PermissionBit.SCOPE_READ (2)', () => {
      assert.strictEqual(mapActionToPermissionBit('scope_read'), PermissionBit.SCOPE_READ);
      assert.strictEqual(mapActionToPermissionBit('view_scope'), PermissionBit.SCOPE_READ);
      assert.strictEqual(mapActionToPermissionBit('read'), PermissionBit.SCOPE_READ);
    });

    it('returns undefined for unrecognized actions', () => {
      assert.strictEqual(mapActionToPermissionBit('exploit:rce'), undefined);
      assert.strictEqual(mapActionToPermissionBit('unknown_action'), undefined);
      assert.strictEqual(mapActionToPermissionBit(''), undefined);
    });
  });
});
