#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ROOT = process.cwd();
const PACKAGES_DIR = path.join(ROOT, 'packages');

/**
 * Architectural Dependency Rules per package.
 * Phase 0 Invariants:
 * - MOD-INV-01: Public facade exported contracts only.
 * - MOD-INV-02: Zero circular imports; strict DAG module hierarchy.
 * - INV-09 / Stage 1: Zero external runtime dependencies for shared-kernel & error-catalog.
 * - ADR-DATA-01 / Stage 2: data-access is permitted ONLY the pg PostgreSQL driver.
 */
export const ARCHITECTURAL_RULES = {
  '@shn/shared-kernel': {
    allowedRuntimeDeps: new Set([]),
    forbiddenWorkspaceDeps: new Set([
      '@shn/error-catalog',
      '@shn/data-access',
      '@shn/telemetry',
      '@shn/event-bus',
      '@shn/auth-rbac',
      '@shn/scope-gatekeeper',
    ]),
  },
  '@shn/error-catalog': {
    allowedRuntimeDeps: new Set([]),
    forbiddenWorkspaceDeps: new Set([
      '@shn/data-access',
      '@shn/telemetry',
      '@shn/event-bus',
      '@shn/auth-rbac',
      '@shn/scope-gatekeeper',
    ]),
  },
  '@shn/telemetry': {
    allowedRuntimeDeps: new Set([]),
    allowedWorkspaceDeps: new Set(['@shn/shared-kernel', '@shn/error-catalog']),
    forbiddenWorkspaceDeps: new Set(['@shn/data-access', '@shn/event-bus', '@shn/auth-rbac', '@shn/scope-gatekeeper']),
  },
  '@shn/data-access': {
    allowedRuntimeDeps: new Set(['pg']),
    allowedWorkspaceDeps: new Set(['@shn/shared-kernel', '@shn/error-catalog']),
    forbiddenWorkspaceDeps: new Set(['@shn/telemetry', '@shn/event-bus', '@shn/auth-rbac', '@shn/scope-gatekeeper']),
  },
  '@shn/event-bus': {
    allowedRuntimeDeps: new Set([]),
    allowedWorkspaceDeps: new Set([
      '@shn/shared-kernel',
      '@shn/error-catalog',
      '@shn/telemetry',
      '@shn/data-access',
    ]),
    forbiddenWorkspaceDeps: new Set(['@shn/auth-rbac', '@shn/scope-gatekeeper']),
  },
  '@shn/auth-rbac': {
    allowedRuntimeDeps: new Set([]),
    allowedWorkspaceDeps: new Set([
      '@shn/shared-kernel',
      '@shn/error-catalog',
      '@shn/telemetry',
      '@shn/data-access',
      '@shn/event-bus',
    ]),
    forbiddenWorkspaceDeps: new Set(['@shn/scope-gatekeeper']),
  },
  '@shn/scope-gatekeeper': {
    allowedRuntimeDeps: new Set([]),
    allowedWorkspaceDeps: new Set([
      '@shn/shared-kernel',
      '@shn/error-catalog',
      '@shn/telemetry',
      '@shn/data-access',
      '@shn/event-bus',
      '@shn/auth-rbac',
    ]),
    forbiddenWorkspaceDeps: new Set([]),
  },
};

export function auditDependencies(packagesDir = PACKAGES_DIR) {
  const violations = [];

  const packages = fs.readdirSync(packagesDir, { withFileTypes: true })
    .filter(dirent => dirent.isDirectory())
    .map(dirent => dirent.name);

  for (const pkg of packages) {
    const pkgJsonPath = path.join(packagesDir, pkg, 'package.json');
    if (!fs.existsSync(pkgJsonPath)) continue;

    const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    const pkgName = pkgJson.name;
    const rules = ARCHITECTURAL_RULES[pkgName];

    if (!rules) {
      violations.push(`Unrecognized package "${pkgName}" without architectural rules definition.`);
      continue;
    }

    const runtimeDeps = Object.keys(pkgJson.dependencies || {});
    for (const dep of runtimeDeps) {
      if (!rules.allowedRuntimeDeps.has(dep)) {
        violations.push(
          `Package "${pkgName}" declares unauthorized runtime dependency: "${dep}". Allowed: [${Array.from(rules.allowedRuntimeDeps).join(', ')}]`
        );
      }
    }

    // Circular / self-dependency check
    if (pkgJson.dependencies && pkgJson.dependencies[pkgName]) {
      violations.push(`Package "${pkgName}" declares a circular self-dependency.`);
    }

    // Workspace DAG hierarchy checks
    const allDeclaredDeps = {
      ...(pkgJson.dependencies || {}),
      ...(pkgJson.devDependencies || {}),
      ...(pkgJson.peerDependencies || {}),
    };

    for (const forbidden of rules.forbiddenWorkspaceDeps) {
      if (allDeclaredDeps[forbidden]) {
        violations.push(
          `Package "${pkgName}" violates module DAG hierarchy by depending on downstream package "${forbidden}".`
        );
      }
    }
  }

  return violations;
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename ?? '')) {
  console.log('[*] Auditing package dependencies and architectural boundaries...');
  const violations = auditDependencies();

  if (violations.length > 0) {
    for (const v of violations) {
      console.error(`[!] VIOLATION: ${v}`);
    }
    console.error(`\n[FAILED] Found ${violations.length} architectural dependency violation(s).`);
    process.exit(1);
  } else {
    console.log('\n[PASSED] All package boundaries adhere to Phase 0 architectural invariants.');
    process.exit(0);
  }
}
