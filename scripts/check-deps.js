#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ROOT = process.cwd();
const PACKAGES_DIR = path.join(ROOT, 'packages');

let errors = 0;

console.log('[*] Auditing package dependencies and architectural boundaries...');

const packages = fs.readdirSync(PACKAGES_DIR, { withFileTypes: true })
  .filter(dirent => dirent.isDirectory())
  .map(dirent => dirent.name);

for (const pkg of packages) {
  const pkgJsonPath = path.join(PACKAGES_DIR, pkg, 'package.json');
  if (!fs.existsSync(pkgJsonPath)) continue;

  const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
  console.log(` -> Checking package: ${pkgJson.name}`);

  // Invariant check: Stage 1 packages must have ZERO runtime dependencies
  const runtimeDeps = Object.keys(pkgJson.dependencies || {});
  if (runtimeDeps.length > 0) {
    console.error(`[!] VIOLATION: Package ${pkgJson.name} declares runtime dependencies: ${runtimeDeps.join(', ')}`);
    errors++;
  } else {
    console.log(`    [+] Zero runtime dependencies verified.`);
  }

  // Verify internal circular dependency prohibition
  if (pkgJson.dependencies && pkgJson.dependencies[pkgJson.name]) {
    console.error(`[!] VIOLATION: Circular self-dependency in ${pkgJson.name}`);
    errors++;
  }
}

if (errors > 0) {
  console.error(`\n[FAILED] Found ${errors} architectural dependency violation(s).`);
  process.exit(1);
} else {
  console.log('\n[PASSED] All package boundaries adhere to Phase 0 architectural invariants.');
  process.exit(0);
}
