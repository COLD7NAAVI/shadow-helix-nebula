#!/usr/bin/env node
/**
 * Shadow : Helix Nebula (SHN) — Sovereign CLI Executable
 */

import process from 'node:process';
import { CliRunner } from '../dist/cli/cli-runner.js';

async function main() {
  const runner = new CliRunner();
  const result = await runner.run({
    argv: process.argv.slice(2),
    env: process.env as Record<string, string | undefined>,
  });

  if (result.output) {
    console.log(result.output);
  }
  if (result.error) {
    console.error(`[-] Error: ${result.error}`);
  }

  process.exit(result.exitCode);
}

main().catch((err) => {
  console.error(`[-] Fatal Error: ${err?.message || err}`);
  process.exit(1);
});
