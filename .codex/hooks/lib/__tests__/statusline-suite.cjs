#!/usr/bin/env node
'use strict';

/**
 * Aggregate runner for statusline test suites.
 *
 * Run:
 *   node .codex/hooks/lib/__tests__/statusline-suite.cjs
 */

const path = require('path');
const fs = require('fs');
const { spawnSync } = require('child_process');

const ROOT = path.resolve(__dirname, '../../../..');
const TEST_DIR = __dirname;

const SUITES = fs
  .readdirSync(TEST_DIR)
  .filter((name) => name.endsWith('.test.cjs'))
  .sort()
  .map((name) => path.join('.codex/hooks/lib/__tests__', name));

if (SUITES.length === 0) {
  console.log('No statusline test suites are installed in this kit export.');
  process.exit(0);
}

let failed = 0;

for (const suite of SUITES) {
  console.log('\n================================================');
  console.log(`Running: ${suite}`);
  console.log('================================================');

  const result = spawnSync('node', [suite], {
    cwd: ROOT,
    stdio: 'inherit',
    env: process.env
  });

  if (result.status !== 0) {
    failed++;
  }
}

console.log('\n================================================');
console.log('STATUSLINE SUITE SUMMARY');
console.log('================================================');
console.log(`Suites run: ${SUITES.length}`);
console.log(`Suites failed: ${failed}`);

if (failed > 0) {
  process.exit(1);
}

console.log('All statusline suites passed.');
process.exit(0);
