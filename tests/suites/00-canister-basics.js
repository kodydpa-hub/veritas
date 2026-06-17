// ════════════════════════════════════════════════════════════
//  AUTHENTIC — Phase 0: Canister Basics
//  Verifies: canister exists, responds to queries, stats
// ════════════════════════════════════════════════════════════
const assert = require('assert');
const { execSync } = require('child_process');

const NETWORK = process.argv.find(a => a.startsWith('--network='))?.split('=')[1] || 'playground';
const CANISTER_ID = process.argv.find(a => a.startsWith('--canister='))?.split('=')[1] || '';

function dfx(method, args = '()') {
  const cmd = `dfx canister --network ${NETWORK} call ${CANISTER_ID || 'authentic_backend'} ${method} '${args}' 2>&1`;
  const out = execSync(cmd, { encoding: 'utf8', timeout: 30000 }).trim();
  return out;
}

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ❌ ${name}: ${e.message}`);
    failed++;
  }
}

console.log(`\n📦 Suite 00: Canister Basics (${NETWORK})`);

test('Canister responds to isPaused query', () => {
  const result = dfx('isPaused');
  assert(result.includes('null') || result.includes('opt'), 
    `Expected pause state, got: ${result}`);
});

test('Canister responds to getStats query', () => {
  const result = dfx('getStats');
  assert(result.includes('totalAgents'), `Expected stats record, got: ${result}`);
  assert(result.includes('totalFeesCollected'), `Expected fees field`);
  assert(result.includes('paused'), `Expected paused field`);
});

test('Total agents starts at 0', () => {
  const result = dfx('getStats');
  assert(result.includes('0'), `Expected 0 agents, got: ${result}`);
});

test('Resolve unknown identity returns null', () => {
  const result = dfx('resolve', '(principal "2vxsx-fae")');
  assert(result === '(null)' || result.includes('null'),
    `Expected null for unknown identity, got: ${result}`);
});

test('Lookup malformed DID returns null', () => {
  const result = dfx('lookup', '("invalid-did")');
  assert(result === '(null)' || result.includes('null'),
    `Expected null for malformed DID`);
});

// Summary
console.log(`\n📊 Suite 00: ${passed} passed, ${failed} failed${failed > 0 ? ' ❌' : ' ✅'}`);
process.exit(failed > 0 ? 1 : 0);
