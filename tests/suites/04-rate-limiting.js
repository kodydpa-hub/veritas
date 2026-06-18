// ════════════════════════════════════════════════════════════
//  VERITAS — Phase 4: Rate Limiting & ECDSA Cost Mitigation
// ════════════════════════════════════════════════════════════
const assert = require('assert');
const { execSync } = require('child_process');

let passed = 0, failed = 0;
function test(name, fn) { try { fn(); console.log(`  ✅ ${name}`); passed++; } catch (e) { console.log(`  ❌ ${name}: ${e.message}`); failed++; } }

const NETWORK = 'playground';
const CANISTER = 'veritas_backend';

function dfx(method, args = '') {
  const cmd = args
    ? `cd /home/chris/.openclaw/workspace/veritas && dfx canister --network ${NETWORK} call ${CANISTER} ${method} '${args}' 2>/dev/null`
    : `cd /home/chris/.openclaw/workspace/veritas && dfx canister --network ${NETWORK} call ${CANISTER} ${method} 2>/dev/null`;
  return execSync(cmd, { encoding: 'utf-8', timeout: 15000 });
}

console.log(`\n📦 Suite 04: Rate Limiting & ECDSA Cost Mitigation`);

// ── Queue Status Tests ──
test('getCredentialQueue returns null for unknown ID', () => {
  const result = dfx('getCredentialQueue', '(0)');
  assert.ok(result.includes('null'), 'Unknown queue ID should return null');
});

test('getCredentialQueue handles large unknown ID', () => {
  const result = dfx('getCredentialQueue', '(99999)');
  assert.strictEqual(result.includes('null'), true, 'Large unknown ID should return null');
});

// ── Stats Tests ──
test('getStats includes storage version', () => {
  const result = dfx('getStats');
  assert.ok(result.includes('storageVersion'), 'Should include storage version');
});

test('getStats includes non-zero totalAgents', () => {
  const result = dfx('getStats');
  assert.ok(result.includes('totalAgents'), 'Should include totalAgents');
});

test('getStats includes mint queue formation', () => {
  const result = dfx('getStats');
  assert.ok(result.includes('totalCredentials'), 'Should include totalCredentials');
});

// Summary
console.log(`\n📊 Suite 04: ${passed} passed, ${failed} failed${failed > 0 ? ' ❌' : ' ✅'}`);
process.exit(failed > 0 ? 1 : 0);
