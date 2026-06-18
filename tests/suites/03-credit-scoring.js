// ════════════════════════════════════════════════════════════
//  VERITAS — Phase 3: Credit Scoring + API Tiers
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

console.log(`\n📦 Suite 03: Credit Scoring + API Tiers`);

// ── Scoring Config Tests ──
test('getScoringConfig returns non-empty result', () => {
  const result = dfx('getScoringConfig');
  assert.ok(result.length > 10, 'Should return data');
  assert.ok(result.includes('base_score'), 'Should include base_score');
});

test('getScoringConfig has 6 factors', () => {
  const result = dfx('getScoringConfig');
  const count = (result.match(/record/g) || []).length;
  assert.ok(count >= 6, `Should have at least 6 records, got ${count}`);
});

// ── Tier Config Tests ──
test('getTierConfig returns non-empty result', () => {
  const result = dfx('getTierConfig');
  assert.ok(result.length > 10, 'Should return data');
  assert.ok(result.includes('Free'), 'Should include Free tier');
});

test('getTierConfig has 4 tier records', () => {
  const result = dfx('getTierConfig');
  const records = (result.match(/record/g) || []).length;
  assert.strictEqual(records, 4, `Should have 4 tier records, got ${records}`);
});

test('Starter tier has daily limit', () => {
  const result = dfx('getTierConfig');
  assert.ok(result.includes('10_000'), 'Starter should have 10K daily limit');
});

// ── Credit Score Tests ──
test('getCreditScore returns null for unknown agent', () => {
  const result = dfx('getCreditScore', '(principal "2vxsx-fae")');
  assert.strictEqual(result.trim(), '(null)', 'Unknown agent should return null');
});

// Summary
console.log(`\n📊 Suite 03: ${passed} passed, ${failed} failed${failed > 0 ? ' ❌' : ' ✅'}`);
process.exit(failed > 0 ? 1 : 0);
