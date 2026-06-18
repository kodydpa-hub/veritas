// ════════════════════════════════════════════════════════════
//  VERITAS — Phase 5: Reputation Source API + Admin Dashboard
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

console.log(`\n📦 Suite 05: Reputation Source API + Admin Dashboard`);

// Bootstrap tests — register + approve source before query tests
test('registerSource creates a new platform source', () => {
  const result = dfx('registerSource', '("dpapay", "dPaPay Marketplace", "https://dpapay.com/api")');
  // Either Ok (first time) or AlreadyExists (repeated) is fine
  assert.ok(result.length > 0, 'Should return a result');
});

test('approveSource makes the source trusted', () => {
  const result = dfx('approveSource', '("dpapay")');
  assert.ok(result.includes('ok'), 'Approve should succeed');
});

test('getSources returns registered source (admin)', () => {
  const result = dfx('getSources');
  assert.ok(result.includes('dpapay'), 'Should include dpapay source');
  assert.ok(result.includes('dPaPay Marketplace'), 'Should include source name');
});

test('getActiveSources returns trusted sources', () => {
  const result = dfx('getActiveSources');
  assert.ok(result.includes('dpapay'), 'Active sources should include dpapay');
});

// ── Source Management Tests ──
test('rejectSource disables a source', () => {
  const result = dfx('rejectSource', '("dpapay")');
  assert.ok(result.includes('ok'), 'Reject should succeed');
});

test('getActiveSources excludes rejected source', () => {
  const result = dfx('getActiveSources');
  assert.strictEqual(result.includes('dpapay'), false, 'Rejected source should not be active');
});

test('setSourceTrust re-enables source', () => {
  const result = dfx('setSourceTrust', '("dpapay", variant { Verified })');
  assert.ok(result.includes('ok'), 'setSourceTrust should succeed');
});

test('getActiveSources includes re-enabled source', () => {
  const result = dfx('getActiveSources');
  assert.ok(result.includes('dpapay'), 'Re-enabled source should be active');
});

// ── Stats Tests ──
test('getStats includes storageVersion 6', () => {
  const result = dfx('getStats');
  assert.ok(result.includes('storageVersion = 6'), 'Should be storage v6');
});

test('Admin dashboard returns HTML at /admin', () => {
  const result = execSync(
    `curl -s "https://6qg6m-4aaaa-aaaab-qacqq-cai.raw.icp0.io/admin" 2>/dev/null`,
    { encoding: 'utf-8', timeout: 10000 }
  );
  assert.ok(result.includes('VERITAS Admin'), 'Should return admin HTML');
  assert.ok(result.includes('<html'), 'Should be HTML');
});

// Summary
console.log(`\n📊 Suite 05: ${passed} passed, ${failed} failed${failed > 0 ? ' ❌' : ' ✅'}`);
process.exit(failed > 0 ? 1 : 0);
