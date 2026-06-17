const assert = require('assert');
const { execSync } = require('child_process');
const NETWORK = process.argv.find(a => a.startsWith('--network='))?.split('=')[1] || 'playground';
const CID = process.argv.find(a => a.startsWith('--canister='))?.split('=')[1] || 'veritas_backend';
function dfx(method, args) {
  return execSync(`dfx canister --network ${NETWORK} call ${CID} ${method} '${args || "()"}'`, { encoding: 'utf8', timeout: 30000 }).trim();
}
let passed = 0, failed = 0;
function test(name, fn) { try { fn(); console.log(`  ✅ ${name}`); passed++; } catch (e) { console.log(`  ❌ ${name}: ${e.message}`); failed++; } }

console.log(`\n📦 Suite 01: Credential Minting (${NETWORK})`);

test('Stats includes credential counter', () => {
  const r = dfx('getStats');
  assert(r.includes('totalCredentials'));
});
test('Credential not found returns null', () => {
  const r = dfx('getCredential', '("nonexistent")');
  assert(r.includes('null'));
});
test('Revocation check on unknown credential', () => {
  const r = dfx('isRevoked', '("nonexistent")');
  assert(r.includes('false'));
});

console.log(`\n📊 Suite 01: ${passed} passed, ${failed} failed ${failed > 0 ? '❌' : '✅'}`);
process.exit(failed > 0 ? 1 : 0);
