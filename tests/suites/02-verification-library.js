// ════════════════════════════════════════════════════════════
//  VERITAS — Phase 2: Verification Library + Agent SDK
//  Tests the veritas-verify and veritas-agent npm packages
// ════════════════════════════════════════════════════════════
const assert = require('assert');
const { execSync } = require('child_process');

let passed = 0, failed = 0;
function test(name, fn) { try { fn(); console.log(`  ✅ ${name}`); passed++; } catch (e) { console.log(`  ❌ ${name}: ${e.message}`); failed++; } }

console.log(`\n📦 Suite 02: Verification Library + Agent SDK`);

// Test veritas-verify package
test('veritas-verify can be required', () => {
  const pkg = require('/home/chris/.openclaw/workspace/veritas/packages/veritas-verify');
  assert.ok(typeof pkg.generateKeypair === 'function');
  assert.ok(typeof pkg.verifyCredential === 'function');
  assert.ok(typeof pkg.generatePoPChallenge === 'function');
  assert.ok(typeof pkg.verifyPoPResponse === 'function');
  assert.ok(typeof pkg.verifyBatch === 'function');
});

test('veritas-verify key generation works', () => {
  const { generateKeypair } = require('/home/chris/.openclaw/workspace/veritas/packages/veritas-verify');
  const kp = generateKeypair();
  assert.ok(kp.privateKey.length === 64, `Expected 64 hex chars, got ${kp.privateKey.length}`);
  assert.ok(kp.publicKey.length > 0);
});

test('veritas-verify PoP cycle works', () => {
  const { generateKeypair, generatePoPChallenge, respondToPoPChallenge, verifyPoPResponse } = 
    require('/home/chris/.openclaw/workspace/veritas/packages/veritas-verify');
  const kp = generateKeypair();
  const challenge = generatePoPChallenge('2vxsx-fae');
  const response = respondToPoPChallenge(kp.privateKey, challenge);
  assert.strictEqual(verifyPoPResponse(challenge, response), true);
});

test('veritas-verify batch verification works', () => {
  const { verifyBatch } = require('/home/chris/.openclaw/workspace/veritas/packages/veritas-verify');
  const result = verifyBatch([{ credentialJson: '{}' }, { credentialJson: '{}' }]);
  assert.strictEqual(result.totalCount, 2);
  assert.strictEqual(result.validCount, 0);
});

// Test veritas-agent package
test('veritas-agent can be required', () => {
  const pkg = require('/home/chris/.openclaw/workspace/veritas/packages/veritas-agent');
  assert.ok(typeof pkg.Agent === 'function');
  assert.ok(typeof pkg.verifyHandshakeProof === 'function');
  assert.ok(typeof pkg.createPlugin === 'function');
});

test('veritas-agent creates identity and handshake', () => {
  const { Agent } = require('/home/chris/.openclaw/workspace/veritas/packages/veritas-agent');
  const agent = new Agent();
  agent.generateKeys('test-principal-123');
  const proof = agent.createHandshakeProof();
  assert.ok(proof.challenge.nonce.length > 0);
  assert.ok(proof.response.signature.length > 0);
  assert.strictEqual(proof.identity.principal, 'test-principal-123');
});

test('veritas-agent plugin interface works', () => {
  const { createPlugin } = require('/home/chris/.openclaw/workspace/veritas/packages/veritas-agent');
  const plugin = createPlugin();
  assert.strictEqual(plugin.name, 'veritas');
  const identity = plugin.methods.generateIdentity('plugin-test');
  assert.strictEqual(identity.principal, 'plugin-test');
});

// Summary
console.log(`\n📊 Suite 02: ${passed} passed, ${failed} failed${failed > 0 ? ' ❌' : ' ✅'}`);
process.exit(failed > 0 ? 1 : 0);
