// ════════════════════════════════════════════════════════════
//  veritas-agent — Tests
// ════════════════════════════════════════════════════════════

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { Agent, verifyHandshakeProof, createPlugin } from './index';

const TEST_PRINCIPAL = '2vxsx-fae';

describe('veritas-agent', () => {
  describe('Agent Creation', () => {
    it('creates an agent with default config', () => {
      const agent = new Agent();
      assert.ok(agent instanceof Agent);
      assert.strictEqual(agent.hasIdentity(), false);
    });

    it('creates an agent without identity initially', () => {
      const agent = new Agent();
      assert.strictEqual(agent.getIdentity(), null);
    });
  });

  describe('Key Generation', () => {
    it('generates keys for an agent', () => {
      const agent = new Agent();
      const identity = agent.generateKeys(TEST_PRINCIPAL);
      assert.ok(identity.privateKey.length > 0, 'Should have private key');
      assert.ok(identity.publicKey.length > 0, 'Should have public key');
      assert.strictEqual(identity.principal, TEST_PRINCIPAL);
      assert.strictEqual(identity.did, `did:icp:${TEST_PRINCIPAL}`);
    });

    it('persists identity in agent', () => {
      const agent = new Agent();
      agent.generateKeys(TEST_PRINCIPAL);
      assert.strictEqual(agent.hasIdentity(), true);
      const identity = agent.getIdentity();
      assert.strictEqual(identity!.principal, TEST_PRINCIPAL);
    });

    it('exportIdentity strips private key', () => {
      const agent = new Agent();
      agent.generateKeys(TEST_PRINCIPAL);
      const exported = agent.exportIdentity();
      assert.ok(exported !== null);
      assert.strictEqual(exported!.principal, TEST_PRINCIPAL);
      assert.ok(exported!.publicKey.length > 0);
      assert.strictEqual((exported as any).privateKey, undefined, 'Should not contain private key');
    });
  });

  describe('Proof-of-Possession (Agent SDK)', () => {
    it('creates a PoP challenge for the agent', () => {
      const agent = new Agent();
      agent.generateKeys(TEST_PRINCIPAL);
      const challenge = agent.createPoPChallenge();
      assert.ok(challenge.nonce.length > 0);
      assert.ok(challenge.message.includes(TEST_PRINCIPAL));
    });

    it('responds to a PoP challenge', () => {
      const agent = new Agent();
      agent.generateKeys(TEST_PRINCIPAL);
      const challenge = agent.createPoPChallenge();
      const response = agent.respondToPoPChallenge(challenge);
      assert.strictEqual(response.nonce, challenge.nonce);
      assert.ok(response.signature.length > 0);
    });

    it('full handshake cycle works', () => {
      const alice = new Agent();
      alice.generateKeys('aaa-aaa-aaa');
      const bob = new Agent();
      bob.generateKeys('bbb-bbb-bbb');

      // Alice creates handshake proof
      const proof = alice.createHandshakeProof();

      // Bob verifies Alice
      const isValid = bob.verifyPoPResponse(proof.challenge, proof.response);
      assert.strictEqual(isValid, true, 'Bob should verify Alice');
    });
  });

  describe('Static Handshake Verifier', () => {
    it('verifies a handshake proof without Agent instance', () => {
      const agent = new Agent();
      agent.generateKeys(TEST_PRINCIPAL);
      const proof = agent.createHandshakeProof();
      const isValid = verifyHandshakeProof(proof);
      assert.strictEqual(isValid, true);
    });
  });

  describe('Plugin Interface', () => {
    it('creates a plugin with all methods', () => {
      const plugin = createPlugin();
      assert.strictEqual(plugin.name, 'veritas');
      assert.strictEqual(plugin.version, '0.1.0');
      assert.ok(typeof plugin.methods.generateIdentity === 'function');
      assert.ok(typeof plugin.methods.checkCredential === 'function');
      assert.ok(typeof plugin.methods.handshake === 'function');
      assert.ok(typeof plugin.methods.verifyHandshake === 'function');
    });

    it('plugin can generate identity', () => {
      const plugin = createPlugin();
      const identity = plugin.methods.generateIdentity(TEST_PRINCIPAL);
      assert.strictEqual(identity.principal, TEST_PRINCIPAL);
    });

    it('plugin handshake works', () => {
      const plugin = createPlugin();
      plugin.methods.generateIdentity(TEST_PRINCIPAL);
      const proof = plugin.methods.handshake();
      assert.ok(proof.challenge.nonce.length > 0);
      assert.strictEqual(proof.challenge.message.includes(TEST_PRINCIPAL), true);
      assert.ok(proof.response.signature.length > 0);
    });
  });
});
