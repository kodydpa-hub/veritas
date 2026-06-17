// ════════════════════════════════════════════════════════════
//  veritas-verify — Tests
// ════════════════════════════════════════════════════════════

import { describe, it, before } from 'node:test';
import assert from 'node:assert/strict';
import {
  generateKeypair,
  derivePublicKey,
  sign,
  verifySignature,
  generatePoPChallenge,
  respondToPoPChallenge,
  verifyPoPResponse,
  parseCredential,
  isExpired,
  isNotYetValid,
  verifyCredential,
  verifyCredentialFull,
  verifyBatch,
  setIssuerKey,
  getIssuerKey,
} from './index';

const TEST_PRINCIPAL = '2vxsx-fae';

describe('veritas-verify', () => {
  describe('Key Management', () => {
    it('generates a valid keypair', () => {
      const kp = generateKeypair();
      assert.ok(kp.privateKey.length > 0, 'Should have private key');
      assert.ok(kp.publicKey.length > 0, 'Should have public key');
      assert.strictEqual(kp.privateKey.length, 64, 'Private key should be 32 bytes = 64 hex chars');
    });

    it('derives matching public key from private', () => {
      const kp = generateKeypair();
      const derived = derivePublicKey(kp.privateKey);
      assert.strictEqual(derived, kp.publicKey, 'Derived public key should match original');
    });

    it('signs and verifies a message', () => {
      const kp = generateKeypair();
      const message = 'hello-world';
      const signature = sign(kp.privateKey, message);
      assert.ok(signature.length > 0, 'Should produce a signature');
      assert.ok(verifySignature(kp.publicKey, message, signature), 'Should verify correctly');
    });

    it('rejects wrong signature', () => {
      const kp1 = generateKeypair();
      const kp2 = generateKeypair();
      const message = 'test-message';
      const signature = sign(kp1.privateKey, message);
      assert.strictEqual(
        verifySignature(kp2.publicKey, message, signature),
        false,
        'Should reject signature from wrong key'
      );
    });
  });

  describe('Proof-of-Possession', () => {
    it('generates a valid PoP challenge', () => {
      const challenge = generatePoPChallenge(TEST_PRINCIPAL);
      assert.ok(challenge.nonce.length > 0, 'Should have nonce');
      assert.ok(challenge.message.includes(TEST_PRINCIPAL), 'Should contain principal');
      assert.ok(challenge.issuedAt > 0, 'Should have timestamp');
    });

    it('responds to a PoP challenge', () => {
      const kp = generateKeypair();
      const challenge = generatePoPChallenge(TEST_PRINCIPAL);

      // Manually set up identity for test
      const publicKey = kp.publicKey;
      const response = respondToPoPChallenge(kp.privateKey, challenge);

      assert.strictEqual(response.nonce, challenge.nonce, 'Nonce should match');
      assert.strictEqual(response.signer, publicKey, 'Signer should match public key');
      assert.ok(response.signature.length > 0, 'Should have signature');
    });

    it('verifies a valid PoP response', () => {
      const kp = generateKeypair();
      const challenge = generatePoPChallenge(TEST_PRINCIPAL);
      const response = respondToPoPChallenge(kp.privateKey, challenge);
      assert.ok(verifyPoPResponse(challenge, response), 'Should verify valid response');
    });

    it('rejects PoP response with wrong nonce', () => {
      const kp = generateKeypair();
      const challenge = generatePoPChallenge(TEST_PRINCIPAL);
      const response = respondToPoPChallenge(kp.privateKey, challenge);
      const tampered = { ...response, nonce: 'tampered-nonce' };
      assert.strictEqual(
        verifyPoPResponse(challenge, tampered),
        false,
        'Should reject tampered nonce'
      );
    });
  });

  describe('Credential Parsing', () => {
    const validVcJson = JSON.stringify({
      '@context': ['https://www.w3.org/ns/credentials/v2', 'https://veritas.icp/reputation/v1'],
      id: 'vrt-test-001',
      type: ['VerifiableCredential', 'AgentReputationCredential'],
      issuer: 'did:key:test-issuer',
      validFrom: '2026-06-17T00:00:00Z',
      validUntil: '2027-06-17T00:00:00Z',
      credentialSubject: {
        id: 'did:icp:2vxsx-fae',
        controllerKey: '0xabc123',
        reputation: [
          { metric: 'completed_jobs', value: '42', source: 'dpaPay', confidence: 0.95 }
        ],
      },
    });

    it('parses a valid VC', () => {
      const parsed = parseCredential(validVcJson);
      assert.ok(parsed !== null, 'Should parse valid VC');
      assert.strictEqual(parsed!.type.includes('VerifiableCredential'), true);
    });

    it('rejects malformed JSON', () => {
      const parsed = parseCredential('not-json');
      assert.strictEqual(parsed, null);
    });

    it('rejects incomplete VC', () => {
      const parsed = parseCredential(JSON.stringify({ foo: 'bar' }));
      assert.strictEqual(parsed, null);
    });
  });

  describe('Expiry Checking', () => {
    const futureVc = JSON.stringify({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'vrt-future',
      type: ['VerifiableCredential'],
      issuer: 'did:key:test',
      validFrom: '2026-06-17T00:00:00Z',
      validUntil: new Date(Date.now() + 86400000).toISOString().replace(/\.\d+Z$/, 'Z'),
      credentialSubject: { id: 'did:icp:test', controllerKey: '0x', reputation: [] },
    });

    const expiredVc = JSON.stringify({
      '@context': ['https://www.w3.org/ns/credentials/v2'],
      id: 'vrt-expired',
      type: ['VerifiableCredential'],
      issuer: 'did:key:test',
      validFrom: '2020-01-01T00:00:00Z',
      validUntil: '2020-06-01T00:00:00Z',
      credentialSubject: { id: 'did:icp:test', controllerKey: '0x', reputation: [] },
    });

    it('detects not-yet-valid credential', () => {
      const future = parseCredential(futureVc)!;
      assert.strictEqual(isExpired(future), false, 'Future VC should not be expired');
    });

    it('detects expired credential', () => {
      const expired = parseCredential(expiredVc)!;
      assert.strictEqual(isExpired(expired), true, 'Expired VC should be expired');
    });
  });

  describe('Credential Verification', () => {
    before(() => {
      setIssuerKey('03test');
    });

    it('fails verification without issuer key', () => {
      setIssuerKey(''); // clear key
      const result = verifyCredential('{}');
      assert.strictEqual(result.valid, false);
      assert.ok(result.reason?.includes('Malformed'));
      setIssuerKey('03test'); // restore
    });

    it('verification fails for expired credential', () => {
      const expiredVc = JSON.stringify({
        '@context': ['https://www.w3.org/ns/credentials/v2'],
        id: 'vrt-expired',
        type: ['VerifiableCredential'],
        issuer: 'did:key:test',
        validFrom: '2020-01-01T00:00:00Z',
        validUntil: '2020-06-01T00:00:00Z',
        credentialSubject: { id: 'did:icp:test', controllerKey: '0x', reputation: [] },
      });
      const result = verifyCredential(expiredVc);
      assert.strictEqual(result.valid, false);
      assert.ok(result.reason?.includes('expired'));
    });
  });

  describe('Batch Verification', () => {
    it('handles empty batch', () => {
      const result = verifyBatch([]);
      assert.strictEqual(result.allValid, true);
      assert.strictEqual(result.totalCount, 0);
    });

    it('processes multiple items', () => {
      const items = [
        { credentialJson: '{}' },
        { credentialJson: '{}' },
      ];
      const result = verifyBatch(items);
      assert.strictEqual(result.totalCount, 2);
      assert.strictEqual(result.validCount, 0);
    });
  });
});

describe('Issuer Key Configuration', () => {
  it('setIssuerKey and getIssuerKey roundtrip', () => {
    setIssuerKey('03abc123');
    assert.strictEqual(getIssuerKey(), '03abc123');
    setIssuerKey(null as any);
    assert.strictEqual(getIssuerKey(), null as any);
  });
});
