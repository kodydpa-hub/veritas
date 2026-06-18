#!/usr/bin/env node
/**
 * VERITAS Demo: Agent-to-Agent Handshake
 * 
 * Two AI agents verify each other's identity using proof-of-possession.
 * 
 * Prerequisites: npm install veritas-agent veritas-verify
 * 
 * Usage: node agent-handshake-demo.js
 */

const { Agent, verifyHandshakeProof } = require('veritas-agent');

console.log('══════════════════════════════════════════════');
console.log('  VERITAS — Agent-to-Agent Handshake Demo');
console.log('══════════════════════════════════════════════');
console.log('');

// Create two agents
const alice = new Agent();
const bob = new Agent();

alice.generateKeys('aaa-aaa-aaa');
bob.generateKeys('bbb-bbb-bbb');

console.log(`🤖 Alice: ${alice.getIdentity().did}`);
console.log(`🤖 Bob:   ${bob.getIdentity().did}`);
console.log('');

// Alice initiates the handshake
console.log('📤 Alice creates handshake proof...');
const proof = alice.createHandshakeProof();
console.log(`   Challenge: ${proof.challenge.nonce.substring(0, 16)}...`);
console.log(`   Signature: ${proof.response.signature.substring(0, 16)}...`);
console.log('');

// Bob verifies Alice
console.log('📥 Bob verifies Alice...');
const isValid = verifyHandshakeProof(proof);
console.log(`   Result: ${isValid ? '✅ VALID' : '❌ INVALID'}`);
console.log('');

// Bob can now trust Alice's identity
if (isValid) {
  console.log('✅ Alice proved she controls her private key.');
  console.log('✅ Bob can now trust credentials issued by Alice.');
  console.log('✅ Peer-to-peer trust established without central authority.');
}

console.log('');
console.log('══════════════════════════════════════════════');
console.log('  How it works:');
console.log('  1. Alice generates a PoP challenge for herself');
console.log('  2. Alice signs the challenge with her private key');
console.log('  3. Alice sends (challenge, signature, publicKey) to Bob');
console.log('  4. Bob verifies the signature against Alice\'s public key');
console.log('  5. If valid, Alice controls her private key → trust established');
console.log('══════════════════════════════════════════════');
