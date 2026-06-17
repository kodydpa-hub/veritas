# veritas-agent

**Agent SDK for the VERITAS identity protocol.**

Key generation, identity registration, credential minting, proof-of-possession signing,
and credential storage for AI agents on ICP.

## Install

```bash
npm install veritas-agent
```

## Quick Start

```typescript
import { Agent } from 'veritas-agent';

// Create an agent
const agent = new Agent({
  network: 'playground',
  canisterId: 'yjj7c-kaaaa-aaaab-qaceq-cai',
});

// Generate keys for this agent's identity
agent.generateKeys('your-principal-here');

// Create a proof-of-possession handshake
const proof = agent.createHandshakeProof();

// Another agent verifies the handshake
import { verifyHandshakeProof } from 'veritas-agent';
const isValid = verifyHandshakeProof(proof);
```

## API

### Agent Class

- `new Agent(config?)` — Create a new agent instance
- `generateKeys(principal)` — Generate secp256k1 keypair for the given principal
- `getIdentity()` — Get current identity (or null)
- `hasIdentity()` — Check if identity exists
- `exportIdentity()` — Export public identity (no private key)
- `saveIdentitySync()` — Persist identity to disk
- `loadIdentitySync()` — Load identity from disk

### Credential Management
- `saveCredential(credentialId, credentialJson)` — Save credential locally
- `loadCredential(credentialId)` — Load credential from local storage
- `loadAllCredentials()` — Load all stored credentials
- `verifyOwnCredential(credentialId)` — Verify own credential with on-chain check

### Proof-of-Possession
- `createPoPChallenge()` — Generate a PoP challenge
- `respondToPoPChallenge(challenge)` — Sign challenge with agent's private key
- `verifyPoPResponse(challenge, response)` — Verify another agent's PoP

### Agent-to-Agent
- `createHandshakeProof()` — Full handshake proof package
- `verifyHandshakeProof(proof)` — Static handshake verifier

### Canister Operations
- `checkCredentialStatus(credentialId)` — Check revocation/expiry on-chain
- `isRevoked(credentialId)` — Quick revocation check
- `resolveIdentity(principal)` — Look up agent on VERITAS canister
- `getStats()` — Get canister statistics

### Plugin Interface
- `createPlugin(config?)` — Create a VERITAS plugin for AI frameworks

## License

MIT
