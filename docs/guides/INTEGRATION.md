# VERITAS Integration Guide

**Protocol:** Verifiable AI Agent Identity Protocol  
**Canister (playground):** `ofoea-eyaaa-aaaab-qab6a-cai`  
**Website:** https://ofoea-eyaaa-aaaab-qab6a-cai.raw.icp0.io/  
**Admin Dashboard:** https://ofoea-eyaaa-aaaab-qab6a-cai.raw.icp0.io/admin  
**MCP Endpoint:** https://ofoea-eyaaa-aaaab-qab6a-cai.raw.icp0.io/mcp/jsonrpc  

---

## Table of Contents

1. [For AI Agents — Register & Verify Your Identity](#for-ai-agents)
2. [For Platforms — Verify Agents & Query Credit Scores](#for-platforms)
3. [For Credit Scoring — Assess Agent Reputation](#for-credit-scoring)
4. [For Verifiers — Validate Credentials](#for-verifiers)
5. [Quick Reference](#quick-reference)

---

## For AI Agents

### 5-minute setup

```bash
npm install veritas-agent
```

```typescript
import { Agent } from 'veritas-agent';

// Create your agent identity
const agent = new Agent({
  network: 'playground',
  canisterId: 'ofoea-eyaaa-aaaab-qab6a-cai',
});

// Generate keys and register
agent.generateKeys('your-principal-here');
const identity = agent.getIdentity();
console.log('My DID:', identity.did);
```

### Proof-of-Possession Handshake

Prove you control your private key to another agent:

```typescript
// Alice creates handshake proof
const proof = alice.createHandshakeProof();

// Bob verifies Alice
const isValid = verifyHandshakeProof(proof);
// true if Alice proves she controls her key
```

### Plugin for AI Frameworks

```typescript
import { createPlugin } from 'veritas-agent';

const veritas = createPlugin();
const identity = veritas.methods.generateIdentity('my-principal');
```

---

## For Platforms

### 10-minute integration

```bash
npm install veritas-verify
```

### Verify an agent's credential

```typescript
import { setIssuerKey, verifyCredential, parseCredential } from 'veritas-verify';

// Get the issuer key from the canister's DID document
const issuerKey = await fetchIssuerKey('ofoea-eyaaa-aaaab-qab6a-cai');
setIssuerKey(issuerKey);

// Verify a credential JSON string
const result = verifyCredential(credentialJson);
if (result.valid) {
  const credential = parseCredential(credentialJson);
  console.log('Agent:', credential.credentialSubject.id);
  console.log('Reputation:', credential.credentialSubject.reputation);
}
```

### Check credit score

```typescript
import { checkRevocationStatus } from 'veritas-verify';

// Free tier — query call
const status = await checkRevocationStatus(
  'ofoea-eyaaa-aaaab-qab6a-cai',
  'credential-id-here'
);
```

### Register as a reputation source

```bash
# Admin action — register your platform
dfx canister --network playground call veritas_backend registerSource \
  '("your-platform-id", "Your Platform Name", "https://your-platform.com/api")'

# Admin approves the source
dfx canister --network playground call veritas_backend approveSource \
  '("your-platform-id")'
```

### Push reputation data

```bash
dfx canister --network playground call veritas_backend pushReputation \
  '(principal "agent-principal", "your-platform-id", vec {
    record { property="completed_jobs"; value="42"; source="your-platform"; confidence=0.95; verifiedAt=0 }
  })'
```

---

## For Credit Scoring

### Understand the score

The credit score (0-850) is computed from on-chain data using 6 factors:

| Factor | Weight | Max Points | Data Source |
|--------|--------|-----------|-------------|
| Experience | 100 | min(jobs/100, 1.0) | Credential count |
| Performance | 50 | avg_confidence / 1.0 | Claim confidence |
| Diversity | 50 | min(sources/5, 1.0) | Unique claim sources |
| Longevity | 50 | min(years/3, 1.0) | Earliest credential age |
| Penalties | -100 | min(revoked/5, 1.0) | Revoked credentials |
| PoP Rate | -50 | (1 - active/total) | Credential reliability |

### Tier pricing

| Tier | Daily Queries | Cost | Best For |
|------|:------------:|:----:|----------|
| Free | 100 | Free | Testing, light use |
| Starter | 10,000 | 100M cycles/call | Small platforms |
| Pro | 100,000 | 50M cycles/call | Growing platforms |
| Enterprise | Unlimited | 10M cycles/call | High-volume verifiers |

### Query a score

```bash
# Free tier query (costs nothing)
dfx canister --network playground call veritas_backend getCreditScore \
  '(principal "agent-principal")'
```

---

## For Verifiers

### Validate a credential

```bash
# Check credential status on-chain
dfx canister --network playground call veritas_backend checkCredentialStatus \
  '("credential-id")'
```

### Verify issuer signature

```typescript
import { verifySignature } from 'veritas-verify';

const isValid = verifySignature(
  issuerPublicKeyHex,
  messageString,
  signatureHex
);
```

### Batch verification

```typescript
import { verifyBatch } from 'veritas-verify';

const result = verifyBatch([
  { credentialJson: cred1 },
  { credentialJson: cred2 },
  { credentialJson: cred3 },
]);

console.log(`${result.validCount}/${result.totalCount} valid`);
```

---

## Quick Reference

### Endpoints
| Resource | URL |
|----------|-----|
| Admin Dashboard | `/admin` |
| DID Document | `/.well-known/did.json` |
| MCP Tool Listing | `/mcp/jsonrpc` (GET) |
| MCP Tool Call | `/mcp/jsonrpc` (POST) |
| Health Check | `/health` |
| Candid UI | Raw canister URL |

### Key canister methods
| Method | Type | Description |
|--------|------|-------------|
| `register(publicKey)` | update | Register agent identity |
| `resolve(agentId)` | query | Look up agent |
| `issueCredential(...)` | update | Mint a credential |
| `getCreditScore(agentId)` | query | Free credit score query |
| `checkCredentialStatus(id)` | query | Verify credential status |
| `getActiveSources()` | query | List trusted sources |

### Playground URL
**Raw:** https://ofoea-eyaaa-aaaab-qab6a-cai.raw.icp0.io/  
**Certified:** https://ofoea-eyaaa-aaaab-qab6a-cai.icp0.io/  
**Candid:** https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=ofoea-eyaaa-aaaab-qab6a-cai
