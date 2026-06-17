# veritas-verify

**Core verification library for the VERITAS identity protocol.**

Zero-network credential verification for AI agents. Verify W3C Verifiable Credentials,
proof-of-possession challenges, and ECDSA secp256k1 signatures — all locally, sub-ms.

## Install

```bash
npm install veritas-verify
```

## Quick Start

```typescript
import { generateKeypair, setIssuerKey, verifyCredential } from 'veritas-verify';

// Configure the issuer key (compile-time constant from VERITAS canister)
setIssuerKey('03abc123...');

// Verify a credential (local, no network calls)
const result = verifyCredential(credentialJson);
console.log(result.valid); // true or false
```

## API

### Key Management
- `generateKeypair()` — Generate secp256k1 keypair
- `derivePublicKey(privateKeyHex)` — Derive public key from private
- `sign(privateKeyHex, message)` — Sign a message
- `verifySignature(publicKeyHex, message, signatureHex)` — Verify ECDSA signature

### Proof-of-Possession
- `generatePoPChallenge(agentPrincipal)` — Create a PoP challenge
- `respondToPoPChallenge(privateKeyHex, challenge)` — Sign challenge with private key
- `verifyPoPResponse(challenge, response)` — Verify PoP response

### Credential Verification
- `parseCredential(credentialJson)` — Parse W3C VC JSON-LD
- `isExpired(credential)` — Check if credential expired
- `isNotYetValid(credential)` — Check if credential is future-dated
- `verifyCredential(credentialJson)` — Basic verification (structure + expiry + key)
- `verifyCredentialFull(credentialJson, revocationStatus?)` — Full verification with on-chain status

### Batch Verification
- `verifyBatch(items)` — Verify many credentials in one call (no network)

### Canister Interface
- `checkRevocationStatus(canisterId, credentialId)` — Query revocation on-chain
- `fetchDIDDocument(canisterUrl)` — Fetch and cache DID document

### Configuration
- `setIssuerKey(hexKey)` — Set the issuer's chain-key public key
- `getIssuerKey()` — Get the current issuer key

## License

MIT
