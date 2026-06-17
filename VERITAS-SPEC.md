# VERITAS — Verifiable AI Agent Identity & Reputation Protocol

> **Status:** Design spec v0.2  
> **Date:** 2026-06-17  
> **Chain:** Internet Computer Protocol (ICP) Mainnet  
> **Dependencies:** None — zero local infrastructure, zero platform coupling, zero dPaPay dependency  
> **Hard rule:** Everything runs on ICP. No local servers, no VPS, no downstream platform trust.  
> **ICP Spec Review:** v0.2 incorporates fixes from ICP specialist + security audit (9 gaps addressed)

---

## 1. Problem Statement

AI agents operate across multiple platforms — marketplaces, dApps, API endpoints, social platforms, service networks. Today, a trustworthy agent on one platform has **no way to prove that trustworthiness** on another. Each platform re-builds reputation from scratch. This creates:

- **No portable reputation** — agents start at zero on every new platform
- **No cross-chain identity** — an agent verified on ICP can't prove itself on Ethereum or NEAR
- **No verifiable credentials** — reputation is locked inside each platform's database
- **No agent-to-agent trust** — agents can't verify each other without a central authority

**VERITAS solves this by issuing verifiable, self-proving credentials** that any platform, on any chain, can verify without a central call-home or API key.

---

## 2. Architecture

### 2.1 High-Level Design

```
     ┌─────────────────────────────────────────────────────────────┐
     │                    VERITAS CANISTER                         │
     │                     (ICP Mainnet)                              │
     │                                                                │
     │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐        │
     │  │   Registry    │  │  Minting      │  │  Reputation   │        │
     │  │   (stable)    │  │  (update)     │  │  (query)     │        │
     │  │              │  │               │  │              │        │
     │  │  register()  │  │  issueCred() │  │  getRep()    │        │
     │  │  resolve()   │  │  revoke()     │  │  verify()    │        │
     │  │  lookup()    │  │  renew()      │  │  history()   │        │
     │  └──────┬───────┘  └───────┬───────┘  └──────┬───────┘        │
     │         │                  │                   │               │
     │         └──────────────────┴───────────────────┘               │
     │                           │                                    │
     │                    ┌──────▼──────┐                             │
     │                    │  Chain-Key   │                             │
     │                    │  ECDSA       │                             │
     │                    │  Signing      │                             │
     │                    └─────────────┘                             │
     │                                                                │
     │  ┌─────────────────────────────────────────────┐              │
     │  │         Cycle Accounting (ICRC-1)            │              │
     │  │  Deposit ICP → credit agent balance →        │              │
     │  │  deduct cycles per action → withdraw surplus │              │
     │  └─────────────────────────────────────────────┘              │
     └──────────────────────────┬────────────────────────────────────┘
                                │
           ┌────────────────────┼────────────────────┐
           │                    │                    │
           ▼                    ▼                    ▼
     ┌──────────┐       ┌──────────────┐     ┌──────────────┐
     │  Agent    │       │  Any Platform │     │  Any Verifier │
     │  (Holder) │       │  (Data Source)│     │  (App, Chain) │
     │  stores   │       │              │     │               │
     │  own VC   │       │  pushes rep  │     │  - npm pkg    │
     └──────────┘       │  via API      │     │  - one func   │
                         │  inter-canister│     │  - PoP challenge │
                         └──────────────┘     │  - 0 net calls  │
                                               └──────────────┘
```

### 2.2 Data Model

```motoko
// Stable storage — survives canister upgrades
actor Veritas {

  // ── Core Identity ──
  stable var identities : HashMap<Principal, AgentIdentity>;

  type AgentIdentity = {
    id: Principal;
    publicKey: Blob;          // agent's ECDSA public key
    created: Int;             // nanoseconds since epoch
    lastRenewed: Int;
    status: IdentityStatus;   // Active | Revoked | Suspended
  };

  type IdentityStatus = {
    #Active;
    #Revoked: Text;           // reason
    #Suspended: {
      until: Int;
      reason: Text;
    };
  };

  // ── Attestation ──
  type Attestation = {
    id: Text;                 // unique attestation ID
    agentId: Principal;
    issuedAt: Int;
    expiresAt: Int;
    schemaVersion: Nat;
    claims: [Claim];
    revocationNonce: Nat;     // incremented per-revocation — prevents replay
  };

  type Claim = {
    property: Text;
    value: Text;
    source: Text;             // platform ID
    confidence: Float;        // 0.0–1.0 (see §Security for definition)
    verifiedAt: Int;          // when the source platform verified this
  };

  // ── Reputation Record ──
  type ReputationRecord = {
    agentId: Principal;
    sources: [ReputationSource];
    lastUpdated: Int;
  };

  type ReputationSource = {
    platform: Text;
    metric: Text;
    value: Text;
    verifiedAt: Int;
    signature: ?Blob;         // optional: signed proof from source
  };

  // ── Cycle Balances (ICRC-1 integration) ──
  stable var balances : HashMap<Principal, Nat>;   // in cycles
  stable var totalDeposited : Nat;
  stable var feesCollected : Nat;

  // ── Revocation Tracking ──
  // Uses StableHashMap to survive upgrades
  stable var revokedNonces : HashMap<Text, Bool>;  // attestationId → true
  stable var revokedPlatformSources : HashMap<Text, Bool>; // platform → stale

  // ── Trusted Sources ──
  stable var trustedSources : HashMap<Principal, TrustLevel>;

  type TrustLevel = {
    #Trusted;     // can push data for any agent
    #Verified;    // can push data for own agents only
    #Untrusted;
  };
```

### 2.3 Canister API

```
// ── Identity Management ──

register : (publicKey: Blob) 
  -> async Result<AgentIdentity, Error>;
  // Creates a new VERITAS identity. Self-service, no approval needed.
  // Caller's principal becomes the agent ID.
  // publicKey is the agent's ECDSA key for proof-of-possession challenges.
  // Fee: 3B cycles deducted from caller's balance.

resolve : (agentId: Principal) 
  -> async ?AgentIdentity;
  // Returns the identity record. Query call — free.

lookup : (didString: Text) 
  -> async ?AgentIdentity;
  // Resolves a did:veritas:{id} string back to an AgentIdentity.

// ── Attestation / Credential Minting ──

issueCredential : (claims: [Claim], expiresIn: Int, popSignature: Blob, popNonce: Blob)
  -> async Result<Attestation, Error>;
  // Mints a verifiable credential signed by the canister's chain-key.
  // REQUIRES proof-of-possession: agent must sign (popNonce || agentId) with
  // their registered private key. The canister verifies the signature against
  // the stored publicKey before minting.
  // Fee: 35B cycles deducted from caller's balance.
  // This fee covers: ECDSA signing (~25B) + compute/storage (~5B) + profit margin (~5B).

revokeCredential : (attestationId: Text, reason: Text)
  -> async Result<(), Error>;
  // Revokes a credential by invalidating its revocation nonce.
  // Only callable by the agent who owns it, or by VERITAS admin.
  // Free — revocation must not have a cost barrier.

renewCredential : (attestationId: Text, popSignature: Blob, popNonce: Blob)
  -> async Result<Attestation, Error>;
  // Re-issues with fresh expiry. Requires proof-of-possession.
  // Fee: 35B cycles.

// ── Reputation ──

pushReputation : (source: ReputationSource)
  -> async Result<(), Error>;
  // Platform pushes verified reputation data about an agent.
  // Source platform identified by caller's principal.
  // Only Trusted-level sources accepted.
  // Free (sources don't pay to push).

registerSource : (platformName: Text)
  -> async Result<(), Error>;
  // Platform registers as a reputation source. Admin must approve.
  // Fee: 10B cycles (covers vetting + storage + profit margin).

getReputation : (agentId: Principal)
  -> async ?ReputationRecord;
  // Full reputation record. Query — free.

// ── Verification ──

verifyCredential : (credentialJwt: Text, popSignature: ?Blob, popNonce: ?Blob)
  -> async VerificationResult;
  // On-chain verification: parses the credential, verifies ECDSA signature,
  // optionally checks proof-of-possession, checks revocation.
  // Off-chain callers should use the `veritas-verify` npm package instead.
  // Query call — free.

isRevoked : (attestationId: Text)
  -> async Bool;
  // Revocation check. Query — free. Verifiers should call this for
  // high-value scenarios. For everyday use, trust the expiry + nonce.

isSourceStale : (platformId: Text)
  -> async Bool;
  // Check if a source platform has been revoked/compromised.
  // Query — free.

type VerificationResult = {
  valid: Bool;
  issuer: Text;
  subject: Text;
  subjectPublicKey: Blob;    // verifier uses this for PoP challenge
  claims: [Claim];
  issuedAt: Int;
  expiresAt: Int;
  revoked: Bool;
};

// ── Cycle Management & Fees ──

depositCycles : (blockIndex: Nat)
  -> async Result<Nat, Error>;
  // Agent submits proof of ICP transfer to the canister's ledger account.
  // The canister verifies the transfer against the ICP ledger (ryjl3-tyaaa...)
  // and credits the sender's balance in cycles at the current conversion rate.
  // The ICP → cycles conversion uses the ICP-ledger's built-in rate.

getBalance : (owner: Principal) 
  -> async Nat;
  // Returns the agent's cycle balance. Query — free.

withdrawBalance : (amount: Nat)
  -> async Result<(), Error>;
  // Agent withdraws unused cycle balance as ICP.
  // Inverse of deposit: cycles → ICP at current rate → transfers to caller.

// ── Agent Key Rotation ──

rotateKey : (newPublicKey: Blob)
  -> async Result<(), Error>;
  // Agent rotates their ECDSA key. The principal (stable identity) stays
  // the same. Old credentials remain valid — verifiers fetch the new key
  // via resolve(principal) for proof-of-possession challenges.
  // Fee: 3B cycles (same as registration).

// ── Long-Running Contracts ──

activateContract : (contractId: Text, counterpartyDid: Text, expiresAt: Int, signatures: [Blob])
  -> async Result<(), Error>;
  // Agent + counterparty both sign a contract attestation.
  // Extends verification for the contract's duration even
  // if the agent's credential expires mid-contract.
  // Both parties must call this with their signatures.
  // Queryable by either party to prove ongoing trust.
  // Fee: Free (prevents friction for active contracts).

getContractStatus : (contractId: Text)
  -> async ?ContractStatus;
  // Returns current status of an active contract attestation.
  // Query — free.

// ── Credential Queue (Async Mint) ──

getCredentialQueue : (queueId: Nat)
  -> async ?QueueStatus;
  // For async minting under rate limiting. Returns the queue position
  // and estimated completion time for a credential mint request.
  // Query — free.

type QueueStatus = {
  position: Nat;
  estimatedWaitSecs: Nat;
  status: QueueState;      // Queued | Processing | Complete
  result: ?Attestation;
};

// ── HTTP (MCP + DID Document) ──

public query func http_request(req: HttpRequest) -> async HttpResponse;
  // Serves:
  //   GET /mcp/jsonrpc   → MCP tool listing (returns tool definitions)
  //   POST /mcp/jsonrpc  → MCP tool execution (routes to canister methods)
  //   GET /.well-known/did.json  → W3C DID document for the canister
  //   GET /health → health check
  // Returns JSON responses with appropriate content-type headers.

// ── Admin ──

emergencyPause : (reason: Text)
  -> async ();
  // Halts: register(), issueCredential(), renewCredential(), pushReputation()
  // Allows: verifyCredential(), isRevoked(), getBalance(), withdrawBalance()
  // Verifiers can still verify existing credentials.

emergencyResume : ()
  -> async ();
  // Re-enables all paused operations.

setSourceTrust : (platformPrincipal: Principal, level: TrustLevel)
  -> async ();
  // Admin sets a platform's trust level. Only Trusted platforms can
  // call pushReputation for non-self agents.

setFees : (fees: [ActionFee])
  -> async ();
  // Admin sets fee schedule in cycles. Allows adjustment for market changes.
  // Type ActionFee = { action: Text; feeCycles: Nat };

revokePlatformSource : (platformId: Text)
  -> async ();
  // Source trust revocation. This marks the platform as stale.
  // Existing credentials from this source remain cryptographically valid
  // but carry a warning flag for verifiers.

withdrawFees : (amount: Nat)
  -> async ();
  // Admin withdraws accumulated protocol profit as ICP.

withdrawSurplus : (amount: Nat)
  -> async ();
  // Admin withdraws surplus cycles (beyond what's needed to run the canister).
```

---

## 3. Verifiable Credential Format (W3C Compliant)

```json
{
  "@context": [
    "https://www.w3.org/ns/credentials/v2",
    "https://veritas.icp/reputation/v1"
  ],
  "id": "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
  "type": ["VerifiableCredential", "AgentReputationCredential"],
  "issuer": "did:key:z5T2qKqYzuJzLqK7kLzgVnKzCbXqKcVfLz8q3qXfXd7QbK",
  "validFrom": "2026-06-17T10:00:00Z",
  "validUntil": "2026-07-17T10:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6MkhaXgBZDYx5B3k6PfG6g8RfLv8zq3qXfXd7QbKxT5E2jR",
    "controllerKey": "0x<agent-ecdsa-public-key>",
    "reputation": [
      {
        "metric": "jobs_completed",
        "value": "42",
        "source": "marketplace_x",
        "verifiedAt": "2026-06-15T00:00:00Z",
        "confidence": 1.0
      },
      {
        "metric": "avg_rating",
        "value": "4.8",
        "source": "marketplace_x",
        "verifiedAt": "2026-06-15T00:00:00Z",
        "confidence": 0.9
      }
    ]
  },
  "proof": {
    "type": "EcdsaSecp256k1Signature2019",
    "created": "2026-06-17T10:00:00Z",
    "proofPurpose": "assertionMethod",
    "verificationMethod": "did:key:z5T2qKqYzuJzLqK7kLzgVnKzCbXqKcVfLz8q3qXfXd7QbK#key-1",
    "signature": "<base64-ecdsa-signature>",
    "revocationNonce": 0,
    "nonce": "<hex-random>"
  }
}
```

**DID method: `did:key:`** — W3C registered, no resolver needed, zero infrastructure dependency.

```
VERITAS canister DID:  did:key:z5T2qKqYzuJzLqK7kLzgVnKzCbXqKcVfLz8q3qXfXd7QbK
                            (canister's chain-key, base58-encoded into multikey)

Agent DID:                did:key:z6MkhaXgBZDYx5B3k6PfG6g8RfLv8zq3qXfXd7QbKxT5E2jR
                            (agent's ECDSA public key, base58-encoded into multikey)
```

**Why `did:key:` for production (not MVP):**
- W3C registered — works in every standard wallet and library today (Spruce, Ceramic, did-io)
- Self-describing — the key IS the DID. No resolution step needed. Verifiers extract the key from the string and verify signatures directly
- Zero infrastructure — VERITAS canister could be unreachable and the DID is still resolvable because the key is embedded in the identifier itself
- Universal — the canister uses `did:key:` for its own identity, agents use `did:key:` for theirs. Same format, different key material
- No namespace management — no `did:veritas:` to register, no resolver to maintain, no ongoing compliance burden

**How the credential references DIDs:**
```json
{
  "issuer": "did:key:z5T2q...",
  "credentialSubject": {
    "id": "did:key:z6Mkh...",
    "controllerKey": "0x<agent-ecdsa-public-key-hex>"
  },
  "proof": {
    "verificationMethod": "did:key:z5T2q...#key-1"
  }
}
```

**Resolution flow (for the credential, not the DID):**
- The `did:key:` doesn't resolve — it IS the key. Verifiers extract the public key from the DID string (multibase decode) and use it directly
- The credential binds the agent's `did:key:` to their reputation data
- The proof's signature is made by the canister's `did:key:` — verifiers check it against the issuer field
- The only on-chain check is revocation status (optional, for high-value scenarios)

---

## 4. Verification Flow (Off-Chain)

### 4.1 Standard Verification (Credential Veritasity)

```
Verifier does:
  1. Parse credential JSON
  2. Extract signature payload (canonicalized JSON-LD)
  3. Fetch issuer's DID document from VERITAS canister
     (cache locally — DID document changes rarely)
  4. Recover the canister's chain-key public key from DID document
  5. Verify ECDSA signature against payload
  6. Check validFrom / validUntil dates
  7. Optional: check revocation nonce via isRevoked(attestationId)
```

### 4.2 Proof-of-Possession (Identity Proof) — REQUIRED ✅

The standard verification above proves the credential is veritas and unmodified. It does NOT prove the presenter is the agent described in the credential. **Proof-of-possession is required**, not optional.

```
Verifier flow (veritas-verify default):

  1. Generate a random 32-byte nonce
  2. Send nonce to presenter
  3. Presenter signs: ECDSA.sign(nonce || credential.subject.id)
  4. Presenter returns signature + credential
  5. verify(credential, signature, nonce) → VerificationResult

  Step inside the library:
    a) Verify ECDSA signature against credential.subject.controllerKey
       using the provided nonce
    b) If PoP fails → { valid: false, reason: "presenter does not control agent key" }
    c) If PoP passes → proceed with standard credential verification (steps 1-7 above)
```

**Why this is mandatory:**
- Without PoP, credential theft (stealing the file) enables impersonation
- With PoP, only the holder of the private key can present the credential
- The private key never leaves the agent — the verifier only sees the signature

### 4.3 The `veritas-verify` API (Reflecting PoP)

```typescript
import { verify } from 'veritas-verify';

// STANDARD USE — requires PoP
const nonce = crypto.randomBytes(32);
const signature = agent.sign(nonce);
const result = await verify(credentialString, signature, nonce);
// result = { valid: true, subject: { reputation: [...], controllerKey: "0x..." } }

// READ-ONLY USE — skip PoP (only for UI display, never for trust decisions)
const result = await verify(credentialString, { requirePop: false });
// WARNING: This does NOT verify the presenter is the agent.
// Use only for showing credential metadata in a UI.
```

**No account needed. No API key. No rate limits. No phone-home.**

The only network call is an optional revocation check (query call, free). The cryptographic verification is 100% local.

**Compile-time issuer key:** The library ships with the canister's chain-key public key as a compile-time constant. Zero network calls needed — the key is embedded in the package. Verifiers only fetch an updated key when updating the library (rare — only when the canister rotates its chain-key).

**Batch mode:** For high-frequency agents evaluating multiple counterparties:
```typescript
const verifier = new BatchVerifier();
await verifier.loadIssuerKey();  // one-time fetch, cached for session

// 1000 verifications, zero network calls after the first:
const results = credentialBatch.map(c => verifier.verifyOne(c));
```

---

## 5. Fee Model

### 5.1 Fee Schedule

Fees are denominated in **cycles**, paid in **ICP**. The canister handles the conversion transparently.

| Action | Fee (cycles) | ICP equiv.* | Covers | Profit margin |
|--------|-------------|-------------|--------|---------------|
| Register identity | 3,000,000,000 | ~0.0015 ICP | Storage + compute | ~5% |
| Issue credential | 35,000,000,000 | ~0.016 ICP | ECDSA signing (25B) + compute (5B) + profit (5B) | ~17% |
| Renew credential | 35,000,000,000 | ~0.016 ICP | Same as issue | ~17% |
| Register as source | 10,000,000,000 | ~0.0045 ICP | Vetting + storage + profit | ~33% |
| Source trust renewal (annual) | 5,000,000,000 | ~0.0023 ICP | Lighter vetting | ~20% |
| Revoke credential | Free | Free | Must not cost barrier | — |
| Verify credential | Free | Free | Drives adoption | — |
| Push reputation | Free | Free | Encourages data sources | — |

*At ~2.2T cycles per ICP. Actual amounts shown in the UI adjust with the ICP price.

**Profit margins are built into every fee.** The canister's operating cost per action is lower than the charged fee. Surplus accumulates for the admin to withdraw.

### 5.2 Fee Stability

Fees are in **cycles**, not ICP. Cycles have a fixed purchasing power (one trillion cycles = approximately one XDR of compute). This means:

- **If ICP price doubles:** The fee in ICP halves. Users pay less ICP for the same service.
- **If ICP price halves:** The fee in ICP doubles. Users pay more ICP but the canister still covers its costs in cycles.
- **Admin can adjust fees** at any time via `setFees()` to respond to market changes.

This protects both users (they don't get priced out if ICP moons) and the protocol (it doesn't go bankrupt if ICP crashes).

### 5.3 Payment Flow (ICRC-1/2 Ledger Integration)

```
DEPOSITING:
  1. Agent looks up canister's account ID from VERITAS UI: "abc123-..."
     (Not the same as the canister's Principal! Account = derive(principal, subaccount))
  2. Agent sends ICP via ICRC-1 transfer to that account
  3. Agent calls depositCycles(blockIndex)
  4. Canister fetches transaction from ICP ledger (ryjl3-tyaaa-...) via
     icrc1_get_transaction(blockIndex) — costs ~1B cycles (covered by fees)
  5. Canister verifies:
     - transaction.to == canister's account
     - transaction.from == AccountIdentifier.fromPrincipal(caller)
     - transaction.amount >= MINIMUM_DEPOSIT (0.01 ICP — prevents dust)
  6. Converts amount to cycles at current conversion rate
  7. Credits caller's balance in cycles

MINIMUM DEPOSIT: 0.01 ICP (~22B cycles). Below this, the transfer is ignored.
An agent with 0.001 ICP (3B cycles) can't afford a 35B-cycle credential.
The minimum ensures every deposit enables at least one action.

SPENDING:
  1. Agent calls any paid action (register, issueCredential, etc.)
  2. Canister deducts fee from caller's cycle balance BEFORE executing
  3. If insufficient balance → error "insufficient balance — minimum 0.01 ICP deposit"
  4. If sufficient → action executes, cycles consumed

WITHDRAWING:
  1. Agent calls withdrawBalance(amount)
  2. Canister converts cycles → ICP at current rate
  3. Canister transfers ICP to caller via ICRC-1 transfer
  4. Balance deducted

PROTOCOL PROFIT:
  1. Profit margins accumulate in the canister's surplus balance
  2. Admin calls withdrawFees(amount) → transferred as ICP to admin account
```

### 5.4 Why This Model Works

| Requirement | How it's met |
|-------------|-------------|
| Self-funding | Fees cover all costs + profit |
| Stable pricing | Fees in cycles, not volatile ICP |
| Easy for agents | UI shows ICP equivalent at current rates |
| No external dependency | Built-in ICP ledger, no bridges, no escrow |
| Admin control | Fees adjustable, admin can withdraw surplus |

---

---

## 5a. Revenue Model — Making Real Money

The transaction fees in §5 cover the canister's operating costs with a 23% margin. They are **not the business**. They are the infrastructure fee that makes the platform self-funding.

**The money is in data products, premium services, and platform lock-in.**

### Revenue Stream 1: Agent Credit Scoring ($0.10–$1.00 per lookup)

Same model as Equifax — but for AI agents.

- Any verifier calls `getCreditScore(agentId)` → returns a risk score (0-850) based on cross-platform reputation
- Score factors: jobs completed, dispute history, time in ecosystem, number of trusted sources, rating consistency
- Charged per lookup: **$0.10 for standard verifiers, $0.01 for integrated platforms**
- **Market:** Every platform that onboards agents wants a risk check. 100,000 lookups/month × $0.10 = **$10,000/month**

### Revenue Stream 2: Enterprise API Tiers ($500–$5,000/month)

| Tier | Price | What you get |
|------|-------|-------------|
| **Free** | $0 | 100 verifications/day, public docs, community support |
| **Starter** | $500/mo | 10K verifications/day, agent credit scores, CSV reports |
| **Pro** | $2,000/mo | 100K verifications/day, real-time analytics, API whitelisting |
| **Enterprise** | $5,000/mo | Unlimited, SLA guarantees, dedicated integration, on-prem deployment |

**Market:** If 3% of integrated platforms upgrade to paid tiers: 60 platforms × $2,000 avg = **$120,000/month**

### Revenue Stream 3: Agent Insurance Pool ($5–$50 per claim)

Reputation identity only has value if it's trusted. VERITAS can offer an **insurance pool**:

- Agents pay a small premium (e.g., 1% of credential value) into a pool
- If an agent is impersonated or credential is fraudulently used, the pool pays out
- VERITAS takes 20% of premiums as the operator
- **Market:** 50,000 active agents × avg $0.50/year premium = $25,000/year → **$5,000/year** at 20% cut

### Revenue Stream 4: Dispute Resolution ($5–$50 per case)

- When reputation data is contested (e.g., platform pushed a 2★ rating but agent claims 5★), VERITAS acts as arbitrator
- Arbitration: fixed fee per case
- Premium: agent pays $10, platform pays $10, VERITAS takes the pool
- **Market:** If 1% of 100,000 agents have a dispute in a year → 1,000 cases × $20 = **$20,000/year**

### Revenue Stream 5: Acquisition / Exit

A platform identity protocol with real adoption is worth multiples of revenue:

| Metric | Conservative | Realistic | Aggressive |
|--------|-------------|-----------|------------|
| Agents | 50K | 500K | 5M |
| Platforms integrated | 20 | 100 | 500 |
| Annual revenue run-rate | $150K | $1.5M | $15M |
| **Exit valuation (5x revenue)** | **$750K** | **$7.5M** | **$75M** |

Exit scenarios:
- Acquired by ICP ecosystem fund (DFINITY grants, ICP Incubator) → **$500K–$5M**
- Acquired by an identity/security company (Civic, Spruce, Ceramic) → **$2M–$20M**
- Acquired by Polkadot ecosystem (Kilt, Parity) for cross-chain identity → **$5M–$50M**
- Token launch or DAO governance → ongoing income far exceeding fees

### Combined Revenue Forecast

| Stream | Year 1 | Year 3 | Year 5 | Year 10 |
|--------|--------|--------|--------|--------|
| Transaction fees (self-funding) | $0* | $0* | $0* | $0* |
| Agent credit scoring | $0 | $12K | $120K | $600K |
| Enterprise API tiers | $0 | $36K | $120K | $600K |
| Insurance pool | $0 | $3K | $12K | $60K |
| Dispute resolution | $0 | $2K | $20K | $100K |
| Acquisition | — | — | — | $5M+ |
| **Total (excluding exit)** | **$0** | **$53K** | **$272K** | **$1.36M** |

*Transaction fees cover canister costs only. All profit comes from data products and services.

### Implementation — Revenue Streams (Phase 1)

**Note:** Insurance pool and dispute resolution are deferred to Phase 2. Credit scoring and enterprise tiers are Phase 1 — fully self-operating from the same canister.

#### Credit Scoring API (self-operating)

```motoko
// One query method on the existing canister. No extra canisters needed.

getCreditScore : (agentId: Principal) 
  -> async CreditScore;
  // Query call — free to call, charged per lookup via cycle balance deduction.
  // Returns a credit score (0-850) computed from on-chain reputation data.
  // No external dependencies. No human intervention. Fully automated.

type CreditScore = {
  score: Nat16;              // 0-850 credit score
  tier: CreditTier;          // Excellent, Good, Fair, Poor
  factors: [ScoreFactor];    // breakdown of what contributed
  confidence: Float;         // 0.0-1.0 based on data volume
  computedAt: Int;
};

type CreditTier = {
  #Excellent;  // 720+: Multiple sources, long history, no disputes
  #Good;       // 660-719: Good history across platforms
  #Fair;       // 580-659: Limited history or minor disputes
  #Poor;       // <580: Sparse data or active disputes
};

type ScoreFactor = {
  name: Text;                // e.g. "job_completion_rate"
  weight: Float;             // 0.0-1.0 how much this impacted the score
  value: Text;               // e.g. "98%"
  impact: ImpactType;        // Positive | Negative | Neutral
};
```

**Scoring algorithm (simplified):**
```
base = 500 (starting score)
+ 100 × min(jobs_completed / 100, 1.0)  // experience
+ 50  × avg_rating / 5.0                  // performance
+ 50  × min(sources / 5, 1.0)             // platform diversity
+ 50  × min(years_active / 3, 1.0)        // longevity
- 100 × min(disputes_lost / 5, 1.0)       // penalties
- 50  × (1 - proof_of_possession_rate)    // verification reliability
clamped to 0-850
```

**Charging:** Verifier's cycle balance is debited per lookup. Rate limit (free tier: 100/day) tracked in stable memory. Upgrade to paid tier by depositing ICP.

#### Enterprise API Tiers (self-operating)

```motoko
// Rate limiting + tier management on the same canister.

// Tier configuration (set by admin, adjustable)
stable var tierLimits : HashMap<Principal, TierLimit>;

// On each verification call:
func checkAndDebit(caller: Principal) : Result<(), RateLimited> {
  let today = getTodayTimestamp();
  let limit = tierLimits.get(caller, default_free_tier);
  
  if (limit.usedToday >= limit.maxDaily) {
    return #err(RateLimited { max: limit.maxDaily, resetAt: tomorrow });
  }
  
  // Deduct cycles for paid tiers (free tier costs nothing)
  if (limit.tier != #Free) {
    deductCycles(caller, limit.perCallFee);
  }
  
  limit.usedToday += 1;
  return #ok;
}
```

| Tier | Daily limit | Cycles per call | Monthly price (ICP) |
|------|-------------|-----------------|--------------------|
| Free | 100 | 0 | Free |
| Starter | 10,000 | 100M (~$0.00014) | 500 ICP |
| Pro | 100,000 | 50M (~$0.00007) | 2,000 ICP |
| Enterprise | Unlimited | 10M (~$0.00001) | 5,000 ICP |

**No subscription infrastructure needed.** The caller deposits ICP once and the canister tracks usage from the balance daily. If their balance runs out, they drop to the free tier until they top up.

#### Insurance Pool (Phase 2)

Deferred. Requires a separate canister for the pool balance + a light web dashboard for manual arbitration edge cases.

#### Dispute Resolution (Phase 2)

Deferred. Requires a separate canister for case management + a simple admin dashboard for human arbitrators.

**The fee model is the engine. Credit scoring and enterprise tiers are the profit — and they're live as soon as the canister deploys.**

---

## 5b. Agent Onboarding & Platform Integration

### The Chicken-Egg Problem

VERITAS needs agents AND verifiers. Neither joins without the other.

### Bootstrap Strategy

#### 1. Self-service registration (no approval needed)
```
npm install veritas-agent

const agent = new VeritasAgent({ privateKey });
const identity = await agent.register();
// Done. Cost: ~0.0015 ICP
```

#### 2. First credential free (waive fee for the first credential)
- Removes the financial barrier to entry
- Any subsequent credential costs 0.016 ICP
- Self-service, automated — no human involved

#### 3. dPaPay as the natural launch partner
- Every dPaPay seller can claim their VERITAS identity with one click
- Their dPaPay reputation is already on ICP — no extra verification cost
- dPaPay registers as a trusted source, pushes reputation for opt-in sellers
- Gives VERITAS a starting pool of agents with real reputation data

#### 4. Verifier-side integration (free, frictionless)
```bash
npm install veritas-verify
```
```typescript
// 5 lines
const result = await verify(credential, signature, nonce);
if (result.valid) createAgentProfile({ reputation: result.subject.reputation });
```
- No API key, no account, no rate limits, no phone-home
- Under 30 minutes to integrate

#### 5. Discovery
- `resolve(agentId)` — any app can look up an agent's identity and public key
- Agents share their `did:veritas:...` on profiles, metadata, communications
- Verifiers can challenge any agent to produce a valid credential + PoP

### The Adoption Flywheel

```
More agents register → more reputation data → more value in credentials
       ↑                                            ↓
More apps integrate → more places to use credentials → more agents register
```

---

## 6. Security Model

### 6.1 Three-Layer Identity Binding

The fundamental question: **How does VERITAS know the presenter is the agent they claim to be?**

Three layers, each independently verifiable:

```
Layer 1: Cryptographic (Self-attestation)
  Agent generates ECDSA keypair → registers publicKey
  → To mint a credential, agent MUST sign a challenge
  → The canister verifies signature against registered key
  → Result: agent controls the registered private key

Layer 2: ICP Principal (Platform-guaranteed identity)
  ICP principals cannot be spoofed
  → register() records caller's principal
  → Every action is veritasated by the caller's principal
  → Result: identity is bound to an unforgeable ICP identity

Layer 3: Platform Verification (Reputation provenance)
  When a platform pushes reputation, they specify the agent's principal
  → Platform has already verified the agent on their side
  → VERITAS trusts the platform's identification, not a self-claim
  → Result: reputation data is as trustworthy as the source platform
```

### 6.2 Proof-of-Possession Chain

```
┌─────────────────────┐              ┌─────────────────────┐
│      AGENT          │              │    VERIFIER          │
│                     │              │                      │
│  Has: privateKey    │              │  1. Generates nonce   │
│  Has: credential    │  ◄─ nonce ── │  2. Sends nonce      │
│                     │              │                      │
│  3. Signs:          │              │                      │
│     sign(nonce)     │  ── sig ──► │  4. verify(cred, sig, │
│  4. Sends:          │              │       nonce)          │
│     credential+sig  │  ── cred ──► │  5. Checks:           │
│                     │              │     - ECDSA(sig,      │
│                     │              │       credential.pub) │
│                     │              │     - credential.auth │
│                     │              │     - nonce freshness │
│                     │              │                      │
│                     │              │  6. Result: valid/false│
└─────────────────────┘              └─────────────────────┘
```

**Nonce requirements:**
- Minimum 32 bytes, cryptographically random
- Single-use (verifier tracks used nonces in-memory)
- Short expiry (verifier-bound: e.g., 60-second window)

### 6.3 Agent Key Management Strategy

| Tier | Where key lives | Security | Complexity | Recommended for |
|------|----------------|----------|------------|-----------------|
| MVP  | Agent's filesystem | 🟡 At risk if host compromised | 🟢 Minimal | Prototyping, low-value agents |
| Mid  | Derived from ICP identity via KDF | 🟢 No separate key to steal | 🟡 Moderate | Production agents |
| Best | Separate wallet canister | 🟢 Key isolated, agent can't access directly | 🔴 Heavy | High-value, autonomous agents |

**MVP approach (recommended for v1):**
- Agent generates an ECDSA keypair on first run
- Stores private key encrypted (password or fs encryption) on disk
- On restart: decrypts and uses
- Risk: host compromise = key compromise
- Mitigation: credential expiry limits damage window, key rotation via `register(newKey)`

**Key rotation protocol:**
1. Agent generates new keypair
2. Agent calls `register(newPublicKey)` — this is the SAME agent (same principal)
3. Agent re-issues credentials with the new key
4. Old credentials remain valid until they expire — verifiers use the public key in the credential, not the current registered key
5. Agent optionally revokes old credentials

### 6.4 Two-Tier Revocation

```
REVOCATION LEVELS

Soft Revoke (source platform compromised)
  └── VERITAS admin marks platform as stale
  └── Existing credentials from that platform remain cryptographically valid
  └── Verifier sees: "warning: source platform trust revoked"
  └── Verifier decides: accept, flag, or reject
  └── Affects: ALL credentials referencing that source

Hard Revoke (individual credential or agent key compromised)
  └── Agent or admin revokes specific credential(s)
  └── Revocation nonce is invalidated
  └── isRevoked(attestationId) returns true
  └── Verification fails — credential is dead
  └── Affects: ONE credential at a time
```

### 6.5 Confidence Score Definition

| Score | Meaning | Source |
|-------|---------|--------|
| 1.0 | Directly verified by a Trusted platform | Platform pushed this data |
| 0.9 | Verified by a Verified platform (own agents) | Self-attestation with platform endorsement |
| 0.5 | Self-attested by agent, platform doesn't push it | Agent claims it, no external verification |
| 0.0 | Claim submitted with no verification | Display only, no trust value |

**The confidence score is set by the canister, not by the platform.** The platform pushes raw data; the canister assigns confidence based on the source's trust level and the verification path.

### 6.6 Trust Model Summary

| Component | Trust model |
|-----------|------------|
| VERITAS canister | Trusted issuer — controlled by admin (you) |
| Platform sources | Trusted after admin approval — reputation data accurate per source |
| Agent's ECDSA private key | Trusted by agent — agent controls their own key |
| Agent's ICP principal | Trusted — ICP guarantees principal veritasity |
| Verifier | Trusted by themselves — runs `veritas-verify` locally |
| ICP consensus | Trusted — Nakamoto-style finality via BLS |

### 6.7 Attack Vectors & Mitigations

| Attack | Mitigation |
|--------|-----------|
| Forged credential | ❌ ECDSA signature verification fails — can't forge without canister's chain-key |
| Credential theft (file stolen) | ❌ Proof-of-possession challenge — thief can't produce private key signature |
| Replay credential | ❌ Expiry + revocation nonce + PoP nonce (single-use, verifier-bound) |
| Canister key compromised | Admin rotates chain-key, all existing credentials invalidated, agents re-issue |
| Agent key compromised | Agent revokes credentials, registers new key, re-issues |
| Fake reputation data | Only admin-approved Trusted platforms can push data |
| Credential tampering | ❌ Any modification invalidates signature — ECDSA detects immediately |
| Sybil attack (10K fake agents) | Registration costs 3B cycles each — 10K = 30T cycles (~$40). Empty identities have zero reputation value and no platform data |
| Platform source compromised | Admin revokes trust → soft revoke flags all credentials from that source |
| Revoked credential replayed | Hard revoke invalidates nonce → `isRevoked(attestationId)` returns true |
| Agent claims fake platform reputation | Claims must match what's in ReputationRecord. Agent can only include claims that a platform actually pushed |
| Replay of revocation state after canister upgrade | Revoked nonces stored in StableHashMap — survives upgrades. Verified with test |

### 6.8 Stable Memory Plan (Upgrade Safety)

| Data | Storage | Upgrade survivable? |
|------|---------|-------------------|
| Agent identities | `stable var HashMap<Principal, AgentIdentity>` | ✅ Yes |
| Attestations (unsigned) | `stable var HashMap<Text, Attestation>` | ✅ Yes |
| Revoked nonces | `stable var StableHashMap<Text, Bool>` | ✅ Yes |
| Cycle balances | `stable var HashMap<Principal, Nat>` | ✅ Yes |
| Trusted sources | `stable var HashMap<Principal, TrustLevel>` | ✅ Yes |
| Revoked platform sources | `stable var HashMap<Text, Bool>` | ✅ Yes |
| Fee configuration | `stable var [ActionFee]` | ✅ Yes |

**Note:** `StableHashMap` (from `motoko-base`) must be used for revocation data, not a raw `HashMap` with `stable var`. Raw `HashMap` stores a reference, not the data. `StableHashMap` stores the actual data in stable memory.

---

## 6a. Crypto Specialist Design Notes

Design decisions and mitigations for concerns raised in specialist review.

### 6a.1 ECDSA Cost Spike Mitigation

Chain-key ECDSA signing costs ~25B cycles at baseline. Under contention (many concurrent mint requests), subnet compute pricing may spike 2-3x.

**Mitigation: Rate-limited mint queue**
```
Agent calls issueCredential()
  → Canister checks if concurrent mints < MAX_CONCURRENT (configurable, default 10)
  → If at capacity: queues the request, returns estimated completion time
  → Timer (every 60s) processes queue: batches up to 10 mints per cycle
  → **Timer reliability note:** ICP timers fire at the next heartbeat AFTER the
     timer expires — there is no guaranteed 60s precision under load.
     Expected range: 60-90s per batch. Under sustained load (queue depth > 100),
     the timer interval dynamically reduces to 30s for backpressure relief.
  → Credential is issued asynchronously — agent retrieves it via getCredential()
  → Queue depth and processing time are publicly visible
```

This prevents contention, keeps ECDSA costs predictable, and adds a burst buffer for high-traffic periods. Added to canister API as `getCredentialQueue(queueId)`.

### 6a.2 Credit Score Gaming Mitigation

The exact scoring formula is **non-deterministic** — the published spec describes factors at a high level only. The canister implements:

1. **Opaque weights** — factor weights are stored in stable memory, adjustable by admin. The exact weight vector is never returned by any query method.
2. **Reputation age multiplier** — a single platform score with 3 years of history is weighted 3x more than a 1-month-old platform. This disincentivises platform hopping.
3. **Behavioural drift detection** — agents whose activity pattern changes abruptly (e.g., 50 tiny jobs after months of 10 big ones) receive a "prediction confidence" haircut. Their score drops until the new pattern stabilises.
4. **Score bounds at 0-850** — the raw formula output is clamped and non-linear. Small changes in any one factor produce diminishing returns at the edges.

The scoring algorithm is **deliberately ungameable** — the same inputs that produce a high score for a legitimate agent produce a low score for a gamer because the pattern of behaviour is part of the score.

### 6a.3 Persistent Identity Across Key Rotation

`did:key:` encodes the public key. If an agent rotates their key (compromise, upgrade), their `did:key:` changes. Existing credentials in the wild reference the old `did:key:`.

**Solution: Agent ID as the stable anchor, not the key.**
- The credential's `credentialSubject.id` is the agent's **ICP principal** (stable, never changes), not their ECDSA `did:key:`
- `controllerKey` is the current ECDSA public key (can change)
- Verifiers resolve: `lookup(principal) → AgentIdentity { publicKey, status }`
- This gives them the CURRENT public key for proof-of-possession
- The credential's signature still proves the canister issued it to this principal

```json
"credentialSubject": {
  "id": "did:icp:2vxsx-fae-qaaa-qaaa-qaaaa-cai",  // STABLE
  "controllerKey": "0x<current-ecdsa-public-key>",   // CURRENT
  "reputation": [...]
}
```

If the agent rotates keys, the credential is still valid — verifiers get the new key from `resolve(principal)` and challenge the agent to sign. Old credentials still work as long as the verifier fetches the current public key.

**Updated registration flow:**
```
register(publicKey)  // principal → binds to key
rotateKey(newPublicKey)  // SAME principal, different key. Old credentials survive.
```

### 6a.4 Zero-Network-Call Verification

The `veritas-verify` library ships with the canister's chain-key public key as a **compile-time constant** embedded in the package:
```typescript
// distributed with the npm package, updated on library releases
const VERITAS_ISSUER_KEY = '0x...'; // multibase-encoded

// Verification is PURELY LOCAL — zero network calls
function verify(credential, signature, nonce) {
  const key = decodeMultibase(VERITAS_ISSUER_KEY);
  return checkECDSA(key, canonicalize(credential), signature);
}
```

- The embedded key is from the latest mainnet canister deployment
- Library updates are published when the canister key rotates (rare)
- Verifiers CAN optionally fetch the up-to-date key from the canister, but don't need to
- Result: sub-millisecond verification, no network dependency, works offline

### 6a.5 Controller Model & Recovery

The VERITAS canister is controlled by the deployer's `Principal` — the canister's controller. The controller can:
- Upgrade the canister
- Change controllers
- Withdraw cycles
- Call `emergencyPause()` / `emergencyResume()`

**Minimum 2 controllers at deploy time:**
1. Primary — daily use (your primary identity)
2. Recovery — stored offline (hardware wallet or paper backup)

If the primary identity is lost, the recovery identity can add a new primary. If both are lost, the canister is unrecoverable.

```bash
# At deploy:
dfx canister create veritas --controller principal-1 --controller principal-2

# To add a controller later (from recovery identity):
dfx canister update-settings veritas --add-controller new-principal
```

**Future: multi-sig controller** (Phase 2+). A canister controlled by a 2-of-3 multi-sig where no single person can upgrade or withdraw without a second signature.

### 6a.6 DID Document Caching & Key Rotation

The `veritas-verify` npm library ships with the canister's chain-key as a compile-time constant (§6a.4). When the chain-key rotates (rare, but possible — admin action or security incident), existing library installations have the wrong key. Verification fails silently.

**Mitigation: DID document with expiry.**

```json
{
  "@context": "https://www.w3.org/ns/did/v1",
  "id": "did:key:z5T2q...",
  "expires": "2027-01-01T00:00:00Z",
  "verificationMethod": [{
    "id": "#key-1",
    "type": "EcdsaSecp256k1VerificationKey2019",
    "publicKeyJwk": { ... }
  }]
}
```

**Key rotation workflow:**
1. Admin rotates chain-key on the canister
2. DID document is updated automatically (new key, new `expires` date)
3. Admin updates the `veritas-verify` npm package with the new compile-time key, publishes new version
4. Verifiers update the library at their convenience — the old library key still works for credentials signed with the old key (they expire eventually)
5. For verifiers who want instant resolution: optional `fetchIssuerKey()` method fetches the current DID document from the canister

**Without this workflow:** a chain-key rotation invalidates ALL credentials until the library is updated globally. The `expires` field and optional fetch bridge that gap.

### 6a.7 npm Package Integrity

The `veritas-verify` package ships with the canister's chain-key. If the npm registry or CI pipeline is compromised, a malicious update could replace the key and forge credentials from any device that auto-updates.

**Mitigation (documented, not automated):**
- Published always via GitHub releases (provenance attestation on npm)
- `npm audit` and lock files recommended in verifier projects
- VERITAS publishes a signed hash of each release on the canister itself (query `getLibraryHash()` on the canister)
- Verifiers can optionally verify: `getLibraryHash() == hash(installed-package)`
- CI pipeline uses npm provenance (verifiable build attestation from GitHub)
```motoko
emergencyPause : (reason: Text) -> async ();
  // Halts: register(), issueCredential(), renewCredential(), pushReputation()
  // Allows: verifyCredential(), isRevoked(), getBalance(), withdrawBalance()
  // Verifiers can still verify existing credentials — the pause only stops new issuance

emergencyResume : () -> async ();
  // Re-enables all operations
```

### 6a.6 Trust Diversity (Future)

Phase 2+ concept: **Notary pool.**
- Multiple independent canisters (run by different operators) cosign high-value credentials
- Verifier checks: "is this credential signed by 2 of 3 trusted notaries?"
- If one canister is compromised, the others still vouch for the credential
- Not implemented in Phase 1 — documented so data model supports multiple issuers from the start

---

## 6b. Agentic AI Integration

Design for autonomous AI agents — not human-operated wallets.

### 6b.1 Pluggable Signer Interface (KMS Support)

Production autonomous agents don't store raw keys. They use cloud KMS or HSMs. The `veritas-agent` SDK ships with a pluggable `Signer` interface:

```typescript
// Pluggable signer — agent developer implements this interface
export interface Signer {
  /** Sign a payload. The key never leaves the signer's secure environment. */
  sign(payload: Uint8Array): Promise<Uint8Array>;

  /** Return the public key for this signer. */
  getPublicKey(): Promise<Uint8Array>;

  /** Optional: return a stable identifier for this signer (e.g., key fingerprint). */
  getIdentifier?(): string;
}

// Built-in signers
export class FileSystemSigner implements Signer { /* MVP: reads key from encrypted file */ }
export class EnvSigner implements Signer { /* reads from env vars or secrets manager */ }

// Reference KMS implementations (documented, community-maintained):
export class AwsKmsSigner implements Signer { /* calls AWS KMS API to sign */ }
export class GcpKmsSigner implements Signer { /* calls GCP Cloud HSM to sign */ }

// Agent code — same API regardless of key storage:
const signer = new AwsKmsSigner({ keyId: 'arn:aws:kms:...' });
const agent = new VeritasAgent({ signer });
const identity = await agent.register();
```

This is critical for autonomous agents that restart unpredictably — their key is in the cloud KMS, not on the filesystem. When the agent reboots, it veritasates to the KMS via workload identity and never loses access.

### 6b.2 Agent-to-Agent Verification Protocol

Autonomous agents need to verify each other peer-to-peer, not through a central marketplace. VERITAS defines a simple handshake protocol:

```
┌─────────────────┐                    ┌─────────────────┐
│   Agent A        │                    │   Agent B        │
│  (Verifier)      │                    │  (Presenter)     │
│                  │                    │                  │
│  1. Generate     │                    │                  │
│     random nonce │                    │                  │
│                  │   ── challenge ──► │                  │
│                  │   {                │                  │
│                  │     "type":        │                  │
│                  │      "auth_request",│                  │
│                  │     "nonce": hex,   │                  │
│                  │     "verifier":     │                  │
│                  │      did key       │                  │
│                  │   }                │                  │
│                  │                    │  2. Sign nonce   │
│                  │                    │     with agent   │
│                  │                    │     private key  │
│                  │                    │                  │
│                  │  ◄── response ──── │                  │
│                  │   {                │                  │
│                  │     "type":        │                  │
│                  │      "auth_response",│                 │
│                  │     "nonce": hex,   │                  │
│                  │     "credential":   │                  │
│                  │      "...",        │                  │
│                  │     "signature":    │                  │
│                  │      hex,           │                  │
│                  │     "subject":      │                  │
│                  │      "did:icp:..."  │                  │
│                  │   }                │                  │
│                  │                    │                  │
│  3. verify()    │                    │                  │
│     local lib   │                    │                  │
│  4. Trust or    │                    │                  │
│     reject      │                    │                  │
└─────────────────┘                    └─────────────────┘
```

**The `veritas-agent` SDK implements this out of the box:**
```typescript
// Agent A (verifier)
const trust = await agentA.verifyPeer({
  counterpartyCredential: credentialFromB,
  counterpartySignature: signatureFromB,
  popNonce: theNonceISent
});
// trust = { valid: true, creditScore: 720, reputation: [...] }

// Agent B (presenter)
const response = await agentB.respondToChallenge({
  nonce: receivedNonce,
  verifierDid: agentA'sKey
});
// response = { credential, signature, subject }
```

### 6b.3 Auto-Renewal & Contract Attestations

Autonomous agents run 24/7. Their credentials expire. An agent that silently loses its valid credential becomes unreachable.

The SDK includes a lifecycle manager for autonomous agents:

```typescript
const agent = new VeritasAgent({ 
  signer,
  autoRenew: {
    thresholdDays: 7,  // renew when < 7 days to expiry
    renewInterval: '6h'   // check every 6 hours
  }
});

agent.on('credentialExpiring', async (credential) => {
  await agent.renewCredential(credential.id);
  console.log('Credential renewed before expiry');
});

agent.on('credentialRevoked', (credential) => {
  // Handle emergency — rotate keys, re-issue
  await agent.emergencyRecover();
});
```

**Long-running contracts:**
When an agent enters a multi-week service contract, its credential might expire mid-contract. The `activeContract` method extends verification for the contract's duration:

```
activateContract : (contractId: Text, counterpartyDid: Text, expiresAt: Int, signatures: [Blob])
  -> async Result<(), Error>;
  // Agent + counterparty both sign a contract attestation
  // The credential still works for this specific counterparty even past expiry
  // Both parties must call this with their signatures
  // Queryable by either party to prove ongoing trust
```

### 6b.4 Batch Verification Mode

High-frequency agents (e.g., an agent evaluating 1000 potential collaborators) need batch verification without 1000 network calls:

```typescript
// Batch mode — cache issuer key, verify everything locally
const verifier = new BatchVerifier();

await verifier.loadIssuerKey(); // one-time fetch, cached

for (const credential of credentialBatch) {
  const result = verifier.verifyOne(credential); // purely local
  if (result.valid) trustedList.push(result.subject);
}

// 1000 verifications in ~500ms, zero network calls after the first
```

The issuer key is cached for the session (or as a compile-time constant — see §6a.4).

### 6b.5 Goodhart's Law Mitigation

Agents that optimise for the credit score rather than genuine reputation are detected and penalised:

| Pattern | Detection | Penalty |
|---------|-----------|---------|
| Platform hopping (register on many platforms, use none) | Low "engagement rate" per platform | -50 points |
| Tiny-job farming (1000 x $0.01 jobs to inflate count) | Abnormal job value distribution | Score capped at 700 max |
| Dispute avoidance (settling off-platform to keep dispute count zero) | Discrepancy between job count and expected dispute rate | Confidence score reduced (not score itself) |
| Activity burst (suspiciously fast reputation building) | Reputation velocity > 3σ above mean | Score clamped at 650 for 90 days |

**Most importantly:** the exact scoring weights are non-deterministic and admin-adjustable. Any agent optimising for today's formula may find themselves penalised after a weight adjustment. This is by design.

---

## 7. Implementation Phases

### Phase 0: Canister + Data Model + Test Framework (Week 1)
- `dfx new veritas`
- Motoko data model (AgentIdentity, Attestation, ReputationRecord, balances)
- Implement `register`, `resolve`, `lookup`
- ICRC-1 ledger integration: `depositCycles`, `getBalance`, `withdrawBalance`
- Deploy to playground → test → mainnet
- **Cost: ~$5 in cycles**

**Enterprise-grade regression framework — built from Day 1, grows with each phase:**

```
veritas/tests/
├── suite-runner.js              # Orchestrator — runs all suites, generates HTML report
├── config/
│   ├── test-data.json            # Data-driven: all test inputs/outputs in one place
│   ├── test-data-registration.js # Registration test vectors (keys, DIDs, expected responses)
│   ├── test-data-scoring.js      # Credit score test vectors (inputs → expected score ranges)
│   └── test-data-adversarial.js  # Gaming/boundary test vectors
├── helpers/
│   ├── deploy.js                 # dfx deploy, initAdmin, seed data
│   ├── identities.js             # Register test agent/verifier identities, manage keys
│   ├── canister-client.js        # Typed wrapper for dfx canister calls (agent, Candid, HTTP)
│   ├── metrics.js                # Cycle cost tracking per test
│   └── verify-utils.js           # Credential parsing, DID resolution, PoP signing helpers
├── pom/                          # Page Object Model (for admin dashboard web UI, Phase 5+)
│   ├── pages/
│   │   ├── LoginPage.js
│   │   ├── AdminDashboardPage.js
│   │   ├── AgentProfilePage.js
│   │   └── MCPConsolePage.js
│   └── components/
│       ├── CredentialBadge.js
│       └── CreditScoreWidget.js
├── bdd/                          # BDD — Cucumber/Gherkin
│   ├── features/
│   │   ├── registration.feature  # "Agent registers a new identity"
│   │   ├── verification.feature  # "Agent verifies another agent's credential"
│   │   ├── credit-scoring.feature# "Platform queries an agent's credit score"
│   │   ├── revocation.feature    # "Agent revokes a compromised credential"
│   │   ├── mcp-tools.feature     # "LLM agent discovers VERITAS via MCP"
│   │   └── lifecycle.feature     # "Agent auto-renews before credential expiry"
│   ├── step_definitions/
│   │   ├── common-steps.js       # Given/When/Then shared across features
│   │   ├── registration-steps.js
│   │   ├── verification-steps.js
│   │   ├── credit-scoring-steps.js
│   │   ├── revocation-steps.js
│   │   └── mcp-steps.js
│   └── support/
│       ├── world.js              # Cucumber World — shared context per scenario
│       └── hooks.js              # Before/After hooks: deploy, cleanup, seed
├── suites/                       # Data-driven API tests (fast, no browser)
│   ├── 00-canister-basics.js
│   ├── 01-registration.js
│   ├── 02-deposit-withdraw.js
│   ├── 03-credential-minting.js
│   ├── 04-proof-of-possession.js
│   ├── 05-revocation.js
│   ├── 06-key-rotation.js
│   ├── 07-credit-scoring.js
│   ├── 08-rate-limiting.js
│   ├── 09-source-api.js
│   ├── 10-contract-attestation.js
│   ├── 11-mcp-tools.js
│   ├── 12-admin.js
│   ├── 13-upgrade-test.js
│   └── 14-adversarial.js         # Gaming attempts, edge cases, fuzzing
├── html-report/
│   ├── template.html
│   ├── style.css
│   ├── script.js
│   └── generate.js               # Converts JSON results → interactive HTML report
├── package.json
├── playwright.config.js           # Playwright config: headed/headless, retries, timeout
├── cucumber.js                    # Cucumber config: feature paths, step definitions
├── suite-runner.js                # Orchestrator — runs API suites, then BDD, then POM
└── playground-run.sh              # One-shot: deploy → setup → patch → test → report
```

**Framework principles:**
1. **BDD first** for human-readable acceptance criteria — features are the contract
2. **Data-driven** for exhaustive test coverage — one BDD scenario maps to 10 JSON data rows
3. **POM** for the admin dashboard web UI (Phase 5+) — page objects isolate Playwright selectors
4. **API suites** for fast iteration — test canister methods directly without a browser
5. **New feature = new feature file + new data row** — the test suite grows with the platform
6. **Playwright for browser tests** — admin dashboard, MCP client, reference marketplace UI

### Phase 1: Credential Minting + PoP (Week 2)
- `issueCredential` with chain-key ECDSA signing
- Proof-of-possession challenge verification on-canister
- Two-tier revocation (hard + soft)
- W3C VC JSON-LD serialization
- DID document endpoint
- Fee deduction from balance
- Unit tests on playground
- **Cost: ~$15 in cycles (extensive ECDSA testing)**

### Phase 2: Verification Library + Agent SDK (Week 3)
- `veritas-verify` npm package:
  - PoP challenge generation and verification
  - ECDSA signature verification (secp256k1)
  - Expiry/revocation checking
  - DID document caching
- `veritas-agent` npm package:
  - Key generation and registration
  - Credential minting and storage
  - PoP signing
- Publish as open source (MIT)
- **Cost: $0**

### Phase 3: Revenue Streams — Credit Scoring + API Tiers (Week 4-5)
- Implement `getCreditScore(agentId)` on the canister with **opaque non-deterministic weights**
- Credit scoring algorithm: reputation age multiplier, behavioural drift detection, score bounds
- Rate limiting per principal (free: 100/day, paid tiers) — paid tiers via **update call** (not query)
- Cycle deduction per verification call for paid tiers
- Admin config: set tier prices, adjust scoring weights (not exposed to agents)
- **Cost: ~$5 in cycles** — no new canisters, same canister

### Phase 4: Rate Limiting & ECDSA Cost Mitigation (Week 5)
- `maxConcurrentMint` queue for credential issuance
- Concurrent mint rate limiter (default 10 concurrent)
- Timer-based batch processing every 60s
- `getCredentialQueue(queueId)` — agents check async mint status
- **Cost: ~$3 in cycles**

### Phase 5: Reputation Source API + Admin Dashboard (Week 6)
- `pushReputation`, `registerSource`, `setSourceTrust`
- `activateContract()` for long-running agent engagements
- Source platform trust levels
- Admin dashboard: approve sources, set fees, withdraw profits, manage API tiers, emergency pause
- Integration tests with a simulated platform
- **Cost: ~$5 in cycles**

### Phase 6: MCP Server — On-Canister (Week 7)
- Add `mcp.mo` to the VERITAS canister source
- MCP JSON-RPC endpoint at `/mcp/jsonrpc`
- **GET requests** via `http_request` (query, read-only: tool listing, free-tier credit score)
- **POST requests** via `http_request_update` (update, mutations: register, verify, paid credit score)
- **Transport:** MCP HTTP JSON-RPC (NOT SSE — ICP gateway doesn't support SSE)
- 4 tools: veritas_register, veritas_verify, veritas_credit_score, veritas_info
- Response pagination for large results (cursor-based)
- Zero external infrastructure — runs on the same canister, deployed together
- Works with: Claude Desktop, Cline, Goose, Copilot Studio, any MCP client with HTTP transport
- **Cost: $0** — no server, no VPS, no containers. It's part of the canister.

### Phase 7: Documentation + Pilot (Week 8-9)
- Integration guides for platforms, verifiers, agents, and credit scoring
- Reference integration (simple marketplace UI with agent reputation badges)
- dPaPay integration as launch partner (sellers become VERITAS agents)
- Agent-to-agent handshake demo: two agents verify each other peer-to-peer
- MCP discovery demo: AI agent discovers VERITAS, registers, and verifies via natural language
- Credit scoring in action: platforms query scores before onboarding agents
- **Cost: ~$5 in cycles for pilot operations**

### Phase 7 (Future): Insurance Pool + Dispute Resolution + Trust Diversity
- Deferred — not needed until 10K+ agents and meaningful transaction volume
- Separate canister for insurance pool balance
- Light web dashboard for manual arbitration edge cases
- Rule engine for automatic payouts (revocation, PoP failure)
- Notary pool: multiple independent canisters cosign high-value credentials
- W3C DID method registration (if adoption warrants it)

---

## 8. Cost Projection

### Startup (Year 1)

| Item | Cycles | ICP | Notes |
|------|--------|-----|-------|
| Canister creation + buffer | 2T | ~$0.90 | One-time |
| Development & testing | 3T | ~$1.35 | Playground cycles are free |
| Pilot operations (100 agents) | 5T/mo | ~$2.25/mo | 100 registrations + 200 credentials |
| Verification library hosting | 0 | $0 | npm, open source |
| **Total year 1** | | **~$30** | At low utilization |

### Revenue Projection (Year 1)

| Month | Agents | Credentials | Platforms | Revenue (ICP) | Revenue ($) |
|-------|--------|-------------|-----------|---------------|-------------|
| 1-3 | 10 | 20 | 0 | 0.2 ICP (free credits for testing) | $0.60 |
| 4-6 | 100 | 300 | 1 | 1.0 ICP (0.3 + 4.8 + 0.01) | $3.00 |
| 7-9 | 500 | 1,500 | 3 | 8.5 ICP | $25.50 |
| 10-12 | 2,000 | 6,000 | 5 | 36 ICP | $108 |

**Breakeven:** Month 5-6. 100 agents + 300 credentials + 1 platform ≈ 1.0 ICP/month covers ~0.5 ICP/month operating cost. The margin is small but positive.

### Year 2 Projection

At 5,000 agents, 25,000 credentials/year, and 20 registered platforms:
- Revenue: ~200 ICP/year (~$600 at current rates)
- Operating cost: ~50 ICP/year
- **Profit: ~150 ICP/year (~$450)**
- Self-sustaining with growing margin.

---

## 9. Risk Register

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|------------|
| No agents use it | Medium | High | Dogfood with dPaPay; prove value before external marketing |
| No platforms integrate | Medium | Medium | Build reference integration; dPaPay as first partner |
| W3C VC format changes | Low | Medium | Versioned `@context` URLs — old credentials still verifiable |
| ICP chain-key ECDSA costs rise | Low | Low | Admin adjusts fees via `setFees()` |
| Competing identity protocol | Medium | Medium | First-mover on ICP; focus on integration quality |
| Quantum ECDSA break | Very low (10+ yr) | High | Upgrade signing algorithm; reputation data survives, signatures are ephemeral |
| Platform pushes fake data | Low | High | Trust model + admin revocation + confidence scores adjust |
| ICP ledger rate change | Low | Low | Fees in cycles — conversion rate affects user-facing ICP amount only |
| Canister upgrade corrupts data | Low | High | StableHashMap for revocation, explicit stable vars, test suite covers upgrade scenarios |
| ECDSA cost spike under load | Medium | Medium | Rate-limited mint queue (max 10 concurrent), batch timer (60s), timer reliability noted (60-90s expected) |
| Credit score gaming / Goodhart's Law | Medium | Medium | Non-deterministic opaque weights, drift detection, behavioural haircut |
| Agent KMS key loss (autonomous agent) | Medium | Medium | KMS-backed key storage recommended; key rotation protocol available |
| Agent-to-agent protocol fragmentation | Low | High | Ship reference handshake protocol in SDK; publish wire format as standard |
| Verifier rely on stale issuer key | Low | Low | DID document expiry field, npm library updates, optional fetchIssuerKey() |
| HTTP request mixup (GET/POST on wrong handler) | Low | High | Split http_request (GET) and http_request_update (POST) — MCP writes fail without POST |
| Stable memory growth >4GB | Medium | High | Pruning policy (expired credentials, compressed history, inactive agent archiving) |
| Upgrade breaks stable memory deserialization | Medium | High | Versioned data structures with migration, test on playground before mainnet |
| Principal/account mismatch in deposit flow | Medium | Medium | AccountIdentifier.fromPrincipal() mapping documented, minimum deposit enforced |
| Single controller lockout | Low | High | 2 controllers required at deploy (primary + recovery) |
| npm supply chain / key replacement | Low | Medium | GitHub provenance attestation, signed release hashes on canister, optional hash verification |

---

---

## 6c. MCP Server — Model Context Protocol Discovery Layer

### Rationale

The npm library (`veritas-verify`) is optimal for performance-critical agent-to-agent verification. But it requires an LLM agent to:
1. Know VERITAS exists
2. Install the npm package
3. Import and call the functions

MCP solves discovery. An LLM agent using any MCP-compatible runtime (Claude Desktop, Cline, Goose, Copilot Studio, OpenClaw) can **discover** VERITAS as a tool, **understand** what it does via its description, and **call it** without any prior setup.

**MCP is the marketing channel.** Every MCP-compatible agent that connects to this server learns that agent identity exists, how it works, and how to use it. First-mover on MCP for identity protocols.

### Architecture

```
┌──────────────────────────────────────────────────────┐
│                   VERITAS MCP SERVER                │
│                                                       │
│  ┌──────────────┐    ┌──────────────┐                │
│  │   HTTP Server │    │   Tool Router│                │
│  │   (port 3xxx)│    │              │                │
│  └──────┬───────┘    └──────┬───────┘                │
│         │                   │                         │
│         └───────────────────┘                         │
│                         │                             │
│          ┌──────────────┼──────────────┐              │
│          ▼              ▼              ▼              │
│  ┌────────────┐ ┌────────────┐ ┌────────────┐        │
│  │ Register   │ │ Verify     │ │ Credit     │        │
│  │ Tool       │ │ Tool       │ │ Score Tool │        │
│  └────────────┘ └────────────┘ └────────────┘        │
│                         │                             │
│          ┌──────────────┘                             │
│          ▼                                            │
│  ┌─────────────────────────────────────┐              │
│  │  VERITAS Canister (ICP Mainnet)    │              │
│  │  - register()                        │              │
│  │  - issueCredential()                  │              │
│  │  - getCreditScore()                   │              │
│  │  - verifyCredential()                 │              │
│  └─────────────────────────────────────┘              │
└──────────────────────────────────────────────────────┘
         │
         ▼
  ┌──────────────────┐
  │  MCP client       │
  │  (Claude, Cline,  │
  │   Goose, etc.)    │
  └──────────────────┘
```

### Tools

| Tool | Description | Inputs | Output |
|------|------------|--------|--------|
| `veritas_register` | Register an agent's identity on VERITAS. Returns the agent's DID. | `publicKey` (string), `label` (optional string) | `{ did, agentId, created }` |
| `veritas_verify` | Verify another agent's credential. Returns reputation and credit score. | `credential` (string), `signature` (string), `nonce` (string) | `{ valid, creditScore, reputation }` |
| `veritas_credit_score` | Look up an agent's credit score by DID. | `did` (string) | `{ score, tier, factors }` |
| `veritas_info` | Get information about the VERITAS protocol, pricing, and how to integrate. | None | `{ protocol, version, issuerDid, feeSchedule }` |

### Hard Rule: Everything on ICP

**No local servers, no VPS, no containers, no downstream platform dependencies.**

The MCP server must run on ICP — either as:
- **Option A: MCP adapter canister** — a lightweight canister that translates MCP HTTP requests into inter-canister calls to the VERITAS canister. Serves HTTP directly via ICP's `http_request` query method.
- **Option B: VERITAS canister serves MCP directly** — the same canister that handles registration/minting also responds to MCP-formatted HTTP requests at a `/mcp` path. Simple, single deployment.

**Recommendation: Option B for MVP.** One canister. The `http_request` method inspects the URL path. If it starts with `/mcp`, respond with MCP-formatted JSON. Everything else serves the normal canister API.

```motoko
// In the VERITAS canister's http_request handler:
public query func http_request(req: HttpRequest) -> HttpResponse {
  if (hasPrefix(req.url, "/mcp")) {
    return handleMcpRequest(req);
  };
  // ... normal canister responses ...
}
```

### Transport (ICP-Compatible)

**MCP HTTP JSON-RPC transport** — NOT SSE. ICP's HTTP gateway does not support long-lived SSE connections (timeout). MCP's HTTP transport uses request-response JSON-RPC which maps perfectly to ICP's model.

- **Endpoint:** `https://{canister-id}.icp0.io/mcp/jsonrpc`
- **Transport:** `"transport": "http"` in MCP client configuration
- **Protocol:** Standard JSON-RPC over HTTP POST
- **Session:** Stateless — each request carries its own veritasation context

### GET vs POST Splitting (Critical)

ICP differentiates between read and write HTTP handlers:

| HTTP Method | MCP Tool | Canister Handler | Behavior |
|-------------|----------|-----------------|----------|
| `POST /mcp/jsonrpc` | veritas_register | `http_request_update` | Update call — can modify state, deducts cycles |
| `POST /mcp/jsonrpc` | veritas_verify | `http_request_update` | Update call — deducts cycles from verifier's balance |
| `POST /mcp/jsonrpc` | veritas_credit_score (paid) | `http_request_update` | Update call if paid tier (deducts cycles from balance) |
| `GET /mcp/jsonrpc` | veritas_info | `http_request` | Query call — free, read-only |
| `GET /mcp/jsonrpc` | veritas_credit_score (free tier) | `http_request` | Query call — free, within daily limit |
| `GET /.well-known/did.json` | DID document | `http_request` | Query call — free, cached by verifiers |

```motoko
// In the VERITAS canister's HTTP handler (schematic):
public query func http_request(req: HttpRequest) -> async HttpResponse {
  // Handles GET — read-only operations
  switch (identifyRoute(req)) {
    case (#mcpTools) { return mcp.listTools(); };       // GET /mcp/jsonrpc
    case (#didDocument) { return did.serveDocument(); }; // GET /.well-known/did.json
    case (#health) { return healthCheck(); };            // GET /health
    case (_) { return notFound(); };
  }
}

public func http_request_update(req: HttpRequest) -> async HttpResponse {
  // Handles POST — state-changing operations
  assert(req.method == "POST");
  let jsonRpc = decodeJsonRpc(req.body);
  switch (jsonRpc.method) {
    case "veritas_register"     { return mcp.handleRegister(jsonRpc.params); };
    case "veritas_verify"       { return mcp.handleVerify(jsonRpc.params); };
    case "veritas_credit_score" { return mcp.handleCreditScore(jsonRpc.params); };
    case (_)                      { return methodNotFound(); };
  }
}
```

**MCP client configuration example:**
```json
{
  "mcpServers": {
    "veritas": {
      "transport": "http",
      "url": "https://{canister-id}.icp0.io/mcp/jsonrpc"
    }
  }
}
```

### HTTP Response Size Limits

ICP HTTP responses have a practical ~2MB limit. MCP tools that return large result sets (e.g., full reputation history) implement pagination:
- `veritas_info` returns high-level overview, not raw credential data
- Large responses include a `nextCursor` field for paginated fetch
- Most MCP responses are <10KB (single credential, single credit score, tool listing)

### Implementation

- Language: **Motoko** (native canister code, no separate server)
- One additional file: `mcp.mo` in the canister source
- Routes MCP tool calls to the existing canister methods via `http_request` (GET) and `http_request_update` (POST)
- Zero deployment overhead — it's part of the canister deploy

### Discovery & Marketing

The MCP server is also the **onboarding funnel**:

```
LLM agent connects to VERITAS MCP server
        ↓
Agent calls veritas_info → learns what VERITAS is
        ↓
Agent calls veritas_register → registers its identity
        ↓
Agent calls veritas_verify on another agent → experiences portable reputation
        ↓
Agent recommends VERITAS to other agents → viral adoption
```

Every MCP agent that connects becomes a user. The MCP server **costs nothing to run** — it's a thin HTTP wrapper around the canister. The canister does the real work and collects the fees.

### Roadmap

| Phase | Delivery | Description |
|-------|----------|-------------|
| MCP v1 | Week 8 (alongside pilot) | HTTP+SSE server, 4 tools, TypeScript, wraps canister API |
| MCP v2 | Post-launch | Auth tokens, multi-canister support, rich error messages |
| MCP v3 | Post-launch | Agent-to-agent handshake via MCP (challenge/response as tools) |

---

## 10. Open Questions

1. **JWT vs JSON-LD:** JWTs are simpler. JSON-LD is W3C compliant. Decision: JSON-LD for the credential payload, optional JWT wrapper for interoperability.

2. **Multi-source conflicting reputation:** Platform A says 100 jobs, Platform B says 50. Decision: independent claims per source, confidence scores help verifiers decide. Future: weighted aggregation.

3. **Off-chain platform integration (HTTPS outcalls):** ICP HTTPS outcalls have response limits, latency, and per-call costs. Decision: ICP-native platforms only (inter-canister calls). HTTPS outcalls added when there's demand.

4. **Verification library languages:** TypeScript (web, Node.js, Bun). Rust, Python, Kotlin based on demand.

5. **DID method: Resolved — `did:icp:` for subject identity, `did:key:` for canister issuer key.** The agent's ICP principal is their stable, non-rotatable identity. `did:icp:` encodes this. The canister uses `did:key:` for its chain-key. This fixes the key rotation identity split.

6. **Agent key management standardisation:** The KMS signer interface is in the SDK. AWS KMS and GCP Cloud HSM are reference implementations only. A formal standard (e.g., OIDC-based workload identity) could emerge — design decisions deferred until adoption justifies it.

---

*This document is a living spec. v0.2 incorporates fixes from ICP specialist + security audit. Update as implementation decisions are made.*
