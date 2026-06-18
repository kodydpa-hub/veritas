# VERITAS Architecture

## Overview

VERITAS is a single-canister Motoko protocol on the Internet Computer. It provides AI agents with self-sovereign, W3C-compliant verifiable credentials and a reputation scoring system — all running on-chain with zero external infrastructure.

## Canister Components

```
src/
├── veritas_backend/
│   └── main.mo           # Main canister — all phases (1-7) + subscription management
└── mcp.mo                # MCP module — JSON-RPC tool definitions, serialization, dispatch
```

## Architecture Diagram

```
                     ┌──────────────────────────────────┐
                     │         VERITAS Canister          │
                     │         (single Motoko)           │
                     │                                   │
  ┌──────────────┐   │  ┌─────────┐  ┌───────────────┐  │
  │ AI Agents    │   │  │ MCP     │  │ Identity       │  │
  │ (MCP clients)│◄──┼──┤ Server  │  │ Registry       │  │
  │ Claude/Cline │   │  │ /mcp/   │  │ register()     │  │
  │ Goose/Hermes │   │  │ jsonrpc │  │ resolve()      │  │
  └──────────────┘   │  └────┬────┘  │ lookup()       │  │
                     │       │       └───────┬─────────┘  │
  ┌──────────────┐   │       │               │            │
  │ Platforms    │   │  ┌────▼────┐  ┌───────▼─────────┐  │
  │ (verifiers)  │◄──┼──┤ Credit  │  │ Credential       │  │
  │ Marketplaces │   │  │ Scoring │  │ Engine           │  │
  │ dApps        │   │  │ 0-850   │  │ issueCredential  │  │
  └──────────────┘   │  │ 6-factor│  │ buildVerifiable  │  │
                     │  └─────────┘  │ Credential       │  │
                     │               │ revokeCredential │  │
  ┌──────────────┐   │  ┌─────────┐  └───────┬─────────┘  │
  │ Reputation   │   │  │MintQueue│          │            │
  │ Sources      │◄──┼──┤ Batch   │  ┌───────▼─────────┐  │
  │ (platforms)  │   │  │ Proc.   │  │ Subscription     │  │
  └──────────────┘   │  │ heartbeat│  │ Management       │  │
                     │  └─────────┘  │ subscribeToTier  │  │
                     │               │ depositCycles    │  │
                     │  ┌─────────┐  │ auto-assign      │  │
                     │  │ Admin   │  └───────┬─────────┘  │
                     │  │ Dashboard│         │            │
                     │  │ /admin  │  ┌───────▼─────────┐  │
                     │  │ /docs   │  │ Heartbeat        │  │
                     │  └─────────┘  │ Cycle monitor    │  │
                     │               │ Auto-pause/resume│  │
                     │               └─────────────────┘  │
                     │                                   │
                     │  External: 6-hour cron alert       │
                     │  (OpenClaw, redundant safety net)  │
                     └──────────────────────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │  ICP Management     │
                    │  Canister           │
                    │  ecdsa_public_key   │
                    │  sign_with_ecdsa    │
                    └─────────────────────┘
```

## Data Flow

### Agent Registration (free)
```
Agent → MCP /mcp/jsonrpc (POST) → canister → register(publicKey) → DID returned
                                                                → 0 cycles (free forever)
```

### Credential Issuance (free Year 1)
```
Agent → issueCredential(claims, popSignature) → canister → generateId → store record
                                                         → ECDSA not called per-credential
                                                         → stored as CredentialRecord
```

### Credit Score Query (100/day free)
```
Platform → getCreditScore(agentId) → canister → compute 6-factor score → return {score, tier, factors}
                                          ↑
                                    Reads: credentials, identities, timestamps
```

### Paid Subscription (Year 2+)
```
Platform → depositCycles() → canister accepts → auto-assigns tier
Platform → subscribeToTier("Starter") → deducts monthly fee → tier upgraded
Platform → getCreditScorePaid(agentId) → deducts per-call → returns score
```

### Agent Handshake (peer-to-peer, 0 canister calls)
```
Alice: generateKeypair() → createHandshakeProof() → sends to Bob
Bob:   verifyHandshakeProof(proof) → true if Alice controls her key
```

## State Management

| Store | Type | Persistence |
|-------|------|-------------|
| identities | HashMap<Principal, AgentIdentity> | Stable var |
| balances | HashMap<Principal, Nat> | Stable var |
| credentials | HashMap<Text, CredentialRecord> | Stable var |
| revokedNonces | HashMap<Text, Bool> | Stable var |
| trustedSources | HashMap<Principal, TrustLevel> | Stable var |
| config | HashMap<Text, Text> | Stable var |
| dailyUsage | HashMap<Principal, DailyUsage> | Stable var |
| mintQueue | [MintQueueItem] | Stable var |
| platformSources | HashMap<Text, PlatformSource> | Stable var |

All stores use stable var serialization for upgrade safety. Storage version: 6.

## Security

- **ECDSA:** Chain-key secp256k1 via ICP management canister
- **PoP:** Proof-of-possession via principal authentication at credential mint time
- **Rate limiting:** Per-principal, date-based, configurable per tier
- **Revocation:** Hard (per-credential) + soft (source-flagged)
- **Auto-pause:** Heartbeat monitors cycle balance, pauses at 5T threshold
- **Immutability:** Credentials are write-once on-chain records

## Cost Structure

| Component | Cost | Frequency |
|-----------|------|-----------|
| Idle burn | ~4B cycles/day (~$0.002) | Continuous |
| ECDSA key init | ~10B cycles ($0.005) | Once |
| Query (credit score) | ~20M cycles ($0.000009) | Per call |
| Update (register) | ~3B cycles ($0.001) | Per call |
| Update (issue credential) | ~35B cycles ($0.016) | Per call |
| **10 ICP seed** | **~$4.50** | **Covers Year 1** |

## Pricing Model

| Year | Strategy | Detail |
|:----:|----------|--------|
| 1 | Free | Agent registration free forever. All tiers $0. Driver adoption. |
| 2+ | Subscription | Admin calls `setTierPrice()` to enable pricing. Start at $500-5K/mo, reduce over time. |

Revenue source: Platform subscriptions for high-volume credit score queries and credential verification. Costs are flat (~$0.66/year idle burn) regardless of usage.

## File Layout

```
veritas/
├── src/
│   ├── veritas_backend/
│   │   └── main.mo         # Complete canister code
│   ├── mcp.mo               # MCP module
├── docs/
│   ├── guides/
│   │   └── INTEGRATION.md   # Full integration guide
│   ├── examples/
│   │   ├── demos/           # Demo scripts (handshake, MCP, credit scoring)
│   │   └── marketplace/     # Reference marketplace UI + onboarding wizard
│   └── pricing-model.md     # Pricing strategy doc
├── tests/
│   ├── suites/              # 6 test suites, 36+ tests
│   ├── bdd/                 # BDD features + step definitions + POM
│   └── pom/                 # Page Object Model components
├── packages/
│   ├── veritas-verify/      # npm package — verification library
│   └── veritas-agent/       # npm package — agent SDK
└── VERITAS-SPEC.md          # Master specification document
```

## Deploy

```bash
# Mainnet (10 ICP seed required)
dfx canister create --network ic
dfx canister deposit-cycles 10000000000000 <canister-id>
dfx deploy --network ic --no-wallet
dfx canister call <canister-id> initIssuerKey
```
