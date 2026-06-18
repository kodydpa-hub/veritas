# 🛡️ VERITAS

**Verifiable AI Agent Identity & Reputation Protocol on ICP**

Self-sovereign, W3C-compliant identity for AI agents. Register once, build reputation across platforms, take it anywhere.

## Quick Facts

| | |
|---|---|
| **Status** | ✅ All 7 phases complete. Ready for mainnet. |
| **Version** | v1.5.0 |
| **Playground** | `6qg6m-4aaaa-aaaab-qacqq-cai` |
| **Seed cost** | 10 ICP (~$4.50) covers Year 1 |
| **Pricing** | Year 1 free. Agent registration free forever. |

## For AI Agents

```bash
npm install veritas-agent
```

```typescript
const agent = new Agent();
agent.generateKeys('principal');
const proof = agent.createHandshakeProof();
```

**Or discover via MCP:** `/mcp/jsonrpc` — works with Claude Desktop, Cline, Goose.

## For Platforms

```bash
npm install veritas-verify
```

```typescript
const result = verifyCredential(credentialJson);
// Or query credit score via canister
```

## Quick Start

1. Open the [onboarding wizard](docs/examples/marketplace/onboard.html)
2. Choose a plan (Free/Starter/Pro/Enterprise)
3. Deposit ICP cycles → tier auto-assigns
4. Start verifying agents

## All Phases Complete

| Phase | What | Cost |
|:-----:|------|:----:|
| 1 | Credential minting + PoP + W3C VCs | ~$15 |
| 2 | veritas-verify + veritas-agent npm | $0 |
| 3 | Credit scoring (6-factor, 0-850) | ~$5 |
| 4 | Rate limiting + mint queue | ~$3 |
| 5 | Reputation sources + admin dashboard | ~$5 |
| 6 | MCP server on-canister | $0 |
| 7 | Docs + demos + subscription management | ~$5 |
| **Total** | | **~$33 (dev + test on playground)** |

## Key Links

| Resource | URL |
|----------|-----|
| **Playground canister** | `6qg6m-4aaaa-aaaab-qacqq-cai` |
| **Admin dashboard** | `GET /admin` |
| **MCP endpoint** | `GET /mcp/jsonrpc` |
| **Docs & onboarding** | `GET /docs` → GitHub |
| **Integration guide** | `docs/guides/INTEGRATION.md` |
| **Architecture** | `ARCHITECTURE.md` |
| **Full spec** | `VERITAS-SPEC.md` |
| **npm** | [`veritas-verify`](https://www.npmjs.com/package/veritas-verify) · [`veritas-agent`](https://www.npmjs.com/package/veritas-agent) |
| **GitHub** | [kodydpa-hub/veritas](https://github.com/kodydpa-hub/veritas) |

## License

MIT — both npm packages and all canister code are open source.
