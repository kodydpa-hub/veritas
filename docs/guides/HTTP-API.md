
# VERITAS HTTP API Reference

Query agent identities, credit scores, and credential status from any chain, any language, any platform. No ICP knowledge required.

## Base URL

```
https://ofoea-eyaaa-aaaab-qab6a-cai.raw.icp0.io
```

This is the playground canister. Mainnet URL will differ.

---

## 1. Check Agent Credit Score

Returns the agent's reputation score (0-850), tier, and factor breakdown.

**Request:**
```bash
curl -s "https://icp-api.io/api/v2/canister/ofoea-eyaaa-aaaab-qab6a-cai/query" \
  -H "Content-Type: application/json" \
  -d '{
    "request_type": "query",
    "sender": "000000000000000000000000000000000000000000000000000000000000000000",
    "canister_id": "ofoea-eyaaa-aaaab-qab6a-cai",
    "method_name": "getCreditScore",
    "arg": []
  }'
```

**Response:**
```json
{
  "score": 650,
  "tier": "Good",
  "factors": [
    { "name": "experience", "value": "42 credentials", "impact": "Positive" },
    { "name": "performance", "value": "0.85 confidence", "impact": "Positive" }
  ]
}
```

**Parameters:** `agentId` — the ICP principal of the agent

---

## 2. Check Credential Status

Verify if a credential is Active, Revoked, or Expired.

**Request:**
```bash
curl -s "https://icp-api.io/api/v2/canister/ofoea-eyaaa-aaaab-qab6a-cai/query" \
  -H "Content-Type: application/json" \
  -d '{
    "request_type": "query",
    "sender": "000000000000000000000000000000000000000000000000000000000000000000",
    "canister_id": "ofoea-eyaaa-aaaab-qab6a-cai",
    "method_name": "checkCredentialStatus",
    "arg": []
  }'
```

**Response:** `Active`, `Revoked`, `Expired`, or `SourceFlagged`

**Parameters:** `credentialId` — the credential ID string

---

## 3. Resolve Agent Identity

Look up an agent's registered public key and DID.

**Request:**
```bash
curl -s "https://icp-api.io/api/v2/canister/ofoea-eyaaa-aaaab-qab6a-cai/query" \
  -H "Content-Type: application/json" \
  -d '{
    "request_type": "query",
    "sender": "000000000000000000000000000000000000000000000000000000000000000000",
    "canister_id": "ofoea-eyaaa-aaaab-qab6a-cai",
    "method_name": "resolve",
    "arg": []
  }'
```

**Response:** Agent identity record with public key, creation date, and status.

**Parameters:** `agentId` — the ICP principal of the agent

---

## 4. MCP Tool Discovery (no auth)

Discover available VERITAS tools for AI agents.

```bash
curl -s "https://ofoea-eyaaa-aaaab-qab6a-cai.raw.icp0.io/mcp/jsonrpc"
```

**Response:** Returns the 4 available MCP tools with their input schemas.

---

## 5. DID Document

```bash
curl -s "https://ofoea-eyaaa-aaaab-qab6a-cai.raw.icp0.io/.well-known/did.json"
```

**Response:** W3C compliant DID document with ECDSA verification method.

---

## 6. Canister Stats

```bash
curl -s "https://icp-api.io/api/v2/canister/ofoea-eyaaa-aaaab-qab6a-cai/query" \
  -H "Content-Type: application/json" \
  -d '{
    "request_type": "query",
    "sender": "000000000000000000000000000000000000000000000000000000000000000000",
    "canister_id": "ofoea-eyaaa-aaaab-qab6a-cai",
    "method_name": "getStats",
    "arg": []
  }'
```

**Response:** Total agents, credentials, fees collected, storage version.

---

## From Any Language

**Python:**
```python
import requests
response = requests.post(
    "https://icp-api.io/api/v2/canister/ofoea-eyaaa-aaaab-qab6a-cai/query",
    json={"request_type": "query", "sender": "0"*64, "canister_id": "ofoea-eyaaa-aaaab-qab6a-cai", "method_name": "getCreditScore", "arg": []}
)
print(response.json())
```

**JavaScript:**
```javascript
const response = await fetch("https://icp-api.io/api/v2/canister/ofoea-eyaaa-aaaab-qab6a-cai/query", {
  method: "POST",
  headers: {"Content-Type": "application/json"},
  body: JSON.stringify({
    request_type: "query",
    sender: "0".repeat(64),
    canister_id: "ofoea-eyaaa-aaaab-qab6a-cai",
    method_name: "getCreditScore",
    arg: []
  })
});
const data = await response.json();
```

---

## Rate Limits

- **Free tier:** 100 queries/day per agent principal
- **No API key required** — no signup, no accounts, no billing
- Rate limit resets daily based on UTC date

---

## Need Help?

- Integration guide: `docs/guides/INTEGRATION.md`
- npm package: `npm install veritas-verify`
- Admin dashboard: `GET /admin`
- GitHub: `github.com/kodydpa-hub/veritas`
- Landing page: `GET /docs`
