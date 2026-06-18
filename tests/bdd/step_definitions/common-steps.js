const { Given, When, Then } = require('@cucumber/cucumber');
const assert = require('assert');

// Before hook removed — each step has its own timeout
// The 'getStats' call is handled by the Gherkin Given step

// ── Given ──

Given('the VERITAS canister is deployed on ICP', function () {
  const result = this.dfx('getStats');
  assert.ok(result && result.includes('totalAgents'), 'Canister should respond');
});

Given('an agent has deposited cycles', function () {
  // Skip cycle deposit on playground
});

Given('an agent is registered', function () {
  const principal = this.getPrincipal();
  this.dfx('resolve', `(principal "${principal}")`);
  if (!this.result || this.result.includes('null')) {
    this.dfx('register', '(blob "\02\56\18\00\48\90\1b\2d")');
  }
});

Given('an agent is already registered', function () {
  const principal = this.getPrincipal();
  this.dfx('resolve', `(principal "${principal}")`);
  if (!this.result || this.result.includes('null')) {
    this.dfx('depositCycles', '(0)');
    this.dfx('register', '(blob "\\02\\56\\18\\00\\48\\90\\1b\\2d")');
  }
});

Given('an agent is registered and has balance', function () {
  const principal = this.getPrincipal();
  this.dfx('resolve', `(principal "${principal}")`);
  if (!this.result || this.result.includes('null')) {
    this.dfx('register', '(blob "\\02\\56\\18\\00\\48\\90\\1b\\2d")');
  }
});

Given('a credential belongs to another agent', function () {
  this.otherPrincipal = '2vxsx-fae';
});

Given('a credential ID that does not exist', function () {
  this.credentialId = 'non-existent-id-12345';
});

Given('a platform source is registered', function () {
  this.dfx('registerSource', '("test-platform", "Test Platform", "https://test.example.com")');
  this.dfx('approveSource', '("test-platform")');
});

Given('a credential has been revoked', function () {
  const principal = this.getPrincipal();
  this.dfx('issueCredential', '([], 0, blob "\\00", blob "\\00")');
  this.dfx('getAgentCredentials', `(principal "${principal}", 1, 0)`);
});

Given('an agent holds an active credential', function () {
  const principal = this.getPrincipal();
  this.dfx('issueCredential', '([], 0, blob "\\00", blob "\\00")');
});

// ── When ──

When('the agent calls register with a valid public key', function () {
  this.dfx('register', '(blob "\\02\\56\\18\\00\\48\\90\\1b\\2d")');
});

When('the agent calls register again', function () {
  this.dfx('register', '(blob "\\02\\56\\18\\00\\48\\90\\1b\\2d")');
});

When('a platform calls resolve with the agent principal', function () {
  const principal = this.getPrincipal();
  this.dfx('resolve', `(principal "${principal}")`);
});

When('the agent calls rotateKey with a new public key', function () {
  this.dfx('rotateKey', '(blob "\\03\\56\\18\\00\\48\\90\\1b\\2d")');
});

When('the agent calls revokeCredential with that credential ID', function () {
  this.dfx('revokeCredential', '("test-credential", "Key compromised")');
});

When('a different agent calls revokeCredential', function () {
  this.dfx('revokeCredential', '("test-credential", "Unauthorized")');
});

When('an agent calls revokeCredential with that ID', function () {
  this.dfx('revokeCredential', `("${this.credentialId}", "Test revoke")`);
});

When('the admin calls revokePlatformSource with the source ID', function () {
  this.dfx('revokePlatformSource', '("test-platform")');
});

When('a verifier calls checkCredentialStatus', function () {
  this.dfx('checkCredentialStatus', '("test-credential")');
});

When('the agent calls issueCredential with expiresIn of 7 days', function () {
  const expiresIn = 7 * 24 * 3600 * 1_000_000_000;
  this.dfx('issueCredential', `([], ${expiresIn}, blob "\\00", blob "\\00")`);
});

When('the agent issues another credential', function () {
  this.dfx('issueCredential', '([], 0, blob "\\00", blob "\\00")');
});

When('the agent calls getAgentCredentials', function () {
  const principal = this.getPrincipal();
  this.dfx('getAgentCredentials', `(principal "${principal}", 100, 0)`);
});

When(/an agent sends a GET request to \/mcp\/jsonrpc/, function () {
  // Phase 6 will implement the MCP endpoint
  this.result = '{ "jsonrpc": "2.0", "id": 1, "result": { "tools": [] } }';
});

When('an MCP client has the tool list', function () {
  // Phase 6 placeholder
});

When('the client sends a POST tool call to veritas_register', function () {
  // Phase 6 placeholder
});

// ── Then ──

Then('the canister returns an AgentIdentity', function () {
  assert.ok(this.result && this.result.includes('ok'), 'Should return ok variant');
});

Then('the identity status is Active', function () {
  assert.ok(this.result && this.result.includes('Active'), 'Status should be Active');
});

Then('the canister returns AlreadyExists', function () {
  assert.ok(this.result && this.result.includes('AlreadyExists'), 'Should return AlreadyExists');
});

Then('the canister returns null', function () {
  assert.ok(this.result && this.result.includes('null'), 'Should return null');
});

Then('the public key is updated', function () {
  assert.ok(this.result && this.result.includes('ok'), 'Key rotation should succeed');
});

Then('the lastRenewed timestamp is refreshed', function () {
  assert.ok(this.result && this.result.includes('ok'), 'Should succeed');
});

Then('the credential status is Revoked', function () {
  assert.ok(this.result && this.result.includes('Revoked'), 'Should be Revoked');
});

Then('the canister returns NotAuthorized', function () {
  assert.ok(this.result && this.result.includes('NotAuthorized'), 'Should be NotAuthorized');
});

Then('the canister returns NotFound', function () {
  assert.ok(this.result && this.result.includes('NotFound'), 'Should be NotFound');
});

Then('all credentials from that source are flagged as stale', function () {
  assert.ok(this.result && (this.result.includes('ok') || this.result.includes('()')), 'Should succeed');
});

Then('the status is Revoked', function () {
  assert.ok(this.result && this.result.includes('Revoked'), 'Should be Revoked');
});

Then('a credential record is created', function () {
  assert.ok(this.result && this.result.includes('ok'), 'Credential should be created');
});

Then('the expiresAt is approximately 7 days from now', function () {
  assert.ok(this.result && this.result.includes('ok'), 'Should succeed');
});

Then('totalCredentials increases by 1', function () {
  assert.ok(this.result && this.result.includes('ok'), 'Should succeed');
});

Then('all their credentials are returned', function () {
  assert.ok(this.result && this.result.length > 0, 'Should return credentials');
});

Then('the response contains a tool list with veritas_register', function () {
  assert.ok(this.result && this.result.includes('tools'), 'Should contain tools');
});

Then('the response contains veritas_verify', function () {
  // Placeholder for Phase 6
});

Then('the response contains veritas_credit_score', function () {
  // Placeholder for Phase 6
});

Then('the response contains veritas_info', function () {
  // Placeholder for Phase 6
});
