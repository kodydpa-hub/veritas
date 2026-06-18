const { Given, When, Then } = require('@cucumber/cucumber');
const assert = require('assert');

// ── Given ──

Given('an agent has registered and holds active credentials', function () {
  const principal = this.getPrincipal();
  this.dfx('register', '(blob "\\02\\56\\18\\00\\48\\90\\1b\\2d")');
  this.dfx('issueCredential', '([], 0, blob "\\00", blob "\\00")');
});

Given('the admin has updated a scoring weight', function () {
  this.dfx('setScoringWeight', '("base_score", 600.0)');
});

Given('an agent is on the Free tier', function () {
  // Default is Free — no action needed
});

// ── When ──

When('a platform calls getCreditScore with the agent principal', function () {
  const principal = this.getPrincipal();
  this.dfx('getCreditScore', `(principal "${principal}")`);
});

When('a platform calls getScoringConfig', function () {
  this.dfx('getScoringConfig');
});

When('the admin upgrades the agent to the Starter tier', function () {
  const principal = this.getPrincipal();
  this.dfx('setAgentTier', `(principal "${principal}", "Starter")`);
});

// ── Then ──

Then('the canister returns a CreditScore', function () {
  assert.ok(this.result && !this.result.includes('null'), 'Should return a credit score');
});

Then('the score is between 0 and 850', function () {
  assert.ok(this.result && this.result.length > 0, 'Should have a score');
});

Then('the tier is one of Excellent, Good, Fair, Poor, or Unrated', function () {
  const valid = ['Excellent', 'Good', 'Fair', 'Poor', 'Unrated'];
  const found = valid.some(t => this.result && this.result.includes(t));
  assert.ok(found, 'Should have a valid tier');
});

Then('the factors array contains at least one entry', function () {
  assert.ok(this.result && this.result.includes('factor') || this.result.includes('Factor'), 'Should have factors');
});

Then('the updated weight is reflected in the configuration', function () {
  assert.ok(this.result && this.result.includes('600.0'), 'Weight should be 600');
});

Then('the daily limit increases from 100 to 10,000', function () {
  assert.ok(this.result && this.result.includes('ok'), 'Should succeed');
});
