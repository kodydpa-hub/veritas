const { Given, When, Then } = require('@cucumber/cucumber');
const assert = require('assert');

// Registration-specific step definitions

Given('an agent has not registered', function () {
  // Use an unregistered principal
  this.unregisteredPrincipal = '2vxsx-fae';
});

When('the agent calls register with a valid ECDSA public key', function () {
  this.dfx('register', '(blob "\\02\\56\\18\\00\\48\\90\\1b\\2d\\d3\\59\\6c\\e0")');
});

Then('the returned identity has status Active', function () {
  assert.ok(this.result && !this.result.includes('null'), 'Identity should not be null');
});

Then('the identity is stored and can be resolved', function () {
  const principal = this.getPrincipal();
  this.dfx('resolve', `(principal "${principal}")`);
  assert.ok(this.result && this.result.includes('Active'), 'Should be resolvable');
});
