const { setWorldConstructor } = require('@cucumber/cucumber');
const { execSync } = require('child_process');

class VeritasWorld {
  constructor({ parameters }) {
    this.network = parameters.network || 'playground';
    this.canister = 'veritas_backend';
    this.result = null;
    this.lastError = null;
    this.identity = null;
  }

  dfx(method, args = '') {
    const cmd = args
      ? `cd /home/chris/.openclaw/workspace/veritas && dfx canister --network ${this.network} call ${this.canister} ${method} '${args}' 2>/dev/null`
      : `cd /home/chris/.openclaw/workspace/veritas && dfx canister --network ${this.network} call ${this.canister} ${method} 2>/dev/null`;
    try {
      this.result = execSync(cmd, { encoding: 'utf-8', timeout: 15000 });
      this.lastError = null;
      return this.result;
    } catch (e) {
      this.result = null;
      this.lastError = e.message;
      return null;
    }
  }

  getPrincipal() {
    const p = execSync(`dfx identity get-principal --network ${this.network}`, { encoding: 'utf-8', timeout: 5000 }).trim();
    return p.replace(/\n/g, '').replace(/\r/g, '');
  }

  resultContains(text) {
    return this.result !== null && this.result.includes(text);
  }

  resultIs(value) {
    return this.result !== null && this.result.trim() === value;
  }
}

setWorldConstructor(VeritasWorld);
