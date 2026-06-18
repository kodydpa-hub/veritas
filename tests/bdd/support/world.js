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
      ? `dfx canister --network ${this.network} call ${this.canister} ${method} '${args}' 2>/dev/null`
      : `dfx canister --network ${this.network} call ${this.canister} ${method} 2>/dev/null`;
    try {
      this.result = execSync(cmd, { encoding: 'utf-8', timeout: 15000, maxBuffer: 1024 * 1024 });
      this.lastError = null;
      return this.result;
    } catch (e) {
      this.result = null;
      this.lastError = e.message;
      return null;
    }
  }

  getPrincipal() {
    try {
      const p = execSync(`dfx identity get-principal --network ${this.network} 2>/dev/null`, { encoding: 'utf-8', timeout: 5000 }).trim();
      return p.replace(/\n/g, '').split('\n')[0].trim();
    } catch (e) {
      return '2vxsx-fae';
    }
  }

  resultContains(text) {
    return this.result !== null && this.result.includes(text);
  }

  resultIs(value) {
    return this.result !== null && this.result.trim() === value;
  }
}

setWorldConstructor(VeritasWorld);
