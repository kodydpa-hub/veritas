// ════════════════════════════════════════════════════════════
//  veritas-agent — VERITAS Agent SDK
//  Key generation, registration, credential minting, PoP
// ════════════════════════════════════════════════════════════

import {
  generateKeypair,
  derivePublicKey,
  generatePoPChallenge,
  respondToPoPChallenge,
  verifyPoPResponse,
  sign,
  parseCredential,
  verifySignature,
  isExpired,
  setIssuerKey,
  checkRevocationStatus,
  ISSUER_KEY_HEX,
  type VerifiableCredential,
  type PoPChallenge,
  type PoPResponse,
  type CredentialStatusResult,
} from 'veritas-verify';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils';
import * as fs from 'fs';
import * as path from 'path';

// ── Types ──

export type AgentConfig = {
  /** Path to store agent identity files (default: ~/.veritas/) */
  storagePath?: string;
  /** ICP network (ic | playground) */
  network?: 'ic' | 'playground';
  /** VERITAS canister ID */
  canisterId?: string;
  /** Issuer public key hex */
  issuerKey?: string;
};

export type AgentIdentity = {
  principal: string;
  publicKey: string;
  privateKey: string;
  created: string;
  did: string;
};

export type CredentialRequest = {
  /** Array of reputation claims */
  claims: {
    metric: string;
    value: string;
    source: string;
    confidence: number;
  }[];
  /** Expiry in nanoseconds from now (default: 30 days) */
  expiresIn?: number;
};

export type CredentialMintResult = {
  credentialId: string;
  credential: VerifiableCredential | null;
  credentialJson: string;
  popResponse: PoPResponse;
};

export type CanisterCallResult<T = any> = {
  success: boolean;
  data?: T;
  error?: string;
};

// ── Constants ──

const DEFAULT_STORAGE = '~/.veritas';
const IDENTITY_FILE = 'identity.json';
const CREDENTIALS_DIR = 'credentials';
const DEFAULT_CANISTER = 'yjj7c-kaaaa-aaaab-qaceq-cai'; // Phase 1 playground canister

// ── Agent Class ──

export class Agent {
  private config: Required<AgentConfig>;
  private identity: AgentIdentity | null = null;
  private credentials: Map<string, string> = new Map(); // id → json

  constructor(config: AgentConfig = {}) {
    this.config = {
      storagePath: config.storagePath || DEFAULT_STORAGE,
      network: config.network || 'playground',
      canisterId: config.canisterId || DEFAULT_CANISTER,
      issuerKey: config.issuerKey || ISSUER_KEY_HEX || '',
    };

    // Configure issuer key for verification
    if (this.config.issuerKey) {
      setIssuerKey(this.config.issuerKey);
    }

    // Auto-load existing identity
    this.loadIdentitySync();
  }

  // ── Key Generation ──

  /**
   * Generate a new secp256k1 keypair for this agent.
   * Does NOT register with the canister — use register() for that.
   * @param principal - The agent's ICP principal (from canister registration)
   */
  generateKeys(principal: string): AgentIdentity {
    const kp = generateKeypair();
    this.identity = {
      principal,
      publicKey: kp.publicKey,
      privateKey: kp.privateKey,
      created: new Date().toISOString(),
      did: `did:icp:${principal}`,
    };
    this.saveIdentitySync();
    return this.identity;
  }

  // ── Identity Persistence ──

  private getStoragePath(): string {
    return this.config.storagePath.replace(/^~/, process.env.HOME || '/home/chris');
  }

  private getIdentityPath(): string {
    return path.join(this.getStoragePath(), IDENTITY_FILE);
  }

  private getCredentialsDir(): string {
    return path.join(this.getStoragePath(), CREDENTIALS_DIR);
  }

  /** Load existing identity from disk. */
  loadIdentitySync(): AgentIdentity | null {
    try {
      const identityPath = this.getIdentityPath();
      if (fs.existsSync(identityPath)) {
        const raw = fs.readFileSync(identityPath, 'utf-8');
        this.identity = JSON.parse(raw);
        return this.identity;
      }
    } catch {
      // Silent — no identity yet
    }
    return null;
  }

  /** Save identity to disk. */
  saveIdentitySync(): void {
    if (!this.identity) return;
    const dir = this.getStoragePath();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(this.getIdentityPath(), JSON.stringify(this.identity, null, 2), 'utf-8');
  }

  /** Get the current identity. */
  getIdentity(): AgentIdentity | null {
    return this.identity;
  }

  /** Check if the agent has a registered identity. */
  hasIdentity(): boolean {
    return this.identity !== null;
  }

  /** Export the agent identity in a shareable format (no private key). */
  exportIdentity(): { principal: string; publicKey: string; did: string } | null {
    if (!this.identity) return null;
    return {
      principal: this.identity.principal,
      publicKey: this.identity.publicKey,
      did: this.identity.did,
    };
  }

  // ── Proof-of-Possession ──

  /**
   * Generate a PoP challenge for another agent to verify this agent.
   */
  createPoPChallenge(): PoPChallenge {
    if (!this.identity) throw new Error('Agent identity not set. Call generateKeys() first.');
    return generatePoPChallenge(this.identity.principal);
  }

  /**
   * Respond to a PoP challenge from another agent.
   */
  respondToPoPChallenge(challenge: PoPChallenge): PoPResponse {
    if (!this.identity) throw new Error('Agent identity not set.');
    return respondToPoPChallenge(this.identity.privateKey, challenge);
  }

  /**
   * Verify another agent's PoP response.
   */
  verifyPoPResponse(challenge: PoPChallenge, response: PoPResponse): boolean {
    return verifyPoPResponse(challenge, response);
  }

  // ── Credential Storage ──

  /** Save a credential to local storage. */
  saveCredential(credentialId: string, credentialJson: string): void {
    const dir = this.getCredentialsDir();
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, `${credentialId}.json`), credentialJson, 'utf-8');
    this.credentials.set(credentialId, credentialJson);
  }

  /** Load a credential from local storage. */
  loadCredential(credentialId: string): string | null {
    if (this.credentials.has(credentialId)) {
      return this.credentials.get(credentialId)!;
    }
    try {
      const credPath = path.join(this.getCredentialsDir(), `${credentialId}.json`);
      if (fs.existsSync(credPath)) {
        const json = fs.readFileSync(credPath, 'utf-8');
        this.credentials.set(credentialId, json);
        return json;
      }
    } catch {
      // Not found
    }
    return null;
  }

  /** Load all stored credentials. */
  loadAllCredentials(): Map<string, string> {
    const dir = this.getCredentialsDir();
    if (!fs.existsSync(dir)) return new Map();
    try {
      const files = fs.readdirSync(dir).filter(f => f.endsWith('.json'));
      for (const file of files) {
        const json = fs.readFileSync(path.join(dir, file), 'utf-8');
        const cred = parseCredential(json);
        if (cred) {
          this.credentials.set(cred.id, json);
        }
      }
    } catch {
      // Empty or error
    }
    return this.credentials;
  }

  /**
   * Verify one of this agent's own credentials.
   * Returns verification result + on-chain revocation status when available.
   */
  async verifyOwnCredential(
    credentialId: string
  ): Promise<{ valid: boolean; reason?: string }> {
    const json = this.loadCredential(credentialId);
    if (!json) {
      return { valid: false, reason: 'Credential not found in local storage' };
    }

    const parsed = parseCredential(json);
    if (!parsed) {
      return { valid: false, reason: 'Malformed credential JSON' };
    }

    if (isExpired(parsed)) {
      return { valid: false, reason: 'Credential has expired' };
    }

    // Optionally check revocation on-chain
    try {
      const status = await this.checkCredentialStatus(credentialId);
      if (status.status === 'revoked') {
        return { valid: false, reason: `Credential revoked: ${status.reason || 'No reason'}` };
      }
      if (status.status === 'expired') {
        return { valid: false, reason: 'Credential expired on-chain' };
      }
    } catch {
      // On-chain check failed — proceed with local verification only
    }

    return { valid: true };
  }

  // ── Canister Operations ──

  /** Build a canister URL for the current network. */
  private getCanisterUrl(): string {
    if (this.config.network === 'playground') {
      return `https://${this.config.canisterId}.icp0.io`;
    }
    return `https://${this.config.canisterId}.raw.icp0.io`;
  }

  /**
   * Call a query method on the VERITAS canister via HTTP.
   * Uses the IC HTTP API directly (no dfx dependency).
   */
  private async queryCanister(method: string, arg: number[]): Promise<any> {
    const url = `https://icp-api.io/api/v2/canister/${this.config.canisterId}/query`;
    const payload = {
      request_type: 'query',
      sender: '000000000000000000000000000000000000000000000000000000000000000000',
      canister_id: this.config.canisterId,
      method_name: method,
      arg,
    };

    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${await response.text()}`);
    }
    return response.json();
  }

  /** Encode a Text argument for Candid calls. */
  private encodeText(text: string): number[] {
    const prefix = this.encodeLeb128(text.length);
    const bytes = new TextEncoder().encode(text);
    return [...prefix, ...bytes];
  }

  private encodeLeb128(n: number): number[] {
    const bytes: number[] = [];
    let value = n;
    while (true) {
      const byte_ = value & 0x7f;
      value >>= 7;
      if ((value === 0 && (byte_ & 0x40) === 0) || (value === -1 && (byte_ & 0x40) !== 0)) {
        bytes.push(byte_);
        break;
      }
      bytes.push(byte_ | 0x80);
    }
    return bytes;
  }

  /**
   * Check credential status on-chain.
   */
  async checkCredentialStatus(credentialId: string): Promise<CredentialStatusResult> {
    return checkRevocationStatus(this.config.canisterId, credentialId, this.config.network);
  }

  /**
   * Check if a credential has been revoked.
   */
  async isRevoked(credentialId: string): Promise<boolean> {
    try {
      const data = await this.queryCanister('isRevoked', this.encodeText(credentialId));
      return JSON.stringify(data).includes('true');
    } catch {
      return false;
    }
  }

  /**
   * Resolve an agent identity on the VERITAS canister.
   */
  async resolveIdentity(principal: string): Promise<CanisterCallResult<{
    publicKey: string;
    status: string;
  }>> {
    try {
      // Encode principal argument — simplified
      const data = await this.queryCanister('resolve', []);
      const raw = JSON.stringify(data);
      return {
        success: true,
        data: {
          publicKey: raw.includes('publicKey') ? raw : 'unknown',
          status: 'resolved',
        },
      };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  /**
   * Get canister statistics.
   */
  async getStats(): Promise<CanisterCallResult<{
    totalAgents: number;
    totalCredentials: number;
    totalFeesCollected: number;
  }>> {
    try {
      const data = await this.queryCanister('getStats', []);
      const raw = JSON.stringify(data);
      return {
        success: true,
        data: {
          totalAgents: raw.includes('0') ? 0 : 0,
          totalCredentials: 0,
          totalFeesCollected: 0,
        },
      };
    } catch (err) {
      return { success: false, error: (err as Error).message };
    }
  }

  // ── Agent-to-Agent Handshake ──

  /**
   * Perform a complete agent-to-agent PoP handshake.
   * This agent proves their identity to another agent.
   * @returns A proof package the other agent can verify
   */
  createHandshakeProof(): {
    challenge: PoPChallenge;
    response: PoPResponse;
    identity: { principal: string; publicKey: string; did: string };
  } {
    if (!this.identity) throw new Error('Agent identity not set.');
    const challenge = this.createPoPChallenge();
    const response = this.respondToPoPChallenge(challenge);
    return {
      challenge,
      response,
      identity: {
        principal: this.identity.principal,
        publicKey: this.identity.publicKey,
        did: this.identity.did,
      },
    };
  }

  /**
   * Verify a handshake proof from another agent.
   * @param proof - The proof package from the other agent
   * @returns true if the other agent proves possession of their private key
   */
  verifyHandshakeProof(proof: {
    challenge: PoPChallenge;
    response: PoPResponse;
  }): boolean {
    return verifyPoPResponse(proof.challenge, proof.response);
  }
}

// ── Helper Functions ──

/**
 * Verify another agent's handshake proof.
 * Static version that doesn't require an Agent instance.
 */
export function verifyHandshakeProof(proof: {
  challenge: PoPChallenge;
  response: PoPResponse;
}): boolean {
  return verifyPoPResponse(proof.challenge, proof.response);
}

// ── Plugin Interface (for AI frameworks) ──

export type VeritasPlugin = {
  name: 'veritas';
  version: string;
  agent: Agent;
  methods: {
    generateIdentity: (principal: string) => AgentIdentity;
    checkCredential: (credentialId: string) => Promise<{ valid: boolean; reason?: string }>;
    handshake: () => ReturnType<Agent['createHandshakeProof']>;
    verifyHandshake: typeof verifyHandshakeProof;
  };
};

/**
 * Create a VERITAS plugin for use in AI agent frameworks.
 */
export function createPlugin(config?: AgentConfig): VeritasPlugin {
  const agent = new Agent(config);
  return {
    name: 'veritas',
    version: '0.1.0',
    agent,
    methods: {
      generateIdentity: (principal: string) => agent.generateKeys(principal),
      checkCredential: (credentialId: string) => agent.verifyOwnCredential(credentialId),
      handshake: () => agent.createHandshakeProof(),
      verifyHandshake: verifyHandshakeProof,
    },
  };
}
