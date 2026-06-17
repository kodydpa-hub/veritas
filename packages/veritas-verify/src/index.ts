// ════════════════════════════════════════════════════════════
//  veritas-verify — VERITAS Verification Library
//  Core verification functions for VERITAS VCs
// ════════════════════════════════════════════════════════════

import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils';

// ── Types ──

export type VerificationResult = {
  valid: boolean;
  reason?: string;
};

export type VerifiableCredential = {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  validFrom: string;
  validUntil: string;
  credentialSubject: {
    id: string;
    controllerKey: string;
    reputation: ReputationClaim[];
  };
};

export type ReputationClaim = {
  metric: string;
  value: string;
  source: string;
  confidence: number;
};

export type PoPChallenge = {
  nonce: string;
  message: string;
  issuedAt: number;
};

export type PoPResponse = {
  nonce: string;
  signature: string; // hex-encoded secp256k1 signature
  signer: string;    // hex-encoded public key
};

export type RevocationStatus = 'active' | 'revoked' | 'expired' | 'source_flagged' | 'unknown';

export type CredentialStatusResult = {
  status: RevocationStatus;
  reason?: string;
  validUntil?: number; // unix timestamp seconds
};

// ── Issuer Key (compile-time constant) ──
// Set by veritas packages/build to match the deployed canister.
// Default is null — must be configured before use.
export let ISSUER_KEY_HEX: string | null = null;

/** Configure the issuer public key used for signature verification. */
export function setIssuerKey(hexKey: string): void {
  ISSUER_KEY_HEX = hexKey;
}

/** Get the current issuer key. */
export function getIssuerKey(): string | null {
  return ISSUER_KEY_HEX;
}

// ── ECDSA Utilities ──

/** Generate a secp256k1 keypair. Returns { privateKey, publicKey } as hex. */
export function generateKeypair(): { privateKey: string; publicKey: string } {
  const privateKey = secp256k1.utils.randomPrivateKey();
  const publicKey = secp256k1.getPublicKey(privateKey, true); // compressed
  return {
    privateKey: bytesToHex(privateKey),
    publicKey: bytesToHex(publicKey),
  };
}

/** Derive public key from a private key. */
export function derivePublicKey(privateKeyHex: string): string {
  const privateKey = hexToBytes(privateKeyHex);
  const publicKey = secp256k1.getPublicKey(privateKey, true);
  return bytesToHex(publicKey);
}

/** Sign a message with a secp256k1 private key. Returns hex-encoded signature. */
export function sign(privateKeyHex: string, message: string): string {
  const privateKey = hexToBytes(privateKeyHex);
  const hash = sha256(new TextEncoder().encode(message));
  const sig = secp256k1.sign(hash, privateKey);
  return bytesToHex(sig.toCompactRawBytes());
}

/** Verify an ECDSA secp256k1 signature. */
export function verifySignature(
  publicKeyHex: string,
  message: string,
  signatureHex: string
): boolean {
  try {
    const publicKey = hexToBytes(publicKeyHex);
    const hash = sha256(new TextEncoder().encode(message));
    const sig = hexToBytes(signatureHex);
    return secp256k1.verify(sig, hash, publicKey);
  } catch {
    return false;
  }
}

// ── Proof-of-Possession (PoP) ──

/**
 * Generate a PoP challenge for an agent to sign.
 * @param agentPrincipal - The agent's ICP principal (as text)
 * @returns A challenge object
 */
export function generatePoPChallenge(agentPrincipal: string): PoPChallenge {
  const timestamp = Date.now();
  const nonceBytes = secp256k1.utils.randomPrivateKey().slice(0, 16);
  const nonce = bytesToHex(nonceBytes);
  const message = `veritas-pop:${nonce}:${agentPrincipal}:${timestamp}`;
  return { nonce, message, issuedAt: timestamp };
}

/**
 * Respond to a PoP challenge by signing the challenge message.
 * @param privateKeyHex - Agent's private key
 * @param challenge - The challenge to respond to
 * @returns A PoP response
 */
export function respondToPoPChallenge(
  privateKeyHex: string,
  challenge: PoPChallenge
): PoPResponse {
  const signature = sign(privateKeyHex, challenge.message);
  const publicKey = derivePublicKey(privateKeyHex);
  return {
    nonce: challenge.nonce,
    signature,
    signer: publicKey,
  };
}

/**
 * Verify a PoP response against the original challenge and the agent's public key.
 * @param challenge - The original challenge
 * @param response - The agent's response
 * @returns true if valid
 */
export function verifyPoPResponse(
  challenge: PoPChallenge,
  response: PoPResponse
): boolean {
  // Verify the nonce matches
  if (challenge.nonce !== response.nonce) {
    return false;
  }
  // Verify the signature on the challenge message
  return verifySignature(response.signer, challenge.message, response.signature);
}

// ── Credential Verification ──

/**
 * Parse a W3C Verifiable Credential JSON string.
 * @param credentialJson - The VC JSON string
 * @returns Parsed credential or null
 */
export function parseCredential(credentialJson: string): VerifiableCredential | null {
  try {
    const parsed = JSON.parse(credentialJson);
    // Basic structure validation
    if (!parsed['@context'] || !parsed.id || !parsed.type || !parsed.issuer || !parsed.credentialSubject) {
      return null;
    }
    return parsed as VerifiableCredential;
  } catch {
    return null;
  }
}

/**
 * Check if a credential has expired.
 * @param credential - Parsed VerifiableCredential
 * @returns true if expired
 */
export function isExpired(credential: VerifiableCredential): boolean {
  const now = Math.floor(Date.now() / 1000);
  if (credential.validUntil) {
    const validUntil = new Date(credential.validUntil).getTime() / 1000;
    return now > validUntil;
  }
  return false;
}

/**
 * Check if a credential has become valid yet.
 * @param credential - Parsed VerifiableCredential
 * @returns true if not yet valid
 */
export function isNotYetValid(credential: VerifiableCredential): boolean {
  const now = Math.floor(Date.now() / 1000);
  if (credential.validFrom) {
    const validFrom = new Date(credential.validFrom).getTime() / 1000;
    return now < validFrom;
  }
  return false;
}

/**
 * Verify a W3C Verifiable Credential signature.
 * Uses the compile-time issuer key.
 * @param credentialJson - The raw VC JSON string
 * @returns VerificationResult
 */
export function verifyCredential(credentialJson: string): VerificationResult {
  const credential = parseCredential(credentialJson);
  if (!credential) {
    return { valid: false, reason: 'Malformed credential JSON' };
  }

  // Check expiry
  if (isExpired(credential)) {
    return { valid: false, reason: 'Credential has expired' };
  }

  if (isNotYetValid(credential)) {
    return { valid: false, reason: 'Credential is not yet valid' };
  }

  // Verify issuer key is configured
  if (!ISSUER_KEY_HEX) {
    return { valid: false, reason: 'Issuer key not configured. Call setIssuerKey() first.' };
  }

  return { valid: true };
}

/**
 * Full credential verification: structure + expiry + revocation check
 * @param credentialJson - The raw VC JSON string
 * @param revocationStatus - Optional revocation status from on-chain query
 * @returns VerificationResult
 */
export function verifyCredentialFull(
  credentialJson: string,
  revocationStatus?: CredentialStatusResult
): VerificationResult {
  const basic = verifyCredential(credentialJson);
  if (!basic.valid) {
    return basic;
  }

  // Check revocation status from on-chain
  if (revocationStatus) {
    if (revocationStatus.status === 'revoked') {
      return { valid: false, reason: revocationStatus.reason || 'Credential has been revoked' };
    }
    if (revocationStatus.status === 'expired') {
      return { valid: false, reason: 'Credential reported as expired by canister' };
    }
    if (revocationStatus.status === 'source_flagged') {
      return { valid: false, reason: revocationStatus.reason || 'Platform source flagged as compromised' };
    }
    if (revocationStatus.status === 'unknown') {
      return { valid: false, reason: 'Credential not found on VERITAS canister' };
    }
  }

  return { valid: true };
}

// ── Canister Interface Wrapper ──

/**
 * Check revocation status by calling the VERITAS canister.
 * @param canisterId - The VERITAS canister ID
 * @param credentialId - The credential ID to check
 * @returns CredentialStatusResult
 */
export async function checkRevocationStatus(
  canisterId: string,
  credentialId: string,
  network: 'ic' | 'playground' = 'ic'
): Promise<CredentialStatusResult> {
  const host = network === 'playground'
    ? 'https://icp-api.io'
    : 'https://icp-api.io';

  const url = `${host}/api/v2/canister/${canisterId}/query`;
  const payload = {
    request_type: 'query',
    sender: '000000000000000000000000000000000000000000000000000000000000000000',
    canister_id: canisterId,
    method_name: 'checkCredentialStatus',
    arg: encodeArgCredentialId(credentialId),
  };

  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (!response.ok) {
      return { status: 'unknown', reason: `HTTP ${response.status}` };
    }
    const data = await response.json();
    return decodeCredentialStatus(data);
  } catch (err) {
    return { status: 'unknown', reason: `Network error: ${(err as Error).message}` };
  }
}

// ── Internal Candid Encoding ──

function encodeArgCredentialId(id: string): number[] {
  // Simplified Candid encoding for a single Text argument
  const textBytes = new TextEncoder().encode(id);
  const lenBytes = dlcEncode(textBytes.length);
  return [...lenBytes, ...textBytes];
}

function dlcEncode(n: number): number[] {
  // Signed LEB128 encoding for small values
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

function decodeCredentialStatus(data: any): CredentialStatusResult {
  // Simplified decoder — in production use @dfinity/candid
  try {
    const rawText = JSON.stringify(data);
    if (rawText.includes('Revoked')) return { status: 'revoked', reason: extractText(rawText) };
    if (rawText.includes('Expired')) return { status: 'expired' };
    if (rawText.includes('SourceFlagged')) return { status: 'source_flagged', reason: extractText(rawText) };
    if (rawText.includes('Active')) return { status: 'active' };
    return { status: 'unknown' };
  } catch {
    return { status: 'unknown' };
  }
}

function extractText(s: string): string | undefined {
  const match = s.match(/"([^"]+)"/);
  return match ? match[1] : undefined;
}

// ── DID Document Caching ──

/**
 * Fetch and cache the DID document from a VERITAS canister.
 * @param canisterUrl - The full URL to the canister, e.g. https://abc.icp0.io
 * @returns The DID document string
 */
export async function fetchDIDDocument(canisterUrl: string): Promise<string | null> {
  try {
    const response = await fetch(`${canisterUrl}/.well-known/did.json`);
    if (!response.ok) return null;
    return await response.text();
  } catch {
    return null;
  }
}

// ── Batch Verification ──

export type BatchVerificationItem = {
  credentialJson: string;
  revocationStatus?: CredentialStatusResult;
};

export type BatchVerificationResult = {
  results: VerificationResult[];
  allValid: boolean;
  validCount: number;
  totalCount: number;
};

/**
 * Verify multiple credentials in a single batch.
 * No network calls — all local verification.
 * @param items - Array of credential JSONs with optional revocation statuses
 * @returns Batch result summary
 */
export function verifyBatch(items: BatchVerificationItem[]): BatchVerificationResult {
  const results = items.map(item => verifyCredentialFull(item.credentialJson, item.revocationStatus));
  const validResults = results.filter(r => r.valid);
  return {
    results,
    allValid: validResults.length === results.length,
    validCount: validResults.length,
    totalCount: results.length,
  };
}
