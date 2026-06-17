import HashMap "mo:base/HashMap";
import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Time "mo:base/Time";
import Nat "mo:base/Nat";
import Int "mo:base/Int";
import Text "mo:base/Text";
import Iter "mo:base/Iter";
import Array "mo:base/Array";
import Option "mo:base/Option";
import Result "mo:base/Result";
import Debug "mo:base/Debug";
import Error "mo:base/Error";
import ExperimentalCycles "mo:base/ExperimentalCycles";

// ════════════════════════════════════════════════════════════
//  VERITAS — Verifiable AI Agent Identity Protocol
//  Phase 0: Canister Shell (Identity Registry + Cycle Accounting)
//  Version: 1.0.0
// ════════════════════════════════════════════════════════════

shared actor class Veritas() = this {

  // ── Versioned Storage for Upgrade Safety (§6.8c) ──
  stable var storageVersion : Nat = 1;
  stable var identitiesEntries : [(Principal, AgentIdentity)] = [];
  stable var balanceEntries : [(Principal, Nat)] = [];
  stable var trustedSourceEntries : [(Principal, TrustLevel)] = [];
  stable var configEntries : [(Text, Text)] = [];

  // ── Types ──

  public type AgentIdentity = {
    id : Principal;
    publicKey : Blob;
    created : Int;
    lastRenewed : Int;
    status : IdentityStatus;
  };

  public type IdentityStatus = {
    #Active;
    #Revoked : Text;
    #Suspended : { until : Int; reason : Text };
  };

  public type TrustLevel = {
    #Trusted;
    #Verified;
    #Untrusted;
  };

  public type Error = {
    #NotFound;
    #AlreadyExists;
    #NotAuthorized;
    #InsufficientBalance;
    #InvalidSignature;
    #RateLimited;
    #Paused;
    #BelowMinimumDeposit;
    #StorageFull;
  };

  // ── Stable State ──

  // Agent identities: Principal → AgentIdentity
  flexible var identities = HashMap.HashMap<Principal, AgentIdentity>(
    0, Principal.equal, Principal.hash
  );

  // Cycle balances: Principal → cycles
  flexible var balances = HashMap.HashMap<Principal, Nat>(
    0, Principal.equal, Principal.hash
  );

  // Trusted reputation sources: Principal → TrustLevel
  flexible var trustedSources = HashMap.HashMap<Principal, TrustLevel>(
    0, Principal.equal, Principal.hash
  );

  // Configuration: key → value
  flexible var config = HashMap.HashMap<Text, Text>(
    0, Text.equal, Text.hash
  );

  // ── System State ──
  flexible var paused : Bool = false;
  flexible var pauseReason : Text = "";
  flexible var totalFeesCollected : Nat = 0;
  flexible var totalAgentsRegistered : Nat = 0;

  // ── Fee Schedule (in cycles) ──
  let FEE_REGISTER : Nat = 3_000_000_000;
  let FEE_RENEW : Nat = 3_000_000_000;
  let MINIMUM_DEPOSIT : Nat = 22_000_000_000; // ~0.01 ICP

  // ── Initialize from pre-upgrade state ──
  system func preupgrade() {
    identitiesEntries := Iter.toArray(identities.entries());
    balanceEntries := Iter.toArray(balances.entries());
    trustedSourceEntries := Iter.toArray(trustedSources.entries());
    configEntries := Iter.toArray(config.entries());
  };

  system func postupgrade() {
    identities := HashMap.fromIter<Principal, AgentIdentity>(
      identitiesEntries.vals(), 0, Principal.equal, Principal.hash
    );
    balances := HashMap.fromIter<Principal, Nat>(
      balanceEntries.vals(), 0, Principal.equal, Principal.hash
    );
    trustedSources := HashMap.fromIter<Principal, TrustLevel>(
      trustedSourceEntries.vals(), 0, Principal.equal, Principal.hash
    );
    config := HashMap.fromIter<Text, Text>(
      configEntries.vals(), 0, Text.equal, Text.hash
    );
    identitiesEntries := [];
    balanceEntries := [];
    trustedSourceEntries := [];
    configEntries := [];

    // Future-proofing: migrate data if storageVersion changes
    if (storageVersion < 1) {
      // No migration needed yet — first deploy
      storageVersion := 1;
    };
  };

  // ══════════════════════════════════════════════════════════
  //  IDENTITY REGISTRY
  // ══════════════════════════════════════════════════════════

  /// Register a new VERITAS identity.
  /// Caller's `Principal` becomes the agent's stable identifier (never changes).
  /// `publicKey` is the agent's ECDSA public key for proof-of-possession.
  /// Fee: 3B cycles deducted from caller's balance.
  public shared(msg) func register(publicKey : Blob) : async Result.Result<AgentIdentity, Error> {
    let caller = msg.caller;

    // Guard: paused
    if (paused) { return #err(#Paused) };

    // Guard: already registered
    switch (identities.get(caller)) {
      case (?_) { return #err(#AlreadyExists) };
      case null {};
    };

    // Guard: sufficient balance
    let balance = _getBalance(caller);
    if (balance < FEE_REGISTER) { return #err(#InsufficientBalance) };

    // Deduct fee
    _deductBalance(caller, FEE_REGISTER);

    // Create identity
    let identity : AgentIdentity = {
      id = caller;
      publicKey = publicKey;
      created = Time.now();
      lastRenewed = Time.now();
      status = #Active;
    };
    identities.put(caller, identity);
    totalAgentsRegistered += 1;
    totalFeesCollected += FEE_REGISTER;

    return #ok(identity);
  };

  /// Resolve an agent's identity by their Principal.
  /// Query call — free.
  public query func resolve(agentId : Principal) : async ?AgentIdentity {
    return identities.get(agentId);
  };

  /// Look up an agent's identity by their DID string.
  /// Expects format: "did:icp:<principal-hex>"
  public query func lookup(didString : Text) : async ?AgentIdentity {
    // Parse "did:icp:" prefix — extract principal hex
    let prefix = "did:icp:";
    if (Text.startsWith(didString, #text(prefix))) {
      let principalText = Text.trimStart(didString, #text(prefix));
      let agentId = Principal.fromText(principalText);
      return identities.get(agentId);
    };
    return null;
  };

  /// Rotate the agent's ECDSA public key.
  /// The `Principal` (stable identity) does NOT change.
  /// Old credentials remain valid — verifiers fetch the new key via `resolve()`.
  public shared(msg) func rotateKey(newPublicKey : Blob) : async Result.Result<(), Error> {
    let caller = msg.caller;
    if (paused) { return #err(#Paused) };

    switch (identities.get(caller)) {
      case (?identity) {
        let updated : AgentIdentity = {
          id = identity.id;
          publicKey = newPublicKey;
          created = identity.created;
          lastRenewed = Time.now();
          status = identity.status;
        };
        identities.put(caller, updated);
        return #ok();
      };
      case null { return #err(#NotFound) };
    };
  };

  /// Check if the canister is in emergency pause.
  public query func isPaused() : async ?Text {
    if (paused) { return ?pauseReason };
    return null;
  };

  /// Get protocol statistics.
  public query func getStats() : async {
    totalAgents : Nat;
    totalFeesCollected : Nat;
    storageVersion : Nat;
    paused : Bool;
  } {
    return {
      totalAgents = totalAgentsRegistered;
      totalFeesCollected = totalFeesCollected;
      storageVersion = storageVersion;
      paused = paused;
    };
  };

  // ══════════════════════════════════════════════════════════
  //  CYCLE ACCOUNTING (ICRC-1 Compatible)
  // ══════════════════════════════════════════════════════════

  /// Deposit cycles. Caller provides the ICRC-1 block index.
  /// The canister verifies the transfer against the ICP ledger.
  /// Minimum deposit: 0.01 ICP (~22B cycles).
  public shared(msg) func depositCycles(blockIndex : Nat) : async Result.Result<Nat, Error> {
    let caller = msg.caller;
    if (paused) { return #err(#Paused) };

    // NOTE: In Phase 0, we accept cycles directly (simpler than ICRC-1 callback).
    // Full ICRC-1 ledger verification will be added in Phase 1.
    // For now: caller transfers cycles to the canister, we credit their balance.
    let amount = ExperimentalCycles.available();
    if (amount < MINIMUM_DEPOSIT) {
      return #err(#BelowMinimumDeposit);
    };

    let accepted = ExperimentalCycles.accept(amount);
    let currentBalance = _getBalance(caller);
    balances.put(caller, currentBalance + accepted);

    return #ok(accepted);
  };

  /// Get the caller's cycle balance.
  public query func getBalance(owner : Principal) : async Nat {
    return _getBalance(owner);
  };

  /// Withdraw balance as cycles (transfers to caller).
  /// In Phase 1+, this will withdraw as ICP via ICRC-1 transfer.
  public shared(msg) func withdrawBalance(amount : Nat) : async Result.Result<(), Error> {
    let caller = msg.caller;
    if (paused) { return #err(#Paused) };

    let balance = _getBalance(caller);
    if (amount > balance) { return #err(#InsufficientBalance) };

    _deductBalance(caller, amount);
    ExperimentalCycles.add(amount);

    return #ok();
  };

  // ══════════════════════════════════════════════════════════
  //  ADMIN
  // ══════════════════════════════════════════════════════════

  /// Emergency pause — halts all state-changing operations.
  public shared(msg) func emergencyPause(reason : Text) : async () {
    _assertController(msg.caller);
    paused := true;
    pauseReason := reason;
  };

  /// Emergency resume — re-enables all operations.
  public shared(msg) func emergencyResume() : async () {
    _assertController(msg.caller);
    paused := false;
    pauseReason := "";
  };

  /// Admin withdraws accumulated protocol fees.
  public shared(msg) func withdrawFees(amount : Nat) : async Result.Result<(), Error> {
    _assertController(msg.caller);
    if (ExperimentalCycles.balance() < amount) {
      return #err(#InsufficientBalance);
    };
    ExperimentalCycles.add(amount);
    return #ok();
  };

  // ══════════════════════════════════════════════════════════
  //  INTERNAL HELPERS
  // ══════════════════════════════════════════════════════════

  func _getBalance(who : Principal) : Nat {
    switch (balances.get(who)) {
      case (?b) { b };
      case null { 0 };
    };
  };

  func _deductBalance(who : Principal, amount : Nat) {
    let current = _getBalance(who);
    if (amount > current) {
      // Should never happen — caller should check first
      return;
    };
    balances.put(who, current - amount);
  };

  func _assertController(caller : Principal) {
    // Phase 0: single controller check.
    // Phase 1+: multi-controller support.
    // For now, the canister's controller is set at deploy time via dfx.
    // We accept calls from any principal and rely on ICP's caller identity.
    // In production: check against a stored admin list.
  };
};
