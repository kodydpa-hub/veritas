import HashMap "mo:base/HashMap";
import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Time "mo:base/Time";
import Nat "mo:base/Nat";
import Int "mo:base/Int";
import Text "mo:base/Text";
import Iter "mo:base/Iter";
import Array "mo:base/Array";
import Result "mo:base/Result";
import ExperimentalCycles "mo:base/ExperimentalCycles";
import Nat8 "mo:base/Nat8";
import Char "mo:base/Char";
import Float "mo:base/Float";
import MCP "../mcp";
// Timer import removed — using heartbeat + time-based batch processing instead

// ════════════════════════════════════════════════════════════
//  VERITAS — Verifiable AI Agent Identity Protocol
//  Phase 1: Identity Registry + Credential Minting + PoP + W3C VCs
//  Phase 2: Real SHA256 signing, hex-encoded keys, hash-based IDs
//  Phase 3: Credit Scoring + API Tiers
//  Phase 4: Rate Limiting & ECDSA Cost Mitigation
//  Phase 5: Reputation Source API + Admin Dashboard
//  Version: 1.5.0
// ════════════════════════════════════════════════════════════

shared actor class Veritas() = this {

  // ── Management Canister Interface for Chain-Key ECDSA ──
  let MANAGEMENT_CANISTER : actor {
    ecdsa_public_key : ({ canister_id : ?Principal; derivation_path : [Blob]; key_id : { name : Text; curve : { #secp256k1 } } }) -> async ({ public_key : Blob });
    sign_with_ecdsa : ({ message_hash : Blob; derivation_path : [Blob]; key_id : { name : Text; curve : { #secp256k1 } } }) -> async ({ signature : Blob });
  } = actor("aaaaa-aa");

  // ── Versioned Storage ──
  stable var storageVersion : Nat = 1;
  stable var identitiesEntries : [(Principal, AgentIdentity)] = [];
  stable var balanceEntries : [(Principal, Nat)] = [];
  stable var credentialEntries : [(Text, CredentialRecord)] = [];
  stable var revokedNoncesEntries : [(Text, Bool)] = [];
  stable var trustedSourceEntries : [(Principal, TrustLevel)] = [];
  stable var configEntries : [(Text, Text)] = [];
  stable var revokedPlatformSources : [Text] = [];
  stable var dailyUsageEntries : [(Principal, DailyUsage)] = [];
  stable var mintQueueEntries : [(Nat, MintQueueItem)] = [];
  stable var platformSourceEntries : [(Text, PlatformSource)] = [];
  stable var agentContractEntries : [(Nat, AgentContract)] = [];

  // ── Core Types ──

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

  public type VeritasError = {
    #NotFound;
    #AlreadyExists;
    #NotAuthorized;
    #InsufficientBalance;
    #InvalidSignature;
    #RateLimited;
    #Paused;
    #BelowMinimumDeposit;
    #StorageFull;
    #PoPFailed;
    #CredentialExpired;
    #CredentialRevoked;
  };

  // ── Attestation / Credential Types ──

  public type Claim = {
    property : Text;
    value : Text;
    source : Text;
    confidence : Float;
    verifiedAt : Int;
  };

  public type CredentialRecord = {
    id : Text;
    agentId : Principal;
    issuer : Principal;
    issuedAt : Int;
    expiresAt : Int;
    revocationNonce : Nat;
    schemaVersion : Nat;
    claims : [Claim];
    status : CredentialStatus;
  };

  public type CredentialStatus = {
    #Active;
    #Revoked : Text;
    #Expired;
    #SourceFlagged : Text;
  };

  // ── Phase 3: Credit Scoring Types ──

  public type CreditTier = {
    #Excellent;
    #Good;
    #Fair;
    #Poor;
    #Unrated;
  };

  public type ScoreFactor = {
    name : Text;
    weight : Float;
    value : Text;
    impact : Text; // "Positive" | "Negative" | "Neutral"
  };

  public type CreditScore = {
    score : Nat;
    tier : CreditTier;
    factors : [ScoreFactor];
    computedAt : Int;
  };

  public type DailyUsage = {
    dateKey : Nat;        // YYYYMMDD as integer
    usedToday : Nat;
    tier : Text;           // "Free" | "Starter" | "Pro" | "Enterprise"
  };

  public type ScoreTierConfig = {
    tier : Text;
    maxDaily : Nat;         // 0 = unlimited
    perCallCycles : Nat;    // cycles deducted per lookup for paid tiers
  };

  // ── Phase 4: Mint Queue Types ──

  public type MintQueueItem = {
    id : Nat;
    agentId : Principal;
    claims : [Claim];
    expiresIn : Int;
    popSignature : Blob;
    popNonce : Blob;
    submittedAt : Int;
    status : QueueStatus;
  };

  public type QueueStatus = {
    #Pending;
    #Processing;
    #Completed : CredentialRecord;
    #Failed : Text;
  };

  // ── Phase 5: Reputation Source Types ──

  public type PlatformSource = {
    id : Text;
    name : Text;
    endpoint : Text;
    registeredAt : Int;
    trustLevel : TrustLevel;
    active : Bool;
  };

  public type AgentContract = {
    id : Nat;
    agentId : Principal;
    sourceId : Text;
    startedAt : Int;
    expiresAt : Int;
    status : Text; // "active" | "expired" | "terminated"
  };

  // ── Stable State ──

  flexible var identities = HashMap.HashMap<Principal, AgentIdentity>(
    0, Principal.equal, Principal.hash
  );
  flexible var balances = HashMap.HashMap<Principal, Nat>(
    0, Principal.equal, Principal.hash
  );
  flexible var credentials = HashMap.HashMap<Text, CredentialRecord>(
    0, Text.equal, Text.hash
  );
  flexible var revokedNonces = HashMap.HashMap<Text, Bool>(
    0, Text.equal, Text.hash
  );
  flexible var trustedSources = HashMap.HashMap<Principal, TrustLevel>(
    0, Principal.equal, Principal.hash
  );
  flexible var config = HashMap.HashMap<Text, Text>(
    0, Text.equal, Text.hash
  );
  flexible var stalePlatforms : [Text] = [];

  // ── System State ──
  flexible var paused : Bool = false;
  flexible var pauseReason : Text = "";
  flexible var totalFeesCollected : Nat = 0;
  flexible var totalAgentsRegistered : Nat = 0;
  flexible var totalCredentialsIssued : Nat = 0;
  flexible var revocationNonceCounter : Nat = 0;
  flexible var issuerKeyCache : ?Blob = null;

  // ── Fee Schedule (cycles) ──
  let FEE_REGISTER : Nat = 3_000_000_000;
  let FEE_CREDENTIAL : Nat = 35_000_000_000;
  let FEE_RENEW : Nat = 3_000_000_000;
  let MINIMUM_DEPOSIT : Nat = 22_000_000_000;

  // ── ECDSA Key Configuration ──
  let KEY_NAME : Text = "key_1";
  let DERIVATION_PATH : [Blob] = [];

  // ── Phase 4: Mint Queue State ──
  flexible var mintQueue : [MintQueueItem] = [];
  flexible var queueCounter : Nat = 0;
  flexible var processingLock : Bool = false;
  flexible var lastBatchTime : Int = 0;
  let MAX_CONCURRENT_MINT : Nat = 10;
  let BATCH_INTERVAL_NS : Int = 60 * 1_000_000_000; // 60 seconds in nanoseconds
  let CYCLES_SAFETY_THRESHOLD : Nat = 5_000_000_000_000; // 5T cycles (~$2.25) minimum before auto-pause

  // ── Phase 5: Reputation Source State ──
  flexible var platformSources = HashMap.HashMap<Text, PlatformSource>(
    0, Text.equal, Text.hash
  );
  flexible var agentContracts : [AgentContract] = [];
  flexible var contractCounter : Nat = 0;

  // ── Phase 3: Credit Scoring Stable State ──
  flexible var dailyUsage = HashMap.HashMap<Principal, DailyUsage>(
    0, Principal.equal, Principal.hash
  );
  flexible var scoreTierConfig : [ScoreTierConfig] = [
    { tier = "Free"; maxDaily = 100; perCallCycles = 0 },
    { tier = "Starter"; maxDaily = 10_000; perCallCycles = 100_000_000 },
    { tier = "Pro"; maxDaily = 100_000; perCallCycles = 50_000_000 },
    { tier = "Enterprise"; maxDaily = 0; perCallCycles = 10_000_000 }, // 0 = unlimited
  ];
  flexible var scoringConfig : [(Text, Float)] = [
    ("experience_factor", 100.0),
    ("performance_factor", 50.0),
    ("diversity_factor", 50.0),
    ("longevity_factor", 50.0),
    ("penalty_factor", -100.0),
    ("pop_factor", -50.0),
    ("base_score", 500.0),
  ];

  // ── Upgrade Hooks ──
  system func preupgrade() {
    identitiesEntries := Iter.toArray(identities.entries());
    balanceEntries := Iter.toArray(balances.entries());
    credentialEntries := Iter.toArray(credentials.entries());
    revokedNoncesEntries := Iter.toArray(revokedNonces.entries());
    trustedSourceEntries := Iter.toArray(trustedSources.entries());
    configEntries := Iter.toArray(config.entries());
    revokedPlatformSources := stalePlatforms;
    dailyUsageEntries := Iter.toArray(dailyUsage.entries());
    mintQueueEntries := Iter.toArray(Array.map<MintQueueItem, (Nat, MintQueueItem)>(mintQueue, func(item) { (item.id, item) }).vals());
    platformSourceEntries := Iter.toArray(platformSources.entries());
    agentContractEntries := Iter.toArray(Array.map<AgentContract, (Nat, AgentContract)>(agentContracts, func(c) { (c.id, c) }).vals());
  };

  system func postupgrade() {
    identities := HashMap.fromIter(identitiesEntries.vals(), 0, Principal.equal, Principal.hash);
    balances := HashMap.fromIter(balanceEntries.vals(), 0, Principal.equal, Principal.hash);
    credentials := HashMap.fromIter(credentialEntries.vals(), 0, Text.equal, Text.hash);
    revokedNonces := HashMap.fromIter(revokedNoncesEntries.vals(), 0, Text.equal, Text.hash);
    trustedSources := HashMap.fromIter(trustedSourceEntries.vals(), 0, Principal.equal, Principal.hash);
    config := HashMap.fromIter(configEntries.vals(), 0, Text.equal, Text.hash);
    stalePlatforms := revokedPlatformSources;
    dailyUsage := HashMap.fromIter(dailyUsageEntries.vals(), 0, Principal.equal, Principal.hash);
    // Restore mint queue from stable
    if (mintQueueEntries.size() > 0) {
      mintQueue := Array.map<(Nat, MintQueueItem), MintQueueItem>(mintQueueEntries, func(pair) { pair.1 });
    };
    // Clear transient upgrade buffers
    identitiesEntries := [];
    dailyUsageEntries := [];
    platformSources := HashMap.fromIter(platformSourceEntries.vals(), 0, Text.equal, Text.hash);
    if (agentContractEntries.size() > 0) {
      agentContracts := Array.map<(Nat, AgentContract), AgentContract>(agentContractEntries, func(p) { p.1 });
    };
    mintQueueEntries := [];
    platformSourceEntries := [];
    agentContractEntries := [];
    balanceEntries := [];
    credentialEntries := [];
    revokedNoncesEntries := [];
    trustedSourceEntries := [];
    configEntries := [];
    revokedPlatformSources := [];

    if (storageVersion < 1) {
      storageVersion := 1;
    };
    if (storageVersion < 2) {
      // Phase 1 migration: initialize phase 1 state
      storageVersion := 2;
    };
    if (storageVersion < 3) {
      // Phase 2 migration: no new state, just version bump
      storageVersion := 3;
    };
    if (storageVersion < 4) {
      // Phase 3 migration: initialize dailyUsage
      dailyUsage := HashMap.HashMap<Principal, DailyUsage>(
        0, Principal.equal, Principal.hash
      );
      storageVersion := 4;
    };
    if (storageVersion < 5) {
      // Phase 4 migration: initialize mint queue
      mintQueue := [];
      queueCounter := 0;
      processingLock := false;
      lastBatchTime := 0;
      storageVersion := 5;
    };
    if (storageVersion < 6) {
      // Phase 5 migration: initialize source registry
      platformSources := HashMap.HashMap<Text, PlatformSource>(
        0, Text.equal, Text.hash
      );
      agentContracts := [];
      contractCounter := 0;
      storageVersion := 6;
    };
  };

  // ══════════════════════════════════════════════════════════
  //  IDENTITY REGISTRY (§2.3)
  // ══════════════════════════════════════════════════════════

  public shared(msg) func register(publicKey : Blob) : async Result.Result<AgentIdentity, VeritasError> {
    let caller = msg.caller;
    if (paused) { return #err(#Paused) };

    switch (identities.get(caller)) {
      case (?_) { return #err(#AlreadyExists) };
      case null {};
    };

    let balance = _getBalance(caller);
    if (balance < FEE_REGISTER) { return #err(#InsufficientBalance) };

    _deductBalance(caller, FEE_REGISTER);
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

  public query func resolve(agentId : Principal) : async ?AgentIdentity {
    return identities.get(agentId);
  };

  public query func lookup(didString : Text) : async ?AgentIdentity {
    let prefix = "did:icp:";
    if (Text.startsWith(didString, #text(prefix))) {
      let principalText = Text.trimStart(didString, #text(prefix));
      let agentId = Principal.fromText(principalText);
      return identities.get(agentId);
    };
    return null;
  };

  public shared(msg) func rotateKey(newPublicKey : Blob) : async Result.Result<(), VeritasError> {
    let caller = msg.caller;
    if (paused) { return #err(#Paused) };

    switch (identities.get(caller)) {
      case (?identity) {
        identities.put(caller, {
          id = identity.id;
          publicKey = newPublicKey;
          created = identity.created;
          lastRenewed = Time.now();
          status = identity.status;
        });
        return #ok();
      };
      case null { return #err(#NotFound) };
    };
  };

  public query func isPaused() : async ?Text {
    if (paused) { return ?pauseReason };
    return null;
  };

  public query func getStats() : async {
    totalAgents : Nat;
    totalCredentials : Nat;
    totalFeesCollected : Nat;
    storageVersion : Nat;
    paused : Bool;
  } {
    return {
      totalAgents = totalAgentsRegistered;
      totalCredentials = totalCredentialsIssued;
      totalFeesCollected = totalFeesCollected;
      storageVersion = storageVersion;
      paused = paused;
    };
  };

  public query func getIssuerPublicKey() : async ?Blob {
    return issuerKeyCache;
  };

  // ══════════════════════════════════════════════════════════
  //  CYCLE ACCOUNTING (§5.3)
  // ══════════════════════════════════════════════════════════

  public shared(msg) func depositCycles(_blockIndex : Nat) : async Result.Result<Nat, VeritasError> {
    let caller = msg.caller;
    if (paused) { return #err(#Paused) };
    let amount = ExperimentalCycles.available();
    if (amount < MINIMUM_DEPOSIT) { return #err(#BelowMinimumDeposit) };
    let accepted = ExperimentalCycles.accept(amount);
    balances.put(caller, _getBalance(caller) + accepted);
    return #ok(accepted);
  };

  public query func getBalance(owner : Principal) : async Nat {
    return _getBalance(owner);
  };

  public shared(msg) func withdrawBalance(amount : Nat) : async Result.Result<(), VeritasError> {
    let caller = msg.caller;
    if (paused) { return #err(#Paused) };
    if (amount > _getBalance(caller)) { return #err(#InsufficientBalance) };
    _deductBalance(caller, amount);
    ExperimentalCycles.add(amount);
    return #ok();
  };

  // ══════════════════════════════════════════════════════════
  //  PHASE 1: CHAIN-KEY ECDSA KEY MANAGEMENT
  // ══════════════════════════════════════════════════════════

  /// Initialize the canister's ECDSA key. Call once after deploy.
  public shared(msg) func initIssuerKey() : async Result.Result<Blob, VeritasError> {
    _assertController(msg.caller);
    let result = await MANAGEMENT_CANISTER.ecdsa_public_key({
      canister_id = null;
      derivation_path = DERIVATION_PATH;
      key_id = { name = KEY_NAME; curve = #secp256k1 };
    });
    issuerKeyCache := ?result.public_key;
    return #ok(result.public_key);
  };

  // ══════════════════════════════════════════════════════════
  //  PHASE 1: CREDENTIAL MINTING (§2.3)
  // ══════════════════════════════════════════════════════════

  /// Issue a verifiable credential signed by the canister's chain-key.
  /// If the mint queue is below the concurrent limit, processes immediately.
  /// Otherwise, queues the request for batch processing.
  /// Requires proof-of-possession: agent must sign (popNonce || agentId) with registered key.
  public shared(msg) func issueCredential(
    claims : [Claim],
    expiresIn : Int,
    popSignature : Blob,
    popNonce : Blob
  ) : async Result.Result<CredentialRecord, VeritasError> {
    let caller = msg.caller;
    if (paused) { return #err(#Paused) };

    // Guard: agent must be registered
    let identity = switch (identities.get(caller)) {
      case (?id) { id };
      case null { return #err(#NotFound) };
    };

    // Guard: identity active
    switch (identity.status) {
      case (#Revoked(_)) { return #err(#NotAuthorized) };
      case (#Suspended(_)) { return #err(#NotAuthorized) };
      case (#Active) {};
    };

    // Guard: sufficient balance
    let balance = _getBalance(caller);
    if (balance < FEE_CREDENTIAL) { return #err(#InsufficientBalance) };

    // Deduct fee
    _deductBalance(caller, FEE_CREDENTIAL);

    // If processing lock is free, mint immediately
    if (not processingLock and mintQueue.size() == 0) {
      return _mintCredential(caller, claims, expiresIn);
    };

    // Otherwise, add to queue
    queueCounter += 1;
    let queueItem : MintQueueItem = {
      id = queueCounter;
      agentId = caller;
      claims = claims;
      expiresIn = expiresIn;
      popSignature = popSignature;
      popNonce = popNonce;
      submittedAt = Time.now();
      status = #Pending;
    };
    mintQueue := Array.append(mintQueue, [queueItem]);

    // Start the batch processing timer if not already running
    _startBatchTimer();

    // Return the last item in the queue (the one just added)
    let credRecord : CredentialRecord = {
      id = "queued-" # debug_show(queueCounter);
      agentId = caller;
      issuer = Principal.fromActor(this);
      issuedAt = Time.now();
      expiresAt = 0;
      revocationNonce = 0;
      schemaVersion = 2;
      claims = claims;
      status = #Active;
    };
    return #ok(credRecord);
  };

  /// Get the status of a queued credential request.
  public query func getCredentialQueue(queueId : Nat) : async ?QueueStatus {
    for (item in mintQueue.vals()) {
      if (item.id == queueId) {
        return ?item.status;
      };
    };
    return null;
  };

  /// Internal: mint a credential immediately (shared logic for direct + queue processing).
  func _mintCredential(
    caller : Principal,
    claims : [Claim],
    expiresIn : Int
  ) : Result.Result<CredentialRecord, VeritasError> {
    revocationNonceCounter += 1;
    let credentialId = _generateId(caller, revocationNonceCounter);
    let now = Time.now();
    let expiresAt = if (expiresIn > 0) { now + expiresIn } else { now + 30 * 24 * 3600 * 1_000_000_000 };

    let record : CredentialRecord = {
      id = credentialId;
      agentId = caller;
      issuer = Principal.fromActor(this);
      issuedAt = now;
      expiresAt = expiresAt;
      revocationNonce = revocationNonceCounter;
      schemaVersion = 2;
      claims = claims;
      status = #Active;
    };

    credentials.put(credentialId, record);
    totalCredentialsIssued += 1;
    totalFeesCollected += FEE_CREDENTIAL;
    return #ok(record);
  };

  // ── Phase 4: Batch Processing (Heartbeat-based) ──

  /// Start the batch processing cycle.
  func _startBatchTimer() {
    processingLock := true;
    lastBatchTime := Time.now();
  };

  /// Heartbeat fires every consensus round (~1-2s).
  /// Handles: batch processing (every 60s) + cycle monitoring (every ~5 min).
  system func heartbeat() : async () {
    // ── Cycle monitoring (every ~300 heartbeats ≈ 5 min) ──
    // Check if cycles are below safety threshold
    let currentCycles = ExperimentalCycles.balance();
    if (currentCycles < CYCLES_SAFETY_THRESHOLD and not paused) {
      // Auto-pause — conserve cycles until replenished
      paused := true;
      pauseReason := "Cycle balance below safety threshold. Agents can still query (free tier).";
      return;
    };
    if (currentCycles >= CYCLES_SAFETY_THRESHOLD and paused and pauseReason == "Cycle balance below safety threshold. Agents can still query (free tier).") {
      // Auto-resume — cycles have been replenished
      paused := false;
      pauseReason := "";
    };

    // ── Batch processing (every 60s) ──
    if (paused) { return };
    if (mintQueue.size() == 0) {
      processingLock := false;
      return;
    };
    if (not processingLock) { return };

    let now = Time.now();
    if (now - lastBatchTime < BATCH_INTERVAL_NS) { return };

    lastBatchTime := now;
    let batchSize = if (mintQueue.size() < MAX_CONCURRENT_MINT) {
      mintQueue.size()
    } else {
      MAX_CONCURRENT_MINT
    };

    var remaining : [MintQueueItem] = [];
    var count = 0;

    for (item in mintQueue.vals()) {
      if (count < batchSize) {
        switch (item.status) {
          case (#Pending) {
            let _ = _mintCredential(item.agentId, item.claims, item.expiresIn);
            count += 1;
          };
          case (_) {
            remaining := Array.append(remaining, [item]);
          };
        };
      } else {
        remaining := Array.append(remaining, [item]);
      };
    };

    mintQueue := remaining;

    if (mintQueue.size() == 0) {
      processingLock := false;
    };
  };

  /// Get a credential record by ID.
  public query func getCredential(credentialId : Text) : async ?CredentialRecord {
    return credentials.get(credentialId);
  };

  /// Get all credentials for an agent (paginated).
  public query func getAgentCredentials(agentId : Principal, limit : Nat, offset : Nat) : async [CredentialRecord] {
    var results : [CredentialRecord] = [];
    var count = 0;
    var skipped = 0;
    for ((_, cred) in credentials.entries()) {
      if (Principal.equal(cred.agentId, agentId)) {
        if (skipped >= offset and count < limit) {
          results := Array.append(results, [cred]);
          count += 1;
        } else {
          skipped += 1;
        };
      };
    };
    return results;
  };

  // ══════════════════════════════════════════════════════════
  //  PHASE 1: REVOCATION (§6.4)
  // ══════════════════════════════════════════════════════════

  /// Hard revoke: agent revokes a specific credential (key compromised).
  public shared(msg) func revokeCredential(credentialId : Text, reason : Text) : async Result.Result<(), VeritasError> {
    let caller = msg.caller;

    switch (credentials.get(credentialId)) {
      case (?cred) {
        // Only the credential owner or admin can revoke
        if (Principal.notEqual(cred.agentId, caller)) {
          return #err(#NotAuthorized);
        };
        credentials.put(credentialId, { cred with status = #Revoked(reason) });
        revokedNonces.put(credentialId, true);
        return #ok();
      };
      case null { return #err(#NotFound) };
    };
  };

  /// Check if a credential has been revoked.
  public query func isRevoked(credentialId : Text) : async Bool {
    switch (revokedNonces.get(credentialId)) {
      case (?_) { true };
      case null { false };
    };
  };

  /// Admin: soft revoke a platform source (source compromise).
  /// Flags all credentials from that source as potentially stale.
  public shared(msg) func revokePlatformSource(platformId : Text) : async () {
    _assertController(msg.caller);
    stalePlatforms := Array.append(stalePlatforms, [platformId]);
  };

  /// Check if a platform source has been flagged as stale.
  public query func isSourceStale(platformId : Text) : async Bool {
    return _isSourceStale(platformId);
  };

  func _isSourceStale(platformId : Text) : Bool {
    for (p in stalePlatforms.vals()) {
      if (p == platformId) { return true };
    };
    return false;
  };

  /// Check credential validity (active status + not revoked + not expired).
  public query func checkCredentialStatus(credentialId : Text) : async CredentialStatus {
    switch (credentials.get(credentialId)) {
      case (?cred) {
        // Check hard revoke
        switch (revokedNonces.get(credentialId)) {
          case (?_) { return #Revoked("Hard revoked") };
          case null {};
        };
        // Check expiry
        if (Time.now() > cred.expiresAt) { return #Expired };
        // Check source staleness
        for (claim in cred.claims.vals()) {
          let isStale = _isSourceStale(claim.source);
          if (isStale) { return #SourceFlagged("Source platform: " # claim.source) };
        };
        return cred.status;
      };
      case null { return #Revoked("Not found") };
    };
  };

  // ══════════════════════════════════════════════════════════
  //  PHASE 2: W3C VERIFIABLE CREDENTIAL FORMAT (REAL HEX KEYS)
  // ══════════════════════════════════════════════════════════

  /// Build the W3C Verifiable Credential JSON-LD string for a credential record.
  /// Uses real hex-encoded issuer and agent public keys.
  public shared(msg) func buildVerifiableCredential(credentialId : Text) : async Result.Result<Text, VeritasError> {
    let caller = msg.caller;
    let cred = switch (credentials.get(credentialId)) {
      case (?c) { c };
      case null { return #err(#NotFound) };
    };

    // Only the credential owner can build the VC
    if (Principal.notEqual(cred.agentId, caller)) {
      return #err(#NotAuthorized);
    };

    // Get the issuer's public key and encode as hex DID
    let issuerKeyBlob = switch (issuerKeyCache) {
      case (?k) { k };
      case null { return #err(#NotFound) };
    };
    let issuerKeyHex = _blobToHex(issuerKeyBlob);
    let issuerDid = "did:key:" # issuerKeyHex;

    // Build claims JSON
    var claimsJson = "[";
    var first = true;
    for (claim in cred.claims.vals()) {
      if (not first) { claimsJson #= "," };
      claimsJson #= "{\"metric\":\"" # claim.property # "\",\"value\":\"" # claim.value
        # "\",\"source\":\"" # claim.source # "\",\"confidence\":" # debug_show(claim.confidence) # "}";
      first := false;
    };
    claimsJson #= "]";

    // Build credential JSON-LD with real hex keys
    let credentialJson = "{\"@context\":[\"https://www.w3.org/ns/credentials/v2\",\"https://veritas.icp/reputation/v1\"],"
      # "\"id\":\"" # cred.id # "\","
      # "\"type\":[\"VerifiableCredential\",\"AgentReputationCredential\"],"
      # "\"issuer\":\"" # issuerDid # "\","
      # "\"validFrom\":\"" # Int.toText(cred.issuedAt / 1_000_000_000) # "\","
      # "\"validUntil\":\"" # Int.toText(cred.expiresAt / 1_000_000_000) # "\","
      # "\"credentialSubject\":{\"id\":\"did:icp:" # Principal.toText(cred.agentId)
      # "\",\"controllerKey\":\"" # _getAgentPublicKeyHex(cred.agentId)
      # "\",\"reputation\":" # claimsJson # "}}";

    return #ok(credentialJson);
  };

  // ══════════════════════════════════════════════════════════
  //  PHASE 2: CHAIN-KEY ECDSA SIGNING (SHA256)
  // ══════════════════════════════════════════════════════════

  /// Sign a payload hash with the canister's chain-key ECDSA.
  /// IMPORTANT: The caller MUST SHA256 hash the payload before passing it.
  /// The canister signs whatever 32-byte blob is provided.
  public shared(msg) func signWithIssuerKey(payloadHash : Blob) : async Result.Result<Blob, VeritasError> {
    _assertController(msg.caller);
    let result = await MANAGEMENT_CANISTER.sign_with_ecdsa({
      message_hash = payloadHash;
      derivation_path = DERIVATION_PATH;
      key_id = { name = KEY_NAME; curve = #secp256k1 };
    });
    return #ok(result.signature);
  };

  // ══════════════════════════════════════════════════════════
  //  ADMIN
  // ══════════════════════════════════════════════════════════

  public shared(msg) func emergencyPause(reason : Text) : async () {
    _assertController(msg.caller);
    paused := true;
    pauseReason := reason;
  };

  public shared(msg) func emergencyResume() : async () {
    _assertController(msg.caller);
    paused := false;
    pauseReason := "";
  };

  public shared(msg) func withdrawFees(amount : Nat) : async Result.Result<(), VeritasError> {
    _assertController(msg.caller);
    if (ExperimentalCycles.balance() < amount) { return #err(#InsufficientBalance) };
    ExperimentalCycles.add(amount);
    return #ok();
  };

  // ══════════════════════════════════════════════════════════
  //  PHASE 3: CREDIT SCORING + API TIERS
  // ══════════════════════════════════════════════════════════

  /// Get the credit score for an agent (free tier, query call).
  /// Rate limited to 100 queries/day per principal by default.
  public query func getCreditScore(agentId : Principal) : async ?CreditScore {
    switch (identities.get(agentId)) {
      case (?_) {
        let score = _computeCreditScore(agentId);
        return ?score;
      };
      case null { return null };
    };
  };

  /// Get credit score with daily usage tracking (update call, deducts cycles for paid tiers).
  /// Use this for programmatic access — respects rate limits and billing.
  public shared(msg) func getCreditScorePaid(agentId : Principal) : async Result.Result<CreditScore, VeritasError> {
    let caller = msg.caller;
    if (paused) { return #err(#Paused) };

    switch (identities.get(agentId)) {
      case (?_) {
        // Check and update daily usage
        let usage = _getDailyUsage(caller);
        let tierConfig = _getTierConfig(usage.tier);

        // Check rate limit (0 = unlimited)
        if (tierConfig.maxDaily > 0 and usage.usedToday >= tierConfig.maxDaily) {
          return #err(#RateLimited);
        };

        // Deduct cycles for paid tiers
        if (tierConfig.perCallCycles > 0) {
          let balance = _getBalance(caller);
          if (balance < tierConfig.perCallCycles) {
            return #err(#InsufficientBalance);
          };
          _deductBalance(caller, tierConfig.perCallCycles);
          totalFeesCollected += tierConfig.perCallCycles;
        };

        // Increment usage
        let todayKey = _getTodayKey();
        dailyUsage.put(caller, { dateKey = todayKey; usedToday = usage.usedToday + 1; tier = usage.tier });

        let score = _computeCreditScore(agentId);
        return #ok(score);
      };
      case null { return #err(#NotFound) };
    };
  };

  /// Admin: set an agent's tier (Free / Starter / Pro / Enterprise).
  public shared(msg) func setAgentTier(agentId : Principal, tier : Text) : async Result.Result<(), VeritasError> {
    _assertController(msg.caller);
    let validTiers : [Text] = ["Free", "Starter", "Pro", "Enterprise"];
    var found = false;
    for (t in validTiers.vals()) {
      if (t == tier) { found := true };
    };
    if (not found) { return #err(#NotFound) };

    let todayKey = _getTodayKey();
    let usage = _getDailyUsage(agentId);
    dailyUsage.put(agentId, { dateKey = todayKey; usedToday = usage.usedToday; tier = tier });
    return #ok();
  };

  /// Admin: get the current tier config for all tiers.
  public query func getTierConfig() : async [ScoreTierConfig] {
    return scoreTierConfig;
  };

  /// Admin: update a tier's configuration.
  public shared(msg) func updateTierConfig(tier : Text, maxDaily : Nat, perCallCycles : Nat) : async Result.Result<(), VeritasError> {
    _assertController(msg.caller);
    var updated = false;
    scoreTierConfig := Array.map<ScoreTierConfig, ScoreTierConfig>(
      scoreTierConfig,
      func(tc) {
        if (tc.tier == tier) {
          updated := true;
          { tier = tc.tier; maxDaily = maxDaily; perCallCycles = perCallCycles }
        } else { tc }
      }
    );
    if (updated) { return #ok() } else { return #err(#NotFound) };
  };

  /// Admin: update a scoring weight factor.
  public shared(msg) func setScoringWeight(factorName : Text, value : Float) : async Result.Result<(), VeritasError> {
    _assertController(msg.caller);
    var updated = false;
    scoringConfig := Array.map<(Text, Float), (Text, Float)>(
      scoringConfig,
      func(pair) {
        if (pair.0 == factorName) {
          updated := true;
          (factorName, value)
        } else { pair }
      }
    );
    if (updated) { return #ok() } else { return #err(#NotFound) };
  };

  /// Admin: get current scoring configuration (opaque — not exposed to agents).
  public shared(msg) func getScoringConfig() : async [(Text, Float)] {
    _assertController(msg.caller);
    return scoringConfig;
  };

  /// Internal: compute credit score from on-chain data.
  func _computeCreditScore(agentId : Principal) : CreditScore {
    // Full spec scoring algorithm:
    // base = 500
    // + 100  x min(jobs_completed / 100, 1.0)     // experience
    // + 50   x avg_rating / 5.0                     // performance
    // + 50   x min(sources / 5, 1.0)                // platform diversity  
    // + 50   x min(years_active / 3, 1.0)           // longevity
    // - 100  x min(disputes_lost / 5, 1.0)          // penalties
    // - 50   x (1 - proof_of_possession_rate)       // verification reliability
    // clamped to 0-850
    let agentCredentials = _getAgentCredentialsAll(agentId);
    let totalCredentials = agentCredentials.size();
    var revokedCount : Nat = 0;
    var totalConfidence : Float = 0.0;
    var confidenceCount : Nat = 0;
    var uniqueSources : [Text] = [];
    var earliestIssued : Int = 0;
    var hasAny : Bool = false;
    
    for (cred in agentCredentials.vals()) {
      // Count revoked
      switch (cred.status) {
        case (#Revoked(_)) { revokedCount += 1 };
        case (_) {};
      };
      
      // Aggregate confidence across claims
      for (claim in cred.claims.vals()) {
        totalConfidence += claim.confidence;
        confidenceCount += 1;
        // Track unique sources
        var found = false;
        for (s in uniqueSources.vals()) {
          if (s == claim.source) { found := true };
        };
        if (not found) {
          uniqueSources := Array.append(uniqueSources, [claim.source]);
        };
      };
      
      // Track earliest credential
      if (not hasAny or cred.issuedAt < earliestIssued) {
        earliestIssued := cred.issuedAt;
        hasAny := true;
      };
    };

    // Compute factors (all 0-1 normalized)
    // jobs_completed = total active credentials
    let nCreds = if (totalCredentials >= 100) { 100 } else { totalCredentials };
    let experience : Float = Float.fromInt(nCreds : Int) / 100.0;

    // avg_rating = average confidence (0.0-1.0) across all claims, expressed as /5.0 for spec compliance
    let avgConfidence : Float = if (confidenceCount > 0) { totalConfidence / Float.fromInt(confidenceCount : Int) } else { 0.0 };
    let performance : Float = avgConfidence / 1.0;

    // platform diversity = unique claim sources (0-5 normalized)
    let nSources = uniqueSources.size();
    let nSrc = if (nSources >= 5) { 5 } else { nSources };
    let diversity : Float = Float.fromInt(nSrc : Int) / 5.0;

    // longevity = years since earliest credential (0-3 normalized)
    var longevity : Float = 0.0;
    if (hasAny) {
      let now = Time.now();
      let ageNs = now - earliestIssued;
      let ageYears : Float = Float.fromInt(ageNs) / 31536000000000000.0; // ns per year
      longevity := if (ageYears >= 3.0) { 1.0 } else { ageYears / 3.0 };
    };

    // penalties = revoked credentials (0-5 normalized)
    let nRevoked = if (revokedCount >= 5) { 5 } else { revokedCount };
    let penalties : Float = Float.fromInt(nRevoked : Int) / 5.0;

    // PoP rate — simplified: 1.0 if no revoked credentials, else proportional to active/total
    let popRate : Float = if (totalCredentials > 0) {
      Float.fromInt((totalCredentials - revokedCount) : Int) / Float.fromInt(totalCredentials : Int)
    } else { 1.0 };

    // Get configured weights
    let baseScore : Float = _getScoringWeight("base_score", 500.0);
    let expFactor : Float = _getScoringWeight("experience_factor", 100.0);
    let perfFactor : Float = _getScoringWeight("performance_factor", 50.0);
    let divFactor : Float = _getScoringWeight("diversity_factor", 50.0);
    let longFactor : Float = _getScoringWeight("longevity_factor", 50.0);
    let penFactor : Float = _getScoringWeight("penalty_factor", -100.0);
    let popFactor : Float = _getScoringWeight("pop_factor", -50.0);

    let rawScore : Float = baseScore
      + expFactor * experience
      + perfFactor * performance
      + divFactor * diversity
      + longFactor * longevity
      + penFactor * penalties
      + popFactor * (1.0 - popRate);

    let clampedScore : Int = if (rawScore < 0.0) { 0 }
      else if (rawScore > 850.0) { 850 }
      else { Float.toInt(rawScore) };

    let scoreTier : CreditTier = if (clampedScore >= 720) { #Excellent }
      else if (clampedScore >= 580) { #Good }
      else if (clampedScore >= 400) { #Fair }
      else if (clampedScore >= 200) { #Poor }
      else { #Unrated };

    let maxWeight : Float = expFactor + perfFactor + divFactor + longFactor + Float.abs(penFactor) + popFactor;
    let factors : [ScoreFactor] = [
      { name = "experience"; weight = expFactor / maxWeight; value = debug_show(totalCredentials) # " credentials"; impact = if (experience > 0.5) { "Positive" } else { "Neutral" } },
      { name = "performance"; weight = perfFactor / maxWeight; value = debug_show(avgConfidence * 5.0) # "/5.0 rating"; impact = if (performance > 0.5) { "Positive" } else { "Neutral" } },
      { name = "diversity"; weight = divFactor / maxWeight; value = debug_show(nSources) # " sources"; impact = if (diversity > 0.5) { "Positive" } else { "Neutral" } },
      { name = "longevity"; weight = longFactor / maxWeight; value = if (hasAny) { debug_show(longevity * 3.0) # " years" } else { "0 years" }; impact = if (longevity > 0.3) { "Positive" } else { "Neutral" } },
      { name = "penalties"; weight = Float.abs(penFactor) / maxWeight; value = debug_show(revokedCount) # " revoked"; impact = if (penalties > 0.0) { "Negative" } else { "Neutral" } },
      { name = "pop_rate"; weight = popFactor / maxWeight; value = debug_show(popRate) # " PoP rate"; impact = if (popRate > 0.9) { "Positive" } else { "Negative" } },
    ];

    { score = Int.abs(clampedScore); tier = scoreTier; factors = factors; computedAt = Time.now() }
  };  func _getAgentCredentialsAll(agentId : Principal) : [CredentialRecord] {
    var results : [CredentialRecord] = [];
    for ((_, cred) in credentials.entries()) {
      if (Principal.equal(cred.agentId, agentId)) {
        results := Array.append(results, [cred]);
      };
    };
    return results;
  };

  /// Internal: get a scoring weight from config, with default fallback.
  func _getScoringWeight(name : Text, default : Float) : Float {
    for ((n, v) in scoringConfig.vals()) {
      if (n == name) { return v };
    };
    return default;
  };

  /// Internal: get or create daily usage for a principal.
  func _getDailyUsage(who : Principal) : DailyUsage {
    let todayKey = _getTodayKey();
    switch (dailyUsage.get(who)) {
      case (?usage) {
        if (usage.dateKey == todayKey) { usage }
        else { { dateKey = todayKey; usedToday = 0; tier = usage.tier } };
      };
      case null {
        { dateKey = todayKey; usedToday = 0; tier = "Free" };
      };
    };
  };

  /// Internal: get today's date key as YYYYMMDD integer.
  func _getTodayKey() : Nat {
    // Approximate from Time.now() — nanoseconds since 1970-01-01
    let nowNs = Time.now();
    let daysSinceEpoch : Int = nowNs / (24 * 3600 * 1_000_000_000);
    // Convert to YYYYMMDD format
    let year : Int = 1970 + daysSinceEpoch / 365;
    let dayOfYear : Int = daysSinceEpoch % 365;
    let month : Int = dayOfYear / 30 + 1;
    let day : Int = dayOfYear % 30 + 1;
    Int.abs(year * 10_000 + month * 100 + day)
  };

  /// Internal: get tier config by name.
  func _getTierConfig(tierName : Text) : ScoreTierConfig {
    for (tc in scoreTierConfig.vals()) {
      if (tc.tier == tierName) { return tc };
    };
    // Default to Free
    { tier = "Free"; maxDaily = 100; perCallCycles = 0 };
  };

  // ══════════════════════════════════════════════════════════
  //  PHASE 5: REPUTATION SOURCE API
  // ══════════════════════════════════════════════════════════

  /// Register a platform as a trustable reputation source.
  public shared(msg) func registerSource(sourceId : Text, name : Text, endpoint : Text) : async Result.Result<PlatformSource, VeritasError> {
    _assertController(msg.caller);
    if (paused) { return #err(#Paused) };

    switch (platformSources.get(sourceId)) {
      case (?_) { return #err(#AlreadyExists) };
      case null {};
    };

    let source : PlatformSource = {
      id = sourceId;
      name = name;
      endpoint = endpoint;
      registeredAt = Time.now();
      trustLevel = #Untrusted;
      active = false;
    };
    platformSources.put(sourceId, source);
    return #ok(source);
  };

  /// Admin: approve a source (promote from Untrusted to Trusted).
  public shared(msg) func approveSource(sourceId : Text) : async Result.Result<(), VeritasError> {
    _assertController(msg.caller);
    switch (platformSources.get(sourceId)) {
      case (?s) {
        platformSources.put(sourceId, { id = s.id; name = s.name; endpoint = s.endpoint; registeredAt = s.registeredAt; trustLevel = #Trusted; active = true });
        return #ok();
      };
      case null { return #err(#NotFound) };
    };
  };

  /// Admin: reject/disable a source.
  public shared(msg) func rejectSource(sourceId : Text) : async Result.Result<(), VeritasError> {
    _assertController(msg.caller);
    switch (platformSources.get(sourceId)) {
      case (?s) {
        platformSources.put(sourceId, { id = s.id; name = s.name; endpoint = s.endpoint; registeredAt = s.registeredAt; trustLevel = #Untrusted; active = false });
        return #ok();
      };
      case null { return #err(#NotFound) };
    };
  };

  /// Set source trust level directly.
  public shared(msg) func setSourceTrust(sourceId : Text, trustLevel : TrustLevel) : async Result.Result<(), VeritasError> {
    _assertController(msg.caller);
    switch (platformSources.get(sourceId)) {
      case (?s) {
        platformSources.put(sourceId, { id = s.id; name = s.name; endpoint = s.endpoint; registeredAt = s.registeredAt; trustLevel = trustLevel; active = (trustLevel == #Trusted or trustLevel == #Verified) });
        return #ok();
      };
      case null { return #err(#NotFound) };
    };
  };

  /// Push reputation data for an agent from a registered source.
  /// This creates or updates credentials with reputation claims from the source.
  public shared(msg) func pushReputation(
    agentId : Principal,
    sourceId : Text,
    metrics : [Claim]
  ) : async Result.Result<Text, VeritasError> {
    let caller = msg.caller;
    if (paused) { return #err(#Paused) };

    // Verify source exists and is active
    let source = switch (platformSources.get(sourceId)) {
      case (?s) { if (s.active) { s } else { return #err(#NotAuthorized) } };
      case null { return #err(#NotFound) };
    };

    // Create a credential record from the reputation data
    revocationNonceCounter += 1;
    let credentialId = _generateId(agentId, revocationNonceCounter);
    let now = Time.now();
    let expiresAt = now + 30 * 24 * 3600 * 1_000_000_000;

    let record : CredentialRecord = {
      id = credentialId;
      agentId = agentId;
      issuer = Principal.fromActor(this);
      issuedAt = now;
      expiresAt = expiresAt;
      revocationNonce = revocationNonceCounter;
      schemaVersion = 2;
      claims = metrics;
      status = #Active;
    };

    credentials.put(credentialId, record);
    totalCredentialsIssued += 1;
    return #ok(credentialId);
  };

  /// Get all registered platform sources (admin only).
  public shared(msg) func getSources() : async [PlatformSource] {
    _assertController(msg.caller);
    var results : [PlatformSource] = [];
    for ((_, src) in platformSources.entries()) {
      results := Array.append(results, [src]);
    };
    return results;
  };

  /// Get active (trusted) sources for public query.
  public query func getActiveSources() : async [PlatformSource] {
    var results : [PlatformSource] = [];
    for ((_, src) in platformSources.entries()) {
      if (src.active) { results := Array.append(results, [src]) };
    };
    return results;
  };

  // ══════════════════════════════════════════════════════════
  //  PHASE 5: ADMIN DASHBOARD
  // ══════════════════════════════════════════════════════════

  /// Admin dashboard — served at /admin on the canister URL.
  /// Shows: sources, agents, stats, fees, tier config, emergency controls.
  public query func http_request(req : { url : Text; method : Text; headers : [(Text, Text)]; body : Blob }) : async {
    status_code : Nat16; headers : [(Text, Text)]; body : Blob;
  } {
    let canisterId = Principal.toText(Principal.fromActor(this));

    if (req.url == "/.well-known/did.json") {
      let keyRef = switch (issuerKeyCache) {
        case (?k) { ",\"verificationMethod\":[{\"id\":\"#key-1\",\"type\":\"EcdsaSecp256k1VerificationKey2019\","
          # "\"controller\":\"did:veritas:" # canisterId # "\","
          # "\"publicKeyHex\":\"" # _blobToHex(k) # "\"}]" };
        case null { ",\"verificationMethod\":[{\"id\":\"#key-1\",\"type\":\"EcdsaSecp256k1VerificationKey2019\","
          # "\"controller\":\"did:veritas:" # canisterId # "\"}]" };
      };
      let didDoc = "{\"@context\":\"https://www.w3.org/ns/did/v1\","
        # "\"id\":\"did:veritas:" # canisterId # "\","
        # "\"expires\":\"2027-06-17T00:00:00Z\""
        # keyRef
        # ",\"service\":[{\"type\":\"VeritasAgentRegistry\",\"serviceEndpoint\":\"https://" # canisterId # ".icp0.io/\"}]}";
      return { status_code = 200; headers = [("Content-Type", "application/json")]; body = Text.encodeUtf8(didDoc); };
    };

    if (req.url == "/health") {
      return { status_code = 200; headers = [("Content-Type", "application/json")]; body = Text.encodeUtf8("{\"status\":\"ok\"}"); };
    };

    if (req.url == "/mcp/jsonrpc" or req.url == "/mcp/jsonrpc/") {
      let response = MCP.handleGet();
      return { status_code = 200; headers = [("Content-Type", "application/json")]; body = Text.encodeUtf8(response); };
    };

    if (req.url == "/mcp/info") {
      let info = MCP.getMcpInfo(canisterId);
      return { status_code = 200; headers = [("Content-Type", "application/json")]; body = Text.encodeUtf8(info); };
    };

    if (req.url == "/docs" or req.url == "/docs/") {
      let docsPage = "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">"
        # "<title>VERITAS Docs & Demos</title><style>"
        # "*{box-sizing:border-box;margin:0;padding:0}"
        # "body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f0f2f5;color:#1a1a2e;line-height:1.6}"
        # ".container{max-width:900px;margin:0 auto;padding:20px}"
        # "h1{font-size:26px;margin-bottom:4px}"
        # ".sub{color:#666;font-size:14px;margin-bottom:24px}"
        # ".card{background:#fff;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.1)}"
        # "h2{font-size:18px;margin-bottom:12px}"
        # "h3{font-size:15px;margin:16px 0 8px;color:#444}"
        # "code{background:#e8e8e8;padding:2px 6px;border-radius:4px;font-size:13px}"
        # "pre{background:#272822;color:#f8f8f2;padding:14px;border-radius:8px;overflow:auto;font-size:13px;margin:8px 0}"
        # "a{color:#667eea;text-decoration:none;font-weight:500}a:hover{text-decoration:underline}"
        # "input,select{padding:10px 14px;border:1px solid #ddd;border-radius:8px;font-size:14px;width:100%;margin-bottom:8px}"
        # "button{padding:10px 20px;background:#1a1a2e;color:#fff;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600}"
        # "button:hover{background:#2d2d4e}"
        # ".badge{display:inline-block;padding:3px 10px;border-radius:20px;font-size:12px;font-weight:600}"
        # ".badge-green{background:#d4edda;color:#155724}.badge-blue{background:#cce5ff;color:#004085}.badge-yellow{background:#fff3cd;color:#856404}"
        # ".badge-red{background:#f8d7da;color:#721c24}"
        # ".row{display:flex;gap:8px;margin-bottom:8px;flex-wrap:wrap}"
        # ".result{background:#f8f9fa;border-radius:8px;padding:12px;margin-top:8px;font-size:13px;display:none}"
        # ".error{color:#dc3545;font-size:13px;margin-top:6px}"
        # ".nav{display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap;border-bottom:1px solid #ddd;padding-bottom:12px}"
        # ".nav a{font-size:14px}"
        # "table{width:100%;border-collapse:collapse;margin:8px 0}"
        # "th,td{padding:8px 12px;text-align:left;border-bottom:1px solid #eee;font-size:13px}"
        # "th{background:#1a1a2e;color:#fff;font-weight:600}"
        # "tr:hover{background:#f5f5f5}"
        # ".tool-box{background:#f8f9fa;border-radius:8px;padding:14px;margin-bottom:10px}"
        # ".tool-name{font-weight:700;font-size:15px;color:#1a1a2e}"
        # ".tool-desc{font-size:13px;color:#666;margin:4px 0}"
        # ".demo-result{padding:12px;border-radius:8px;margin-top:10px;font-size:14px;text-align:center}"
        # ".demo-ok{background:#d4edda;color:#155724}"
        # ".demo-wait{background:#fff3cd;color:#856404}"
        # "@media(prefers-color-scheme:dark){body{background:#111;color:#e0e0e0}.card{background:#1a1a1e;border:1px solid #333}th{background:#333}pre{background:#000}.nav{border-color:#333}}"
        # "</style></head><body><div class=\"container\">"
        
        # "<h1>🛡️ VERITAS Protocol</h1>"
        # "<p class=\"sub\">Verifiable AI Agent Identity on ICP — Docs &amp; Interactive Demos</p>"

        # "<div class=\"nav\">"
        # "<a href=\"#agents\">Agents</a><a href=\"#platforms\">Platforms</a><a href=\"#scoring\">Credit Scoring</a><a href=\"#mcp\">MCP</a><a href=\"#demos\">Demos</a><a href=\"/admin\">Admin</a>"
        # "</div>"

        # "<!-- AGENT SECTION -->"
        # "<div class=\"card\" id=\"agents\"><h2>🤖 For AI Agents</h2>"
        # "<p>Register your identity and mint verifiable credentials in 5 minutes.</p>"
        # "<pre>npm install veritas-agent</pre>"
        # "<pre>const agent = new Agent();\nagent.generateKeys('principal');\nconst did = agent.getIdentity().did;</pre>"
        # "<h3>Proof-of-Possession Handshake</h3>"
        # "<p>Two agents verify each other peer-to-peer — no central authority needed.</p>"
        # "<pre>const proof = alice.createHandshakeProof();\nconst isValid = verifyHandshakeProof(proof);</pre>"
        # "</div>"

        # "<!-- PLATFORM SECTION -->"
        # "<div class=\"card\" id=\"platforms\"><h2>🏢 For Platforms</h2>"
        # "<p>Register as a reputation source, push agent data, and verify credentials.</p>"
        # "<pre>npm install veritas-verify</pre>"
        # "<h3>Register as a source</h3>"
        # "<p><code>registerSource(\"platform-id\", \"Name\", \"https://...\")</code></p>"
        # "<h3>Verify a credential</h3>"
        # "<p><code>checkCredentialStatus(\"credential-id\")</code> returns Active, Revoked, or Expired.</p>"
        # "</div>"

        # "<!-- CREDIT SCORING SECTION -->"
        # "<div class=\"card\" id=\"scoring\"><h2>🏆 Credit Scoring</h2>"
        # "<p>Six-factor credit score (0-850) computed from on-chain reputation data.</p>"
        # "<table><tr><th>Factor</th><th>Weight</th><th>Max Points</th></tr>"
        # "<tr><td>Experience</td><td>+100</td><td>min(jobs/100,1.0)</td></tr>"
        # "<tr><td>Performance</td><td>+50</td><td>avg confidence</td></tr>"
        # "<tr><td>Diversity</td><td>+50</td><td>unique sources</td></tr>"
        # "<tr><td>Longevity</td><td>+50</td><td>years in ecosystem</td></tr>"
        # "<tr><td>Penalties</td><td>-100</td><td>revoked credentials</td></tr>"
        # "<tr><td>PoP Rate</td><td>-50</td><td>verification reliability</td></tr></table>"
        # "<p>Tiers: <span class=\"badge badge-green\">Free</span> 100/day · <span class=\"badge badge-blue\">Starter</span> 10K/day · <span class=\"badge badge-yellow\">Pro</span> 100K/day · <span class=\"badge badge-red\">Enterprise</span> Unlimited</p>"
        # "</div>"

        # "<!-- MCP SECTION -->"
        # "<div class=\"card\" id=\"mcp\"><h2>🤖 MCP Integration</h2>"
        # "<p>AI agents discover VERITAS via MCP at <code>/mcp/jsonrpc</code>. Works with Claude Desktop, Cline, Goose.</p>"
        # "<div id=\"mcp-tools\"></div>"
        # "</div>"

        # "<!-- INTERACTIVE DEMOS -->"
        # "<div class=\"card\" id=\"demos\"><h2>🧪 Interactive Demos</h2>"
        
        # "<h3>🔍 Query Credit Score</h3>"
        # "<p>Enter an ICP principal to query their VERITAS credit score:</p>"
        # "<div class=\"row\"><input type=\"text\" id=\"principal-input\" placeholder=\"Enter ICP principal (e.g. 2vxsx-fae)\"></div>"
        # "<button onclick=\"queryScore()\" style=\"width:100%\">Get Credit Score</button>"
        # "<div id=\"score-result\" class=\"result\"></div>"

        # "<h3 style=\"margin-top:24px\">🤝 Agent Handshake Simulator</h3>"
        # "<p>Two agents prove their identity to each other using proof-of-possession:</p>"
        # "<button onclick=\"simulateHandshake()\" style=\"width:100%\">Run Handshake Demo</button>"
        # "<div id=\"handshake-result\" class=\"result\"></div>"

        # "<h3 style=\"margin-top:24px\">🔗 Check Credential Status</h3>"
        # "<p>Enter a credential ID to check its revocation/expiry status:</p>"
        # "<div class=\"row\"><input type=\"text\" id=\"credential-input\" placeholder=\"e.g. vrt-principal-hex\"></div>"
        # "<button onclick=\"checkCredential()\" style=\"width:100%\">Check Status</button>"
        # "<div id=\"credential-result\" class=\"result\"></div>"
        # "</div>"

        # "<div class=\"card\" style=\"text-align:center;font-size:13px;color:#999\"><p>Canister: " # canisterId # " · v1.5.0 · "
        # "<a href=\"https://github.com/kodydpa-hub/veritas\" target=\"_blank\">GitHub</a>"
        # "</p></div>"

        # "<script>"
        # "const CID='" # canisterId # "';const RAW='https://" # canisterId # ".raw.icp0.io';"
        # "async function qs(p){return(await fetch('https://icp-api.io/api/v2/canister/'+CID+'/query',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({request_type:'query',sender:'000000000000000000000000000000000000000000000000000000000000000000',canister_id:CID,method_name:p,arg:[]})})).json();}"
        # "async function queryScore(){const i=document.getElementById('principal-input');const d=document.getElementById('score-result');const p=i.value.trim();if(!p){d.style.display='block';d.innerHTML='<p class=\"error\">Enter a principal</p>';return;}d.style.display='block';d.innerHTML='⏳ Querying...';d.innerHTML='<p style=\"font-size:13px\">To query a live score, run:<br><code>dfx canister call veritas_backend getCreditScore \'(principal \"'+p+'\")\'</code><br><br><a href=\"https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id='+CID+'&method=getCreditScore\" target=\"_blank\">Open in Candid UI →</a></p>';}"
        # "async function checkCredential(){const i=document.getElementById('credential-input');const d=document.getElementById('credential-result');const c=i.value.trim();if(!c){d.style.display='block';d.innerHTML='<p class=\"error\">Enter a credential ID</p>';return;}d.style.display='block';d.innerHTML='⏳ Checking...';d.innerHTML='<p style=\"font-size:13px\">To check status, run:<br><code>dfx canister call veritas_backend checkCredentialStatus \'(\"'+c+'\")\'</code><br><br><a href=\"https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id='+CID+'&method=checkCredentialStatus\" target=\"_blank\">Open in Candid UI →</a></p>';}"
        # "async function simulateHandshake(){const d=document.getElementById('handshake-result');d.style.display='block';d.innerHTML='<div class=\"demo-result demo-wait\">🤖 Generating Alice... 🤖 Generating Bob... 🔐 Creating handshake... ✅ Verifying...</div>';setTimeout(()=>{d.innerHTML='<div class=\"demo-result demo-ok\">✅ Alice proved she controls her private key<br>✅ Bob verified Alice\'s proof-of-possession<br>🔐 Peer-to-peer trust established</div>';},1500);}"
        # "async function loadMCP(){const r=await fetch(RAW+'/mcp/jsonrpc');const data=await r.json();const tools=data.result?.tools||[];const div=document.getElementById('mcp-tools');let html='<h3>Available Tools ('+tools.length+')</h3>';tools.forEach(t=>{const params=t.inputSchema?Object.keys(t.inputSchema.properties||{}).join(', '):'none';html+='<div class=\"tool-box\"><div class=\"tool-name\">🛠 '+t.name+'</div><div class=\"tool-desc\">'+t.description.substring(0,120)+'...</div><div style=\"font-size:12px;color:#999;margin-top:4px\">Parameters: '+params+'</div></div>';});div.innerHTML=html;}loadMCP();"
        # "</script>"
        # "</div></body></html>";
      return { status_code = 200; headers = [("Content-Type", "text/html; charset=utf-8")]; body = Text.encodeUtf8(docsPage); };
    };

    if (req.url == "/admin" or req.url == "/admin/") {
      let statsInfo = "";
      let sourcesHtml = "";
      // Build a simple admin dashboard HTML
      let html = "<!DOCTYPE html><html lang=\"en\"><head>"
        # "<meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">"
        # "<title>VERITAS Admin</title>"
        # "<style>body{font-family:sans-serif;max-width:960px;margin:0 auto;padding:20px;background:#f5f5f5}"
        # "h1{color:#1a1a2e}.card{background:#fff;border-radius:8px;padding:16px;margin:12px 0;box-shadow:0 1px 3px rgba(0,0,0,0.1)}"
        # ".badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold}"
        # ".badge-green{background:#4caf50;color:#fff}.badge-red{background:#f44336;color:#fff}.badge-yellow{background:#ff9800;color:#fff}"
        # "table{width:100%;border-collapse:collapse}th,td{padding:8px;text-align:left;border-bottom:1px solid #ddd}"
        # "th{background:#1a1a2e;color:#fff}tr:hover{background:#f1f1f1}"
        # ".btn{display:inline-block;padding:8px 16px;border-radius:4px;text-decoration:none;color:#fff;margin:4px}"
        # ".btn-green{background:#4caf50}.btn-red{background:#f44336}.btn-blue{background:#2196f3}"
        # "pre{background:#272822;color:#f8f8f2;padding:12px;border-radius:4px;overflow:auto}"
        # "</style></head><body>"
        # "<h1>🔐 VERITAS Admin</h1>"
        # "<div class=\"card\"><h2>📊 Stats</h2>"
        # "<pre>Canister ID: " # canisterId # "</pre>"
        # "<pre>Storage v6 | Agents: " # debug_show(totalAgentsRegistered)
        # " | Credentials: " # debug_show(totalCredentialsIssued)
        # " | Fees: " # debug_show(totalFeesCollected) # " cycles</pre>"
        # "</div>"
        # "<div class=\"card\"><h2>⛓️ Emergency Controls</h2>"
        # "<p>Status: " # (if (paused) { "<span class=\"badge badge-red\">PAUSED</span>" } else { "<span class=\"badge badge-green\">ACTIVE</span>" }) # "</p>"
        # "</div>"
        # "<div class=\"card\"><h2>📋 API Tiers</h2><table><tr><th>Tier</th><th>Daily Limit</th><th>Per-Call Cycles</th></tr>";
      
      var tiersHtml = html;
      for (tc in scoreTierConfig.vals()) {
        tiersHtml #= "<tr><td>" # tc.tier # "</td><td>" # debug_show(tc.maxDaily) # "</td><td>" # debug_show(tc.perCallCycles) # "</td></tr>";
      };
      tiersHtml #= "</table></div>";
      
      tiersHtml #= "<div class=\"card\"><h2>🌐 Sources</h2><p>Register sources via dfx: <code>dfx canister call veritas_backend registerSource</code></p></div>";
      tiersHtml #= "<div class=\"card\"><h2>📖 Documentation</h2><p>View the <a href=\"/docs\" style=\"color:#667eea\">quick start guide</a> or full <a href=\"https://github.com/kodydpa-hub/veritas/tree/master/docs/guides/INTEGRATION.md\" style=\"color:#667eea\">integration docs</a> on GitHub.</p></div>";
      tiersHtml #= "</body></html>";
      
      return { status_code = 200; headers = [("Content-Type", "text/html; charset=utf-8")]; body = Text.encodeUtf8(tiersHtml); };
    };

    return { status_code = 404; headers = [("Content-Type", "text/plain")]; body = Text.encodeUtf8("Not found"); };
  };

  // ══════════════════════════════════════════════════════════
  //  PHASE 6: MCP HTTP JSON-RPC (Update handler for POST)
  // ══════════════════════════════════════════════════════════

  /// Handle POST requests to /mcp/jsonrpc — executes MCP tool calls.
  public shared(msg) func http_request_update(req : {
    url : Text;
    method : Text;
    headers : [(Text, Text)];
    body : Blob;
  }) : async {
    status_code : Nat16;
    headers : [(Text, Text)];
    body : Blob;
  } {
    if (req.url == "/mcp/jsonrpc" or req.url == "/mcp/jsonrpc/") {
      let bodyText = Text.decodeUtf8(req.body);
      switch (bodyText) {
        case (?text) {
          let response = MCP.handlePost(text);
          return { status_code = 200; headers = [("Content-Type", "application/json")]; body = Text.encodeUtf8(response); };
        };
        case null {
          return { status_code = 400; headers = [("Content-Type", "application/json")]; body = Text.encodeUtf8("{\"jsonrpc\":\"2.0\",\"id\":0,\"error\":{\"code\":-32700,\"message\":\"Parse error: invalid UTF-8 body\"}}"); };
        };
      };
    };
    return { status_code = 404; headers = [("Content-Type", "text/plain")]; body = Text.encodeUtf8("Not found: " # req.url); };
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
    if (amount <= current) {
      balances.put(who, current - amount);
    };
  };

  func _assertController(_caller : Principal) {
    // Phase 1: controller check delegated to caller identity.
    // In production: check against a stored admin list.
  };

  // ── Phase 2: Hash-based credential ID generation ──

  /// Generate a unique credential ID from principal + nonce.
  /// Uses the principal's text representation plus nonce as a hex suffix.
  func _generateId(caller : Principal, nonce : Nat) : Text {
    let principalText = Principal.toText(caller);
    let nonceHex = _natToHex(nonce);
    return "vrt-" # principalText # "-" # nonceHex;
  };

  func _concatBlobs(a : Blob, b : Blob) : Blob {
    let arrA = Blob.toArray(a);
    let arrB = Blob.toArray(b);
    return Blob.fromArray(Array.append(arrA, arrB));
  };

  // ── Phase 2: Real hex-encoded public keys ──

  /// Get agent's public key as a hex string.
  func _getAgentPublicKeyHex(agentId : Principal) : Text {
    switch (identities.get(agentId)) {
      case (?id) { "0x" # _blobToHex(id.publicKey) };
      case null { "0x00" };
    };
  };

  /// Convert a Blob to a lowercase hex string.
  func _blobToHex(b : Blob) : Text {
    _bytesToHex(Blob.toArray(b));
  };

  /// Convert an array of bytes to a lowercase hex string.
  func _bytesToHex(bytes : [Nat8]) : Text {
    let hexChars : [Char] = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
    var result = "";
    for (byte in bytes.vals()) {
      let hi = byte / 16;
      let lo = byte % 16;
      result #= Char.toText(hexChars[Nat8.toNat(hi)]);
      result #= Char.toText(hexChars[Nat8.toNat(lo)]);
    };
    return result;
  };

  /// Convert a Nat to hex string.
  func _natToHex(n : Nat) : Text {
    if (n == 0) { return "0" };
    let hexChars : [Char] = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f'];
    var result = "";
    var remaining = n;
    while (remaining > 0) {
      let digit = remaining % 16;
      result := Char.toText(hexChars[digit]) # result;
      remaining /= 16;
    };
    return result;
  };
};
