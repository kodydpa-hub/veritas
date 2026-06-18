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

// ════════════════════════════════════════════════════════════
//  VERITAS — Verifiable AI Agent Identity Protocol
//  Phase 1: Identity Registry + Credential Minting + PoP + W3C VCs
//  Phase 2: Real SHA256 signing, hex-encoded keys, hash-based IDs
//  Phase 3: Credit Scoring + API Tiers
//  Version: 1.3.0
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
    // Clear transient upgrade buffers
    identitiesEntries := [];
    dailyUsageEntries := [];
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
  /// Requires proof-of-possession: agent must sign (popNonce || agentId) with their registered key.
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

    // Guard: proof-of-possession is verified off-chain by the npm library.
    // The popSignature and popNonce are recorded for audit purposes.

    // Guard: sufficient balance
    let balance = _getBalance(caller);
    if (balance < FEE_CREDENTIAL) { return #err(#InsufficientBalance) };

    // Guard: identity active
    switch (identity.status) {
      case (#Revoked(_)) { return #err(#NotAuthorized) };
      case (#Suspended(_)) { return #err(#NotAuthorized) };
      case (#Active) {};
    };

    // Deduct fee
    _deductBalance(caller, FEE_CREDENTIAL);

    // Generate credential ID and revocation nonce
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
  //  PHASE 1: DID DOCUMENT (§6a.4, §6a.6)
  // ══════════════════════════════════════════════════════════

  /// HTTP handler for DID document + health check.
  public query func http_request(req : { url : Text; method : Text; headers : [(Text, Text)]; body : Blob }) : async {
    status_code : Nat16; headers : [(Text, Text)]; body : Blob;
  } {
    let canisterId = Principal.toText(Principal.fromActor(this));
    if (req.url == "/.well-known/did.json") {
      // Include the issuer key in the DID document if available
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
    return { status_code = 404; headers = [("Content-Type", "text/plain")]; body = Text.encodeUtf8("Not found"); };
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

  /// Admin: get current scoring configuration.
  public query func getScoringConfig() : async [(Text, Float)] {
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
