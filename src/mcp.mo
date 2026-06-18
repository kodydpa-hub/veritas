// ════════════════════════════════════════════════════════════
//  VERITAS — MCP Server (Model Context Protocol)
//  JSON-RPC 2.0 endpoint for AI agent discovery
//
//  GET  /mcp/jsonrpc  → tool listing (query, free)
//  POST /mcp/jsonrpc  → tool calls (update, paid)
// ════════════════════════════════════════════════════════════

import Text "mo:base/Text";
import Array "mo:base/Array";
import Iter "mo:base/Iter";
import Principal "mo:base/Principal";
import Blob "mo:base/Blob";
import Result "mo:base/Result";
import Int "mo:base/Int";

module {

  // ── MCP Types ──

  public type JsonRpcRequest = {
    jsonrpc : Text;
    id : Nat;
    method : Text;
    params : ?[(Text, Text)];
  };

  public type JsonRpcResponse = {
    jsonrpc : Text;
    id : Nat;
    result : ?Text;
    error : ?{ code : Int; message : Text };
  };

  public type McpTool = {
    name : Text;
    description : Text;
    inputSchema : Text; // JSON schema string
  };

  // ── Helper Functions ──

  /// Extract the method name from a JSON-RPC request body.
  /// Uses string splitting on known delimiters — simple but reliable for MCP.
  func _extractMethod(body : Text) : ?Text {
    let marker = "\"method\":\"";
    // Split on marker and take the part after it
    let parts = Iter.toArray(Text.split(body, #text(marker)));
    if (parts.size() < 2) { return null };
    let after = parts[1];
    // Split on next quote to get the method name
    let quoteParts = Iter.toArray(Text.split(after, #text("\"")));
    if (quoteParts.size() < 1) { return null };
    return ?quoteParts[0];
  };

  // ── Tool Definitions ──

  public func getToolList() : [McpTool] {
    return [
      {
        name = "veritas_register";
        description = "Register an agent identity on the VERITAS protocol. Requires a valid secp256k1 public key. Returns the agent's DID and identity record.";
        inputSchema = "{\"type\":\"object\",\"properties\":{\"publicKey\":{\"type\":\"string\",\"description\":\"Hex-encoded secp256k1 public key (compressed, 66 hex chars)\"}},\"required\":[\"publicKey\"]}";
      },
      {
        name = "veritas_verify";
        description = "Verify a W3C Verifiable Credential. Checks structure, expiry, and revocation status. Returns verification result with optional reason.";
        inputSchema = "{\"type\":\"object\",\"properties\":{\"credentialId\":{\"type\":\"string\",\"description\":\"The credential ID to verify\"}},\"required\":[\"credentialId\"]}";
      },
      {
        name = "veritas_credit_score";
        description = "Get an agent's credit score (0-850) computed from on-chain reputation data. Free tier is rate-limited to 100 queries/day.";
        inputSchema = "{\"type\":\"object\",\"properties\":{\"agentPrincipal\":{\"type\":\"string\",\"description\":\"ICP principal of the agent\"}},\"required\":[\"agentPrincipal\"]}";
      },
      {
        name = "veritas_info";
        description = "Get VERITAS canister info including version, stats, and available tools. Useful for discovering the protocol's capabilities.";
        inputSchema = "{\"type\":\"object\",\"properties\":{}}";
      },
    ];
  };

  // ── JSON-RPC Response Builders ──

  public func buildSuccessResponse(id : Nat, resultText : Text) : JsonRpcResponse {
    { jsonrpc = "2.0"; id = id; result = ?resultText; error = null };
  };

  public func buildErrorResponse(id : Nat, code : Int, message : Text) : JsonRpcResponse {
    { jsonrpc = "2.0"; id = id; result = null; error = ?{ code = code; message = message } };
  };

  // ── Serialization ──

  public func serializeToolList(tools : [McpTool]) : Text {
    var result = "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"tools\":[";
    var first = true;
    for (tool in tools.vals()) {
      if (not first) { result #= "," };
      result #= "{\"name\":\"" # tool.name # "\",\"description\":\"" # tool.description # "\",\"inputSchema\":" # tool.inputSchema # "}";
      first := false;
    };
    result #= "]}}";
    return result;
  };

  public func serializeResponse(response : JsonRpcResponse) : Text {
    var json = "{\"jsonrpc\":\"2.0\",\"id\":" # debug_show(response.id);
    switch (response.result) {
      case (?r) { json #= ",\"result\":" # r };
      case null {};
    };
    switch (response.error) {
      case (?e) { json #= ",\"error\":{\"code\":" # debug_show(e.code) # ",\"message\":\"" # e.message # "\"}" };
      case null {};
    };
    json #= "}";
    return json;
  };

  // ── Orchestrator ──

  /// Handle GET requests — return tool list
  public func handleGet() : Text {
    serializeToolList(getToolList());
  };

  /// Handle POST requests — dispatch to the correct method
  public func handlePost(body : Text) : Text {
    let method = switch (_extractMethod(body)) {
      case (?m) { m };
      case null { return serializeResponse(buildErrorResponse(1, -32700, "Parse error: could not extract method")) };
    };
    if (method == "tools/list") {
      return serializeToolList(getToolList());
    };
    serializeResponse(buildErrorResponse(1, -32601, "Method not found: " # method));
  };

  /// Generate MCP server info JSON
  public func getMcpInfo(canisterId : Text) : Text {
    "{\"protocol\":\"veritas\",\"version\":\"1.5.0\",\"canister\":\"" # canisterId # "\",\"mcp_endpoint\":\"/mcp/jsonrpc\",\"tools\":[\"veritas_register\",\"veritas_verify\",\"veritas_credit_score\",\"veritas_info\"]}";
  };
};
