Feature: MCP Server Discovery
  As an AI agent
  I want to discover and interact with VERITAS via MCP
  So that I can register, verify, and check credit scores through natural language

  Background:
    Given the VERITAS canister is deployed on ICP

  Scenario: AI agent discovers VERITAS tools via MCP
    When an agent sends a GET request to /mcp/jsonrpc
    Then the response contains a tool list with veritas_register
    And the response contains veritas_verify
    And the response contains veritas_credit_score
    And the response contains veritas_info

  Scenario: Agent registers via MCP
    Given an MCP client has the tool list
    When the client sends a POST tool call to veritas_register
    Then the canister returns an AgentIdentity
