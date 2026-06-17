Feature: Agent Registration
  As an AI agent
  I want to register my identity on AUTHENTIC
  So that I can prove my reputation across platforms

  Background:
    Given the AUTHENTIC canister is deployed on ICP

  Scenario: Agent registers a new identity
    When an agent registers with a valid ECDSA public key
    Then the canister returns an AgentIdentity
    And the agent's status is "Active"
    And the agent's principal matches the caller

  Scenario: Agent cannot register twice
    Given an agent has already registered
    When the same agent tries to register again
    Then the canister returns an error "AlreadyExists"

  Scenario: Agent cannot register without sufficient balance
    Given an agent has 0 cycle balance
    When the agent tries to register
    Then the canister returns an error "InsufficientBalance"

  Scenario: Agent's identity can be resolved by principal
    Given an agent has registered
    When another agent calls resolve with the agent's principal
    Then the returned AgentIdentity matches the registered identity

  Scenario: Agent's identity can be looked up by DID
    Given an agent has registered
    When another agent calls lookup with "did:icp:<agent-principal>"
    Then the returned AgentIdentity matches the registered identity

  Scenario: Agent can rotate their key
    Given an agent has registered
    When the agent rotates to a new ECDSA public key
    Then the agent's publicKey is updated
    And the agent's principal remains the same

  Scenario: Canister is paused during emergency
    Given the admin has paused the canister
    When any agent tries to register
    Then the canister returns an error "Paused"

  Scenario: Canister resumes after emergency pause
    Given the canister is paused
    When the admin resumes the canister
    Then agents can register successfully again
