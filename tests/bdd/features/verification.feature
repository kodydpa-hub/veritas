Feature: Identity Registration
  As an agent
  I want to register my identity on the VERITAS canister
  So that I can mint credentials and build reputation

  Background:
    Given the VERITAS canister is deployed on ICP

  Scenario: Agent registers a new identity
    Given an agent has deposited cycles
    When the agent calls register with a valid public key
    Then the canister returns an AgentIdentity
    And the identity status is Active

  Scenario: Duplicate registration is rejected
    Given an agent is already registered
    When the agent calls register again
    Then the canister returns AlreadyExists

  Scenario: Unknown agent returns null on resolve
    Given an agent has not registered
    When a platform calls resolve with the agent's principal
    Then the canister returns null

  Scenario: Agent rotates their public key
    Given an agent is registered
    When the agent calls rotateKey with a new public key
    Then the public key is updated
    And the lastRenewed timestamp is refreshed
