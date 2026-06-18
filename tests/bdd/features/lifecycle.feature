Feature: Credential Lifecycle
  As an agent
  I want my credentials to stay valid through renewal
  So that my reputation remains active over time

  Background:
    Given the VERITAS canister is deployed on ICP

  Scenario: Agent issues a credential with custom expiry
    Given an agent is registered and has balance
    When the agent calls issueCredential with expiresIn of 7 days
    Then a credential record is created
    And the expiresAt is approximately 7 days from now

  Scenario: Expired credential shows as Expired
    Given a credential has passed its validUntil date
    When a verifier calls checkCredentialStatus
    Then the status is Expired

  Scenario: Credential counter increments with each issuance
    Given an agent has 1 credential
    When the agent issues another credential
    Then totalCredentials increases by 1

  Scenario: Agent views their credentials
    Given an agent holds multiple credentials
    When the agent calls getAgentCredentials
    Then all their credentials are returned
