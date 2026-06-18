Feature: Credential Revocation
  As an agent
  I want to revoke compromised credentials
  So that verifiers know they are no longer trustworthy

  Background:
    Given the VERITAS canister is deployed on ICP

  Scenario: Agent revokes their own credential
    Given an agent holds an active credential
    When the agent calls revokeCredential with that credential ID
    Then the credential status is Revoked

  Scenario: Only the credential owner can revoke
    Given a credential belongs to another agent
    When a different agent calls revokeCredential
    Then the canister returns NotAuthorized

  Scenario: Unknown credential returns NotFound
    Given a credential ID that does not exist
    When an agent calls revokeCredential with that ID
    Then the canister returns NotFound

  Scenario: Admin revokes a platform source
    Given a platform source is registered
    When the admin calls revokePlatformSource with the source ID
    Then all credentials from that source are flagged as stale

  Scenario: Revoked credential shows on checkCredentialStatus
    Given a credential has been revoked
    When a verifier calls checkCredentialStatus
    Then the status is Revoked
