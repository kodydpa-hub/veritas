Feature: Rate Limiting & Mint Queue
  As an agent
  I want to submit credential requests that are processed asynchronously
  So that I don't hit ECDSA rate limits and can scale issuance

  Background:
    Given the VERITAS canister is deployed on ICP

  Scenario: Agent submits a credential request to the queue
    Given an agent has registered and deposited cycles
    When the agent calls issueCredential
    Then the request is queued for batch processing
    And a placeholder credential is returned immediately

  Scenario: Agent checks queue status
    Given an agent has submitted a credential request
    When the agent calls getCredentialQueue with their queue ID
    Then the canister returns the current status
    And the status is Pending, Processing, Completed, or Failed

  Scenario: Unknown queue ID returns null
    Given a queue ID that does not exist
    When the agent calls getCredentialQueue with that ID
    Then the canister returns null

  Scenario: Batch processing reduces queue size
    Given the mint queue has items
    When the heartbeat fires after 60 seconds
    Then up to 10 items are processed from the queue
