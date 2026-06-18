Feature: Credit Scoring
  As a platform
  I want to query an agent's credit score
  So that I can assess their reputation before onboarding or transacting

  Background:
    Given the VERITAS canister is deployed on ICP

  Scenario: Platform queries an agent's credit score
    Given an agent has registered and holds active credentials
    When a platform calls getCreditScore with the agent principal
    Then the canister returns a CreditScore
    And the score is between 0 and 850
    And the tier is one of Excellent, Good, Fair, Poor, or Unrated
    And the factors array contains at least one entry

  Scenario: Unknown agent returns no credit score
    Given an agent has not registered
    When a platform calls getCreditScore with the agent principal
    Then the canister returns null

  Scenario: Scoring weights are admin-configurable
    Given the admin has updated a scoring weight
    When a platform calls getScoringConfig
    Then the updated weight is reflected in the configuration

  Scenario: Agent tier can be upgraded to Starter
    Given an agent is on the Free tier
    When the admin upgrades the agent to the Starter tier
    Then the daily limit increases from 100 to 10,000

  Scenario: Paid tier deducts cycles per lookup
    Given an agent is on the Starter tier
    When a paid credit score lookup is performed
    Then cycles are deducted from the caller's balance
    And the daily usage counter increments
