#!/bin/bash
# BDD Test Runner for VERITAS
# Run all BDD features against the playground

set -e
NETWORK="${1:-playground}"
CANISTER_ID="${2:-ofoea-eyaaa-aaaab-qab6a-cai}"

echo "🔄 Running BDD tests on $NETWORK..."
cd "$(dirname "$0")/.."

# Install Cucumber if not present
if ! node -e "require('@cucumber/cucumber')" 2>/dev/null; then
  npm install --save-dev @cucumber/cucumber 2>&1 | tail -1
fi

# Run all features
npx cucumber-js --config tests/bdd/cucumber.js \
  --world-parameters "{\"network\": \"$NETWORK\"}" \
  --format summary \
  --format json:tests/bdd/report.json \
  --format html:tests/bdd/report.html \
  2>&1

echo ""
echo "📊 BDD report: tests/bdd/report.html"
echo "Done."
