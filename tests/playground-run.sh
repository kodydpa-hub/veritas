#!/bin/bash
# ════════════════════════════════════════════════════════════
#  VERITAS — Playground Deploy + Regression Runner
#  Phase 0: Canister Shell
# ════════════════════════════════════════════════════════════
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
TIMESTAMP=$(date +%Y%m%d_%H%M)
REPORT_DIR="${SCRIPT_DIR}/html-report/report-${TIMESTAMP}"
PASS=0
FAIL=0
SKIP=0

cd "$PROJECT_DIR"

echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  VERITAS — Playground Run                              ║"
echo "║  ${TIMESTAMP}                                ║"
echo "╚═══════════════════════════════════════════════════════════╝"

# ── Step 1: Deploy ──
echo ""
echo "📦 Deploying to ICP Playground..."
dfx deploy --network playground --no-wallet 2>&1 | tail -5

# Get canister IDs
BACKEND_ID=$(dfx canister --network playground id veritas_backend 2>/dev/null || echo "")
echo "   Backend: ${BACKEND_ID}"

# ── Step 2: Deploy test framework dependencies ──
echo ""
echo "🔧 Installing test framework..."
cd "$SCRIPT_DIR"
npm install --no-save playwright @cucumber/cucumber 2>&1 | tail -3
cd "$PROJECT_DIR"

# ── Step 3: Run API suites ──
echo ""
echo "🧪 Running API test suites..."
for suite in "${SCRIPT_DIR}/suites/"*.js; do
  name=$(basename "$suite" .js)
  echo "   Suite: ${name}"
  if node "$suite" --canister "$BACKEND_ID" --network playground 2>&1; then
    echo "   ✅ ${name} PASS"
    PASS=$((PASS + 1))
  else
    echo "   ❌ ${name} FAIL"
    FAIL=$((FAIL + 1))
  fi
done

# ── Step 4: Run BDD features ──
echo ""
echo "📋 Running BDD features..."
if ls "${SCRIPT_DIR}/bdd/features/"*.feature 2>/dev/null; then
  npx cucumber-js \
    --config "${SCRIPT_DIR}/cucumber.js" \
    --world-parameters "{\"canisterId\":\"${BACKEND_ID}\",\"network\":\"playground\"}" \
    2>&1 && PASS=$((PASS + 1)) || FAIL=$((FAIL + 1))
else
  echo "   ⏭ No BDD features yet"
  SKIP=$((SKIP + 1))
fi

# ── Step 5: Generate Report ──
echo ""
echo "📊 Generating HTML report..."
mkdir -p "$REPORT_DIR"
if [ -f "${SCRIPT_DIR}/html-report/template.html" ]; then
  node "${SCRIPT_DIR}/html-report/generate.js" \
    --pass "$PASS" --fail "$FAIL" --skip "$SKIP" \
    --timestamp "$TIMESTAMP" \
    --output "$REPORT_DIR" \
    --canister "$BACKEND_ID"
fi

# ── Summary ──
echo ""
echo "╔═══════════════════════════════════════════════════════════╗"
echo "║  RESULTS                                                 ║"
echo "╠═══════════════════════════════════════════════════════════╣"
printf "║  Pass:  %-3d   Fail:  %-3d   Skip:  %-3d              ║\n" "$PASS" "$FAIL" "$SKIP"
echo "╚═══════════════════════════════════════════════════════════╝"

if [ "$FAIL" -eq 0 ] && [ "$PASS" -gt 0 ]; then
  echo ""
  echo "🎉 ALL TESTS PASSING — Ready for next phase"
  exit 0
else
  echo ""
  echo "❌ Some tests failed. Review output before proceeding."
  exit 1
fi
