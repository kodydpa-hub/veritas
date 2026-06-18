#!/usr/bin/env node
/**
 * VERITAS Demo: Credit Scoring in Action
 * 
 * A marketplace queries an agent's credit score before onboarding them.
 * Shows how platforms use VERITAS to assess agent reputation.
 * 
 * Usage: node credit-scoring-demo.js
 * Prerequisites: dfx identity configured for playground
 */

const { execSync } = require('child_process');

const NETWORK = 'playground';
const CANISTER = 'veritas_backend';

function dfx(method, args = '') {
  const cmd = args
    ? `cd /home/chris/.openclaw/workspace/veritas && dfx canister --network ${NETWORK} call ${CANISTER} ${method} '${args}' 2>/dev/null`
    : `cd /home/chris/.openclaw/workspace/veritas && dfx canister --network ${NETWORK} call ${CANISTER} ${method} 2>/dev/null`;
  return execSync(cmd, { encoding: 'utf-8', timeout: 15000 });
}

function getPrincipal() {
  const p = execSync(`dfx identity get-principal --network ${NETWORK} 2>/dev/null`, { encoding: 'utf-8', timeout: 5000 });
  return p.trim().replace(/\n/g, '');
}

async function main() {
  console.log('══════════════════════════════════════════════');
  console.log('  VERITAS — Credit Scoring in Action Demo');
  console.log('══════════════════════════════════════════════');
  console.log('');

  // Step 1: Check canister health
  console.log('📡 Step 1: Check canister health');
  const stats = dfx('getStats');
  console.log(`   Storage: v${stats.match(/storageVersion = (\d+)/)?.[1] || '?'}`);
  console.log(`   Agents: ${stats.match(/totalAgents = (\d+)/)?.[1] || '0'}`);
  console.log(`   Credentials: ${stats.match(/totalCredentials = (\d+)/)?.[1] || '0'}`);
  console.log('');

  const principal = getPrincipal();

  // Step 2: Check credit score for an agent
  console.log('📡 Step 2: Query agent credit score');
  const score = dfx('getCreditScore', `(principal "${principal}")`);
  if (score.includes('null')) {
    console.log('   ℹ️  Agent not registered. Credit score unavailable.');
    console.log('   📝 Register an agent first on the playground.');
  } else {
    console.log(`   Score data received`);
  }
  console.log('');

  // Step 3: Show tier pricing
  console.log('📡 Step 3: API tier pricing');
  const tiers = dfx('getTierConfig');
  const tierRecords = (tiers.match(/record \{/g) || []).length;
  console.log(`   ${tierRecords} tiers available`);
  console.log('');
  
  // Step 4: Show scoring configuration
  console.log('📡 Step 4: Scoring weights (admin-opaque)');
  const config = dfx('getScoringConfig');
  if (config.includes('base_score')) {
    console.log('   Scoring configuration available');
  }
  console.log('');

  console.log('══════════════════════════════════════════════');
  console.log('  How platforms use credit scoring:');
  console.log('══════════════════════════════════════════════');
  console.log('');
  console.log('  1. Seller applies to marketplace');
  console.log('  2. Marketplace queries VERITAS credit score');
  console.log('  3. Score ≥ 580 (Good) → auto-approve');
  console.log('  4. Score 400-579 (Fair) → manual review');
  console.log('  5. Score < 400 (Poor/Unrated) → request more credentials');
  console.log('  6. Revoked credentials → reject immediately');
  console.log('');
  console.log('  Cost: Free tier = 100 queries/day (no cycles)');
  console.log('        Paid tier = cycles per query');
  console.log('══════════════════════════════════════════════');
}

main().catch(console.error);
