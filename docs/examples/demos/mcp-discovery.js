#!/usr/bin/env node
const CANISTER_ID = process.env.CANISTER_ID || 'ofoea-eyaaa-aaaab-qab6a-cai';
const MCP_URL = `https://${CANISTER_ID}.raw.icp0.io/mcp/jsonrpc`;

async function main() {
  console.log('══════════════════════════════════════════════');
  console.log('  VERITAS MCP Discovery Demo');
  console.log('══════════════════════════════════════════════\n');

  const r = await fetch(MCP_URL);
  const data = await r.json();
  const tools = data.result?.tools || [];
  console.log(`Found ${tools.length} tools:\n`);
  for (const t of tools) {
    const schema = typeof t.inputSchema === 'object' ? t.inputSchema : JSON.parse(t.inputSchema || '{}');
    const params = Object.keys(schema.properties || {}).join(', ') || 'none';
    console.log(`  Tool: ${t.name}`);
    console.log(`  Description: ${t.description.substring(0, 100)}...`);
    console.log(`  Parameters: ${params}\n`);
  }

  const r2 = await fetch(MCP_URL, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list' }),
  });
  const d2 = await r2.json();
  console.log(`POST tools/list: ${d2.result?.tools?.length || 0} tools returned`);

  console.log('\nMCP Endpoint: ' + MCP_URL);
}
main().catch(console.error);
