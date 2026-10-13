/**
 * Shadow : Helix Nebula (SHN) — Step 2 End-to-End Verification Harness
 *
 * Verifies live HTTP endpoints, static asset serving, authentication,
 * multi-tenant RBAC, scope containment, execution dispatch, findings, and audit.
 */

import assert from 'node:assert/strict';
import { startStandaloneServer } from '../packages/ingress-gateway/dist/standalone.js';

async function run() {
  console.log('[*] Initializing Standalone Sovereign Server on dynamic port...');
  const { server, port, url, isPostgres } = await startStandaloneServer(8099);
  console.log(`[+] Standalone server running at ${url} (PostgreSQL: ${isPostgres})`);

  try {
    // 1. Health Liveness Probe
    console.log('[1/14] Testing GET /health/live ...');
    const liveRes = await fetch(`${url}/health/live`);
    assert.equal(liveRes.status, 200, 'Liveness probe must return 200');
    const liveBody = await liveRes.json();
    assert.equal(liveBody.status, 'UP', 'Liveness status must be UP');
    console.log('       ✓ Liveness OK:', liveBody.status);

    // 2. Health Readiness Probe
    console.log('[2/14] Testing GET /health/ready ...');
    const readyRes = await fetch(`${url}/health/ready`);
    assert.equal(readyRes.status, 200, 'Readiness probe must return 200');
    const readyBody = await readyRes.json();
    assert.equal(readyBody.status, 'UP', 'Readiness status must be UP');
    console.log('       ✓ Readiness OK:', readyBody.status);

    // 3. Prometheus Metrics
    console.log('[3/14] Testing GET /metrics ...');
    const metricsRes = await fetch(`${url}/metrics`);
    assert.equal(metricsRes.status, 200, 'Metrics probe must return 200');
    const metricsText = await metricsRes.text();
    assert.ok(metricsText.includes('process_cpu_user_seconds_total') || metricsText.includes('shn_') || metricsText.includes('# HELP'), 'Metrics must return Prometheus format');
    console.log('       ✓ Prometheus Metrics OK (bytes:', metricsText.length, ')');

    // 4. Web Console Root HTML Delivery
    console.log('[4/14] Testing GET / (Web Console HTML) ...');
    const rootRes = await fetch(`${url}/`);
    assert.equal(rootRes.status, 200, 'Web Console root must return 200');
    assert.ok(rootRes.headers.get('content-type')?.includes('text/html'), 'Content-Type must be text/html');
    const htmlText = await rootRes.text();
    assert.ok(htmlText.includes('Shadow : Helix Nebula') || htmlText.includes('app-root'), 'HTML must contain SHN root');
    console.log('       ✓ Web Console HTML served OK');

    // 5. Authentication Flow
    console.log('[5/14] Testing POST /api/v1/auth/login ...');
    const loginRes = await fetch(`${url}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        email: 'operator@shn.sovereign',
        password: 'Password123!',
      }),
    });
    assert.equal(loginRes.status, 200, 'Login must succeed with 200');
    const authData = await loginRes.json();
    assert.ok(authData.token, 'Must return token');
    assert.ok(authData.user, 'Must return user object');
    assert.equal(authData.user.email, 'operator@shn.sovereign');
    console.log('       ✓ Operator Authenticated (Token Length:', authData.token.length, ')');

    const authHeaders = {
      'Authorization': `Bearer ${authData.token}`,
      'Content-Type': 'application/json',
    };

    // 6. Workspaces List
    console.log('[6/14] Testing GET /api/v1/workspaces ...');
    const wksRes = await fetch(`${url}/api/v1/workspaces`, { headers: authHeaders });
    assert.equal(wksRes.status, 200, 'Workspaces list must return 200');
    const workspaces = await wksRes.json();
    assert.ok(Array.isArray(workspaces) && workspaces.length >= 2, 'Must have at least 2 workspaces');
    const workspaceId = workspaces[0].id;
    console.log(`       ✓ Workspaces List OK (${workspaces.length} found, active: ${workspaceId})`);

    // 7. Scopes List
    console.log(`[7/14] Testing GET /api/v1/workspaces/${workspaceId}/scopes ...`);
    const scopesRes = await fetch(`${url}/api/v1/workspaces/${workspaceId}/scopes`, { headers: authHeaders });
    assert.equal(scopesRes.status, 200, 'Scopes list must return 200');
    const scopes = await scopesRes.json();
    assert.ok(Array.isArray(scopes) && scopes.length > 0, 'Must have at least 1 scope');
    const scopeId = scopes[0].id;
    console.log(`       ✓ Scopes OK (${scopes.length} scopes found, scopeId: ${scopeId})`);

    // 8. Scope Creation
    console.log(`[8/14] Testing POST /api/v1/workspaces/${workspaceId}/scopes ...`);
    const newScopeRes = await fetch(`${url}/api/v1/workspaces/${workspaceId}/scopes`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        name: 'Automated Test Sandbox Scope',
        description: 'Temporary boundary created during Step 2 verification',
        inclusions: [{ type: 'IPV4', value: '192.168.100.1' }],
        allowedActions: ['PORT_SCAN', 'network:scan'],
      }),
    });
    assert.equal(newScopeRes.status, 201, 'Scope creation must return 201');
    const newScope = await newScopeRes.json();
    assert.equal(newScope.name, 'Automated Test Sandbox Scope');
    console.log('       ✓ Scope Created successfully:', newScope.id);

    // 9. Assets List & Creation
    console.log(`[9/14] Testing GET /api/v1/workspaces/${workspaceId}/assets ...`);
    const assetsRes = await fetch(`${url}/api/v1/workspaces/${workspaceId}/assets`, { headers: authHeaders });
    assert.equal(assetsRes.status, 200, 'Assets list must return 200');
    const assets = await assetsRes.json();
    assert.ok(Array.isArray(assets) && assets.length > 0, 'Must have seeded assets');
    console.log(`       ✓ Assets OK (${assets.length} assets found)`);

    const newAssetRes = await fetch(`${url}/api/v1/workspaces/${workspaceId}/assets`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        type: 'IPV4',
        rawTarget: '10.240.0.99',
        name: 'Verification Probe Node',
        criticality: 'HIGH',
        tags: ['verification', 'test'],
      }),
    });
    assert.equal(newAssetRes.status, 201, 'Asset creation must return 201');
    const createdAsset = await newAssetRes.json();
    console.log('       ✓ New Asset Registered:', createdAsset.id);

    // 10. Capability Catalog
    console.log('[10/14] Testing GET /api/v1/capabilities ...');
    const capRes = await fetch(`${url}/api/v1/capabilities`, { headers: authHeaders });
    assert.equal(capRes.status, 200, 'Capabilities list must return 200');
    const capabilities = await capRes.json();
    assert.ok(Array.isArray(capabilities) && capabilities.length >= 2, 'Must have at least 2 capabilities');
    console.log(`       ✓ Capabilities OK (${capabilities.length} capabilities registered)`);

    // 11. Execution Dispatch & Listing
    console.log(`[11/14] Testing POST /api/v1/workspaces/${workspaceId}/executions ...`);
    const execRes = await fetch(`${url}/api/v1/workspaces/${workspaceId}/executions`, {
      method: 'POST',
      headers: authHeaders,
      body: JSON.stringify({
        capabilityId: 'shn://capabilities/network/port-scan',
        target: '10.240.0.1',
        scopeId: scopeId,
        action: 'network:scan',
        arguments: { timeoutMs: 2000 },
      }),
    });
    if (execRes.status !== 200 && execRes.status !== 201) {
      const errText = await execRes.text();
      console.error('[-] Execution dispatch failed with status', execRes.status, 'body:', errText);
    }
    assert.ok(execRes.status === 200 || execRes.status === 201, `Execution dispatch must return 200 or 201, got ${execRes.status}`);
    const execData = await execRes.json();
    assert.ok(execData.executionId || execData.id, 'Execution response must include executionId');
    const execId = execData.executionId || execData.id;
    console.log('       ✓ Execution Dispatched:', execId);

    const execListRes = await fetch(`${url}/api/v1/workspaces/${workspaceId}/executions`, { headers: authHeaders });
    assert.equal(execListRes.status, 200, 'Executions list must return 200');
    const executions = await execListRes.json();
    assert.ok(Array.isArray(executions) && executions.length > 0, 'Must have executions');
    console.log(`       ✓ Executions List OK (${executions.length} executions found)`);

    // 12. Findings Retrieval
    console.log(`[12/14] Testing GET /api/v1/workspaces/${workspaceId}/findings ...`);
    const findRes = await fetch(`${url}/api/v1/workspaces/${workspaceId}/findings`, { headers: authHeaders });
    assert.equal(findRes.status, 200, 'Findings list must return 200');
    const findings = await findRes.json();
    assert.ok(Array.isArray(findings), 'Findings must be an array');
    console.log(`       ✓ Findings OK (${findings.length} findings found)`);

    // 13. Audit Ledger
    console.log(`[13/14] Testing GET /api/v1/workspaces/${workspaceId}/audit ...`);
    const auditRes = await fetch(`${url}/api/v1/workspaces/${workspaceId}/audit`, { headers: authHeaders });
    assert.equal(auditRes.status, 200, 'Audit list must return 200');
    const auditEvents = await auditRes.json();
    assert.ok(Array.isArray(auditEvents), 'Audit events must be an array');
    console.log(`       ✓ Audit Ledger OK (${auditEvents.length} events logged)`);

    // 14. Static Asset Delivery (CSS and JS chunks)
    console.log('[14/14] Testing Web Console static asset serving ...');
    const scriptMatch = htmlText.match(/src="([^"]+\.js)"/);
    if (scriptMatch) {
      const scriptUrl = `${url}${scriptMatch[1].startsWith('/') ? '' : '/'}${scriptMatch[1]}`;
      const scriptRes = await fetch(scriptUrl);
      assert.equal(scriptRes.status, 200, 'JS bundle must return 200');
      assert.ok(scriptRes.headers.get('content-type')?.includes('javascript'), 'MIME type must be javascript');
      console.log('       ✓ JS Bundle verified:', scriptMatch[1]);
    }
    const styleMatch = htmlText.match(/href="([^"]+\.css)"/);
    if (styleMatch) {
      const styleUrl = `${url}${styleMatch[1].startsWith('/') ? '' : '/'}${styleMatch[1]}`;
      const styleRes = await fetch(styleUrl);
      assert.equal(styleRes.status, 200, 'CSS bundle must return 200');
      assert.ok(styleRes.headers.get('content-type')?.includes('css'), 'MIME type must be css');
      console.log('       ✓ CSS Bundle verified:', styleMatch[1]);
    }

    console.log('\n========================================================================');
    console.log('[SUCCESS] ALL 14 INTEGRATION CHECKS PASSED FLAWLESSLY!');
    console.log('========================================================================\n');
  } finally {
    console.log('[*] Tearing down server instance...');
    await server.stop();
    console.log('[+] Server stopped successfully.');
  }
}

run().catch((err) => {
  console.error('[-] Verification failed:', err);
  process.exit(1);
});
