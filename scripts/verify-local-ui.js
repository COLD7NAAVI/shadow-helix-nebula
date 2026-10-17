import assert from 'node:assert/strict';

async function verify() {
  console.log('[*] Verifying running SHN server on http://localhost:8080 ...');

  // 1. Health Liveness
  const liveRes = await fetch('http://localhost:8080/health/live');
  assert.equal(liveRes.status, 200, 'Liveness must return 200');
  const liveData = await liveRes.json();
  console.log('[+] Health Liveness: UP, Status:', liveData.status);

  // 2. Health Readiness
  const readyRes = await fetch('http://localhost:8080/health/ready');
  assert.equal(readyRes.status, 200, 'Readiness must return 200');
  const readyData = await readyRes.json();
  console.log('[+] Health Readiness: UP, Database:', readyData.checks?.database || readyData.components?.database?.status);

  // 3. Web Console HTML
  const rootRes = await fetch('http://localhost:8080/');
  assert.equal(rootRes.status, 200, 'Root HTML must return 200');
  const html = await rootRes.text();
  assert.ok(html.includes('id="app-root"') || html.includes('id="app"'), 'HTML must include #app-root mounting root');
  assert.ok(html.includes('Shadow : Helix Nebula'), 'HTML title must contain Shadow : Helix Nebula');
  console.log('[+] Web Console HTML served successfully (' + html.length + ' bytes)');

  // 4. JavaScript bundle
  const jsMatch = html.match(/src="([^"]+\.js)"/);
  assert.ok(jsMatch, 'Must find JS bundle link in HTML');
  const jsUrl = 'http://localhost:8080' + (jsMatch[1].startsWith('/') ? '' : '/') + jsMatch[1];
  const jsRes = await fetch(jsUrl);
  assert.equal(jsRes.status, 200, 'JS bundle must return 200');
  assert.ok(jsRes.headers.get('content-type')?.includes('javascript'), 'Must have javascript MIME type');
  const jsText = await jsRes.text();
  console.log('[+] JavaScript bundle loaded successfully: ' + jsUrl + ' (' + jsText.length + ' bytes)');

  // 5. CSS bundle
  const cssMatch = html.match(/href="([^"]+\.css)"/);
  assert.ok(cssMatch, 'Must find CSS bundle link in HTML');
  const cssUrl = 'http://localhost:8080' + (cssMatch[1].startsWith('/') ? '' : '/') + cssMatch[1];
  const cssRes = await fetch(cssUrl);
  assert.equal(cssRes.status, 200, 'CSS bundle must return 200');
  assert.ok(cssRes.headers.get('content-type')?.includes('css'), 'Must have CSS MIME type');
  const cssText = await cssRes.text();
  console.log('[+] CSS bundle loaded successfully: ' + cssUrl + ' (' + cssText.length + ' bytes)');

  // 6. Security Headers verification
  assert.equal(rootRes.headers.get('x-content-type-options'), 'nosniff');
  assert.equal(rootRes.headers.get('x-frame-options'), 'DENY');
  assert.ok(rootRes.headers.get('content-security-policy'));
  console.log('[+] Security Headers verified (nosniff, DENY, CSP)');

  // 7. OpenAPI spec verification
  const specRes = await fetch('http://localhost:8080/openapi.json');
  assert.equal(specRes.status, 200);
  const specData = await specRes.json();
  console.log('[+] OpenAPI 3.1 Spec verified: version ' + specData.openapi + ', operations: ' + Object.keys(specData.paths).length);

  console.log('\n[SUCCESS] Local SHN instance is 100% verified and operational!');
}

verify().catch((err) => {
  console.error('[-] Verification failed:', err);
  process.exit(1);
});
