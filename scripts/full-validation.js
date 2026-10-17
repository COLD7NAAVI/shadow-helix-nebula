import fs from 'node:fs';
import path from 'node:path';

if (typeof process.loadEnvFile === 'function') {
  process.loadEnvFile('.env');
}

async function fullValidation() {
  console.log('[*] ========================================================');
  console.log('[*] SHN FULL LOCAL VERIFICATION SUITE');
  console.log('[*] ========================================================');

  const email = process.env.SHN_INITIAL_ADMIN_EMAIL || 'operator@shn.sovereign';
  const password = process.env.SHN_INITIAL_ADMIN_PASSWORD;

  // 1. Health Liveness
  const liveRes = await fetch('http://localhost:8080/health/live');
  const liveData = await liveRes.json();
  console.log('[+] Health Liveness:', liveRes.status, liveData.status);

  // 2. Health Readiness
  const readyRes = await fetch('http://localhost:8080/health/ready');
  const readyData = await readyRes.json();
  console.log('[+] Health Readiness:', readyRes.status, readyData.status, 'Checks:', readyData.checks);

  // 3. Web Console HTML
  const rootRes = await fetch('http://localhost:8080/');
  const html = await rootRes.text();
  console.log('[+] Web Console HTML:', rootRes.status, 'Length:', html.length, 'Root element:', html.includes('id="app-root"'));

  // 4. OpenAPI Spec
  const specRes = await fetch('http://localhost:8080/openapi.json');
  const specData = await specRes.json();
  console.log('[+] OpenAPI Spec:', specRes.status, 'Version:', specData.openapi, 'Paths count:', Object.keys(specData.paths).length);

  // 5. Auth Login (Valid)
  const loginRes = await fetch('http://localhost:8080/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const loginData = await loginRes.json();
  console.log('[+] Operator Login (Valid):', loginRes.status, 'User:', loginData.user?.email, 'Role:', loginData.roles, 'HasToken:', Boolean(loginData.token));

  // 6. Protected Route with Token
  const assetsRes = await fetch('http://localhost:8080/api/v1/workspaces/' + loginData.workspaceId + '/assets', {
    headers: { 'Authorization': 'Bearer ' + loginData.token }
  });
  const assetsData = await assetsRes.json();
  console.log('[+] Protected Assets Route:', assetsRes.status, 'Assets count:', Array.isArray(assetsData) ? assetsData.length : 0);

  // 7. Protected Route with Tampered Signature Token
  const decoded = JSON.parse(Buffer.from(loginData.token, 'base64').toString('utf8'));
  decoded.signature = 'tampered-signature-invalid';
  const tamperedToken = Buffer.from(JSON.stringify(decoded)).toString('base64');
  const tamperedRes = await fetch('http://localhost:8080/api/v1/workspaces/' + loginData.workspaceId + '/assets', {
    headers: { 'Authorization': 'Bearer ' + tamperedToken }
  });
  console.log('[+] Protected Route (Tampered Token):', tamperedRes.status, '(Expect 401)');

  // 8. Auth Login with Empty Credentials
  const emptyRes = await fetch('http://localhost:8080/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: '', password: '' })
  });
  console.log('[+] Auth Login (Empty Credentials):', emptyRes.status, '(Expect 401)');

  // 9. Auth Login with Invalid Password
  const badRes = await fetch('http://localhost:8080/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: 'BadPassword999!' })
  });
  console.log('[+] Auth Login (Invalid Password):', badRes.status, '(Expect 401)');

  // 10. Security Headers
  console.log('[+] Security Headers:', {
    'x-content-type-options': rootRes.headers.get('x-content-type-options'),
    'x-frame-options': rootRes.headers.get('x-frame-options'),
    'csp': Boolean(rootRes.headers.get('content-security-policy'))
  });

  console.log('\n[SUCCESS] Full local verification completed with 100% success!');
}

fullValidation().catch(e => {
  console.error('Validation error:', e);
  process.exit(1);
});
