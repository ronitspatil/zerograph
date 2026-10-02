import { chromium } from 'playwright';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { report } from './reporter.mjs';

const consoleOrigin = 'https://console.oidc.test:8443';
const apiOrigin = 'https://api.oidc.test:8443';
const outcomes = [];
let stage = 'initialize disposable browser fixture';
let browser;
let accounts;
let diagnostics;
const require = condition => { if (!condition) throw new Error('fixed assertion'); };
const step = label => { stage = label; };
const snapshot = {
  nodes: [
    { id: 'agent:browser', name: 'Browser Agent', type: 'AIAgent', provider: 'fixture' },
    { id: 'data:browser', name: 'Browser Data', type: 'Database', provider: 'fixture', sensitivity: 'restricted' },
  ],
  edges: [{ source: 'agent:browser', target: 'data:browser', type: 'CAN_READ',
    certainty: 'confirmed', evidence: ['Disposable browser fixture'] }],
};

async function api(page, method, path, body) {
  return page.evaluate(async ({ method, path, body }) => {
    const response = await fetch('/api/zg/' + path, { method,
      headers: { 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    return { status: response.status, body: await response.json() };
  }, { method, path, body });
}

async function visible(locator) { await locator.waitFor({ state: 'visible', timeout: 15000 }); }

async function login(context, username) {
  const page = await context.newPage();
  const health = { errors: 0, active: true };
  let documentPolicy = '';
  page.on('pageerror', () => { if (health.active) { health.errors++; diagnostics.page_errors++; } });
  page.on('console', message => {
    if (health.active && message.type() === 'error') {
      health.errors++; diagnostics.console_errors++;
      if (/content security policy/i.test(message.text())) diagnostics.csp_errors++;
    }
  });
  page.on('response', response => {
    const url = new URL(response.url());
    if (url.origin === consoleOrigin && url.pathname === '/' && response.request().resourceType() === 'document') {
      documentPolicy = response.headers()['content-security-policy'] || '';
    }
    if (url.origin === consoleOrigin && url.pathname.startsWith('/api/zg/')) {
      const status = response.status();
      if (status >= 200 && status < 300) diagnostics.api_success++;
      if (status === 401 || status === 403) diagnostics.api_denied++;
      if (status >= 500) diagnostics.api_server_errors++;
    }
  });
  step('validated HTTPS protected navigation');
  await page.goto(consoleOrigin + '/', { waitUntil: 'domcontentloaded' });
  require(new URL(page.url()).pathname === '/login');
  require(await page.getByRole('button', { name: 'Explore the demo workspace' }).count() === 0);
  step('browser provider redirect and credential form');
  await page.getByRole('link', { name: 'Sign in with your organization' }).click();
  await visible(page.locator('#username'));
  require(new URL(page.url()).origin === 'https://auth.oidc.test:8443');
  await page.locator('#username').fill(username);
  await page.locator('#password').fill(accounts[username]);
  await page.locator('#kc-login').click();
  step('provider returns browser to console origin');
  await page.waitForURL(url => url.origin === consoleOrigin, { timeout: 15000 });
  step('authorized callback lands workspace');
  require(new URL(page.url()).pathname === '/');
  step('workspace graph heading rendered');
  await visible(page.getByRole('heading', { name: 'Identity & data graph', exact: true }));
  const nonce = documentPolicy.match(/'nonce-([^']+)'/)?.[1] || '';
  diagnostics.document_nonce_present = nonce ? 1 : 0;
  Object.assign(diagnostics, await page.evaluate(expected => {
    const scripts = [...document.scripts];
    return { script_count: scripts.length,
      script_nonce_match: scripts.filter(script => expected && script.nonce === expected).length,
      script_nonce_mismatch: scripts.filter(script => !expected || script.nonce !== expected).length };
  }, nonce));
  step('hydrated console API connection');
  await visible(page.getByText('API connected', { exact: true }));
  require(new URL(page.url()).origin === consoleOrigin);
  step('workspace has no application error banner');
  // Next's accessibility route announcer has role=alert during normal navigation.
  require(await page.locator('.error-banner[role="alert"]').count() === 0);
  step('secure cookie and HttpOnly DOM enforcement');
  const cookies = await context.cookies(consoleOrigin);
  const session = cookies.find(cookie => cookie.name === 'zg_session');
  require(session && session.secure && session.httpOnly && session.sameSite === 'Lax');
  require(!(await page.evaluate(() => document.cookie)).includes('zg_session'));
  require(session.value.split('.').length === 5);
  return { page, health, session };
}

async function run(label, action) {
  diagnostics = { page_errors: 0, console_errors: 0, csp_errors: 0,
    api_success: 0, api_denied: 0, api_server_errors: 0,
    document_nonce_present: 0, script_count: 0, script_nonce_match: 0, script_nonce_mismatch: 0 };
  const context = await browser.newContext({ ignoreHTTPSErrors: false, viewport: { width: 1440, height: 1000 } });
  try {
    await action(context);
    outcomes.push({ label, stage: 'complete', passed: true, diagnostics: { ...diagnostics } });
  } catch {
    outcomes.push({ label, stage, passed: false, diagnostics: { ...diagnostics } });
  } finally {
    await context.close();
  }
}

try {
  accounts = JSON.parse(await readFile(join(process.env.ZG_OIDC_FIXTURE_DIR, 'accounts.json'), 'utf8'));
  step('real HTTPS provider discovery readiness');
  const deadline = Date.now() + 120000;
  let ready = false;
  while (Date.now() < deadline) {
    try {
      const response = await fetch('https://auth.oidc.test:8443/realms/zerograph/.well-known/openid-configuration',
        { signal: AbortSignal.timeout(5000) });
      ready = response.ok && (await response.json()).issuer === 'https://auth.oidc.test:8443/realms/zerograph';
      if (ready) break;
    } catch { /* Only fixed stages escape this runner. */ }
    await new Promise(resolve => setTimeout(resolve, 1000));
  }
  require(ready);
  step('launch verified Chromium');
  browser = await chromium.launch({ headless: true, channel: 'chromium',
    env: { ...process.env, HOME: process.env.ZG_BROWSER_HOME, DEBUG: '', PWDEBUG: '' } });

  await run('admin UI ingestion graph and simulation', async context => {
    const { page, health } = await login(context, 'admin-a');
    step('browser UI synthetic snapshot ingestion');
    await page.getByRole('button', { name: 'Data sources', exact: true }).click();
    await page.getByLabel('JSON inventory').fill(JSON.stringify(snapshot));
    const accepted = page.waitForResponse(response => response.url() === consoleOrigin + '/api/zg/ingestions'
      && response.request().method() === 'POST');
    await page.getByRole('button', { name: 'Queue ingestion', exact: true }).click();
    require((await accepted).status() === 202);
    await visible(page.getByText('completed', { exact: true }));
    step('graph rendering keyboard selection and filter');
    await page.getByRole('button', { name: 'Knowledge graph', exact: true }).click();
    await visible(page.getByRole('img', { name: /Identity and data graph with 2 nodes/ }));
    require(await page.locator('.graph-canvas canvas').count() > 0);
    const identity = page.getByRole('button', { name: 'Browser Agent', exact: true });
    await identity.focus();
    await page.keyboard.press('Enter');
    await visible(page.getByRole('heading', { name: 'Browser Agent', exact: true }));
    await page.getByLabel('Search identities').fill('Browser Data');
    await visible(page.getByRole('img', { name: /Identity and data graph with 1 nodes/ }));
    await page.getByLabel('Search identities').fill('');
    await visible(page.getByRole('img', { name: /Identity and data graph with 2 nodes/ }));
    step('simulator UI actual response and traversal slider');
    await page.getByRole('button', { name: 'Simulate compromise', exact: true }).click();
    await visible(page.locator('.affected-asset').getByText('data:browser', { exact: true }));
    const simulated = page.waitForResponse(response => response.url() === consoleOrigin + '/api/zg/simulate');
    await page.getByLabel('Traversal depth').fill('1');
    require((await simulated).status() === 200);
    await visible(page.getByText('1 hops', { exact: true }));
    step('normal UI console and page error counts');
    require(health.errors === 0);
  });

  for (const [username, role, writable] of [['viewer-a', 'Viewer', false], ['analyst-a', 'Analyst', true]]) {
    await run(role + ' browser role boundaries', async context => {
      const { page, health } = await login(context, username);
      step('signed persona role and graph UI');
      await visible(page.locator('.user').getByText(role, { exact: true }));
      await page.getByRole('button', { name: 'Browser Agent', exact: true }).click();
      require(await page.getByRole('button', { name: 'Simulate compromise', exact: true }).isEnabled() === writable);
      if (writable) {
        await page.getByRole('button', { name: 'Simulate compromise', exact: true }).click();
        await visible(page.locator('.affected-asset').getByText('data:browser', { exact: true }));
        await page.getByRole('button', { name: 'Return to graph', exact: true }).click();
      }
      await page.getByRole('button', { name: 'Remediation', exact: true }).click();
      require(await page.getByRole('button', { name: 'Generate least-privilege preview', exact: true }).isEnabled() === writable);
      await page.getByRole('button', { name: 'Data sources', exact: true }).click();
      await page.getByLabel('JSON inventory').fill(JSON.stringify(snapshot));
      require(await page.getByRole('button', { name: 'Queue ingestion', exact: true }).isDisabled());
      step('normal persona UI has no console or page errors');
      require(health.errors === 0);
      health.active = false; // Expected denied fetches intentionally produce browser resource errors.
      step('browser authenticated mutation and audit denial');
      require((await api(page, 'POST', 'ingestions', { source: 'snapshot', payload: snapshot })).status === 403);
      require((await api(page, 'GET', 'audit')).status === 403);
      if (!writable) require((await api(page, 'POST', 'simulate', { node_id: 'agent:browser' })).status === 403);
    });
  }

  await run('cross-origin form denial and browser logout', async context => {
    const { page, health, session } = await login(context, 'viewer-a');
    step('cross-origin browser form mutation denied');
    const attacker = await context.newPage();
    const healthResponse = await attacker.goto(apiOrigin + '/health/live', { waitUntil: 'domcontentloaded' });
    require(healthResponse.status() === 200);
    const denied = attacker.waitForResponse(response => response.url() === consoleOrigin + '/api/auth/logout');
    await attacker.evaluate(target => {
      const form = document.createElement('form');
      form.action = target; form.method = 'POST'; document.body.append(form); form.submit();
    }, consoleOrigin + '/api/auth/logout');
    require((await denied).status() === 403);
    require((await api(page, 'GET', 'me')).status === 200);
    step('actual sign-out click removes encrypted cookie');
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await visible(page.getByRole('link', { name: 'Sign in with your organization' }));
    require(!(await context.cookies(consoleOrigin)).some(cookie => cookie.name === 'zg_session'));
    require(health.errors === 0);
    health.active = false;
    require((await api(page, 'GET', 'me')).status === 401);
    // Logout clears the browser session; cryptographic revocation of copied cookies is not claimed.
    require(session.secure);
  });

  await run('expired encrypted session replay denied', async context => {
    const { page, health, session } = await login(context, 'viewer-a');
    step('bounded actual session expiry');
    const wait = session.expires * 1000 - Date.now() + 11000;
    require(wait > 0 && wait <= 75000);
    await new Promise(resolve => setTimeout(resolve, wait));
    health.active = false;
    step('expired-cookie replay into browser context');
    await context.addCookies([{ ...session, expires: Date.now() / 1000 + 120 }]);
    require((await api(page, 'GET', 'me')).status === 401);
    await page.getByRole('button', { name: 'Refresh workspace', exact: true }).click();
    await visible(page.getByRole('link', { name: 'Sign in with your organization' }));
  });
} catch {
  outcomes.push({ label: 'browser fixture infrastructure', stage, passed: false });
} finally {
  if (browser) await browser.close().catch(() => {});
}

try {
  const success = await report(outcomes, process.env.ZG_BROWSER_RESULT);
  console.log(`Browser qualification: ${outcomes.filter(item => item.passed).length} passed, ${outcomes.filter(item => !item.passed).length} failed (fixed labels only)`);
  process.exitCode = success ? 0 : 1;
} catch {
  console.log('Browser qualification: sanitized result persistence failed');
  process.exitCode = 1;
}
