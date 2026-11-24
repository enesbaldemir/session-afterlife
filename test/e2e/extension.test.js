import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startDemo, launch, openPanel, signIn, pickReference, snapshot, lastResult } from './helpers.js';

let env;
before(async () => { env = await launch(); });
after(async () => { await env?.close(); });

async function scenario(opts, fn) {
  const demo = await startDemo(opts);
  const panel = await openPanel(env, demo.base);
  const site = await env.context.newPage();
  try {
    await fn({ demo, panel, site });
  } finally {
    await site.close();
    await panel.close();
    await demo.close();
    await env.context.clearCookies();
  }
}

async function checkLogout(flaws) {
  let result;
  await scenario({ flaws }, async ({ demo, panel, site }) => {
    await signIn(site, demo.base);
    await pickReference(panel, '/account');
    await snapshot(panel);
    assert.match(await panel.locator('#s-main').textContent(), /Authenticated and anonymous responses differ/);
    assert.match(await panel.locator('#s-session').textContent(), /(29d 23h|30d 0h) left/, 'declared cookie lifetime is shown');
    await site.click('#logout');
    await site.waitForURL(/\/login\?logged_out=1/);
    await panel.getByRole('button', { name: 'Logout', exact: true }).click();
    await panel.getByRole('button', { name: 'Check old session' }).click();
    result = await lastResult(panel);
  });
  return result;
}

test('logout that only clears the cookie is reported as a failure', { timeout: 90_000 }, async () => {
  const r = await checkLogout(['logout']);
  assert.equal(r.badge, 'FAIL');
  assert.equal(r.browser, 'cookie deleted ✓');
  assert.equal(r.server, 'old session still valid ✗');
});

test('logout that replaces the cookie but keeps the session is reported as a failure', { timeout: 90_000 }, async () => {
  const r = await checkLogout(['logout-rotate']);
  assert.equal(r.badge, 'FAIL');
  assert.equal(r.browser, 'cookie replaced ✓');
  assert.equal(r.server, 'old session still valid ✗');
});

test('correct logout passes', { timeout: 90_000 }, async () => {
  const r = await checkLogout([]);
  assert.equal(r.badge, 'PASS');
  assert.equal(r.server, 'old session rejected ✓');
});

async function checkPassword(flaws) {
  let result;
  await scenario({ flaws }, async ({ demo, panel, site }) => {
    await signIn(site, demo.base);
    await pickReference(panel, '/account');
    await snapshot(panel);
    await panel.getByRole('button', { name: 'Password change' }).click();
    await panel.getByRole('button', { name: 'Start second session' }).click();
    await panel.getByRole('button', { name: 'Second session started ✓' }).waitFor();
    // The browser now holds no session: a fresh login creates session B.
    await signIn(site, demo.base);
    await site.goto(`${demo.base}/password`);
    await site.fill('input[name=current]', 'wonderland');
    await site.fill('input[name=next]', 'looking-glass');
    await site.click('form button');
    await site.getByText('Password changed').waitFor();
    // Session B is valid in the browser; the check must not use it.
    await panel.getByRole('button', { name: 'Check old session' }).click();
    result = await lastResult(panel);
  });
  return result;
}

test('password change that keeps other sessions is reported as a failure', { timeout: 90_000 }, async () => {
  const r = await checkPassword(['password']);
  assert.equal(r.badge, 'FAIL');
  assert.equal(r.browser, 'second session');
  assert.equal(r.server, 'old session still valid ✗');
});

test('password change that ends other sessions passes, and the browser\'s own valid cookie is not used', { timeout: 90_000 }, async () => {
  const r = await checkPassword([]);
  assert.equal(r.badge, 'PASS');
  assert.equal(r.server, 'old session rejected ✓');
});

async function checkBearer(flaws) {
  let result;
  await scenario({ flaws }, async ({ demo, panel, site }) => {
    await site.goto(`${demo.base}/spa`);
    await site.fill('#login input[name=password]', 'wonderland');
    await site.click('#login button');
    await site.getByText('Signed in as alice').waitFor();
    await pickReference(panel, '/api/profile');
    assert.match(await panel.locator('.reqs li', { hasText: '/api/profile' }).first().innerHTML(), /tag on">auth header/);
    await snapshot(panel);
    assert.match(await panel.locator('#s-session').textContent(), /Authorization/);
    assert.match(await panel.locator('#s-findings').textContent(), /lifetime 1h 0m/, 'JWT exp/iat is read');
    await site.click('#logout');
    await site.getByText('Not signed in.').waitFor();
    await panel.getByRole('button', { name: 'Logout', exact: true }).click();
    await panel.getByRole('button', { name: 'Check old session' }).click();
    result = await lastResult(panel);
  });
  return result;
}

test('bearer token that survives logout is reported as a failure', { timeout: 90_000 }, async () => {
  const r = await checkBearer(['jwt']);
  assert.equal(r.badge, 'FAIL');
  assert.equal(r.server, 'old session still valid ✗');
});

test('bearer token revoked on logout passes', { timeout: 90_000 }, async () => {
  const r = await checkBearer([]);
  assert.equal(r.badge, 'PASS');
});

test('idle timeout is bracketed (time unit shortened to seconds)', { timeout: 90_000 }, async () => {
  await scenario({ idle: 8 }, async ({ demo, panel, site }) => {
    await panel.evaluate(() => chrome.storage.local.set({ debugTimeUnitMs: 1000 }));
    await signIn(site, demo.base);
    await pickReference(panel, '/account');
    await snapshot(panel);
    await site.goto('about:blank'); // leave the site alone
    await panel.getByRole('button', { name: 'Idle timeout' }).click();
    await panel.getByRole('button', { name: 'Start' }).click();
    await panel.locator('.progress').waitFor({ timeout: 5000 }).catch(async (e) => {
      throw new Error(`${e.message}\nPANEL ERROR: ${await panel.locator('#error').textContent()}\nMAIN: ${await panel.locator("#s-main").textContent()}`);
    });
    const r = await lastResult(panel, 60_000);
    assert.equal(r.badge, 'INFO');
    assert.equal(r.server, 'expired');
    // waits are 1, 2, 3, 5, 8 units: valid after 5, expired after 8
    assert.match(r.text, /Idle timeout is between 5 × 1s and 8 × 1s/);
    await panel.evaluate(() => chrome.storage.local.remove('debugTimeUnitMs'));
  });
});

test('report export contains the verdicts but no secrets', { timeout: 90_000 }, async () => {
  await scenario({ flaws: ['logout'] }, async ({ demo, panel, site }) => {
    await signIn(site, demo.base);
    const sid = (await env.context.cookies(demo.base)).find((c) => c.name === 'sid').value;
    await pickReference(panel, '/account');
    await snapshot(panel);
    await site.click('#logout');
    await site.waitForURL(/logged_out/);
    await panel.getByRole('button', { name: 'Logout', exact: true }).click();
    await panel.getByRole('button', { name: 'Check old session' }).click();
    await lastResult(panel);
    const md = await panel.evaluate(async (origin) => {
      const { toMarkdown } = await import('./lib/report.js');
      const { auditSession } = await import('./lib/findings.js');
      const res = await chrome.runtime.sendMessage({ type: 'getState' });
      const site = res.state.sites[origin];
      return toMarkdown(site, { findings: auditSession(site) });
    }, demo.base);
    assert.match(md, /Logout \(WSTG-SESS-06\): FAIL/);
    assert.match(md, /`sid` deleted/);
    assert.ok(!md.includes(sid), 'session id is not in the report');
  });
});

test('absolute timeout is found while the session is kept active', { timeout: 90_000 }, async () => {
  await scenario({ absolute: 10 }, async ({ demo, panel, site }) => {
    await panel.evaluate(() => chrome.storage.local.set({ debugTimeUnitMs: 1000 }));
    await signIn(site, demo.base);
    await pickReference(panel, '/account');
    await snapshot(panel);
    await site.goto('about:blank');
    await panel.getByRole('button', { name: 'Absolute timeout' }).click();
    await panel.locator('#abs-interval').selectOption('2');
    await panel.getByRole('button', { name: 'Start' }).click();
    const r = await lastResult(panel, 40_000);
    assert.equal(r.server, 'expired');
    // Probes every 2 units keep it active; it still dies 10 units after login.
    // The measurement starts a little after login, so only the bracket is checked.
    const m = /session ended between (\d+) × 1s and (\d+) × 1s/.exec(r.text);
    assert.ok(m, r.text);
    assert.equal(Number(m[2]) - Number(m[1]), 2);
    const since = Number(/(\d+)s after recording/.exec(r.text)[1]);
    assert.ok(since >= 4 && since <= 12, `ended ${since}s after the snapshot`);
    await panel.evaluate(() => chrome.storage.local.remove('debugTimeUnitMs'));
  });
});

test('manual mode refuses to replay a logout-like request', { timeout: 90_000 }, async () => {
  await scenario({}, async ({ demo, panel, site }) => {
    await signIn(site, demo.base);
    await site.goto(`${demo.base}/logout`); // a GET to a logout-looking URL (404 in the demo)
    const item = panel.locator('.reqs li', { hasText: '/logout' }).first();
    await item.waitFor();
    await item.locator('input[type=radio]').click();
    await panel.locator('#error', { hasText: 'never replayed' }).waitFor();
    assert.equal(await panel.locator('.reqs input:checked').count(), 0);
  });
});
