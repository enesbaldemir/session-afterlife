// Automatic mode: after "Use this site", the user only uses the site.
// No clicks in the panel except where noted.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { startDemo, launch, openPanel, signIn, lastResult, waitStatus } from './helpers.js';

let env;
before(async () => { env = await launch(); });
after(async () => { await env?.close(); });

async function scenario(opts, fn) {
  const demo = await startDemo(opts);
  const panel = await openPanel(env, demo.base, { mode: 'auto' });
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

async function autoLogout(flaws) {
  let r;
  await scenario({ flaws }, async ({ demo, panel, site }) => {
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
    assert.match(await panel.locator('#s-main').textContent(), /GET \/account/);
    await site.click('#logout');
    r = await lastResult(panel, 20_000);
    assert.match(r.text, /auto/);
    // It re-arms when the user signs in again.
    await waitStatus(panel, 'Waiting for you to sign in');
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
  });
  return r;
}

test('auto: logout that only clears the cookie is caught', { timeout: 90_000 }, async () => {
  const r = await autoLogout(['logout']);
  assert.equal(r.badge, 'FAIL');
  assert.equal(r.browser, 'cookie deleted ✓');
  assert.equal(r.server, 'old session still valid ✗');
});

test('auto: logout that replaces the cookie is caught', { timeout: 90_000 }, async () => {
  const r = await autoLogout(['logout-rotate']);
  assert.equal(r.badge, 'FAIL');
  assert.equal(r.browser, 'cookie replaced ✓');
});

test('auto: correct logout passes', { timeout: 90_000 }, async () => {
  const r = await autoLogout([]);
  assert.equal(r.badge, 'PASS');
});

async function autoPassword(flaws) {
  const out = {};
  await scenario({ flaws }, async ({ demo, panel, site }) => {
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
    // The one panel click: ask for a second session.
    await panel.getByRole('button', { name: 'Test password change and a second login' }).click();
    await waitStatus(panel, 'Sign in again');
    await signIn(site, demo.base);
    await waitStatus(panel, 'Second session found');
    out.elsewhere = await lastResult(panel);
    await site.goto(`${demo.base}/password`);
    await site.fill('input[name=current]', 'wonderland');
    await site.fill('input[name=next]', 'looking-glass');
    await site.click('form button');
    await site.getByText('Password changed').waitFor();
    await panel.locator('#s-results .result .title', { hasText: 'Password change' }).waitFor({ timeout: 20_000 });
    out.password = await lastResult(panel);
  });
  return out;
}

test('auto: password change that keeps other sessions is caught', { timeout: 90_000 }, async () => {
  const r = await autoPassword(['password']);
  assert.equal(r.elsewhere.badge, 'INFO');
  assert.equal(r.elsewhere.server, 'both sessions active');
  assert.equal(r.password.badge, 'FAIL');
});

test('auto: password change that ends other sessions passes', { timeout: 90_000 }, async () => {
  const r = await autoPassword([]);
  assert.equal(r.password.badge, 'PASS');
});

test('auto: a failed password change does not trigger a check', { timeout: 90_000 }, async () => {
  await scenario({}, async ({ demo, panel, site }) => {
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
    await panel.getByRole('button', { name: 'Test password change and a second login' }).click();
    await signIn(site, demo.base);
    await waitStatus(panel, 'Second session found');
    await site.goto(`${demo.base}/password`);
    await site.fill('input[name=current]', 'wrong');
    await site.fill('input[name=next]', 'x');
    await site.click('form button');
    await site.getByText('Password not changed').waitFor();
    await new Promise((r) => setTimeout(r, 4000));
    assert.equal(await panel.locator('#s-results .result .title', { hasText: 'Password change' }).count(), 0);
    await waitStatus(panel, 'Second session found');
  });
});

test('auto: bearer token that survives API logout is caught', { timeout: 90_000 }, async () => {
  await scenario({ flaws: ['jwt'] }, async ({ demo, panel, site }) => {
    await site.goto(`${demo.base}/spa`);
    await site.fill('#login input[name=password]', 'wonderland');
    await site.click('#login button');
    await site.getByText('Signed in as alice').waitFor();
    await waitStatus(panel, 'Watching this session');
    assert.match(await panel.locator('#s-main').textContent(), /\/api\/profile/);
    await site.click('#logout');
    const r = await lastResult(panel, 20_000);
    assert.equal(r.badge, 'FAIL');
    assert.equal(r.server, 'old session still valid ✗');
  });
});

test('auto: public pages before login do not arm it', { timeout: 90_000 }, async () => {
  await scenario({}, async ({ demo, panel, site }) => {
    await site.goto(`${demo.base}/`); // sets a non-session cookie
    await site.goto(`${demo.base}/login`);
    await new Promise((r) => setTimeout(r, 3000));
    await waitStatus(panel, 'Waiting for you to sign in');
  });
});

test('auto: already signed in when the panel is opened', { timeout: 90_000 }, async () => {
  const demo = await startDemo({ flaws: ['logout'] });
  const site = await env.context.newPage();
  try {
    await signIn(site, demo.base);
    // The panel opens next to a tab that already shows a signed-in page.
    const panel = await openPanel(env, demo.base, { mode: 'auto', tab: `${demo.base}/account` });
    await waitStatus(panel, 'Watching this session');
    assert.match(await panel.locator('#s-findings').textContent(), /Session fixation not checked/, 'the sign-in was not seen');
    await site.click('#logout');
    assert.equal((await lastResult(panel, 20_000)).badge, 'FAIL');
    await panel.close();
  } finally {
    await site.close();
    await demo.close();
    await env.context.clearCookies();
  }
});

test('auto: findings for weak cookie, fixation, cache and token in URL', { timeout: 90_000 }, async () => {
  await scenario({ flaws: ['weak-cookie', 'fixation', 'cache', 'token-in-url'] }, async ({ demo, panel, site }) => {
    await site.goto(`${demo.base}/login`);
    await site.fill('input[name=password]', 'wonderland');
    await site.click('form button');
    await site.waitForURL(/\/account\?sid=/); // token-in-url puts the session ID in the URL
    await waitStatus(panel, 'Watching this session');
    const text = (await panel.locator('#s-findings').textContent()).replace(/\s+/g, ' ');
    assert.match(text, /sid can be read by JavaScript/);
    assert.match(text, /sid has no SameSite attribute/);
    assert.match(text, /sid was not renewed at login/);
    assert.match(text, /Signed-in response may be cached/);
    assert.match(text, /sid value appears in a URL/);
    assert.match(text, /kept for (364|365)d/);
    // Findings describe the recorded session and stay the same after logout.
    await site.goto(`${demo.base}/account`);
    await site.click('#logout');
    await lastResult(panel, 20_000);
    assert.match(await panel.locator('#s-findings').textContent(), /sid was not renewed at login/);
  });
});

test('auto: a well-behaved app has no findings and passes fixation', { timeout: 90_000 }, async () => {
  await scenario({}, async ({ demo, panel, site }) => {
    await site.goto(`${demo.base}/`); // a cookie before login
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
    const text = (await panel.locator('#s-findings').textContent()).replace(/\s+/g, ' ');
    assert.match(text, /no issues/);
    assert.match(text, /sid got a new value at login/);
    assert.match(text, /sid is HttpOnly/);
  });
});

test('inspector: values are masked until shown; the session cookie is identified', { timeout: 90_000 }, async () => {
  await scenario({}, async ({ demo, panel, site }) => {
    await site.goto(`${demo.base}/`); // adds a non-session cookie (theme)
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
    const sid = (await env.context.cookies(demo.base)).find((c) => c.name === 'sid').value;
    const box = panel.locator('#s-session');
    assert.ok(!(await box.textContent()).includes(sid), 'masked');
    const row = box.locator('tr', { hasText: 'sid' });
    assert.match(await row.textContent(), /session/, 'sid is tagged as the session cookie');
    assert.doesNotMatch(await box.locator('tr', { hasText: 'theme' }).textContent(), /\bsession\b/);
    await row.getByRole('button', { name: 'Show' }).click();
    assert.ok((await box.textContent()).includes(sid), 'shown');
    const curl = await panel.evaluate(async (origin) => {
      const { toCurl } = await import('./lib/report.js');
      const res = await chrome.runtime.sendMessage({ type: 'getState' });
      return toCurl(res.state.sites[origin]);
    }, demo.base);
    assert.match(curl, new RegExp(`Cookie: (theme=light; )?sid=${sid}|sid=${sid}`));
  });
});

test('scope: sites outside the list are not watched until added', { timeout: 90_000 }, async () => {
  const demo = await startDemo({ flaws: ['logout'] });
  const site = await env.context.newPage();
  const panel = await openPanel(env, demo.base, { mode: 'auto', scope: ['localhost'] });
  try {
    await signIn(site, demo.base);
    await new Promise((r) => setTimeout(r, 2500));
    const before = await panel.evaluate(async () => (await chrome.runtime.sendMessage({ type: 'getState' })).state.sites);
    assert.deepEqual(Object.keys(before), [], '127.0.0.1 is not watched');
    await panel.locator('#scope-details').evaluate((d) => { d.open = true; });
    await panel.fill('#scope-input', `${demo.base}/whatever`);
    await panel.getByRole('button', { name: 'Add', exact: true }).click();
    await panel.locator('#s-scope code', { hasText: '127.0.0.1' }).waitFor();
    await site.reload();
    await waitStatus(panel, 'Watching this session');
  } finally {
    await panel.close();
    await site.close();
    await demo.close();
    await env.context.clearCookies();
  }
});

test('auto: a logout right after the worker wakes up is checked promptly', { timeout: 90_000 }, async () => {
  await scenario({ flaws: ['logout', 'fixation'] }, async ({ demo, panel, site }) => {
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
    // Put the service worker to sleep, as Chrome does after ~30 s of inactivity.
    const cdp = await env.context.newCDPSession(site);
    await cdp.send('ServiceWorker.enable');
    await cdp.send('ServiceWorker.stopAllWorkers');
    await new Promise((r) => setTimeout(r, 1500));
    const t0 = Date.now();
    await site.click('#logout');
    const r = await lastResult(panel, 20_000);
    const ms = Date.now() - t0;
    assert.equal(r.badge, 'FAIL');
    assert.equal(r.browser, 'cookie replaced ✓', 'fixation hands out a new anonymous ID on the login page');
    assert.ok(ms < 6000, `result after ${ms} ms (the 10 s fallback must not be needed)`);
  });
});

test('auto: re-arms after logout even when the login keeps the same session ID (fixation)', { timeout: 90_000 }, async () => {
  await scenario({ flaws: ['logout', 'fixation'] }, async ({ demo, panel, site }) => {
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
    await site.click('#logout');
    await lastResult(panel, 20_000);
    await waitStatus(panel, 'Waiting for you to sign in');
    // The login page hands out an anonymous ID; browse a bit so that it is tried and fails.
    await site.goto(`${demo.base}/account`);
    await site.waitForURL(/\/login/);
    await new Promise((r) => setTimeout(r, 2500));
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
    const text = (await panel.locator('#s-findings').textContent()).replace(/\s+/g, ' ');
    assert.match(text, /sid was not renewed at login/);
  });
});

test('tamper: a trusted role cookie is caught, and the session cookie is validated', { timeout: 90_000 }, async () => {
  await scenario({ flaws: ['trust-role'] }, async ({ demo, panel, site }) => {
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
    const box = panel.locator('#s-session');

    // Tamper the role cookie: user -> admin. The account page trusts it.
    const roleRow = box.locator('tr', { hasText: 'role' }).first();
    await roleRow.getByRole('button', { name: 'Tamper' }).click();
    const input = box.locator('.tamper-input').first();
    await input.fill('admin');
    await box.getByRole('button', { name: 'Replay' }).click();
    await box.locator('.tamper-result .v', { hasText: 'Changed' }).waitFor({ timeout: 15_000 });

    // Tamper the session cookie with garbage: the server rejects it.
    const sidRow = box.locator('tr', { hasText: 'sid' }).first();
    await sidRow.getByRole('button', { name: 'Tamper' }).click();
    await box.locator('.tamper-input').fill('not-a-real-session'); // only one editor is open at a time
    await box.getByRole('button', { name: 'Replay' }).click();
    await box.locator('.tamper-result .v', { hasText: 'Rejected' }).waitFor({ timeout: 15_000 });

    // The real session is untouched: the page still shows the account.
    await site.reload();
    await site.getByText('Signed in as').waitFor();
  });
});

test('tamper: no change when the server ignores the value', { timeout: 90_000 }, async () => {
  await scenario({}, async ({ demo, panel, site }) => {
    await site.goto(`${demo.base}/`); // sets a theme cookie, so it is in the recorded session
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
    const box = panel.locator('#s-session');
    const themeRow = box.locator('tr', { hasText: 'theme' }).first();
    await themeRow.getByRole('button', { name: 'Tamper' }).click();
    await box.locator('.tamper-input').first().fill('dark');
    await box.getByRole('button', { name: 'Replay' }).click();
    await box.locator('.tamper-result .v', { hasText: 'No change' }).waitFor({ timeout: 15_000 });
  });
});

test('storage: a token left in localStorage after logout is caught', { timeout: 90_000 }, async () => {
  await scenario({ flaws: ['storage-logout'] }, async ({ demo, panel, site }) => {
    await signIn(site, demo.base); // the account page stashes access_token in localStorage
    await waitStatus(panel, 'Watching this session');
    await site.click('#logout');
    const r = await lastResult(panel, 20_000);
    assert.equal(r.badge, 'PASS', 'the server-side logout itself is fine');
    const card = panel.locator('#s-results .result').first();
    const text = (await card.textContent()).replace(/\s+/g, ' ');
    assert.match(text, /Client storage:.*access_token.*localStorage.*still present after logout/);
  });
});

test('storage: a clean logout shows no storage warning', { timeout: 90_000 }, async () => {
  await scenario({}, async ({ demo, panel, site }) => {
    await signIn(site, demo.base);
    await waitStatus(panel, 'Watching this session');
    await site.click('#logout');
    await lastResult(panel, 20_000);
    const text = (await panel.locator('#s-results .result').first().textContent()).replace(/\s+/g, ' ');
    assert.doesNotMatch(text, /still present after logout/);
  });
});
