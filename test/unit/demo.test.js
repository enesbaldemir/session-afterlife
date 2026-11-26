// The demo app must behave as documented, since the e2e tests rely on it.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
const { createApp } = require('../../demo/server.js');

async function start(opts) {
  const server = createApp(opts);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { server, base, close: () => new Promise((r) => server.close(r)) };
}

const sidOf = (res) => /sid=([^;]*)/.exec(res.headers.get('set-cookie') || '')?.[1];

async function login(base, password = 'wonderland') {
  const r = await fetch(`${base}/login`, {
    method: 'POST', redirect: 'manual',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=alice&password=${password}`,
  });
  assert.equal(r.status, 302);
  return sidOf(r);
}
const me = (base, sid) => fetch(`${base}/api/me`, { headers: { Cookie: `sid=${sid}` } }).then((r) => r.status);
const logout = (base, sid) => fetch(`${base}/logout`, { method: 'POST', redirect: 'manual', headers: { Cookie: `sid=${sid}` } });
const changePassword = (base, sid, current, next) => fetch(`${base}/password`, {
  method: 'POST', headers: { Cookie: `sid=${sid}`, 'Content-Type': 'application/x-www-form-urlencoded' },
  body: `current=${current}&next=${next}`,
});

test('secure mode: logout ends the server session', async () => {
  const app = await start({});
  try {
    const sid = await login(app.base);
    assert.equal(await me(app.base, sid), 200);
    const r = await logout(app.base, sid);
    assert.equal(sidOf(r), '');
    assert.equal(await me(app.base, sid), 401);
  } finally { await app.close(); }
});

test('flaw logout: cookie cleared, server session kept', async () => {
  const app = await start({ flaws: ['logout'] });
  try {
    const sid = await login(app.base);
    const r = await logout(app.base, sid);
    assert.equal(sidOf(r), '');
    assert.equal(await me(app.base, sid), 200);
  } finally { await app.close(); }
});

test('flaw logout-rotate: cookie replaced, server session kept', async () => {
  const app = await start({ flaws: ['logout-rotate'] });
  try {
    const sid = await login(app.base);
    const r = await logout(app.base, sid);
    assert.ok(sidOf(r) && sidOf(r) !== sid);
    assert.equal(await me(app.base, sid), 200);
  } finally { await app.close(); }
});

test('password change ends other sessions unless the flaw is on', async () => {
  for (const [flaws, expected] of [[[], 401], [['password'], 200]]) {
    const app = await start({ flaws });
    try {
      const a = await login(app.base);
      const b = await login(app.base);
      assert.equal((await changePassword(app.base, b, 'wonderland', 'looking-glass')).status, 200);
      assert.equal(await me(app.base, a), expected, `flaws=${flaws}`);
      assert.equal(await me(app.base, b), 200, 'current session stays');
    } finally { await app.close(); }
  }
});

test('bearer token: logout revokes it unless the jwt flaw is on', async () => {
  for (const [flaws, expected] of [[[], 401], [['jwt'], 200]]) {
    const app = await start({ flaws });
    try {
      const { token } = await fetch(`${app.base}/api/token`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'alice', password: 'wonderland' }),
      }).then((r) => r.json());
      const h = { Authorization: `Bearer ${token}` };
      assert.equal((await fetch(`${app.base}/api/profile`, { headers: h })).status, 200);
      await fetch(`${app.base}/api/logout`, { method: 'POST', headers: h });
      assert.equal((await fetch(`${app.base}/api/profile`, { headers: h })).status, expected, `flaws=${flaws}`);
    } finally { await app.close(); }
  }
});

test('idle timeout', async () => {
  const app = await start({ idle: 1 });
  try {
    const sid = await login(app.base);
    await new Promise((r) => setTimeout(r, 600));
    assert.equal(await me(app.base, sid), 200, 'activity resets the timer');
    await new Promise((r) => setTimeout(r, 1300));
    assert.equal(await me(app.base, sid), 401);
  } finally { await app.close(); }
});

test('unknown flaw is rejected', () => {
  assert.throws(() => createApp({ flaws: ['nope'] }), /unknown flaw/);
});

test('flaw fixation keeps the pre-login session ID', async () => {
  const app = await start({ flaws: ['fixation'] });
  try {
    const pre = sidOf(await fetch(`${app.base}/login`));
    assert.ok(pre);
    assert.equal(await me(app.base, pre), 401, 'anonymous before login');
    const r = await fetch(`${app.base}/login`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: `sid=${pre}` },
      body: 'username=alice&password=wonderland',
    });
    assert.equal(sidOf(r), undefined, 'no new cookie');
    assert.equal(await me(app.base, pre), 200, 'the same ID is now signed in');
  } finally { await app.close(); }
});

test('flaws weak-cookie, cache and token-in-url', async () => {
  const app = await start({ flaws: ['weak-cookie', 'cache', 'token-in-url'] });
  try {
    const r = await fetch(`${app.base}/login`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'username=alice&password=wonderland',
    });
    const cookie = r.headers.get('set-cookie');
    assert.ok(!/HttpOnly/i.test(cookie) && !/SameSite/i.test(cookie));
    const sid = sidOf(r);
    assert.equal(r.headers.get('location'), `/account?sid=${sid}`);
    const acc = await fetch(`${app.base}/account`, { headers: { Cookie: `sid=${sid}` } });
    assert.equal(acc.headers.get('cache-control'), 'private, max-age=600');
  } finally { await app.close(); }
});

test('flaw trust-role: the account page obeys a client role cookie', async () => {
  const app = await start({ flaws: ['trust-role'] });
  try {
    const r = await fetch(`${app.base}/login`, {
      method: 'POST', redirect: 'manual',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'username=alice&password=wonderland',
    });
    const setCookie = r.headers.getSetCookie();
    assert.ok(setCookie.some((c) => /^role=user/.test(c)), 'a role cookie is issued');
    const sid = sidOf(r);
    const asUser = await fetch(`${app.base}/account`, { headers: { Cookie: `sid=${sid}; role=user` } }).then((x) => x.text());
    assert.ok(!asUser.includes('Administrator tools'));
    const asAdmin = await fetch(`${app.base}/account`, { headers: { Cookie: `sid=${sid}; role=admin` } }).then((x) => x.text());
    assert.ok(asAdmin.includes('Administrator tools'), 'role=admin unlocks the admin section');
  } finally { await app.close(); }
});

test('without trust-role, the role cookie is ignored', async () => {
  const app = await start({});
  try {
    const sid = await login(app.base);
    const asAdmin = await fetch(`${app.base}/account`, { headers: { Cookie: `sid=${sid}; role=admin` } }).then((x) => x.text());
    assert.ok(!asAdmin.includes('Administrator tools'));
  } finally { await app.close(); }
});

test('flaw storage-logout: account page stashes a token in localStorage', async () => {
  const app = await start({ flaws: ['storage-logout'] });
  try {
    const sid = await login(app.base);
    const html = await fetch(`${app.base}/account`, { headers: { Cookie: `sid=${sid}` } }).then((r) => r.text());
    assert.match(html, /localStorage\.setItem\('access_token'/);
    assert.match(html, /sessionStorage\.setItem\('csrf'/);
  } finally { await app.close(); }
});

test('without storage-logout, no token is stashed', async () => {
  const app = await start({});
  try {
    const sid = await login(app.base);
    const html = await fetch(`${app.base}/account`, { headers: { Cookie: `sid=${sid}` } }).then((r) => r.text());
    assert.ok(!html.includes('localStorage.setItem'));
  } finally { await app.close(); }
});
