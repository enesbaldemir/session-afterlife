import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classify, baselineQuality, normalizeBody, similarity, compareCookieJars, VERDICT } from '../../extension/lib/compare.js';

const page = (body, extra = {}) => ({ status: 200, finalUrl: 'https://app.test/account', redirected: false, contentType: 'text/html', body, ...extra });

const ACCOUNT = (n) => `<html><head><title>Account</title><script>var csrf="${'a'.repeat(30)}${n}"</script></head>
<body><header>Home Account Token app</header><h1>Account</h1><p>Signed in as <strong>alice</strong>.</p>
<p>Session started 2026-11-24T10:0${n}:00.000Z.</p><p>Active sessions for this user: ${n}</p>
<a href="/password">Change password</a><button>Log out</button></body></html>`;
const LOGIN = `<html><body><header>Home Account Token app</header><h1>Sign in</h1><form>Username Password Sign in</form></body></html>`;

const auth = [page(ACCOUNT(1)), page(ACCOUNT(2))];
const anon = page(LOGIN, { finalUrl: 'https://app.test/login?next=/account', redirected: true });

test('normalizeBody masks numbers, tokens, tags and scripts', () => {
  const a = normalizeBody(ACCOUNT(1), 'text/html');
  const b = normalizeBody(ACCOUNT(2), 'text/html');
  assert.equal(a, b);
  assert.ok(!a.includes('<'));
  assert.ok(!a.includes('csrf'));
});

test('two loads of the same page are similar, login page is not', () => {
  assert.equal(similarity(auth[0], auth[1]), 1);
  assert.ok(similarity(auth[0], anon) < 0.3);
});

test('old session still accepted -> STILL_VALID', () => {
  const r = classify(page(ACCOUNT(3)), { auth, anon });
  assert.equal(r.verdict, VERDICT.STILL_VALID);
});

test('redirect to the login page -> INVALIDATED', () => {
  const probe = page(LOGIN, { finalUrl: 'https://app.test/login?next=/account', redirected: true });
  assert.equal(classify(probe, { auth, anon }).verdict, VERDICT.INVALIDATED);
});

test('401 from a JSON API -> INVALIDATED', () => {
  const a = [{ status: 200, finalUrl: 'https://app.test/api/me', contentType: 'application/json', body: '{"user":"alice","sessionStarted":"2026-11-24T10:00:00Z"}' }];
  const n = { status: 401, finalUrl: 'https://app.test/api/me', contentType: 'application/json', body: '{"error":"not authenticated"}' };
  assert.equal(classify({ ...n }, { auth: a, anon: n }).verdict, VERDICT.INVALIDATED);
  assert.equal(classify({ ...a[0] }, { auth: a, anon: n }).verdict, VERDICT.STILL_VALID);
});

test('a page that looks the same without a session gives INCONCLUSIVE', () => {
  const pub = page('<h1>Welcome</h1><p>Public news page with lots of words in it for testing</p>');
  const q = baselineQuality({ auth: [pub, pub], anon: pub });
  assert.equal(q.usable, false);
  assert.equal(classify(pub, { auth: [pub], anon: pub }).verdict, VERDICT.INCONCLUSIVE);
});

test('marker decides when set', () => {
  const base = { auth, anon, marker: 'alice' };
  assert.equal(classify(page(ACCOUNT(5)), base).verdict, VERDICT.STILL_VALID);
  assert.equal(classify(page('<h1>Account</h1><p>Signed in as <b>bob</b></p>'), base).verdict, VERDICT.INVALIDATED);
  assert.equal(baselineQuality({ auth, anon, marker: 'Sign in' }).usable, false); // appears in anon too
  assert.equal(baselineQuality({ auth, anon, marker: 'nobody' }).usable, false); // not in auth
});

test('network error -> INCONCLUSIVE', () => {
  assert.equal(classify({ error: 'Failed to fetch' }, { auth, anon }).verdict, VERDICT.INCONCLUSIVE);
});

test('a page that matches neither baseline -> INCONCLUSIVE', () => {
  const odd = page('<h1>Maintenance</h1><p>We will be back soon. Thank you for your patience today.</p>', { status: 503, finalUrl: 'https://app.test/maintenance' });
  assert.equal(classify(odd, { auth, anon }).verdict, VERDICT.INCONCLUSIVE);
});

test('compareCookieJars reports deleted, changed and unchanged cookies', () => {
  const before = [
    { name: 'sid', value: 'a', domain: 'app.test', path: '/', httpOnly: true },
    { name: 'theme', value: 'light', domain: 'app.test', path: '/' },
    { name: 'rt', value: 'x', domain: 'app.test', path: '/' },
  ];
  const after = [
    { name: 'theme', value: 'light', domain: 'app.test', path: '/' },
    { name: 'rt', value: 'y', domain: 'app.test', path: '/' },
  ];
  const d = Object.fromEntries(compareCookieJars(before, after).map((x) => [x.name, x.status]));
  assert.deepEqual(d, { sid: 'deleted', theme: 'unchanged', rt: 'changed' });
});
