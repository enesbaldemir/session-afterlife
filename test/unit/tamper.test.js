import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyTamper, mutatedCookieHeader, TAMPER } from '../../extension/lib/tamper.js';

const page = (body, extra = {}) => ({ status: 200, finalUrl: 'https://app.test/account', redirected: false, contentType: 'text/html', body, ...extra });

const ACCOUNT = '<html><body><header>Home Account</header><h1>Account</h1><p>Signed in as <strong>alice</strong>.</p><p>Active sessions: 1</p><a href="/password">Change password</a></body></html>';
const ADMIN = ACCOUNT.replace('<a href="/password">', '<h2>Administrator tools</h2><p>You can manage all users and delete accounts.</p><a href="/password">');
const LOGIN = '<html><body><header>Home Account</header><h1>Sign in</h1><form>Username Password Sign in</form></body></html>';

const auth = [page(ACCOUNT), page(ACCOUNT)];
const anon = page(LOGIN, { finalUrl: 'https://app.test/login?next=/account', redirected: true });
const base = { auth, anon };

test('mutatedCookieHeader replaces only the named cookie', () => {
  const cookies = [{ name: 'sid', value: 'abc' }, { name: 'role', value: 'user' }];
  assert.equal(mutatedCookieHeader(cookies, 'role', 'admin'), 'sid=abc; role=admin');
  assert.equal(mutatedCookieHeader(cookies, 'sid', 'x'), 'sid=x; role=user');
});

test('an unchanged response is IGNORED', () => {
  assert.equal(classifyTamper(page(ACCOUNT), base).verdict, TAMPER.IGNORED);
});

test('a different but still authenticated response is CHANGED', () => {
  const r = classifyTamper(page(ADMIN), base);
  assert.equal(r.verdict, TAMPER.CHANGED);
});

test('dropping to the login page is REJECTED', () => {
  const probe = page(LOGIN, { finalUrl: 'https://app.test/login?next=/account', redirected: true });
  assert.equal(classifyTamper(probe, base).verdict, TAMPER.REJECTED);
});

test('a 401 is REJECTED', () => {
  const a = [{ status: 200, finalUrl: 'https://app.test/api/me', contentType: 'application/json', body: '{"user":"alice"}' }];
  const n = { status: 401, finalUrl: 'https://app.test/api/me', contentType: 'application/json', body: '{"error":"no"}' };
  assert.equal(classifyTamper({ ...n }, { auth: a, anon: n }).verdict, TAMPER.REJECTED);
});

test('a failed replay is INCONCLUSIVE', () => {
  assert.equal(classifyTamper({ error: 'Failed to fetch' }, base).verdict, TAMPER.INCONCLUSIVE);
});

test('an unusable baseline is INCONCLUSIVE', () => {
  const pub = page('<h1>Public</h1><p>Same page for everyone, nothing secret here at all.</p>');
  assert.equal(classifyTamper(pub, { auth: [pub], anon: pub }).verdict, TAMPER.INCONCLUSIVE);
});
