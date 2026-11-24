import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatDuration, cookieLifetime, decodeJwt, tokenLifetime, analyseLifetimes } from '../../extension/lib/lifetime.js';
import * as T from '../../extension/lib/timeout.js';
import { toMarkdown, assess, headline } from '../../extension/lib/report.js';

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (payload) => `${b64u({ alg: 'HS256', typ: 'JWT' })}.${b64u(payload)}.c2ln`;

test('formatDuration', () => {
  assert.equal(formatDuration(45), '45s');
  assert.equal(formatDuration(125), '2m 5s');
  assert.equal(formatDuration(3600), '1h 0m');
  assert.equal(formatDuration(30 * 86400 - 3600), '29d 23h');
  assert.equal(formatDuration(null), '—');
});

test('cookie lifetimes', () => {
  assert.equal(cookieLifetime({ session: true }).kind, 'session');
  const c = cookieLifetime({ session: false, expirationDate: 1000 + 3600 }, 1000);
  assert.equal(c.kind, 'persistent');
  assert.equal(c.text, '1h 0m left');
  assert.equal(cookieLifetime({ session: false, expirationDate: 10 }, 1000).text, 'already expired');
});

test('decodeJwt reads header and claims without verifying', () => {
  const t = jwt({ sub: 'alice', iat: 1000, exp: 4600 });
  assert.equal(decodeJwt(t).payload.sub, 'alice');
  assert.equal(decodeJwt(`Bearer ${t}`).header.alg, 'HS256');
  assert.equal(decodeJwt(encodeURIComponent(t)).payload.exp, 4600);
  assert.equal(decodeJwt('5f2b9c0e1d'), null);
  assert.equal(decodeJwt('a.b.c'), null);
  const l = tokenLifetime({ iat: 1000, exp: 4600 }, 1000);
  assert.equal(l.ttlSec, 3600);
  assert.match(l.text, /1h 0m left \(lifetime 1h 0m\)/);
  assert.match(tokenLifetime({ sub: 'x' }).text, /never expires/);
});

test('analyseLifetimes covers cookies and the Authorization header', () => {
  const items = analyseLifetimes({
    cookies: [{ name: 'sid', value: 'abc', session: false, expirationDate: 2000, httpOnly: true }],
    authorization: `Bearer ${jwt({ iat: 0, exp: 1600 })}`,
  }, 1000);
  assert.equal(items.length, 2);
  assert.equal(items[0].jwt, null);
  assert.equal(items[1].name, 'Authorization');
  assert.equal(items[1].jwt.ttlSec, 1600);
});

function run(state, verdictAt) {
  let s = state;
  while (!s.done) s = T.advance(s, verdictAt(s), T.nextDelayUnits(s));
  return s;
}

test('idle timeout: brackets the timeout between two waits', () => {
  // server idle timeout = 30 units: a probe after waiting w succeeds if w < 30
  const s = run(T.startIdle(), (st) => (T.nextDelayUnits(st) < 30 ? 'STILL_VALID' : 'INVALIDATED'));
  assert.deepEqual(s.result, { kind: 'expired', lowerUnits: 25, upperUnits: 35 });
  assert.match(T.describeResult(s), /between 25 min and 35 min/);
});

test('idle timeout: no expiry within the limit', () => {
  const s = run(T.startIdle({ maxUnits: 60 }), () => 'STILL_VALID');
  assert.equal(s.result.kind, 'survived');
  assert.equal(s.result.units, 60);
});

test('idle timeout: expires before the first probe', () => {
  const s = run(T.startIdle(), () => 'INVALIDATED');
  assert.deepEqual(s.result, { kind: 'expired', lowerUnits: 0, upperUnits: 1 });
  assert.match(T.describeResult(s), /less than 1 min/);
});

test('absolute timeout: dies while kept active', () => {
  // dies at 42 units after start
  const s = run(T.startAbsolute({ intervalUnits: 5 }), (st) => (st.elapsed + 5 < 42 ? 'STILL_VALID' : 'INVALIDATED'));
  assert.deepEqual(s.result, { kind: 'expired', lowerUnits: 40, upperUnits: 45 });
});

test('absolute timeout: survives the whole window', () => {
  const s = run(T.startAbsolute({ intervalUnits: 5, maxUnits: 12 }), () => 'STILL_VALID');
  assert.equal(s.result.kind, 'survived');
  assert.equal(s.result.units, 12);
  assert.deepEqual(s.history.map((h) => h.waited), [5, 5, 2]);
});

test('inconclusive probe stops the measurement', () => {
  const s = T.advance(T.startIdle(), 'INCONCLUSIVE');
  assert.equal(s.done, true);
  assert.equal(s.result.kind, 'inconclusive');
});

test('assess and headline', () => {
  assert.equal(assess('logout', 'STILL_VALID'), 'fail');
  assert.equal(assess('logout', 'INVALIDATED'), 'pass');
  assert.equal(assess('elsewhere', 'STILL_VALID'), 'info');
  assert.equal(assess('password', 'INCONCLUSIVE'), 'unknown');
  assert.equal(
    headline({ verdict: 'STILL_VALID', cookieDiff: [{ name: 'sid', status: 'deleted' }] }),
    'Browser: session cookie cleared or replaced — Server: old session still accepted',
  );
});

test('the Markdown report never contains cookie values or tokens', () => {
  const secret = 'f00dfacecafebeef1234';
  const token = jwt({ sub: 'alice', iat: 1, exp: 2 });
  const md = toMarkdown({
    target: { origin: 'https://app.test' },
    reference: { method: 'GET', url: 'https://app.test/account' },
    marker: 'alice',
    snapshot: {
      takenAt: 0,
      cookies: [{ name: 'sid', value: secret }],
      cookieHeader: `sid=${secret}`,
      authorization: `Bearer ${token}`,
      lifetimes: analyseLifetimes({ cookies: [{ name: 'sid', value: secret, session: true }], authorization: `Bearer ${token}` }, 0),
    },
    checks: [{ at: 0, scenario: 'logout', verdict: 'STILL_VALID', reasons: ['Status 200'], cookieDiff: [{ name: 'sid', status: 'deleted' }] }],
    events: [{ at: 0, name: 'sid', removed: true, cause: 'expired_overwrite' }],
  });
  assert.ok(!md.includes(secret));
  assert.ok(!md.includes(token));
  assert.ok(!md.includes('alice'), 'marker value is not written');
  assert.match(md, /Logout \(WSTG-SESS-06\): FAIL/);
  assert.match(md, /`sid` deleted/);
});
