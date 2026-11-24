import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizePattern, hostMatches, hostInScope, patternToOrigins, suggestPatterns, DEFAULT_SCOPE } from '../../extension/lib/scope.js';
import { auditSession, sessionCookieNames, fnv1a } from '../../extension/lib/findings.js';
import { toCurl, toMarkdown } from '../../extension/lib/report.js';

test('normalizePattern accepts what people paste', () => {
  assert.equal(normalizePattern('https://App.Example.com:8443/login?x=1').pattern, 'app.example.com');
  assert.equal(normalizePattern('*.staging.example.com').pattern, '*.staging.example.com');
  assert.equal(normalizePattern('127.0.0.1:8090').pattern, '127.0.0.1');
  assert.equal(normalizePattern('*.test').pattern, '*.test');
  assert.ok(normalizePattern('*.com').error);
  assert.ok(normalizePattern('*').error);
  assert.ok(normalizePattern('app.*.com').error);
  assert.ok(normalizePattern('*.10.0.0.1').error);
  assert.ok(normalizePattern('exa mple.com').error);
  assert.ok(normalizePattern('').error);
});

test('scope matching', () => {
  assert.ok(hostMatches('example.com', '*.example.com'));
  assert.ok(hostMatches('a.b.example.com', '*.example.com'));
  assert.ok(!hostMatches('badexample.com', '*.example.com'));
  assert.ok(!hostMatches('example.com.evil.net', '*.example.com'));
  assert.ok(hostInScope('localhost', DEFAULT_SCOPE));
  assert.ok(!hostInScope('bank.example', DEFAULT_SCOPE));
  assert.deepEqual(patternToOrigins('*.example.com'), ['*://*.example.com/*']);
  assert.deepEqual(suggestPatterns('app.staging.example.com'), ['app.staging.example.com', '*.staging.example.com']);
  assert.deepEqual(suggestPatterns('example.com'), ['example.com', '*.example.com']);
  assert.deepEqual(suggestPatterns('10.0.0.5'), ['10.0.0.5']);
});

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = (h, p) => `${b64u(h)}.${b64u(p)}.c2ln`;
const NOW = 1_800_000_000;

function siteWith({ origin = 'https://app.example.com', cookies, authorization = '', essential, cacheControl = 'no-store', captured = [], cookieSeen = {}, loginWriteAt = 0 }) {
  return {
    origin,
    snapshot: { takenAt: 0, cookies, authorization, essential, loginWriteAt, cookieHeader: cookies.map((c) => `${c.name}=${c.value}`).join('; ') },
    baselines: { auth: [{ status: 200, cacheControl, body: '' }] },
    captured,
    cookieSeen,
  };
}
const ids = (f) => Object.fromEntries(f.map((x) => [x.id, x.status]));

test('cookie attribute findings', () => {
  const f = auditSession(siteWith({
    cookies: [
      { name: 'sid', value: 'a'.repeat(32), httpOnly: false, secure: false, sameSite: 'no_restriction', hostOnly: false, domain: '.example.com', path: '/', session: false, expirationDate: NOW + 90 * 86400 },
      { name: 'theme', value: 'light', httpOnly: false, secure: false, sameSite: 'lax', hostOnly: true, domain: 'app.example.com', path: '/', session: true },
    ],
    essential: ['sid'],
  }), { nowSec: NOW });
  const r = ids(f);
  assert.equal(r['httponly-sid'], 'fail');
  assert.equal(r['secure-sid'], 'fail');
  assert.equal(r['samesite-sid'], 'fail');
  assert.equal(r['domain-sid'], 'warn');
  assert.equal(r['persist-sid'], 'warn');
  assert.ok(!('httponly-theme' in r), 'only session cookies are audited');
  assert.equal(f[0].severity, 'high', 'sorted by severity');
});

test('a well-configured session passes', () => {
  const f = auditSession(siteWith({
    cookies: [{ name: '__Host-sid', value: 'b'.repeat(32), httpOnly: true, secure: true, sameSite: 'lax', hostOnly: true, domain: 'app.example.com', path: '/', session: true }],
  }), { nowSec: NOW });
  assert.deepEqual(f.filter((x) => x.status === 'fail' || x.status === 'warn'), []);
});

test('plain HTTP: localhost is exempt, other hosts are not', () => {
  const c = [{ name: 'sid', value: 'c'.repeat(20), httpOnly: true, secure: false, sameSite: 'lax', hostOnly: true, domain: 'x', path: '/', session: true }];
  assert.ok(!('secure-sid' in ids(auditSession(siteWith({ origin: 'http://localhost:8090', cookies: c })))));
  assert.equal(ids(auditSession(siteWith({ origin: 'http://intranet.example', cookies: c })))['secure-sid'], 'fail');
});

test('JWT findings', () => {
  const none = jwt({ alg: 'none' }, { sub: 'a', email: 'a@b.c' });
  const long = jwt({ alg: 'HS256' }, { sub: 'a', iat: NOW, exp: NOW + 30 * 86400, password: 'x' });
  const f = ids(auditSession(siteWith({ cookies: [], authorization: `Bearer ${none}` }), { nowSec: NOW }));
  assert.equal(f['jwt-none-Authorization'], 'fail');
  assert.equal(f['jwt-exp-Authorization'], 'fail');
  assert.equal(f['jwt-pii-Authorization'], 'warn');
  const g = ids(auditSession(siteWith({ cookies: [], authorization: `Bearer ${long}` }), { nowSec: NOW }));
  assert.equal(g['jwt-ttl-Authorization'], 'warn');
  assert.equal(g['jwt-secret-Authorization'], 'fail');
});

test('cache and token-in-URL findings', () => {
  const c = [{ name: 'sid', value: 'deadbeefcafe1234', httpOnly: true, secure: true, sameSite: 'lax', hostOnly: true, domain: 'x', path: '/', session: true }];
  const f = auditSession(siteWith({ cookies: c, cacheControl: 'private, max-age=600', captured: [{ url: 'https://app.example.com/account?sid=deadbeefcafe1234' }] }));
  const r = ids(f);
  assert.equal(r.cache, 'fail');
  assert.equal(r['url-token'], 'fail');
  const leak = f.find((x) => x.id === 'url-token');
  assert.ok(!leak.detail.includes('deadbeefcafe1234'), 'the secret is masked');
  assert.match(leak.detail, /sid=•••/);
});

test('session fixation', () => {
  const c = [{ name: 'sid', value: 'v1v1v1v1v1v1', httpOnly: true, secure: true, sameSite: 'lax', hostOnly: true, domain: 'x', path: '/', session: true }];
  const fixed = auditSession(siteWith({ cookies: c, loginWriteAt: 2000, cookieSeen: { sid: { hash: fnv1a('v1v1v1v1v1v1'), at: 1000 } } }));
  assert.equal(ids(fixed)['fixation-sid'], 'fail');
  const renewed = auditSession(siteWith({ cookies: c, loginWriteAt: 2000, cookieSeen: { sid: { hash: fnv1a('v1v1v1v1v1v1'), at: 2100 } } }));
  assert.equal(ids(renewed)['fixation-sid'], 'pass');
  const frozen = siteWith({ cookies: c, loginWriteAt: 2000, cookieSeen: { sid: { hash: 'later-value', at: 3000 } } });
  frozen.snapshot.cookieSeen = { sid: { hash: fnv1a('v1v1v1v1v1v1'), at: 1000 } };
  assert.equal(ids(auditSession(frozen))['fixation-sid'], 'fail', 'uses what was known when the session was recorded');
  const unknown = auditSession(siteWith({ cookies: c, loginWriteAt: 0, cookieSeen: { sid: { hash: 'x', at: 1 } } }));
  assert.ok(!('fixation-sid' in ids(unknown)), 'no login seen, no verdict');
  assert.equal(ids(unknown).fixation, 'skip', 'but it says so');
});

test('sessionCookieNames guesses when not measured', () => {
  assert.deepEqual(sessionCookieNames({ cookies: [{ name: 'PHPSESSID', value: 'x' }, { name: 'lang', value: 'en' }] }), ['PHPSESSID']);
  assert.deepEqual(sessionCookieNames({ essential: ['a'], cookies: [] }), ['a']);
});

test('toCurl and report with findings', () => {
  const s = siteWith({ cookies: [{ name: 'sid', value: 'x"y', httpOnly: true, secure: true, sameSite: 'lax', hostOnly: true, domain: 'x', path: '/', session: true }], cacheControl: '' });
  s.reference = { url: 'https://app.example.com/me', method: 'GET', headers: { accept: 'application/json' } };
  assert.equal(toCurl(s), `curl -i 'https://app.example.com/me' \\\n  -H 'Cookie: sid=x"y' \\\n  -H 'Accept: application/json'`);
  const md = toMarkdown(s, { findings: auditSession(s) });
  assert.match(md, /## Findings/);
  assert.match(md, /\*\*LOW\*\* Signed-in response may be cached/);
  assert.ok(!md.includes('x"y'));
});
