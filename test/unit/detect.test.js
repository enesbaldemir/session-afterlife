import { test } from 'node:test';
import assert from 'node:assert/strict';
import { isLogoutRequest, isPasswordChange, isCandidate, isUnsafeUrl, rankCandidates, separationScore } from '../../extension/lib/detect.js';

const B = 'https://app.test';

test('logout requests are recognised', () => {
  for (const p of ['/logout', '/api/logout', '/auth/sign-out', '/users/sign_out', '/account/logoff', '/sessions/destroy', '/oauth/revoke', '/end_session'])
    assert.ok(isLogoutRequest(B + p, 'POST'), p);
  assert.ok(isLogoutRequest(`${B}/api/session`, 'DELETE'));
  for (const p of ['/catalog/outlet', '/blog/logging-out-tips-2', '/api/session', '/login'])
    assert.ok(!isLogoutRequest(B + p, 'GET'), p);
});

test('password changes are recognised, only for write methods', () => {
  for (const p of ['/password', '/account/change-password', '/api/me/password', '/settings/credentials', '/user/change_passwd'])
    assert.ok(isPasswordChange(B + p, 'POST'), p);
  assert.ok(isPasswordChange(`${B}/api/me/password`, 'PUT'));
  assert.ok(!isPasswordChange(`${B}/password`, 'GET'));
  assert.ok(!isPasswordChange(`${B}/passport/apply`, 'POST'));
});

test('only safe, session-bearing GET requests are candidates', () => {
  const e = (url, extra = {}) => ({ url: B + url, method: 'GET', type: 'main_frame', hasCookie: true, ...extra });
  assert.ok(isCandidate(e('/account')));
  assert.ok(isCandidate(e('/api/me', { type: 'xmlhttprequest', hasCookie: false, hasAuth: true })));
  assert.ok(!isCandidate(e('/account', { hasCookie: false })), 'no session');
  assert.ok(!isCandidate(e('/account', { method: 'POST' })), 'not GET');
  assert.ok(!isCandidate(e('/static/app.js')), 'static');
  assert.ok(!isCandidate(e('/logout')), 'logout');
  assert.ok(!isCandidate(e('/items/7/delete')), 'state change');
  assert.ok(!isCandidate(e('/newsletter?action=unsubscribe')), 'state change in query');
  assert.ok(!isCandidate(e('/img/a.png', { type: 'image' })), 'type');
});

test('identity endpoints are ranked first', () => {
  const list = [
    { url: `${B}/blog/post-1`, method: 'GET', type: 'main_frame', hasCookie: true, at: 3 },
    { url: `${B}/api/me`, method: 'GET', type: 'xmlhttprequest', hasCookie: true, at: 1, headers: { accept: 'application/json' } },
    { url: `${B}/logout`, method: 'GET', type: 'main_frame', hasCookie: true, at: 4 },
    { url: `${B}/blog/post-1?x=1`, method: 'GET', type: 'main_frame', hasCookie: true, at: 2 },
  ];
  const r = rankCandidates(list).map((c) => new URL(c.url).pathname);
  assert.deepEqual(r, ['/api/me', '/blog/post-1']);
});

test('separationScore prefers clear signals', () => {
  const json = (status, body) => ({ status, finalUrl: `${B}/api/me`, contentType: 'application/json', body });
  const page = (url, body) => ({ status: 200, finalUrl: B + url, contentType: 'text/html', body });
  const api = separationScore(json(200, '{"user":"alice","id":1}'), json(401, '{"error":"not authenticated"}'));
  const html = separationScore(page('/account', '<h1>Account</h1><p>Signed in as alice today</p>'), page('/login', '<h1>Sign in</h1><form>username password</form>'));
  const none = separationScore(page('/', '<h1>Welcome to the public home page</h1>'), page('/', '<h1>Welcome to the public home page</h1>'));
  assert.ok(api > html && html > 0);
  assert.equal(none, -1);
});

test('isUnsafeUrl guards manual choices too', () => {
  assert.ok(isUnsafeUrl(`${B}/logout`));
  assert.ok(isUnsafeUrl(`${B}/items/3/delete`));
  assert.ok(isUnsafeUrl(`${B}/mail?action=unsubscribe`));
  assert.ok(!isUnsafeUrl(`${B}/account`));
  assert.ok(!isUnsafeUrl(`${B}/api/me`));
});
