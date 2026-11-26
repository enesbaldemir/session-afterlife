import { test } from 'node:test';
import assert from 'node:assert/strict';
import { classifyStorage, storageResidue, storageSummary, areaLabel } from '../../extension/lib/storage.js';

const b64u = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt = `${b64u({ alg: 'HS256', typ: 'JWT' })}.${b64u({ sub: 'alice', exp: 9999999999 })}.sig`;

test('token-like entries are detected; benign ones are ignored', () => {
  const raw = {
    local: {
      access_token: jwt,
      refreshToken: 'abcdef0123456789abcdef0123456789',
      theme: 'dark',
      locale: 'en-US',
      cart_id: '42',
    },
    session: { csrf: 'x7y8z9', auth: 'Bearer zzzz' },
    idb: ['keyval-store', 'auth-db'],
  };
  const found = classifyStorage(raw);
  const keys = found.map((e) => `${e.area}:${e.key}`);
  assert.ok(keys.includes('local:access_token'));
  assert.ok(keys.includes('local:refreshToken'));
  assert.ok(keys.includes('session:auth'));
  assert.ok(keys.includes('indexeddb:auth-db'));
  assert.ok(!keys.includes('local:theme'), 'theme is benign');
  assert.ok(!keys.includes('local:locale'));
  assert.ok(!keys.includes('local:cart_id'));
  assert.ok(!keys.includes('indexeddb:keyval-store'));
  assert.equal(found.find((e) => e.key === 'access_token').kind, 'jwt');
});

test('a JWT value under any key is flagged', () => {
  const found = classifyStorage({ local: { data: jwt } });
  assert.equal(found.length, 1);
  assert.equal(found[0].kind, 'jwt');
});

test('benign key wins even over a long value', () => {
  assert.equal(classifyStorage({ local: { theme_cache: 'a'.repeat(50) } }).length, 0);
});

test('storageResidue keeps only entries present before and after', () => {
  const before = [{ area: 'local', key: 'access_token', kind: 'jwt' }, { area: 'session', key: 'csrf', kind: 'token-ish' }];
  const after = [{ area: 'local', key: 'access_token', kind: 'jwt' }, { area: 'local', key: 'new_token', kind: 'jwt' }];
  const r = storageResidue(before, after);
  assert.deepEqual(r.map((e) => e.key), ['access_token']);
});

test('storageSummary wording', () => {
  assert.equal(storageSummary([], false), 'no tokens were stored client-side');
  assert.equal(storageSummary([], true), 'client storage cleared ✓');
  assert.match(storageSummary([{ area: 'local', key: 'access_token', kind: 'jwt' }], true), /access_token.*localStorage.*✗/);
  assert.match(storageSummary([{ area: 'local', key: 'a' }, { area: 'session', key: 'b' }], true), /\+1 more/);
});

test('areaLabel', () => {
  assert.equal(areaLabel('local'), 'localStorage');
  assert.equal(areaLabel('indexeddb'), 'IndexedDB');
});
