import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { toFirefox } from '../../scripts/firefox-manifest.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const base = JSON.parse(readFileSync(path.join(root, 'extension/manifest.json'), 'utf8'));
const ff = toFirefox(base);

test('Firefox manifest replaces the side panel with a sidebar', () => {
  assert.ok(!ff.side_panel);
  assert.equal(ff.sidebar_action.default_panel, 'panel.html');
});

test('Firefox manifest drops DNR/sidePanel and adds blocking webRequest', () => {
  assert.ok(!ff.permissions.includes('declarativeNetRequestWithHostAccess'));
  assert.ok(!ff.permissions.includes('sidePanel'));
  assert.ok(ff.permissions.includes('webRequestBlocking'));
  assert.ok(ff.permissions.includes('cookies') && ff.permissions.includes('scripting'));
});

test('Firefox manifest uses an event page and declares a gecko id', () => {
  assert.deepEqual(ff.background, { scripts: ['background.js'], type: 'module' });
  assert.match(ff.browser_specific_settings.gecko.id, /@/);
  assert.deepEqual(ff.browser_specific_settings.gecko.data_collection_permissions, { required: ['none'] });
  assert.ok(!ff.minimum_chrome_version);
});

test('the base (Chrome) manifest is unchanged by the transform', () => {
  assert.ok(base.side_panel, 'base still has side_panel');
  assert.ok(base.permissions.includes('declarativeNetRequestWithHostAccess'));
  assert.ok(!base.sidebar_action);
});
