// Shared setup for end-to-end tests: a demo server, Chromium with the
// extension loaded, and the panel opened as a tab.
import { createRequire } from 'node:module';
import { cpSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const require = createRequire(import.meta.url);
const { createApp } = require('../../demo/server.js');

function loadPlaywright() {
  try { return require('playwright'); } catch { /* fall through */ }
  const globalRoot = process.env.PLAYWRIGHT_MODULE || '/opt/npm-tools/node_modules/playwright';
  return require(globalRoot);
}

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

export async function startDemo(opts) {
  const server = createApp(opts);
  await new Promise((r) => server.listen(opts?.port || 0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${server.address().port}`;
  return { server, base, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(r); }) };
}

// A throwaway copy of the extension, so that the browser cannot write into the source.
function testBuild() {
  const dir = mkdtempSync(path.join(tmpdir(), 'afterlife-ext-'));
  cpSync(path.join(root, 'extension'), dir, { recursive: true });
  return dir;
}

export async function launch() {
  for (const k of ['HTTP_PROXY', 'HTTPS_PROXY', 'http_proxy', 'https_proxy', 'ALL_PROXY', 'all_proxy']) delete process.env[k];
  const { chromium } = loadPlaywright();
  const ext = testBuild();
  const profile = mkdtempSync(path.join(tmpdir(), 'afterlife-profile-'));
  const context = await chromium.launchPersistentContext(profile, {
    channel: 'chromium',
    headless: process.env.HEADED ? false : true,
    viewport: { width: 420, height: 900 },
    args: [`--disable-extensions-except=${ext}`, `--load-extension=${ext}`, '--no-proxy-server'],
  });
  let [sw] = context.serviceWorkers();
  if (!sw) sw = await context.waitForEvent('serviceworker');
  const extId = new URL(sw.url()).host;
  return {
    context,
    sw,
    extId,
    async close() {
      await context.close();
      rmSync(ext, { recursive: true, force: true });
      rmSync(profile, { recursive: true, force: true });
    },
  };
}

export async function openPanel(env, origin, { mode = 'manual', scope = ['localhost', '127.0.0.1'], tab = '' } = {}) {
  const panel = await env.context.newPage();
  const q = `origin=${encodeURIComponent(origin)}${tab ? `&tab=${encodeURIComponent(tab)}` : ''}`;
  await panel.goto(`chrome-extension://${env.extId}/panel.html?${q}`);
  // Start each scenario from a clean state, in the requested mode.
  await panel.evaluate(async ({ m, sc }) => {
    await chrome.storage.local.set({ mode: m, scope: sc });
    await chrome.runtime.sendMessage({ type: 'setMode', mode: m });
    await chrome.runtime.sendMessage({ type: 'reset' });
  }, { m: mode, sc: scope });
  await panel.reload();
  return panel;
}

export async function signIn(site, base, password = 'wonderland') {
  await site.goto(`${base}/login`);
  await site.fill('input[name=password]', password);
  await site.click('form button');
  await site.waitForURL(`${base}/account`);
}

export async function pickReference(panel, pathText) {
  const item = panel.locator('.reqs li', { hasText: pathText }).first();
  await item.waitFor();
  await item.locator('input[type=radio]').check();
  await panel.locator('.reqs li', { hasText: pathText }).first().locator('input:checked').waitFor();
}

export async function snapshot(panel) {
  await panel.getByRole('button', { name: /Record (session|again)/ }).click();
  await panel.locator('#s-main .note').first().waitFor();
}

export async function lastResult(panel, timeout = 15_000) {
  const card = panel.locator('#s-results .result').first();
  await card.waitFor({ timeout });
  return {
    badge: (await card.locator('.badge').textContent()).trim(),
    browser: (await card.locator('.side').nth(0).locator('.v').textContent()).trim(),
    server: (await card.locator('.side').nth(1).locator('.v').textContent()).trim(),
    text: (await card.textContent()).replace(/\s+/g, ' '),
  };
}

export async function waitStatus(panel, title, timeout = 20_000) {
  await panel.locator('#s-main .status .t', { hasText: title }).waitFor({ timeout });
}
