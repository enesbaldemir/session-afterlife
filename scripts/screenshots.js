// Renders the README screenshots: node scripts/screenshots.js
import { launch, startDemo, openPanel, signIn, pickReference, lastResult, waitStatus } from '../test/e2e/helpers.js';

const env = await launch();
const out = (n) => new URL(`../docs/screenshots/${n}`, import.meta.url).pathname;
async function tall(panel, name) {
  const h = await panel.evaluate(() => document.documentElement.scrollHeight);
  await panel.setViewportSize({ width: 400, height: h });
  await panel.screenshot({ path: out(name) });
  await panel.setViewportSize({ width: 400, height: 900 });
}
try {
  let demo = await startDemo({ flaws: ['logout', 'weak-cookie', 'cache'], idle: 1800 });
  let panel = await openPanel(env, demo.base, { mode: 'auto' });
  await panel.setViewportSize({ width: 400, height: 900 });
  const site = await env.context.newPage();
  await site.goto(`${demo.base}/`);
  await signIn(site, demo.base);
  await waitStatus(panel, 'Watching this session');
  await panel.locator('#s-main').screenshot({ path: out('1-auto-watching.png') });
  await panel.locator('#s-findings').screenshot({ path: out('3-findings.png') });
  await panel.locator('#s-session tr', { hasText: 'sid' }).getByRole('button', { name: 'Show' }).click();
  await panel.locator('#s-session details').first().evaluate((d) => { d.open = true; }).catch(() => {});
  await panel.locator('#s-session').screenshot({ path: out('4-session.png') });
  await site.click('#logout');
  await lastResult(panel, 20_000);
  await panel.locator('#s-session tr', { hasText: 'sid' }).getByRole('button', { name: 'Hide' }).click();
  await signIn(site, demo.base);
  await waitStatus(panel, 'Watching this session');
  await tall(panel, '2-panel.png');
  await panel.locator('#s-test').screenshot({ path: out('5-timeouts.png') });
  await panel.locator('#scope-details').evaluate((d) => { d.open = true; });
  await panel.locator('#s-scope').screenshot({ path: out('6-scope.png') });
  await panel.close();
  await demo.close();
  await env.context.clearCookies();

  demo = await startDemo({});
  panel = await openPanel(env, demo.base, { mode: 'manual' });
  await signIn(site, demo.base);
  await site.goto(`${demo.base}/api/me`);
  await site.goto(`${demo.base}/account`);
  await pickReference(panel, '/account');
  await panel.locator('#s-main').screenshot({ path: out('7-manual.png') });
  await demo.close();
} finally {
  await env.close();
}
console.log('screenshots written');
