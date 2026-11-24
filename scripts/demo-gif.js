// Records docs/demo.gif: the demo site and the side panel, side by side.
//   node scripts/demo-gif.js
import { execFileSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { launch, startDemo, openPanel, signIn, lastResult, waitStatus } from '../test/e2e/helpers.js';

const require = createRequire(import.meta.url);
let sharp;
try { sharp = require('sharp'); } catch { sharp = require('/opt/npm-tools/node_modules/sharp'); }

const W = 1280; const H = 720; const BAR = 64;
const SITE_W = 840; const PANEL_W = W - SITE_W;
const dir = mkdtempSync(path.join(tmpdir(), 'afterlife-gif-'));
const frames = [];

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;');
async function frame(site, panel, step, caption, seconds) {
  const s = await site.screenshot();
  const p = await panel.screenshot();
  const bar = Buffer.from(`<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${BAR}">
    <rect width="100%" height="100%" fill="#1c1c1a"/>
    <circle cx="40" cy="${BAR / 2}" r="17" fill="#f2c94c"/>
    <text x="40" y="${BAR / 2 + 7}" font-family="DejaVu Sans, sans-serif" font-size="19" font-weight="700" text-anchor="middle" fill="#1c1c1a">${step}</text>
    <text x="72" y="${BAR / 2 + 8}" font-family="DejaVu Sans, sans-serif" font-size="23" fill="#f6f5f2">${esc(caption)}</text>
  </svg>`);
  const file = path.join(dir, `f${frames.length}.png`);
  await sharp({ create: { width: W, height: H, channels: 3, background: '#1c1c1a' } })
    .composite([
      { input: bar, top: 0, left: 0 },
      { input: await sharp(s).resize(SITE_W - 8, H - BAR - 8, { fit: 'cover', position: 'top' }).png().toBuffer(), top: BAR + 4, left: 4 },
      { input: await sharp(p).resize(PANEL_W - 8, H - BAR - 8, { fit: 'cover', position: 'top' }).png().toBuffer(), top: BAR + 4, left: SITE_W + 4 },
    ])
    .png().toFile(file);
  frames.push({ file, seconds });
}

const env = await launch();
try {
  const demo = await startDemo({ flaws: ['logout', 'fixation', 'weak-cookie', 'cache'], port: 8090 });
  const panel = await openPanel(env, demo.base, { mode: 'auto' });
  await panel.setViewportSize({ width: PANEL_W - 8, height: H - BAR - 8 });
  const site = await env.context.newPage();
  await site.setViewportSize({ width: SITE_W - 8, height: H - BAR - 8 });

  await site.goto(`${demo.base}/login`);
  await panel.locator('#s-main .status').waitFor();
  await site.fill('input[name=password]', 'wonderland');
  await frame(site, panel, 1, 'Use your app as usual. localhost is watched out of the box.', 2.6);

  await site.click('form button');
  await site.waitForURL(`${demo.base}/account`);
  await waitStatus(panel, 'Watching this session');
  await frame(site, panel, 2, 'Sign in: the session is recorded and audited automatically.', 3.6);

  await site.click('#logout');
  await site.waitForURL(/logged_out/);
  await frame(site, panel, 3, 'Log out. The browser forgets the cookie…', 2.2);
  await lastResult(panel, 20_000);
  await frame(site, panel, 4, '…but the server still accepts the old session. Caught.', 4.5);
  await demo.close();
} finally {
  await env.close();
}

const list = path.join(dir, 'list.txt');
writeFileSync(list, frames.map((f) => `file '${f.file}'\nduration ${f.seconds}`).join('\n') + `\nfile '${frames.at(-1).file}'\n`);
const out = new URL('../docs/demo.gif', import.meta.url).pathname;
const palette = path.join(dir, 'palette.png');
execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', list, '-vf', 'fps=10,scale=1000:-1:flags=lanczos,palettegen=max_colors=128', palette]);
execFileSync('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'concat', '-safe', '0', '-i', list, '-i', palette, '-lavfi', 'fps=10,scale=1000:-1:flags=lanczos[x];[x][1:v]paletteuse=dither=none', out]);
rmSync(dir, { recursive: true, force: true });
console.log('docs/demo.gif written');
