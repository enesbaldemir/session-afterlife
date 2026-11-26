// Builds browser-specific unpacked extensions and zips.
//   node scripts/build.js            -> dist/chrome/ , dist/firefox/ and zips
//
// The source in extension/ is the Chrome build. The Firefox build is the same
// files with a transformed manifest (sidebar instead of side panel, event-page
// background, blocking webRequest instead of declarativeNetRequest).

import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { toFirefox } from './firefox-manifest.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const src = path.join(root, 'extension');
const base = JSON.parse(readFileSync(path.join(src, 'manifest.json'), 'utf8'));
const { version } = base;

function build(name, manifest) {
  const out = path.join(root, 'dist', name);
  rmSync(out, { recursive: true, force: true });
  mkdirSync(out, { recursive: true });
  cpSync(src, out, { recursive: true });
  writeFileSync(path.join(out, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  const zip = path.join(root, 'dist', `session-afterlife-${name}-${version}.zip`);
  rmSync(zip, { force: true });
  execFileSync('zip', ['-r', '-X', '-q', zip, '.', '-x', '.DS_Store', '*/.DS_Store'], { cwd: out });
  console.log(`${name}: ${path.relative(root, out)}/  ->  ${path.relative(root, zip)}`);
}

mkdirSync(path.join(root, 'dist'), { recursive: true });
build('chrome', base);
build('firefox', toFirefox(base));
