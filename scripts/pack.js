// Builds dist/session-afterlife-<version>.zip from the extension folder.
import { execFileSync } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { version } = JSON.parse(readFileSync(path.join(root, 'extension/manifest.json'), 'utf8'));
const out = path.join(root, 'dist', `session-afterlife-${version}.zip`);
mkdirSync(path.dirname(out), { recursive: true });
rmSync(out, { force: true });
execFileSync('zip', ['-r', '-X', '-q', out, '.', '-x', '.DS_Store', '*/.DS_Store'], { cwd: path.join(root, 'extension'), stdio: 'inherit' });
console.log(path.relative(root, out));
