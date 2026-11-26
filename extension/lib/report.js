// Markdown report. Secret values (cookie values, tokens) are never written.

import { formatDuration } from './lifetime.js';
import { describeResult } from './timeout.js';
import { storageSummary, areaLabel } from './storage.js';

export const SCENARIOS = Object.freeze({
  logout: { title: 'Logout', wstg: 'WSTG-SESS-06', expect: 'INVALIDATED' },
  password: { title: 'Password change ends other sessions', wstg: 'WSTG-ATHN-08', expect: 'INVALIDATED' },
  elsewhere: { title: 'New login elsewhere (concurrent sessions)', wstg: 'WSTG-SESS-11', expect: null },
  idle: { title: 'Idle timeout', wstg: 'WSTG-SESS-07', expect: null },
  absolute: { title: 'Absolute timeout', wstg: 'WSTG-SESS-07', expect: null },
});

const VERDICT_TEXT = {
  STILL_VALID: 'Old session STILL VALID',
  INVALIDATED: 'Old session INVALIDATED',
  INCONCLUSIVE: 'INCONCLUSIVE',
};

const COOKIE_TEXT = { deleted: 'deleted', changed: 'value changed', unchanged: 'unchanged' };

// Is this outcome a finding? Logout and password change should end the old
// session; concurrent sessions are informational.
export function assess(scenario, verdict) {
  const exp = SCENARIOS[scenario]?.expect;
  if (verdict === 'INCONCLUSIVE') return 'unknown';
  if (!exp) return 'info';
  return verdict === exp ? 'pass' : 'fail';
}

export function browserSummary(cookieDiff = []) {
  if (cookieDiff.length === 0) return 'No cookies were sent with the reference request.';
  const parts = cookieDiff.map((c) => `\`${c.name}\` ${COOKIE_TEXT[c.status]}`);
  return parts.join(', ');
}

// One line, the way the panel shows it: "Browser: cookie deleted ✓ — Server: old session still valid ✗"
export function headline(check) {
  const changed = (check.cookieDiff || []).some((c) => c.status !== 'unchanged');
  const browser = (check.cookieDiff || []).length === 0
    ? 'Browser: no cookies'
    : changed ? 'Browser: session cookie cleared or replaced' : 'Browser: cookies untouched';
  const server = check.verdict === 'STILL_VALID'
    ? 'Server: old session still accepted'
    : check.verdict === 'INVALIDATED' ? 'Server: old session rejected' : 'Server: unclear';
  let line = `${browser} — ${server}`;
  if (check.storage?.hadBefore) {
    line += check.storage.residue.length ? ` — Storage: ${check.storage.residue.length} token(s) left behind` : ' — Storage: cleared';
  }
  return line;
}

export function toMarkdown(state, { findings = [] } = {}) {
  const lines = [];
  const snap = state.snapshot;
  lines.push('# Session Afterlife report', '');
  lines.push(`- Target: ${state.origin || state.target?.origin || '—'}`);
  if (state.reference) lines.push(`- Reference request: \`${state.reference.method} ${state.reference.url}\``);
  if (snap) lines.push(`- Snapshot taken: ${new Date(snap.takenAt).toISOString()}`);
  if (state.marker) lines.push('- Marker: set (value not shown)');
  lines.push('');

  if (snap?.lifetimes?.length) {
    lines.push('## Declared lifetime', '');
    lines.push('| Item | Flags | Browser lifetime | Token lifetime |', '| --- | --- | --- | --- |');
    for (const it of snap.lifetimes) {
      const flags = it.source === 'cookie'
        ? [it.httpOnly ? 'HttpOnly' : null, it.secure ? 'Secure' : null, it.sameSite ? `SameSite=${it.sameSite}` : null].filter(Boolean).join(', ') || '—'
        : 'header';
      const life = it.lifetime ? it.lifetime.text : '—';
      const tok = it.jwt ? `${it.jwt.text} (JWT ${it.jwt.alg})` : '—';
      lines.push(`| \`${it.name}\` | ${flags} | ${life} | ${tok} |`);
    }
    lines.push('');
  }

  const shown = findings.filter((f) => f.status === 'fail' || f.status === 'warn');
  const skipped = findings.filter((f) => f.status === 'skip');
  if (findings.length) {
    lines.push('## Findings', '');
    if (!shown.length) lines.push('No issues found in the recorded session.');
    for (const f of shown) {
      lines.push(`- **${f.severity.toUpperCase()}** ${f.title} (${f.wstg})${f.detail ? `: ${f.detail}` : ''}`);
    }
    for (const f of skipped) lines.push(`- Not checked: ${f.title.replace(/ not checked$/, '')} (${f.wstg}). ${f.detail}`);
    const passed = findings.filter((f) => f.status === 'pass').length;
    if (passed) lines.push(`- ${passed} check(s) passed.`);
    lines.push('');
  }

  const checks = state.checks || [];
  if (checks.length) {
    lines.push('## Checks', '');
    for (const c of checks) {
      const sc = SCENARIOS[c.scenario] || { title: c.scenario, wstg: '' };
      const a = assess(c.scenario, c.verdict);
      const mark = { pass: 'PASS', fail: 'FAIL', info: 'INFO', unknown: '?' }[a];
      lines.push(`### ${sc.title} (${sc.wstg}): ${mark}`, '');
      lines.push(`- When: ${new Date(c.at).toISOString()}${c.sinceSnapshotSec !== undefined ? ` (${formatDuration(c.sinceSnapshotSec)} after the snapshot)` : ''}`);
      lines.push(`- Server: ${VERDICT_TEXT[c.verdict]}`);
      if (c.cookieDiff) lines.push(`- Browser: ${browserSummary(c.cookieDiff)}`);
      if (c.storage?.hadBefore) {
        lines.push(`- Client storage: ${c.storage.residue.length === 0 ? 'cleared at logout' : c.storage.residue.map((e) => `\`${e.key}\` in ${areaLabel(e.area)}`).join(', ') + ' left behind'}`);
      }
      if (c.timeout) lines.push(`- Timeout: ${describeResult(c.timeout, c.unitName || 'min')}`);
      for (const r of c.reasons || []) lines.push(`  - ${r}`);
      lines.push('');
    }
  }

  const events = state.events || [];
  if (events.length) {
    lines.push('## Cookie events after the snapshot', '');
    for (const e of events) {
      lines.push(`- ${new Date(e.at).toISOString()} \`${e.name}\` ${e.removed ? 'removed' : 'set'} (cause: ${e.cause})`);
    }
    lines.push('');
  }

  lines.push('---', 'Generated by Session Afterlife. Test only applications you own or are authorized to test.');
  return lines.join('\n');
}

const shq = (v) => `'${String(v).replace(/'/g, "'\\''")}'`;

// A curl command that sends the reference request with the recorded (old)
// session, to reproduce a result outside the browser. Contains secrets.
export function toCurl(state) {
  const ref = state.reference;
  const snap = state.snapshot;
  if (!ref || !snap) return '';
  const parts = [`curl -i ${ref.method === 'HEAD' ? '-I ' : ''}${shq(ref.url)}`];
  if (snap.cookieHeader) parts.push(`-H ${shq(`Cookie: ${snap.cookieHeader}`)}`);
  if (snap.authorization) parts.push(`-H ${shq(`Authorization: ${snap.authorization}`)}`);
  const accept = ref.headers?.accept;
  if (accept) parts.push(`-H ${shq(`Accept: ${accept}`)}`);
  return parts.join(' \\\n  ');
}
