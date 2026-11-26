import { analyseLifetimes, decodeJwt, formatDuration } from './lib/lifetime.js';
import { describeResult, nextDelayUnits } from './lib/timeout.js';
import { SCENARIOS, assess, toMarkdown, toCurl } from './lib/report.js';
import { areaLabel } from './lib/storage.js';
import { DEFAULT_SCOPE, normalizePattern, hostInScope, patternToOrigins, suggestPatterns } from './lib/scope.js';
import { auditSession, sessionCookieNames } from './lib/findings.js';
import { TAMPER } from './lib/tamper.js';

// Cross-browser binding (see background.js): shadows the global so chrome.* works on Firefox too.
const chrome = globalThis.browser ?? globalThis.chrome;

const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const params = new URLSearchParams(location.search);

let state = null; // { sites, timeout, mode, scope }
let current = params.get('origin') || ''; // origin shown in the panel
let tab = { url: params.get('tab') || '', id: null }; // the active tab, if its URL is visible
let ui = { scenario: 'logout', timeoutTab: 'idle', idleMax: 480, absInterval: 5, absMax: 1440 };
const revealed = new Set();
let tamperOpen = ''; // cookie key whose tamper editor is open
const tamperDraft = {}; // cookie key -> edited value in the open editor

// ---------- messaging ----------

async function send(type, payload = {}) {
  showError(null);
  let res;
  try {
    res = await chrome.runtime.sendMessage({ type, origin: current, ...payload });
  } catch (e) {
    showError(`The extension did not answer: ${e.message}`);
    return null;
  }
  if (!res) { showError('No answer from the extension. Try reloading it.'); return null; }
  state = res.state;
  render();
  if (!res.ok) { showError(res.error); return null; }
  return res.value;
}

function showError(msg) {
  $('error').hidden = !msg;
  $('error').textContent = msg || '';
}

const scope = () => state?.scope || [...DEFAULT_SCOPE];
const site = () => (current && state?.sites?.[current]) || null;
const auto = () => state?.mode !== 'manual';

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return ''; }
}
function originOf(url) {
  try { const u = new URL(url); return /^https?:$/.test(u.protocol) ? u.origin : ''; } catch { return ''; }
}

// Follow the active tab when its site is in scope.
async function detectTab() {
  if (params.get('origin')) return;
  try {
    const [t] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    tab = { url: t?.url && /^https?:/.test(t.url) ? t.url : '', id: t?.id ?? null };
  } catch {
    tab = { url: '', id: null };
  }
  const o = originOf(tab.url);
  if (o && hostInScope(hostOf(tab.url), scope())) current = o;
  else if (!current || !state?.sites?.[current]) current = Object.keys(state?.sites || {})[0] || '';
}

// ---------- rendering helpers ----------

function relTime(ms) {
  const s = Math.round((Date.now() - ms) / 1000);
  return s < 5 ? 'just now' : `${formatDuration(s)} ago`;
}
const clock = (ms) => new Date(ms).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
function shortUrl(url) {
  try { const u = new URL(url); return u.pathname + u.search; } catch { return url; }
}
const hours = (m) => (m % 60 === 0 ? `${m / 60} h` : `${m} min`);
// Replace a section only when its HTML changed, so that clicks and focus are
// not lost to needless re-rendering.
function put(el, html) {
  if (el._html === html) return;
  el._html = html;
  el.innerHTML = html;
}
const mask = (v) => `${'•'.repeat(Math.min(12, Math.max(6, v.length)))}  (${v.length} chars)`;

function render() {
  if (!state) return;
  const s = site();
  $('mode-auto').setAttribute('aria-pressed', String(auto()));
  $('mode-manual').setAttribute('aria-pressed', String(!auto()));
  $('busy').hidden = !s?.busy;
  $('busy').textContent = s?.busy || '';
  renderSite();
  if (auto()) renderStatus(); else renderManual();
  renderFindings();
  renderSession();
  renderTest();
  renderResults();
  renderScope();
  $('s-main').hidden = !s;
  $('s-findings').hidden = !s?.snapshot;
  $('s-session').hidden = !s?.snapshot;
  $('s-test').hidden = !s?.snapshot;
  $('s-results').hidden = !s?.checks?.length;
}

// ---------- site ----------

function renderSite() {
  const v = $('s-site');
  const sites = Object.keys(state.sites || {});
  const tabHost = hostOf(tab.url);
  const tabInScope = tabHost && hostInScope(tabHost, scope());
  let notice = '';
  if (tab.url && !tabInScope) {
    const sugg = suggestPatterns(tabHost);
    notice = `<div class="note warn"><b>${esc(tabHost)}</b> is not in scope, so it is not watched.
      <div class="actions">${sugg.map((p) => `<button data-act="add-scope" data-p="${esc(p)}">${p === tabHost ? 'Watch this site' : `Watch ${esc(p)}`}</button>`).join('')}</div></div>`;
  }
  if (!sites.length) {
    put(v, `<h2>Site</h2>${notice}
      <p>Open a site in scope and sign in. ${scope().length ? `In scope: ${scope().map((p) => `<code>${esc(p)}</code>`).join(', ')}.` : ''}</p>
      <p class="hint">Add your test site below under <b>Sites in scope</b>, or open this panel from its tab.</p>`);
    return;
  }
  const opts = sites.map((o) => `<option value="${esc(o)}" ${o === current ? 'selected' : ''}>${esc(o)}</option>`).join('');
  const s = site();
  const dot = !s ? '' : s.phase === 'armed' || s.phase === 'second-armed' ? 'live' : 'wait';
  put(v, `<h2>Site</h2>${notice}
    <div class="site"><span class="status"><span class="dot ${dot}"></span></span>
    <select id="site-select" aria-label="Site">${opts}</select>
    <button class="link" data-act="forget" title="Forget everything recorded for this site">Forget</button></div>`);
}

// ---------- automatic mode ----------

function renderStatus() {
  const v = $('s-main');
  const s = site();
  if (!s) { put(v, ''); return; }
  const ref = s.reference ? `<span class="mono">${esc(s.reference.method)} ${esc(shortUrl(s.reference.url))}</span>` : '';
  const t = state.timeout;
  let dot = 'wait';
  let title;
  let text;
  let actions = '';
  if (t && !t.done && t.origin === s.origin) {
    dot = 'live';
    title = 'Measuring a timeout';
    text = 'Automatic checks are paused until the measurement ends.';
  } else if (s.phase === 'armed') {
    dot = 'live';
    title = 'Watching this session';
    text = `Recorded from ${ref}. Log out whenever you like: the old session is checked automatically.`;
    actions = `<button data-act="second">Test password change and a second login</button>
      <button class="link" data-act="check-now" title="Use this if you logged out and nothing happened">I logged out, check now</button>`;
  } else if (s.phase === 'second-session') {
    title = 'Sign in again';
    text = 'This site\'s cookies were cleared in this browser. Sign in again to start a second session; the first one is kept for the check.';
    actions = '<button class="link" data-act="mode" data-mode="auto">Cancel</button>';
  } else if (s.phase === 'second-armed') {
    dot = 'live';
    title = 'Second session found';
    text = 'Now change the password in this second session. The first session is checked automatically afterwards.';
    actions = '<button class="link" data-act="check-now">I changed it, check now</button>';
  } else {
    title = 'Waiting for you to sign in';
    text = 'Sign in and open any page that needs login. The session is recorded automatically.';
  }
  const note = s.autoNote ? `<p class="hint">${esc(s.autoNote)}</p>` : '';
  put(v, `<h2>Status</h2>
    <div class="status"><span class="dot ${dot}"></span><div><div class="t">${esc(title)}</div><p>${text}</p>${note}</div></div>
    ${actions ? `<div class="actions">${actions}</div>` : ''}`);
}

// ---------- manual mode ----------

function renderManual() {
  const v = $('s-main');
  const s = site();
  if (!s) { put(v, ''); return; }
  const list = [...s.captured].sort((a, b) => (b.hasCookie || b.hasAuth) - (a.hasCookie || a.hasAuth)).slice(0, 15);
  const selected = s.reference?.url;
  const items = list.map((c) => `<li><label>
      <input type="radio" name="ref" value="${esc(c.id)}" ${c.url === selected ? 'checked' : ''}>
      <span class="u"><span class="mono">${esc(c.method)} ${esc(shortUrl(c.url))}</span><br>
      <span class="tag">${c.type === 'main_frame' ? 'page' : c.type === 'xmlhttprequest' ? 'fetch' : esc(c.type)}</span>
      <span class="tag ${c.hasCookie ? 'on' : ''}">cookie</span><span class="tag ${c.hasAuth ? 'on' : ''}">auth header</span>
      <span class="muted">${esc(relTime(c.at))}</span></span></label></li>`).join('');
  const q = s.quality;
  const qNote = !s.snapshot ? '' : q?.usable
    ? `<div class="note ok">✓ ${esc(q.reason)}</div>${q.warning ? `<div class="note warn">${esc(q.warning)}</div>` : ''}`
    : `<div class="note bad">✗ ${esc(q?.reason || 'Baselines missing.')}</div>`;
  put(v, `<h2>Reference request</h2>
    <p class="hint">Pick a request whose response shows that you are signed in, such as your account page or <code>/api/me</code>. Only GET and HEAD requests are replayed.</p>
    ${list.length ? `<ul class="reqs">${items}</ul>` : '<p class="note warn">No requests seen yet. Reload a signed-in page of the site.</p>'}
    <div class="row"><input type="text" id="manual" placeholder="or type a path, e.g. /account"><button data-act="manual-ref">Use</button></div>
    <div class="row"><input type="text" id="marker" placeholder="Marker (optional): text only a signed-in user sees" value="${esc(s.marker)}"></div>
    <div class="actions"><button class="primary" data-act="snapshot" ${selected ? '' : 'disabled'}>${s.snapshot ? 'Record again' : 'Record session'}</button></div>
    ${s.snapshot ? `<p class="hint" style="margin-top:8px">Recorded ${esc(relTime(s.snapshot.takenAt))} from <span class="mono">${esc(shortUrl(s.reference.url))}</span>.</p>${qNote}` : ''}`);
}

// ---------- findings ----------

function renderFindings() {
  const v = $('s-findings');
  const s = site();
  if (!s?.snapshot) { put(v, ''); return; }
  const all = auditSession(s);
  const issues = all.filter((f) => f.status === 'fail' || f.status === 'warn');
  const passed = all.filter((f) => f.status === 'pass');
  const skipped = all.filter((f) => f.status === 'skip');
  const label = (f) => (f.status === 'pass' ? 'ok' : f.status === 'skip' ? 'n/a' : f.severity);
  const row = (f) => `<div class="finding"><span class="sev ${f.status === 'pass' ? 'pass' : f.status === 'skip' ? 'skip' : f.severity}">${esc(label(f))}</span>
    <div><div>${md(f.title)}</div>${f.detail ? `<div class="hint">${esc(f.detail)}</div>` : ''}<div class="wstg">${esc(f.wstg)}</div></div></div>`;
  put(v, `<h2>Findings <span class="right muted">${issues.length ? `${issues.length} to review` : 'no issues'}</span></h2>
    ${issues.length ? issues.map(row).join('') : '<p class="note ok">✓ No issues in the recorded session.</p>'}
    ${skipped.map(row).join('')}
    ${passed.length ? `<details><summary>${passed.length} check(s) passed</summary>${passed.map(row).join('')}</details>` : ''}`);
}

// Inline `code` only.
function md(s) {
  return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');
}

// ---------- session inspector ----------

function renderSession() {
  const v = $('s-session');
  const s = site();
  const snap = s?.snapshot;
  if (!snap) { put(v, ''); return; }
  const essential = new Set(sessionCookieNames(snap));
  const life = analyseLifetimes(snap, Date.now() / 1000);
  const tamper = s.tamper || {};
  const rows = snap.cookies.map((c, i) => {
    const l = life[i];
    const key = `c:${c.name}:${c.path}`;
    const shown = revealed.has(key);
    const flags = [c.httpOnly && 'HttpOnly', c.secure && 'Secure', c.sameSite && c.sameSite !== 'unspecified' && `SameSite=${c.sameSite === 'no_restriction' ? 'None' : c.sameSite}`, !c.hostOnly && `Domain=${c.domain}`, c.path !== '/' && `Path=${c.path}`].filter(Boolean).join(' · ');
    const jwt = decodeJwt(c.value);
    const main = `<tr><td>
      <div><code>${esc(c.name)}</code> ${essential.has(c.name) ? '<span class="tag session">session</span>' : ''}</div>
      <div class="val ${shown ? '' : 'masked'}">${shown ? esc(c.value) : esc(mask(c.value))}</div>
      <div class="hint">${esc(flags || 'no flags')} · ${esc(l.lifetime.text)}</div>
      ${jwt ? jwtBlock(jwt) : ''}
      </td><td style="white-space:nowrap;text-align:right">
      <button class="icon-btn" data-act="reveal" data-k="${esc(key)}" title="${shown ? 'Hide' : 'Show'} value">${shown ? 'Hide' : 'Show'}</button>
      <button class="icon-btn" data-act="copy-val" data-i="${i}" title="Copy value">Copy</button>
      <button class="icon-btn" data-act="tamper-open" data-k="${esc(key)}" data-name="${esc(c.name)}" title="Replay with a changed value">Tamper</button></td></tr>`;
    return main + tamperRow(c, key, tamper[c.name]);
  }).join('');
  let authRow = '';
  if (snap.authorization) {
    const key = 'auth';
    const shown = revealed.has(key);
    const jwt = decodeJwt(snap.authorization);
    authRow = `<tr><td><div><code>Authorization</code> <span class="tag session">header</span></div>
      <div class="val ${shown ? '' : 'masked'}">${shown ? esc(snap.authorization) : esc(mask(snap.authorization))}</div>
      ${jwt ? jwtBlock(jwt) : ''}</td><td style="white-space:nowrap;text-align:right">
      <button class="icon-btn" data-act="reveal" data-k="auth">${shown ? 'Hide' : 'Show'}</button>
      <button class="icon-btn" data-act="copy-auth">Copy</button></td></tr>`;
  }
  put(v, `<h2>Recorded session <span class="right muted">${esc(relTime(snap.takenAt))}</span></h2>
    <table class="kv"><tbody>${rows}${authRow}</tbody></table>
    <div class="actions"><button data-act="copy-curl" title="A curl command that sends the reference request with this session">Copy as curl</button>
    ${snap.cookieHeader ? '<button data-act="copy-cookie">Copy Cookie header</button>' : ''}
    ${auto() ? '<button class="link" data-act="rerecord">Record again</button>' : ''}</div>
    <p class="hint">These are live credentials for your test account. Do not paste them into tickets or chats.</p>`);
}

function jwtBlock(jwt) {
  const p = jwt.payload;
  const exp = typeof p.exp === 'number' ? (p.exp * 1000 > Date.now() ? `expires in ${formatDuration(p.exp - Date.now() / 1000)}` : 'expired') : 'no exp';
  return `<details><summary>JWT · ${esc(jwt.header.alg)} · ${esc(exp)}</summary>
    <pre class="json">${esc(JSON.stringify(jwt.header, null, 2))}</pre><pre class="json">${esc(JSON.stringify(p, null, 2))}</pre></details>`;
}

const TAMPER_UI = {
  REJECTED: { cls: 'good', text: 'Rejected — the server validates this value ✓' },
  IGNORED: { cls: '', text: 'No change — the server ignored the new value for this request' },
  CHANGED: { cls: 'bad', text: 'Changed — the server trusted the new value, review it ✗' },
  INCONCLUSIVE: { cls: 'meh', text: 'Inconclusive' },
};

// The editor and the last result for one cookie, shown as a second table row.
function tamperRow(c, key, result) {
  if (tamperOpen !== key && !result) return '';
  let editor = '';
  if (tamperOpen === key) {
    const draft = tamperDraft[key] ?? c.value;
    editor = `<div class="row"><input type="text" class="tamper-input" data-k="${esc(key)}" value="${esc(draft)}" placeholder="new value">
      <button class="primary" data-act="tamper-run" data-name="${esc(c.name)}" data-k="${esc(key)}">Replay</button>
      <button class="link" data-act="tamper-close" data-k="${esc(key)}">Close</button></div>
      <p class="hint">Replays the reference request with <code>${esc(c.name)}</code> set to this value. Read-only; your real session is untouched. Authorized targets only.</p>`;
  }
  let res = '';
  if (result) {
    const u = TAMPER_UI[result.verdict] || TAMPER_UI.INCONCLUSIVE;
    res = `<div class="tamper-result"><span class="v ${u.cls}">${esc(u.text)}</span>
      <details><summary>Details</summary><ul>${(result.reasons || []).map((r) => `<li>${esc(r)}</li>`).join('')}</ul></details></div>`;
  }
  return `<tr class="tamper-row"><td colspan="2">${editor}${res}</td></tr>`;
}

// ---------- tests ----------

const HOWTO = {
  logout: ['Log out in the page the way a user would.', 'Press <b>Check old session</b>.'],
  password: ['Press <b>Start second session</b>. This clears the site\'s cookies in this browser only; the recorded session is kept.',
    'Sign in again. This is the second session.', 'Change the password in the second session.', 'Press <b>Check old session</b>.'],
  elsewhere: ['Press <b>Start second session</b>.', 'Sign in again.', 'Press <b>Check old session</b>. Whether both sessions may stay active is up to the application\'s policy.'],
  idle: ['Close the site\'s tabs. Any request from a tab resets the idle timer.', 'Press <b>Start</b>. The old session is probed after growing waits (1, 2, 3, 5, 8… min) until it stops working.', 'Keep the browser open. You get a notification when it finishes.'],
  absolute: ['Press <b>Start</b>. The old session is probed every few minutes, which keeps it active.', 'If it still ends, that is the absolute timeout. Keep the browser open.'],
};

function renderTest() {
  const v = $('s-test');
  const s = site();
  if (!s?.snapshot) { put(v, ''); return; }
  const keys = auto() ? ['idle', 'absolute'] : Object.keys(SCENARIOS);
  if (!keys.includes(ui.scenario)) ui.scenario = keys[0];
  const sc = ui.scenario;
  const tabs = keys.map((k) => `<button data-act="scenario" data-k="${k}" aria-pressed="${k === sc}">${esc(SCENARIOS[k].title.replace(' ends other sessions', '').replace(' (concurrent sessions)', ''))}</button>`).join('');
  let body;
  if (sc === 'idle' || sc === 'absolute') body = renderTimeout(sc);
  else {
    const second = sc !== 'logout' ? `<button data-act="second">${s.secondSession ? 'Second session started ✓' : 'Start second session'}</button>` : '';
    body = `<div class="actions">${second}<button class="primary" data-act="check">Check old session</button></div>`;
  }
  put(v, `<h2>${auto() ? 'Timeout tests' : 'Tests'}</h2><div class="tabs">${tabs}</div>
    <p class="hint">${esc(SCENARIOS[sc].wstg)}</p><ol class="howto">${HOWTO[sc].map((h) => `<li>${h}</li>`).join('')}</ol>${body}`);
}

function renderTimeout(mode) {
  const t = state.timeout;
  const s = site();
  const unitName = t && t.unitMs !== 60_000 ? `× ${t.unitMs / 1000}s` : 'min';
  if (t && !t.done && t.origin !== s.origin) {
    return `<p class="note warn">A timeout measurement is running for ${esc(t.origin)}. Only one can run at a time.</p>`;
  }
  if (t && !t.done && t.mode === mode) {
    const total = mode === 'idle' ? t.plan.length : Math.ceil(t.maxUnits / t.intervalUnits);
    const done = mode === 'idle' ? t.step : Math.round(t.elapsed / t.intervalUnits);
    const pct = Math.min(100, Math.round((done / total) * 100));
    const hist = t.history.map((h) => `<li>after ${h.waited} ${esc(unitName)}: ${h.verdict === 'STILL_VALID' ? 'still valid' : esc(h.verdict.toLowerCase())}</li>`).join('');
    return `<div class="progress"><div style="width:${pct}%"></div></div>
      <p>Probe ${done + 1}${mode === 'idle' ? ` of up to ${total}` : ''}: waiting ${nextDelayUnits(t)} ${esc(unitName)}, next probe at <b>${esc(clock(t.nextAt))}</b>.</p>
      ${t.disturbed ? `<div class="note warn">A tab requested <code>${esc(shortUrl(t.disturbed.url))}</code> at ${esc(clock(t.disturbed.at))}, which may have reset the idle timer. For a clean result, stop, close the site's tabs and start again.</div>` : ''}
      ${hist ? `<ul class="muted">${hist}</ul>` : ''}
      <div class="actions"><button class="danger" data-act="timeout-stop">Stop</button></div>`;
  }
  if (t && !t.done) return `<p class="note warn">A ${esc(t.mode)} timeout measurement is running. Stop it first.</p>`;
  const opts = mode === 'idle'
    ? `<div class="row">Stop after <select id="idle-max">${[60, 240, 480, 1440].map((m) => `<option value="${m}" ${ui.idleMax === m ? 'selected' : ''}>${hours(m)}</option>`).join('')}</select> without expiry</div>`
    : `<div class="row">Probe every <select id="abs-interval">${[2, 5, 10].map((m) => `<option value="${m}" ${ui.absInterval === m ? 'selected' : ''}>${m} min</option>`).join('')}</select>
       for up to <select id="abs-max">${[240, 480, 1440].map((m) => `<option value="${m}" ${ui.absMax === m ? 'selected' : ''}>${hours(m)}</option>`).join('')}</select></div>`;
  return `${opts}<div class="actions"><button class="primary" data-act="timeout-start" data-mode="${mode}">Start</button></div>`;
}

// ---------- results ----------

function sides(c) {
  const second = c.scenario === 'password' || c.scenario === 'elsewhere';
  let browser = { v: '—', cls: '' };
  if (c.timeout) browser = { v: 'not checked', cls: '' };
  else if (second) browser = { v: 'second session', cls: '' };
  else if (c.cookieDiff?.length) {
    if (c.cookieDiff.some((x) => x.status === 'deleted')) browser = { v: 'cookie deleted ✓', cls: 'good' };
    else if (c.cookieDiff.some((x) => x.status === 'changed')) browser = { v: 'cookie replaced ✓', cls: 'good' };
    else browser = { v: 'cookies untouched ✗', cls: 'bad' };
  }
  const expected = SCENARIOS[c.scenario]?.expect;
  let server;
  if (c.verdict === 'STILL_VALID') {
    server = { v: c.scenario === 'elsewhere' ? 'both sessions active' : c.timeout ? 'never expired' : 'old session still valid ✗', cls: expected ? 'bad' : 'meh' };
  } else if (c.verdict === 'INVALIDATED') {
    server = { v: c.scenario === 'elsewhere' ? 'old session ended' : c.timeout ? 'expired' : 'old session rejected ✓', cls: expected ? 'good' : '' };
  } else server = { v: 'unclear', cls: 'meh' };
  return { browser, server };
}

// A note under a logout/password result about tokens left in client storage.
function storageLine(c) {
  const st = c.storage;
  if (!st || !st.hadBefore) return '';
  if (st.residue.length === 0) {
    return '<div class="note ok">Client storage: session tokens were cleared at logout ✓</div>';
  }
  const items = st.residue.map((e) => `<code>${esc(e.key)}</code> in ${esc(areaLabel(e.area))}`).join(', ');
  return `<div class="note bad">Client storage: ${items} still present after logout ✗<br>
    <span class="hint">The app forgot to clear these. Anyone with access to this browser profile can read them.</span></div>`;
}

function renderResults() {
  const v = $('s-results');
  const s = site();
  const checks = s?.checks || [];
  if (!checks.length) { put(v, ''); return; }
  const cards = [...checks].reverse().map((c) => {
    const sc = SCENARIOS[c.scenario];
    const a = assess(c.scenario, c.verdict);
    const label = { pass: 'PASS', fail: 'FAIL', info: 'INFO', unknown: '?' }[a];
    const { browser, server } = sides(c);
    const cookies = (c.cookieDiff || []).map((x) => `<li><code>${esc(x.name)}</code> ${esc(x.status)}</li>`).join('');
    return `<div class="result">
      <div class="head"><span class="title">${esc(sc.title)}${c.auto ? '<span class="auto-tag">auto</span>' : ''}</span><span class="badge b-${a}">${label}</span></div>
      <div class="muted">${esc(sc.wstg)} · ${esc(clock(c.at))}${c.sinceSnapshotSec !== undefined ? ` · ${esc(formatDuration(c.sinceSnapshotSec))} after recording` : ''}</div>
      <div class="split">
        <div class="side"><div class="k">Browser</div><div class="v ${browser.cls}">${esc(browser.v)}</div></div>
        <div class="side"><div class="k">Server</div><div class="v ${server.cls}">${esc(server.v)}</div></div>
      </div>
      ${c.timeout ? `<p>${esc(describeResult(c.timeout, c.unitName))}</p>` : ''}
      ${storageLine(c)}
      <details><summary>Details</summary><ul>${(c.reasons || []).map((r) => `<li>${esc(r)}</li>`).join('')}</ul>
      ${cookies ? `<p class="muted">Cookies sent with the reference request:</p><ul>${cookies}</ul>` : ''}</details>
    </div>`;
  }).join('');
  const events = (s.events || []).map((e) => `<li><span class="muted">${esc(clock(e.at))}</span> <code>${esc(e.name)}</code> ${e.removed ? 'removed' : 'set'} (${esc(e.cause)})</li>`).join('');
  put(v, `<h2>Results</h2>${cards}
    ${events ? `<details><summary>Cookie events since recording (${s.events.length})</summary><ul>${events}</ul></details>` : ''}
    <div class="actions"><button data-act="copy-report">Copy report</button><button data-act="download">Download .md</button>
    <button class="link" data-act="clear">Clear results</button></div>`);
}

// ---------- scope ----------

function renderScope() {
  const v = $('s-scope');
  const list = scope().map((p) => `<li><code>${esc(p)}</code><button class="icon-btn" data-act="remove-scope" data-p="${esc(p)}" title="Stop watching">Remove</button></li>`).join('');
  const open = ui.scopeOpen ?? !Object.keys(state?.sites || {}).length;
  put(v, `<details id="scope-details" ${open ? 'open' : ''}><summary><b>Sites in scope</b> (${scope().length})</summary>
    <p class="hint">Only these sites are watched. <code>*.example.com</code> covers example.com and all of its subdomains.</p>
    <ul class="scope-list">${list || '<li class="muted">Nothing in scope.</li>'}</ul>
    <div class="row"><input type="text" id="scope-input" placeholder="app.example.com or *.staging.example.com"><button data-act="add-scope-input">Add</button></div></details>`);
}

async function addScope(input) {
  const r = normalizePattern(input);
  if (r.error) { showError(r.error); return; }
  const p = r.pattern;
  if (scope().includes(p)) return;
  const granted = await chrome.permissions.request({ origins: patternToOrigins(p) });
  if (!granted) { showError('Access to the site was not granted.'); return; }
  const next = [...scope(), p];
  await chrome.storage.local.set({ scope: next });
  state.scope = next;
  if (tab.url && hostInScope(hostOf(tab.url), next)) {
    current = originOf(tab.url);
    await send('seedPage', { url: tab.url });
  } else render();
}

async function removeScope(p) {
  const next = scope().filter((x) => x !== p);
  await chrome.storage.local.set({ scope: next });
  state.scope = next;
  if (!DEFAULT_SCOPE.includes(p)) chrome.permissions.remove({ origins: patternToOrigins(p) }).catch(() => {});
  render();
}

// ---------- events ----------

async function copy(text, btn) {
  await navigator.clipboard.writeText(text);
  if (btn) {
    const old = btn.textContent;
    btn.textContent = 'Copied';
    setTimeout(() => { btn.textContent = old; }, 1200);
  }
}

function focusTamper(key) {
  const input = document.querySelector(`.tamper-input[data-k="${CSS.escape(key)}"]`);
  if (input) { input.focus(); input.select(); }
}

document.addEventListener('click', async (e) => {
  const b = e.target.closest('[data-act]');
  if (!b) return;
  const act = b.dataset.act;
  const s = site();
  switch (act) {
    case 'mode': await send('setMode', { mode: b.dataset.mode }); break;
    case 'add-scope': await addScope(b.dataset.p); break;
    case 'add-scope-input': await addScope($('scope-input').value); break;
    case 'remove-scope': await removeScope(b.dataset.p); break;
    case 'forget': await send('forgetSite'); current = Object.keys(state.sites || {})[0] || ''; render(); break;
    case 'manual-ref': { const p = $('manual').value.trim(); if (p) await send('setReference', { url: p }); break; }
    case 'snapshot':
      await send('setMarker', { marker: $('marker').value });
      await send('takeSnapshot');
      break;
    case 'scenario': ui.scenario = b.dataset.k; saveUi(); render(); break;
    case 'second': await send('startSecondSession'); break;
    case 'check': await send('check', { scenario: ui.scenario }); break;
    case 'check-now': await send('checkNow'); break;
    case 'rerecord': await send('rerecord'); break;
    case 'timeout-start':
      if (b.dataset.mode === 'idle') await send('timeoutStart', { mode: 'idle', maxUnits: ui.idleMax });
      else await send('timeoutStart', { mode: 'absolute', intervalUnits: ui.absInterval, maxUnits: ui.absMax });
      break;
    case 'timeout-stop': await send('timeoutStop'); break;
    case 'reveal': if (revealed.has(b.dataset.k)) revealed.delete(b.dataset.k); else revealed.add(b.dataset.k); render(); break;
    case 'copy-val': await copy(s.snapshot.cookies[Number(b.dataset.i)].value, b); break;
    case 'tamper-open': tamperOpen = b.dataset.k; render(); focusTamper(b.dataset.k); break;
    case 'tamper-close': if (tamperOpen === b.dataset.k) tamperOpen = ''; delete tamperDraft[b.dataset.k]; render(); break;
    case 'tamper-run': {
      const input = document.querySelector(`.tamper-input[data-k="${CSS.escape(b.dataset.k)}"]`);
      const value = input ? input.value : '';
      tamperDraft[b.dataset.k] = value;
      await send('tamperCheck', { cookieName: b.dataset.name, value });
      break;
    }
    case 'copy-auth': await copy(s.snapshot.authorization, b); break;
    case 'copy-cookie': await copy(s.snapshot.cookieHeader, b); break;
    case 'copy-curl': await copy(toCurl(s), b); break;
    case 'copy-report': await copy(toMarkdown(s, { findings: auditSession(s) }), b); break;
    case 'download': {
      const blob = new Blob([toMarkdown(s, { findings: auditSession(s) })], { type: 'text/markdown' });
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `session-afterlife-${s.hostname}-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.md`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      break;
    }
    case 'clear': await send('clearChecks'); break;
    default: break;
  }
});

document.addEventListener('change', async (e) => {
  const t = e.target;
  if (t.id === 'site-select') { current = t.value; render(); } else if (t.name === 'ref') {
    const r = await chrome.runtime.sendMessage({ type: 'setReference', origin: current, id: t.value });
    state = r.state;
    if (!r.ok) {
      t.checked = false; // the section may not re-render, so undo the click here
      showError(r.error);
    } else showError(null);
    render();
  }
  else if (t.classList.contains('tamper-input')) tamperDraft[t.dataset.k] = t.value;
  else if (t.id === 'marker') await send('setMarker', { marker: t.value });
  else if (t.id === 'idle-max') { ui.idleMax = Number(t.value); saveUi(); } else if (t.id === 'abs-interval') { ui.absInterval = Number(t.value); saveUi(); } else if (t.id === 'abs-max') { ui.absMax = Number(t.value); saveUi(); }
});

document.addEventListener('toggle', (e) => {
  if (e.target.id === 'scope-details') ui.scopeOpen = e.target.open;
}, true);

document.addEventListener('input', (e) => {
  if (e.target.classList?.contains('tamper-input')) tamperDraft[e.target.dataset.k] = e.target.value;
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Enter' && e.target.id === 'scope-input') addScope(e.target.value);
  if (e.key === 'Enter' && e.target.classList?.contains('tamper-input')) {
    const row = e.target.closest('.tamper-row');
    row?.querySelector('[data-act="tamper-run"]')?.click();
  }
});

function saveUi() { chrome.storage.local.set({ ui }); }

function typing() {
  const f = document.activeElement;
  return f && (f.tagName === 'INPUT' || f.tagName === 'SELECT');
}

chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area === 'session' && changes.state) {
    state = changes.state.newValue;
    if (!current || !state.sites?.[current]) await detectTab();
    if (!typing()) render();
  }
  if (area === 'local' && changes.scope && state) {
    state.scope = changes.scope.newValue;
    if (!typing()) render();
  }
});

chrome.tabs.onActivated.addListener(async () => { await detectTab(); render(); });
chrome.tabs.onUpdated.addListener(async (id, info) => {
  if (info.status === 'complete' || info.url) { await detectTab(); if (!typing()) render(); }
});

setInterval(() => { if (!typing() && (site()?.snapshot || state?.timeout)) render(); }, 15_000);

(async () => {
  const saved = (await chrome.storage.local.get('ui')).ui;
  if (saved) ui = { ...ui, ...saved };
  const res = await chrome.runtime.sendMessage({ type: 'getState' });
  state = res?.state || { sites: {}, scope: [...DEFAULT_SCOPE], mode: 'auto' };
  await detectTab();
  render();
  if (tab.url && hostInScope(hostOf(tab.url), scope())) send('seedPage', { url: tab.url });
})();
