// Session Afterlife service worker.
//
// Every site in scope (localhost and 127.0.0.1 by default, more can be added
// in the panel) is watched on its own. In automatic mode the worker records
// the session when the user signs in, recognises a logout or a password
// change, and replays the old session to see whether the server still accepts
// it. Manual mode leaves each step to the user.
//
// Replays leave the browser's own cookies out (credentials: 'omit') and set
// the old Cookie header through a temporary declarativeNetRequest rule that
// only matches the extension's own requests. Only GET and HEAD are replayed.
// Secrets stay in chrome.storage.session (memory only).

import { classify, baselineQuality, compareCookieJars } from './lib/compare.js';
import { classifyStorage, storageResidue } from './lib/storage.js';
import { analyseLifetimes } from './lib/lifetime.js';
import * as T from './lib/timeout.js';
import { isLogoutRequest, isPasswordChange, isUnsafeUrl, rankCandidates, separationScore } from './lib/detect.js';
import { headline } from './lib/report.js';
import { DEFAULT_SCOPE, hostInScope } from './lib/scope.js';
import { fnv1a } from './lib/findings.js';
import { classifyTamper, mutatedCookieHeader } from './lib/tamper.js';

const MAX_BODY = 200_000;
const MAX_CAPTURED = 40;
const MAX_EVENTS = 200;
const MAX_ESSENTIAL_PROBES = 12;
const ALARM = 'afterlife-timeout';
const REQUEST_TIMEOUT_MS = 20_000;

const SKIP_HEADERS = new Set([
  'cookie', 'authorization', 'host', 'connection', 'content-length', 'origin', 'referer',
  'user-agent', 'accept-encoding', 'upgrade-insecure-requests', 'priority', 'dnt', 'te',
  'keep-alive', 'via', 'trailer', 'transfer-encoding', 'upgrade', 'expect', 'date',
  'cache-control', 'pragma', 'if-none-match', 'if-modified-since', 'if-match',
  'if-unmodified-since', 'if-range', 'range', 'purpose',
]);

function newSite(origin) {
  const u = new URL(origin);
  return {
    origin: u.origin,
    hostname: u.hostname,
    createdAt: Date.now(),
    captured: [],
    reference: null,
    marker: '',
    snapshot: null,
    baselines: null,
    quality: null,
    events: [],
    checks: [],
    phase: 'waiting-login', // waiting-login | armed | second-session | second-armed
    autoNote: '',
    secondSession: false,
    busy: null,
    cookieSeen: {}, // name -> { hash, at }: when the current value first appeared
    lastWriteAt: 0, // last POST/PUT/PATCH from a tab (normally the login)
  };
}

// ---------- state ----------

let cache = null; // { sites: { [origin]: site }, timeout, mode, scope }
let loading = null;
let scope = [...DEFAULT_SCOPE];
let mode = 'auto';

async function load() {
  if (cache) return cache;
  if (!loading) {
    loading = (async () => {
      const [{ state }, local] = await Promise.all([
        chrome.storage.session.get('state'),
        chrome.storage.local.get(['scope', 'mode']),
      ]);
      scope = Array.isArray(local.scope) ? local.scope : [...DEFAULT_SCOPE];
      mode = local.mode === 'manual' ? 'manual' : 'auto';
      cache = state && state.sites ? state : { sites: {}, timeout: null };
      cache.mode = mode;
      cache.scope = scope;
      return cache;
    })();
  }
  return loading;
}

let saveTimer = null;
async function save() {
  clearTimeout(saveTimer);
  saveTimer = null;
  await chrome.storage.session.set({ state: cache });
}
function saveSoon() {
  if (saveTimer) return;
  saveTimer = setTimeout(() => { save(); }, 250);
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  if (changes.scope) {
    scope = changes.scope.newValue || [...DEFAULT_SCOPE];
    if (cache) { cache.scope = scope; saveSoon(); }
    refreshAllIcons();
  }
  if (changes.mode) {
    mode = changes.mode.newValue === 'manual' ? 'manual' : 'auto';
    if (cache) cache.mode = mode;
  }
});

function getSite(origin, create = true) {
  if (!cache.sites[origin] && create) {
    const s = newSite(origin);
    cache.sites[origin] = s;
    seedCookies(s);
  }
  return cache.sites[origin] || null;
}

async function seedCookies(s) {
  const all = await chrome.cookies.getAll({ domain: s.hostname });
  const at = s.createdAt - 1;
  for (const c of all) if (!s.cookieSeen[c.name]) s.cookieSeen[c.name] = { hash: fnv1a(c.value), at };
  saveSoon();
}

// Replays run one at a time, so that the temporary Cookie rule applies to
// exactly one request chain.
let chain = Promise.resolve();
function serial(fn) {
  const run = chain.then(fn, fn);
  chain = run.catch(() => {});
  return run;
}

// ---------- helpers ----------

function originOf(url) {
  try {
    const u = new URL(url);
    return /^https?:$/.test(u.protocol) ? u.origin : null;
  } catch { return null; }
}

function inScopeUrl(url) {
  try { return hostInScope(new URL(url).hostname, scope); } catch { return false; }
}

function domainMatches(hostname, cookieDomain) {
  const d = cookieDomain.replace(/^\./, '');
  return hostname === d || hostname.endsWith(`.${d}`);
}

function reEscape(s) {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

function headerMap(list = []) {
  const out = {};
  for (const h of list) out[h.name.toLowerCase()] = h.value ?? '';
  return out;
}

function replayableHeaders(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (SKIP_HEADERS.has(k) || k.startsWith('sec-') || k.startsWith('proxy-')) continue;
    out[k] = v;
  }
  return out;
}

async function cookiesFor(url) {
  const list = await chrome.cookies.getAll({ url });
  list.sort((a, b) => b.path.length - a.path.length);
  return list;
}

const cookieHeaderOf = (list) => list.map((c) => `${c.name}=${c.value}`).join('; ');

// ---------- replay ----------

let ruleSeq = 1;

async function replay({ url, method, headers }, session) {
  return serial(async () => {
    const h = new Headers();
    for (const [k, v] of Object.entries(replayableHeaders(headers))) {
      try { h.set(k, v); } catch { /* not settable from fetch */ }
    }
    if (session?.authorization) h.set('Authorization', session.authorization);

    const target = originOf(url);
    let ruleId = null;
    if (session?.cookieHeader) {
      ruleId = 1000 + (ruleSeq++ % 100000);
      await chrome.declarativeNetRequest.updateSessionRules({
        removeRuleIds: [ruleId],
        addRules: [{
          id: ruleId,
          priority: 1,
          action: { type: 'modifyHeaders', requestHeaders: [{ header: 'cookie', operation: 'set', value: session.cookieHeader }] },
          condition: {
            regexFilter: `^${reEscape(target)}/`,
            tabIds: [chrome.tabs.TAB_ID_NONE],
            initiatorDomains: [chrome.runtime.id],
          },
        }],
      });
    }
    try {
      const res = await fetch(url, {
        method: method === 'HEAD' ? 'HEAD' : 'GET',
        headers: h,
        credentials: 'omit',
        redirect: 'follow',
        cache: 'no-store',
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
      const body = method === 'HEAD' ? '' : (await res.text()).slice(0, MAX_BODY);
      return {
        status: res.status,
        finalUrl: res.url,
        redirected: res.redirected,
        contentType: res.headers.get('content-type') || '',
        cacheControl: res.headers.get('cache-control') || '',
        body,
        at: Date.now(),
      };
    } catch (e) {
      return { error: String(e?.message || e), at: Date.now() };
    } finally {
      if (ruleId !== null) await chrome.declarativeNetRequest.updateSessionRules({ removeRuleIds: [ruleId] });
    }
  });
}

const sessionOf = (snap) => ({ cookieHeader: snap.cookieHeader, authorization: snap.authorization });
const baselineOf = (s) => ({ auth: s.baselines?.auth || [], anon: s.baselines?.anon, marker: s.marker || '' });

async function currentSession(ref) {
  const cookies = await cookiesFor(ref.url);
  const authorization = ref.headers?.authorization || '';
  const snapshot = { takenAt: Date.now(), cookies, cookieHeader: cookieHeaderOf(cookies), authorization };
  snapshot.lifetimes = analyseLifetimes(snapshot, snapshot.takenAt / 1000);
  return snapshot;
}

// Which cookies actually carry the session? Replay without each one.
async function findEssential(s) {
  const snap = s.snapshot;
  const list = snap.cookies;
  if (!s.quality?.usable || list.length === 0) return;
  if (list.length === 1) { snap.essential = [list[0].name]; return; }
  if (list.length > MAX_ESSENTIAL_PROBES) return;
  const essential = [];
  for (const c of list) {
    const without = cookieHeaderOf(list.filter((x) => x !== c));
    const probe = await replay(s.reference, { cookieHeader: without, authorization: snap.authorization });
    if (classify(probe, baselineOf(s)).verdict === 'INVALIDATED') essential.push(c.name);
  }
  snap.essential = essential;
}

// Record a session and its baselines. `prepared` reuses measurements made
// while choosing the reference in automatic mode.
async function recordSession(s, ref, session, prepared = null) {
  const auth1 = prepared?.auth || await replay(ref, sessionOf(session));
  const auth2 = await replay(ref, sessionOf(session));
  const anon = prepared?.anon || await replay(ref, null);
  s.reference = ref;
  s.snapshot = session;
  s.snapshot.loginWriteAt = s.lastWriteAt > s.createdAt ? s.lastWriteAt : 0;
  // When each recorded cookie got its value, frozen now: later cookie changes
  // (a logout, a new login) must not change what is reported for this session.
  s.snapshot.cookieSeen = Object.fromEntries(
    session.cookies.filter((c) => s.cookieSeen[c.name]).map((c) => [c.name, { ...s.cookieSeen[c.name] }]),
  );
  s.baselines = { auth: [auth1, auth2], anon };
  s.quality = baselineQuality(baselineOf(s));
  s.events = [];
  s.tamper = {};
  await findEssential(s);
  // Token-like entries in client storage while signed in, to compare after logout.
  const raw = await readClientStorage(s.origin);
  s.snapshot.storageTokens = raw ? classifyStorage(raw) : [];
  s.snapshot.storageRead = !!raw;
}

// ---------- client-side storage ----------

// Remember a tab per origin so storage can be read from the page later.
const lastTabForOrigin = new Map();

// Injected into the page (serialized): read localStorage, sessionStorage and
// the names of IndexedDB databases. Must be self-contained.
async function pageStorageReader() {
  const dump = (s) => {
    const o = {};
    try { for (let i = 0; i < s.length; i++) { const k = s.key(i); o[k] = s.getItem(k); } } catch (e) { /* blocked */ }
    return o;
  };
  let idb = [];
  try { if (indexedDB.databases) idb = (await indexedDB.databases()).map((d) => d.name).filter(Boolean); } catch (e) { /* unsupported */ }
  return { local: dump(window.localStorage), session: dump(window.sessionStorage), idb };
}

async function tabForOrigin(origin) {
  const remembered = lastTabForOrigin.get(origin);
  if (remembered != null) {
    try { const t = await chrome.tabs.get(remembered); if (t && originOf(t.url) === origin) return remembered; } catch { /* gone */ }
  }
  try {
    const tabs = await chrome.tabs.query({});
    const t = tabs.find((x) => originOf(x.url) === origin);
    return t ? t.id : null;
  } catch { return null; }
}

// Returns { local, session, idb } from a tab on the origin, or null.
async function readClientStorage(origin) {
  const tabId = await tabForOrigin(origin);
  if (tabId == null) return null;
  try {
    const [res] = await chrome.scripting.executeScript({ target: { tabId }, world: 'ISOLATED', func: pageStorageReader });
    return res?.result || null;
  } catch {
    return null; // tab navigated, blocked, or no host permission
  }
}

// ---------- capture ----------

chrome.webRequest.onBeforeSendHeaders.addListener(
  (details) => { onRequest(details); },
  { urls: ['<all_urls>'] },
  ['requestHeaders', 'extraHeaders'],
);

async function onRequest(d) {
  if (d.tabId === chrome.tabs.TAB_ID_NONE) return;
  const origin = originOf(d.url);
  if (!origin) return;
  await load();
  if (!inScopeUrl(d.url)) return;
  const s = getSite(origin);
  if (d.tabId >= 0 && (d.type === 'main_frame' || !lastTabForOrigin.has(origin))) lastTabForOrigin.set(origin, d.tabId);

  if (['POST', 'PUT', 'PATCH'].includes(d.method)) s.lastWriteAt = Date.now();

  const t = cache.timeout;
  if (t && !t.done && t.origin === origin && t.mode === 'idle' && !t.disturbed) {
    t.disturbed = { at: Date.now(), url: d.url };
    saveSoon();
  }

  if (mode === 'auto' && !timeoutRunningFor(origin)) watchForEvents(s, d);

  if (d.method !== 'GET' && d.method !== 'HEAD') { saveSoon(); return; }
  if (!['main_frame', 'sub_frame', 'xmlhttprequest', 'other'].includes(d.type)) return;
  const headers = headerMap(d.requestHeaders);
  const entry = {
    id: `${d.requestId}-${d.timeStamp}`,
    url: d.url,
    method: d.method,
    type: d.type,
    at: Date.now(),
    hasCookie: !!headers.cookie,
    hasAuth: !!headers.authorization,
    headers: Object.fromEntries(Object.entries(headers).filter(([k]) => k !== 'cookie')),
  };
  s.captured = s.captured.filter((c) => !(c.url === entry.url && c.method === entry.method));
  s.captured.unshift(entry);
  s.captured.length = Math.min(s.captured.length, MAX_CAPTURED);
  saveSoon();
  if (mode === 'auto' && (entry.hasCookie || entry.hasAuth)) scheduleAutoArm(origin);
}

chrome.cookies.onChanged.addListener(async (info) => {
  await load();
  for (const s of Object.values(cache.sites)) {
    if (!domainMatches(s.hostname, info.cookie.domain)) continue;
    const name = info.cookie.name;
    if (!info.removed) {
      const hash = fnv1a(info.cookie.value);
      if (s.cookieSeen[name]?.hash !== hash) s.cookieSeen[name] = { hash, at: Date.now() };
    }
    if (!s.snapshot) continue;
    s.events.push({ at: Date.now(), name, removed: info.removed, cause: info.cause });
    if (s.events.length > MAX_EVENTS) s.events.splice(0, s.events.length - MAX_EVENTS);
    if (mode === 'auto' && s.phase === 'armed' && info.removed && info.cause !== 'overwrite'
        && s.snapshot.cookies.some((c) => c.name === name && c.path === info.cookie.path)) {
      setTimeout(() => { cookieLogoutCheck(s.origin, info.cookie); }, 1500);
    }
  }
  saveSoon();
});

// ---------- actions (manual mode and shared) ----------

function siteFor(msg) {
  if (!msg.origin) throw new Error('No site selected.');
  const s = getSite(msg.origin, false);
  if (!s) throw new Error('Nothing has been seen on this site yet. Open a page of it first.');
  return s;
}

async function setMode(msg) {
  mode = msg.mode === 'manual' ? 'manual' : 'auto';
  cache.mode = mode;
  await chrome.storage.local.set({ mode });
  if (mode === 'auto') {
    for (const s of Object.values(cache.sites)) {
      s.phase = s.snapshot && s.quality?.usable ? 'armed' : 'waiting-login';
      s.secondSession = false;
      scheduleAutoArm(s.origin, 0);
    }
  }
  await save();
}

async function setReference(msg) {
  const s = siteFor(msg);
  if (msg.id) {
    const c = s.captured.find((x) => x.id === msg.id);
    if (!c) throw new Error('That request is no longer in the list.');
    s.reference = { url: c.url, method: c.method, headers: c.headers };
  } else if (msg.url) {
    const full = new URL(msg.url, s.origin).href;
    if (originOf(full) !== s.origin) throw new Error('The URL must be on the same site.');
    s.reference = { url: full, method: 'GET', headers: { accept: 'text/html,application/json;q=0.9,*/*;q=0.8' } };
  }
  if (s.reference && isUnsafeUrl(s.reference.url)) {
    const bad = s.reference.url;
    s.reference = null;
    await save();
    throw new Error(`${new URL(bad).pathname} looks like it changes something (logout, delete…), so it is never replayed. Pick a page that only shows data.`);
  }
  await save();
}

async function setMarker(msg) {
  const s = siteFor(msg);
  s.marker = String(msg.marker || '');
  if (s.baselines) s.quality = baselineQuality(baselineOf(s));
  await save();
}

async function takeSnapshot(msg) {
  const s = siteFor(msg);
  if (!s.reference) throw new Error('Pick a reference request first.');
  const session = await currentSession(s.reference);
  if (session.cookies.length === 0 && !session.authorization) {
    throw new Error('No cookies or Authorization header were found for this request. Sign in first.');
  }
  s.busy = 'Measuring baselines…';
  await save();
  try {
    await recordSession(s, s.reference, session);
    s.secondSession = false;
    if (mode === 'auto') s.phase = s.quality.usable ? 'armed' : 'waiting-login';
  } finally {
    s.busy = null;
    await save();
  }
}

async function startSecondSession(msg) {
  const s = siteFor(msg);
  if (!s.snapshot) throw new Error('No session has been recorded yet.');
  if (mode === 'auto') s.phase = 'second-session'; // before clearing, so it is not taken for a logout
  const all = await chrome.cookies.getAll({ domain: s.hostname });
  for (const c of all) {
    const host = c.domain.replace(/^\./, '');
    const proto = c.secure ? 'https:' : new URL(s.origin).protocol;
    await chrome.cookies.remove({ url: `${proto}//${host}${c.path}`, name: c.name, storeId: c.storeId });
  }
  s.secondSession = true;
  s.autoNote = '';
  await save();
  return { cleared: all.length };
}

async function check(msg) {
  const s = siteFor(msg);
  if (!s.snapshot) throw new Error('No session has been recorded yet.');
  s.busy = 'Replaying the old session…';
  await save();
  try {
    const probe = await replay(s.reference, sessionOf(s.snapshot));
    const { verdict, reasons, scores } = classify(probe, baselineOf(s));
    const after = await cookiesFor(s.reference.url);
    const result = {
      at: Date.now(),
      scenario: msg.scenario,
      verdict,
      reasons,
      scores,
      sinceSnapshotSec: Math.round((Date.now() - s.snapshot.takenAt) / 1000),
      cookieDiff: compareCookieJars(s.snapshot.cookies, after),
      auto: !!msg.auto,
    };
    // Client-storage residue: did session tokens survive in the page's storage?
    if (['logout', 'password', 'elsewhere'].includes(msg.scenario)) {
      const raw = await readClientStorage(s.origin);
      const now = raw ? classifyStorage(raw) : [];
      const before = s.snapshot.storageTokens || [];
      result.storage = { residue: storageResidue(before, now), hadBefore: before.length > 0, read: !!raw };
    }
    s.checks.push(result);
    refreshAllIcons();
    return result;
  } finally {
    s.busy = null;
    await save();
  }
}

// Replay the reference request with one recorded cookie changed, to see
// whether the server trusts the client-supplied value. Read-only.
async function tamperCheck(msg) {
  const s = siteFor(msg);
  if (!s.snapshot) throw new Error('No session has been recorded yet.');
  if (!s.quality?.usable) throw new Error('The recorded session cannot be told apart from an anonymous visit yet.');
  const name = msg.cookieName;
  if (!s.snapshot.cookies.some((c) => c.name === name)) throw new Error('That cookie is not in the recorded session.');
  const value = String(msg.value ?? '');
  s.busy = 'Replaying with the changed value…';
  await save();
  try {
    const session = {
      cookieHeader: mutatedCookieHeader(s.snapshot.cookies, name, value),
      authorization: s.snapshot.authorization,
    };
    const probe = await replay(s.reference, session);
    const { verdict, reasons, scores } = classifyTamper(probe, baselineOf(s));
    s.tamper = { ...(s.tamper || {}), [name]: { at: Date.now(), cookieName: name, verdict, reasons, scores } };
    return s.tamper[name];
  } finally {
    s.busy = null;
    await save();
  }
}

// ---------- automatic mode ----------
//
// waiting-login  no usable session yet; signed-in requests trigger autoArm
// armed          session recorded; a logout triggers a 'logout' check
// second-session the user asked to test a second login; cookies cleared
// second-armed   second login seen ('elsewhere' check done); a password
//                change triggers a 'password' check

const timeoutRunningFor = (origin) => !!(cache?.timeout && !cache.timeout.done && cache.timeout.origin === origin);
const failedCandidates = new Set();
const armTimers = new Map();
const arming = new Set();
const rearm = new Set(); // asked to arm again while an attempt was running
const pending = new Map(); // origin -> { scenario, requestId }

function scheduleAutoArm(origin, delay = 1200) {
  clearTimeout(armTimers.get(origin));
  armTimers.set(origin, setTimeout(() => { autoArm(origin); }, delay));
}

async function autoArm(origin) {
  await load();
  if (arming.has(origin)) { rearm.add(origin); return; }
  const s = getSite(origin, false);
  if (!s || mode !== 'auto' || s.busy || timeoutRunningFor(origin)) return;
  if (s.phase !== 'waiting-login' && s.phase !== 'second-session') return;
  arming.add(origin);
  try {
    const list = rankCandidates(s.captured);
    if (s.phase === 'second-session' && s.reference) {
      list.unshift({ url: s.reference.url, method: s.reference.method, headers: s.reference.headers, hasCookie: true });
    }
    let best = null;
    for (const c of list) {
      const ref = { url: c.url, method: c.method, headers: c.headers || {} };
      const session = await currentSession(ref);
      if (!session.cookieHeader && !session.authorization) continue;
      if (s.phase === 'second-session' && sameSession(session, s.snapshot)) continue;
      // A failed attempt is only remembered until the next form submission:
      // with session fixation, the same cookie value becomes signed in at login.
      const key = `${s.lastWriteAt}|${ref.url}|${session.cookieHeader}|${session.authorization}`;
      if (failedCandidates.has(key)) continue;
      const auth = await replay(ref, sessionOf(session));
      const anon = await replay(ref, null);
      const score = separationScore(auth, anon);
      if (score < 0) { failedCandidates.add(key); continue; }
      if (!best || score > best.score) best = { ref, session, auth, anon, score };
      if (score >= 2) break;
    }
    if (!best) {
      s.autoNote = s.captured.length ? 'No signed-in page seen yet.' : '';
      await save();
      return;
    }
    if (s.phase === 'second-session') {
      s.phase = 'second-armed';
      s.autoNote = '';
      await save();
      const r = await check({ origin, scenario: 'elsewhere', auto: true });
      notify(s, `New login elsewhere: ${headline(r)}`);
      return;
    }
    s.busy = 'Recording the session…';
    await save();
    try {
      await recordSession(s, best.ref, best.session, best);
      s.secondSession = false;
      s.phase = s.quality.usable ? 'armed' : 'waiting-login';
      s.autoNote = '';
    } finally {
      s.busy = null;
      await save();
    }
  } finally {
    arming.delete(origin);
    if (rearm.delete(origin)) scheduleAutoArm(origin, 300);
  }
}

function sameSession(a, b) {
  if (!a || !b) return false;
  return a.cookieHeader === b.cookieHeader && a.authorization === b.authorization;
}

// Requests that finished recently. After the worker has been asleep, a fast
// request (a logout on a local server, say) can finish before the state is
// loaded and the request is recognised, so its completion is remembered here.
const finished = new Map(); // requestId -> { ok, at }

function watchForEvents(s, d) {
  let scenario = null;
  if (s.phase === 'armed' && isLogoutRequest(d.url, d.method)) scenario = 'logout';
  else if (s.phase === 'second-armed' && isPasswordChange(d.url, d.method)) scenario = 'password';
  if (!scenario) return;
  pending.set(s.origin, { scenario, requestId: d.requestId });
  setTimeout(() => { firePending(s.origin, d.requestId); }, 10_000); // fallback
  const done = finished.get(d.requestId);
  if (done) requestDone(d.requestId, done.ok);
}

function pendingFor(requestId) {
  for (const [origin, p] of pending) if (p.requestId === requestId) return [origin, p];
  return [null, null];
}

function requestDone(requestId, ok) {
  const [origin, p] = pendingFor(requestId);
  if (!p) return;
  if (p.scenario === 'password' && !ok) { // a failed password change does not count
    pending.delete(origin);
    return;
  }
  setTimeout(() => { firePending(origin, requestId); }, 1200);
}

function remember(requestId, ok) {
  finished.set(requestId, { ok, at: Date.now() });
  if (finished.size > 200) finished.delete(finished.keys().next().value);
}

chrome.webRequest.onCompleted.addListener((d) => {
  if (d.tabId === chrome.tabs.TAB_ID_NONE) return;
  const ok = d.statusCode >= 200 && d.statusCode < 400;
  remember(d.requestId, ok);
  requestDone(d.requestId, ok);
}, { urls: ['<all_urls>'] });

chrome.webRequest.onErrorOccurred.addListener((d) => {
  if (d.tabId === chrome.tabs.TAB_ID_NONE) return;
  remember(d.requestId, false);
  const [, p] = pendingFor(d.requestId);
  if (p?.scenario === 'logout') requestDone(d.requestId, true); // the logout may still have happened
  else requestDone(d.requestId, false);
}, { urls: ['<all_urls>'] });

async function cookieLogoutCheck(origin, cookie) {
  await load();
  const s = getSite(origin, false);
  if (!s || s.phase !== 'armed' || pending.has(origin)) return;
  const still = await chrome.cookies.getAll({ name: cookie.name, domain: s.hostname });
  if (still.some((c) => c.path === cookie.path)) return; // replaced, not removed
  const requestId = `cookie-${Date.now()}`;
  pending.set(origin, { scenario: 'logout', requestId });
  firePending(origin, requestId);
}

async function firePending(origin, requestId) {
  const p = pending.get(origin);
  if (!p || p.requestId !== requestId) return;
  pending.delete(origin);
  await load();
  const s = getSite(origin, false);
  if (!s || mode !== 'auto') return;
  const ok = p.scenario === 'logout' ? s.phase === 'armed' : s.phase === 'second-armed';
  if (!ok) return;
  const r = await check({ origin, scenario: p.scenario, auto: true });
  notify(s, `${p.scenario === 'logout' ? 'Logout' : 'Password change'}: ${headline(r)}`);
  s.phase = 'waiting-login';
  s.secondSession = false;
  await save();
  scheduleAutoArm(origin, 1500);
}

// Fallback for logouts and password changes the heuristics do not recognise.
async function checkNow(msg) {
  const s = siteFor(msg);
  const scenario = s.phase === 'second-armed' ? 'password' : 'logout';
  const r = await check({ origin: s.origin, scenario, auto: false });
  if (mode === 'auto') {
    s.phase = 'waiting-login';
    s.secondSession = false;
    await save();
    scheduleAutoArm(s.origin, 500);
  }
  return r;
}

async function rerecord(msg) {
  const s = siteFor(msg);
  s.phase = 'waiting-login';
  s.snapshot = null;
  s.baselines = null;
  s.quality = null;
  s.secondSession = false;
  failedCandidates.clear();
  await save();
  scheduleAutoArm(s.origin, 0);
}

// ---------- timeout measurement ----------

async function unitMs() {
  const { debugTimeUnitMs } = await chrome.storage.local.get('debugTimeUnitMs');
  return Number(debugTimeUnitMs) > 0 ? Number(debugTimeUnitMs) : 60_000;
}

async function timeoutStart(msg) {
  const s = siteFor(msg);
  if (cache.timeout && !cache.timeout.done) throw new Error('Another timeout measurement is running.');
  if (!s.snapshot) throw new Error('No session has been recorded yet.');
  if (!s.quality?.usable) throw new Error('The recorded session cannot be told apart from an anonymous visit yet.');
  const unit = await unitMs();
  const probe = await replay(s.reference, sessionOf(s.snapshot));
  if (classify(probe, baselineOf(s)).verdict !== 'STILL_VALID') {
    throw new Error('The recorded session is not valid right now. Sign in again first.');
  }
  const plan = msg.mode === 'idle'
    ? T.startIdle({ maxUnits: msg.maxUnits || 480 })
    : T.startAbsolute({ intervalUnits: msg.intervalUnits || 5, maxUnits: msg.maxUnits || 1440 });
  cache.timeout = { ...plan, origin: s.origin, startedAt: Date.now(), unitMs: unit, disturbed: false, nextAt: null };
  scheduleNext(cache.timeout);
  await save();
}

function scheduleNext(t) {
  const delay = T.nextDelayUnits(t) * t.unitMs;
  t.nextAt = Date.now() + delay;
  chrome.alarms.create(ALARM, { when: Math.max(t.nextAt, Date.now() + 30_000) });
  if (delay < 30_000) setTimeout(() => { timeoutTick(); }, delay);
}

let ticking = false;
async function timeoutTick() {
  if (ticking) return;
  ticking = true;
  try {
    await load();
    const t = cache.timeout;
    if (!t || t.done) return;
    if (Date.now() < t.nextAt - 500) {
      chrome.alarms.create(ALARM, { when: Math.max(t.nextAt, Date.now() + 30_000) });
      return;
    }
    const s = getSite(t.origin, false);
    if (!s?.snapshot) { cache.timeout = null; await save(); return; }
    const waited = T.nextDelayUnits(t);
    const probe = await replay(s.reference, sessionOf(s.snapshot));
    const { verdict, reasons } = classify(probe, baselineOf(s));
    const next = { ...T.advance(t, verdict, waited), origin: t.origin, startedAt: t.startedAt, unitMs: t.unitMs, disturbed: t.disturbed, nextAt: null };
    cache.timeout = next;
    if (next.done) {
      const unitName = t.unitMs === 60_000 ? 'min' : `× ${t.unitMs / 1000}s`;
      const extra = next.disturbed ? [`A tab requested ${shortPath(next.disturbed.url)} during the measurement, which may have reset the idle timer.`] : [];
      s.checks.push({
        at: Date.now(),
        scenario: t.mode,
        verdict: next.result.kind === 'expired' ? 'INVALIDATED' : next.result.kind === 'survived' ? 'STILL_VALID' : 'INCONCLUSIVE',
        reasons: [...extra, ...reasons],
        timeout: next,
        unitName,
        sinceSnapshotSec: Math.round((Date.now() - s.snapshot.takenAt) / 1000),
      });
      chrome.alarms.clear(ALARM);
      notify(s, T.describeResult(next, unitName));
    } else {
      scheduleNext(next);
    }
    await save();
  } finally {
    ticking = false;
  }
}

function shortPath(url) {
  try { const u = new URL(url); return u.pathname + u.search; } catch { return url; }
}

async function timeoutStop() {
  if (cache.timeout && !cache.timeout.done) {
    cache.timeout = null;
    await chrome.alarms.clear(ALARM);
    await save();
  }
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM) timeoutTick();
});

// ---------- toolbar icon ----------

const ICON_ON = { 16: 'icons/16.png', 32: 'icons/32.png', 48: 'icons/48.png' };
const ICON_OFF = { 16: 'icons/off-16.png', 32: 'icons/off-32.png', 48: 'icons/off-48.png' };

async function refreshIcon(tabId, url) {
  try {
    await load();
    const origin = url ? originOf(url) : null;
    const on = !!origin && inScopeUrl(url);
    await chrome.action.setIcon({ tabId, path: on ? ICON_ON : ICON_OFF });
    const s = on ? cache.sites[origin] : null;
    const fails = s ? s.checks.filter((c) => c.verdict === 'STILL_VALID' && (c.scenario === 'logout' || c.scenario === 'password')).length : 0;
    await chrome.action.setBadgeText({ tabId, text: fails ? String(fails) : '' });
    if (fails) await chrome.action.setBadgeBackgroundColor({ tabId, color: '#b42318' });
    await chrome.action.setTitle({ tabId, title: on ? 'Session Afterlife: watching this site' : 'Session Afterlife: this site is not in scope' });
  } catch { /* tab closed */ }
}

async function refreshAllIcons() {
  const tabs = await chrome.tabs.query({});
  for (const t of tabs) refreshIcon(t.id, t.url);
}

chrome.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.url || info.status === 'complete') refreshIcon(tabId, tab.url);
});
chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  try { const tab = await chrome.tabs.get(tabId); refreshIcon(tabId, tab.url); } catch { /* gone */ }
});

function notify(s, message) {
  chrome.notifications.create({
    type: 'basic',
    iconUrl: 'icons/128.png',
    title: `Session Afterlife · ${s.hostname}`,
    message,
  });
}

// ---------- messaging ----------

const ACTIONS = {
  getState: async () => cache,
  setMode,
  setReference,
  setMarker,
  takeSnapshot,
  startSecondSession,
  check,
  checkNow,
  tamperCheck,
  clearTamper: async (msg) => { const s = siteFor(msg); delete (s.tamper || {})[msg.cookieName]; await save(); },
  rerecord,
  timeoutStart,
  timeoutStop,
  clearChecks: async (msg) => { const s = siteFor(msg); s.checks = []; await save(); refreshAllIcons(); },
  forgetSite: async (msg) => {
    delete cache.sites[msg.origin];
    pending.delete(msg.origin);
    if (cache.timeout?.origin === msg.origin) { cache.timeout = null; await chrome.alarms.clear(ALARM); }
    await save();
    refreshAllIcons();
  },
  reset: async () => {
    cache.sites = {};
    cache.timeout = null;
    pending.clear();
    failedCandidates.clear();
    await chrome.alarms.clear(ALARM);
    await save();
    refreshAllIcons();
  },
  // The page that is open when a site is added is a good first candidate.
  seedPage: async (msg) => {
    if (!msg.url || !inScopeUrl(msg.url)) return;
    const origin = originOf(msg.url);
    const s = getSite(origin);
    if (!s.captured.some((c) => c.url === msg.url)) {
      const cookies = await cookiesFor(msg.url);
      s.captured.unshift({
        id: `tab-${Date.now()}`, url: msg.url, method: 'GET', type: 'main_frame', at: Date.now(),
        hasCookie: cookies.length > 0, hasAuth: false, headers: { accept: 'text/html,*/*;q=0.8' },
      });
    }
    await save();
    if (mode === 'auto') scheduleAutoArm(origin, 0);
  },
};

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id || !msg || !ACTIONS[msg.type]) return false;
  load()
    .then(() => ACTIONS[msg.type](msg))
    .then(async (value) => {
      if (saveTimer) await save();
      sendResponse({ ok: true, value: value ?? null, state: cache });
    })
    .catch((e) => sendResponse({ ok: false, error: String(e?.message || e), state: cache }));
  return true;
});

function init() {
  chrome.sidePanel?.setPanelBehavior({ openPanelOnActionClick: true }).catch(() => {});
  refreshAllIcons();
}
chrome.runtime.onInstalled.addListener(init);
chrome.runtime.onStartup?.addListener(init);
