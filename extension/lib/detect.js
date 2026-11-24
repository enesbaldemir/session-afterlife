// Heuristics for automatic mode: which requests are safe to replay, which
// ones show that the user is signed in, and which ones are a logout or a
// password change. Pure functions.

import { similarity, pathOf, baselineQuality } from './compare.js';

const LOGOUT_RE = /(^|[/_.-])(log[-_]?out|sign[-_]?out|log[-_]?off|sign[-_]?off|end[-_]?session)([/_.?-]|$)|\/sessions?\/(destroy|end|delete|revoke)|\/revoke([/?]|$)/i;
const PASSWORD_RE = /(^|[/_.-])(change[-_]?)?pass(word|wd)?([/_.?-]|$)|(^|[/_.-])credentials?([/_.?-]|$)/i;
// Words in a URL that suggest a GET request changes state. Such requests are
// never replayed, even though only GET and HEAD are replayed at all.
const UNSAFE_RE = /(^|[/_.=?&-])(delete|remove|destroy|unsubscribe|confirm|verify|activate|deactivate|approve|reject|cancel|disable|enable|toggle|reset|revoke|logout|signout|log-out|sign-out|logoff|transfer|pay|purchase|checkout)([/_.=?&-]|$)/i;
const STATIC_RE = /\.(m?js|css|png|jpe?g|gif|svg|ico|webp|avif|bmp|woff2?|ttf|otf|eot|map|mp4|webm|mp3|wav|ogg|pdf|zip|gz|txt|xml|webmanifest)$/i;
const IDENTITY_RE = /(^|\/)(me|whoami|account|accounts|profile|user|users|session|dashboard|settings|home|inbox)([/?.]|$)/i;

function urlParts(url) {
  try {
    const u = new URL(url);
    return { path: u.pathname, full: u.pathname + u.search };
  } catch {
    return { path: '', full: '' };
  }
}

export function isLogoutRequest(url, method = 'GET') {
  const { path } = urlParts(url);
  if (LOGOUT_RE.test(path)) return true;
  // DELETE /api/session, DELETE /auth/token and similar
  return method === 'DELETE' && /(^|\/)(session|sessions|auth|token|tokens|login)(\/|$)/i.test(path);
}

export function isPasswordChange(url, method = 'POST') {
  if (!['POST', 'PUT', 'PATCH'].includes(method)) return false;
  return PASSWORD_RE.test(urlParts(url).path);
}

// URLs that look like they change state. They are never replayed, in either mode.
export function isUnsafeUrl(url) {
  const { full } = urlParts(url);
  return UNSAFE_RE.test(full) || isLogoutRequest(url, 'GET');
}

// A captured request that may be replayed to tell a live session from a dead one.
export function isCandidate(entry) {
  if (entry.method !== 'GET' && entry.method !== 'HEAD') return false;
  if (!entry.hasCookie && !entry.hasAuth) return false;
  if (!['main_frame', 'xmlhttprequest', 'other'].includes(entry.type)) return false;
  const { path, full } = urlParts(entry.url);
  if (!path || STATIC_RE.test(path)) return false;
  if (UNSAFE_RE.test(full) || isLogoutRequest(entry.url, 'GET')) return false;
  return true;
}

// Order candidates: identity-looking endpoints and API calls first, then the
// most recent pages.
export function rankCandidates(captured, limit = 6) {
  const seen = new Set();
  const list = [];
  for (const c of captured) {
    if (!isCandidate(c)) continue;
    const key = pathOf(c.url);
    if (seen.has(key)) continue;
    seen.add(key);
    let score = 0;
    if (IDENTITY_RE.test(urlParts(c.url).path)) score += 2;
    if (c.type === 'xmlhttprequest') score += 1;
    if (/json/i.test(c.headers?.accept || '')) score += 0.5;
    if (c.hasAuth) score += 0.5;
    list.push({ c, score, at: c.at || 0 });
  }
  list.sort((a, b) => b.score - a.score || b.at - a.at);
  return list.slice(0, limit).map((x) => x.c);
}

// How clearly does this request separate a signed-in response from an
// anonymous one? Negative means it cannot.
export function separationScore(auth, anon) {
  const q = baselineQuality({ auth: [auth], anon });
  if (!q.usable) return -1;
  let s = 1 - similarity(auth, anon);
  if (auth.status !== anon.status) s += 1;
  if (pathOf(auth.finalUrl) !== pathOf(anon.finalUrl)) s += 1;
  if (auth.status >= 200 && auth.status < 300) s += 0.25;
  if (/json/i.test(auth.contentType)) s += 0.25;
  return s;
}
