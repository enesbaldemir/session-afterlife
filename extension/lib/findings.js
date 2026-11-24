// Passive checks on a recorded session. They use what the extension has
// already seen and send no requests. Pure functions.

import { decodeJwt, formatDuration } from './lifetime.js';

export const SEVERITY_ORDER = { high: 0, medium: 1, low: 2, info: 3 };

// Short, stable hash so that cookie values seen over time can be compared
// without storing them twice.
export function fnv1a(str) {
  let h = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

const SESSION_NAME_RE = /(sess|sid|auth|token|jwt|login|logged|remember|identity|connect\.sid|phpsessid|jsessionid|asp\.net)/i;

export function isLocalHost(host) {
  return host === 'localhost' || host === '127.0.0.1' || host.endsWith('.localhost') || host === '[::1]';
}

// Names of the cookies that carry the session: measured ones if the snapshot
// has them, otherwise a guess from names and flags.
export function sessionCookieNames(snapshot) {
  if (snapshot?.essential?.length) return snapshot.essential;
  const cookies = snapshot?.cookies || [];
  const guess = cookies.filter((c) => SESSION_NAME_RE.test(c.name) || (c.httpOnly && (c.value || '').length >= 16));
  return (guess.length ? guess : cookies.length === 1 ? cookies : []).map((c) => c.name);
}

const SENSITIVE_CLAIM_RE = /(pass(word)?|secret|ssn|credit|card|cvv|iban|pin)$/i;
const PERSONAL_CLAIM_RE = /^(email|e-mail|phone|mobile|address|birth(date|day)?|dob|tckn|national_?id)$/i;

function jwtFindings(label, value, nowSec, out) {
  const jwt = decodeJwt(value);
  if (!jwt) return;
  const { header, payload } = jwt;
  const alg = String(header.alg || '');
  if (alg.toLowerCase() === 'none') {
    out.push({ id: `jwt-none-${label}`, status: 'fail', severity: 'high', wstg: 'WSTG-SESS-10', title: `${label}: JWT is not signed (alg "none")`, detail: 'Anyone can change the claims. The server must reject unsigned tokens.' });
  }
  if (typeof payload.exp !== 'number') {
    out.push({ id: `jwt-exp-${label}`, status: 'fail', severity: 'medium', wstg: 'WSTG-SESS-10', title: `${label}: JWT has no expiry (exp)`, detail: 'Unless the server tracks it, a stolen token works forever.' });
  } else if (typeof payload.iat === 'number' && payload.exp - payload.iat > 86400) {
    out.push({ id: `jwt-ttl-${label}`, status: 'warn', severity: 'low', wstg: 'WSTG-SESS-10', title: `${label}: JWT is valid for ${formatDuration(payload.exp - payload.iat)}`, detail: 'Long-lived tokens give a stolen token a long life. Prefer short access tokens with refresh.' });
  } else {
    out.push({ id: `jwt-exp-${label}`, status: 'pass', severity: 'info', wstg: 'WSTG-SESS-10', title: `${label}: JWT expires (${typeof payload.iat === 'number' ? `lifetime ${formatDuration(payload.exp - payload.iat)}` : 'exp set'})` });
  }
  const keys = Object.keys(payload);
  const sensitive = keys.filter((k) => SENSITIVE_CLAIM_RE.test(k));
  const personal = keys.filter((k) => PERSONAL_CLAIM_RE.test(k));
  if (sensitive.length) {
    out.push({ id: `jwt-secret-${label}`, status: 'fail', severity: 'high', wstg: 'WSTG-SESS-10', title: `${label}: JWT payload contains ${sensitive.join(', ')}`, detail: 'A JWT payload is only encoded, not encrypted. Anyone holding the token can read it.' });
  } else if (personal.length) {
    out.push({ id: `jwt-pii-${label}`, status: 'warn', severity: 'info', wstg: 'WSTG-SESS-10', title: `${label}: JWT payload contains ${personal.join(', ')}`, detail: 'The payload is readable by anyone holding the token.' });
  }
}

// site: the per-site state kept by the background worker.
export function auditSession(site, { nowSec = Date.now() / 1000 } = {}) {
  const out = [];
  const snap = site?.snapshot;
  if (!snap) return out;
  let url;
  try { url = new URL(site.origin); } catch { return out; }
  const https = url.protocol === 'https:';
  const local = isLocalHost(url.hostname);
  const names = sessionCookieNames(snap);
  const cookies = snap.cookies.filter((c) => names.includes(c.name));

  for (const c of cookies) {
    const n = `\`${c.name}\``;
    if (!c.httpOnly) {
      out.push({ id: `httponly-${c.name}`, status: 'fail', severity: 'medium', wstg: 'WSTG-SESS-02', title: `${n} can be read by JavaScript (no HttpOnly)`, detail: 'Any XSS bug on the site can steal the session.' });
    } else {
      out.push({ id: `httponly-${c.name}`, status: 'pass', severity: 'info', wstg: 'WSTG-SESS-02', title: `${n} is HttpOnly` });
    }
    if (https && !c.secure) {
      out.push({ id: `secure-${c.name}`, status: 'fail', severity: 'high', wstg: 'WSTG-SESS-02', title: `${n} has no Secure flag`, detail: 'The browser will also send it over plain HTTP, where it can be intercepted.' });
    } else if (!https && !local) {
      out.push({ id: `secure-${c.name}`, status: 'fail', severity: 'high', wstg: 'WSTG-CRYP-03', title: `${n} is sent over plain HTTP`, detail: 'The site is not using HTTPS, so the session can be intercepted on the network.' });
    } else if (https) {
      out.push({ id: `secure-${c.name}`, status: 'pass', severity: 'info', wstg: 'WSTG-SESS-02', title: `${n} is Secure` });
    }
    if (c.sameSite === 'no_restriction') {
      out.push({ id: `samesite-${c.name}`, status: 'fail', severity: 'medium', wstg: 'WSTG-SESS-02', title: `${n} is SameSite=None`, detail: 'It is sent with cross-site requests, so CSRF defenses must not rely on SameSite.' });
    } else if (!c.sameSite || c.sameSite === 'unspecified') {
      out.push({ id: `samesite-${c.name}`, status: 'warn', severity: 'low', wstg: 'WSTG-SESS-02', title: `${n} has no SameSite attribute`, detail: 'Chrome treats it as Lax, but other browsers and older versions may send it cross-site.' });
    } else {
      out.push({ id: `samesite-${c.name}`, status: 'pass', severity: 'info', wstg: 'WSTG-SESS-02', title: `${n} is SameSite=${c.sameSite === 'strict' ? 'Strict' : 'Lax'}` });
    }
    if (c.hostOnly === false) {
      out.push({ id: `domain-${c.name}`, status: 'warn', severity: 'low', wstg: 'WSTG-SESS-02', title: `${n} is shared with subdomains (Domain=${c.domain.replace(/^\./, '')})`, detail: 'Any subdomain, including a compromised or user-controlled one, receives the session.' });
    }
    if (!c.session && typeof c.expirationDate === 'number' && c.expirationDate - nowSec > 30 * 86400) {
      out.push({ id: `persist-${c.name}`, status: 'warn', severity: 'low', wstg: 'WSTG-SESS-07', title: `${n} is kept for ${formatDuration(c.expirationDate - nowSec)}`, detail: 'A long-lived session cookie stays on shared computers. Check the server-side timeout in Timeout tests.' });
    }
    jwtFindings(n, c.value, nowSec, out);
  }
  if (snap.authorization) jwtFindings('Authorization', snap.authorization, nowSec, out);

  // Cache-Control on the signed-in response
  const auth = site.baselines?.auth?.[0];
  if (auth && !auth.error) {
    const cc = (auth.cacheControl || '').toLowerCase();
    if (/no-store/.test(cc)) {
      out.push({ id: 'cache', status: 'pass', severity: 'info', wstg: 'WSTG-ATHN-06', title: 'Signed-in response is not cached (no-store)' });
    } else {
      out.push({ id: 'cache', status: 'fail', severity: 'low', wstg: 'WSTG-ATHN-06', title: 'Signed-in response may be cached', detail: `Cache-Control is ${cc ? `"${cc}"` : 'missing'}. After logout, the back button or a shared computer may show the page. Use Cache-Control: no-store.` });
    }
  }

  // Session token in a URL
  const secrets = [];
  for (const c of cookies) if ((c.value || '').length >= 8) secrets.push({ label: c.name, value: c.value });
  const bearer = (snap.authorization || '').replace(/^Bearer\s+/i, '');
  if (bearer.length >= 8) secrets.push({ label: 'bearer token', value: bearer });
  const leaks = [];
  for (const e of site.captured || []) {
    let decoded = e.url;
    try { decoded = decodeURIComponent(e.url); } catch { /* keep */ }
    for (const s of secrets) {
      if (e.url.includes(s.value) || decoded.includes(s.value)) leaks.push({ label: s.label, path: safePath(e.url, s.value) });
    }
  }
  if (leaks.length) {
    const l = leaks[0];
    out.push({ id: 'url-token', status: 'fail', severity: 'high', wstg: 'WSTG-SESS-04', title: `The ${l.label === 'bearer token' ? 'bearer token' : `\`${l.label}\` value`} appears in a URL`, detail: `Seen in ${l.path}. URLs end up in history, logs and Referer headers.` });
  } else if (secrets.length) {
    out.push({ id: 'url-token', status: 'pass', severity: 'info', wstg: 'WSTG-SESS-04', title: 'Session token not seen in any URL' });
  }

  // Session fixation: was the session cookie's value already there before the
  // last form submission (normally the login)?
  const seen = snap.cookieSeen || site.cookieSeen || {};
  const loginAt = snap.loginWriteAt || 0;
  if (!loginAt && cookies.length) {
    out.push({ id: 'fixation', status: 'skip', severity: 'info', wstg: 'WSTG-SESS-03', title: 'Session fixation not checked', detail: 'The sign-in was not seen, because you were already signed in when watching started. Log out and sign in again to check it.' });
  }
  if (loginAt) {
    for (const c of cookies) {
      const rec = seen[c.name];
      if (!rec) continue;
      if (rec.hash === fnv1a(c.value || '') && rec.at < loginAt) {
        out.push({ id: `fixation-${c.name}`, status: 'fail', severity: 'high', wstg: 'WSTG-SESS-03', title: `\`${c.name}\` was not renewed at login`, detail: 'The value existed before signing in, so an attacker who planted it could share the signed-in session (session fixation).' });
      } else {
        out.push({ id: `fixation-${c.name}`, status: 'pass', severity: 'info', wstg: 'WSTG-SESS-03', title: `\`${c.name}\` got a new value at login` });
      }
    }
  }

  out.sort((a, b) => statusRank(a) - statusRank(b) || SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
  return out;
}

function statusRank(f) {
  return { fail: 0, warn: 1, pass: 2, skip: 3 }[f.status] ?? 2;
}

// Show where a secret appeared without showing the secret.
function safePath(url, secret) {
  try {
    const u = new URL(url);
    return (u.pathname + u.search).split(secret).join('•••').slice(0, 120);
  } catch {
    return '(url)';
  }
}
