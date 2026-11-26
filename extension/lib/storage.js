// Client-side storage checks: after logout, does the app leave session
// tokens behind in localStorage, sessionStorage or IndexedDB? Pure functions;
// the actual read happens in the page via chrome.scripting.
//
// Only key names and a classification are kept, never the stored values.

import { decodeJwt } from './lifetime.js';

// Key names that suggest a credential or session token.
const TOKEN_KEY_RE = /(^|[._-])(access|refresh|id)[._-]?token|(^|[._-])(jwt|bearer|auth|authorization|session|sess|sid|credential|apikey|api[._-]?key|secret|accesstoken|refreshtoken|id_token)(s)?([._-]|$)/i;
// Storage keys that are plainly not sessions, to cut noise.
const BENIGN_KEY_RE = /(theme|lang|locale|consent|cookieconsent|gdpr|analytics|ab[._-]?test|feature[._-]?flag|cache|timestamp|lastseen|visited|onboarding|tour)/i;

function looksLikeToken(key, value) {
  if (decodeJwt(value)) return 'jwt';
  if (BENIGN_KEY_RE.test(key)) return null;
  if (TOKEN_KEY_RE.test(key)) return 'token-ish';
  // Long opaque value under a short/unknown key is a weak signal; require the
  // key not to be obviously benign and the value to look like a token.
  if (/^[A-Za-z0-9+/_-]{32,}={0,2}$/.test(String(value || '').trim()) && /(token|auth|sess|key|secret|id)/i.test(key)) return 'token-ish';
  return null;
}

// raw: { local: {k:v}, session: {k:v}, idb: [names] }
// Returns token-like entries as { area, key, kind } (no values).
export function classifyStorage(raw = {}) {
  const out = [];
  for (const area of ['local', 'session']) {
    const bag = raw[area] || {};
    for (const [key, value] of Object.entries(bag)) {
      const kind = looksLikeToken(key, value);
      if (kind) out.push({ area, key, kind });
    }
  }
  for (const name of raw.idb || []) {
    if (name && TOKEN_KEY_RE.test(name) && !BENIGN_KEY_RE.test(name)) {
      out.push({ area: 'indexeddb', key: name, kind: 'db' });
    }
  }
  return out;
}

const entryKey = (e) => `${e.area}|${e.key}`;

// Token-like entries that were present while signed in and are still present
// after logout.
export function storageResidue(before = [], after = []) {
  const wasThere = new Set(before.map(entryKey));
  return after.filter((e) => wasThere.has(entryKey(e)));
}

const AREA_LABEL = { local: 'localStorage', session: 'sessionStorage', indexeddb: 'IndexedDB' };
export const areaLabel = (a) => AREA_LABEL[a] || a;

// One-line summary for a result card.
export function storageSummary(residue = [], hadBefore = false) {
  if (!hadBefore) return 'no tokens were stored client-side';
  if (residue.length === 0) return 'client storage cleared ✓';
  const first = residue[0];
  const extra = residue.length > 1 ? ` (+${residue.length - 1} more)` : '';
  return `${first.kind === 'db' ? 'database' : 'token'} \`${first.key}\` still in ${areaLabel(first.area)}${extra} ✗`;
}
