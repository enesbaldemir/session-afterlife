// Response comparison and verdicts. Pure functions, no browser APIs, so they
// can be unit tested in Node.

export const VERDICT = Object.freeze({
  STILL_VALID: 'STILL_VALID',
  INVALIDATED: 'INVALIDATED',
  INCONCLUSIVE: 'INCONCLUSIVE',
});

// Turn a response body into comparable text: drop scripts, styles and tags,
// and mask numbers and long hex/base64 runs (timestamps, ids, CSRF tokens) so
// that two loads of the same page compare as equal.
export function normalizeBody(body = '', contentType = '') {
  let t = String(body);
  if (/html/i.test(contentType) || /^\s*</.test(t)) {
    t = t
      .replace(/<script[\s\S]*?<\/script>/gi, ' ')
      .replace(/<style[\s\S]*?<\/style>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&[a-z#0-9]+;/gi, ' ');
  }
  return t
    .toLowerCase()
    .replace(/[a-z0-9+/_-]{24,}={0,2}/g, ' tok ')
    .replace(/\d+/g, '0')
    .replace(/\s+/g, ' ')
    .trim();
}

export function shingles(text, n = 4) {
  const words = text.split(/[^\p{L}\p{N}]+/u).filter(Boolean);
  const out = new Set();
  if (words.length === 0) return out;
  if (words.length < n) {
    out.add(words.join(' '));
    return out;
  }
  for (let i = 0; i + n <= words.length; i++) out.add(words.slice(i, i + n).join(' '));
  return out;
}

export function jaccard(a, b) {
  if (a.size === 0 && b.size === 0) return 1;
  let inter = 0;
  for (const x of a) if (b.has(x)) inter++;
  return inter / (a.size + b.size - inter);
}

export function similarity(r1, r2) {
  if (!r1 || !r2) return 0;
  return jaccard(
    shingles(normalizeBody(r1.body, r1.contentType)),
    shingles(normalizeBody(r2.body, r2.contentType)),
  );
}

export function pathOf(url) {
  try {
    const u = new URL(url);
    return u.origin + u.pathname;
  } catch {
    return String(url || '');
  }
}

const round = (x) => Math.round(x * 100) / 100;

// Are the authenticated and anonymous baselines different enough that the
// reference request can tell a live session from a dead one?
export function baselineQuality({ auth, anon, marker }) {
  const a1 = auth?.[0];
  if (!a1 || a1.error) return { usable: false, reason: 'The authenticated baseline request failed.' };
  if (!anon || anon.error) return { usable: false, reason: 'The anonymous baseline request failed.' };
  if (marker) {
    if (!a1.body.includes(marker)) {
      return { usable: false, reason: `The marker "${marker}" does not appear in the authenticated response.` };
    }
    if (anon.body.includes(marker)) {
      return { usable: false, reason: `The marker "${marker}" also appears without a session, so it cannot tell them apart.` };
    }
    return { usable: true, reason: 'The marker appears only with the session.' };
  }
  const sim = similarity(a1, anon);
  const same = a1.status === anon.status && pathOf(a1.finalUrl) === pathOf(anon.finalUrl) && sim >= 0.9;
  if (same) {
    return {
      usable: false,
      reason: 'This request returns the same response with and without the session. Pick a page that needs you to be signed in.',
    };
  }
  const selfSim = auth[1] && !auth[1].error ? similarity(a1, auth[1]) : null;
  if (selfSim !== null && selfSim < 0.5) {
    return {
      usable: true,
      warning: `The page changes a lot between loads (self-similarity ${round(selfSim)}). Add a marker for a reliable verdict.`,
      reason: 'Authenticated and anonymous responses differ.',
    };
  }
  return { usable: true, reason: 'Authenticated and anonymous responses differ.' };
}

// Decide whether a replayed old session is still accepted.
//   probe     response to the replay with the old session
//   baseline  { auth: [resp, resp?], anon: resp, marker?: string }
export function classify(probe, baseline) {
  const reasons = [];
  const { auth = [], anon, marker } = baseline;
  const a1 = auth[0];

  if (!probe || probe.error) {
    return { verdict: VERDICT.INCONCLUSIVE, reasons: [`The replay request failed: ${probe?.error || 'no response'}.`], scores: {} };
  }
  const quality = baselineQuality(baseline);
  if (!quality.usable) {
    return { verdict: VERDICT.INCONCLUSIVE, reasons: [quality.reason], scores: {} };
  }

  const sAuth = similarity(probe, a1);
  const sAnon = similarity(probe, anon);
  const statusLikeAuth = probe.status === a1.status;
  const statusLikeAnon = probe.status === anon.status;
  const urlLikeAuth = pathOf(probe.finalUrl) === pathOf(a1.finalUrl);
  const urlLikeAnon = pathOf(probe.finalUrl) === pathOf(anon.finalUrl);
  const scores = { similarityToAuthenticated: round(sAuth), similarityToAnonymous: round(sAnon), status: probe.status };

  reasons.push(`Status ${probe.status} (signed in: ${a1.status}, anonymous: ${anon.status}).`);
  if (probe.redirected || !urlLikeAuth) reasons.push(`Ended at ${pathOf(probe.finalUrl)}.`);

  if (marker) {
    const found = probe.body.includes(marker);
    reasons.push(found ? `Marker "${marker}" found in the response.` : `Marker "${marker}" not found in the response.`);
    return { verdict: found ? VERDICT.STILL_VALID : VERDICT.INVALIDATED, reasons, scores };
  }

  reasons.push(`Body similarity: ${round(sAuth)} to the signed-in response, ${round(sAnon)} to the anonymous one.`);

  if ((probe.status === 401 || probe.status === 403) && !statusLikeAuth) {
    return { verdict: VERDICT.INVALIDATED, reasons, scores };
  }

  const selfSim = auth[1] && !auth[1].error ? similarity(a1, auth[1]) : null;
  const threshold = selfSim === null ? 0.7 : Math.max(0.5, Math.min(0.7, selfSim - 0.2));

  if (statusLikeAuth && urlLikeAuth && sAuth >= threshold && sAuth > sAnon) {
    return { verdict: VERDICT.STILL_VALID, reasons, scores };
  }

  const authScore = (statusLikeAuth ? 1 : 0) + (urlLikeAuth ? 1 : 0) + 2 * sAuth;
  const anonScore = (statusLikeAnon ? 1 : 0) + (urlLikeAnon ? 1 : 0) + 2 * sAnon;
  if (anonScore > authScore && (urlLikeAnon || statusLikeAnon) && sAnon >= sAuth) {
    return { verdict: VERDICT.INVALIDATED, reasons, scores };
  }

  reasons.push('The response matches neither baseline clearly. Add a marker (for example your username) and check again.');
  return { verdict: VERDICT.INCONCLUSIVE, reasons, scores };
}

// Browser side: what happened to each cookie that was sent with the reference
// request, comparing the snapshot with the cookie jar now.
export function cookieKey(c) {
  return `${c.name}|${c.domain}|${c.path}`;
}

export function compareCookieJars(before = [], after = []) {
  const now = new Map(after.map((c) => [cookieKey(c), c]));
  return before.map((c) => {
    const later = now.get(cookieKey(c));
    let status = 'unchanged';
    if (!later) status = 'deleted';
    else if (later.value !== c.value) status = 'changed';
    return { name: c.name, domain: c.domain, path: c.path, httpOnly: c.httpOnly, status };
  });
}
