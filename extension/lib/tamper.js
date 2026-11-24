// Tamper check: replay the reference request with one cookie value changed,
// and report whether the server treated the client-supplied value as trusted.
// Pure functions; the replay itself happens in the service worker.
//
// This answers "does the server trust what the client sends in this cookie?"
// for one authorized test target. It never changes the browser's own session
// and only ever replays GET/HEAD.

import { similarity, pathOf, baselineQuality } from './compare.js';

export const TAMPER = Object.freeze({
  REJECTED: 'REJECTED', // the tampered value is no longer accepted (server validates it)
  IGNORED: 'IGNORED', // same response as before (server does not use the value here)
  CHANGED: 'CHANGED', // still authenticated but a different response (server trusted the value)
  INCONCLUSIVE: 'INCONCLUSIVE',
});

const round = (x) => Math.round(x * 100) / 100;

// probe: response to the reference request replayed with the mutated cookie.
// baseline: { auth: [resp, resp?], anon: resp, marker? }
export function classifyTamper(probe, baseline) {
  const { auth = [], anon } = baseline;
  const a1 = auth[0];
  if (!probe || probe.error) {
    return { verdict: TAMPER.INCONCLUSIVE, reasons: [`The replay failed: ${probe?.error || 'no response'}.`], scores: {} };
  }
  const quality = baselineQuality(baseline);
  if (!quality.usable) {
    return { verdict: TAMPER.INCONCLUSIVE, reasons: [quality.reason], scores: {} };
  }

  const sAuth = similarity(probe, a1);
  const sAnon = similarity(probe, anon);
  const statusLikeAuth = probe.status === a1.status;
  const urlLikeAuth = pathOf(probe.finalUrl) === pathOf(a1.finalUrl);
  const urlLikeAnon = pathOf(probe.finalUrl) === pathOf(anon.finalUrl);
  const scores = { similarityToOriginal: round(sAuth), similarityToAnonymous: round(sAnon), status: probe.status };
  const reasons = [`Status ${probe.status} (original signed-in: ${a1.status}).`];
  if (pathOf(probe.finalUrl) !== pathOf(a1.finalUrl)) reasons.push(`Ended at ${pathOf(probe.finalUrl)}.`);
  reasons.push(`Similarity: ${round(sAuth)} to the original response, ${round(sAnon)} to the anonymous one.`);

  // The changed value dropped the request to an unauthenticated response.
  const looksAnon = (sAnon > sAuth && sAnon >= 0.7) || ((probe.status === 401 || probe.status === 403) && !statusLikeAuth) || (urlLikeAnon && !urlLikeAuth);
  if (looksAnon) {
    reasons.push('The server no longer treats the request as signed in, so it validates this value.');
    return { verdict: TAMPER.REJECTED, reasons, scores };
  }
  // Same authenticated response as before.
  if (statusLikeAuth && urlLikeAuth && sAuth >= 0.95) {
    reasons.push('The response is unchanged, so the server did not use the new value for this request.');
    return { verdict: TAMPER.IGNORED, reasons, scores };
  }
  // Still authenticated, but a different response: the client value was trusted.
  if (sAuth >= sAnon) {
    reasons.push('The server produced a different signed-in response. Review whether it granted more than it should.');
    return { verdict: TAMPER.CHANGED, reasons, scores };
  }
  reasons.push('The response matches neither the original nor an anonymous visit clearly.');
  return { verdict: TAMPER.INCONCLUSIVE, reasons, scores };
}

// Build the Cookie header for a snapshot with one cookie's value replaced.
export function mutatedCookieHeader(cookies, name, value) {
  return cookies.map((c) => `${c.name}=${c.name === name ? value : c.value}`).join('; ');
}
