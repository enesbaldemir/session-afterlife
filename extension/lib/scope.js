// Sites in scope. A pattern is a host name ("app.example.com"), an IP address,
// or a wildcard ("*.example.com", which also covers example.com itself).
// Ports and schemes are not part of a pattern.

export const DEFAULT_SCOPE = Object.freeze(['localhost', '127.0.0.1']);

// Single-label wildcards are allowed only for names reserved for testing.
const DEV_TLDS = new Set(['localhost', 'test', 'local', 'internal', 'example', 'invalid', 'lan', 'home.arpa']);

const LABEL = '[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?';
const HOST_RE = new RegExp(`^${LABEL}(\\.${LABEL})*$`);
const IPV4_RE = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;

// Accepts what people paste: a URL, a host with a port, a wildcard.
// Returns { pattern } or { error }.
export function normalizePattern(input) {
  let s = String(input || '').trim().toLowerCase();
  if (!s) return { error: 'Enter a site, for example app.example.com or *.example.com.' };
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, ''); // scheme
  s = s.replace(/[/?#].*$/, ''); // path
  s = s.replace(/^[^@]*@/, ''); // credentials
  if (s.startsWith('[')) return { error: 'IPv6 addresses are not supported yet.' };
  s = s.replace(/:\d+$/, ''); // port
  s = s.replace(/\.$/, '');
  const wild = s.startsWith('*.');
  const base = wild ? s.slice(2) : s;
  if (base.includes('*')) return { error: 'A wildcard can only be used at the start, as in *.example.com.' };
  if (IPV4_RE.test(base)) {
    if (wild) return { error: 'Wildcards cannot be used with IP addresses.' };
    return { pattern: base };
  }
  if (!HOST_RE.test(base)) return { error: `"${input}" is not a valid site name.` };
  if (wild && !base.includes('.') && !DEV_TLDS.has(base)) {
    return { error: `*.${base} would cover a whole top-level domain. Use a narrower pattern.` };
  }
  return { pattern: wild ? `*.${base}` : base };
}

export function hostMatches(host, pattern) {
  const h = String(host || '').toLowerCase();
  if (pattern.startsWith('*.')) {
    const base = pattern.slice(2);
    return h === base || h.endsWith(`.${base}`);
  }
  return h === pattern;
}

export function hostInScope(host, scope) {
  return (scope || []).some((p) => hostMatches(host, p));
}

// Chrome match patterns that grant access to a scope pattern.
export function patternToOrigins(pattern) {
  return [`*://${pattern}/*`];
}

// Patterns a user is likely to want for a host: the host itself, and its
// parent domain with a wildcard.
export function suggestPatterns(host) {
  const h = String(host || '').toLowerCase();
  const out = [h];
  if (!IPV4_RE.test(h)) {
    const parts = h.split('.');
    if (parts.length >= 3) out.push(`*.${parts.slice(1).join('.')}`);
    else if (parts.length === 2) out.push(`*.${h}`);
  }
  return out;
}
