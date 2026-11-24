// What the browser and the tokens claim about session lifetime: cookie
// Expires/Max-Age and JWT exp/iat. Pure functions.

export function formatDuration(totalSeconds) {
  if (totalSeconds === null || totalSeconds === undefined || !Number.isFinite(totalSeconds)) return '—';
  const neg = totalSeconds < 0;
  let s = Math.round(Math.abs(totalSeconds));
  const d = Math.floor(s / 86400); s -= d * 86400;
  const h = Math.floor(s / 3600); s -= h * 3600;
  const m = Math.floor(s / 60); s -= m * 60;
  let out;
  if (d) out = `${d}d ${h}h`;
  else if (h) out = `${h}h ${m}m`;
  else if (m) out = `${m}m ${s}s`;
  else out = `${s}s`;
  return neg ? `-${out}` : out;
}

// chrome.cookies.Cookie -> lifetime summary
export function cookieLifetime(cookie, nowSec = Date.now() / 1000) {
  if (cookie.session || cookie.expirationDate === undefined) {
    return { kind: 'session', text: 'Until the browser is closed (no Expires or Max-Age)' };
  }
  const remaining = cookie.expirationDate - nowSec;
  return {
    kind: 'persistent',
    expires: new Date(cookie.expirationDate * 1000).toISOString(),
    remainingSec: remaining,
    text: remaining > 0 ? `${formatDuration(remaining)} left` : 'already expired',
  };
}

const JWT_RE = /^([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)$/;

function b64urlJson(part) {
  const pad = '='.repeat((4 - (part.length % 4)) % 4);
  const b64 = (part + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = typeof atob === 'function' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary');
  const bytes = Uint8Array.from(bin, (ch) => ch.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes));
}

// Decode (do not verify) a JWT. Returns null if the value is not one.
export function decodeJwt(value) {
  if (!value) return null;
  let v = String(value).trim();
  try { v = decodeURIComponent(v); } catch { /* keep as is */ }
  v = v.replace(/^Bearer\s+/i, '').replace(/^"|"$/g, '');
  const m = JWT_RE.exec(v);
  if (!m) return null;
  try {
    const header = b64urlJson(m[1]);
    const payload = b64urlJson(m[2]);
    if (typeof header !== 'object' || !header || !header.alg) return null;
    if (typeof payload !== 'object' || !payload) return null;
    return { header, payload };
  } catch {
    return null;
  }
}

export function tokenLifetime(payload, nowSec = Date.now() / 1000) {
  const out = {};
  if (typeof payload.iat === 'number') out.issuedAt = new Date(payload.iat * 1000).toISOString();
  if (typeof payload.exp === 'number') {
    out.expires = new Date(payload.exp * 1000).toISOString();
    out.remainingSec = payload.exp - nowSec;
    if (typeof payload.iat === 'number') out.ttlSec = payload.exp - payload.iat;
  }
  if (out.expires === undefined) out.text = 'No exp claim: the token never expires by itself';
  else if (out.remainingSec <= 0) out.text = 'already expired';
  else out.text = `${formatDuration(out.remainingSec)} left${out.ttlSec ? ` (lifetime ${formatDuration(out.ttlSec)})` : ''}`;
  return out;
}

// Summarise everything the snapshot holds: each cookie, and any JWT found in a
// cookie value or the Authorization header.
export function analyseLifetimes({ cookies = [], authorization = '' }, nowSec = Date.now() / 1000) {
  const items = [];
  for (const c of cookies) {
    const life = cookieLifetime(c, nowSec);
    const jwt = decodeJwt(c.value);
    items.push({
      source: 'cookie',
      name: c.name,
      httpOnly: !!c.httpOnly,
      secure: !!c.secure,
      sameSite: c.sameSite,
      lifetime: life,
      jwt: jwt ? { alg: jwt.header.alg, ...tokenLifetime(jwt.payload, nowSec) } : null,
    });
  }
  if (authorization) {
    const jwt = decodeJwt(authorization);
    items.push({
      source: 'header',
      name: 'Authorization',
      lifetime: null,
      jwt: jwt ? { alg: jwt.header.alg, ...tokenLifetime(jwt.payload, nowSec) } : null,
    });
  }
  return items;
}
