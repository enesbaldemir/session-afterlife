#!/usr/bin/env node
// Session Afterlife demo app: a small, dependency-free web app with switchable
// session-termination flaws, used to try the extension and to run its tests.
//
//   node demo/server.js [--port 8090] [--flaws logout,password,jwt]
//                       [--idle SECONDS] [--absolute SECONDS]
//
// Flaws (all off by default, which means the app behaves correctly):
//   logout         Logout deletes the cookie in the browser but keeps the
//                  session alive on the server.
//   logout-rotate  Logout replaces the cookie with a new value but keeps the
//                  old session alive on the server.
//   password       Changing the password does not end the user's other sessions
//                  or revoke tokens issued earlier.
//   jwt            API logout does not revoke the bearer token.
//   fixation       A session ID is issued before login and kept after it.
//   weak-cookie    The session cookie has no HttpOnly and no SameSite, and
//                  is kept for a year.
//   cache          Signed-in pages can be cached (no Cache-Control: no-store).
//   token-in-url   After login, the session ID is put in the URL.
//   trust-role     A client-side `role` cookie decides what the account page
//                  shows, so changing it to `admin` unlocks an admin section.
//   storage-logout The account page stores an access token in localStorage,
//                  and logout clears the cookie but leaves that token behind.
//
// Only run this on your own machine. It is deliberately insecure when flaws
// are enabled.

'use strict';

const http = require('node:http');
const crypto = require('node:crypto');

function parseArgs(argv) {
  const opts = { port: 8090, host: '127.0.0.1', flaws: new Set(), idle: 0, absolute: 0 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i];
    if (a === '--port') opts.port = Number(next());
    else if (a === '--host') opts.host = next();
    else if (a === '--flaws') next().split(',').filter(Boolean).forEach((f) => opts.flaws.add(f.trim()));
    else if (a === '--idle') opts.idle = Number(next());
    else if (a === '--absolute') opts.absolute = Number(next());
    else if (a === '--help' || a === '-h') {
      console.log(`usage: node demo/server.js [--port N] [--flaws ${KNOWN_FLAWS.join(',')}] [--idle S] [--absolute S]`);
      process.exit(0);
    }
  }
  return opts;
}

const KNOWN_FLAWS = ['logout', 'logout-rotate', 'password', 'jwt', 'fixation', 'weak-cookie', 'cache', 'token-in-url', 'trust-role', 'storage-logout'];
const COOKIE_MAX_AGE = 30 * 24 * 3600; // what the cookie claims: 30 days
const TOKEN_TTL = 3600;

function createApp(options = {}) {
  const opts = {
    flaws: new Set(options.flaws || []),
    idle: options.idle || 0,
    absolute: options.absolute || 0,
  };
  for (const f of opts.flaws) {
    if (!KNOWN_FLAWS.includes(f)) throw new Error(`unknown flaw: ${f}`);
  }
  const has = (f) => opts.flaws.has(f);

  const users = new Map([['alice', { password: 'wonderland', tokensValidAfter: 0 }]]);
  const sessions = new Map(); // sid -> { user, created, lastSeen }
  const revokedJti = new Set();
  const jwtKey = crypto.randomBytes(32);

  const now = () => Date.now();
  const rid = () => crypto.randomBytes(16).toString('hex');

  function parseCookies(req) {
    const out = {};
    for (const part of (req.headers.cookie || '').split(';')) {
      const i = part.indexOf('=');
      if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
    }
    return out;
  }

  function getSession(req) {
    const sid = parseCookies(req).sid;
    if (!sid) return null;
    const s = sessions.get(sid);
    if (!s || !s.user) return null; // anonymous (pre-login) sessions do not count
    const t = now();
    if (opts.idle > 0 && t - s.lastSeen > opts.idle * 1000) { sessions.delete(sid); return null; }
    if (opts.absolute > 0 && t - s.created > opts.absolute * 1000) { sessions.delete(sid); return null; }
    s.lastSeen = t;
    return { sid, ...s };
  }

  const sessionCookie = (sid) => (has('weak-cookie')
    ? `sid=${sid}; Path=/; Max-Age=${365 * 24 * 3600}`
    : `sid=${sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${COOKIE_MAX_AGE}`);
  const clearedCookie = 'sid=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0';

  // --- minimal HS256 JWT ---
  const b64u = (buf) => Buffer.from(buf).toString('base64url');
  function signJwt(payload) {
    const head = b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
    const body = b64u(JSON.stringify(payload));
    const sig = crypto.createHmac('sha256', jwtKey).update(`${head}.${body}`).digest('base64url');
    return `${head}.${body}.${sig}`;
  }
  function verifyJwt(token) {
    const parts = (token || '').split('.');
    if (parts.length !== 3) return null;
    const sig = crypto.createHmac('sha256', jwtKey).update(`${parts[0]}.${parts[1]}`).digest();
    const given = Buffer.from(parts[2], 'base64url');
    if (given.length !== sig.length || !crypto.timingSafeEqual(given, sig)) return null;
    let p;
    try { p = JSON.parse(Buffer.from(parts[1], 'base64url').toString()); } catch { return null; }
    const t = Math.floor(now() / 1000);
    if (typeof p.exp !== 'number' || p.exp < t) return null;
    if (revokedJti.has(p.jti)) return null;
    const u = users.get(p.sub);
    if (!u) return null;
    if (!has('password') && p.iat * 1000 < u.tokensValidAfter) return null;
    return p;
  }
  function bearer(req) {
    const m = /^Bearer\s+(.+)$/i.exec(req.headers.authorization || '');
    return m ? m[1] : null;
  }

  // --- helpers ---
  function readBody(req) {
    return new Promise((resolve, reject) => {
      let data = '';
      req.on('data', (c) => { data += c; if (data.length > 1e5) req.destroy(); });
      req.on('end', () => resolve(data));
      req.on('error', reject);
    });
  }
  async function form(req) {
    return Object.fromEntries(new URLSearchParams(await readBody(req)));
  }
  async function json(req) {
    try { return JSON.parse(await readBody(req) || '{}'); } catch { return {}; }
  }
  function send(res, status, body, headers = {}) {
    res.writeHead(status, { 'Cache-Control': 'no-store', ...headers });
    // (a 'Cache-Control' in headers overrides the default)
    res.end(body);
  }
  const sendJson = (res, status, obj, headers = {}) =>
    send(res, status, JSON.stringify(obj), { 'Content-Type': 'application/json', ...headers });
  const redirect = (res, location, headers = {}) => send(res, 302, '', { Location: location, ...headers });
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

  function page(title, body) {
    const flaws = [...opts.flaws];
    const mode = flaws.length ? `flaws: ${flaws.join(', ')}` : 'secure (no flaws)';
    const timeouts = `idle timeout: ${opts.idle ? `${opts.idle}s` : 'none'} · absolute timeout: ${opts.absolute ? `${opts.absolute}s` : 'none'}`;
    return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(title)} · Afterlife Demo</title>
<style>
  body{font:15px/1.5 system-ui,sans-serif;margin:0;background:#f6f5f2;color:#1d1d1b}
  header{background:#1d1d1b;color:#f6f5f2;padding:10px 24px;display:flex;gap:18px;align-items:center;flex-wrap:wrap}
  header b{margin-right:auto} header a{color:#f6f5f2}
  .mode{font-size:12px;background:#3a3a37;padding:2px 8px;border-radius:4px}
  main{max-width:640px;margin:32px auto;padding:0 24px}
  form{display:grid;gap:10px;max-width:320px} input,button{font:inherit;padding:8px}
  button{background:#1d1d1b;color:#fff;border:0;border-radius:4px;cursor:pointer}
  .card{background:#fff;border:1px solid #ddd9d0;border-radius:6px;padding:16px 20px;margin:16px 0}
  code{background:#eceae4;padding:1px 4px;border-radius:3px}
</style></head><body>
<header><b>Afterlife Demo</b><a href="/">Home</a><a href="/account">Account</a><a href="/spa">Token app</a>
<span class="mode">${esc(mode)}</span><span class="mode">${esc(timeouts)}</span></header>
<main>${body}</main></body></html>`;
  }
  const html = (res, status, title, body, headers = {}) =>
    send(res, status, page(title, body), { 'Content-Type': 'text/html; charset=utf-8', ...headers });

  function destroyUserSessions(user, exceptSid) {
    for (const [sid, s] of sessions) if (s.user === user && sid !== exceptSid) sessions.delete(sid);
  }

  async function handle(req, res) {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    const m = req.method;

    if (m === 'GET' && p === '/') {
      return html(res, 200, 'Home', `<h1>Session termination demo</h1>
<p>Sign in as <code>alice</code> / <code>wonderland</code>, then use the extension to check whether the old session really ends after you log out, change your password or wait.</p>
<div class="card"><a href="/login">Sign in</a> · <a href="/spa">Token-based app</a></div>`,
      { 'Set-Cookie': 'theme=light; Path=/; SameSite=Lax; Max-Age=31536000' });
    }

    if (m === 'GET' && p === '/login') {
      const note = url.searchParams.get('logged_out') ? '<p class="card">You have been logged out.</p>' : '';
      const extra = {};
      if (has('fixation') && !sessions.has(parseCookies(req).sid)) {
        // An anonymous session that will be upgraded at login.
        const sid = rid();
        sessions.set(sid, { user: null, created: now(), lastSeen: now() });
        extra['Set-Cookie'] = sessionCookie(sid);
      }
      return html(res, 200, 'Sign in', `<h1>Sign in</h1>${note}
<form method="post" action="/login">
<label>Username <input name="username" autocomplete="username" value="alice"></label>
<label>Password <input name="password" type="password" autocomplete="current-password"></label>
<button>Sign in</button></form>`, extra);
    }

    if (m === 'POST' && p === '/login') {
      const f = await form(req);
      const u = users.get(f.username);
      if (!u || u.password !== f.password) {
        return html(res, 401, 'Sign in', '<h1>Sign in failed</h1><p><a href="/login">Try again</a></p>');
      }
      const t = now();
      const existing = parseCookies(req).sid;
      const next = has('token-in-url') ? (sid) => `/account?sid=${sid}` : () => '/account';
      // A client-side role cookie, which the account page below trusts.
      const roleCookie = has('trust-role') ? ['role=user; Path=/; SameSite=Lax; Max-Age=' + COOKIE_MAX_AGE] : [];
      if (has('fixation') && sessions.has(existing)) {
        // Upgrade the pre-login session instead of issuing a new ID.
        Object.assign(sessions.get(existing), { user: f.username, created: t, lastSeen: t });
        return redirect(res, next(existing), roleCookie.length ? { 'Set-Cookie': roleCookie } : {});
      }
      const sid = rid();
      sessions.set(sid, { user: f.username, created: t, lastSeen: t });
      return redirect(res, next(sid), { 'Set-Cookie': [sessionCookie(sid), ...roleCookie] });
    }

    if (m === 'GET' && p === '/account') {
      const s = getSession(req);
      if (!s) return redirect(res, '/login?next=/account');
      const cache = has('cache') ? { 'Cache-Control': 'private, max-age=600' } : {};
      // The account page trusts a client-side role cookie instead of the server session.
      const isAdmin = has('trust-role') && parseCookies(req).role === 'admin';
      const adminSection = isAdmin
        ? '<div class="card"><h2>Administrator tools</h2><p id="admin">You can manage all users and delete accounts.</p></div>'
        : '';
      return html(res, 200, 'Account', `<h1>Account</h1>
<div class="card"><p>Signed in as <strong id="user">${esc(s.user)}</strong>.</p>
<p>Session started ${esc(new Date(s.created).toISOString())}.</p>
<p>Active sessions for this user: ${[...sessions.values()].filter((x) => x.user === s.user).length}</p></div>
${adminSection}<div class="card"><a href="/password">Change password</a></div>
<form method="post" action="/logout"><button id="logout">Log out</button></form>
${has('storage-logout') ? `<script>
  // Flaw: an access token is kept in localStorage and never cleared at logout.
  localStorage.setItem('access_token', ${JSON.stringify(signJwt({ sub: s.user, iat: Math.floor(now() / 1000), exp: Math.floor(now() / 1000) + TOKEN_TTL, jti: rid() }))});
  sessionStorage.setItem('csrf', ${JSON.stringify(rid())});
</script>` : ''}`, cache);
    }

    if (m === 'GET' && p === '/api/me') {
      const s = getSession(req);
      if (!s) return sendJson(res, 401, { error: 'not authenticated' });
      return sendJson(res, 200, { user: s.user, sessionStarted: new Date(s.created).toISOString() },
        has('cache') ? { 'Cache-Control': 'private, max-age=600' } : {});
    }

    if (m === 'POST' && p === '/logout') {
      const s = getSession(req);
      let cookie = clearedCookie;
      if (s) {
        if (has('logout-rotate')) cookie = sessionCookie(rid()); // new value, old session left alive
        else if (!has('logout')) sessions.delete(s.sid);
      }
      return redirect(res, '/login?logged_out=1', { 'Set-Cookie': cookie });
    }

    if (m === 'GET' && p === '/password') {
      const s = getSession(req);
      if (!s) return redirect(res, '/login?next=/password');
      return html(res, 200, 'Change password', `<h1>Change password</h1>
<form method="post" action="/password">
<label>Current password <input name="current" type="password" autocomplete="current-password"></label>
<label>New password <input name="next" type="password" autocomplete="new-password"></label>
<button>Change password</button></form>`);
    }

    if (m === 'POST' && p === '/password') {
      const s = getSession(req);
      if (!s) return redirect(res, '/login?next=/password');
      const f = await form(req);
      const u = users.get(s.user);
      if (u.password !== f.current || !f.next) {
        return html(res, 400, 'Change password', '<h1>Password not changed</h1><p><a href="/password">Try again</a></p>');
      }
      u.password = f.next;
      if (!has('password')) {
        destroyUserSessions(s.user, s.sid);
        u.tokensValidAfter = Math.floor(now() / 1000) * 1000; // second precision, like iat
      }
      return html(res, 200, 'Change password', `<h1>Password changed</h1>
<p>${has('password') ? 'Your other sessions are still signed in.' : 'All your other sessions have been signed out.'}</p>
<p><a href="/account">Back to account</a></p>`);
    }

    // --- token-based API ---
    if (m === 'POST' && p === '/api/token') {
      const b = await json(req);
      const u = users.get(b.username);
      if (!u || u.password !== b.password) return sendJson(res, 401, { error: 'invalid credentials' });
      const iat = Math.floor(now() / 1000);
      const token = signJwt({ sub: b.username, iat, exp: iat + TOKEN_TTL, jti: rid() });
      return sendJson(res, 200, { token });
    }

    if (m === 'GET' && p === '/api/profile') {
      const claims = verifyJwt(bearer(req));
      if (!claims) return sendJson(res, 401, { error: 'invalid token' });
      return sendJson(res, 200, { user: claims.sub, tokenExpires: new Date(claims.exp * 1000).toISOString() });
    }

    if (m === 'POST' && p === '/api/logout') {
      const claims = verifyJwt(bearer(req));
      if (claims && !has('jwt')) revokedJti.add(claims.jti);
      return sendJson(res, 200, { ok: true });
    }

    if (m === 'GET' && p === '/spa') {
      return html(res, 200, 'Token app', `<h1>Token-based app</h1>
<p>This page keeps a bearer token in <code>localStorage</code> and sends it in the <code>Authorization</code> header.</p>
<div class="card" id="out">Loading…</div>
<form id="login" hidden><label>Username <input name="username" value="alice"></label>
<label>Password <input name="password" type="password"></label><button>Get token</button></form>
<button id="refresh" hidden>Reload profile</button> <button id="logout" hidden>Log out</button>
<script>
const out = document.getElementById('out');
const show = (id, on) => { document.getElementById(id).hidden = !on; };
async function profile() {
  const token = localStorage.getItem('token');
  if (!token) { out.textContent = 'Not signed in.'; show('login', true); show('logout', false); show('refresh', false); return; }
  const r = await fetch('/api/profile', { headers: { Authorization: 'Bearer ' + token } });
  const j = await r.json();
  out.textContent = r.ok ? 'Signed in as ' + j.user + ' (token expires ' + j.tokenExpires + ')' : 'Token rejected.';
  show('login', !r.ok); show('logout', r.ok); show('refresh', r.ok);
}
document.getElementById('login').onsubmit = async (e) => {
  e.preventDefault();
  const f = Object.fromEntries(new FormData(e.target));
  const r = await fetch('/api/token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(f) });
  if (r.ok) localStorage.setItem('token', (await r.json()).token);
  profile();
};
document.getElementById('refresh').onclick = profile;
document.getElementById('logout').onclick = async () => {
  await fetch('/api/logout', { method: 'POST', headers: { Authorization: 'Bearer ' + localStorage.getItem('token') } });
  localStorage.removeItem('token');
  profile();
};
profile();
</script>`);
    }

    return html(res, 404, 'Not found', '<h1>Not found</h1>');
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      console.error(err);
      if (!res.headersSent) send(res, 500, 'internal error');
    });
  });
  server.state = { sessions, users, opts };
  return server;
}

module.exports = { createApp, KNOWN_FLAWS };

if (require.main === module) {
  const opts = parseArgs(process.argv.slice(2));
  const server = createApp(opts);
  server.listen(opts.port, opts.host, () => {
    const flaws = [...opts.flaws];
    console.log(`Afterlife demo on http://${opts.host}:${opts.port}  (${flaws.length ? 'flaws: ' + flaws.join(', ') : 'secure'})`);
    console.log('Sign in as alice / wonderland. This app is for local testing only.');
  });
}
