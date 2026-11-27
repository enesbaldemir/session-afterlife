# Store listing

Copy-paste content for the Firefox Add-ons (AMO) and Chrome Web Store listings.

## Name

Session Afterlife

## Summary (≤250 characters)

Checks whether an old session ends after logout, password change or timeout, and audits session cookies and tokens. Replays the old session read-only and reports what the server still accepts. Mapped to OWASP WSTG. For authorized testing only.

## Category

Privacy & Security

## Description

When you click "Log out", most apps delete the cookie in your browser — but that proves nothing. If the server never invalidated the session, anyone who copied the cookie earlier can keep using the account. The same goes for "change your password to sign everyone out" and for sessions that never time out.

Session Afterlife records your session while you use an app, then automatically replays it after you log out or change your password to check whether the server still accepts it. It reports both sides:

Browser: cookie deleted — Server: old session still valid

What it checks:

- Logout actually ends the session (WSTG-SESS-06)
- Password change ends other sessions (WSTG-ATHN-08)
- Idle and absolute session timeout (WSTG-SESS-07)
- Session cookie attributes: HttpOnly, Secure, SameSite, Domain, lifetime (WSTG-SESS-02)
- Session fixation — whether the session ID is renewed at login (WSTG-SESS-03)
- Session tokens in URLs (WSTG-SESS-04)
- Caching of signed-in pages (WSTG-ATHN-06)
- JWT weaknesses: alg none, missing/long expiry, readable sensitive claims (WSTG-SESS-10)
- Tokens left in localStorage, sessionStorage or IndexedDB after logout (WSTG-CLNT-12)
- Tamper check: replay the reference request with one cookie value changed to see whether the server trusts a client-supplied value

How it works and privacy:

- Only sites you add to the scope list are watched. localhost and 127.0.0.1 are in scope by default.
- Only GET and HEAD requests are replayed, and never URLs with words like "delete" or "logout". It never submits forms.
- Session values stay in the browser's memory (storage.session) and are cleared when the browser closes. Nothing is sent anywhere. There is no analytics and no remote code.

Open source (MIT): https://github.com/enesbaldemir/session-afterlife

Use it only on applications you own or are authorized to test.

## Support

- Homepage / source: https://github.com/enesbaldemir/session-afterlife
- Issues: https://github.com/enesbaldemir/session-afterlife/issues

## Privacy policy

Use the text of PRIVACY.md (https://github.com/enesbaldemir/session-afterlife/blob/main/PRIVACY.md).

## Notes to reviewer (permission justifications)

This is an open-source session-security testing tool for web pentesters, used only on sites the user owns or is authorized to test. No data ever leaves the browser (data_collection_permissions: none).

- cookies: read the session cookies for the site under test (including HttpOnly) to snapshot and audit them, and to detect whether logout removed them.
- webRequest: observe request headers on in-scope sites so the user can pick a reference request that shows they are signed in.
- webRequestBlocking (Firefox): fetch() cannot set the forbidden Cookie header, so the old session's Cookie header is injected into the extension's OWN replay request only. The request is identified by a unique nonce header; no other traffic is modified. (On Chrome this is done with declarativeNetRequest session rules instead.)
- scripting: after a logout, read the page's localStorage, sessionStorage and IndexedDB database names to detect session tokens left behind. Only key names are kept, never the values.
- storage: keep state in memory (storage.session) and a small amount of preferences in storage.local (the scope list and UI options).
- alarms: schedule the idle/absolute timeout probes, which run over minutes to hours.
- notifications: show the result of a check when the panel is not in view.
- activeTab + optional host permissions (http/https): the user grants access per site via the scope list; nothing is watched until they do. localhost and 127.0.0.1 are included by default.

Source and build: the submitted package is produced by `npm run build`, which copies the `extension/` folder and swaps in the Firefox manifest (sidebar instead of side panel, blocking webRequest instead of declarativeNetRequest). There is no minification or transpilation; the JavaScript in the package is the source. Full source, tests and build script are at the GitHub repository above.
