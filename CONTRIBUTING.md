# Contributing

Thanks for helping. Bug reports, ideas and pull requests are all welcome.

## Reporting a bug

Open an issue with:

- your Chrome version and operating system;
- what you did, what you expected and what happened;
- the result card's **Details** and, if you can, the exported report. Reports never contain cookie values or tokens, but check before you paste.

If the app you were testing is public, say which kind of login it uses (form, OAuth, SAML, token API) rather than naming it.

## Suggesting a check

New checks are most useful when they map to a test in the [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/) and can run without changing data on the server. Describe the test, how the extension could recognise it, and how the demo app could show the flaw.

## Development

```sh
node demo/server.js --flaws logout     # demo app on http://127.0.0.1:8090
npm test                               # unit tests
npm install --no-save playwright && npx playwright install chromium
npm run test:e2e                       # end-to-end tests with the extension loaded
```

- The extension has no build step and no runtime dependencies. Keep it that way.
- Logic that does not need browser APIs goes in `extension/lib/` with unit tests in `test/unit/`.
- Every new check or flaw gets a flaw in `demo/server.js` and an end-to-end test.
- Replays (including the tamper check) must stay read-only: `GET` and `HEAD` only, and nothing that matches the unsafe URL rules in `extension/lib/detect.js`.

## Pull requests

Keep them focused, describe what changed and why, and make sure `npm test` and `npm run test:e2e` pass. Commits should be signed off (`git commit -s`).
