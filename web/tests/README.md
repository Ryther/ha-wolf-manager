# Browser contract tests

Run `npm run test:ui` from the repository root after installing the locked
Node development dependencies and `npx playwright install chromium`.

These tests exercise the real embedded HTML, CSS and JavaScript in Chromium.
The `wolf.test` routes are isolated, simulated canonical API responses; the
Steam cover response is also a local fixture. No Home Assistant, MQTT, SSH,
Wolf runtime or household state is contacted. This is frontend contract
integration evidence, not actual Supervisor/PC streaming validation.

The tests observe browser requests and rendered behavior: deployment prefix,
origin-bound CSRF, challenge login/bootstrap, password revocation UI, explicit
host fingerprint enrollment, two-PC catalog identity, unsupported capabilities,
desired versus staged/running revision, service admission versus observation,
uncertain reconciliation, bounded logs, error recovery and keyboard/mobile
layout. Credentials are test-only strings and never enter local storage.

Ignored `_tmp/ui-evidence/` can hold RED/GREEN logs and screenshots. Test outputs
and browser installation caches are development artifacts, not runtime assets.
The production manager embeds only `index.html`, `app.js` and `styles.css`;
production needs no Node runtime, Playwright or fixture server.
