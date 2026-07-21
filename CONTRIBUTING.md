# Contributing

Thanks for considering a contribution to unveily.

## Development

1. Clone the repository.
2. Run `npm ci`.
3. Run `npm test`.
4. Run `npm run check`.
5. Run `npm run package:extension && npm run test:package`.
6. Run `npm run test:e2e:chrome` with Chrome 140 or newer.
7. Load the project folder from `chrome://extensions` with Developer mode enabled for the remaining manual checks.

`npm run check` syntax-checks every `src/*.js` extension module and every `scripts/*.mjs` repository maintenance or CI script. Packaging uses an explicit runtime-file allowlist, fixed ZIP metadata, and checksum/content verification; `dist/` remains ignored and packaged artifacts must not be committed.

The registrable-domain resolver uses an offline generated copy of the official Public Suffix List. Run `npm run update:psl` only as an intentional data update, then review the version/commit recorded in `src/publicSuffixRules.js`, the generated diff, private-suffix behavior tests, and `THIRD_PARTY_NOTICES.md`.

The fast `npm test` suite runs in Node with Chrome API mocks. The separate `npm run test:e2e:chrome` command launches real Chrome 140+ with a clean temporary profile and controlled localhost fixtures for the opt-in companion-overlay baseline. Before a release, also complete and record [MANUAL_TESTING.md](MANUAL_TESTING.md), including permissions, passive-observation controls, navigation isolation, hostile-page overlay tampering, partitioned cookies, Manifest V3 restart/expiry behavior, saved-policy fetch alarms, browser-frame inspection, and export redaction that the focused E2E does not automate.

CI installs exactly `package-lock.json`, keeps the 80% line, 70% branch, and 80% function gate across directly unit-testable source modules, builds and verifies the allowlisted ZIP, and runs the Chrome E2E headlessly. The event-driven MV3 `background.js` entry point remains separate because runtime-mock suites import isolated worker instances. `npm run test:coverage:background` executes the navigation, startup, and cookie runtime suites serially, explicitly includes only `background.js`, and evaluates the combined coverage of its isolated instances. It requires at least 39% line, 38% branch, and 44% function coverage, and fails if the source row, aggregate row, or representative runtime evidence is missing.

This project is a Chrome Manifest V3 extension with no backend by default. Keep new features local-first unless there is a clear reason to introduce a remote service.

## Pull requests

- Keep changes focused and easy to review.
- Add or update tests for behavior changes.
- Avoid committing generated files, except the deliberately pinned and reviewed Public Suffix List artifact; never commit packaged extension files, local reports, logs, private keys, or browser-specific metadata.
- Do not add external network calls for analysis without explicit user consent and documentation.
- Clearly document user-visible privacy or permission changes.
- Keep the toolbar badge authoritative when changing the display-only companion overlay; website DOM can detect, remove, hide, cover, or spoof the overlay host, so it must not perform privileged actions.
- Add regression tests for navigation isolation, worker-state restoration, URL/body minimization, cookie reconciliation, and sender validation when changing observation code.
- Add negation, benign-language, public-suffix, and severity-consistency cases when changing analyzer rules.

## Pull request policy

- All changes to `main` should go through pull requests.
- At least one approving review is expected before merge.
- Required CI checks must pass.
- Stale approvals should be refreshed after meaningful changes.
- Conversations should be resolved before merge.
- Prefer squash merges to keep the public history readable.
- Security-sensitive changes, permission changes, and remote-data-flow changes require extra scrutiny in the pull request description.

## Code style

- Use plain JavaScript modules matching the existing style.
- Prefer small, testable functions in `src/analyzer.js` and storage helpers.
- Keep popup UI text localized through `src/i18n.js`.
- Keep user data local unless a feature explicitly opts in to a documented remote service.
- Derive content-script tab/document identity from the runtime message sender and keep observation state scoped to one top-level navigation.

## Reporting issues

When filing a bug, include:

- Browser and operating system.
- Extension version or commit.
- Page type being analyzed, without sharing private policy text unless necessary.
- Expected behavior and actual behavior.
