# unveily

[![CI](https://github.com/wnsdy95/unveily/actions/workflows/ci.yml/badge.svg)](https://github.com/wnsdy95/unveily/actions/workflows/ci.yml)

Chrome extension that summarizes terms of service and privacy policies, then highlights risky clauses, collected data categories, retention, sharing concerns, cookie consent behavior, and observed page activity.

## Why this exists

We live inside countless websites and online services through everyday web browsing.

Most users cannot realistically read every terms page, privacy policy, cookie banner, and data-processing notice before using a service. At the same time, many websites collect, infer, or share information in ways that are difficult to notice. In some cases, the actual behavior of a website does not match what its written terms or privacy policy appear to promise.

That mismatch matters. When a site sends data before meaningful consent, hides rejection options, or behaves differently from its own documents, users can unknowingly provide information they never clearly agreed to share.

unveily exists to make those risks visible. It is built for the rights and privacy of everyday internet users: to help people understand what a site says, what it appears to do, and where they should be careful.

## Development status

unveily is under active development. The current codebase is a working prototype, but not every behavior is smooth, complete, or production-ready yet. Some pages will analyze well; others may fail because of browser restrictions, dynamic rendering, consent-manager complexity, or extraction limits.

For user security and privacy, unveily is currently being built as a local-only Chrome extension without server communication. Analysis runs in the browser, and the project intentionally avoids sending analyzed page text, policy text, cookies, storage keys, or browsing activity to a backend.

## What it does

- Reads visible text from the active tab.
- Detects likely collected data categories such as contact, account, payment, device, location, usage, and sensitive data.
- Flags clauses that may be unfavorable to users, including broad third-party sharing, targeted ads, unilateral policy changes, account termination, liability limits, unclear retention, overseas transfer, arbitration, and vague security language.
- Supports pasted text when the current page cannot be read.
- Observes page network requests and compares request destinations and field names against the policy text.
- Detects visible signup form fields and checks whether requested data categories are disclosed in the policy.
- Tracks cookie changes and browser storage keys to detect missing cookie/storage disclosures.
- Detects visible cookie/consent controls and compares disabled tracking choices against observed tracking requests or cookies.
- Saves an observation snapshot so activity after a consent choice can be compared separately.
- Structures policy text into evidence sections such as collected data, retention, third-party sharing, cookies, user rights, and security.
- Automatically applies Korea or US rule checks from browser language, timezone, and site domain signals.
- Automatically applies GDPR/EU checks for EU/EEA signals and verifies lawful basis, rights, international transfer, consent, and profiling disclosures.
- If an IP country code is provided by a trusted caller or user setting, it takes priority; this extension does not call an external IP geolocation API by default.
- Scores how well observed behavior aligns with policy evidence sections.
- Uses a bundled local vendor ruleset to classify third-party domains without a server database.
- Supports user-defined vendor rules stored only in `chrome.storage.local`.
- Exports the latest analysis as local Markdown or JSON files.
- Saves per-site policy snapshots in `chrome.storage.local` and detects text, section, and risk changes.
- Periodically checks saved policy URLs in the background and sends deduplicated Chrome notifications for important changes.
- Shows a bottom-right floating risk indicator on analyzed webpages.

unveily is rule-based by design. It is useful for fast triage, but it is not legal advice or a complete security audit.

## Not implemented or still incomplete

- Show the current page risk directly through the browser toolbar icon or badge, so users can understand the risk level without opening the popup.
- Make all analysis flows feel consistently smooth across real websites. Current behavior still depends heavily on page structure, content-script availability, and when the user opens the popup.
- Improve automatic policy discovery. The extension currently works best when the active page already contains the policy text, or when the user pastes text manually.
- Improve terms-vs-privacy separation. The analyzer can inspect policy-like text, but it does not yet provide a fully separate terms report and privacy report.
- Add a guided consent test flow that walks the user through baseline capture, rejecting optional cookies, browsing, and comparing post-rejection tracking.
- Improve the floating page indicator. It currently reflects a local page scan or popup analysis result, but it is not a complete replacement for the popup report and can be stale after major page changes.
- Add controls for hiding or configuring the floating indicator per site.
- Improve real-browser end-to-end test coverage. The current test suite covers rules and wiring, but does not fully simulate Chrome extension behavior across many live websites.
- Improve generated report localization. The popup is localized, but exported Markdown report headings are currently English-first.
- Add stronger vendor and tracker classification. The current bundled ruleset is intentionally small and local.
- Add clearer per-site history and comparison views beyond the current saved snapshot and change detection flow.
- Prepare release packaging and Chrome Web Store distribution. The repository can be loaded unpacked, but it is not yet a polished store release.

## Limitations

- Rule-based analysis can miss subtle legal language, unusual page structures, or context that requires legal interpretation.
- The extension is not legal advice, compliance certification, or a full security audit.
- The extension intentionally avoids reading form values, cookie values, localStorage values, and sessionStorage values. This protects users, but it also means analysis is based on metadata and visible text rather than full payload contents.
- Network analysis is limited by Chrome extension APIs, browser permissions, request visibility, and the page lifecycle.
- The extension observes request metadata and field names, not full payload values. It may miss sensitive data that is encoded, bundled, encrypted, renamed, or sent through an opaque SDK.
- Consent analysis can identify visible banners, buttons, toggles, and observed tracking behavior, but it cannot guarantee that every hidden consent path or third-party script behavior has been captured.
- The extension does not automatically click cookie rejection controls. Post-rejection analysis depends on the user making a consent choice and then running comparison steps.
- Jurisdiction detection is best-effort. Browser language, timezone, domain, and optional country signals can be incomplete or misleading.
- Policy-change monitoring only works for policy URLs that have been saved and can be fetched by the extension.
- Dynamic pages, iframes, closed shadow DOM, anti-bot protections, or heavily scripted consent managers may reduce extraction quality.
- Restricted pages such as Chrome internal pages, extension pages, some browser-controlled pages, and pages with strict access limitations cannot be analyzed.
- Background policy checks can fail when a saved policy URL requires authentication, blocks extension fetches, uses heavy client-side rendering, or changes content based on region.
- Local-first storage keeps user data on the device, but it also means there is no server-side account sync, shared database, or managed policy corpus.

## Privacy model

unveily is local-first. The current extension is designed to work without server communication, and it does not send analyzed page text, policy text, cookies, storage keys, or browsing activity to a remote service by default. See [PRIVACY.md](PRIVACY.md) for the data handling model.

## Run locally

1. Open `chrome://extensions`.
2. Turn on Developer mode.
3. Click Load unpacked.
4. Select this project folder.
5. Open a terms or privacy policy page and click the extension icon.

## Check locally

```bash
npm test
npm run check
```

## Contributing and security

- See [CONTRIBUTING.md](CONTRIBUTING.md) for local development and pull request expectations.
- See [SECURITY.md](SECURITY.md) for vulnerability reporting and security expectations.
- See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for contributor behavior standards.

## Project structure

- `manifest.json`: Chrome Manifest V3 config.
- `src/analyzer.js`: Rule-based policy, consent, jurisdiction, storage, form, network, and behavior-alignment analysis.
- `src/background.js`: Records bounded tab-level network/cookie metadata, stores observation snapshots, runs policy-change checks, and publishes page risk indicators.
- `src/content.js`: Extracts readable page text, visible form metadata, storage keys, consent UI controls, jurisdiction signals, and renders the floating risk indicator.
- `src/popup.html`, `src/popup.js`, `src/popup.css`: Toolbar popup UI and report rendering.
- `src/options.html`, `src/options.js`, `src/options.css`: Options page for local custom vendor rules and saved snapshots.
- `src/vendorRules.js`: Local built-in vendor rules for analytics, ads, payment, support, infrastructure, auth, and security services.
- `src/customRulesStorage.js`: Local storage helpers for custom vendor rules.
- `src/report.js`: Local Markdown/JSON report generation and download helpers.
- `src/policySnapshots.js`: Per-site local policy snapshot creation, storage, and comparison.
- `src/policyMonitor.js`: Background policy fetch text extraction, notification filtering, and dedupe helpers.
- `src/i18n.js` and `_locales/`: Popup/options/report UI localization.
- `test/`: Node test suite for analyzer behavior, popup wiring, reports, policy snapshots, notifications, i18n, and floating indicators.

## Design constraints

- Keep analysis local-first.
- Keep captured network/cookie metadata bounded.
- Do not store form values, cookie values, localStorage values, or sessionStorage values.
- Require explicit consent and documentation before adding any remote analysis path.
- Treat new Chrome permissions as user-visible product and security changes.

## License

MIT. See [LICENSE](LICENSE).
