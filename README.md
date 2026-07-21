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

For user security and privacy, unveily is currently built as a local-only Chrome extension without an analysis backend. Analysis runs in the browser. The extension observes HTTP and HTTPS activity across enabled sites so it can compare policy claims with behavior, but observations are minimized, bounded, separated by top-level navigation, and not sent to a remote service.

## What it does

- Observes bounded request and cookie metadata across HTTP and HTTPS sites while the extension is enabled.
- Applies a bounded per-tab burst/rate allowance before parsing subresource metadata, resets it for each distinct top-level request without repeatedly refilling redirect stages, and rejects raw network URLs over 16 KiB during request-metadata sanitization and document fingerprinting; main-frame boundaries remain exempt from rate sampling.
- Provides a global passive-observation pause and a validated exact-origin exclusion list of up to 100 sites in the options page; invalid or over-limit input is rejected instead of silently broadened or truncated.
- Samples a bounded amount of visible text outside form controls and editable/user-input subtrees locally to identify policy-like pages; only then sends a larger bounded excerpt to the extension service worker. That text is not added to observation history or sent to a remote service. Explicit current-page analysis uses the same input-area exclusion and remains available.
- Suspends automatic policy/consent DOM work when a tab becomes hidden by clearing its scan timers and disconnecting its mutation observers, then reconnects and rescans when the tab is visible again. Prerendered documents wait for trusted browser activation, and BFCache documents stop DOM work before freezing and reload the current pause/exclusion setting before resuming. Bounded value-free request/cookie metadata observation remains active in the background so behavior comparison is not broken; prerender activity before activation is not attributed to a user-visible visit.
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
- The analyzer can prioritize an IP-derived country code when a trusted integration supplies one. The current extension UI neither collects nor configures this signal, and the extension does not call an external IP geolocation API by default.
- Scores how well observed behavior aligns with policy evidence sections.
- Uses a bundled local vendor ruleset to classify third-party domains without a server database.
- Uses a pinned offline Public Suffix List, including private hosting suffixes, so sibling tenants are treated as separate sites.
- Supports user-defined vendor rules stored only in `chrome.storage.local`.
- Exports the latest analysis as local Markdown or JSON files after reducing the source to a redacted route/host and aggregating form, storage, consent-label, and request-field identifiers.
- Saves explicitly selected HTTPS policy-URL snapshots in `chrome.storage.local` using the same bounded fetch/extraction pipeline used for later comparisons.
- Best-effort automatically checks each saved HTTPS policy URL at most once every six hours in the background, records coarse per-URL check health, and sends deduplicated Chrome notifications for important changes. A user-triggered “Check changes” run may contact a URL sooner. The worker recreates a missing check alarm when it starts, but Chrome can delay an alarm while the browser or device sleeps.
- Keeps the latest risk level in the Chrome toolbar badge, which is the authoritative companion signal. An explicit opt-in enables a display-only circular companion overlay in eligible website DOM with a continuous green–orange–red score color and textual/numeric status. Because the overlay host belongs to the analyzed page's DOM, that page can detect, remove, hide, cover, or spoof it; users should verify any consequential reading against the toolbar badge.

unveily is rule-based by design. It is useful for fast triage, but it is not legal advice or a complete security audit.

## Not implemented or still incomplete

- Make all analysis flows feel consistently smooth across real websites. Current behavior still depends heavily on page structure, content-script availability, and when the user opens the popup.
- Improve automatic policy discovery. The extension currently works best when the active page already contains the policy text, or when the user pastes text manually.
- Improve terms-vs-privacy separation. The analyzer can inspect policy-like text, but it does not yet provide a fully separate terms report and privacy report.
- Add a guided consent test flow that walks the user through baseline capture, rejecting optional cookies, browsing, and comparing post-rejection tracking.
- Improve the compact toolbar-badge and accessible companion-overlay states without treating the page-hosted overlay as an authenticated browser surface.
- Expand automated real-browser coverage beyond the current companion baseline. Permissions, privacy sentinels, consent/cookie behavior, alarms and sleep, policy monitoring, exports, and browser-frame accessibility still require the separate Chrome 140+ manual matrix.
- Improve generated report localization. The popup is localized, but exported Markdown report headings are currently English-first.
- Add stronger vendor and tracker classification. The current bundled ruleset is intentionally small and local.
- Add clearer per-site history and comparison views beyond the current saved snapshot and change detection flow.
- Prepare the Chrome Web Store listing, review assets, and submission record. The repository now creates a reproducible allowlisted ZIP, but it is not yet a reviewed or published store release.

## Limitations

- Rule-based analysis can miss subtle legal language, unusual page structures, or context that requires legal interpretation.
- The extension is not legal advice, compliance certification, or a full security audit.
- The extension intentionally avoids reading form values, cookie values, localStorage values, and sessionStorage values. This protects users, but it also means analysis is based on metadata and visible text rather than full payload contents.
- Network analysis is limited by Chrome extension APIs, browser permissions, request visibility, and the page lifecycle.
- On unusually high-volume pages, subresource activity above the abuse-rate allowance is sampled out, and oversized network URLs are ignored, so the report is intentionally not a complete traffic log.
- The extension observes request metadata and field names, not full payload values. It may miss sensitive data that is encoded, bundled, encrypted, renamed, or sent through an opaque SDK.
- The extension does not request Chrome's `webRequest` request-body view. Form values and raw upload bytes therefore are not delivered to the service worker; POST/PUT/PATCH methods and value-free visible form metadata still support behavior comparison.
- Consent analysis can identify visible banners, buttons, toggles, and observed tracking behavior, but it cannot guarantee that every hidden consent path or third-party script behavior has been captured.
- The extension does not automatically click cookie rejection controls. Post-rejection analysis depends on the user making a consent choice and then running comparison steps.
- Jurisdiction detection is best-effort. Browser language, timezone, domain, and optional country signals can be incomplete or misleading.
- Policy-change monitoring only works for HTTPS policy URLs that have been saved and can be fetched by the extension. HTTP pages can still be observed and analyzed, but cannot become automatic remote-fetch targets.
- Dynamic pages, iframes, closed shadow DOM, anti-bot protections, or heavily scripted consent managers may reduce extraction quality.
- Restricted pages such as Chrome internal pages, extension pages, some browser-controlled pages, and pages with strict access limitations cannot be analyzed.
- The companion reports the current page's most recent automatic policy, explicit page, or cookie analysis result. It is not a continuously recomputed whole-site security score; ordinary non-policy pages may remain unknown, and unknown does not mean safe. The in-page overlay is display-only and tamperable by the website, so only the toolbar badge is authoritative.
- Background policy checks can fail when a saved policy URL requires authentication, redirects instead of serving the final canonical URL, blocks extension fetches, uses heavy client-side rendering, or changes content based on region. The options page shows bounded last-attempt/success and categorical failure state rather than response bodies.
- Automatic policy checks are best-effort. They use a recreated six-hour Chrome alarm and enforce the interval independently from each URL's last attempt (or baseline capture when it has never been checked), but sleep, browser scheduling, network delays, or Manifest V3 worker termination can delay or interrupt a run. Explicit “Check changes” requests bypass that automatic interval.
- Each automatic policy request uses `cache: "no-store"` and no credentials. The destination server still receives the requested policy URL and ordinary connection metadata such as the user's IP address, user-agent headers, and request time. Up to 50 saved policy URLs are eligible for each run.
- Local-first storage keeps user data on the device, but it also means there is no server-side account sync, shared database, or managed policy corpus.
- `chrome.storage.local` is browser-profile storage, not an encrypted vault. Anyone with sufficient access to the profile or extension DevTools may be able to inspect saved settings, policy URLs, and policy excerpts.
- The one-hour observation inactivity limit is a logical expiry. A one-shot cleanup alarm and the next observation access both enforce it, but browser sleep can delay physical removal from `chrome.storage.session`.

## Privacy model

unveily is local-first. It does not send analyzed page text, policy text, cookies, storage keys, or browsing activity to a remote analysis service. Always-on observation is required for behavior comparison, so ordinary observation records are minimized to bounded metadata, omit URL credentials/query values/fragments, replace dynamic cookie-name and field-key identifiers with category placeholders, avoid retaining request or cookie values, rotate on document/SPA navigation, and disable incognito access. Known tracking-cookie families keep only a static family marker; their dynamic suffixes are removed. Unpartitioned cookie changes can update state but are not treated as causal pre/post-consent timing evidence. Safely attributed partitioned changes retain bounded first/last set-or-update evidence separately from deletion time: deletion alone is not post-consent tracking, while real updates on both sides of a consent choice can be reported in both evidence buckets without double-counting the cookie identity total. Document/query and exact cookie-name/path identity fingerprints are kept transient rather than persisted, and identities that cannot be reconstructed safely are rebuilt from current browser inventory after worker recovery. Explicitly saved HTTPS policy URLs retain their pathname and only validated locale/version query parameters; unknown semantic parameters fail closed instead of being silently removed. Those explicitly enabled monitoring requests contact the policy host directly on a best-effort automatic schedule of at most once per URL every six hours and are not anonymous, even though credentials and observed-page data are omitted; an explicit “Check changes” action may contact them sooner. See [PRIVACY.md](PRIVACY.md) for the full data handling model.

## Run locally

1. Open `chrome://extensions`.
2. Turn on Developer mode.
3. Click Load unpacked.
4. Select this project folder.
5. Open a terms or privacy policy page and click the extension icon.

Chrome 140 or newer is required. The extension relies on partitioned-cookie metadata and Chrome 140's ability to restrict `chrome.storage.local` to trusted extension contexts before any persisted state is read.

## Check locally

```bash
npm ci
npm test
npm run check
npm run package:extension
npm run test:package
npm run test:e2e:chrome
```

The syntax check covers both extension modules in `src/` and repository maintenance or CI scripts in `scripts/`. `npm run package:extension` creates `dist/unveily-<version>.zip` from an explicit runtime-file allowlist with fixed ZIP metadata; `npm run test:package` verifies its paths, checksums, content, manifest/import references, and byte-for-byte reproducibility. Dependencies, tests, repository scripts, reports, and local files are excluded.

`npm test` is the fast Node suite with Chrome API mocks. `npm run test:e2e:chrome` launches a real Chrome 140+ installation, loads the unpacked extension in a clean temporary profile, and uses controlled localhost fixtures to verify the companion-overlay path, including explicit enablement, hidden-tab DOM idling/resume while value-free request observation continues, popup analysis, continuous colors, stale-document rejection, document isolation, and Manifest V3 worker recovery. Set `E2E_CHROME_PATH` when Chrome is installed outside the detected platform paths; CI runs the same command headlessly.

Complete [MANUAL_TESTING.md](MANUAL_TESTING.md) before a release for the security, privacy, browser-frame, and lifecycle behaviors that are not automated by this focused E2E baseline.

## Contributing and security

- See [CONTRIBUTING.md](CONTRIBUTING.md) for local development and pull request expectations.
- See [SECURITY.md](SECURITY.md) for vulnerability reporting and security expectations.
- See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for contributor behavior standards.

## Project structure

- `manifest.json`: Chrome Manifest V3 config.
- `src/analyzer.js`: Rule-based policy, consent, jurisdiction, storage, form, network, and behavior-alignment analysis.
- `src/background.js`: Records bounded navigation-scoped network/cookie metadata, restores short-lived session state, runs hardened policy-change checks, and publishes toolbar/companion risk state.
- `src/backgroundSecurity.js`: Minimizes request/cookie records, validates runtime messages and document-bound companion-overlay senders, verifies document identity, and enforces saved-policy fetch limits.
- `src/observationSettings.js`: Normalizes the global observation switch and exact-origin exclusions.
- `src/runtimeLimits.js`: Enforces bounded per-tab request bursts and indexed cookie-change queue limits before observation work expands.
- `src/domWorkLimits.js`: Provides per-scan node, computed-style, and elapsed-time budgets plus shared DOM caches for content-script traversal.
- `src/content.js`: Extracts readable page text, visible form metadata, storage keys, consent UI controls, and jurisdiction signals; companion rendering is isolated in its own content-script module.
- `src/popup.html`, `src/popup.js`, `src/popup.css`: Toolbar popup UI and report rendering.
- `src/companionOverlay.js`, `src/companionOverlayRuntime.js`, `src/companionRuntime.js`, `src/companionSettings.js`, `src/riskColor.js`: Opt-in display-only website overlay, bounded document-targeted delivery with restart-safe generations, minimized companion state and preference normalization, and continuous 0–100 risk-color interpolation.
- `src/options.html`, `src/options.js`, `src/options.css`: Options page for local custom vendor rules and saved snapshots.
- `src/vendorRules.js`: Local built-in vendor rules for analytics, ads, payment, support, infrastructure, auth, and security services.
- `src/customRulesStorage.js`: Local storage helpers for custom vendor rules.
- `src/report.js`: Local Markdown/JSON report generation and download helpers.
- `src/policySnapshots.js`: Per-policy-URL local snapshot creation, bounded storage, migration, comparison, and categorical check-health state.
- `src/policyMonitor.js`: Background policy fetch text extraction, notification filtering, and dedupe helpers.
- `src/publicSuffixRules.js`: Generated, pinned offline ICANN+PRIVATE Public Suffix List and registrable-domain resolver.
- `src/i18n.js` and `_locales/`: Popup/options/report UI localization.
- `test/`: Node test suite with Chrome API mocks for analyzer behavior, popup/companion-overlay wiring, reports, policy snapshots, notifications, i18n, and toolbar risk state.
- `scripts/e2e-companion.mjs`: Real Chrome 140+ companion-overlay E2E using a clean temporary profile and controlled localhost fixtures.
- `MANUAL_TESTING.md`: Remaining Chrome 140+ human release checklist for permissions, observation, navigation, cookies, worker recovery, monitoring, browser-frame UI, and report redaction.

## Design constraints

- Keep analysis local-first and disclose that passive behavior observation covers HTTP/HTTPS sites while it is enabled.
- Keep captured network/cookie metadata bounded, value-free, short-lived, and isolated by top-level navigation.
- Never retain full request URLs, query values, cookie values, form values, browser-storage values, or persistent low-entropy URL/path fingerprints; do not request request-body data; only bounded route shapes, query keys, value-free page-form metadata, and storage key names are eligible analysis inputs.
- Require explicit consent and documentation before adding any remote analysis path.
- Treat new Chrome permissions as user-visible product and security changes.
- Keep the toolbar badge authoritative: the opt-in display-only overlay is hosted in website DOM, so a page can detect, remove, hide, cover, or spoof it.
- Update the pinned PSL deliberately with `npm run update:psl`, review its recorded version/commit, and keep its third-party notice.

## Permission rationale

| Permission | Purpose |
| --- | --- |
| `http://*/*`, `https://*/*` | Required for the product's all-site HTTP(S) behavior comparison and content script. |
| `webRequest` | Observes bounded request metadata without requesting Chrome's request-body view. |
| `webNavigation` | Separates records across committed documents, subframes, and SPA history changes. |
| `cookies` | Observes cookie metadata; values exposed by Chrome are discarded immediately. |
| `activeTab`, `scripting` | Supports user-invoked analysis and a bounded fallback extractor for the active page. |
| `storage` | Stores short-lived session state plus explicit settings, rules, and policy snapshots locally. |
| `alarms`, `notifications` | Best-effort runs six-hour checks for explicitly saved policy URLs, expires inactive observation shards, and reports important changes. |

## License

MIT. See [LICENSE](LICENSE).

Bundled third-party data is listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
