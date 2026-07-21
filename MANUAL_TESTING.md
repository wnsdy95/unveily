# Manual Chrome release testing

The fast Node suite uses Chrome API mocks. A separate `npm run test:e2e:chrome` baseline launches real Chrome 140+ with a clean temporary profile and controlled localhost fixtures, but it intentionally covers only the companion path. Complete this checklist for the remaining security, privacy, browser-frame, accessibility, and lifecycle behavior before publishing a release candidate. Record every skipped item and its reason.

Use controlled test pages and synthetic sentinel values. Do not enter real passwords, authentication tokens, payment data, or private policy text while collecting screenshots or logs.

## Test record

- [ ] Commit or version:
- [ ] Chrome version:
- [ ] Operating system:
- [ ] Tester and date:
- [ ] Test profile was newly created or its prior extension data was cleared.
- [ ] Controlled HTTP and HTTPS fixtures used for the run are identified in the release record.

## Repository gates

- [ ] `npm test` passes.
- [ ] `npm run test:coverage` passes.
- [ ] `npm run test:coverage:background` passes.
- [ ] `npm run check` passes.
- [ ] `npm run package:extension && npm run test:package` creates and verifies the allowlisted reproducible ZIP.
- [ ] `npm run test:e2e:chrome` passes in Chrome 140 or newer.
- [ ] `git diff --check` reports no whitespace errors.

## Automated Chrome E2E baseline

The real-browser command automatically covers unpacked installation and first-run options, hidden-tab automatic DOM observer/timer suspension and visible-tab resumption while value-free request observation continues, completed toolbar-popup analysis, explicit companion-overlay enablement, scores and interpolated colors at 0/25/50/75/100, badge/ARIA text, inactive-tab and stale-document isolation, and explicit Manifest V3 worker termination/reconnection with persisted state recovery.

Keep the manual items below: the automated baseline does not inspect permission-warning copy, real privacy sentinels, consent/cookie/storage behavior, SPA transition races, pause/exclusion/restricted states, hostile-page overlay tampering, browser-frame placement and controls, screen-reader speech, policy alarms and device sleep, monitoring network behavior, or export files.

## Installation, permissions, and first-run disclosure

- [ ] Load the repository as an unpacked extension from `chrome://extensions`.
- [ ] Extract the generated `dist/unveily-<version>.zip` into a clean temporary directory, load that directory as an unpacked extension, and confirm its version and first-run behavior match the source-tree installation.
- [ ] Confirm the extension requires Chrome 140 or newer and incognito access is not allowed.
- [ ] Review the permission warning and confirm all-site HTTP/HTTPS host access plus `webRequest`, `webNavigation`, `cookies`, `storage`, `alarms`, and `notifications` match the documented purposes; confirm no `sidePanel` permission remains.
- [ ] On a clean first install, confirm the options page opens once and clearly says that value-free request/cookie metadata observation is enabled by default on all allowed HTTP/HTTPS sites; bounded visible text outside user-input/editing areas is assessed locally for policy likelihood; only a bounded policy-like excerpt reaches the service worker; the text is not stored in observation history or sent remotely; and pause/exclusion controls apply to this automatic scan.
- [ ] Reloading or updating the unpacked extension does not repeatedly open the options page.
- [ ] Confirm the Korean and English extension descriptions disclose default all-site observation, value-free metadata, and local analysis.
- [ ] Switch the options-page language between Korean and English and confirm the same disclosure remains visible.

## Observation, pause, and exclusions

- [ ] With observation enabled, visit controlled HTTP and HTTPS pages and confirm bounded request and cookie metadata appears in current-page analysis.
- [ ] Send query and form-body sentinel values. Inspect the registered `webRequest` listener and confirm it does not request `requestBody`; confirm body field names, values, and raw upload bytes do not appear in popup output, service-worker state, `chrome.storage.session`, policy snapshots, or exports.
- [ ] Put unique sentinels in a `textarea`, nested/inherited `contenteditable`, `role="textbox"`/`searchbox`/`combobox`, and a design-mode editing document. Confirm automatic policy scans and explicit current-page text analysis omit every sentinel while value-free form metadata remains available.
- [ ] Type repeatedly in an excluded editable area and confirm its confined mutation batches do not schedule whole-page automatic rescans; then change ordinary visible page text and confirm a rescan is still scheduled.
- [ ] Set cookies whose values contain unique sentinels. Confirm names may be minimized or classified but values never appear in observation state or reports.
- [ ] Pause passive observation globally. Confirm new request/cookie activity is absent and any existing observation shards are removed.
- [ ] While paused, run explicit current-page and pasted-text analysis and confirm both remain usable without restoring passive network/cookie history.
- [ ] Restart the service worker while paused and confirm cold-start request/cookie queues do not restore observation.
- [ ] Add an exact HTTPS origin exclusion. Confirm its existing session is removed and later activity is not reported.
- [ ] Confirm exclusion is exact: a different scheme, port, or sibling origin is not excluded accidentally.
- [ ] Remove the exclusion and confirm observation resumes only for new activity in a fresh navigation-scoped session.
- [ ] Enter more than 100 unique origins and confirm the save is rejected with a clear limit message while the previously saved settings remain unchanged.
- [ ] Enter an origin with credentials, path, query, fragment, or unsupported scheme and confirm the save is rejected instead of silently broadening it to an origin.

## Trusted local-storage isolation failure

Use a controlled test build that forces the shared trusted-local-storage gate to fail, and restore the unmodified source before release sign-off.

- [ ] Instrument `chrome.storage.local.get` and `set`, then open the popup and options page and start the service worker. Confirm each context attempts `setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" })` before any local operation and that forced failure produces zero local reads and writes.
- [ ] Make `setAccessLevel` never settle. Confirm each context fails closed within about five seconds rather than hanging indefinitely, then confirm a later invocation can retry after the API recovers.
- [ ] Confirm the service worker discards startup queues and keeps passive observation paused. Confirm the popup shows a persistent isolation warning; disables language, observation-state, and policy-monitoring controls; and can still run current-page, limited cookie, and pasted-text analysis and export their reports without loading saved vendor rules.
- [ ] Confirm the options page shows an immediately visible isolation error, disables every form control, and binds no save, delete, edit, language, or observation-settings action while the gate is unavailable.

## Navigation and document isolation

- [ ] Navigate from site A to site B in one tab. Confirm site A requests, cookies, snapshots, and badge state are not attached to site B.
- [ ] Reload the same URL and confirm a new top-level `documentId` creates a fresh observation generation.
- [ ] Change query and fragment routes and confirm query/fragment-sensitive document identity rotates without persisting the raw fingerprint.
- [ ] Exercise `history.pushState`, `history.replaceState`, back, and forward on a single-page application. Confirm each committed route is isolated and stale content-script results are rejected.
- [ ] Follow a same-origin and cross-origin redirect chain. Confirm one top-level boundary is retained for the final committed document and redirect stages do not repeatedly refill the request allowance.
- [ ] Start a navigation that fails or is cancelled. Confirm the last committed page is restored without mixing requests from the failed target.
- [ ] Load, navigate, detach, and replace same-origin and cross-origin iframes. Confirm only requests tied to current, connected frame documents are retained.
- [ ] Generate more than the per-tab request burst. Confirm the page remains responsive, main-frame boundaries survive, and the report is explicitly incomplete rather than corrupted.
- [ ] Send a raw URL longer than 16 KiB in a controlled fixture. Confirm it produces no observation record.

## Cookies and consent timing

- [ ] Use a controlled CHIPS fixture and confirm `partitionKey.topLevelSite` keeps otherwise identical partitioned cookies separate.
- [ ] Open the same cookie domain under multiple top-level tabs. Confirm ambiguous changes are not promoted to uniquely attributed causal timing evidence.
- [ ] Confirm an unpartitioned cookie may update current inventory but does not gain pre/post-consent timing solely from its change event.
- [ ] For a partitioned cookie, test set, update, delete, delete-then-set, set-then-delete, and set-update-delete sequences.
- [ ] Confirm deletion time alone is never reported as post-choice tracking.
- [ ] Confirm a genuine set/update before and after the choice can appear in both evidence buckets while the cookie identity total remains one.
- [ ] Save a baseline, reject optional tracking in a visible consent UI, browse, and analyze again. Confirm pre-choice, post-choice, and unknown timing counts match the controlled events.
- [ ] Repeat with accept-all and saved-preferences controls, including disabled tracking toggles.
- [ ] Stop and restart the worker between cookie events. Confirm safely reconstructible identities recover and dynamic exact-name/path identities rebuild from current value-free inventory rather than duplicating stale records.

## Manifest V3 restart, persistence, and expiry

- [ ] Inspect `chrome.storage.session` and confirm observation state is sharded by tab, stays within the documented aggregate budget, and contains no `documentFingerprint`, cookie `pathFingerprint`, request/cookie values, or raw URLs.
- [ ] Stop the extension service worker from DevTools, then trigger a request on an unchanged document. Confirm matching `documentId` state recovers and new activity is appended.
- [ ] Stop the worker, replace or reload the top-level document, and trigger recovery. Confirm stale state is discarded instead of attaching to the replacement document.
- [ ] Generate activity and immediately stop the worker before the debounced write. Confirm the extension remains safe and navigation-isolated even if the newest records are lost; suspension-time writes are best-effort.
- [ ] In the service-worker console, confirm `chrome.alarms.get("observation-session-expiry")` returns the one-shot deadline for the earliest inactive rich session or backup.
- [ ] Leave a controlled observed tab inactive for more than one hour with Chrome awake. Confirm the expiry alarm removes its shard/index and schedules the next deadline if another session remains.
- [ ] Repeat across browser/device sleep and record any delayed physical deletion; on wake or the next observation access, confirm logically expired state is removed before use.
- [ ] Pause observation and confirm the expiry alarm is cleared when no expirable observation state remains.
- [ ] Fully restart Chrome and confirm `chrome.storage.session` observation data from the prior browser session is gone.

## Saved-policy fetch and alarm behavior

- [ ] Switch the popup between Korean and English. Confirm the save button says that it starts policy-change monitoring and its always-visible nearby disclosure says saving contacts the policy host now; automatic checks contact each URL at most once every six hours afterward (checks may be delayed); choosing “Check changes” may contact it sooner; requests expose the IP address, User-Agent, and request time despite omitting cookies/login credentials; and deleting the saved policy stops monitoring that URL.
- [ ] Save a controlled public HTTPS policy page. Confirm the baseline is created from a fresh background fetch, not page-supplied text.
- [ ] Confirm the save success message says monitoring started. Delete the saved policy, confirm the success message says monitoring for that URL stopped, then run a manual policy check and confirm the deleted URL is not contacted.
- [ ] Confirm HTTP URLs, credentials, fragments, duplicate parameters, campaign parameters, unknown query parameters, unsafe values, private/local IP literals, and common local hostnames are rejected.
- [ ] Confirm permitted locale/version query parameters remain in the exact saved URL and distinct policy variants do not collide.
- [ ] Confirm redirects are rejected and the final canonical HTTPS URL must be opened and saved explicitly.
- [ ] Confirm authentication-dependent, unsupported content-type, oversized, timeout, and heavily client-rendered pages fail with a coarse category and do not store response bodies.
- [ ] On a controlled policy server, confirm saving/checking uses `cache: no-store`, sends no cookies or authorization credentials, and caps the response body at one MiB.
- [ ] Review the controlled server log and record that it still receives the requested URL, source IP, user-agent headers, and request time.
- [ ] Confirm at most 50 URL-keyed snapshots survive bounded storage pruning and deleting one also removes its associated health and notification-dedupe state.
- [ ] In the service-worker console, confirm `chrome.alarms.get("policy-snapshot-check")` exists and has an approximately six-hour period.
- [ ] Clear that alarm, stop the worker, then wake it with an extension action. Confirm startup recreates the missing alarm.
- [ ] Use the popup/menu “check now” action instead of waiting six hours. Confirm unchanged, changed, failed, and notified counts plus per-URL health are accurate.
- [ ] Trigger the same important change twice and confirm notification deduplication; trigger a different later change and confirm a new notification can appear.
- [ ] Click a policy notification and confirm only its validated saved HTTPS URL opens.
- [ ] Put the device to sleep across an alarm deadline and confirm a delayed check is treated as best-effort, without claiming the scheduled wall-clock time was met.
- [ ] Treat DNS rebinding as a documented residual boundary: hostname validation does not inspect the resolved IP. Test only in an authorized environment and confirm HTTPS certificate validation still applies.

## Report and export redaction

- [ ] Export both Markdown and JSON after using unique sentinels in the page title, URL credentials/query/fragment, request values, cookie values, form values, storage values, consent labels, and dynamic identifiers.
- [ ] Confirm the raw page title, credentials, query values, fragment, request/cookie/form/storage values, and exact dynamic identifiers are absent.
- [ ] Confirm the source is reduced to host plus redacted route shape and form/storage/consent/request-field details are categories and counts.
- [ ] Confirm policy excerpts, observed hostnames, minimized cookie categories, and findings can remain, matching the sharing warning.
- [ ] Open the downloaded files in a text editor and search for every sentinel before approving the release.

## Restricted pages and UI resilience

- [ ] Confirm `chrome://`, Chrome Web Store, extension pages, inaccessible frames, and other restricted pages fail safely with an actionable message.
- [ ] With the companion disabled, confirm automatic and popup analyses update the authoritative toolbar badge without adding a companion host or shadow root to website DOM.
- [ ] Exercise a long, dynamic page and confirm automatic scans remain throttled, stop while hidden, and fail closed on their DOM work budget.
- [ ] With observation ON, place a controlled page into BFCache, switch observation OFF or exclude its origin from another active page, then go Back. Confirm the restored page performs no automatic scan and remains stopped; repeat OFF-to-ON and confirm it starts only after reloading the current setting.
- [ ] Activate a controlled prerendered page and confirm automatic DOM observation is absent before activation and begins once, using the current setting, after Chrome's activation event. Confirm synthetic lifecycle events do not cause settings requests or scans.
- [ ] Confirm popup and options rendering does not interpret hostile policy, vendor, URL, or page text as HTML.

## Companion overlay

- [ ] Explicitly enable the companion in the popup and confirm a display-only circular overlay appears at the lower left of eligible top-level HTTP(S) pages with a closed shadow root; disable it and confirm the host is removed. Restart Chrome and confirm the global `companionOverlayEnabled` choice persists only through trusted `chrome.storage.local` access.
- [ ] Confirm a completed page or cookie analysis updates the overlay's numeric/textual status and color without reopening the popup, while the toolbar badge remains the authoritative signal.
- [ ] Exercise synthetic scores at 0, 25, 50, 75, and 100 and confirm the anchors are green, orange, and red while 25 and 75 use visibly intermediate colors.
- [ ] Confirm the meter exposes `role="meter"`, `aria-valuemin="0"`, `aria-valuemax="100"`, the current numeric value, and a textual risk description so color is not the only signal.
- [ ] Navigate through full-document and SPA transitions, reload the same URL, switch tabs, and move a tab between windows. Confirm each overlay remains bound to its own top-level document/route and out-of-order responses never restore a previous page's score.
- [ ] Confirm ordinary non-policy pages say that no completed result is available and do not present `unknown` as safe.
- [ ] Pause observation, exclude the active origin, and open a restricted page. Confirm the companion fails closed to the documented paused, excluded, unsupported, or absent state without exposing a stale score.
- [ ] From a controlled hostile page, detect the overlay host, remove it, alter its host styles, cover it, and draw a fake green circle. Confirm these website capabilities are treated as an expected trust-boundary limitation, there is no unbounded reinsertion loop, and none of them changes the authoritative toolbar badge. If a later trusted state update remounts a removed host, confirm the page can still remove it again.
- [ ] Confirm the overlay is display-only: clicks or synthetic DOM events cannot change settings, navigate, save, export, or invoke another privileged extension action.
- [ ] Test strict page CSP and Trusted Types, page-level capture listeners, fullscreen/top-layer content, 200–400% zoom, keyboard-only operation, forced colors, reduced motion, and screen-reader output. Confirm failure leaves the badge usable and never represents `unknown` as safe.
- [ ] Restart the service worker repeatedly while an overlay is present, including after several rapid updates. Confirm the trusted browser-session worker generation increases, a lower revision from the newer generation is accepted, and late older-generation state is rejected. Force generation storage or trusted-local-storage isolation to fail and confirm the startup broadcast removes the host instead of retaining a stale green score.

## Release sign-off

- [ ] Every unchecked or failed item has an issue link, owner, severity, and release decision.
- [ ] Privacy-impacting screenshots and logs contain only synthetic data.
- [ ] The observed permissions and data flows still match `README.md`, `PRIVACY.md`, and `SECURITY.md`.
- [ ] No unexplained High or Medium security, privacy, navigation-isolation, monitoring, or redaction failure remains.
