# Privacy

unveily is a local-first browser extension. It does not send analyzed content or browsing observations to an unveily server or a third-party analysis service.

## Always-on observation

To compare what sites say with what they do, the extension observes HTTP and HTTPS pages while it is enabled. This requires host access across websites. Incognito access is disabled by the manifest.

The always-on observer is designed to retain only bounded metadata such as:

- Top-level site origin, a redacted route shape, a Chrome-issued document identifier, and a per-navigation session generation. A fixed-length route fingerprint is used transiently inside extension contexts to distinguish query- and fragment-specific SPA routes, but it is not written to session storage.
- Request host, redacted route shape, method, resource type, timestamp, and bounded query field-key metadata. Long numbers, UUIDs, hashes, and token-like portions of field keys are replaced with category placeholders before history is created.
- Cookie change metadata without cookie values when the change can be attributed safely. Cookie paths are retained as redacted route shapes, and dynamic portions of cookie names are replaced with category placeholders; known analytics families retain only a static family marker so tracking classification still works. Exact name/path identity fingerprints used for in-memory reconciliation are never persisted. Records whose identity cannot be reconstructed without those fingerprints are discarded during worker recovery and rebuilt from the browser's current value-free cookie inventory. Partition top-level-site metadata is retained where Chrome provides it. Unpartitioned changes may update current cookie state, but their event receive time is not used as evidence that tracking happened before or after a consent choice. Only a uniquely top-site-attributed partitioned change can carry bounded first and last **set/update** times. Deletion time is stored separately and is never treated as post-choice tracking by itself; a deleted record retains genuine earlier set/update evidence. If one identity has set/update evidence on both sides of a choice boundary, it counts once in the total identity count and once in each applicable pre/post evidence count.
- Aggregated counts and local vendor classifications.

Full request URLs, query values, cookie values, form values, localStorage values, and sessionStorage values are not retained. Unknown path segments are replaced with route placeholders. Observation state is isolated by top-level document navigation so activity from one site is not reused for another site.

The extension does not ask Chrome for the `webRequest` request-body view. Request-body form values and raw upload bytes therefore are not delivered to the service worker, including while observation settings are loading or for paused and excluded sites. The analyzer still sees the request method and uses separately collected, value-free visible form metadata.

Chrome's cookies API supplies a cookie value as part of the browser object. unveily immediately constructs a value-free record and never adds that value to its in-memory history, startup queue, session storage, reports, or policy snapshots. Cookie attribution is evaluated against all matching HTTP(S) tabs before excluded sites are filtered, so an exclusion cannot make an ambiguous cookie appear uniquely attributable elsewhere.

During a Manifest V3 worker cold start, at most 500 already-redacted request events and 500 value-free cookie changes can be held briefly in memory while the saved observation setting is loaded. Request queues are capped at 50 events per tab and preserve main-frame boundaries ahead of subresources. Cookie changes are coalesced to their final set/delete state with identity/domain indexes while retaining the earliest and latest safely attributed non-removal time separately from the latest deletion time. Thus delete-then-set uses the set time as its first activity evidence, while set-then-delete preserves the earlier set evidence in a tombstone. The queue is capped at 50 identities per cookie domain and evicted fairly across domains. If observation is paused, or an origin is excluded, those pending events are discarded before being added to observation state or storage.

To prevent an enabled site from using unbounded request churn to consume extension CPU, subresource capture has a per-tab burst allowance of 300 events and then replenishes at 60 events per second. Excess subresource events are dropped before URL and field-key parsing; top-level main-frame boundaries are exempt from this sampling limit and start a fresh allowance for the new page. Redirect stages sharing Chrome's request identifier do not repeatedly refill that allowance. Raw network URLs longer than 16 KiB are rejected by request-metadata sanitization and document fingerprinting, including for main-frame events, so those oversized URLs do not create observation records. These abuse controls can omit some activity on unusually high-volume or oversized pages, but do not cause raw payloads to be retained.

## Page analysis

The extension may read:

- Visible text outside form controls and editable/user-input subtrees from a page that appears to contain a policy for automatic risk indication.
- Visible page text outside those input/editing areas when the user explicitly runs current-page analysis.
- Terms or privacy text pasted by the user.
- Visible form metadata such as field name, label, type, placeholder, and required state.
- Browser storage key names.
- Visible cookie consent text, buttons, toggles, and the timing of classified consent choices.

Automatic scans sample a bounded amount of visible text locally for the policy-likelihood gate. Text under `input`, `textarea`, `select`, `option`, inherited `contenteditable`, editable ARIA roles, whole-document design mode, and detected read-write editing surfaces is excluded; the same exclusion applies to explicit current-page text extraction, while value-free form metadata remains available separately. For ordinary pages the scanner sends only a bounded length/confidence assessment and no text to the background worker. A larger bounded policy-text excerpt is sent only after that local gate passes. Dynamic-page rescans are throttled, run only while the document is visible, ignore mutation batches confined to excluded input/editing areas, and share hard per-scan limits for DOM-node visits, computed-style reads, and elapsed time. When a tab becomes hidden, the content script clears automatic scan/consent timers and disconnects its policy/consent DOM mutation observers; it reconnects them and queues a bounded scan when the tab becomes visible. A prerendered document does not initialize automatic DOM observation until Chrome activates it as the visible document. A document entering BFCache stops that work and, on trusted browser restoration, remains stopped until it reloads the current global pause and exact-origin exclusion decision; stale settings responses cannot override a newer settings push. Activity before prerender activation is not attributed to a user-visible visit. This DOM idling does not pause the separate bounded, value-free request/cookie metadata observation needed for behavior comparison on an active document. Visibility and completed subtree text are cached only for that synchronous scan; if its budget is exhausted, automatic policy classification fails closed without sending page text. Page text used for analysis is not added to the observation history or sent to a remote analysis service.

## Companion overlay

The companion is off until the user explicitly enables it in the toolbar popup. While enabled, a top-level content script adds a display-only circular overlay with a closed shadow root to eligible HTTP(S) website DOM. This makes the extension's enabled state observable to the website. A website can also remove, hide, cover, move, or imitate the overlay host; a closed shadow root does not make that host an authenticated browser surface. The Chrome toolbar badge remains the authoritative risk signal.

The document-bound companion messaging path receives only a minimal state containing a coarse availability status, risk level, finite 0–100 score or `null`, an allowlisted analysis source, update time, browser-session worker generation, and per-worker revision. It does not receive the page URL, title, analysis label, page or policy text, cookies, requests, observation records, document identifier, or route fingerprint. State is rendered inside the closed shadow root rather than copied into host attributes, and the overlay performs no settings changes, navigation, saving, or export actions.

The displayed value is the current page's most recent automatic policy analysis, explicit page analysis, or cookie analysis—not a continuously recomputed whole-site security verdict. Ordinary pages that do not look like policies can remain `unknown`; `unknown` does not mean safe. Available numeric scores select a continuous color between green at 0, orange at 50, and red at 100, and the overlay also supplies numeric and textual status so color is not the only signal.

## Local storage

`chrome.storage.session` is used for best-effort recovery of short-lived observation state across a Manifest V3 worker restart. It also stores one small page-data-free companion worker-generation counter so an existing overlay can reject state from an older worker. Recovery accepts observation records only when Chrome's current top-level `documentId` still matches, so stale state is discarded instead of being attached to a replacement document. A small identity index and bounded per-tab shards avoid rewriting every tab's history when one tab changes. Combined observation state is limited to 50 tabs, a 4 MiB budget, bounded per-tab records, and a one-hour inactivity lifetime. That hour is a logical expiry: the worker schedules a one-shot alarm for the earliest expiry and also prunes expired state on the next access, then rewrites or removes the affected shard and index. Chrome can delay alarm delivery while the browser or device sleeps, so physical removal may occur after the one-hour boundary. Session data is cleared when the browser session ends and is rotated when the top-level document or SPA route changes. Browser shutdown or an interrupted worker suspension can still lose the latest not-yet-written records because asynchronous work started during suspension is not guaranteed to finish.

`chrome.storage.local` is used for explicit longer-lived features:

- User-defined vendor rules.
- Policy snapshots saved by the user, keyed by normalized policy URL.
- Policy-change notification deduplication.
- Bounded policy-check health metadata: last attempt/success times, consecutive failure count, and a coarse error category without response content.
- Passive-observation enablement and exact-origin exclusions.
- The explicit global companion-overlay enablement boolean (`companionOverlayEnabled`).
- UI language preference.

`chrome.storage.local` belongs to the local browser profile; it is not end-to-end encrypted or an encrypted vault. A person or program with sufficient access to that profile or the extension's DevTools may be able to inspect these settings, saved policy URLs, and policy excerpts.

Every extension entry point that uses `chrome.storage.local`—the service worker, popup, and options page—first restricts it to Chrome's `TRUSTED_CONTEXTS`, before its first local read or write, so content scripts cannot access it. The access-level operation has a five-second upper bound and a later invocation can retry a failed decision. If the restriction fails or times out, the entry point fails closed: the service worker does not load local settings, discards startup queues and owned session-recovery shards, keeps observation paused, leaves the companion overlay off, and removes its policy-check alarm; the popup does not load or save companion enablement, saved rules, or other local-state and policy-monitoring controls, but still permits analysis that uses no saved local state; and the options page leaves all controls disabled without reading or writing local data.

Only HTTPS policy URLs can be saved for automatic monitoring. Legacy HTTP snapshot entries are discarded during loading and must be re-saved from an HTTPS version if one exists. URLs containing credentials, fragments, campaign parameters, unknown query parameters, duplicated parameters, or unsafe parameter values are rejected so normalization cannot silently select a different document. Strictly validated locale keys (`hl`, `lang`, `locale`) and numeric version keys (`v`, `version`) are retained so policy variants do not collide. Because monitoring must fetch the same document again, the pathname of an explicitly saved policy URL is retained locally. At most 50 snapshots and 6 MiB of snapshot data are kept; each stored normalized-text excerpt is limited to 80,000 characters. Policy text/section integrity uses SHA-256 where Web Crypto is available. Users can delete rules and individual URL-keyed snapshots from the options page.

## Network behavior

The extension does not send observed page data to an external analysis service. Background policy monitoring directly fetches only normalized HTTPS policy URLs explicitly saved by the user. Saving and later checking use the same bounded background-fetch and HTML-extraction pipeline. Up to 50 saved URLs are eligible for automatic best-effort checks, with each URL contacted at most once every six hours based on its last attempt or, before its first check, its baseline capture time. The user-triggered “Check changes” action may contact a URL sooner. The worker verifies that the periodic alarm exists whenever it starts and recreates a missing alarm; Chrome can still delay delivery during browser/device sleep, and a Manifest V3 worker termination can interrupt a run.

Each policy request uses `cache: "no-store"`, omits browser credentials, rejects redirects and private/local host literals, and applies response timeout, content-type, one-MiB input, bounded output, and parser-depth limits. Omitting credentials does not make the request anonymous: the destination policy server still receives the requested URL and ordinary network metadata such as the user's IP address, user-agent headers, and request time. A redirecting policy must be saved again using its final canonical URL. The extension cannot independently inspect DNS resolution, so HTTPS certificate validation is an additional required boundary rather than a claim that hostname-only validation can identify every rebinding setup.

## Reports

Markdown and JSON reports are generated locally and downloaded by the browser. Source URLs are reduced to a host and redacted route shape; credentials, query strings, fragments, and the raw page title are omitted. Form fields, storage keys, consent labels, and request-field identifiers are exported only as categories and counts. Reports can still include policy excerpts, observed hostnames, minimized cookie categories, and analysis findings, so users should review them before sharing.

## User controls

Users can pause passive observation globally, maintain a validated exact-origin exclusion list of up to 100 sites, explicitly enable or disable the display-only companion overlay in the toolbar popup, reset the active observation session, delete saved policy snapshots, and remove custom vendor rules. Invalid or over-limit exclusion input is rejected rather than silently broadened or truncated. Explicit current-page analysis remains available when passive observation is paused because it is initiated by the user.

## Remote features

Any future AI or remote-analysis feature must require explicit opt-in, clearly identify the data sent and recipient, and preserve a fully local mode.
