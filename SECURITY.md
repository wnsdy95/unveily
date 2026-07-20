# Security Policy

## Supported versions

The main branch is the supported development line until versioned releases are published.

## Reporting a vulnerability

Please report security issues privately before opening a public issue. Include:

- A clear description of the issue.
- Reproduction steps.
- Affected browser/version when relevant.
- Whether the issue can expose page data, policy text, cookies, extension storage, or browsing activity.

If no private security channel is listed in the repository, open a minimal public issue asking for a maintainer contact without publishing exploit details.

## Security expectations

- The extension should not transmit analyzed page text, policy text, cookies, storage keys, or browsing activity to a remote service by default.
- Always-on observation must retain only bounded, value-free metadata and must be disclosed to users.
- Observation records must be isolated by top-level navigation and must not cross site or document boundaries.
- Full request URLs, query values, raw request bodies, cookie values, form values, and browser-storage values must not be retained.
- Automatic and explicit page-text extraction must exclude form controls, inherited editable/user-input subtrees, and whole-document editing surfaces. Value-free form metadata may still be collected separately, and mutations confined to excluded editing areas must not trigger automatic rescans.
- Hidden tabs must clear automatic policy/consent scan timers and disconnect their DOM mutation observers until visible again. Prerendered documents must wait for a trusted activation event, and BFCache documents must fail closed on freeze and revalidate current pause/exclusion settings on trusted restoration. Settings queries and pushes require an ordering guard so an older response cannot restart observation. Synthetic lifecycle events must not trigger privileged runtime work. This content-script idling must not be represented as pausing the separate bounded, value-free background request/cookie observation for an active document.
- The `webRequest` listener does not request Chrome's request-body view, so request-body form values and raw upload bytes are not delivered to the service worker. Request methods and separately collected value-free visible form metadata remain available for analysis.
- Query/fragment and exact cookie-name/path fingerprints used for live document or cookie identity must not be persisted with recoverable observation history.
- Runtime messages from content scripts must derive tab, document, and URL identity from the Chrome-provided sender rather than page-provided fields.
- The companion overlay must remain an explicit opt-in, display-only surface; the toolbar badge is the authoritative risk signal because website DOM cannot authenticate extension UI.
- Saved-policy fetches must require HTTPS, omit credentials, bypass caches, reject redirects, and enforce URL-scheme, destination, timeout, content-type, response-size, and parser-work limits.
- A policy baseline and later comparison must use the same fetch/extraction pipeline, and a completed check must revalidate that the baseline was not replaced or deleted while the request was in flight.
- New permissions must be justified in the pull request.
- Secrets, private keys, packaged extension signing keys, and local export files must not be committed.
- Remote analysis features, if added later, must require explicit user consent and a documented data flow.

## Trust boundaries

- The toolbar popup, options page, service worker, and toolbar badge are extension-controlled UI. The toolbar badge is the authoritative companion signal.
- After explicit opt-in, a top-level isolated content script injects the display-only companion host into website DOM and renders its state inside a closed shadow root. The website can detect, remove, hide, cover, move, or spoof that host; the shadow root protects ordinary internal DOM encapsulation, not the host's authenticity or availability. The overlay performs no settings changes, navigation, saving, export, or other privileged action.
- The overlay requests initial state with an exact, field-bounded runtime message. The service worker validates the extension ID, top-level frame, active document lifecycle, Chrome-provided tab/document identity, and sender/top-frame URL rather than accepting page-provided identity; later updates target a twice-checked current top-level `documentId` without enumerating subframes. A browser-session worker generation reserved in trusted `chrome.storage.session`, followed by a per-worker revision, lets the overlay reject both cross-worker and in-worker stale updates without relying on the wall clock. Startup visibility delivery is bounded to four tabs at a time; generation-storage failure sends a trusted fail-closed removal message. The overlay receives only a status, allowlisted level/source, finite 0–100 score or `null`, update time, generation, and revision—never a URL, title, label, page text, observation record, cookie/request data, document ID, or route fingerprint. There is no page-triggerable privileged overlay action or unbounded reinsertion loop.
- The service worker, popup, and options page each restrict `chrome.storage.local` to trusted extension contexts before their first local read or write. The operation times out fail-closed after five seconds and a later invocation may retry. If Chrome cannot enforce that boundary, the worker keeps passive observation paused, leaves `companionOverlayEnabled` off without loading it, does not hydrate persisted state, removes owned session-recovery shards, and clears its policy-check alarm; the popup cannot load or save companion enablement and disables other local-state and policy-monitoring controls while retaining only analysis that uses no saved local state; and the options page remains disabled without touching local storage.
- Data in `chrome.storage.local` is local browser-profile data, not encrypted vault storage. Profile or extension-DevTools access can expose saved settings, policy URLs, and policy excerpts.
- Observation records have a one-hour logical inactivity expiry enforced by a one-shot cleanup alarm and again on access. Chrome may delay the alarm during sleep, and Manifest V3 suspension may interrupt an asynchronous final write, so physical deletion and capture completeness are best-effort rather than real-time guarantees.
- The six-hour saved-policy alarm is checked and recreated whenever the service worker starts. Automatic runs enforce the interval per URL from the last attempt, falling back to baseline capture time before the first attempt; the explicit “Check changes” action bypasses that interval. Alarm delivery and an entire multi-URL run remain best-effort. Chrome scheduling, sleep, network failures, or worker termination can delay or interrupt checks.
- A credential-free policy fetch is not anonymous. The destination receives the requested URL and ordinary connection metadata, including the user's IP address, user-agent headers, and request time; requests use `cache: "no-store"` and can contact up to 50 explicitly saved URLs per run.
- Private-network literals and common local hostnames are blocked for saved-policy checks, HTTP monitoring URLs are rejected, and redirects are rejected. The extension cannot independently inspect DNS resolution, so HTTPS certificate validation remains part of the boundary; saved monitoring URLs remain an explicit-user feature and fetched markup is processed as untrusted, bounded input.
- Chrome 140 is the minimum supported browser version because safe cookie attribution depends on partitioned-cookie keys and the local-storage trust boundary depends on `chrome.storage.local.setAccessLevel()` support for trusted-only contexts.
