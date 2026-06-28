# Privacy

unveily is designed as a local-first browser extension.

## Data handled by the extension

The extension may read or observe:

- Visible page text from the active tab.
- Terms and privacy policy text pasted by the user.
- Network request metadata such as URL, host, method, request type, query keys, and request body field names.
- Cookie change metadata such as cookie name, domain, security flags, and change reason.
- Browser storage key names from the analyzed page.
- Visible form field metadata such as field name, label, type, placeholder, and required state.
- Visible cookie consent banner text, buttons, and toggles.

The extension is designed to avoid reading or storing form values, cookie values, localStorage values, or sessionStorage values.

## Local storage

The extension stores data in `chrome.storage.local` for features such as:

- User-defined vendor rules.
- Per-site policy snapshots.
- Notification deduplication.
- UI language preference.

These records stay in the user's browser unless the user exports a report or explicitly enables a documented remote feature.

## Network behavior

The extension does not send analyzed content to an external service by default. Background policy checks may fetch URLs that the user has already saved as policy snapshots so changes can be detected locally.

## Exports

Markdown and JSON reports are generated locally and downloaded by the browser. Users should review exported files before sharing them because they may include policy text excerpts, observed domains, or other site-specific metadata.

## Remote features

Any AI or remote analysis feature must require explicit opt-in, clear disclosure of what is sent, and a way to use the extension without that remote feature.
