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
- Captured network and cookie metadata should stay bounded and local.
- New permissions must be justified in the pull request.
- Secrets, private keys, packaged extension signing keys, and local export files must not be committed.
- Remote analysis features, if added later, must require explicit user consent and a documented data flow.
