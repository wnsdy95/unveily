# Contributing

Thanks for considering a contribution to unveily.

## Development

1. Clone the repository.
2. Run `npm test`.
3. Run `npm run check`.
4. Load the project folder from `chrome://extensions` with Developer mode enabled.

This project is a Chrome Manifest V3 extension with no backend by default. Keep new features local-first unless there is a clear reason to introduce a remote service.

## Pull requests

- Keep changes focused and easy to review.
- Add or update tests for behavior changes.
- Avoid committing generated files, packaged extension files, local reports, logs, private keys, or browser-specific metadata.
- Do not add external network calls for analysis without explicit user consent and documentation.
- Clearly document user-visible privacy or permission changes.

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

## Reporting issues

When filing a bug, include:

- Browser and operating system.
- Extension version or commit.
- Page type being analyzed, without sharing private policy text unless necessary.
- Expected behavior and actual behavior.
