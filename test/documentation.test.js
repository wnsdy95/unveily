import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [readme, privacy, security, contributing, manualTesting] = await Promise.all(
  ["README.md", "PRIVACY.md", "SECURITY.md", "CONTRIBUTING.md", "MANUAL_TESTING.md"].map((file) =>
    readFile(new URL(`../${file}`, import.meta.url), "utf8")
  )
);
const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));

test("documents policy monitoring network and scheduling boundaries", () => {
  for (const document of [readme, privacy, security]) {
    assert.match(document, /six-hour|six hours/);
    assert.match(document, /no-store/);
    assert.match(document, /IP address/);
    assert.match(document, /user-agent/);
    assert.match(document, /50/);
    assert.match(document, /best-effort/);
  }
  assert.match(manualTesting, /always-visible nearby disclosure/);
  assert.match(manualTesting, /at most once every six hours/);
  assert.match(manualTesting, /“Check changes” may contact it sooner/);
  assert.match(manualTesting, /deleting the saved policy stops monitoring that URL/);
});

test("documents request-body non-collection and the local storage boundary", () => {
  for (const document of [readme, privacy, security]) {
    assert.match(document, /does not (?:ask Chrome for|request Chrome's).*request-body view/i);
    assert.match(document, /raw upload bytes/);
    assert.match(document, /not (?:an )?(?:end-to-end encrypted|encrypted vault)/);
  }
  assert.match(privacy, /one-shot alarm/);
  assert.match(privacy, /logical expiry/);
});

test("documents fail-closed local storage isolation for every extension entry point", () => {
  for (const document of [privacy, security]) {
    assert.match(document, /service worker/);
    assert.match(document, /popup/);
    assert.match(document, /options page/);
    assert.match(document, /before (?:its|their) first local read or write/);
    assert.match(document, /observation paused|observation remains paused/);
  }
  assert.match(manualTesting, /Trusted local-storage isolation failure/);
  assert.match(manualTesting, /setAccessLevel\(\{ accessLevel: "TRUSTED_CONTEXTS" \}\)/);
  assert.match(manualTesting, /zero local reads and writes/);
  assert.match(manualTesting, /persistent isolation warning/);
});

test("documents page-text editing-area exclusions and first-run disclosure", () => {
  for (const document of [readme, privacy, security]) {
    assert.match(document, /editable|editing|user-input/);
    assert.match(document, /form controls|form metadata/);
  }
  assert.match(manualTesting, /textarea/);
  assert.match(manualTesting, /contenteditable/);
  assert.match(manualTesting, /policy-like excerpt reaches the service worker/);
  assert.match(manualTesting, /not stored in observation history or sent remotely/);
});

test("documents hidden-tab DOM idling without overstating the observation pause", () => {
  for (const document of [readme, privacy, security]) {
    assert.match(document, /hidden/i);
    assert.match(document, /disconnect/i);
    assert.match(document, /request\/cookie|request.*cookie/i);
  }
  assert.match(manualTesting, /hidden-tab automatic DOM observer\/timer suspension/);
});

test("documents the opt-in display-only companion overlay and its non-verdict semantics", () => {
  for (const document of [readme, privacy, security]) {
    assert.match(document, /companion overlay|companion-overlay/i);
    assert.match(document, /explicit opt-in|explicitly enable|explicitly enables/i);
    assert.match(document, /display-only/i);
    assert.match(document, /toolbar badge.{0,80}authoritative|authoritative.{0,80}toolbar badge/is);
    assert.match(document, /detect|observable/i);
    assert.match(document, /remove/i);
    assert.match(document, /hide/i);
    assert.match(document, /cover/i);
    assert.match(document, /spoof|imitate/i);
    assert.doesNotMatch(document, /side-panel|side panel/i);
  }
  assert.match(readme, /most recent|latest/);
  assert.match(privacy, /unknown.*does not mean safe/);
  assert.match(privacy, /green at 0, orange at 50, and red at 100/);
  assert.match(privacy, /companionOverlayEnabled/);
  assert.match(privacy, /chrome\.storage\.local/);
  assert.match(privacy, /document-bound companion messaging path/);
  assert.match(security, /never a URL, title, label/);
  assert.match(security, /current top-level `documentId`/);
  assert.match(security, /worker generation.{0,120}per-worker revision/is);
  assert.match(security, /without relying on the wall clock/);
  assert.match(security, /no .*unbounded reinsertion loop/);
  assert.doesNotMatch(security, /runtime port/i);
  assert.match(manualTesting, /0, 25, 50, 75, and 100/);
  assert.match(manualTesting, /role="meter"/);
  assert.match(manualTesting, /older-generation state is rejected/);
  assert.match(manualTesting, /startup broadcast removes the host/);
});

test("documents the automated Chrome companion-overlay E2E and remaining manual release matrix", () => {
  assert.match(readme, /\[MANUAL_TESTING\.md\]\(MANUAL_TESTING\.md\)/);
  assert.match(contributing, /\[MANUAL_TESTING\.md\]\(MANUAL_TESTING\.md\)/);
  for (const document of [readme, contributing, manualTesting]) {
    assert.match(document, /npm run test:e2e:chrome/);
    assert.match(document, /clean temporary profile/);
    assert.match(document, /controlled localhost fixture/);
    assert.match(document, /manual|does not automate|not automate/i);
  }
  assert.equal(packageJson.scripts["test:e2e:chrome"], "node scripts/e2e-companion.mjs");
  for (const heading of [
    "Installation, permissions, and first-run disclosure",
    "Observation, pause, and exclusions",
    "Trusted local-storage isolation failure",
    "Navigation and document isolation",
    "Cookies and consent timing",
    "Manifest V3 restart, persistence, and expiry",
    "Saved-policy fetch and alarm behavior",
    "Report and export redaction",
    "Companion overlay"
  ]) {
    assert.match(manualTesting, new RegExp(heading));
  }
  assert.doesNotMatch(readme, /IP country code is provided by a trusted caller or user setting/);
});

test("keeps the Chrome 140 storage-isolation baseline consistent across release docs", () => {
  for (const document of [readme, security, contributing, manualTesting]) {
    assert.match(document, /Chrome 140/);
  }
});

test("documents reproducible allowlisted release packaging without treating it as a store release", () => {
  for (const document of [readme, contributing, manualTesting]) {
    assert.match(document, /npm run package:extension/);
    assert.match(document, /npm run test:package/);
    assert.match(document, /allowlist/i);
  }
  assert.match(readme, /fixed ZIP metadata/);
  assert.match(readme, /not yet a reviewed or published store release/);
  assert.match(manualTesting, /Extract the generated `dist\/unveily-<version>\.zip`/);
});
