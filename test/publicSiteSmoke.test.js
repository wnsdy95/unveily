import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const [source, packageText, readme, manualTesting, ciWorkflow, gitignore] = await Promise.all([
  "scripts/smoke-public-sites.mjs",
  "package.json",
  "README.md",
  "MANUAL_TESTING.md",
  ".github/workflows/ci.yml",
  ".gitignore"
].map((file) => readFile(new URL(`../${file}`, import.meta.url), "utf8")));

const packageJson = JSON.parse(packageText);

const expectedTargets = [
  ["naver-privacy", "https://policy.naver.com/policy/privacy.html"],
  ["kakao-privacy", "https://kakao.com/policy/privacy"],
  ["wikipedia-ordinary", "https://www.wikipedia.org/"],
  ["example-ordinary", "https://example.com/"],
  ["apple-privacy-ko", "https://www.apple.com/kr/legal/privacy/kr/"],
  ["ikea-ordinary", "https://www.ikea.com/"],
  ["mdn-csp-ordinary", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP"],
  [
    "github-privacy",
    "https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement"
  ],
  ["google-privacy", "https://policies.google.com/privacy?hl=en-US"],
  ["korea-ordinary", "https://www.korea.kr/"],
  ["notion-ordinary", "https://www.notion.com/product"],
  ["cloudflare-privacy", "https://www.cloudflare.com/policies/privacy/"],
  ["microsoft-privacy", "https://www.microsoft.com/en-us/privacy/privacystatement"],
  ["canva-privacy", "https://www.canva.com/policies/privacy-policy/"],
  ["slack-privacy", "https://slack.com/trust/privacy/privacy-policy"]
];

test("keeps live public-site requests behind explicit manual-only guards", () => {
  assert.equal(packageJson.scripts["test:live-sites"], "node scripts/smoke-public-sites.mjs");
  assert.equal(
    packageJson.scripts["test:live-sites:safety"],
    "node scripts/smoke-public-sites.mjs --safety-preflight-only"
  );
  assert.doesNotMatch(packageJson.scripts["test:live-sites"], /--live/);
  assert.match(source, /const live = argv\.includes\("--live"\)/);
  assert.match(source, /const all = argv\.includes\("--all"\)/);
  assert.match(source, /if \(!live\) throw new Error\([^\n]*explicit --live flag/);
  assert.match(source, /Choose exactly one explicit scope: --all or --only/);
  assert.match(source, /process\.env\.CI \|\| process\.env\.GITHUB_ACTIONS/);
  assert.match(source, /manual-only and refuses to run in CI/);
});

test("keeps the fixed public-site matrix at fifteen validated HTTPS targets", () => {
  const targetBlock = source.match(/const TARGETS = Object\.freeze\(\[([\s\S]*?)\n\]\);/)?.[1];
  assert.ok(targetBlock, "TARGETS must remain a statically reviewable fixed list");

  const targets = [...targetBlock.matchAll(
    /\{\s*id: "([^"]+)",\s*url: "([^"]+)",\s*category: "([^"]+)"/g
  )].map(([, id, url, category]) => ({ id, url, category }));

  assert.equal(targets.length, 15);
  assert.deepEqual(targets.map(({ id, url }) => [id, url]), expectedTargets);
  assert.equal(new Set(targets.map(({ id }) => id)).size, 15);
  assert.equal(new Set(targets.map(({ url }) => url)).size, 15);

  for (const target of targets) {
    const url = new URL(target.url);
    assert.equal(url.protocol, "https:", `${target.id} must use HTTPS`);
    assert.equal(url.username, "", `${target.id} must omit credentials`);
    assert.equal(url.password, "", `${target.id} must omit credentials`);
    assert.equal(url.hash, "", `${target.id} must omit fragments`);
    assert.ok(!url.port || url.port === "443", `${target.id} must use the default HTTPS port`);
  }

  for (const categoryMarker of [
    "ko-policy",
    "en-policy",
    "ordinary-",
    "strict-csp",
    "consent-ui",
    "heavy-spa",
    "heavy-hydration"
  ]) {
    assert.ok(
      targets.some(({ category }) => category.includes(categoryMarker)),
      `target matrix must retain ${categoryMarker} coverage`
    );
  }
  assert.match(targetBlock, /id: "google-privacy"[\s\S]*?allowedQueryKeys: \["hl"\]/);
  assert.match(
    targetBlock,
    /id: "slack-privacy"[\s\S]*?allowedFinalDocumentUrls:[\s\S]*?\/intl\/ko-kr\/trust\/privacy\/privacy-policy/
  );
});

test("keeps live navigation sequential, GET-only, and locally minimized", () => {
  assert.match(source, /for \(const \[targetIndex, target\] of targets\.entries\(\)\) \{/);
  assert.equal((source.match(/\bpage\.goto\s*\(/g) || []).length, 2);
  assert.equal((source.match(/page\.goto\(fixture\.url/g) || []).length, 1);
  assert.equal((source.match(/page\.goto\(target\.url/g) || []).length, 1);
  assert.match(source, /if \(method !== "GET"\) blockedReason = "non_get_method"/);
  assert.match(source, /\["websocket", "eventsource"\]\.includes\(type\)/);
  assert.match(source, /parsed\.protocol !== "https:"/);
  assert.match(source, /isPrivateOrLocalHostname\(parsed\.hostname\)/);
  assert.match(source, /host === "home\.arpa"/);
  assert.match(source, /specialUseHostnameClassifierVerified = true/);
  assert.match(source, /requestAllowedTopLevelOrigins\.has\(parsed\.origin\)/);
  assert.match(source, /request\.abort\("blockedbyclient"\)/);
  assert.match(source, /setBypassServiceWorker\(true\)/);
  assert.match(source, /blocklist: \["ws:\/\/\*\/\*", "wss:\/\/\*\/\*"/);
  assert.match(source, /setDownloadBehavior\(\{ policy: "deny" \}\)/);
  assert.match(source, /monitorUnexpectedNonExtensionTargets/);
  for (const guardedApi of [
    "WebSocket",
    "EventSource",
    "WebTransport",
    "Worker",
    "SharedWorker",
    "RTCPeerConnection",
    "serviceWorkerRegister",
    "sendBeacon",
    "formSubmit",
    "formRequestSubmit",
    "anchorClick",
    "windowOpen"
  ]) {
    assert.match(source, new RegExp(guardedApi));
  }
  assert.match(source, /form\.target = '_blank'/);
  assert.match(source, /form\.method = 'POST'/);
  assert.match(source, /new-target-post/);
  assert.match(source, /unexpectedTargetPreflightVerified = true/);
  assert.doesNotMatch(source, /\bpage\.(?:click|type|tap|select|focus|hover)\s*\(/);
  assert.doesNotMatch(source, /\bpage\.(?:keyboard|mouse|touchscreen)\b/);

  for (const reportInvariant of [
    /sequentialTopLevelTargets: true/,
    /cleanProfilePerRun: true/,
    /cleanProfilePerTarget: false/,
    /crossSiteStateMayCarryWithinRun: true/,
    /httpsThirdPartySubresourcesMayLoad: true/,
    /instrumentedPageAllowedHttpMethods: \["GET"\]/,
    /publicSiteClicks: 0/,
    /publicSiteInputs: 0/,
    /consentActions: 0/,
    /loginActions: 0/,
    /storedRawPageText: false/,
    /storedCookieValues: false/,
    /storedRequestUrls: false/
  ]) {
    assert.match(source, reportInvariant);
  }

  assert.match(source, /join\(REPOSITORY_ROOT, "reports", "public-site-smoke"\)/);
  assert.match(source, /\.local\.json/);
  assert.match(source, /mode: 0o600/);
  assert.match(source, /rm\(profileDirectory, \{ recursive: true, force: true \}\)/);
  assert.doesNotMatch(source, /requestedLocation|finalLocation/);
  assert.match(source, /requestedOrigin/);
  assert.match(source, /finalOrigin/);
  assert.match(source, /GET_ANALYSIS_MODE_PREFERENCE/);
  assert.match(source, /overlay state recovery after service-worker restart/);
  assert.match(source, /const DOCUMENT_HEALTH_PATTERNS = Object\.freeze/);
  assert.match(source, /reviewedDocumentHealth\(/);
  assert.match(source, /expectedFingerprints\.has\(reviewedDocumentFingerprint\(finalUrl\.href\)\)/);
  assert.match(source, /url\.hash = ""/);
  assert.match(source, /"This text cannot be identified reliably as terms or a privacy policy\."/);
  assert.match(source, /\["completed", "not_policy", "error"\]\.includes\(latest\.terminalKind\)/);
  assert.match(source, /state\?\.terminalKind === "completed"/);
  assert.match(source, /state\.terminalKind === "not_policy"/);
  assert.match(source, /a popup analysis error must never pass as not-policy/);
  assert.match(source, /popupTerminalClassifierVerified = true/);
  assert.match(source, /return "inconclusive"/);
  assert.match(source, /\["pass", "warn", "inconclusive", "fail"\]/);
});

test("documents the live-only boundary and keeps it out of CI", () => {
  for (const document of [readme, manualTesting]) {
    assert.match(document, /npm run test:live-sites -- --live --all/);
    assert.match(document, /npm run test:live-sites:safety/);
    assert.match(document, /manual-only|manual public-site smoke/i);
    assert.match(document, /never (?:be )?add(?:ed)? (?:it )?to CI|never CI/i);
    assert.match(document, /public-site clicks/);
    assert.match(document, /text input/);
    assert.match(document, /raw page text/);
    assert.match(document, /cookie values/);
    assert.match(document, /raw request URLs/);
    assert.match(document, /third-party/i);
    assert.match(document, /temporary profile/i);
    assert.match(document, /inconclusive/i);
    assert.match(document, /network sandbox/i);
    assert.match(document, /reports\/public-site-smoke\/\*\.local\.json/);
  }

  assert.equal(packageJson.scripts.test, "node --test");
  assert.doesNotMatch(ciWorkflow, /test:live-sites|smoke-public-sites|--live/);
  assert.match(gitignore, /^reports\/$/m);
  assert.match(gitignore, /^\*\.local\.json$/m);
});
