import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rename, rm, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { isIP } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import puppeteer from "puppeteer-core";

import { documentUrlFingerprint } from "../src/backgroundSecurity.js";
import { riskColorForScore } from "../src/riskColor.js";

const REPOSITORY_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const MINIMUM_CHROME_VERSION = 140;
const DEFAULT_TIMEOUT_MS = 45_000;
const ANALYSIS_MODE_PREFERENCE_KEY = "analysisModePreferenceV1";
const COMPANION_OVERLAY_ENABLED_KEY = "companionOverlayEnabled";
const REPORT_SCHEMA_VERSION = 1;

const TARGETS = Object.freeze([
  {
    id: "naver-privacy",
    url: "https://policy.naver.com/policy/privacy.html",
    category: "ko-policy-static",
    expectedPolicy: true
  },
  {
    id: "kakao-privacy",
    url: "https://kakao.com/policy/privacy",
    category: "ko-policy-dynamic",
    expectedPolicy: true
  },
  {
    id: "wikipedia-ordinary",
    url: "https://www.wikipedia.org/",
    category: "ordinary-static",
    expectedPolicy: false
  },
  {
    id: "example-ordinary",
    url: "https://example.com/",
    category: "ordinary-minimal",
    expectedPolicy: false
  },
  {
    id: "apple-privacy-ko",
    url: "https://www.apple.com/kr/legal/privacy/kr/",
    category: "ko-policy-accordion",
    expectedPolicy: true
  },
  {
    id: "ikea-ordinary",
    url: "https://www.ikea.com/",
    category: "ordinary-csp-consent-ui",
    expectedPolicy: false
  },
  {
    id: "mdn-csp-ordinary",
    url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP",
    category: "ordinary-strict-csp-sentinel",
    expectedPolicy: false
  },
  {
    id: "github-privacy",
    url: "https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement",
    category: "en-policy-csp-docs",
    expectedPolicy: true
  },
  {
    id: "google-privacy",
    url: "https://policies.google.com/privacy?hl=en-US",
    category: "en-policy-locale-query",
    expectedPolicy: true,
    allowedQueryKeys: ["hl"]
  },
  {
    id: "korea-ordinary",
    url: "https://www.korea.kr/",
    category: "ordinary-ko-dynamic",
    expectedPolicy: false
  },
  {
    id: "notion-ordinary",
    url: "https://www.notion.com/product",
    category: "ordinary-heavy-spa",
    expectedPolicy: false
  },
  {
    id: "cloudflare-privacy",
    url: "https://www.cloudflare.com/policies/privacy/",
    category: "en-policy-consent-ui",
    expectedPolicy: true
  },
  {
    id: "microsoft-privacy",
    url: "https://www.microsoft.com/en-us/privacy/privacystatement",
    category: "en-policy-large",
    expectedPolicy: true
  },
  {
    id: "canva-privacy",
    url: "https://www.canva.com/policies/privacy-policy/",
    category: "en-policy-heavy-hydration",
    expectedPolicy: true
  },
  {
    id: "slack-privacy",
    url: "https://slack.com/trust/privacy/privacy-policy",
    category: "en-policy-locale-redirect",
    expectedPolicy: true,
    allowedFinalDocumentUrls: [
      "https://slack.com/trust/privacy/privacy-policy",
      "https://slack.com/intl/ko-kr/trust/privacy/privacy-policy"
    ]
  }
]);

const DOCUMENT_HEALTH_PATTERNS = Object.freeze({
  "naver-privacy": /(?:개인정보\s*처리방침|privacy)/iu,
  "kakao-privacy": /(?:개인정보\s*처리방침|privacy)/iu,
  "wikipedia-ordinary": /wikipedia/iu,
  "example-ordinary": /example\s+domain/iu,
  "apple-privacy-ko": /(?:apple.{0,40}개인정보|개인정보.{0,40}apple|privacy)/iu,
  "ikea-ordinary": /ikea/iu,
  "mdn-csp-ordinary": /(?:content\s+security\s+policy|\bcsp\b)/iu,
  "github-privacy": /(?:github.{0,80}privacy|privacy.{0,80}github)/iu,
  "google-privacy": /(?:google.{0,80}privacy|privacy.{0,80}google)/iu,
  "korea-ordinary": /(?:대한민국\s*정책브리핑|정책브리핑)/iu,
  "notion-ordinary": /notion/iu,
  "cloudflare-privacy": /(?:cloudflare.{0,80}privacy|privacy.{0,80}cloudflare)/iu,
  "microsoft-privacy": /(?:microsoft.{0,80}privacy|privacy.{0,80}microsoft)/iu,
  "canva-privacy": /(?:canva.{0,80}privacy|privacy.{0,80}canva)/iu,
  "slack-privacy": /(?:slack.{0,80}privacy|privacy.{0,80}slack|개인정보\s*처리방침)/iu
});

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function waitFor(check, { timeoutMs = DEFAULT_TIMEOUT_MS, intervalMs = 150, label } = {}) {
  const deadline = Date.now() + timeoutMs;
  let lastError = null;
  while (Date.now() < deadline) {
    try {
      const value = await check();
      if (value) return value;
    } catch (error) {
      lastError = error;
    }
    await delay(intervalMs);
  }
  const suffix = lastError ? ` Last error: ${lastError.message}` : "";
  throw new Error(`Timed out waiting for ${label || "condition"}.${suffix}`);
}

async function withTimeout(promise, label, timeoutMs = DEFAULT_TIMEOUT_MS) {
  let timeoutId;
  try {
    return await Promise.race([
      promise,
      new Promise((_, reject) => {
        timeoutId = setTimeout(() => reject(new Error(`Timed out during ${label}.`)), timeoutMs);
      })
    ]);
  } finally {
    clearTimeout(timeoutId);
  }
}

function chromeCandidates() {
  const configured = process.env.E2E_CHROME_PATH || process.env.CHROME_PATH;
  const candidates = configured ? [configured] : [];
  if (process.platform === "darwin") {
    candidates.push(
      "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
      "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary"
    );
  } else if (process.platform === "win32") {
    for (const root of [process.env.PROGRAMFILES, process.env["PROGRAMFILES(X86)"], process.env.LOCALAPPDATA]) {
      if (root) candidates.push(join(root, "Google", "Chrome", "Application", "chrome.exe"));
    }
  } else {
    candidates.push(
      "/usr/bin/google-chrome",
      "/usr/bin/google-chrome-stable",
      "/usr/bin/chromium",
      "/usr/bin/chromium-browser"
    );
  }
  return candidates;
}

function resolveChrome() {
  const executablePath = chromeCandidates().find((candidate) => candidate && existsSync(candidate));
  if (!executablePath) throw new Error("Chrome was not found. Set E2E_CHROME_PATH.");
  const versionResult = spawnSync(executablePath, ["--version"], { encoding: "utf8" });
  const versionText = `${versionResult.stdout || ""} ${versionResult.stderr || ""}`.trim();
  const majorVersion = Number(/(?:Chrome|Chromium)\s+(\d+)/i.exec(versionText)?.[1]);
  if (!Number.isInteger(majorVersion) || majorVersion < MINIMUM_CHROME_VERSION) {
    throw new Error(`Chrome ${MINIMUM_CHROME_VERSION}+ is required; found ${versionText || "unknown"}.`);
  }
  return { executablePath, majorVersion, versionText };
}

function parseArguments(argv) {
  const live = argv.includes("--live");
  const all = argv.includes("--all");
  const headed = argv.includes("--headed");
  const safetyPreflightOnly = argv.includes("--safety-preflight-only");
  const onlyArguments = argv.filter((argument) => argument.startsWith("--only="));
  const onlyArgument = onlyArguments[0];
  const unknownArguments = argv.filter(
    (argument) =>
      !["--live", "--all", "--headed", "--safety-preflight-only"].includes(argument) &&
      !argument.startsWith("--only=")
  );
  const only = new Set(
    String(onlyArgument?.slice("--only=".length) || "")
      .split(",")
      .map((value) => value.trim())
      .filter(Boolean)
  );
  if (safetyPreflightOnly) {
    if (live || all || onlyArgument || unknownArguments.length > 0) {
      throw new Error("--safety-preflight-only cannot be combined with a live public-site scope.");
    }
    return { headed, targets: [], safetyPreflightOnly: true };
  }
  if (!live) throw new Error("Public-site requests require the explicit --live flag.");
  if (process.env.CI || process.env.GITHUB_ACTIONS) {
    throw new Error("The public-site smoke test is manual-only and refuses to run in CI.");
  }
  if (unknownArguments.length > 0 || onlyArguments.length > 1) {
    throw new Error("Unknown or repeated public-site smoke argument.");
  }
  if (all === Boolean(onlyArgument)) {
    throw new Error("Choose exactly one explicit scope: --all or --only=<target-id,...>.");
  }
  if (onlyArgument && only.size === 0) {
    throw new Error("--only must contain at least one public-site target id.");
  }
  const targets = all ? [...TARGETS] : TARGETS.filter((target) => only.has(target.id));
  if (targets.length === 0 || targets.length !== (only.size || targets.length)) {
    throw new Error("--only contains an unknown or empty public-site target id.");
  }
  return { headed, targets, safetyPreflightOnly: false };
}

function validateTarget(target) {
  const url = new URL(target.url);
  assert.equal(url.protocol, "https:", `${target.id} must use HTTPS`);
  assert.equal(url.username, "", `${target.id} must not contain credentials`);
  assert.equal(url.password, "", `${target.id} must not contain credentials`);
  assert.equal(url.hash, "", `${target.id} must not contain a fragment`);
  assert.ok(!url.port || url.port === "443", `${target.id} must use the default HTTPS port`);
  const allowedQueryKeys = new Set(target.allowedQueryKeys || []);
  for (const key of url.searchParams.keys()) {
    assert.ok(allowedQueryKeys.has(key), `${target.id} contains an unapproved query key`);
  }
  assert.ok(
    DOCUMENT_HEALTH_PATTERNS[target.id] instanceof RegExp,
    `${target.id} must have an in-memory document health marker`
  );
  for (const finalUrl of target.allowedFinalDocumentUrls || [target.url]) {
    const parsedFinalUrl = new URL(finalUrl);
    assert.equal(parsedFinalUrl.protocol, "https:", `${target.id} final document must use HTTPS`);
    assert.ok(
      parsedFinalUrl.origin === url.origin || (target.allowedTopLevelOrigins || []).includes(parsedFinalUrl.origin),
      `${target.id} final document origin must be explicitly approved`
    );
  }
}

function safeOrigin(rawUrl) {
  try {
    return new URL(rawUrl).origin;
  } catch {
    return "";
  }
}

function isPrivateOrLocalHostname(hostname) {
  const host = String(hostname || "")
    .toLowerCase()
    .replace(/^\[|\]$/gu, "")
    .replace(/\.+$/gu, "");
  if (!host) return true;
  const specialUseSuffixes = [
    ".corp",
    ".example",
    ".home",
    ".home.arpa",
    ".internal",
    ".invalid",
    ".lan",
    ".local",
    ".localdomain",
    ".localhost",
    ".onion",
    ".test"
  ];
  return (
    isIP(host) > 0 ||
    !host.includes(".") ||
    host === "localhost" ||
    host === "local" ||
    host === "home.arpa" ||
    specialUseSuffixes.some((suffix) => host.endsWith(suffix))
  );
}

function verifyLocalHostnameClassifier(report) {
  for (const hostname of [
    "localhost",
    "intranet",
    "home.arpa",
    "device.home.arpa",
    "service.internal",
    "router.lan",
    "site.local"
  ]) {
    assert.equal(isPrivateOrLocalHostname(hostname), true, `${hostname} must remain blocked`);
  }
  for (const hostname of ["example.com", "www.wikipedia.org", "policies.google.com"]) {
    assert.equal(isPrivateOrLocalHostname(hostname), false, `${hostname} must remain public`);
  }
  report.safety.specialUseHostnameClassifierVerified = true;
}

function redactErrorMessage(value, privatePaths = []) {
  let message = String(value || "unknown failure");
  for (const privatePath of [REPOSITORY_ROOT, ...privatePaths]) {
    if (privatePath) message = message.replaceAll(privatePath, "[redacted-path]");
  }
  return message
    .replace(/\b[a-z][a-z0-9+.-]*:\/\/[^\s"'<>]+/giu, "[redacted-url]")
    .replace(/\b[A-Z]:\\[^\s"'<>]+/giu, "[redacted-path]")
    .slice(0, 500);
}

function incrementCounter(record, key) {
  record[key] = (record[key] || 0) + 1;
}

function reviewedDocumentFingerprint(rawUrl) {
  try {
    const url = new URL(rawUrl);
    url.hash = "";
    return documentUrlFingerprint(url.href);
  } catch {
    return "";
  }
}

async function reviewedDocumentHealth(page, target, httpStatus, finalOriginAllowed) {
  const expectedUrls = (target.allowedFinalDocumentUrls || [target.url]).map(
    (rawUrl) => new URL(rawUrl)
  );
  const expectedFingerprints = new Set(
    expectedUrls.map((url) => reviewedDocumentFingerprint(url.href))
  );
  const finalUrl = new URL(page.url());
  const finalDocumentReviewed = expectedFingerprints.has(reviewedDocumentFingerprint(finalUrl.href));
  const withoutTrailingSlash = (pathname) => pathname === "/" ? "/" : pathname.replace(/\/$/u, "");
  const exactPathCandidate = expectedUrls.some(
    (expected) => expected.origin === finalUrl.origin && expected.pathname === finalUrl.pathname
  );
  const trailingSlashOnlyCandidate = expectedUrls.some(
    (expected) =>
      expected.origin === finalUrl.origin &&
      expected.pathname !== finalUrl.pathname &&
      withoutTrailingSlash(expected.pathname) === withoutTrailingSlash(finalUrl.pathname) &&
      expected.search === finalUrl.search
  );
  const queryOnlyDifference = expectedUrls.some(
    (expected) =>
      expected.origin === finalUrl.origin &&
      expected.pathname === finalUrl.pathname &&
      expected.search !== finalUrl.search
  );
  const pattern = DOCUMENT_HEALTH_PATTERNS[target.id];
  let markerPresent = false;
  if (finalDocumentReviewed) {
    markerPresent = Boolean(
      await waitFor(
        () =>
          page.evaluate(({ source, flags }) => {
            const text = `${document.title || ""}\n${(document.body?.innerText || "").slice(0, 2_000_000)}`;
            return new RegExp(source, flags).test(text);
          }, { source: pattern.source, flags: pattern.flags }),
        { timeoutMs: 10_000, label: `${target.id} reviewed document marker` }
      ).catch(() => false)
    );
  }
  const statusAccepted = httpStatus >= 200 && httpStatus < 300;
  return {
    statusAccepted,
    finalOriginAllowed,
    finalDocumentReviewed,
    markerPresent,
    differenceSummary: {
      exactPathCandidate,
      trailingSlashOnlyCandidate,
      queryOnlyDifference,
      finalHasQuery: finalUrl.search.length > 0,
      finalHasFragment: finalUrl.hash.length > 0
    },
    established:
      statusAccepted && finalOriginAllowed && finalDocumentReviewed && markerPresent
  };
}

async function installPublicPageApiGuards(page) {
  await page.setBypassServiceWorker(true);
  await page.evaluateOnNewDocument(() => {
    const guardState = {};
    const blockedConstructor = function BlockedPublicSmokeTransport() {
      throw new DOMException("Blocked by the public-site smoke safety boundary", "SecurityError");
    };
    const blockGlobal = (name) => {
      if (!(name in globalThis)) return true;
      try {
        Object.defineProperty(globalThis, name, {
          value: blockedConstructor,
          writable: false,
          configurable: false
        });
        return globalThis[name] === blockedConstructor;
      } catch {
        return false;
      }
    };
    const blockPrototypeMethod = (constructorName, methodName, replacement) => {
      const prototype = globalThis[constructorName]?.prototype;
      if (!prototype || typeof prototype[methodName] !== "function") return true;
      try {
        Object.defineProperty(prototype, methodName, {
          value: replacement,
          writable: false,
          configurable: false
        });
        return prototype[methodName] === replacement;
      } catch {
        return false;
      }
    };
    const blockedOperation = () => {
      throw new DOMException("Blocked by the public-site smoke safety boundary", "SecurityError");
    };

    for (const name of [
      "WebSocket",
      "EventSource",
      "WebTransport",
      "Worker",
      "SharedWorker",
      "RTCPeerConnection",
      "webkitRTCPeerConnection"
    ]) {
      guardState[name] = blockGlobal(name);
    }
    const rejectServiceWorkerRegistration = () =>
      Promise.reject(
        new DOMException("Blocked by the public-site smoke safety boundary", "SecurityError")
      );
    guardState.serviceWorkerRegister = blockPrototypeMethod(
      "ServiceWorkerContainer",
      "register",
      rejectServiceWorkerRegistration
    );
    guardState.sendBeacon = blockPrototypeMethod("Navigator", "sendBeacon", () => false);
    guardState.formSubmit = blockPrototypeMethod(
      "HTMLFormElement",
      "submit",
      blockedOperation
    );
    guardState.formRequestSubmit = blockPrototypeMethod(
      "HTMLFormElement",
      "requestSubmit",
      blockedOperation
    );
    guardState.anchorClick = blockPrototypeMethod(
      "HTMLAnchorElement",
      "click",
      blockedOperation
    );
    const preventDefault = Event.prototype.preventDefault;
    const stopImmediatePropagation = Event.prototype.stopImmediatePropagation;
    const blockActivation = (event) => {
      preventDefault.call(event);
      stopImmediatePropagation.call(event);
    };
    globalThis.addEventListener("click", blockActivation, true);
    globalThis.addEventListener("submit", blockActivation, true);
    guardState.activationEvents = true;
    guardState.windowOpen = (() => {
      try {
        Object.defineProperty(globalThis, "open", {
          value: () => null,
          writable: false,
          configurable: false
        });
        return true;
      } catch {
        return false;
      }
    })();
    Object.defineProperty(globalThis, "__unveilyPublicSmokeApiGuards", {
      value: Object.freeze({ ...guardState }),
      writable: false,
      configurable: false
    });
  });
}

function monitorUnexpectedNonExtensionTargets(browser, primaryPage) {
  const events = [];
  const pending = new Set();
  let inspectionErrors = 0;
  const guardedTypes = new Set(["page", "service_worker", "shared_worker", "worker"]);
  const listener = (target) => {
    if (target === primaryPage.target()) return;
    const inspection = (async () => {
      await delay(50);
      const type = target.type();
      const url = target.url();
      if (!guardedTypes.has(type) || url.startsWith("chrome-extension://")) return;
      events.push(type);
      try {
        if (type === "page") {
          const unexpectedPage = await target.asPage();
          if (unexpectedPage && !unexpectedPage.isClosed()) await unexpectedPage.close();
          return;
        }
        const unexpectedWorker = await target.worker();
        if (unexpectedWorker) await unexpectedWorker.close();
      } catch {
        inspectionErrors += 1;
      }
    })();
    pending.add(inspection);
    void inspection.finally(() => pending.delete(inspection));
  };
  browser.on("targetcreated", listener);
  return {
    checkpoint: () => ({ eventCount: events.length, inspectionErrors }),
    async changesSince(checkpoint) {
      await Promise.allSettled([...pending]);
      return {
        types: events.slice(checkpoint.eventCount),
        inspectionErrors: inspectionErrors - checkpoint.inspectionErrors
      };
    },
    stop() {
      browser.off("targetcreated", listener);
    }
  };
}

async function startSafetyPreflightServer() {
  const observations = [];
  const sockets = new Set();
  const server = createServer((request, response) => {
    const pathname = new URL(request.url || "/", "http://127.0.0.1").pathname;
    observations.push({ method: String(request.method || ""), pathname });
    if (pathname === "/probe") {
      response.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store"
      });
      response.end(`<!doctype html><meta charset="utf-8"><script>
        (async () => {
          const attempt = (callback) => { try { callback(); } catch {} };
          if (navigator.serviceWorker) {
            try { await navigator.serviceWorker.register('/sw.js'); } catch {}
          }
          attempt(() => new WebSocket('ws://' + location.host + '/socket'));
          attempt(() => new EventSource('/events'));
          attempt(() => new Worker('/worker.js'));
          attempt(() => new SharedWorker('/shared.js'));
          attempt(() => navigator.sendBeacon('/beacon', 'blocked'));
          attempt(() => {
            const form = document.createElement('form');
            form.method = 'POST';
            form.target = '_blank';
            form.action = '/new-target-post';
            document.documentElement.append(form);
            form.submit();
          });
          attempt(() => {
            const anchor = document.createElement('a');
            anchor.href = '/new-target-get';
            anchor.target = '_blank';
            document.documentElement.append(anchor);
            anchor.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true }));
          });
          globalThis.__unveilySafetyProbeComplete = true;
        })();
      </script>`);
      return;
    }
    if (pathname === "/sw.js") {
      response.writeHead(200, { "content-type": "text/javascript", "cache-control": "no-store" });
      response.end("fetch('/sw-post', { method: 'POST', body: 'blocked' });");
      return;
    }
    if (["/worker.js", "/shared.js"].includes(pathname)) {
      response.writeHead(200, { "content-type": "text/javascript", "cache-control": "no-store" });
      response.end("fetch('/worker-post', { method: 'POST', body: 'blocked' });");
      return;
    }
    response.writeHead(204, { "cache-control": "no-store" });
    response.end();
  });
  server.on("upgrade", (request, socket) => {
    observations.push({ method: "UPGRADE", pathname: new URL(request.url || "/", "http://127.0.0.1").pathname });
    socket.destroy();
  });
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object", "safety preflight server must bind locally");
  return {
    url: `http://127.0.0.1:${address.port}/probe`,
    observations,
    close: async () => {
      server.closeAllConnections?.();
      for (const socket of sockets) socket.destroy();
      await withTimeout(
        new Promise((resolve, reject) => {
          server.close((error) => (error ? reject(error) : resolve()));
        }),
        "local safety preflight server close",
        5_000
      );
    }
  };
}

async function verifyRuntimeSafetyBoundary(page, report, fixture) {
  try {
    await page.goto(fixture.url, { waitUntil: "domcontentloaded", timeout: DEFAULT_TIMEOUT_MS });
    await page.waitForFunction(() => globalThis.__unveilySafetyProbeComplete === true, {
      timeout: 10_000
    });
    const guards = await page.evaluate(() => globalThis.__unveilyPublicSmokeApiGuards || null);
    assert.ok(guards && Object.values(guards).every(Boolean), "every public-page API guard must install");
    await page.evaluate(async () => {
      try {
        await fetch("/page-post", { method: "POST", body: "blocked" });
      } catch {
        // The GET-only request interceptor must reject this probe.
      }
    });
    await delay(300);
    const unexpectedBeforeInterception = fixture.observations.filter(
      ({ pathname }) => !["/probe", "/favicon.ico"].includes(pathname)
    );
    assert.equal(
      unexpectedBeforeInterception.length,
      0,
      "service worker, worker, beacon, event stream, and WebSocket probes must stay local"
    );
    report.safety.runtimeApiGuardsVerified = true;
    report.safety.serviceWorkerAndStreamingPreflightVerified = true;
    report.safety.pageGetOnlyPreflightVerified = true;
    report.safety.newTargetNavigationPreflightVerified = true;
  } finally {
    await fixture.close();
  }
}

async function extensionWorker(browser, extensionId, excludedTarget = null) {
  const existing = browser
    .targets()
    .find(
      (target) =>
        target !== excludedTarget &&
        target.type() === "service_worker" &&
        target.url() === `chrome-extension://${extensionId}/src/background.js`
    );
  const target =
    existing ||
    (await browser.waitForTarget(
      (candidate) =>
        candidate !== excludedTarget &&
        candidate.type() === "service_worker" &&
        candidate.url() === `chrome-extension://${extensionId}/src/background.js`,
      { timeout: DEFAULT_TIMEOUT_MS }
    ));
  const worker = await target.worker();
  assert.ok(worker, "extension service worker target must expose a worker");
  return { target, worker };
}

async function activeTab(worker) {
  const tab = await worker.evaluate(async () => {
    const [current] = await chrome.tabs.query({ active: true, currentWindow: true });
    return current || null;
  });
  assert.ok(Number.isInteger(tab?.id), "active Chrome tab is unavailable");
  return tab;
}

async function activatePageTab(worker, page) {
  await page.bringToFront();
  const tab = await waitFor(
    async () => {
      const candidate = await activeTab(worker);
      return documentUrlFingerprint(candidate.url) === documentUrlFingerprint(page.url())
        ? candidate
        : null;
    },
    { label: "public page to become the active Chrome tab" }
  );
  await worker.evaluate(async (tabId) => chrome.tabs.update(tabId, { active: true }), tab.id);
  return tab;
}

async function openPopup({ browser, extension, extensionId, page }) {
  const existingTargets = new Set(browser.targets());
  const targetPromise = browser.waitForTarget(
    (target) =>
      !existingTargets.has(target) &&
      target.url() === `chrome-extension://${extensionId}/src/popup.html`,
    { timeout: DEFAULT_TIMEOUT_MS }
  );
  await withTimeout(page.triggerExtensionAction(extension), "extension action trigger", 10_000);
  const target = await targetPromise;
  const popup = await target.asPage();
  await popup.waitForSelector("#analyzePageButton", { timeout: DEFAULT_TIMEOUT_MS });
  return popup;
}

async function closePopup(popup) {
  if (!popup || popup.isClosed()) return;
  await withTimeout(popup.close(), "popup close", 5_000);
}

async function popupState(popup) {
  return popup.evaluate(() => {
    const result = document.querySelector("#result");
    const meter = result?.querySelector("meter") || null;
    const status = document.querySelector("#status");
    const source = document.querySelector("#sourceLabel")?.textContent?.trim() || "";
    const scoreCard = result?.querySelector(".score-card") || null;
    const modes = Object.fromEntries(
      Array.from(document.querySelectorAll(".mode-button"), (button) => [
        button.dataset.mode,
        button.getAttribute("aria-pressed") === "true"
      ])
    );
    const statusText = status?.textContent?.trim() || "";
    const busy = /읽는 중|분석하는 중|Reading|Analyzing/i.test(statusText);
    const notPolicy = new Set([
      "현재 텍스트를 약관 또는 개인정보처리방침으로 신뢰하기 어렵습니다.",
      "This text cannot be identified reliably as terms or a privacy policy."
    ]).has(statusText);
    const completed =
      /분석 완료|Analysis complete/i.test(statusText) &&
      (result?.childElementCount || 0) > 0;
    const terminalKind = busy
      ? "busy"
      : notPolicy
        ? "not_policy"
        : completed
          ? "completed"
          : status?.classList.contains("error")
            ? "error"
            : "pending";
    return {
      mode: Object.entries(modes).find(([, pressed]) => pressed)?.[0] || "",
      busy,
      terminalKind,
      statusPresent: statusText.length > 0,
      statusError: Boolean(status?.classList.contains("error")),
      sourceResolved: Boolean(source && !["현재 페이지", "Current page"].includes(source)),
      resultChildCount: result?.childElementCount || 0,
      resultTextLength: result?.textContent?.replace(/\s+/g, " ").trim().length || 0,
      score: meter && Number.isFinite(Number(meter.value)) ? Number(meter.value) : null,
      level: /(?:^|\s)level-(low|medium|high)(?:\s|$)/u.exec(scoreCard?.className || "")?.[1] || "unknown",
      meterMin: meter?.getAttribute("min") || "",
      meterMax: meter?.getAttribute("max") || ""
    };
  });
}

async function waitForPopupAnalysis(popup, expectedMode) {
  let latest = null;
  try {
    return await waitFor(
      async () => {
        latest = await popupState(popup);
        const terminal =
          latest.mode === expectedMode &&
          latest.statusPresent &&
          ["completed", "not_policy", "error"].includes(latest.terminalKind);
        return terminal ? latest : null;
      },
      { label: `${expectedMode} analysis to reach a terminal popup state` }
    );
  } catch (error) {
    throw new Error(`${error.message} Last popup state: ${JSON.stringify(latest)}`);
  }
}

async function waitForPopupToggle(popup, enabled) {
  await popup.waitForFunction(
    (expected) => {
      const button = document.querySelector("#companionOverlayToggleButton");
      return button && !button.disabled && button.getAttribute("aria-pressed") === String(expected);
    },
    { timeout: DEFAULT_TIMEOUT_MS },
    enabled
  );
}

async function enableOverlayFromPopup(popup) {
  await waitForPopupToggle(popup, false);
  await popup.click("#companionOverlayToggleButton");
  await waitForPopupToggle(popup, true);
  const preference = await popup.evaluate(async (storageKey) => ({
    stored: (await chrome.storage.local.get(storageKey))?.[storageKey],
    runtime: await chrome.runtime.sendMessage({ type: "GET_COMPANION_OVERLAY_PREFERENCE" })
  }), COMPANION_OVERLAY_ENABLED_KEY);
  assert.deepEqual(preference, { stored: true, runtime: { ok: true, enabled: true } });
}

async function verifyPopupScrolling(popup) {
  const before = await popup.evaluate(() => {
    const scrollingElement = document.scrollingElement || document.documentElement;
    scrollingElement.scrollTop = 0;
    return {
      scrollHeight: scrollingElement.scrollHeight,
      clientHeight: scrollingElement.clientHeight
    };
  });
  await popup.mouse.move(200, 300);
  await popup.mouse.wheel({ deltaY: Math.max(800, before.scrollHeight) });
  const after = await waitFor(
    () => popup.evaluate(() => (document.scrollingElement || document.documentElement).scrollTop || 0),
    { timeoutMs: 10_000, label: "popup wheel scrolling" }
  );
  return {
    scrollable: before.scrollHeight > before.clientHeight,
    scrolled: after > 0,
    scrollHeight: before.scrollHeight,
    clientHeight: before.clientHeight
  };
}

async function switchModeAndClose(popup, nextMode) {
  const selector = nextMode === "cookies" ? "#analyzeCookiesButton" : "#analyzePageButton";
  await popup.click(selector);
  await closePopup(popup);
}

async function waitForStoredMode(extensionPage, expectedMode) {
  return waitFor(
    () =>
      extensionPage.evaluate(async ({ key, expected }) => {
        const stored = await chrome.storage.local.get(key);
        return stored?.[key] === expected;
      }, { key: ANALYSIS_MODE_PREFERENCE_KEY, expected: expectedMode }),
    { timeoutMs: 10_000, label: `stored analysis mode ${expectedMode}` }
  );
}

async function observationSummary(popup, tabId, expectedDocumentFingerprint) {
  return popup.evaluate(async ({ targetTabId, expectedFingerprint }) => {
    const response = await chrome.runtime.sendMessage({ type: "GET_NETWORK_ACTIVITY", tabId: targetTabId });
    return {
      ok: response?.ok === true,
      observationEnabled: response?.observationEnabled === true,
      requestCount: Array.isArray(response?.requests) ? response.requests.length : 0,
      cookieCount: Array.isArray(response?.cookies) ? response.cookies.length : 0,
      sessionMatchesActiveDocument:
        typeof expectedFingerprint === "string" &&
        expectedFingerprint.length > 0 &&
        response?.session?.documentFingerprint === expectedFingerprint
    };
  }, { targetTabId: tabId, expectedFingerprint: expectedDocumentFingerprint });
}

async function contentReceiverState(worker, tabId) {
  return worker.evaluate(async (targetTabId) => {
    try {
      const response = await chrome.tabs.sendMessage(targetTabId, { type: "PAGE_CONTEXT_CHANGED" });
      return { responded: true, observationActive: response?.ok === true };
    } catch {
      return { responded: false, observationActive: false };
    }
  }, tabId);
}

async function waitForContentReceiver(worker, tabId) {
  return waitFor(
    async () => {
      const state = await contentReceiverState(worker, tabId);
      return state.responded ? state : null;
    },
    { label: `content receiver on tab ${tabId}` }
  );
}

async function overlayState(worker, tabId) {
  return worker.evaluate(async (targetTabId) => {
    const results = await chrome.scripting.executeScript({
      target: { tabId: targetTabId, frameIds: [0] },
      world: "ISOLATED",
      func: () => {
        const api = globalThis.__unveilyCompanionOverlay;
        const ownedHosts = globalThis.__unveilyCompanionOverlayOwnedHosts;
        const hosts = ownedHosts
          ? Array.from(document.querySelectorAll("*")).filter((element) => ownedHosts.has(element))
          : [];
        const host = hosts[0] || null;
        const rect = host?.getBoundingClientRect();
        const style = host ? getComputedStyle(host) : null;
        return {
          apiAvailable: Boolean(api?.snapshot),
          ownedHostCount: hosts.length,
          snapshot: api?.snapshot?.() || null,
          viewportHeight: innerHeight,
          host: host
            ? {
                shadowRootIsNull: host.shadowRoot === null,
                childElementCount: host.childElementCount,
                exposedStateAttributeCount: Array.from(host.attributes).filter(
                  (attribute) =>
                    attribute.name === "role" ||
                    attribute.name.startsWith("aria-") ||
                    attribute.name.startsWith("data-")
                ).length,
                left: rect.left,
                bottomGap: innerHeight - rect.bottom,
                width: rect.width,
                height: rect.height,
                position: style.position,
                pointerEvents: style.pointerEvents,
                zIndex: style.zIndex
              }
            : null
        };
      }
    });
    return results[0]?.result || null;
  }, tabId);
}

async function waitForOverlayMatchingPopup(worker, tabId, popup, expectedMode) {
  const expectedSource = expectedMode === "cookies" ? "cookie-analysis" : "page-analysis";
  return waitFor(
    async () => {
      const state = await overlayState(worker, tabId);
      const snapshot = state?.snapshot;
      const resultMatches = popup.score === null
        ? snapshot?.score === null && snapshot?.source === "none" && snapshot?.status === "unknown"
        : snapshot?.score === popup.score &&
          snapshot?.source === expectedSource &&
          snapshot?.status === "ready" &&
          snapshot?.color === riskColorForScore(popup.score);
      return snapshot?.enabled === true &&
        snapshot?.mounted === true &&
        state.ownedHostCount === 1 &&
        resultMatches
        ? state
        : null;
    },
    { label: `${expectedMode} popup result in the companion overlay on tab ${tabId}` }
  );
}

async function waitForFreshNavigationOverlay(worker, tabId) {
  const explicitSources = new Set(["page-analysis", "cookie-analysis"]);
  return waitFor(
    async () => {
      const state = await overlayState(worker, tabId);
      const source = state?.snapshot?.source || "none";
      return state?.snapshot?.enabled === true &&
        state?.snapshot?.mounted === true &&
        state.ownedHostCount === 1 &&
        !explicitSources.has(source)
        ? state
        : null;
    },
    { label: `fresh navigation overlay state on tab ${tabId}` }
  );
}

function overlayChecks(state, popup, expectedMode) {
  const snapshot = state?.snapshot || {};
  const host = state?.host;
  const checks = {
    oneOwnedHost: state?.ownedHostCount === 1,
    enabledAndMounted: snapshot.enabled === true && snapshot.mounted === true,
    validStamp:
      Number.isSafeInteger(snapshot.generation) &&
      snapshot.generation >= 1 &&
      Number.isSafeInteger(snapshot.revision) &&
      snapshot.revision >= 0,
    protocolHealthy: snapshot.protocolFailedClosed === false,
    closedIsolatedHost:
      host?.shadowRootIsNull === true &&
      host?.childElementCount === 0 &&
      host?.exposedStateAttributeCount === 0,
    fixedLayout:
      host?.position === "fixed" &&
      host?.left === 16 &&
      host?.bottomGap === 16 &&
      host?.width === 56 &&
      host?.height === 56 &&
      host?.pointerEvents === "none" &&
      host?.zIndex === "2147483647",
    sourceMatchesPopupMode:
      popup.score === null
        ? snapshot.source === "none"
        : snapshot.source === (expectedMode === "cookies" ? "cookie-analysis" : "page-analysis"),
    scoreMatchesPopup:
      popup.score === null
        ? snapshot.score === null && snapshot.status === "unknown" && snapshot.role === "status"
        : snapshot.score === popup.score &&
          snapshot.status === "ready" &&
          snapshot.role === "meter" &&
          snapshot.ariaValueNow === String(popup.score) &&
          snapshot.color === riskColorForScore(popup.score)
  };
  return checks;
}

function rgbaForHex(hex) {
  const match = /^#([0-9a-f]{2})([0-9a-f]{2})([0-9a-f]{2})$/iu.exec(String(hex || ""));
  if (!match) return null;
  return [Number.parseInt(match[1], 16), Number.parseInt(match[2], 16), Number.parseInt(match[3], 16), 255];
}

async function badgeState(worker, tabId) {
  return worker.evaluate(async (targetTabId) => ({
    text: await chrome.action.getBadgeText({ tabId: targetTabId }),
    color: await chrome.action.getBadgeBackgroundColor({ tabId: targetTabId })
  }), tabId);
}

function badgeChecks(state, score, level) {
  if (score === null) {
    return {
      textMatchesScore: state?.text === "",
      colorMatchesScore: true
    };
  }
  const expectedText = level === "low" ? "L" : level === "medium" ? "!" : level === "high" ? "H" : "";
  return {
    textMatchesScore: Boolean(expectedText) && state?.text === expectedText,
    colorMatchesScore:
      JSON.stringify(state?.color || null) === JSON.stringify(rgbaForHex(riskColorForScore(score)))
  };
}

function popupChecks(state, expectedPolicy) {
  const hasNumericScore = Number.isFinite(state?.score) && state.score >= 0 && state.score <= 100;
  return {
    pageModeSelected: state?.mode === "page",
    pageSourceResolved: state?.sourceResolved === true,
    expectedPolicyScored: !expectedPolicy || hasNumericScore,
    terminalKindValid:
      state?.terminalKind === "not_policy" || state?.terminalKind === "completed",
    meterBoundsValid:
      !hasNumericScore || (state.meterMin === "0" && state.meterMax === "100"),
    resultShapeValid:
      hasNumericScore
        ? state.terminalKind === "completed" &&
          state.statusError === false &&
          state.resultChildCount > 0 &&
          state.resultTextLength > 100 &&
          ["low", "medium", "high"].includes(state.level)
        : state.terminalKind === "not_policy" &&
          state.statusError === true &&
          state.resultChildCount === 0 &&
          state.level === "unknown"
  };
}

function verifyPopupTerminalClassifier(report) {
  const common = {
    mode: "page",
    sourceResolved: true,
    meterMin: "",
    meterMax: "",
    resultTextLength: 0
  };
  const notPolicy = popupChecks(
    {
      ...common,
      score: null,
      terminalKind: "not_policy",
      statusError: true,
      resultChildCount: 0,
      level: "unknown"
    },
    false
  );
  assert.ok(Object.values(notPolicy).every(Boolean), "not-policy must be a valid ordinary result");
  const actualError = popupChecks(
    {
      ...common,
      score: null,
      terminalKind: "error",
      statusError: true,
      resultChildCount: 0,
      level: "unknown"
    },
    false
  );
  assert.ok(
    Object.values(actualError).some((value) => value !== true),
    "a popup analysis error must never pass as not-policy"
  );
  const completedPolicy = popupChecks(
    {
      ...common,
      score: 50,
      terminalKind: "completed",
      statusError: false,
      resultChildCount: 1,
      resultTextLength: 101,
      level: "medium",
      meterMin: "0",
      meterMax: "100"
    },
    true
  );
  assert.ok(Object.values(completedPolicy).every(Boolean), "a scored policy must remain valid");
  report.safety.popupTerminalClassifierVerified = true;
}

async function waitForMatchingBadge(worker, tabId, score, level) {
  return waitFor(
    async () => {
      const state = await badgeState(worker, tabId);
      return Object.values(badgeChecks(state, score, level)).every(Boolean) ? state : null;
    },
    { label: `badge matching popup score on tab ${tabId}` }
  );
}

function summarizeOutcome(record) {
  if (record.siteHealth?.established !== true) return "inconclusive";
  const hardChecks = [
    record.httpStatus >= 200 && record.httpStatus < 300,
    record.page?.finalHttps === true,
    record.page?.finalOriginAllowed === true,
    record.receiver?.responded === true,
    record.receiver?.observationActive === true,
    record.observation?.ok === true,
    record.observation?.observationEnabled === true,
    record.observation?.sessionMatchesActiveDocument === true,
    record.popup?.mode === record.expectedMode,
    ...Object.values(record.popup?.checks || {}),
    record.popup?.scroll?.scrollable === true,
    record.popup?.scroll?.scrolled === true,
    record.overlay?.navigationFresh === true,
    ...Object.values(record.overlay?.checks || {}),
    ...Object.values(record.badge?.checks || {}),
    ...Object.values(record.modePersistence?.checks || {}),
    record.requestSafety?.interceptionErrors === 0,
    record.requestSafety?.blockedTopLevelOrigins?.length === 0,
    record.requestSafety?.unexpectedNonExtensionTargetTypes?.length === 0,
    record.requestSafety?.targetInspectionErrors === 0
  ];
  if (record.error) return "fail";
  if (hardChecks.some((value) => value !== true)) return "fail";
  if (record.expectedPolicy && record.popup?.mode === "page" && record.popup?.score === null) return "fail";
  if (!record.expectedPolicy && record.popup?.mode === "page" && record.popup?.score !== null) return "warn";
  return "pass";
}

async function writeReport(report) {
  const directory = join(REPOSITORY_ROOT, "reports", "public-site-smoke");
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const stamp = report.startedAt.replaceAll(":", "-").replaceAll(".", "-");
  const outputPath = join(directory, `${stamp}.local.json`);
  const temporaryPath = `${outputPath}.${process.pid}.tmp`;
  try {
    await writeFile(temporaryPath, `${JSON.stringify(report, null, 2)}\n`, {
      encoding: "utf8",
      flag: "wx",
      mode: 0o600
    });
    await rename(temporaryPath, outputPath);
  } finally {
    await rm(temporaryPath, { force: true });
  }
  return outputPath;
}

async function run() {
  const { headed, targets, safetyPreflightOnly } = parseArguments(process.argv.slice(2));
  targets.forEach(validateTarget);
  const report = {
    schemaVersion: REPORT_SCHEMA_VERSION,
    startedAt: new Date().toISOString(),
    finishedAt: "",
    chrome: "",
    extensionVersion: "",
    headed,
    safety: {
      explicitScope: safetyPreflightOnly ? "safety-preflight-only" : targets.length === TARGETS.length ? "all" : "only",
      sequentialTopLevelTargets: true,
      cleanProfilePerRun: true,
      cleanProfilePerTarget: false,
      crossSiteStateMayCarryWithinRun: true,
      httpsThirdPartySubresourcesMayLoad: true,
      instrumentedPageAllowedHttpMethods: ["GET"],
      publicSiteClicks: 0,
      publicSiteInputs: 0,
      consentActions: 0,
      loginActions: 0,
      storedRawPageText: false,
      storedCookieValues: false,
      storedRequestUrls: false
    },
    targets: [],
    fatalError: null,
    cleanupErrors: []
  };
  let browser = null;
  let profileDirectory = "";
  let targetMonitor = null;

  try {
    const chrome = resolveChrome();
    report.chrome = chrome.versionText;
    verifyLocalHostnameClassifier(report);
    verifyPopupTerminalClassifier(report);
    profileDirectory = await mkdtemp(join(tmpdir(), "unveily-public-smoke-"));
    browser = await puppeteer.launch({
      executablePath: chrome.executablePath,
      headless: !headed,
      userDataDir: profileDirectory,
      enableExtensions: true,
      ignoreDefaultArgs: ["--disable-popup-blocking"],
      blocklist: ["ws://*/*", "wss://*/*", "ftp://*/*", "file://*/*"],
      defaultViewport: { width: 1200, height: 900 },
      args: [
        "--enable-unsafe-extension-debugging",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-component-update",
        "--disable-sync",
        "--disable-background-networking",
        "--disable-domain-reliability",
        "--disable-preconnect",
        "--dns-prefetch-disable",
        "--metrics-recording-only"
      ]
    });
    await browser.defaultBrowserContext().setDownloadBehavior({ policy: "deny" });
    report.safety.downloadsDenied = true;
    report.safety.browserStreamingBlocklistInstalled = true;

    const extensionId = await browser.installExtension(REPOSITORY_ROOT);
    const extension = (await browser.extensions()).get(extensionId);
    assert.ok(extension?.enabled, "unpacked extension must be enabled");
    report.extensionVersion = extension.version;
    let workerContext = await extensionWorker(browser, extensionId);

    const optionsTarget = await browser.waitForTarget(
      (target) => target.url() === `chrome-extension://${extensionId}/src/options.html`,
      { timeout: DEFAULT_TIMEOUT_MS }
    );
    const optionsPage = await optionsTarget.asPage();

    const page = await browser.newPage();
    await installPublicPageApiGuards(page);
    targetMonitor = monitorUnexpectedNonExtensionTargets(browser, page);
    await page.setExtraHTTPHeaders({ DNT: "1" });
    await page.setRequestInterception(true);
    let activeRequestCounters = null;
    let allowedTopLevelOrigins = new Set();
    let safetyPreflightActive = false;
    let safetyPreflightOrigin = "";
    page.on("request", (request) => {
      const requestCounters = activeRequestCounters;
      const requestAllowedTopLevelOrigins = allowedTopLevelOrigins;
      void (async () => {
        if (request.isInterceptResolutionHandled?.()) return;
        const method = request.method().toUpperCase();
        const type = request.resourceType();
        let parsed = null;
        try {
          parsed = new URL(request.url());
        } catch {
          // The request is blocked below as an unsafe scheme.
        }
        const localNonNetworkResource = parsed && ["blob:", "data:"].includes(parsed.protocol);
        const localSafetyPreflightRequest =
          safetyPreflightActive && parsed?.origin === safetyPreflightOrigin;
        const topLevelNavigation =
          request.isNavigationRequest() && request.frame() === page.mainFrame();
        let blockedReason = "";
        if (method !== "GET") blockedReason = "non_get_method";
        else if (["websocket", "eventsource"].includes(type)) blockedReason = "streaming_transport";
        else if (
          !parsed ||
          (!localNonNetworkResource && !localSafetyPreflightRequest && parsed.protocol !== "https:")
        ) {
          blockedReason = "unsafe_scheme";
        } else if (
          !localNonNetworkResource &&
          !localSafetyPreflightRequest &&
          isPrivateOrLocalHostname(parsed.hostname)
        ) {
          blockedReason = "private_or_local_host";
        } else if (
          topLevelNavigation &&
          !localSafetyPreflightRequest &&
          (!parsed ||
            parsed.protocol !== "https:" ||
            !requestAllowedTopLevelOrigins.has(parsed.origin))
        ) {
          blockedReason = "unexpected_top_level_origin";
        }

        if (blockedReason) {
          if (requestCounters) {
            incrementCounter(requestCounters.blockedByMethod, method);
            incrementCounter(requestCounters.blockedByType, type);
            incrementCounter(requestCounters.blockedByReason, blockedReason);
            if (
              blockedReason === "unexpected_top_level_origin" &&
              parsed?.origin &&
              !requestCounters.blockedTopLevelOrigins.includes(parsed.origin) &&
              requestCounters.blockedTopLevelOrigins.length < 4
            ) {
              requestCounters.blockedTopLevelOrigins.push(parsed.origin);
            }
          }
          await request.abort("blockedbyclient");
          return;
        }
        if (requestCounters) {
          requestCounters.allowedRequestCount += 1;
          incrementCounter(requestCounters.allowedByType, type);
        }
        await request.continue();
      })().catch(async () => {
        if (requestCounters) requestCounters.interceptionErrors += 1;
        try {
          if (!request.isInterceptResolutionHandled?.()) await request.abort("failed");
        } catch {
          // A closing target can resolve the intercepted request first.
        }
      });
    });

    const safetyFixture = await startSafetyPreflightServer();
    const safetyTargetCheckpoint = targetMonitor.checkpoint();
    safetyPreflightOrigin = safeOrigin(safetyFixture.url);
    safetyPreflightActive = true;
    try {
      await verifyRuntimeSafetyBoundary(page, report, safetyFixture);
    } finally {
      safetyPreflightActive = false;
      safetyPreflightOrigin = "";
    }
    const safetyTargetChanges = await targetMonitor.changesSince(safetyTargetCheckpoint);
    assert.deepEqual(
      safetyTargetChanges,
      { types: [], inspectionErrors: 0 },
      "local probes must not create a non-extension page or worker target"
    );
    report.safety.unexpectedTargetPreflightVerified = true;

    let overlayEnabled = false;
    const modeScenarioEnabled = targets.length >= 2;

    for (const [targetIndex, target] of targets.entries()) {
      const startedAt = Date.now();
      const requestedOrigin = safeOrigin(target.url);
      const targetAllowedOrigins = new Set([
        requestedOrigin,
        ...(target.allowedTopLevelOrigins || [])
      ]);
      const scenarioRole =
        modeScenarioEnabled && targetIndex === 0
          ? "arm-cookie-mode"
          : modeScenarioEnabled && targetIndex === 1
            ? "restore-cookie-then-page"
            : "page-analysis";
      const record = {
        id: target.id,
        category: target.category,
        expectedPolicy: target.expectedPolicy,
        requestedOrigin,
        finalOrigin: "",
        httpStatus: 0,
        durationMs: 0,
        expectedMode: "page",
        requestSafety: {
          allowedRequestCount: 0,
          allowedByType: {},
          blockedByMethod: {},
          blockedByType: {},
          blockedByReason: {},
          blockedTopLevelOrigins: [],
          interceptionErrors: 0
        },
        page: null,
        siteHealth: null,
        receiver: null,
        observation: null,
        popup: null,
        overlay: null,
        badge: null,
        modePersistence: {
          scenarioRole,
          checks: {
            initialModeRestored: false,
            ...(scenarioRole === "arm-cookie-mode"
              ? { immediateCloseWriteVerified: false }
              : {}),
            ...(scenarioRole === "restore-cookie-then-page"
              ? {
                  immediateCloseWriteVerified: false,
                  cookieModeRestoredOnNextPage: false,
                  pageModeRestoredAfterClose: false,
                  workerRestartVerified: false
                }
              : {})
          }
        },
        outcome: "fail",
        error: null
      };
      activeRequestCounters = record.requestSafety;
      allowedTopLevelOrigins = targetAllowedOrigins;
      const targetCheckpoint = targetMonitor.checkpoint();

      try {
        const response = await page.goto(target.url, {
          waitUntil: "domcontentloaded",
          timeout: DEFAULT_TIMEOUT_MS
        });
        record.httpStatus = response?.status() || 0;
        record.finalOrigin = safeOrigin(page.url());
        await delay(1_000);
        record.page = {
          finalHttps: page.url().startsWith("https://"),
          finalOriginAllowed: targetAllowedOrigins.has(record.finalOrigin),
          finalOriginMatchesRequested: record.finalOrigin === requestedOrigin
        };
        record.siteHealth = await reviewedDocumentHealth(
          page,
          target,
          record.httpStatus,
          record.page.finalOriginAllowed
        );
        if (!record.siteHealth.established) {
          const siteError = new Error("The reviewed public document health checks did not pass.");
          siteError.name = "SiteInconclusiveError";
          throw siteError;
        }
        workerContext = await extensionWorker(browser, extensionId, null);
        const tab = await activatePageTab(workerContext.worker, page);
        record.receiver = await waitForContentReceiver(workerContext.worker, tab.id);

        const beforePopupOverlay = overlayEnabled
          ? await waitForFreshNavigationOverlay(workerContext.worker, tab.id)
          : null;
        let popup = await openPopup({ browser, extension, extensionId, page });
        let popupClosed = false;
        try {
          const initialExpectedMode = modeScenarioEnabled && targetIndex === 1 ? "cookies" : "page";
          let analyzed = await waitForPopupAnalysis(popup, initialExpectedMode);
          record.modePersistence.checks.initialModeRestored = analyzed.mode === initialExpectedMode;

          if (modeScenarioEnabled && targetIndex === 1) {
            const cookieOverlay = await waitForOverlayMatchingPopup(
              workerContext.worker,
              tab.id,
              analyzed,
              "cookies"
            );
            record.modePersistence.checks.cookieModeRestoredOnNextPage =
              analyzed.mode === "cookies" &&
              analyzed.statusError === false &&
              Number.isFinite(analyzed.score) &&
              cookieOverlay.snapshot?.source === "cookie-analysis" &&
              cookieOverlay.snapshot?.score === analyzed.score;
            await switchModeAndClose(popup, "page");
            popupClosed = true;
            await waitForStoredMode(optionsPage, "page");
            record.modePersistence.checks.immediateCloseWriteVerified = true;
            popup = await openPopup({ browser, extension, extensionId, page });
            popupClosed = false;
            analyzed = await waitForPopupAnalysis(popup, "page");
            record.modePersistence.checks.pageModeRestoredAfterClose = analyzed.mode === "page";
          }

          if (!overlayEnabled) {
            await enableOverlayFromPopup(popup);
            overlayEnabled = true;
          }
          const scroll = await verifyPopupScrolling(popup);
          record.observation = await observationSummary(
            popup,
            tab.id,
            documentUrlFingerprint(page.url())
          );
          const mounted = await waitForOverlayMatchingPopup(
            workerContext.worker,
            tab.id,
            analyzed,
            "page"
          );
          const badge = await waitForMatchingBadge(
            workerContext.worker,
            tab.id,
            analyzed.score,
            analyzed.level
          );
          record.popup = { ...analyzed, scroll, checks: popupChecks(analyzed, target.expectedPolicy) };
          record.overlay = {
            beforePopupSource: beforePopupOverlay?.snapshot?.source || "none",
            navigationFresh:
              !beforePopupOverlay ||
              !["page-analysis", "cookie-analysis"].includes(beforePopupOverlay.snapshot?.source),
            status: mounted.snapshot?.status || "unknown",
            score: mounted.snapshot?.score ?? null,
            source: mounted.snapshot?.source || "none",
            color: mounted.snapshot?.color || "",
            checks: overlayChecks(mounted, analyzed, "page")
          };
          record.badge = {
            ...badge,
            checks: badgeChecks(badge, analyzed.score, analyzed.level)
          };

          if (modeScenarioEnabled && targetIndex === 0) {
            await switchModeAndClose(popup, "cookies");
            popupClosed = true;
            await waitForStoredMode(optionsPage, "cookies");
            record.modePersistence.checks.immediateCloseWriteVerified = true;
          } else {
            await closePopup(popup);
            popupClosed = true;
          }
        } finally {
          if (!popupClosed) await closePopup(popup);
        }

        if (modeScenarioEnabled && targetIndex === 1) {
          const beforeRestart = await overlayState(workerContext.worker, tab.id);
          const previousTarget = workerContext.target;
          await workerContext.worker.close();
          const restartedWorker = extensionWorker(browser, extensionId, previousTarget);
          const restoredPopupPromise = openPopup({ browser, extension, extensionId, page });
          workerContext = await restartedWorker;
          const restoredPopup = await restoredPopupPromise;
          try {
            const wake = await restoredPopup.evaluate(async (storageKey) => ({
              runtime: await chrome.runtime.sendMessage({ type: "GET_ANALYSIS_MODE_PREFERENCE" }),
              stored: (await chrome.storage.local.get(storageKey))?.[storageKey]
            }), ANALYSIS_MODE_PREFERENCE_KEY);
            assert.deepEqual(
              wake,
              { runtime: { ok: true, mode: "page" }, stored: "page" },
              "a real action popup must wake the worker with the saved page-analysis mode"
            );
            const recovered = await waitFor(
              async () => {
                const state = await overlayState(workerContext.worker, tab.id);
                return Number.isSafeInteger(state?.snapshot?.generation) &&
                  state.snapshot.generation > beforeRestart?.snapshot?.generation &&
                  state.snapshot.score === beforeRestart?.snapshot?.score &&
                  state.snapshot.source === beforeRestart?.snapshot?.source
                  ? state
                  : null;
              },
              { label: "overlay state recovery after service-worker restart" }
            );
            const restoredAnalysis = await waitForPopupAnalysis(restoredPopup, "page");
            record.modePersistence.checks.workerRestartVerified =
              recovered.ownedHostCount === 1 && restoredAnalysis.mode === "page";
          } finally {
            await closePopup(restoredPopup);
          }
        }
      } catch (error) {
        record.error = {
          name: String(error?.name || "Error").slice(0, 80),
          message: redactErrorMessage(error?.message || error)
        };
      } finally {
        activeRequestCounters = null;
        const targetChanges = await targetMonitor.changesSince(targetCheckpoint);
        record.requestSafety.unexpectedNonExtensionTargetTypes = targetChanges.types;
        record.requestSafety.targetInspectionErrors = targetChanges.inspectionErrors;
        record.durationMs = Date.now() - startedAt;
        record.outcome = summarizeOutcome(record);
        report.targets.push(record);
        const outcomeMarker =
          record.outcome === "pass"
            ? "✓"
            : record.outcome === "warn"
              ? "!"
              : record.outcome === "inconclusive"
                ? "?"
                : "✗";
        process.stdout.write(
          `${outcomeMarker} ` +
            `${record.id} mode=${record.popup?.mode || record.expectedMode} ` +
            `status=${record.httpStatus || "network-error"} score=${record.popup?.score ?? "unknown"}\n`
        );
      }
    }
  } catch (error) {
    report.fatalError = {
      name: String(error?.name || "Error").slice(0, 80),
      message: redactErrorMessage(error?.message || error, [profileDirectory])
    };
  } finally {
    report.finishedAt = new Date().toISOString();
    targetMonitor?.stop();
    try {
      if (browser) await withTimeout(browser.close(), "browser close", 10_000);
    } catch (error) {
      browser?.process()?.kill("SIGKILL");
      report.cleanupErrors.push({
        name: String(error?.name || "Error").slice(0, 80),
        message: redactErrorMessage(error?.message || error, [profileDirectory])
      });
    }
    try {
      if (profileDirectory) await rm(profileDirectory, { recursive: true, force: true });
    } catch (error) {
      report.cleanupErrors.push({
        name: String(error?.name || "Error").slice(0, 80),
        message: redactErrorMessage(error?.message || error, [profileDirectory])
      });
    }
  }

  const outputPath = await writeReport(report);
  const counts = Object.fromEntries(
    ["pass", "warn", "inconclusive", "fail"].map((outcome) => [
      outcome,
      report.targets.filter((target) => target.outcome === outcome).length
    ])
  );
  process.stdout.write(`Report: ${outputPath}\n`);
  process.stdout.write(`Summary: ${JSON.stringify(counts)}\n`);
  if (
    counts.fail > 0 ||
    counts.inconclusive > 0 ||
    report.fatalError ||
    report.cleanupErrors.length > 0
  ) {
    process.exitCode = 1;
  }
}

await run();
