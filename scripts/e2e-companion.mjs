import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import http from "node:http";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

import puppeteer from "puppeteer-core";

const REPOSITORY_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const MINIMUM_CHROME_VERSION = 140;
const DEFAULT_TIMEOUT_MS = 15_000;
const HIDDEN_SCAN_WAIT_MS = 16_000;
const COMPANION_OVERLAY_GENERATION_KEY = "companionOverlayWorkerGenerationV1";
const COMPANION_OVERLAY_ENABLED_KEY = "companionOverlayEnabled";
const EXPECTED_COLORS = new Map([
  [0, { hex: "#039855", rgba: [3, 152, 85, 255] }],
  [25, { hex: "#70802C", rgba: [112, 128, 44, 255] }],
  [50, { hex: "#DC6803", rgba: [220, 104, 3, 255] }],
  [75, { hex: "#DB4B12", rgba: [219, 75, 18, 255] }],
  [100, { hex: "#D92D20", rgba: [217, 45, 32, 255] }]
]);

const SAFE_POLICY_TEXT = [
  "Privacy Policy. This notice explains how personal information is handled when an account is created and used.",
  "We collect a name and email address only to provide the requested account, answer support requests, and secure the service.",
  "We do not sell personal information and do not use it for behavioral advertising.",
  "Account information is retained for thirty days after closure and is then deleted unless a legal obligation requires a shorter documented exception.",
  "Users can request access, correction, export, or deletion by contacting the privacy team.",
  "Service providers may process limited information only under written instructions and confidentiality duties.",
  "Encryption, access controls, audit logging, and incident response procedures protect stored information.",
  "Material notice updates are presented before they take effect, and users may stop using the service without penalty."
].join(" ");

const HIGH_RISK_POLICY_TEXT = [
  "Privacy Policy. This policy describes extensive collection and use of personal information across the service.",
  "We collect names, email addresses, precise location, financial information, health information, passwords, device identifiers, browsing history, biometric identifiers, and information about children.",
  "We sell personal information to advertisers and data brokers, and we share it with unrelated partners for their own marketing purposes.",
  "We may retain all collected information indefinitely without a fixed deletion schedule and may transfer it overseas to any jurisdiction.",
  "We may change this policy and the service terms at any time without prior notice or renewed consent.",
  "Every dispute requires binding arbitration, users waive class actions, and the provider may terminate access at its sole discretion.",
  "The service may combine account details with advertising profiles, location histories, purchase records, and third-party datasets.",
  "These practices apply to account holders, visitors, children, household members, and any person whose information is uploaded by another user."
].join(" ");

assert.ok(SAFE_POLICY_TEXT.length >= 600, "safe policy fixture must pass the policy preflight");
assert.ok(HIGH_RISK_POLICY_TEXT.length >= 600, "high-risk policy fixture must pass the policy preflight");

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
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

async function closeTransientPage(page, label) {
  if (!page || page.isClosed()) return;
  await withTimeout(page.close(), label, 5_000);
}

function step(message) {
  process.stdout.write(`✓ ${message}\n`);
}

function overlayStamp(snapshot) {
  const generation = snapshot?.generation;
  const revision = snapshot?.revision;
  assert.ok(Number.isSafeInteger(generation) && generation >= 1, `invalid generation: ${generation}`);
  assert.ok(Number.isSafeInteger(revision) && revision >= 0, `invalid revision: ${revision}`);
  return { generation, revision };
}

function compareOverlayStamps(left, right) {
  return left.generation === right.generation
    ? left.revision - right.revision
    : left.generation - right.generation;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function waitFor(check, { timeoutMs = DEFAULT_TIMEOUT_MS, intervalMs = 100, label } = {}) {
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
  if (!executablePath) {
    throw new Error("Chrome was not found. Set E2E_CHROME_PATH to a Chrome 140+ executable.");
  }
  const versionResult = spawnSync(executablePath, ["--version"], { encoding: "utf8" });
  const versionText = `${versionResult.stdout || ""} ${versionResult.stderr || ""}`.trim();
  const majorVersion = Number(/(?:Chrome|Chromium)\s+(\d+)/i.exec(versionText)?.[1]);
  if (!Number.isInteger(majorVersion) || majorVersion < MINIMUM_CHROME_VERSION) {
    throw new Error(`Chrome ${MINIMUM_CHROME_VERSION}+ is required; found ${versionText || "unknown version"}.`);
  }
  return { executablePath, majorVersion, versionText };
}

function fixtureHtml({ title, heading, text }) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>${escapeHtml(title)}</title>
    <style>body { min-height: 1100px; margin: 0; font: 16px/1.6 system-ui, sans-serif; } main { max-width: 760px; margin: 40px auto; padding: 24px; }</style>
  </head>
  <body>
    <main id="fixture">
      <h1>${escapeHtml(heading)}</h1>
      <p id="fixtureText">${escapeHtml(text)}</p>
    </main>
  </body>
</html>`;
}

async function startFixtureServer() {
  const server = http.createServer((request, response) => {
    const path = new URL(request.url || "/", "http://127.0.0.1").pathname;
    if (path === "/favicon.ico") {
      response.writeHead(204);
      response.end();
      return;
    }
    if (path.startsWith("/api/")) {
      response.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store"
      });
      response.end(JSON.stringify({ ok: true, path }));
      return;
    }

    const policyFixture = path === "/idle-policy";
    const strictCspFixture = path === "/strict-csp";
    const body = fixtureHtml(
      policyFixture
        ? { title: "E2E Privacy Policy", heading: "Privacy Policy", text: SAFE_POLICY_TEXT }
        : strictCspFixture
          ? {
              title: "E2E Strict CSP",
              heading: "Strict CSP fixture",
              text: "This controlled page blocks page scripts, styles, connections, frames, and objects."
            }
          : {
              title: "E2E Ordinary Page",
              heading: "Ordinary page",
              text: "This controlled page intentionally contains no complete privacy policy or terms document."
            }
    );
    const headers = {
      "content-type": "text/html; charset=utf-8",
      // BFCache stores a live document rather than an HTTP response; avoid
      // no-store so the lifecycle boundary can be exercised in real Chrome.
      "cache-control": "no-cache"
    };
    if (strictCspFixture) {
      headers["content-security-policy"] =
        "default-src 'none'; base-uri 'none'; connect-src 'none'; font-src 'none'; form-action 'none'; frame-src 'none'; img-src 'none'; object-src 'none'; script-src 'none'; style-src 'none'";
    }
    response.writeHead(200, headers);
    response.end(body);
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");
  return {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close: () =>
      new Promise((resolve, reject) => server.close((error) => (error ? reject(error) : resolve())))
  };
}

async function extensionWorker(browser, extensionId, excludedTarget = null) {
  const target = await browser.waitForTarget(
    (candidate) =>
      candidate !== excludedTarget &&
      candidate.type() === "service_worker" &&
      candidate.url() === `chrome-extension://${extensionId}/src/background.js`,
    { timeout: DEFAULT_TIMEOUT_MS }
  );
  const worker = await target.worker();
  assert.ok(worker, "extension service worker target must expose a worker");
  return { target, worker };
}

async function tabForUrl(worker, url) {
  const tab = await worker.evaluate(async (targetUrl) => {
    const tabs = await chrome.tabs.query({ url: targetUrl });
    return tabs[0] || null;
  }, url);
  assert.ok(Number.isInteger(tab?.id), `Chrome tab was not found for ${url}`);
  assert.ok(Number.isInteger(tab?.windowId), `Chrome window was not found for ${url}`);
  return tab;
}

async function activateTab(worker, tabId) {
  await worker.evaluate(async (targetTabId) => {
    await chrome.tabs.update(targetTabId, { active: true });
  }, tabId);
}

async function createTab(worker, { windowId, url, active = true }) {
  return worker.evaluate(async (createProperties) => {
    const tab = await chrome.tabs.create(createProperties);
    return { id: tab.id, windowId: tab.windowId, url: tab.url };
  }, { windowId, url, active });
}

async function badgeState(worker, tabId) {
  return worker.evaluate(async (targetTabId) => ({
    text: await chrome.action.getBadgeText({ tabId: targetTabId }),
    color: await chrome.action.getBadgeBackgroundColor({ tabId: targetTabId })
  }), tabId);
}

async function waitForBadge(worker, tabId, expectedText, timeoutMs = DEFAULT_TIMEOUT_MS) {
  return waitFor(async () => {
    const state = await badgeState(worker, tabId);
    return state.text === expectedText ? state : null;
  }, { timeoutMs, label: `badge ${expectedText} on tab ${tabId}` });
}

async function networkActivity(extensionPage, tabId) {
  return extensionPage.evaluate(
    async (targetTabId) => chrome.runtime.sendMessage({ type: "GET_NETWORK_ACTIVITY", tabId: targetTabId }),
    tabId
  );
}

async function setObservationEnabledFromOptions(optionsPage, worker, enabled) {
  await optionsPage.waitForFunction(
    () => {
      const checkbox = document.querySelector("#observationEnabled");
      const button = document.querySelector("#saveObservationSettingsButton");
      return checkbox instanceof HTMLInputElement && button instanceof HTMLButtonElement && !button.disabled;
    },
    { timeout: DEFAULT_TIMEOUT_MS }
  );
  await optionsPage.evaluate((checked) => {
    const checkbox = document.querySelector("#observationEnabled");
    const button = document.querySelector("#saveObservationSettingsButton");
    if (!(checkbox instanceof HTMLInputElement) || !(button instanceof HTMLButtonElement)) {
      throw new Error("Observation controls are unavailable");
    }
    checkbox.checked = checked;
    button.click();
  }, enabled);
  await waitFor(
    () =>
      worker.evaluate(async (expected) => {
        const stored = await chrome.storage.local.get("observationSettings");
        return stored?.observationSettings?.enabled === expected;
      }, enabled),
    { label: `observation setting ${enabled ? "ON" : "OFF"} from the real options page` }
  );
}

async function setCompanionOverlayEnabledFromStorage(extensionPage, worker, enabled) {
  await extensionPage.evaluate(
    async ({ storageKey, nextEnabled }) => {
      await chrome.storage.local.set({ [storageKey]: nextEnabled });
    },
    { storageKey: COMPANION_OVERLAY_ENABLED_KEY, nextEnabled: enabled }
  );
  await waitFor(
    () =>
      worker.evaluate(async ({ storageKey, expected }) => {
        const stored = await chrome.storage.local.get(storageKey);
        return stored?.[storageKey] === expected;
      }, { storageKey: COMPANION_OVERLAY_ENABLED_KEY, expected: enabled }),
    { label: `companion preference ${enabled ? "ON" : "OFF"} in trusted extension storage` }
  );
}

async function companionPreferenceState(popup) {
  return popup.evaluate(async (storageKey) => ({
    stored: (await chrome.storage.local.get(storageKey))?.[storageKey],
    runtime: await chrome.runtime.sendMessage({ type: "GET_COMPANION_OVERLAY_PREFERENCE" })
  }), COMPANION_OVERLAY_ENABLED_KEY);
}

async function contentObservationActive(worker, tabId) {
  return worker.evaluate(async (targetTabId) => {
    try {
      return await chrome.tabs.sendMessage(targetTabId, { type: "PAGE_CONTEXT_CHANGED" });
    } catch {
      return null;
    }
  }, tabId);
}

async function waitForContentObservation(worker, tabId, active) {
  return waitFor(async () => {
    const response = await contentObservationActive(worker, tabId);
    return response?.ok === active ? response : null;
  }, { label: `content observation ${active ? "active" : "inactive"} on tab ${tabId}` });
}

async function installContentMessageTrace(worker, tabId) {
  await worker.evaluate((targetTabId) => {
    if (globalThis.__unveilyE2eContentMessageListener) {
      chrome.runtime.onMessage.removeListener(globalThis.__unveilyE2eContentMessageListener);
    }
    globalThis.__unveilyE2eContentMessages = [];
    globalThis.__unveilyE2eContentMessageListener = (message, sender) => {
      if (sender?.tab?.id !== targetTabId || typeof message?.type !== "string") return;
      globalThis.__unveilyE2eContentMessages.push({
        type: message.type,
        documentId: typeof sender.documentId === "string" ? sender.documentId : "",
        url: typeof sender.url === "string" ? sender.url : ""
      });
    };
    chrome.runtime.onMessage.addListener(globalThis.__unveilyE2eContentMessageListener);
  }, tabId);
}

async function resetContentMessageTrace(worker) {
  await worker.evaluate(() => {
    globalThis.__unveilyE2eContentMessages = [];
  });
}

async function contentMessageTrace(worker) {
  return worker.evaluate(() => globalThis.__unveilyE2eContentMessages || []);
}

async function openPopup({ browser, extension, extensionId, page }) {
  const existingTargets = new Set(browser.targets());
  const popupTargetPromise = browser.waitForTarget(
    (target) =>
      !existingTargets.has(target) &&
      target.url() === `chrome-extension://${extensionId}/src/popup.html`,
    { timeout: DEFAULT_TIMEOUT_MS }
  );
  await withTimeout(page.triggerExtensionAction(extension), "extension action trigger", 5_000);
  const target = await popupTargetPromise;
  const popup = await target.asPage();
  await popup.waitForSelector("#companionOverlayToggleButton", { timeout: DEFAULT_TIMEOUT_MS });
  return popup;
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

async function toggleOverlayFromPopup(popup, enabled) {
  await waitForPopupToggle(popup, !enabled);
  await popup.click("#companionOverlayToggleButton");
  await waitForPopupToggle(popup, enabled);
}

async function popupAnalysisState(popup) {
  return popup.evaluate(() => {
    const result = document.querySelector("#result");
    const meter = result?.querySelector(".score-card meter") || null;
    const score = meter && Number.isFinite(Number(meter.value)) ? Number(meter.value) : null;
    return {
      status: document.querySelector("#status")?.textContent?.trim() || "",
      source: document.querySelector("#sourceLabel")?.textContent?.trim() || "",
      resultText: result?.textContent?.replace(/\s+/g, " ").trim() || "",
      resultChildCount: result?.childElementCount || 0,
      score,
      meterMin: meter?.getAttribute("min") || "",
      meterMax: meter?.getAttribute("max") || ""
    };
  });
}

async function waitForCompletedPopupAnalysis(popup) {
  return waitFor(async () => {
    const state = await popupAnalysisState(popup);
    return /분석 완료|Analysis complete/i.test(state.status) &&
      state.resultChildCount > 0 &&
      state.resultText.length > 100 &&
      state.score !== null
      ? state
      : null;
  }, { label: "completed current-page analysis in the real popup" });
}

async function triggerPopupPageAnalysis(popup) {
  const status = await popup.evaluate(() => {
    const button = document.querySelector("#analyzePageButton");
    if (!(button instanceof HTMLButtonElement)) throw new Error("Analyze-page button is unavailable");
    button.click();
    return document.querySelector("#status")?.textContent?.trim() || "";
  });
  assert.match(status, /읽는 중|Reading page text/i, `unexpected analysis start status: ${status}`);
}

async function verifyPopupScrolling(popup) {
  const before = await popup.evaluate(() => {
    const scrollingElement = document.scrollingElement || document.documentElement;
    scrollingElement.scrollTop = 0;
    return {
      before: scrollingElement.scrollTop,
      documentScrollHeight: document.documentElement.scrollHeight,
      documentClientHeight: document.documentElement.clientHeight,
      scrollHeight: scrollingElement.scrollHeight,
      clientHeight: scrollingElement.clientHeight
    };
  });
  await popup.mouse.move(200, 300);
  await popup.mouse.wheel({ deltaY: Math.max(800, before.scrollHeight) });
  const after = await waitFor(
    () => popup.evaluate(() => (document.scrollingElement || document.documentElement).scrollTop || 0),
    { label: "popup wheel scrolling" }
  );
  await popup.evaluate(() => {
    (document.scrollingElement || document.documentElement).scrollTop = 0;
  });
  return { ...before, after };
}

async function overlayState(worker, tabId) {
  return worker.evaluate(async (targetTabId) => {
    const results = await chrome.scripting.executeScript({
      target: { tabId: targetTabId, frameIds: [0] },
      world: "ISOLATED",
      func: () => {
        const api = globalThis.__unveilyCompanionOverlay;
        const ownedHosts = globalThis.__unveilyCompanionOverlayOwnedHosts;
        const allElements = Array.from(document.querySelectorAll("*"));
        const hosts = ownedHosts ? allElements.filter((element) => ownedHosts.has(element)) : [];
        const host = hosts[0] || null;
        const rect = host?.getBoundingClientRect();
        const style = host ? getComputedStyle(host) : null;
        return {
          apiAvailable: Boolean(api?.snapshot),
          ownedHostCount: hosts.length,
          snapshot: api?.snapshot?.() || null,
          viewport: { width: innerWidth, height: innerHeight },
          host: host
            ? {
                tagName: host.tagName,
                id: host.id,
                className: host.className,
                childElementCount: host.childElementCount,
                shadowRootIsNull: host.shadowRoot === null,
                stateAttributes: Array.from(host.attributes)
                  .map((attribute) => attribute.name)
                  .filter((name) => name === "role" || name.startsWith("aria-") || name.startsWith("data-")),
                rect: {
                  left: rect.left,
                  top: rect.top,
                  right: rect.right,
                  bottom: rect.bottom,
                  width: rect.width,
                  height: rect.height
                },
                computed: {
                  position: style.position,
                  left: style.left,
                  bottom: style.bottom,
                  width: style.width,
                  height: style.height,
                  pointerEvents: style.pointerEvents,
                  zIndex: style.zIndex
                }
              }
            : null
        };
      }
    });
    return results[0]?.result || null;
  }, tabId);
}

async function waitForOverlay(worker, tabId, predicate, label) {
  let latest = null;
  try {
    return await waitFor(async () => {
      latest = await overlayState(worker, tabId);
      return latest && predicate(latest) ? latest : null;
    }, { label });
  } catch (error) {
    throw new Error(`${error.message} Last overlay state: ${JSON.stringify(latest)}`);
  }
}

function assertMountedOverlayLayout(state) {
  assert.equal(state.apiAvailable, true);
  assert.equal(state.ownedHostCount, 1, "the top document must contain exactly one owned overlay host");
  assert.equal(state.snapshot?.enabled, true);
  assert.equal(state.snapshot?.mounted, true);
  assert.equal(state.snapshot?.protocolFailedClosed, false);
  overlayStamp(state.snapshot);
  assert.ok(state.host);
  assert.equal(state.host.tagName, "DIV");
  assert.equal(state.host.id, "");
  assert.equal(state.host.className, "");
  assert.equal(state.host.childElementCount, 0, "the closed shadow UI must not leak into light DOM");
  assert.equal(state.host.shadowRootIsNull, true, "the overlay shadow root must be closed");
  assert.deepEqual(state.host.stateAttributes, [], "the page-visible host must not expose risk state attributes");
  assert.equal(state.host.computed.position, "fixed");
  assert.equal(state.host.computed.left, "16px");
  assert.equal(state.host.computed.bottom, "16px");
  assert.equal(state.host.computed.width, "56px");
  assert.equal(state.host.computed.height, "56px");
  assert.equal(state.host.computed.pointerEvents, "none");
  assert.equal(state.host.computed.zIndex, "2147483647");
  assert.equal(state.host.rect.width, 56);
  assert.equal(state.host.rect.height, 56);
  assert.equal(state.host.rect.left, 16);
  assert.equal(state.viewport.height - state.host.rect.bottom, 16);
}

async function riskContextForUrl(extensionPage, targetUrl) {
  return extensionPage.evaluate(async (url) => {
    const tabs = await chrome.tabs.query({ url });
    const tab = tabs[0];
    if (!tab?.id || !tab.url) throw new Error(`Target tab is unavailable: ${url}`);
    const frame = await chrome.webNavigation.getFrame({ tabId: tab.id, frameId: 0 });
    if (!frame?.documentId) throw new Error(`Target document is unavailable: ${url}`);
    const { documentUrlFingerprint } = await import(chrome.runtime.getURL("src/backgroundSecurity.js"));
    return {
      tabId: tab.id,
      url: tab.url,
      documentFingerprint: documentUrlFingerprint(tab.url),
      documentId: frame.documentId
    };
  }, targetUrl);
}

async function publishSyntheticRiskForContext(extensionPage, context, score) {
  return extensionPage.evaluate(async ({ pageContext, riskScore }) => {
    const level = riskScore >= 67 ? "high" : riskScore >= 34 ? "medium" : "low";
    return chrome.runtime.sendMessage({
      type: "SET_RISK_INDICATOR",
      tabId: pageContext.tabId,
      indicator: {
        level,
        score: riskScore,
        source: "popup-page",
        url: pageContext.url,
        documentFingerprint: pageContext.documentFingerprint,
        documentId: pageContext.documentId
      }
    });
  }, { pageContext: context, riskScore: score });
}

async function publishSyntheticRisk(extensionPage, targetUrl, score) {
  const context = await riskContextForUrl(extensionPage, targetUrl);
  return publishSyntheticRiskForContext(extensionPage, context, score);
}

async function waitForOverlayScore(worker, tabId, score) {
  return waitForOverlay(
    worker,
    tabId,
    (state) => state.ownedHostCount === 1 && state.snapshot?.score === score,
    `overlay score ${score} on tab ${tabId}`
  );
}

async function waitForUnknownOverlayAfterStamp(worker, tabId, previousStamp) {
  return waitForOverlay(
    worker,
    tabId,
    (state) => {
      const snapshot = state.snapshot;
      if (
        state.ownedHostCount !== 1 ||
        snapshot?.status !== "unknown" ||
        !Number.isSafeInteger(snapshot.generation) ||
        !Number.isSafeInteger(snapshot.revision)
      ) {
        return false;
      }
      return compareOverlayStamps(
        { generation: snapshot.generation, revision: snapshot.revision },
        previousStamp
      ) > 0;
    },
    `terminal unknown popup result on tab ${tabId}`
  );
}

async function waitForPersistedRisk(worker, { tabId, url, score, source }) {
  const key = `observationSessionTabV4:${tabId}`;
  const expected = {
    storageKey: key,
    navigationOrigin: new URL(url).origin,
    expectedScore: score,
    expectedSource: source
  };
  try {
    return await waitFor(
      () =>
        worker.evaluate(async ({ storageKey, navigationOrigin, expectedScore, expectedSource }) => {
          const stored = (await chrome.storage.session.get(storageKey))[storageKey];
          let storedOrigin = "";
          try {
            storedOrigin = new URL(stored?.session?.navigationKey || "").origin;
          } catch {
            return false;
          }
          return storedOrigin === navigationOrigin &&
            stored?.session?.navigationKey === stored?.riskIndicator?.url &&
            stored?.riskIndicator?.score === expectedScore &&
            stored?.riskIndicator?.source === expectedSource;
        }, expected),
      { label: `persisted risk ${score} on tab ${tabId}` }
    );
  } catch (error) {
    const stored = await worker.evaluate(async (storageKey) => {
      const all = await chrome.storage.session.get(null);
      return { keys: Object.keys(all).sort(), shard: all[storageKey] || null };
    }, key);
    throw new Error(`${error.message} Stored session: ${JSON.stringify(stored)}`);
  }
}

async function run() {
  const chrome = resolveChrome();
  const fixture = await startFixtureServer();
  const profileDirectory = await mkdtemp(join(tmpdir(), "unveily-companion-e2e-"));
  let browser = null;

  try {
    browser = await puppeteer.launch({
      executablePath: chrome.executablePath,
      headless: process.env.E2E_HEADLESS === "1",
      userDataDir: profileDirectory,
      enableExtensions: true,
      defaultViewport: { width: 1200, height: 900 },
      args: [
        "--enable-unsafe-extension-debugging",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-component-update",
        "--disable-sync",
        "--metrics-recording-only"
      ]
    });

    const extensionId = await browser.installExtension(REPOSITORY_ROOT);
    const extension = (await browser.extensions()).get(extensionId);
    assert.ok(extension?.enabled, "unpacked extension must be enabled");
    assert.equal(extension.name, "unveily");
    const initialWorker = await extensionWorker(browser, extensionId);
    let workerTarget = initialWorker.target;
    let worker = initialWorker.worker;
    step(`loaded unpacked extension ${extensionId} in ${chrome.versionText}`);

    const optionsTarget = await browser.waitForTarget(
      (target) => target.url() === `chrome-extension://${extensionId}/src/options.html`,
      { timeout: DEFAULT_TIMEOUT_MS }
    );
    const extensionPage = await optionsTarget.asPage();
    assert.match(await extensionPage.title(), /unveily/i);
    step("verified first-install extension page in a clean temporary profile");

    const policyUrl = `${fixture.baseUrl}/idle-policy`;
    const policyPage = await browser.newPage();
    await policyPage.goto(policyUrl, { waitUntil: "domcontentloaded" });
    await policyPage.bringToFront();
    const policyTab = await tabForUrl(worker, policyUrl);
    await activateTab(worker, policyTab.id);

    const defaultOverlay = await waitForOverlay(
      worker,
      policyTab.id,
      (state) => state.apiAvailable && state.snapshot?.enabled === false,
      "disabled overlay initialization in a clean profile"
    );
    assert.equal(defaultOverlay.ownedHostCount, 0);
    assert.equal(defaultOverlay.snapshot?.mounted, false);
    assert.equal(defaultOverlay.host, null);
    step("verified a clean profile does not inject an overlay host by default");

    await waitForBadge(worker, policyTab.id, "L");
    const hiddenPageUrl = `${fixture.baseUrl}/ordinary-hidden`;
    const hiddenTab = await createTab(worker, {
      windowId: policyTab.windowId,
      url: hiddenPageUrl,
      active: true
    });
    const hiddenTarget = await browser.waitForTarget((target) => target.url() === hiddenPageUrl, {
      timeout: DEFAULT_TIMEOUT_MS
    });
    const hiddenPage = await hiddenTarget.asPage();
    await waitFor(
      () => policyPage.evaluate(() => document.visibilityState === "hidden"),
      { label: "policy tab to become hidden" }
    );
    const hiddenPopup = await openPopup({ browser, extension, extensionId, page: hiddenPage });
    const networkBeforeHidden = await networkActivity(hiddenPopup, policyTab.id);
    assert.equal(networkBeforeHidden?.ok, true, JSON.stringify(networkBeforeHidden));
    // Both path segments are on the request minimizer's semantic allowlist, so
    // the exact value-free probe remains identifiable without retaining secrets.
    const hiddenProbeUrl = `${fixture.baseUrl}/api/metrics`;
    assert.equal(
      (networkBeforeHidden?.requests || []).some((request) => request?.url === hiddenProbeUrl),
      false,
      "the unique hidden-tab probe must not exist in the baseline"
    );
    await policyPage.evaluate((text) => {
      document.querySelector("#fixtureText").textContent = text;
    }, HIGH_RISK_POLICY_TEXT);
    await policyPage.evaluate(async (url) => {
      const response = await fetch(url, { cache: "no-store" });
      await response.text();
    }, hiddenProbeUrl);
    await waitFor(async () => {
      const activity = await networkActivity(hiddenPopup, policyTab.id);
      return (activity?.requests || []).some((request) => request?.url === hiddenProbeUrl);
    }, { label: "the exact value-free network probe in a hidden tab" });
    await delay(HIDDEN_SCAN_WAIT_MS);
    assert.equal((await badgeState(worker, policyTab.id)).text, "L", "hidden policy scan must remain idle");
    await closeTransientPage(hiddenPopup, "hidden-tab popup close");
    await activateTab(worker, policyTab.id);
    await waitFor(
      () => policyPage.evaluate(() => document.visibilityState === "visible"),
      { label: "policy tab to become visible" }
    );
    await waitForBadge(worker, policyTab.id, "H", 8_000);
    step("verified hidden-tab DOM scans idle/resume while value-free network observation continues");

    const popup = await openPopup({ browser, extension, extensionId, page: policyPage });
    await waitForPopupToggle(popup, false);
    await triggerPopupPageAnalysis(popup);
    const completedAnalysis = await waitForCompletedPopupAnalysis(popup);
    assert.ok(completedAnalysis.score >= 0 && completedAnalysis.score <= 100);
    assert.equal(completedAnalysis.meterMin, "0");
    assert.equal(completedAnalysis.meterMax, "100");
    assert.ok(completedAnalysis.source.length > 0);
    const scroll = await verifyPopupScrolling(popup);
    assert.ok(
      scroll.documentScrollHeight > scroll.documentClientHeight,
      `popup document must overflow vertically: ${JSON.stringify(scroll)}`
    );
    assert.ok(scroll.scrollHeight > scroll.clientHeight, `popup must expose a scroll range: ${JSON.stringify(scroll)}`);
    assert.ok(scroll.after > scroll.before, `popup scrollTop must change: ${JSON.stringify(scroll)}`);
    step("completed a real current-page analysis, rendered result content, and scrolled the popup");

    await toggleOverlayFromPopup(popup, true);
    const mountedOverlay = await waitForOverlayScore(worker, policyTab.id, completedAnalysis.score);
    assertMountedOverlayLayout(mountedOverlay);
    assert.equal(mountedOverlay.snapshot?.role, "meter");
    assert.equal(mountedOverlay.snapshot?.ariaValueNow, String(completedAnalysis.score));
    assert.match(mountedOverlay.snapshot?.ariaValueText || "", new RegExp(`${completedAnalysis.score}/100`));
    step("enabled the overlay in the real popup and reflected analysis in one closed 56px bottom-left host");

    let previousColorStamp = overlayStamp(mountedOverlay.snapshot);
    for (const [score, expected] of EXPECTED_COLORS) {
      const response = await publishSyntheticRisk(popup, policyUrl, score);
      assert.equal(response?.ok, true, JSON.stringify(response));
      const state = await waitForOverlayScore(worker, policyTab.id, score);
      const stamp = overlayStamp(state.snapshot);
      assert.ok(
        compareOverlayStamps(stamp, previousColorStamp) > 0,
        `overlay stamp must advance: ${JSON.stringify(previousColorStamp)} -> ${JSON.stringify(stamp)}`
      );
      previousColorStamp = stamp;
      assert.equal(state.snapshot?.color, expected.hex);
      assert.equal(state.snapshot?.text, String(score));
      assert.equal(state.snapshot?.role, "meter");
      assert.equal(state.snapshot?.ariaValueNow, String(score));
      assert.match(state.snapshot?.ariaValueText || "", new RegExp(`${score}/100`));
      assertMountedOverlayLayout(state);
      const badge = await badgeState(worker, policyTab.id);
      assert.deepEqual(badge.color, expected.rgba);
    }
    step("verified actual overlay colors and ARIA for 0/25/50/75/100 in the isolated extension world");

    await toggleOverlayFromPopup(popup, false);
    const removedOverlay = await waitForOverlay(
      worker,
      policyTab.id,
      (state) => state.snapshot?.enabled === false && state.ownedHostCount === 0,
      "overlay removal after popup toggle off"
    );
    assert.equal(removedOverlay.snapshot?.mounted, false);
    const whileDisabledResponse = await publishSyntheticRisk(popup, policyUrl, 75);
    assert.equal(whileDisabledResponse?.ok, true, JSON.stringify(whileDisabledResponse));
    await delay(200);
    assert.equal((await overlayState(worker, policyTab.id)).ownedHostCount, 0);
    await toggleOverlayFromPopup(popup, true);
    const restoredOverlay = await waitForOverlayScore(worker, policyTab.id, 75);
    assertMountedOverlayLayout(restoredOverlay);
    step("verified OFF removes the host and ON restores the latest tab score");

    await closeTransientPage(popup, "analyzed popup close before BFCache navigation");
    await installContentMessageTrace(worker, policyTab.id);
    await waitForContentObservation(worker, policyTab.id, true);
    step("armed content lifecycle tracing before BFCache navigation");

    await policyPage.evaluate(() => {
      globalThis.__unveilyE2ePageHidePersisted = null;
      globalThis.__unveilyE2ePageShowPersisted = null;
      addEventListener("pagehide", (event) => {
        globalThis.__unveilyE2ePageHidePersisted = event.persisted;
      }, { once: true });
      addEventListener("pageshow", (event) => {
        globalThis.__unveilyE2ePageShowPersisted = event.persisted;
      }, { once: true });
    });
    const bfcacheDestinationUrl = `${fixture.baseUrl}/ordinary-bfcache-destination`;
    await policyPage.goto(bfcacheDestinationUrl, { waitUntil: "domcontentloaded" });
    const bfcacheDestinationOverlay = await waitForOverlay(
      worker,
      policyTab.id,
      (state) => state.ownedHostCount === 1 && state.snapshot?.enabled === true,
      "enabled overlay in the BFCache destination document"
    );
    assertMountedOverlayLayout(bfcacheDestinationOverlay);
    step("entered the BFCache destination with the prior observation-enabled document frozen");
    await setCompanionOverlayEnabledFromStorage(extensionPage, worker, false);
    await waitForOverlay(
      worker,
      policyTab.id,
      (state) => state.ownedHostCount === 0 && state.snapshot?.enabled === false,
      "disabled overlay in the BFCache destination document"
    );
    await setObservationEnabledFromOptions(extensionPage, worker, false);
    await waitForContentObservation(worker, policyTab.id, false);
    step("disabled automatic observation from the real options page while the prior document was frozen");
    await policyPage.goBack({ waitUntil: "domcontentloaded", timeout: DEFAULT_TIMEOUT_MS });
    await waitFor(
      () => policyPage.evaluate((expectedUrl) => location.href === expectedUrl, policyUrl),
      { label: "the original policy document to return from BFCache" }
    );
    const bfcacheEvents = await policyPage.evaluate(() => ({
      pagehidePersisted: globalThis.__unveilyE2ePageHidePersisted,
      pageshowPersisted: globalThis.__unveilyE2ePageShowPersisted
    }));
    assert.deepEqual(bfcacheEvents, { pagehidePersisted: true, pageshowPersisted: true });
    const restoredDisabledOverlay = await waitForOverlay(
      worker,
      policyTab.id,
      (state) =>
        state.apiAvailable &&
        state.ownedHostCount === 0 &&
        state.snapshot?.enabled === false &&
        state.snapshot?.mounted === false,
      "authoritative OFF state in the restored BFCache document"
    );
    assert.equal(restoredDisabledOverlay.snapshot.protocolFailedClosed, false);
    await waitForContentObservation(worker, policyTab.id, false);
    step("restored the BFCache document with overlay and automatic observation both OFF");
    await resetContentMessageTrace(worker);
    await policyPage.evaluate(() => {
      const text = document.querySelector("#fixtureText");
      text.append(document.createTextNode(" BFCache restored while observation is disabled."));
    });
    await delay(1_500);
    const disabledRestoreMessages = await contentMessageTrace(worker);
    assert.equal(
      disabledRestoreMessages.some((message) => message.type === "PAGE_RISK_SCAN"),
      false,
      `a restored OFF document must not scan DOM mutations: ${JSON.stringify(disabledRestoreMessages)}`
    );

    await setObservationEnabledFromOptions(extensionPage, worker, true);
    await waitForContentObservation(worker, policyTab.id, true);
    await waitFor(
      async () =>
        (await contentMessageTrace(worker)).some((message) => message.type === "PAGE_RISK_SCAN"),
      { label: "automatic page scan after observation is explicitly re-enabled" }
    );
    step("confirmed restored OFF DOM mutations stay idle and an explicit ON restarts scanning");

    await setCompanionOverlayEnabledFromStorage(extensionPage, worker, true);
    const bfcacheReenabledOverlay = await waitForOverlay(
      worker,
      policyTab.id,
      (state) => state.ownedHostCount === 1 && state.snapshot?.enabled === true,
      "companion re-enable after the BFCache observation boundary"
    );
    assertMountedOverlayLayout(bfcacheReenabledOverlay);
    step("verified BFCache DOM-work suspension, restored OFF idling, and explicit observation reactivation");

    const ordinaryUrl = `${fixture.baseUrl}/ordinary-tab-isolation`;
    const ordinaryTab = await createTab(worker, {
      windowId: policyTab.windowId,
      url: ordinaryUrl,
      active: true
    });
    const ordinaryTarget = await browser.waitForTarget((target) => target.url() === ordinaryUrl, {
      timeout: DEFAULT_TIMEOUT_MS
    });
    const ordinaryPage = await ordinaryTarget.asPage();
    let ordinaryInitial;
    try {
      ordinaryInitial = await waitForOverlay(
        worker,
        ordinaryTab.id,
        (state) => state.ownedHostCount === 1 && state.snapshot?.score === null,
        "unknown overlay in a second tab"
      );
    } catch (error) {
      const diagnosticPopup = await openPopup({ browser, extension, extensionId, page: ordinaryPage });
      const preference = await companionPreferenceState(diagnosticPopup);
      await closeTransientPage(diagnosticPopup, "tab-isolation diagnostic popup close");
      throw new Error(`${error.message} Companion preference: ${JSON.stringify(preference)}`);
    }
    assertMountedOverlayLayout(ordinaryInitial);
    const ordinaryInitialStamp = overlayStamp(ordinaryInitial.snapshot);
    const ordinaryPopup = await openPopup({ browser, extension, extensionId, page: ordinaryPage });
    await triggerPopupPageAnalysis(ordinaryPopup);
    await waitForUnknownOverlayAfterStamp(worker, ordinaryTab.id, ordinaryInitialStamp);
    const restoredPolicyResponse = await publishSyntheticRisk(ordinaryPopup, policyUrl, 75);
    assert.equal(restoredPolicyResponse?.ok, true, JSON.stringify(restoredPolicyResponse));
    await waitForOverlayScore(worker, policyTab.id, 75);
    const ordinaryResponse = await publishSyntheticRisk(ordinaryPopup, ordinaryUrl, 25);
    assert.equal(ordinaryResponse?.ok, true, JSON.stringify(ordinaryResponse));
    await waitForOverlayScore(worker, ordinaryTab.id, 25);
    assert.equal((await overlayState(worker, policyTab.id)).snapshot?.score, 75);
    const policyResponse = await publishSyntheticRisk(ordinaryPopup, policyUrl, 100);
    assert.equal(policyResponse?.ok, true, JSON.stringify(policyResponse));
    await waitForOverlayScore(worker, policyTab.id, 100);
    assert.equal((await overlayState(worker, ordinaryTab.id)).snapshot?.score, 25);
    step("verified risk updates remain isolated between two live tabs");

    assert.deepEqual(await companionPreferenceState(ordinaryPopup), {
      stored: true,
      runtime: { ok: true, enabled: true }
    });
    await closeTransientPage(ordinaryPopup, "tab-isolation popup close");

    const staleSourceUrl = `${fixture.baseUrl}/ordinary-stale-source`;
    const staleDestinationUrl = `${fixture.baseUrl}/ordinary-stale-destination`;
    const staleTab = await createTab(worker, {
      windowId: policyTab.windowId,
      url: staleSourceUrl,
      active: true
    });
    const staleTarget = await browser.waitForTarget((target) => target.url() === staleSourceUrl, {
      timeout: DEFAULT_TIMEOUT_MS
    });
    const stalePage = await staleTarget.asPage();
    let staleInitial;
    try {
      staleInitial = await waitForOverlay(
        worker,
        staleTab.id,
        (state) => state.ownedHostCount === 1 && state.snapshot?.score === null,
        "stale-source initial overlay"
      );
    } catch (error) {
      const diagnosticPopup = await openPopup({ browser, extension, extensionId, page: stalePage });
      const preference = await companionPreferenceState(diagnosticPopup);
      await closeTransientPage(diagnosticPopup, "stale-source diagnostic popup close");
      throw new Error(`${error.message} Companion preference: ${JSON.stringify(preference)}`);
    }
    const staleInitialStamp = overlayStamp(staleInitial.snapshot);
    const staleSourcePopup = await openPopup({ browser, extension, extensionId, page: stalePage });
    await triggerPopupPageAnalysis(staleSourcePopup);
    await waitForUnknownOverlayAfterStamp(worker, staleTab.id, staleInitialStamp);
    const staleContext = await riskContextForUrl(staleSourcePopup, staleSourceUrl);
    const currentResponse = await publishSyntheticRiskForContext(staleSourcePopup, staleContext, 50);
    assert.equal(currentResponse?.ok, true, JSON.stringify(currentResponse));
    await waitForOverlayScore(worker, staleTab.id, 50);
    await closeTransientPage(staleSourcePopup, "stale-source popup close");
    await stalePage.goto(staleDestinationUrl, { waitUntil: "domcontentloaded" });
    const staleDestinationInitial = await waitForOverlay(
      worker,
      staleTab.id,
      (state) => state.ownedHostCount === 1 && state.snapshot?.score === null,
      "new-document unknown overlay"
    );
    const staleDestinationInitialStamp = overlayStamp(staleDestinationInitial.snapshot);
    const staleDestinationPopup = await openPopup({ browser, extension, extensionId, page: stalePage });
    await triggerPopupPageAnalysis(staleDestinationPopup);
    await waitForUnknownOverlayAfterStamp(worker, staleTab.id, staleDestinationInitialStamp);
    const rejectedStaleResponse = await publishSyntheticRiskForContext(staleDestinationPopup, staleContext, 100);
    assert.equal(rejectedStaleResponse?.ok, false);
    assert.equal(rejectedStaleResponse?.error, "Stale page context");
    await delay(300);
    assert.equal((await overlayState(worker, staleTab.id)).snapshot?.score, null);
    assert.equal((await overlayState(worker, policyTab.id)).snapshot?.score, 100);
    step("verified stale-document results are rejected without contaminating another tab");

    const strictCspUrl = `${fixture.baseUrl}/strict-csp`;
    const strictCspTab = await createTab(worker, {
      windowId: policyTab.windowId,
      url: strictCspUrl,
      active: false
    });
    await browser.waitForTarget((target) => target.url() === strictCspUrl, { timeout: DEFAULT_TIMEOUT_MS });
    const strictCspOverlay = await waitForOverlay(
      worker,
      strictCspTab.id,
      (state) => state.ownedHostCount === 1 && state.snapshot?.enabled === true,
      "overlay under a strict page CSP"
    );
    assertMountedOverlayLayout(strictCspOverlay);
    const strictResponse = await publishSyntheticRisk(staleDestinationPopup, strictCspUrl, 50);
    assert.equal(strictResponse?.ok, true, JSON.stringify(strictResponse));
    const strictReady = await waitForOverlayScore(worker, strictCspTab.id, 50);
    assert.equal(strictReady.snapshot?.color, EXPECTED_COLORS.get(50).hex);
    assert.equal(strictReady.snapshot?.role, "meter");
    step("verified the isolated overlay lifecycle on a strict-CSP page");

    await waitForPersistedRisk(worker, {
      tabId: policyTab.id,
      url: policyUrl,
      score: 100,
      source: "popup-page"
    });
    await waitForPersistedRisk(worker, {
      tabId: strictCspTab.id,
      url: strictCspUrl,
      score: 50,
      source: "popup-page"
    });
    const beforeRestart = await overlayState(worker, policyTab.id);
    const beforeRestartStrict = await overlayState(worker, strictCspTab.id);
    const beforeRestartStamp = overlayStamp(beforeRestart.snapshot);
    const beforeRestartStrictStamp = overlayStamp(beforeRestartStrict.snapshot);
    const previousWorkerTarget = workerTarget;
    await worker.close();
    const restartedWorkerPromise = extensionWorker(browser, extensionId, previousWorkerTarget);
    const wakeResponsePromise = staleDestinationPopup.evaluate(async () =>
      chrome.runtime.sendMessage({ type: "GET_COMPANION_OVERLAY_PREFERENCE" })
    );
    const restarted = await restartedWorkerPromise;
    workerTarget = restarted.target;
    worker = restarted.worker;
    const wakeResponse = await wakeResponsePromise;
    assert.equal(wakeResponse?.ok, true, JSON.stringify(wakeResponse));
    assert.equal(wakeResponse?.enabled, true);
    const startupPolicyState = await waitForOverlay(
      worker,
      policyTab.id,
      (state) =>
        state.ownedHostCount === 1 &&
        Number.isSafeInteger(state.snapshot?.generation) &&
        state.snapshot.generation > beforeRestartStamp.generation,
      "startup visibility broadcast to the existing policy document"
    );
    const startupStrictState = await waitForOverlay(
      worker,
      strictCspTab.id,
      (state) =>
        state.ownedHostCount === 1 &&
        Number.isSafeInteger(state.snapshot?.generation) &&
        state.snapshot.generation > beforeRestartStrictStamp.generation,
      "startup visibility broadcast to the existing strict-CSP document"
    );
    const startupPolicyStamp = overlayStamp(startupPolicyState.snapshot);
    const startupStrictStamp = overlayStamp(startupStrictState.snapshot);
    assert.ok(compareOverlayStamps(startupPolicyStamp, beforeRestartStamp) > 0);
    assert.ok(compareOverlayStamps(startupStrictStamp, beforeRestartStrictStamp) > 0);
    assert.equal(startupPolicyState.snapshot.score, 100);
    assert.equal(startupStrictState.snapshot.score, 50);
    const postRestartResponse = await publishSyntheticRisk(staleDestinationPopup, policyUrl, 0);
    assert.equal(postRestartResponse?.ok, true, JSON.stringify(postRestartResponse));
    const afterRestart = await waitForOverlayScore(worker, policyTab.id, 0);
    const afterRestartStamp = overlayStamp(afterRestart.snapshot);
    assert.ok(
      compareOverlayStamps(afterRestartStamp, startupPolicyStamp) > 0,
      `overlay stamp must advance after restart: ${JSON.stringify(startupPolicyStamp)} -> ${JSON.stringify(afterRestartStamp)}`
    );
    assert.equal(afterRestart.snapshot.color, EXPECTED_COLORS.get(0).hex);
    step("verified startup broadcasts and lexicographically monotonic stamps after MV3 worker restart");

    await activateTab(worker, policyTab.id);
    await policyPage.bringToFront();
    await waitForOverlayScore(worker, policyTab.id, 0);
    const screenshot = await policyPage.screenshot(
      process.env.E2E_SCREENSHOT_PATH ? { path: process.env.E2E_SCREENSHOT_PATH } : {}
    );
    assert.ok(screenshot.length > 1_000, "the actual fixture-page screenshot must contain rendered pixels");
    step(
      process.env.E2E_SCREENSHOT_PATH
        ? `saved actual page screenshot to ${process.env.E2E_SCREENSHOT_PATH}`
        : "captured the actual page with its rendered overlay"
    );

    const failClosedPopup = await openPopup({ browser, extension, extensionId, page: policyPage });
    await triggerPopupPageAnalysis(failClosedPopup);
    await waitForCompletedPopupAnalysis(failClosedPopup);
    await worker.evaluate(async (storageKey) => {
      await chrome.storage.session.set({ [storageKey]: Number.MAX_SAFE_INTEGER });
    }, COMPANION_OVERLAY_GENERATION_KEY);
    const normalWorkerTarget = workerTarget;
    await worker.close();
    const failedGenerationWorkerPromise = extensionWorker(browser, extensionId, normalWorkerTarget);
    const failClosedWakePromise = failClosedPopup.evaluate(async () =>
      chrome.runtime.sendMessage({ type: "GET_COMPANION_OVERLAY_PREFERENCE" })
    );
    const failedGenerationWorker = await failedGenerationWorkerPromise;
    workerTarget = failedGenerationWorker.target;
    worker = failedGenerationWorker.worker;
    const failClosedWake = await failClosedWakePromise;
    assert.equal(failClosedWake?.ok, true, JSON.stringify(failClosedWake));
    assert.equal(failClosedWake?.enabled, true, "the saved preference remains enabled during protocol failure");
    const failClosedPolicy = await waitForOverlay(
      worker,
      policyTab.id,
      (state) => state.ownedHostCount === 0 && state.snapshot?.protocolFailedClosed === true,
      "fail-closed host removal in the policy document"
    );
    const failClosedStrict = await waitForOverlay(
      worker,
      strictCspTab.id,
      (state) => state.ownedHostCount === 0 && state.snapshot?.protocolFailedClosed === true,
      "fail-closed host removal in the strict-CSP document"
    );
    assert.equal(failClosedPolicy.snapshot.enabled, false);
    assert.equal(failClosedPolicy.snapshot.mounted, false);
    assert.equal(failClosedStrict.snapshot.enabled, false);
    assert.equal(failClosedStrict.snapshot.mounted, false);
    step("verified generation-reservation failure latches existing documents OFF and removes their hosts");

    process.stdout.write(
      `\nCompanion overlay E2E passed in Chrome ${chrome.majorVersion}; extension ${extensionId}; fixture ${fixture.baseUrl}.\n`
    );

    await worker.evaluate(async (tabIds) => {
      await chrome.tabs.remove(tabIds.filter(Number.isInteger)).catch(() => {});
    }, [hiddenTab.id, ordinaryTab.id, staleTab.id, strictCspTab.id]).catch(() => {});
  } finally {
    if (browser) await browser.close().catch(() => {});
    await fixture.close().catch(() => {});
    await rm(profileDirectory, { recursive: true, force: true });
  }
}

run().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
