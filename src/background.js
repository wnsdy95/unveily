import { analyzePolicy } from "./analyzer.js";
import {
  comparePolicySnapshot,
  createPolicySnapshot,
  loadPolicySnapshots
} from "./policySnapshots.js";
import {
  buildPolicyChangeDedupeKey,
  buildPolicyChangeNotification,
  extractPolicyTextFromHtml,
  shouldNotifyPolicyChange
} from "./policyMonitor.js";
import { t } from "./i18n.js";

const MAX_REQUESTS_PER_TAB = 300;
const MAX_COOKIES_PER_TAB = 120;
const MAX_SNAPSHOTS_PER_TAB = 5;
const MAX_FIELD_KEYS = 40;
const tabRequests = new Map();
const tabCookies = new Map();
const tabObservationStartedAt = new Map();
const tabSnapshots = new Map();
const tabRiskIndicators = new Map();
const POLICY_CHECK_ALARM = "policy-snapshot-check";
const NOTIFIED_POLICY_CHANGES_KEY = "notifiedPolicyChanges";
const POLICY_CHECK_INTERVAL_MINUTES = 360;
const RISK_LEVELS = new Set(["unknown", "analyzing", "low", "medium", "high"]);

function getHost(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function getQueryKeys(url) {
  try {
    return Array.from(new URL(url).searchParams.keys()).slice(0, MAX_FIELD_KEYS);
  } catch {
    return [];
  }
}

function parseJsonKeys(raw) {
  try {
    const parsed = JSON.parse(raw);
    return collectKeys(parsed).slice(0, MAX_FIELD_KEYS);
  } catch {
    return [];
  }
}

function collectKeys(value, prefix = "") {
  if (!value || typeof value !== "object") return [];
  if (Array.isArray(value)) return value.flatMap((item) => collectKeys(item, prefix));

  return Object.entries(value).flatMap(([key, nested]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    return [path, ...collectKeys(nested, path)];
  });
}

function getRequestBodyKeys(requestBody) {
  if (!requestBody) return [];

  const formKeys = requestBody.formData ? Object.keys(requestBody.formData) : [];
  const rawKeys = (requestBody.raw || [])
    .flatMap((item) => {
      if (!item.bytes) return [];
      const text = new TextDecoder("utf-8").decode(item.bytes);
      return parseJsonKeys(text);
    });

  return Array.from(new Set([...formKeys, ...rawKeys])).slice(0, MAX_FIELD_KEYS);
}

function rememberRequest(details) {
  if (details.tabId < 0) return;
  ensureObservation(details.tabId);

  const request = {
    requestId: details.requestId,
    url: details.url,
    host: getHost(details.url),
    method: details.method,
    type: details.type,
    timeStamp: details.timeStamp,
    queryKeys: getQueryKeys(details.url),
    bodyKeys: getRequestBodyKeys(details.requestBody)
  };

  const requests = tabRequests.get(details.tabId) || [];
  requests.push(request);

  if (requests.length > MAX_REQUESTS_PER_TAB) {
    requests.splice(0, requests.length - MAX_REQUESTS_PER_TAB);
  }

  tabRequests.set(details.tabId, requests);
}

chrome.webRequest.onBeforeRequest.addListener(
  rememberRequest,
  { urls: ["http://*/*", "https://*/*"] },
  ["requestBody"]
);

chrome.runtime.onInstalled.addListener(() => {
  schedulePolicyChecks();
});

chrome.runtime.onStartup.addListener(() => {
  schedulePolicyChecks();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === POLICY_CHECK_ALARM) {
    checkSavedPoliciesForChanges();
  }
});

chrome.notifications.onClicked.addListener((notificationId) => {
  if (!notificationId.startsWith("policy-change:")) return;
  const url = decodeURIComponent(notificationId.slice("policy-change:".length));
  chrome.tabs.create({ url });
});

function schedulePolicyChecks() {
  chrome.alarms.create(POLICY_CHECK_ALARM, {
    delayInMinutes: 1,
    periodInMinutes: POLICY_CHECK_INTERVAL_MINUTES
  });
}

chrome.tabs.onRemoved.addListener((tabId) => {
  tabRequests.delete(tabId);
  tabCookies.delete(tabId);
  tabObservationStartedAt.delete(tabId);
  tabSnapshots.delete(tabId);
  tabRiskIndicators.delete(tabId);
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) {
    tabRiskIndicators.delete(tabId);
  }
});

chrome.cookies.onChanged.addListener((changeInfo) => {
  const cookie = changeInfo.cookie;
  if (!cookie?.domain) return;

  chrome.tabs.query({ url: ["http://*/*", "https://*/*"] }, (tabs) => {
    tabs
      .filter((tab) => tab.id >= 0 && hostMatchesCookieDomain(getHost(tab.url || ""), cookie.domain))
      .forEach((tab) => rememberCookieChange(tab.id, changeInfo));
  });
});

function rememberCookieChange(tabId, changeInfo) {
  ensureObservation(tabId);
  const cookie = changeInfo.cookie;
  const cookies = tabCookies.get(tabId) || [];
  cookies.push({
    name: cookie.name,
    domain: cookie.domain,
    path: cookie.path,
    secure: cookie.secure,
    httpOnly: cookie.httpOnly,
    sameSite: cookie.sameSite,
    session: cookie.session,
    expirationDate: cookie.expirationDate,
    removed: changeInfo.removed,
    cause: changeInfo.cause,
    timeStamp: Date.now()
  });

  if (cookies.length > MAX_COOKIES_PER_TAB) {
    cookies.splice(0, cookies.length - MAX_COOKIES_PER_TAB);
  }

  tabCookies.set(tabId, cookies);
}

function hostMatchesCookieDomain(host, cookieDomain) {
  const normalizedDomain = cookieDomain.replace(/^\./, "");
  return host === normalizedDomain || host.endsWith(`.${normalizedDomain}`);
}

function ensureObservation(tabId) {
  if (!tabObservationStartedAt.has(tabId)) {
    tabObservationStartedAt.set(tabId, Date.now());
  }
}

function createSnapshot(tabId, label = t("snapshotBaseline")) {
  ensureObservation(tabId);
  const requests = tabRequests.get(tabId) || [];
  const cookies = tabCookies.get(tabId) || [];
  const snapshot = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    label,
    createdAt: Date.now(),
    requestCount: requests.length,
    cookieCount: cookies.length
  };
  const snapshots = tabSnapshots.get(tabId) || [];
  snapshots.push(snapshot);

  if (snapshots.length > MAX_SNAPSHOTS_PER_TAB) {
    snapshots.splice(0, snapshots.length - MAX_SNAPSHOTS_PER_TAB);
  }

  tabSnapshots.set(tabId, snapshots);
  return snapshot;
}

function normalizeRiskLevel(level) {
  return RISK_LEVELS.has(level) ? level : "unknown";
}

function createRiskIndicator(indicator = {}) {
  return {
    level: normalizeRiskLevel(indicator.level),
    score: Number.isFinite(indicator.score) ? Math.round(indicator.score) : null,
    label: typeof indicator.label === "string" ? indicator.label : "",
    source: typeof indicator.source === "string" ? indicator.source : "unknown",
    title: typeof indicator.title === "string" ? indicator.title : "",
    url: typeof indicator.url === "string" ? indicator.url : "",
    updatedAt: Date.now()
  };
}

function createRiskIndicatorFromPolicy(policyAnalysis, metadata = {}) {
  if (!policyAnalysis?.ok) {
    return createRiskIndicator({
      ...metadata,
      level: "unknown",
      score: null,
      label: policyAnalysis?.message || ""
    });
  }

  return createRiskIndicator({
    ...metadata,
    level: policyAnalysis.level,
    score: policyAnalysis.score,
    label: policyAnalysis.levelLabel || policyAnalysis.level
  });
}

function rememberRiskIndicator(tabId, indicator) {
  if (!Number.isInteger(tabId) || tabId < 0) return null;
  const normalized = createRiskIndicator(indicator);
  tabRiskIndicators.set(tabId, normalized);
  return normalized;
}

function publishRiskIndicator(tabId, indicator) {
  const normalized = rememberRiskIndicator(tabId, indicator);
  if (!normalized) return null;

  chrome.tabs.sendMessage(tabId, { type: "RISK_INDICATOR_UPDATE", indicator: normalized }, () => {
    // The content script may not be available on restricted or not-yet-ready pages.
    void chrome.runtime.lastError;
  });
  return normalized;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "GET_NETWORK_ACTIVITY") {
    ensureObservation(message.tabId);
    sendResponse({
      requests: tabRequests.get(message.tabId) || [],
      cookies: tabCookies.get(message.tabId) || [],
      observationStartedAt: tabObservationStartedAt.get(message.tabId),
      snapshots: tabSnapshots.get(message.tabId) || []
    });
    return false;
  }

  if (message?.type === "CLEAR_NETWORK_ACTIVITY") {
    tabRequests.set(message.tabId, []);
    tabCookies.set(message.tabId, []);
    tabSnapshots.set(message.tabId, []);
    tabObservationStartedAt.set(message.tabId, Date.now());
    sendResponse({ ok: true, observationStartedAt: tabObservationStartedAt.get(message.tabId) });
    return false;
  }

  if (message?.type === "SAVE_OBSERVATION_SNAPSHOT") {
    const snapshot = createSnapshot(message.tabId, message.label || t("snapshotBaseline"));
    sendResponse({ ok: true, snapshot, snapshots: tabSnapshots.get(message.tabId) || [] });
    return false;
  }

  if (message?.type === "GET_RISK_INDICATOR") {
    const tabId = sender.tab?.id ?? message.tabId;
    sendResponse({
      ok: true,
      indicator: tabRiskIndicators.get(tabId) || createRiskIndicator({ level: "unknown", url: message.url })
    });
    return false;
  }

  if (message?.type === "PAGE_RISK_SCAN") {
    const tabId = sender.tab?.id ?? message.tabId;
    const policyAnalysis = analyzePolicy(message.text || "");
    const indicator = publishRiskIndicator(
      tabId,
      createRiskIndicatorFromPolicy(policyAnalysis, {
        source: "page-scan",
        title: message.title,
        url: message.url
      })
    );
    sendResponse({ ok: true, indicator });
    return false;
  }

  if (message?.type === "SET_RISK_INDICATOR") {
    const tabId = message.tabId ?? sender.tab?.id;
    const indicator = publishRiskIndicator(tabId, message.indicator || {});
    sendResponse({ ok: Boolean(indicator), indicator });
    return false;
  }

  if (message?.type === "CHECK_SAVED_POLICIES_NOW") {
    checkSavedPoliciesForChanges().then((result) => sendResponse(result));
    return true;
  }

  return false;
});

async function checkSavedPoliciesForChanges() {
  const snapshots = await loadPolicySnapshots();
  const entries = Object.entries(snapshots).filter(([_origin, snapshot]) => snapshot?.url);
  const results = [];

  for (const [origin, previousSnapshot] of entries) {
    try {
      const result = await checkSinglePolicy(origin, previousSnapshot);
      results.push(result);
    } catch (error) {
      results.push({ origin, ok: false, error: String(error?.message || error) });
    }
  }

  return {
    ok: true,
    checked: results.length,
    changed: results.filter((result) => result.changed).length,
    notified: results.filter((result) => result.notified).length,
    results
  };
}

async function checkSinglePolicy(origin, previousSnapshot) {
  const response = await fetch(previousSnapshot.url, { credentials: "include", cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Policy fetch failed: ${response.status}`);
  }

  const html = await response.text();
  const text = extractPolicyTextFromHtml(html);
  const policyAnalysis = analyzePolicy(text);
  const currentSnapshot = await createPolicySnapshot({
    title: previousSnapshot.title,
    url: previousSnapshot.url,
    text,
    policyAnalysis
  });
  const changeAnalysis = comparePolicySnapshot(previousSnapshot, currentSnapshot);

  if (!changeAnalysis.changed) {
    return { origin, ok: true, changed: false, notified: false };
  }

  const notified = await maybeNotifyPolicyChange(origin, previousSnapshot, currentSnapshot, changeAnalysis);
  return { origin, ok: true, changed: true, notified };
}

async function maybeNotifyPolicyChange(origin, previousSnapshot, currentSnapshot, changeAnalysis) {
  if (!shouldNotifyPolicyChange(changeAnalysis)) return false;

  const dedupeKey = buildPolicyChangeDedupeKey(origin, changeAnalysis, currentSnapshot);
  const notifiedChanges = await loadNotifiedPolicyChanges();
  if (notifiedChanges[origin] === dedupeKey) return false;

  const notification = buildPolicyChangeNotification(currentSnapshot, changeAnalysis);
  await chrome.notifications.create(`policy-change:${encodeURIComponent(previousSnapshot.url)}`, {
    type: "basic",
    iconUrl: chrome.runtime.getURL("icons/icon.png"),
    title: notification.title,
    message: notification.message,
    priority: 2
  });

  notifiedChanges[origin] = dedupeKey;
  await chrome.storage.local.set({ [NOTIFIED_POLICY_CHANGES_KEY]: notifiedChanges });
  return true;
}

async function loadNotifiedPolicyChanges() {
  const result = await chrome.storage.local.get(NOTIFIED_POLICY_CHANGES_KEY);
  return result[NOTIFIED_POLICY_CHANGES_KEY] && typeof result[NOTIFIED_POLICY_CHANGES_KEY] === "object"
    ? result[NOTIFIED_POLICY_CHANGES_KEY]
    : {};
}
