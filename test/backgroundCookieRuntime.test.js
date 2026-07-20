import assert from "node:assert/strict";
import test from "node:test";
import { setTimeout as delay } from "node:timers/promises";
import { OBSERVATION_SETTINGS_KEY } from "../src/observationSettings.js";

function eventChannel() {
  const listeners = [];
  return {
    listeners,
    addListener(listener) {
      listeners.push(listener);
    }
  };
}

function selectStorage(data, keys) {
  if (keys === null || keys === undefined) return { ...data };
  if (typeof keys === "string") return keys in data ? { [keys]: data[keys] } : {};
  if (Array.isArray(keys)) {
    return Object.fromEntries(keys.filter((key) => key in data).map((key) => [key, data[key]]));
  }
  return { ...data };
}

function createChromeMock() {
  const tabs = new Map([
    [1, { id: 1, status: "complete", url: "https://account.example.com/home" }],
    [2, { id: 2, status: "complete", url: "https://shop.example.com/cart" }],
    [3, { id: 3, status: "complete", url: "https://unique.test/home" }],
    [4, { id: 4, status: "complete", url: "https://race.test/home" }]
  ]);
  const frames = new Map(
    Array.from(tabs, ([tabId, tab]) => [
      tabId,
      [
        {
          frameId: 0,
          parentFrameId: -1,
          documentId: `document-${tabId}`,
          documentLifecycle: "active",
          url: tab.url
        }
      ]
    ])
  );
  const localData = {
    companionOverlayEnabled: true,
    [OBSERVATION_SETTINGS_KEY]: {
      enabled: true,
      excludedOrigins: ["https://account.example.com"]
    }
  };
  const sessionData = {};
  const cookieInventory = new Map();
  const tabMessages = [];
  const hooks = { onGetAllFrames: null, tabsQuerySnapshot: null };
  const channels = {
    beforeRequest: eventChannel(),
    committed: eventChannel(),
    history: eventChannel(),
    referenceFragment: eventChannel(),
    beforeNavigate: eventChannel(),
    navigationError: eventChannel(),
    cookieChanged: eventChannel(),
    message: eventChannel(),
    storageChanged: eventChannel(),
    tabUpdated: eventChannel(),
    suspended: eventChannel()
  };

  const chrome = {
    runtime: {
      id: "cookie-runtime-test-extension",
      lastError: null,
      getURL: (path) => `chrome-extension://cookie-runtime-test-extension/${path}`,
      onInstalled: eventChannel(),
      onStartup: eventChannel(),
      onSuspend: channels.suspended,
      onMessage: channels.message
    },
    webRequest: { onBeforeRequest: channels.beforeRequest },
    webNavigation: {
      onCommitted: channels.committed,
      onHistoryStateUpdated: channels.history,
      onReferenceFragmentUpdated: channels.referenceFragment,
      onBeforeNavigate: channels.beforeNavigate,
      onErrorOccurred: channels.navigationError,
      async getAllFrames({ tabId }) {
        const snapshot = (frames.get(tabId) || []).map((frame) => ({ ...frame }));
        hooks.onGetAllFrames?.(tabId);
        return snapshot;
      },
      async getFrame({ tabId, frameId }) {
        const frame = (frames.get(tabId) || []).find((candidate) => candidate.frameId === frameId);
        return frame ? { ...frame } : null;
      }
    },
    cookies: {
      onChanged: channels.cookieChanged,
      async getAll(details = {}) {
        if (!details.url) return [];
        return (cookieInventory.get(new URL(details.url).origin) || []).map((cookie) => ({ ...cookie }));
      }
    },
    tabs: {
      onRemoved: eventChannel(),
      onUpdated: channels.tabUpdated,
      async get(tabId) {
        const tab = tabs.get(tabId);
        if (!tab) throw new Error("missing tab");
        return { ...tab };
      },
      query(_query, callback) {
        const source = Array.isArray(hooks.tabsQuerySnapshot)
          ? hooks.tabsQuerySnapshot
          : Array.from(tabs.values());
        const result = source.map((tab) => ({ ...tab }));
        if (callback) {
          callback(result);
          return undefined;
        }
        return Promise.resolve(result);
      },
      sendMessage(tabId, message, optionsOrCallback, callback) {
        const options =
          optionsOrCallback && typeof optionsOrCallback === "object" ? optionsOrCallback : undefined;
        tabMessages.push({
          tabId,
          message: structuredClone(message),
          ...(options ? { options: structuredClone(options) } : {})
        });
        const done = typeof optionsOrCallback === "function" ? optionsOrCallback : callback;
        done?.();
      },
      async create() {
        return {};
      }
    },
    storage: {
      local: {
        async setAccessLevel() {},
        async get(keys) {
          return selectStorage(localData, keys);
        },
        async set(values) {
          Object.assign(localData, values);
        }
      },
      session: {
        async get(keys) {
          return selectStorage(sessionData, keys);
        },
        async set(values) {
          Object.assign(sessionData, values);
        },
        async remove(keys) {
          for (const key of Array.isArray(keys) ? keys : [keys]) delete sessionData[key];
        }
      },
      onChanged: channels.storageChanged
    },
    alarms: {
      create() {},
      async get() {
        return null;
      },
      async clear() {
        return true;
      },
      onAlarm: eventChannel()
    },
    notifications: { onClicked: eventChannel(), async create() {} },
    action: {
      async setBadgeText() {},
      async setBadgeBackgroundColor() {}
    },
    i18n: {
      getUILanguage: () => "en",
      getMessage: () => ""
    }
  };

  return {
    chrome,
    channels,
    cookieInventory,
    frames,
    hooks,
    localData,
    sessionData,
    tabMessages,
    tabs
  };
}

async function settleCookieBatch() {
  await delay(140);
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

async function sendRuntimeMessage(listener, message) {
  return new Promise((resolve, reject) => {
    const keepAlive = listener(
      message,
      {
        id: "cookie-runtime-test-extension",
        url: "chrome-extension://cookie-runtime-test-extension/src/popup.html"
      },
      resolve
    );
    if (keepAlive !== true) reject(new Error("background did not keep the response channel open"));
  });
}

async function sendRuntimeMessageFromContent(listener, message, mock, tabId, senderOverrides = {}) {
  const tab = mock.tabs.get(tabId);
  const frame = mock.frames.get(tabId)?.[0];
  return new Promise((resolve, reject) => {
    const keepAlive = listener(
      message,
      {
        id: "cookie-runtime-test-extension",
        tab: { ...tab },
        frameId: 0,
        documentId: frame?.documentId,
        documentLifecycle: "active",
        url: tab?.url,
        ...senderOverrides
      },
      resolve
    );
    if (keepAlive !== true) reject(new Error("background did not keep the response channel open"));
  });
}

test("background cookie batching preserves attribution and document-session boundaries", async () => {
  const mock = createChromeMock();
  globalThis.chrome = mock.chrome;
  const background = await import(`../src/background.js?cookie-runtime-test=${Date.now()}`);
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));

  const beforeRequest = mock.channels.beforeRequest.listeners[0];
  const cookieChanged = mock.channels.cookieChanged.listeners[0];
  const onMessage = mock.channels.message.listeners[0];
  assert.equal(typeof beforeRequest, "function");
  assert.equal(typeof cookieChanged, "function");
  assert.deepEqual(
    await sendRuntimeMessage(onMessage, { type: "GET_COMPANION_OVERLAY_PREFERENCE" }),
    { ok: true, enabled: true }
  );
  const initialCompanion = await sendRuntimeMessageFromContent(
    onMessage,
    { type: "GET_COMPANION_OVERLAY_STATE" },
    mock,
    3
  );
  assert.equal(initialCompanion.ok, true);
  assert.equal(initialCompanion.enabled, true);
  assert.equal(initialCompanion.state.status, "unknown");
  const automaticIndicator = await sendRuntimeMessageFromContent(
    onMessage,
    {
      type: "PAGE_RISK_SCAN",
      policyLike: false,
      policyConfidence: 0,
      textLength: 0
    },
    mock,
    3
  );
  assert.equal(automaticIndicator.ok, true);
  assert.equal(automaticIndicator.skipped, true);
  const policyText =
    "Privacy Policy. We collect email addresses to provide the service. " +
    "We may share data with service providers and retain it for 30 days. " +
    "You may request access, correction, or deletion of personal data.";
  const analyzedIndicator = await sendRuntimeMessageFromContent(
    onMessage,
    {
      type: "PAGE_RISK_SCAN",
      policyLike: true,
      policyConfidence: 0.95,
      textLength: policyText.length,
      text: policyText
    },
    mock,
    3
  );
  assert.equal(analyzedIndicator.ok, true);
  assert.equal(analyzedIndicator.indicator.source, "page-scan");
  const analyzedCompanion = await sendRuntimeMessageFromContent(
    onMessage,
    { type: "GET_COMPANION_OVERLAY_STATE" },
    mock,
    3
  );
  assert.equal(analyzedCompanion.state.status, "ready");
  assert.equal(Number.isFinite(analyzedCompanion.state.score), true);
  const staleCompanion = await sendRuntimeMessageFromContent(
    onMessage,
    { type: "GET_COMPANION_OVERLAY_STATE" },
    mock,
    3,
    { documentId: "stale-document" }
  );
  assert.deepEqual(staleCompanion, {
    ok: false,
    error: "Stale companion overlay document"
  });
  assert.deepEqual(
    await sendRuntimeMessage(onMessage, {
      type: "SET_COMPANION_OVERLAY_PREFERENCE",
      enabled: false
    }),
    { ok: true, enabled: false }
  );
  assert.deepEqual(
    await sendRuntimeMessage(onMessage, {
      type: "SET_COMPANION_OVERLAY_PREFERENCE",
      enabled: true
    }),
    { ok: true, enabled: true }
  );
  mock.channels.storageChanged.listeners[0](
    { companionOverlayEnabled: { newValue: false } },
    "local"
  );
  await new Promise((resolve) => setImmediate(resolve));
  mock.channels.storageChanged.listeners[0](
    { companionOverlayEnabled: { newValue: true } },
    "local"
  );
  await new Promise((resolve) => setImmediate(resolve));
  assert.ok(
    mock.tabMessages.some(
      (entry) =>
        entry.tabId === 3 &&
        entry.message.type === "COMPANION_OVERLAY_VISIBILITY" &&
        entry.message.enabled === true &&
        entry.options?.documentId === "document-3"
    )
  );
  mock.tabMessages.length = 0;

  // An excluded first-party candidate still participates in ambiguity calculation.
  beforeRequest({
    tabId: 2,
    frameId: 0,
    documentId: "document-2",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: mock.tabs.get(2).url
  });
  await new Promise((resolve) => setImmediate(resolve));
  cookieChanged({
    removed: false,
    cause: "explicit",
    cookie: {
      name: "shared-id",
      value: "ambiguous-secret-value",
      domain: ".example.com",
      hostOnly: false,
      path: "/accounts/12345",
      storeId: "0"
    }
  });
  await settleCookieBatch();
  let persisted = background.buildPersistedObservationState();
  assert.deepEqual(persisted.tabs["2"].cookies, []);
  assert.doesNotMatch(JSON.stringify(persisted), /ambiguous-secret-value/);

  // A uniquely attributable cold tab is recovered from its stable current top document.
  const coldCookie = {
    name: "customer_1234567890",
    value: "cold-secret-value",
    domain: "unique.test",
    hostOnly: true,
    path: "/users/98765",
    secure: true,
    httpOnly: true,
    sameSite: "lax",
    storeId: "0"
  };
  const partitionedCookie = {
    name: "_ga_partitioned_9876543210",
    value: "partitioned-secret-value",
    domain: "analytics.test",
    hostOnly: true,
    path: "/events/123e4567-e89b-42d3-a456-426614174000",
    secure: true,
    sameSite: "none",
    storeId: "0",
    partitionKey: { topLevelSite: "https://unique.test" }
  };
  mock.cookieInventory.set("https://unique.test", [coldCookie, partitionedCookie]);
  const observedAfter = Date.now();
  cookieChanged({ removed: false, cause: "explicit", cookie: coldCookie });
  cookieChanged({ removed: false, cause: "explicit", cookie: partitionedCookie });
  await settleCookieBatch();
  persisted = background.buildPersistedObservationState();
  const coldState = persisted.tabs["3"];
  assert.equal(coldState.session.documentId, "document-3");
  assert.equal(coldState.cookies.length, 2);
  const unpartitionedState = coldState.cookies.find((cookie) => !cookie.partitionKey);
  const partitionedState = coldState.cookies.find((cookie) => cookie.partitionKey);
  assert.equal(unpartitionedState.name, "customer___number__");
  assert.equal(unpartitionedState.timingConfidence, "unknown");
  assert.equal("timeStamp" in unpartitionedState, false);
  assert.equal(partitionedState.name, "_ga___identifier__");
  assert.equal(partitionedState.timingConfidence, "observed");
  assert.ok(partitionedState.timeStamp >= observedAfter);
  assert.ok(coldState.session.startedAt <= partitionedState.timeStamp);
  assert.doesNotMatch(JSON.stringify(coldState), /1234567890|9876543210|123e4567/);

  const coldResponse = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: 3
  });
  assert.equal(coldResponse.cookies.length, 2);
  assert.equal(
    coldResponse.cookies.find((cookie) => !cookie.partitionKey).timingConfidence,
    "unknown"
  );
  assert.equal(
    coldResponse.cookies.find((cookie) => cookie.partitionKey).timingConfidence,
    "observed"
  );
  assert.doesNotMatch(JSON.stringify(coldResponse), /(?:cold|partitioned)-secret-value/);

  // A tab-query snapshot must never roll an existing live session back to an
  // older route. A mismatch is discarded without even consulting a cached
  // frame context.
  beforeRequest({
    tabId: 4,
    frameId: 0,
    documentId: "document-4",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: mock.tabs.get(4).url
  });
  await new Promise((resolve) => setImmediate(resolve));
  mock.tabs.get(4).url = "https://race.test/reloaded";
  mock.frames.set(4, [
    {
      frameId: 0,
      parentFrameId: -1,
      documentId: "document-4-reloaded",
      documentLifecycle: "active",
      url: mock.tabs.get(4).url
    }
  ]);
  let replacedDuringLookup = false;
  mock.hooks.onGetAllFrames = (tabId) => {
    if (tabId !== 4 || replacedDuringLookup) return;
    replacedDuringLookup = true;
    beforeRequest({
      tabId: 4,
      frameId: 0,
      documentId: "document-4-reloaded",
      documentLifecycle: "active",
      type: "main_frame",
      method: "GET",
      url: mock.tabs.get(4).url
    });
  };
  const originalDateNow = Date.now;
  const raceTime = originalDateNow();
  Date.now = () => raceTime;
  try {
    cookieChanged({
      removed: false,
      cause: "explicit",
      cookie: {
        name: "raced-id",
        value: "raced-secret-value",
        domain: "race.test",
        hostOnly: true,
        path: "/",
        storeId: "0"
      }
    });
    await settleCookieBatch();
  } finally {
    Date.now = originalDateNow;
  }
  assert.equal(replacedDuringLookup, false);
  persisted = background.buildPersistedObservationState();
  assert.equal(persisted.tabs["4"].session.documentId, "document-4");
  assert.deepEqual(persisted.tabs["4"].cookies, []);

  // Once B is authoritative, a cached/stale tabs.query result for A is bound
  // to A's fingerprint and generation and cannot rotate B back to A.
  beforeRequest({
    tabId: 4,
    frameId: 0,
    documentId: "document-4-reloaded",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: mock.tabs.get(4).url
  });
  await new Promise((resolve) => setImmediate(resolve));
  mock.hooks.tabsQuerySnapshot = Array.from(mock.tabs.values(), (tab) =>
    tab.id === 4 ? { ...tab, url: "https://race.test/home" } : { ...tab }
  );
  cookieChanged({
    removed: false,
    cause: "explicit",
    cookie: {
      name: "stale-context-id",
      domain: "race.test",
      hostOnly: true,
      path: "/",
      storeId: "0"
    }
  });
  await settleCookieBatch();
  mock.hooks.tabsQuerySnapshot = null;
  persisted = background.buildPersistedObservationState();
  assert.equal(persisted.tabs["4"].session.documentId, "document-4-reloaded");
  assert.deepEqual(persisted.tabs["4"].cookies, []);

  // Coalescing keeps only the final state for an identity.
  const transientCookie = {
    name: "transient-final-state",
    domain: "unique.test",
    hostOnly: true,
    path: "/",
    storeId: "0"
  };
  cookieChanged({ removed: false, cause: "explicit", cookie: transientCookie });
  cookieChanged({ removed: true, cause: "explicit", cookie: transientCookie });
  await settleCookieBatch();
  persisted = background.buildPersistedObservationState();
  assert.equal(
    persisted.tabs["3"].cookies.some((cookie) => cookie.name === "transient-final-state"),
    false
  );

  // A partition-attributed identity keeps its first and last evidence even
  // when queue coalescing sees an update followed by deletion before flush.
  const evidenceCookie = {
    name: "_ga",
    domain: "analytics.test",
    hostOnly: true,
    path: "/",
    storeId: "0",
    partitionKey: { topLevelSite: "https://unique.test" }
  };
  const evidenceStart = Date.now() + 2_000;
  Date.now = () => evidenceStart;
  try {
    cookieChanged({ removed: false, cause: "explicit", cookie: evidenceCookie });
    Date.now = () => evidenceStart + 4_000;
    cookieChanged({ removed: true, cause: "explicit", cookie: evidenceCookie });

    const deleteOnlyCookie = {
      ...evidenceCookie,
      name: "_ga_delete_only",
      domain: "delete-only.analytics.test"
    };
    const deleteThenSetCookie = {
      ...evidenceCookie,
      name: "_ga_delete_set",
      domain: "delete-set.analytics.test"
    };
    const setThenUpdateCookie = {
      ...evidenceCookie,
      name: "_ga_set_update",
      domain: "set-update.analytics.test"
    };
    Date.now = () => evidenceStart + 10_000;
    cookieChanged({ removed: true, cause: "explicit", cookie: deleteOnlyCookie });
    Date.now = () => evidenceStart + 11_000;
    cookieChanged({ removed: true, cause: "explicit", cookie: deleteThenSetCookie });
    Date.now = () => evidenceStart + 12_000;
    cookieChanged({ removed: false, cause: "explicit", cookie: deleteThenSetCookie });
    Date.now = () => evidenceStart + 13_000;
    cookieChanged({ removed: false, cause: "explicit", cookie: setThenUpdateCookie });
    Date.now = () => evidenceStart + 14_000;
    cookieChanged({ removed: false, cause: "overwrite", cookie: setThenUpdateCookie });
  } finally {
    Date.now = originalDateNow;
  }
  await settleCookieBatch();
  persisted = background.buildPersistedObservationState();
  const deletedEvidence = persisted.tabs["3"].cookies.find(
    (cookie) => cookie.name === "_ga" && cookie.removed
  );
  assert.equal(deletedEvidence.firstObservedAt, evidenceStart);
  assert.equal(deletedEvidence.firstSetObservedAt, evidenceStart);
  assert.equal(deletedEvidence.lastSetObservedAt, evidenceStart);
  assert.equal(deletedEvidence.lastObservedAt, evidenceStart);
  assert.equal(deletedEvidence.deletedAt, evidenceStart + 4_000);
  assert.equal(deletedEvidence.timeStamp, evidenceStart);
  assert.equal(
    persisted.tabs["3"].cookies.some(
      (cookie) => cookie.domain === "delete-only.analytics.test"
    ),
    false
  );
  const deleteThenSet = persisted.tabs["3"].cookies.find(
    (cookie) => cookie.domain === "delete-set.analytics.test"
  );
  assert.equal(deleteThenSet.removed, false);
  assert.equal(deleteThenSet.firstSetObservedAt, evidenceStart + 12_000);
  assert.equal(deleteThenSet.lastSetObservedAt, evidenceStart + 12_000);
  assert.equal(deleteThenSet.deletedAt, evidenceStart + 11_000);
  const setThenUpdate = persisted.tabs["3"].cookies.find(
    (cookie) => cookie.domain === "set-update.analytics.test"
  );
  assert.equal(setThenUpdate.removed, false);
  assert.equal(setThenUpdate.firstSetObservedAt, evidenceStart + 13_000);
  assert.equal(setThenUpdate.lastSetObservedAt, evidenceStart + 14_000);
  assert.equal("deletedAt" in setThenUpdate, false);

  // A low-volume domain survives a 500-event burst from other domains. Every
  // domain is independently capped, and global eviction comes from a most
  // represented domain instead of blindly deleting the oldest domain.
  for (let domainIndex = 0; domainIndex <= 10; domainIndex += 1) {
    const tabId = 10 + domainIndex;
    const url = `https://queue${domainIndex}.test/home`;
    mock.tabs.set(tabId, { id: tabId, status: "complete", url });
    mock.frames.set(tabId, [
      {
        frameId: 0,
        parentFrameId: -1,
        documentId: `queue-document-${domainIndex}`,
        documentLifecycle: "active",
        url
      }
    ]);
  }
  cookieChanged({
    removed: false,
    cause: "explicit",
    cookie: {
      name: "fairness-sentinel",
      domain: "queue0.test",
      hostOnly: true,
      path: "/",
      storeId: "0"
    }
  });
  for (let domainIndex = 1; domainIndex <= 10; domainIndex += 1) {
    const cookieCount = domainIndex === 1 ? 60 : 50;
    for (let cookieIndex = 0; cookieIndex < cookieCount; cookieIndex += 1) {
      cookieChanged({
        removed: false,
        cause: "explicit",
        cookie: {
          name: `queue-cookie-${cookieIndex}`,
          domain: `queue${domainIndex}.test`,
          hostOnly: true,
          path: "/",
          storeId: "0"
        }
      });
    }
  }
  await settleCookieBatch();
  persisted = background.buildPersistedObservationState();
  assert.equal(persisted.tabs["10"].cookies.length, 1);
  assert.equal(persisted.tabs["10"].cookies[0].domain, "queue0.test");
  const queuedCookieCounts = Array.from({ length: 11 }, (_, index) =>
    persisted.tabs[String(10 + index)]?.cookies.length || 0
  );
  assert.equal(Math.max(...queuedCookieCounts), 50);
  assert.equal(queuedCookieCounts.reduce((sum, count) => sum + count, 0), 500);
  // Raw dynamic names and their identity fingerprints are intentionally not
  // exposed by persisted-state assertions; queue ordering is covered by the
  // indexed queue's unit test.
  assert.equal(persisted.tabs["11"].cookies.length <= 50, true);

  // Force a session write and verify that neither raw values nor transient path fingerprints persist.
  mock.channels.suspended.listeners[0]?.();
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  const serializedStorage = JSON.stringify({ local: mock.localData, session: mock.sessionData });
  assert.doesNotMatch(serializedStorage, /(?:ambiguous|cold|partitioned|raced)-secret-value/);
  assert.doesNotMatch(serializedStorage, /1234567890|9876543210|123e4567/);
  assert.doesNotMatch(serializedStorage, /pathFingerprint/);
});
