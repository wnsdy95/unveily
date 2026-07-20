import assert from "node:assert/strict";
import test from "node:test";
import {
  POLICY_CHECK_HEALTH_KEY,
  POLICY_SNAPSHOTS_KEY
} from "../src/policySnapshots.js";
import { COMPANION_OVERLAY_GENERATION_KEY } from "../src/companionOverlayRuntime.js";

const OBSERVATION_SETTINGS_KEY = "observationSettings";

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
  if (typeof keys === "string") return keys in data ? { [keys]: data[keys] } : {};
  if (Array.isArray(keys)) {
    return Object.fromEntries(keys.filter((key) => key in data).map((key) => [key, data[key]]));
  }
  return { ...data };
}

function createGate() {
  let release;
  let reject;
  const promise = new Promise((resolve, rejectPromise) => {
    release = resolve;
    reject = rejectPromise;
  });
  return { promise, release, reject };
}

function createChromeMock({
  localData = {},
  sessionData: initialSessionData = {},
  tabs: initialTabs = [],
  frames: initialFrames = [],
  blockedFrameTabId = null,
  localAccessLevelError = null,
  deferLocalAccessLevel = false,
  localGetError = null,
  initialAlarms = [],
  rejectedAlarmCreates = [],
  rejectedAlarmClears = []
} = {}) {
  const initializationGate = createGate();
  const frameLookupGate = createGate();
  const localAccessLevelGate = createGate();
  const tabs = new Map(initialTabs.map((tab) => [tab.id, { ...tab }]));
  const frames = new Map(
    initialFrames.map(([tabId, tabFrames]) => [
      tabId,
      tabFrames.map((frame) => ({ ...frame }))
    ])
  );
  const sessionData = structuredClone(initialSessionData);
  const localStorageOperations = [];
  const alarms = new Map(
    initialAlarms.map((alarm) => [alarm.name, structuredClone(alarm)])
  );
  const alarmCreateFailures = new Set(rejectedAlarmCreates);
  const alarmClearFailures = new Set(rejectedAlarmClears);
  const alarmCreateCalls = [];
  const alarmClearCalls = [];
  const tabMessages = [];
  let optionsOpenCalls = 0;
  let frameLookupHook = null;
  const channels = {
    beforeRequest: eventChannel(),
    cookieChanged: eventChannel(),
    committed: eventChannel(),
    history: eventChannel(),
    referenceFragment: eventChannel(),
    beforeNavigate: eventChannel(),
    navigationError: eventChannel(),
    message: eventChannel(),
    tabUpdated: eventChannel(),
    storageChanged: eventChannel(),
    suspended: eventChannel(),
    installed: eventChannel(),
    startup: eventChannel(),
    alarm: eventChannel(),
    notificationClicked: eventChannel()
  };
  const localStorage = {
    async setAccessLevel(details) {
      localStorageOperations.push({ type: "setAccessLevel", details: { ...details } });
      if (deferLocalAccessLevel) await localAccessLevelGate.promise;
      if (localAccessLevelError) throw localAccessLevelError;
    },
    async get(keys) {
      localStorageOperations.push({ type: "get", keys });
      await initializationGate.promise;
      if (localGetError) throw localGetError;
      return selectStorage(localData, keys);
    },
    async set(values) {
      localStorageOperations.push({ type: "set", values: structuredClone(values) });
      Object.assign(localData, values);
    }
  };
  const sessionStorage = {
    async get(keys) {
      return selectStorage(sessionData, keys);
    },
    async set(values) {
      Object.assign(sessionData, values);
    },
    async remove(keys) {
      for (const key of Array.isArray(keys) ? keys : [keys]) delete sessionData[key];
    }
  };

  const chrome = {
    runtime: {
      id: "initialization-runtime-test-extension",
      lastError: null,
      getURL: (path) => `chrome-extension://initialization-runtime-test-extension/${path}`,
      onInstalled: channels.installed,
      onStartup: channels.startup,
      onSuspend: channels.suspended,
      onMessage: channels.message,
      async openOptionsPage() {
        optionsOpenCalls += 1;
      }
    },
    webRequest: { onBeforeRequest: channels.beforeRequest },
    webNavigation: {
      onCommitted: channels.committed,
      onHistoryStateUpdated: channels.history,
      onReferenceFragmentUpdated: channels.referenceFragment,
      onBeforeNavigate: channels.beforeNavigate,
      onErrorOccurred: channels.navigationError,
      async getAllFrames({ tabId }) {
        if (tabId === blockedFrameTabId) await frameLookupGate.promise;
        await frameLookupHook?.({ tabId, frameId: null });
        return (frames.get(tabId) || []).map((frame) => ({ ...frame }));
      },
      async getFrame({ tabId, frameId }) {
        if (tabId === blockedFrameTabId) await frameLookupGate.promise;
        await frameLookupHook?.({ tabId, frameId });
        const frame = (frames.get(tabId) || []).find((candidate) => candidate.frameId === frameId);
        return frame ? { ...frame } : null;
      }
    },
    cookies: {
      onChanged: channels.cookieChanged,
      async getAll() {
        return [];
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
        const result = Array.from(tabs.values(), (tab) => ({ ...tab }));
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
      local: localStorage,
      session: sessionStorage,
      onChanged: channels.storageChanged
    },
    alarms: {
      create(name, info) {
        const alarm = { name, ...structuredClone(info) };
        alarmCreateCalls.push(alarm);
        if (alarmCreateFailures.has(name)) {
          return Promise.reject(new Error(`alarm create failed: ${name}`));
        }
        alarms.set(name, alarm);
        return Promise.resolve();
      },
      async get(name) {
        const alarm = alarms.get(name);
        return alarm ? structuredClone(alarm) : null;
      },
      async clear(name) {
        alarmClearCalls.push(name);
        if (alarmClearFailures.has(name)) {
          throw new Error(`alarm clear failed: ${name}`);
        }
        return alarms.delete(name);
      },
      onAlarm: channels.alarm
    },
    notifications: {
      onClicked: channels.notificationClicked,
      async create() {}
    },
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
    initializationGate,
    frameLookupGate,
    localAccessLevelGate,
    localStorageOperations,
    localData,
    sessionData,
    alarms,
    alarmCreateCalls,
    alarmClearCalls,
    tabMessages,
    alarmCreateFailures,
    alarmClearFailures,
    get optionsOpenCalls() {
      return optionsOpenCalls;
    },
    setFrameLookupHook(hook) {
      frameLookupHook = typeof hook === "function" ? hook : null;
    },
    tabs,
    frames
  };
}

async function flushBackgroundWork({ includeCookieBatch = false } = {}) {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
  if (includeCookieBatch) {
    await new Promise((resolve) => setTimeout(resolve, 125));
    await new Promise((resolve) => setImmediate(resolve));
  }
}

async function waitForBackgroundCondition(predicate, message) {
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (predicate()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.fail(message);
}

async function sendRuntimeMessage(listener, message) {
  return sendRuntimeMessageFromSender(listener, message, {
    id: "initialization-runtime-test-extension",
    url: "chrome-extension://initialization-runtime-test-extension/src/popup.html"
  });
}

async function sendRuntimeMessageFromSender(listener, message, sender) {
  return new Promise((resolve, reject) => {
    const keepAlive = listener(
      message,
      sender,
      resolve
    );
    if (keepAlive !== true) reject(new Error("background did not keep the response channel open"));
  });
}

function tabFixture(id, hostname) {
  const url = `https://${hostname}/app`;
  return {
    tab: { id, status: "complete", url },
    frames: [
      {
        frameId: 0,
        parentFrameId: -1,
        documentId: `document-${id}`,
        documentLifecycle: "active",
        url
      }
    ]
  };
}

function persistedObservationForTab(fixture, requests = []) {
  const savedAt = Date.now();
  const tabId = fixture.tab.id;
  const shardKey = `observationSessionTabV4:${tabId}`;
  const session = {
    generation: 3,
    documentId: fixture.frames[0].documentId,
    origin: new URL(fixture.tab.url).origin,
    navigationKey: `${new URL(fixture.tab.url).origin}/:segment`,
    startedAt: savedAt - 1_000,
    lastSeenAt: savedAt
  };
  return {
    observationSessionStateV1: {
      version: 4,
      layout: "per-tab-v1",
      savedAt,
      tabs: {
        [tabId]: { key: shardKey, session }
      }
    },
    [shardKey]: {
      session,
      requests,
      cookies: [],
      snapshots: [],
      frameDocuments: [[0, fixture.frames[0].documentId]],
      riskIndicator: null
    }
  };
}

let moduleSequence = 0;

async function loadBackground(mock) {
  globalThis.chrome = mock.chrome;
  moduleSequence += 1;
  return import(`../src/background.js?initialization-runtime=${Date.now()}-${moduleSequence}`);
}

test("worker alarm repair retries failures and onboarding opens only on first install", async () => {
  const fixture = tabFixture(93, "alarm-retry.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]],
    rejectedAlarmCreates: ["policy-snapshot-check", "observation-session-expiry"],
    rejectedAlarmClears: ["observation-session-expiry"]
  });
  await loadBackground(mock);
  await flushBackgroundWork();

  const workerStartCalls = mock.alarmCreateCalls.filter(
    (alarm) => alarm.name === "policy-snapshot-check"
  );
  assert.equal(workerStartCalls.length, 1);
  assert.equal(workerStartCalls[0].delayInMinutes, 1);
  assert.equal(workerStartCalls[0].periodInMinutes, 360);
  assert.equal(mock.alarms.has("policy-snapshot-check"), false);

  mock.alarmCreateFailures.delete("policy-snapshot-check");
  mock.channels.startup.listeners[0]();
  await flushBackgroundWork();
  assert.equal(mock.alarms.has("policy-snapshot-check"), true);

  mock.channels.installed.listeners[0]({ reason: "update" });
  await flushBackgroundWork();
  assert.equal(mock.optionsOpenCalls, 0);

  mock.channels.installed.listeners[0]({ reason: "install" });
  await flushBackgroundWork();
  assert.equal(mock.optionsOpenCalls, 1);

  mock.initializationGate.release();
  await flushBackgroundWork();
  assert.ok(mock.alarmClearCalls.includes("observation-session-expiry"));

  await establishObservedTopDocument(mock, fixture);
  assert.equal(mock.alarms.has("observation-session-expiry"), false);
  mock.alarmCreateFailures.delete("observation-session-expiry");
  mock.alarmClearFailures.delete("observation-session-expiry");
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: fixture.frames[0].documentId,
    documentLifecycle: "active",
    type: "xmlhttprequest",
    method: "GET",
    url: "https://alarm-retry-collector.example/collect"
  });
  await flushBackgroundWork();
  assert.equal(mock.alarms.has("observation-session-expiry"), true);
});

test("worker start preserves its alarm and automatic checks enforce a per-URL six-hour interval", async () => {
  const now = Date.now();
  const scheduledTime = now + 60_000;
  const freshUrl = "https://fresh-policy.example/privacy";
  const recentAttemptUrl = "https://recent-policy.example/privacy";
  const dueUrl = "https://due-policy.example/privacy";
  const baseline = (url, capturedAt) => ({
    key: url,
    origin: new URL(url).origin,
    title: "Privacy policy",
    url,
    capturedAt: new Date(capturedAt).toISOString(),
    textHash: "a".repeat(64),
    hashAlgorithm: "sha256",
    textLength: 20,
    normalizedText: "Old privacy policy.",
    policySections: [],
    riskSummary: { level: "low", score: 10, riskIds: [] }
  });
  const mock = createChromeMock({
    localData: {
      [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] },
      [POLICY_SNAPSHOTS_KEY]: {
        [freshUrl]: baseline(freshUrl, now - 60_000),
        [recentAttemptUrl]: baseline(recentAttemptUrl, now - 12 * 60 * 60 * 1000),
        [dueUrl]: baseline(dueUrl, now - 6 * 60 * 60 * 1000 - 60_000)
      },
      [POLICY_CHECK_HEALTH_KEY]: {
        [recentAttemptUrl]: {
          lastAttemptAt: new Date(now - 60_000).toISOString(),
          lastSuccessAt: "",
          consecutiveFailures: 1,
          errorCategory: "network"
        }
      }
    },
    initialAlarms: [
      {
        name: "policy-snapshot-check",
        scheduledTime,
        periodInMinutes: 360
      }
    ]
  });
  await loadBackground(mock);
  await flushBackgroundWork();
  assert.equal(
    mock.alarmCreateCalls.some((alarm) => alarm.name === "policy-snapshot-check"),
    false
  );

  mock.channels.startup.listeners[0]();
  mock.channels.installed.listeners[0]({ reason: "update" });
  await flushBackgroundWork();
  assert.equal(
    mock.alarmCreateCalls.some((alarm) => alarm.name === "policy-snapshot-check"),
    false
  );
  assert.equal(mock.alarms.get("policy-snapshot-check")?.scheduledTime, scheduledTime);

  mock.alarms.set("policy-snapshot-check", {
    name: "policy-snapshot-check",
    scheduledTime,
    periodInMinutes: 1
  });
  mock.channels.startup.listeners[0]();
  await flushBackgroundWork();
  const repaired = mock.alarmCreateCalls.filter(
    (alarm) => alarm.name === "policy-snapshot-check"
  );
  assert.equal(repaired.length, 1);
  assert.equal(repaired[0].periodInMinutes, 360);

  mock.initializationGate.release();
  await flushBackgroundWork();
  assert.equal(repaired[0].delayInMinutes, 1);

  const fetchedPolicyText =
    "Privacy Policy. We collect email addresses to provide the service. " +
    "We share data with service providers and retain it for 30 days. " +
    "You may request access, correction, and deletion of personal data.";
  const fetches = [];
  let releaseFirstFetch;
  const firstFetchGate = new Promise((resolve) => {
    releaseFirstFetch = resolve;
  });
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    fetches.push(String(url));
    if (fetches.length === 1) await firstFetchGate;
    return new Response(`<main>${fetchedPolicyText}</main>`, {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" }
    });
  };

  try {
    mock.channels.alarm.listeners[0]({ name: "policy-snapshot-check" });
    await waitForBackgroundCondition(
      () => fetches.length === 1,
      "the due automatic policy check should contact its URL"
    );
    assert.deepEqual(fetches, [dueUrl]);

    const manualPromise = sendRuntimeMessage(mock.channels.message.listeners[0], {
      type: "CHECK_SAVED_POLICIES_NOW"
    });
    await flushBackgroundWork();
    assert.deepEqual(fetches, [dueUrl]);
    releaseFirstFetch();

    const manual = await manualPromise;
    assert.equal(manual.ok, true);
    assert.equal(manual.checked, 3);
    assert.deepEqual(fetches.slice(1).sort(), [dueUrl, freshUrl, recentAttemptUrl].sort());

    mock.channels.alarm.listeners[0]({ name: "policy-snapshot-check" });
    await flushBackgroundWork();
    assert.equal(fetches.length, 4);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("cold-start hydration and its TTL alarm reject an exactly expired session", async () => {
  const originalDateNow = Date.now;
  let currentTime = 2_000_000_000_000;
  Date.now = () => currentTime;
  try {
    const fixture = tabFixture(90, "cold-alarm-expiry.example");
    const sessionData = persistedObservationForTab(fixture, [
      {
        url: "https://cold-alarm-collector.example/collect",
        method: "GET",
        type: "xmlhttprequest",
        timeStamp: currentTime
      }
    ]);
    currentTime += 60 * 60 * 1000;
    const mock = createChromeMock({
      localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
      sessionData,
      tabs: [fixture.tab],
      frames: [[fixture.tab.id, fixture.frames]],
      initialAlarms: [
        { name: "observation-session-expiry", scheduledTime: currentTime, when: currentTime }
      ]
    });
    const backgroundModule = await loadBackground(mock);

    mock.alarms.delete("observation-session-expiry");
    mock.channels.alarm.listeners[0]({ name: "observation-session-expiry" });
    await flushBackgroundWork();
    assert.ok(mock.sessionData[`observationSessionTabV4:${fixture.tab.id}`]);

    mock.initializationGate.release();
    await flushBackgroundWork();
    await flushBackgroundWork();

    assert.deepEqual(backgroundModule.buildPersistedObservationState().tabs, {});
    assert.equal(mock.sessionData.observationSessionStateV1, undefined);
    assert.equal(mock.sessionData[`observationSessionTabV4:${fixture.tab.id}`], undefined);
    assert.equal(mock.alarms.has("observation-session-expiry"), false);
  } finally {
    Date.now = originalDateNow;
  }
});

test("restricts local storage to trusted contexts before reading initialization state", async () => {
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    localGetError: new Error("local read failure")
  });

  const backgroundModule = await loadBackground(mock);
  await flushBackgroundWork();

  assert.deepEqual(mock.localStorageOperations[0], {
    type: "setAccessLevel",
    details: { accessLevel: "TRUSTED_CONTEXTS" }
  });
  assert.ok(mock.localStorageOperations.some((operation) => operation.type === "get"));
  assert.equal(
    mock.localStorageOperations.findIndex((operation) => operation.type === "setAccessLevel") <
      mock.localStorageOperations.findIndex((operation) => operation.type === "get"),
    true
  );

  mock.initializationGate.release();
  await flushBackgroundWork();
  await flushBackgroundWork();

  assert.deepEqual(backgroundModule.buildPersistedObservationState().tabs, {});
  const activity = await sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: 999
  });
  assert.equal(activity.observationEnabled, false);
  assert.equal(activity.session, null);
});

test("content settings expose only the current tab decision, never other excluded origins", async () => {
  const fixture = tabFixture(94, "current-settings.example");
  const privateOriginSentinel = "https://private-origin-sentinel.example";
  const mock = createChromeMock({
    localData: {
      [OBSERVATION_SETTINGS_KEY]: {
        enabled: true,
        excludedOrigins: [privateOriginSentinel]
      }
    },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();

  const sender = {
    id: "initialization-runtime-test-extension",
    frameId: 0,
    documentId: fixture.frames[0].documentId,
    documentLifecycle: "active",
    url: fixture.tab.url,
    tab: { ...fixture.tab }
  };
  const allowed = await sendRuntimeMessageFromSender(
    mock.channels.message.listeners[0],
    { type: "GET_OBSERVATION_SETTINGS" },
    sender
  );
  assert.deepEqual(allowed, {
    ok: true,
    settings: { enabled: true, allowed: true }
  });
  assert.doesNotMatch(JSON.stringify(allowed), /private-origin-sentinel|excludedOrigins/);

  await applyObservationSettingsChange(mock, {
    enabled: true,
    excludedOrigins: [privateOriginSentinel, new URL(fixture.tab.url).origin]
  });
  const update = mock.tabMessages
    .filter(({ message }) => message.type === "OBSERVATION_SETTINGS_UPDATE")
    .at(-1);
  assert.deepEqual(update, {
    tabId: fixture.tab.id,
    message: {
      type: "OBSERVATION_SETTINGS_UPDATE",
      settings: { enabled: true, allowed: false }
    }
  });
  assert.doesNotMatch(JSON.stringify(mock.tabMessages), /private-origin-sentinel|excludedOrigins/);

  const denied = await sendRuntimeMessageFromSender(
    mock.channels.message.listeners[0],
    { type: "GET_OBSERVATION_SETTINGS" },
    sender
  );
  assert.deepEqual(denied, {
    ok: true,
    settings: { enabled: true, allowed: false }
  });
});

test("delayed storage isolation failure discards startup queues and policy work", async () => {
  const fixture = tabFixture(19, "storage-access-failure.example");
  const policyUrl = "https://storage-access-failure.example/privacy";
  const sessionData = persistedObservationForTab(fixture, [
    {
      url: "https://should-not-hydrate.example/collect",
      method: "GET",
      type: "xmlhttprequest",
      timeStamp: Date.now() - 100
    }
  ]);
  const originalFetch = globalThis.fetch;
  let fetchCalls = 0;
  globalThis.fetch = async () => {
    fetchCalls += 1;
    throw new Error("policy fetch must not run while the storage gate is closed");
  };

  try {
    const mock = createChromeMock({
      deferLocalAccessLevel: true,
      localData: {
        [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] },
        companionOverlayEnabled: true,
        [POLICY_SNAPSHOTS_KEY]: {
          [policyUrl]: {
            key: policyUrl,
            origin: new URL(policyUrl).origin,
            url: policyUrl,
            title: "Privacy",
            capturedAt: new Date(Date.now() - 7 * 60 * 60 * 1000).toISOString()
          }
        }
      },
      sessionData,
      tabs: [fixture.tab],
      frames: [[fixture.tab.id, fixture.frames]],
      initialAlarms: [
        {
          name: "policy-snapshot-check",
          scheduledTime: Date.now() + 1_000,
          periodInMinutes: 360
        }
      ]
    });
    const backgroundModule = await loadBackground(mock);
    await waitForBackgroundCondition(
      () => mock.localStorageOperations.length > 0,
      "trusted storage access should begin before startup events are captured"
    );
    assert.deepEqual(mock.localStorageOperations, [
      {
        type: "setAccessLevel",
        details: { accessLevel: "TRUSTED_CONTEXTS" }
      }
    ]);

    let requestCaptured = false;
    const startupRequest = {
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: fixture.frames[0].documentId,
      documentLifecycle: "active",
      requestId: "delayed-gate-request",
      type: "main_frame",
      url: `${fixture.tab.url}?delayed_request_marker=must_be_discarded`
    };
    Object.defineProperty(startupRequest, "method", {
      get() {
        requestCaptured = true;
        return "GET";
      }
    });
    mock.channels.beforeRequest.listeners[0](startupRequest);

    let cookieCaptured = false;
    const startupCookie = {
      value: "delayed-cookie-secret",
      domain: "storage-access-failure.example",
      path: "/private/delayed-cookie-path",
      secure: true,
      httpOnly: false,
      sameSite: "lax",
      session: true,
      hostOnly: true
    };
    Object.defineProperty(startupCookie, "name", {
      get() {
        cookieCaptured = true;
        return "delayed_gate_cookie_marker";
      }
    });
    mock.channels.cookieChanged.listeners[0]({
      removed: false,
      cause: "explicit",
      cookie: startupCookie
    });
    mock.channels.alarm.listeners[0]({ name: "policy-snapshot-check" });

    assert.equal(requestCaptured, true);
    assert.equal(cookieCaptured, true);
    assert.equal(mock.alarms.has("policy-snapshot-check"), true);
    assert.equal(fetchCalls, 0);

    mock.localAccessLevelGate.reject(new Error("delayed access-level failure"));
    await flushBackgroundWork({ includeCookieBatch: true });

    assert.deepEqual(mock.localStorageOperations, [
      {
        type: "setAccessLevel",
        details: { accessLevel: "TRUSTED_CONTEXTS" }
      }
    ]);
    assert.equal(mock.alarms.has("policy-snapshot-check"), false);
    assert.ok(mock.alarmClearCalls.includes("policy-snapshot-check"));
    assert.equal(fetchCalls, 0);
    assert.deepEqual(mock.sessionData, { [COMPANION_OVERLAY_GENERATION_KEY]: 1 });
    const companionDisable = mock.tabMessages.find(
      (entry) => entry.message.type === "COMPANION_OVERLAY_VISIBILITY"
    );
    assert.ok(companionDisable);
    assert.equal(companionDisable.message.enabled, false);
    assert.equal(companionDisable.message.generation, 1);
    assert.equal(companionDisable.options.documentId, fixture.frames[0].documentId);

    const activity = await sendRuntimeMessage(mock.channels.message.listeners[0], {
      type: "GET_NETWORK_ACTIVITY",
      tabId: fixture.tab.id
    });
    assert.equal(activity.observationEnabled, false);
    assert.equal(activity.session, null);
    assert.deepEqual(activity.requests, []);
    assert.deepEqual(activity.cookies, []);
    assert.deepEqual(backgroundModule.buildPersistedObservationState().tabs, {});

    mock.channels.storageChanged.listeners[0](
      {
        [OBSERVATION_SETTINGS_KEY]: {
          newValue: { enabled: true, excludedOrigins: [] }
        }
      },
      "local"
    );
    mock.channels.storageChanged.listeners[0](
      { uiLocaleOverride: { newValue: "ko" } },
      "local"
    );
    await flushBackgroundWork();
    const afterChange = await sendRuntimeMessage(mock.channels.message.listeners[0], {
      type: "GET_NETWORK_ACTIVITY",
      tabId: fixture.tab.id
    });
    assert.equal(afterChange.observationEnabled, false);

    const policyCheck = await sendRuntimeMessage(mock.channels.message.listeners[0], {
      type: "CHECK_SAVED_POLICIES_NOW"
    });
    assert.equal(policyCheck.ok, false);
    assert.equal(policyCheck.code, "STORAGE_ISOLATION_UNAVAILABLE");

    const companionPreference = await sendRuntimeMessage(
      mock.channels.message.listeners[0],
      { type: "GET_COMPANION_OVERLAY_PREFERENCE" }
    );
    assert.equal(companionPreference.ok, false);
    assert.equal(companionPreference.enabled, false);
    assert.equal(companionPreference.code, "STORAGE_ISOLATION_UNAVAILABLE");
    const companionEnable = await sendRuntimeMessage(mock.channels.message.listeners[0], {
      type: "SET_COMPANION_OVERLAY_PREFERENCE",
      enabled: true
    });
    assert.equal(companionEnable.ok, false);
    assert.equal(companionEnable.enabled, false);
    assert.equal(companionEnable.code, "STORAGE_ISOLATION_UNAVAILABLE");

    const policySave = await sendRuntimeMessage(mock.channels.message.listeners[0], {
      type: "SAVE_MONITORED_POLICY_SNAPSHOT",
      tabId: fixture.tab.id,
      documentId: fixture.frames[0].documentId,
      policyUrl,
      title: "Privacy"
    });
    assert.equal(policySave.ok, false);
    assert.equal(policySave.code, "STORAGE_ISOLATION_UNAVAILABLE");

    mock.channels.alarm.listeners[0]({ name: "policy-snapshot-check" });
    mock.channels.notificationClicked.listeners[0]("policy-change:any-token");
    mock.channels.suspended.listeners[0]?.();
    await flushBackgroundWork();
    assert.equal(fetchCalls, 0);
    assert.deepEqual(mock.localStorageOperations, [
      {
        type: "setAccessLevel",
        details: { accessLevel: "TRUSTED_CONTEXTS" }
      }
    ]);
    assert.deepEqual(mock.sessionData, { [COMPANION_OVERLAY_GENERATION_KEY]: 1 });
    assert.doesNotMatch(
      JSON.stringify({ activity, persisted: backgroundModule.buildPersistedObservationState(), session: mock.sessionData }),
      /delayed_request_marker|delayed_gate_cookie_marker|delayed-cookie-secret|delayed-cookie-path/
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("hydration accepts startup subresources queued before the recovered session boundary", async () => {
  const fixture = tabFixture(20, "startup-recovered.example");
  const baselineRequest = {
    url: "https://baseline.example/collect",
    method: "GET",
    type: "xmlhttprequest",
    timeStamp: Date.now() - 500
  };
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    sessionData: persistedObservationForTab(fixture, [baselineRequest]),
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  await loadBackground(mock);
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: fixture.frames[0].documentId,
    documentLifecycle: "active",
    type: "xmlhttprequest",
    method: "POST",
    url: "https://startup-collector.example/collect"
  });

  mock.initializationGate.release();
  await flushBackgroundWork();

  const activity = await sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  assert.deepEqual(
    activity.requests.map((request) => request.host),
    ["baseline.example", "startup-collector.example"]
  );
});

test("hydration discards uncertain cookie identities and lazily reconciles stable inventory", async () => {
  const fixture = tabFixture(23, "cookie-recovery.example");
  const sessionData = persistedObservationForTab(fixture);
  const shardKey = `observationSessionTabV4:${fixture.tab.id}`;
  const legacyDeletedAt = Date.now() - 100;
  sessionData[shardKey].cookies = [
    {
      name: "customer___number__",
      domain: "cookie-recovery.example",
      hostOnly: true,
      path: "/users/:id",
      storeId: "0",
      identityStable: false,
      removed: false,
      timingConfidence: "unknown"
    },
    {
      name: "_gid",
      domain: "cookie-recovery.example",
      hostOnly: true,
      path: "/",
      storeId: "0",
      identityStable: true,
      removed: false,
      timingConfidence: "unknown"
    },
    {
      name: "_ga",
      domain: "cookie-recovery.example",
      hostOnly: true,
      path: "/",
      storeId: "0",
      identityStable: true,
      removed: true,
      timingConfidence: "observed",
      firstObservedAt: legacyDeletedAt,
      lastObservedAt: legacyDeletedAt,
      timeStamp: legacyDeletedAt,
      deletedAt: legacyDeletedAt,
      partitionKey: { topLevelSite: "https://cookie-recovery.example" }
    }
  ];
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    sessionData,
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();

  const hydrated = backgroundModule.buildPersistedObservationState().tabs[String(fixture.tab.id)];
  assert.deepEqual(hydrated.cookies.map((cookie) => cookie.name), ["_gid"]);

  mock.channels.suspended.listeners[0]?.();
  await flushBackgroundWork();
  assert.deepEqual(
    mock.sessionData[shardKey].cookies.map((cookie) => cookie.name),
    ["_gid"]
  );
  assert.doesNotMatch(JSON.stringify(mock.sessionData[shardKey]), /firstObservedAt|deletedAt/);

  const activity = await sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  assert.deepEqual(activity.cookies, []);

  const rawDynamicCookie = {
    name: "customer_1234567890",
    domain: "cookie-recovery.example",
    hostOnly: true,
    path: "/users/987654",
    storeId: "0"
  };
  mock.channels.cookieChanged.listeners[0]({
    removed: false,
    cause: "explicit",
    cookie: rawDynamicCookie
  });
  mock.channels.cookieChanged.listeners[0]({
    removed: true,
    cause: "explicit",
    cookie: rawDynamicCookie
  });
  await flushBackgroundWork({ includeCookieBatch: true });

  const afterRemoval = backgroundModule.buildPersistedObservationState().tabs[String(fixture.tab.id)];
  assert.deepEqual(afterRemoval.cookies, []);
  assert.doesNotMatch(JSON.stringify(afterRemoval), /1234567890|987654|pathFingerprint/);
});

test("a startup main-frame request supersedes hydrated history without a webNavigation marker", async () => {
  const fixture = tabFixture(21, "startup-main-old.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    sessionData: persistedObservationForTab(fixture, [
      {
        url: "https://old-history.example/collect",
        method: "GET",
        type: "xmlhttprequest",
        timeStamp: Date.now() - 500
      }
    ]),
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "startup-main-new-document",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: "https://startup-main-new.example/app"
  });

  mock.initializationGate.release();
  await flushBackgroundWork();

  const state = backgroundModule.buildPersistedObservationState().tabs[String(fixture.tab.id)];
  assert.equal(state.session.documentId, "startup-main-new-document");
  assert.deepEqual(state.requests.map((request) => request.host), ["startup-main-new.example"]);
});

test("initialization queue preserves another tab's main-frame boundary during a noisy-tab flood", async () => {
  const noisy = tabFixture(1, "noise.example");
  const target = tabFixture(2, "target.example");
  target.tab.url += "?startup_boundary=retain-this-value";
  target.frames[0].url = target.tab.url;
  const localData = {
    [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] }
  };
  const mock = createChromeMock({
    localData,
    tabs: [noisy.tab, target.tab],
    frames: [
      [noisy.tab.id, noisy.frames],
      [target.tab.id, target.frames]
    ]
  });
  const backgroundModule = await loadBackground(mock);
  const beforeRequest = mock.channels.beforeRequest.listeners[0];
  assert.equal(typeof beforeRequest, "function");

  beforeRequest({
    tabId: target.tab.id,
    frameId: 0,
    documentId: target.frames[0].documentId,
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: target.tab.url
  });
  for (let index = 0; index < 600; index += 1) {
    beforeRequest({
      tabId: noisy.tab.id,
      frameId: 0,
      documentId: noisy.frames[0].documentId,
      documentLifecycle: "active",
      type: "xmlhttprequest",
      method: "POST",
      url: `https://collector.example/batch/${index}?token=never-retain-request-value`,
      requestBody: {
        formData: { password: ["never-retain-body-value"] }
      }
    });
  }

  mock.initializationGate.release();
  await flushBackgroundWork();

  const onMessage = mock.channels.message.listeners[0];
  const targetActivity = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: target.tab.id
  });
  assert.equal(targetActivity.ok, true);
  assert.equal(targetActivity.observationEnabled, true);
  assert.equal(targetActivity.session.documentId, target.frames[0].documentId);
  assert.equal(targetActivity.requests.length, 1, JSON.stringify(targetActivity));
  assert.equal(targetActivity.requests[0].type, "main_frame");
  assert.deepEqual(targetActivity.requests[0].queryKeys, []);

  const noisyActivity = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: noisy.tab.id
  });
  assert.ok(noisyActivity.requests.length <= 50, JSON.stringify(noisyActivity));

  const serialized = JSON.stringify({
    targetActivity,
    noisyActivity,
    persisted: backgroundModule.buildPersistedObservationState(),
    sessionStorage: mock.sessionData
  });
  assert.doesNotMatch(serialized, /retain-this-value/);
  assert.doesNotMatch(serialized, /never-retain-request-value/);
  assert.doesNotMatch(serialized, /never-retain-body-value/);
});

test("subresource limiting resets across top-level sites without refilling one redirect chain", async () => {
  const fixture = tabFixture(9, "rate-limit.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  const beforeRequest = mock.channels.beforeRequest.listeners[0];

  beforeRequest({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: fixture.frames[0].documentId,
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    requestId: "rate-navigation-a",
    url: fixture.tab.url
  });
  await flushBackgroundWork();

  const originalDateNow = Date.now;
  const fixedNow = originalDateNow();
  Date.now = () => fixedNow;
  try {
    for (let index = 0; index < 300; index += 1) {
      beforeRequest({
        tabId: fixture.tab.id,
        frameId: 0,
        documentId: fixture.frames[0].documentId,
        documentLifecycle: "active",
        type: "xmlhttprequest",
        method: "GET",
        url: `https://collector.example/events/${index}`
      });
    }

    const overLimit = {
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: fixture.frames[0].documentId,
      documentLifecycle: "active",
      type: "xmlhttprequest",
      url: "https://collector.example/over-limit"
    };
    Object.defineProperty(overLimit, "method", {
      get() {
        throw new Error("rate-limited request reached request sanitization");
      }
    });
    assert.doesNotThrow(() => beforeRequest(overLimit));

    const nextUrl = "https://fresh-rate-limit.example/next";
    beforeRequest({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: "rate-limit-next-document",
      documentLifecycle: "active",
      type: "main_frame",
      method: "GET",
      requestId: "rate-navigation-b",
      url: nextUrl
    });
    await flushBackgroundWork();

    let freshRequestWasSanitized = false;
    const freshRequest = {
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: "rate-limit-next-document",
      documentLifecycle: "active",
      type: "xmlhttprequest",
      method: "POST",
      url: "https://fresh-collector.example/first"
    };
    Object.defineProperty(freshRequest, "method", {
      get() {
        freshRequestWasSanitized = true;
        return "POST";
      }
    });
    beforeRequest(freshRequest);
    assert.equal(
      freshRequestWasSanitized,
      true,
      "a different top-level navigation must receive a fresh subresource budget"
    );
    for (let index = 1; index < 300; index += 1) {
      beforeRequest({
        tabId: fixture.tab.id,
        frameId: 0,
        documentId: "rate-limit-next-document",
        documentLifecycle: "active",
        type: "xmlhttprequest",
        method: "GET",
        url: `https://fresh-collector.example/events/${index}`
      });
    }

    beforeRequest({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: "rate-limit-final-document",
      documentLifecycle: "active",
      type: "main_frame",
      method: "GET",
      requestId: "rate-navigation-b",
      url: "https://fresh-rate-limit.example/final"
    });
    const redirectOverLimit = {
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: "rate-limit-final-document",
      documentLifecycle: "active",
      type: "xmlhttprequest",
      url: "https://fresh-collector.example/redirect-over-limit"
    };
    Object.defineProperty(redirectOverLimit, "method", {
      get() {
        throw new Error("a same-request redirect incorrectly refilled the subresource budget");
      }
    });
    assert.doesNotThrow(() => beforeRequest(redirectOverLimit));
  } finally {
    Date.now = originalDateNow;
  }
  await flushBackgroundWork();

  const state = backgroundModule.buildPersistedObservationState().tabs[String(fixture.tab.id)];
  assert.equal(state.session.documentId, "rate-limit-final-document");
  assert.equal(state.requests.length, 1);
  assert.equal(state.requests[0].type, "main_frame");
});

test("persisted pause discards startup request and cookie queues before returning or persisting data", async () => {
  const paused = tabFixture(11, "paused.example");
  const localData = {
    [OBSERVATION_SETTINGS_KEY]: { enabled: false, excludedOrigins: [] }
  };
  const mock = createChromeMock({
    localData,
    tabs: [paused.tab],
    frames: [[paused.tab.id, paused.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  const beforeRequest = mock.channels.beforeRequest.listeners[0];
  const cookieChanged = mock.channels.cookieChanged.listeners[0];
  assert.equal(typeof beforeRequest, "function");
  assert.equal(typeof cookieChanged, "function");

  beforeRequest({
    tabId: paused.tab.id,
    frameId: 0,
    documentId: paused.frames[0].documentId,
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: `${paused.tab.url}?paused_request_marker=never-persist-query-value`
  });
  cookieChanged({
    removed: false,
    cause: "explicit",
    cookie: {
      name: "never_persist_cookie_metadata",
      value: "never-persist-cookie-value",
      domain: "paused.example",
      path: "/private/account/1234",
      secure: true,
      httpOnly: false,
      sameSite: "lax",
      session: true,
      hostOnly: true
    }
  });

  mock.initializationGate.release();
  await flushBackgroundWork({ includeCookieBatch: true });

  const onMessage = mock.channels.message.listeners[0];
  const activity = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: paused.tab.id
  });
  assert.equal(activity.ok, true);
  assert.equal(activity.observationEnabled, false);
  assert.equal(activity.session, null);
  assert.deepEqual(activity.requests, []);
  assert.deepEqual(activity.cookies, []);

  const persisted = backgroundModule.buildPersistedObservationState();
  assert.deepEqual(persisted.tabs, {});
  const serializedRuntimeState = JSON.stringify({ activity, persisted, session: mock.sessionData });
  assert.doesNotMatch(serializedRuntimeState, /paused_request_marker/);
  assert.doesNotMatch(serializedRuntimeState, /never_persist_cookie_metadata/);
  assert.doesNotMatch(serializedRuntimeState, /never-persist-query-value/);
  assert.doesNotMatch(serializedRuntimeState, /never-persist-cookie-value/);
  assert.doesNotMatch(serializedRuntimeState, /\/private\/account\/1234/);
});

test("cold hydration rejects prior-route history when a same-document SPA URL changes", async () => {
  const cold = tabFixture(21, "cold-spa.example");
  cold.tab.url += "?account=old";
  cold.frames[0].url = cold.tab.url;
  const savedAt = Date.now();
  const storedSession = {
    generation: 9,
    documentId: cold.frames[0].documentId,
    origin: "https://cold-spa.example",
    navigationKey: "https://cold-spa.example/:segment",
    startedAt: savedAt - 1_000,
    lastSeenAt: savedAt
  };
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    sessionData: {
      observationSessionStateV1: {
        version: 4,
        layout: "per-tab-v1",
        savedAt,
        tabs: {
          21: { key: "observationSessionTabV4:21", session: storedSession }
        }
      },
      "observationSessionTabV4:21": {
        session: storedSession,
        requests: [
          {
            url: "https://prior-route.example/collect",
            method: "POST",
            type: "xmlhttprequest",
            timeStamp: savedAt - 100
          }
        ],
        cookies: [],
        snapshots: [],
        frameDocuments: [[0, cold.frames[0].documentId]],
        riskIndicator: null
      }
    },
    tabs: [cold.tab],
    frames: [[cold.tab.id, cold.frames]]
  });
  await loadBackground(mock);

  const nextUrl = "https://cold-spa.example/app?account=new#billing";
  mock.tabs.get(cold.tab.id).url = nextUrl;
  mock.frames.get(cold.tab.id)[0].url = nextUrl;
  mock.channels.tabUpdated.listeners[0](
    cold.tab.id,
    { url: nextUrl },
    { ...mock.tabs.get(cold.tab.id) }
  );

  mock.initializationGate.release();
  await flushBackgroundWork();
  const activity = await sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: cold.tab.id
  });
  assert.equal(activity.ok, true);
  assert.equal(activity.session.documentId, cold.frames[0].documentId);
  assert.notEqual(activity.session.generation, 9);
  assert.deepEqual(activity.requests, []);
  assert.doesNotMatch(JSON.stringify(activity), /prior-route\.example/);
});

test("runtime stays gated and drains requests that arrive during startup flushing", async () => {
  const blocked = tabFixture(31, "blocked-recovery.example");
  const live = tabFixture(32, "live-during-flush.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    tabs: [blocked.tab, live.tab],
    frames: [
      [blocked.tab.id, blocked.frames],
      [live.tab.id, live.frames]
    ],
    blockedFrameTabId: blocked.tab.id
  });
  await loadBackground(mock);
  const beforeRequest = mock.channels.beforeRequest.listeners[0];
  beforeRequest({
    tabId: blocked.tab.id,
    frameId: 0,
    documentId: blocked.frames[0].documentId,
    documentLifecycle: "active",
    type: "xmlhttprequest",
    method: "GET",
    url: "https://blocked-recovery.example/queued"
  });
  mock.initializationGate.release();
  await new Promise((resolve) => setImmediate(resolve));

  beforeRequest({
    tabId: live.tab.id,
    frameId: 0,
    documentId: live.frames[0].documentId,
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: live.tab.url
  });
  const activityPromise = sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: live.tab.id
  });
  const earlyResult = await Promise.race([
    activityPromise.then(() => "resolved"),
    new Promise((resolve) => setTimeout(() => resolve("still-gated"), 20))
  ]);
  assert.equal(earlyResult, "still-gated");

  mock.frameLookupGate.release();
  const activity = await activityPromise;
  assert.equal(activity.ok, true);
  assert.equal(activity.session.documentId, live.frames[0].documentId);
  assert.equal(activity.requests.length, 1, JSON.stringify(activity));
  assert.equal(activity.requests[0].type, "main_frame");
});

async function establishObservedTopDocument(mock, fixture) {
  const beforeRequest = mock.channels.beforeRequest.listeners[0];
  beforeRequest({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: fixture.frames[0].documentId,
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: fixture.tab.url
  });
  await flushBackgroundWork();
  mock.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: fixture.frames[0].documentId,
    documentLifecycle: "active",
    url: fixture.tab.url
  });
  await flushBackgroundWork();
  beforeRequest({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: fixture.frames[0].documentId,
    documentLifecycle: "active",
    type: "xmlhttprequest",
    method: "POST",
    url: "https://baseline-collector.example/retain?token=never-retain-value",
    requestBody: { formData: { token: ["never-retain-value"] } }
  });
  await flushBackgroundWork();
}

async function persistBackgroundNow(mock) {
  const onSuspend = mock.channels.suspended.listeners[0];
  assert.equal(typeof onSuspend, "function");
  onSuspend();
  await flushBackgroundWork();
}

async function applyObservationSettingsChange(mock, settings) {
  mock.localData[OBSERVATION_SETTINGS_KEY] = structuredClone(settings);
  mock.channels.storageChanged.listeners[0](
    { [OBSERVATION_SETTINGS_KEY]: { newValue: structuredClone(settings) } },
    "local"
  );
  await flushBackgroundWork();
}

function storedObservationForTab(mock, tabId) {
  const index = mock.sessionData.observationSessionStateV1;
  return {
    indexEntry: index?.tabs?.[String(tabId)],
    shard: mock.sessionData[`observationSessionTabV4:${tabId}`]
  };
}

test("delayed TTL delivery and slow refresh cannot revive expired navigation sessions", async () => {
  const originalDateNow = Date.now;
  let currentTime = 2_100_000_000_000;
  Date.now = () => currentTime;
  try {
    const fixture = tabFixture(91, "ttl-backup-a.example");
    const mock = createChromeMock({
      localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
      tabs: [fixture.tab],
      frames: [[fixture.tab.id, fixture.frames]]
    });
    const backgroundModule = await loadBackground(mock);
    mock.initializationGate.release();
    await flushBackgroundWork();
    await establishObservedTopDocument(mock, fixture);
    await persistBackgroundNow(mock);

    const beforeDelayedExpiry = await sendRuntimeMessage(
      mock.channels.message.listeners[0],
      { type: "GET_NETWORK_ACTIVITY", tabId: fixture.tab.id }
    );
    currentTime += 60 * 60 * 1000;
    const recoveryLookupGate = createGate();
    mock.setFrameLookupHook(() => recoveryLookupGate.promise);
    mock.channels.beforeRequest.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: fixture.frames[0].documentId,
      documentLifecycle: "active",
      type: "xmlhttprequest",
      method: "GET",
      url: "https://post-expiry-collector.example/collect"
    });
    await flushBackgroundWork();
    currentTime += 30_000;
    mock.setFrameLookupHook(null);
    recoveryLookupGate.release();
    await flushBackgroundWork();
    const afterDelayedExpiry = await sendRuntimeMessage(
      mock.channels.message.listeners[0],
      { type: "GET_NETWORK_ACTIVITY", tabId: fixture.tab.id }
    );
    assert.equal(
      afterDelayedExpiry.session.generation,
      beforeDelayedExpiry.session.generation + 1
    );
    assert.deepEqual(
      afterDelayedExpiry.requests.map((request) => request.host),
      ["post-expiry-collector.example"]
    );

    const refreshStartedAt = currentTime;
    const originalGetAll = mock.chrome.cookies.getAll;
    mock.chrome.cookies.getAll = async () => {
      currentTime = refreshStartedAt + 60 * 60 * 1000;
      return [];
    };
    const expiredDuringRefresh = await sendRuntimeMessage(
      mock.channels.message.listeners[0],
      { type: "GET_NETWORK_ACTIVITY", tabId: fixture.tab.id }
    );
    mock.chrome.cookies.getAll = originalGetAll;
    assert.equal(expiredDuringRefresh.session, null);
    assert.deepEqual(backgroundModule.buildPersistedObservationState().tabs, {});

    mock.channels.beforeRequest.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: fixture.frames[0].documentId,
      documentLifecycle: "active",
      type: "xmlhttprequest",
      method: "GET",
      url: "https://after-refresh-expiry.example/collect"
    });
    await flushBackgroundWork();
    const afterRefreshRecovery = await sendRuntimeMessage(
      mock.channels.message.listeners[0],
      { type: "GET_NETWORK_ACTIVITY", tabId: fixture.tab.id }
    );
    assert.equal(
      afterRefreshRecovery.session.generation,
      afterDelayedExpiry.session.generation + 1
    );
    assert.deepEqual(
      afterRefreshRecovery.requests.map((request) => request.host),
      ["after-refresh-expiry.example"]
    );
    await persistBackgroundNow(mock);

    const committedLastSeenAt = currentTime;
    const committedDeadline = committedLastSeenAt + 60 * 60 * 1000;
    assert.equal(mock.alarms.get("observation-session-expiry")?.when, committedDeadline);

    currentTime += 1_000;
    const provisionalLastSeenAt = currentTime;
    const provisionalUrl = "https://ttl-provisional-b.example/destination";
    const provisionalDocumentId = "ttl-provisional-b-document";
    mock.channels.beforeNavigate.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      timeStamp: currentTime,
      url: provisionalUrl
    });
    mock.channels.beforeRequest.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: provisionalDocumentId,
      documentLifecycle: "active",
      type: "main_frame",
      method: "GET",
      url: provisionalUrl
    });
    await flushBackgroundWork();

    assert.equal(mock.alarms.get("observation-session-expiry")?.when, committedDeadline);

    currentTime = committedDeadline;
    mock.alarms.delete("observation-session-expiry");
    mock.channels.alarm.listeners[0]({ name: "observation-session-expiry" });
    await flushBackgroundWork();
    await flushBackgroundWork();

    const liveAfterBackupExpiry =
      backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id];
    assert.equal(liveAfterBackupExpiry.session.documentId, provisionalDocumentId);
    assert.equal(storedObservationForTab(mock, fixture.tab.id).indexEntry, undefined);
    assert.equal(storedObservationForTab(mock, fixture.tab.id).shard, undefined);
    assert.equal(
      mock.alarms.get("observation-session-expiry")?.when,
      provisionalLastSeenAt + 60 * 60 * 1000
    );

    currentTime = provisionalLastSeenAt + 60 * 60 * 1000;
    mock.alarms.delete("observation-session-expiry");
    mock.channels.alarm.listeners[0]({ name: "observation-session-expiry" });
    await flushBackgroundWork();
    await flushBackgroundWork();

    assert.deepEqual(backgroundModule.buildPersistedObservationState().tabs, {});
    assert.equal(mock.alarms.has("observation-session-expiry"), false);

    mock.tabs.get(fixture.tab.id).url = provisionalUrl;
    mock.frames.get(fixture.tab.id)[0].url = provisionalUrl;
    mock.frames.get(fixture.tab.id)[0].documentId = provisionalDocumentId;
    mock.channels.committed.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: provisionalDocumentId,
      documentLifecycle: "active",
      url: provisionalUrl
    });
    await flushBackgroundWork();
    assert.equal(mock.alarms.has("observation-session-expiry"), true);

    await applyObservationSettingsChange(mock, { enabled: false, excludedOrigins: [] });
    assert.equal(mock.alarms.has("observation-session-expiry"), false);
    assert.ok(mock.alarmClearCalls.includes("observation-session-expiry"));
  } finally {
    Date.now = originalDateNow;
  }
});

test("an allowed provisional top navigation preserves committed recovery until commit", async () => {
  const fixture = tabFixture(46, "persisted-committed.example");
  const settings = { enabled: true, excludedOrigins: [] };
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: settings },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);
  await persistBackgroundNow(mock);

  const nextUrl = "https://allowed-provisional.example/next";
  mock.channels.beforeNavigate.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    timeStamp: Date.now(),
    url: nextUrl
  });
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "allowed-provisional-document",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: nextUrl
  });
  await flushBackgroundWork();
  await persistBackgroundNow(mock);

  let stored = storedObservationForTab(mock, fixture.tab.id);
  assert.equal(stored.indexEntry.session.documentId, fixture.frames[0].documentId);
  assert.equal(stored.shard.session.documentId, fixture.frames[0].documentId);
  assert.equal(stored.shard.requests.at(-1).host, "baseline-collector.example");
  assert.doesNotMatch(JSON.stringify(stored), /allowed-provisional/);

  const restarted = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: settings },
    sessionData: mock.sessionData,
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  await loadBackground(restarted);
  restarted.initializationGate.release();
  await flushBackgroundWork();
  const recovered = await sendRuntimeMessage(restarted.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  assert.equal(recovered.session.documentId, fixture.frames[0].documentId);
  assert.equal(recovered.requests.at(-1).host, "baseline-collector.example");

  restarted.channels.beforeNavigate.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    timeStamp: Date.now(),
    url: nextUrl
  });
  restarted.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "allowed-provisional-document",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: nextUrl
  });
  restarted.tabs.get(fixture.tab.id).url = nextUrl;
  restarted.frames.get(fixture.tab.id)[0].url = nextUrl;
  restarted.frames.get(fixture.tab.id)[0].documentId = "allowed-provisional-document";
  restarted.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "allowed-provisional-document",
    documentLifecycle: "active",
    url: nextUrl
  });
  await flushBackgroundWork();
  await persistBackgroundNow(restarted);

  stored = storedObservationForTab(restarted, fixture.tab.id);
  assert.equal(stored.indexEntry.session.documentId, "allowed-provisional-document");
  assert.equal(stored.shard.session.documentId, "allowed-provisional-document");
  assert.deepEqual(stored.shard.requests.map((request) => request.host), [
    "allowed-provisional.example"
  ]);
});

test("an excluded provisional top navigation preserves restart recovery until failure or commit", async () => {
  const fixture = tabFixture(47, "excluded-backup.example");
  const excludedUrl = "https://excluded-provisional.example/private";
  const settings = {
    enabled: true,
    excludedOrigins: ["https://excluded-provisional.example"]
  };
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: settings },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);
  await persistBackgroundNow(mock);

  mock.channels.beforeNavigate.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    timeStamp: Date.now(),
    url: excludedUrl
  });
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "excluded-provisional-document",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: excludedUrl
  });
  await flushBackgroundWork();
  await persistBackgroundNow(mock);

  let stored = storedObservationForTab(mock, fixture.tab.id);
  assert.equal(stored.indexEntry.session.documentId, fixture.frames[0].documentId);
  assert.equal(stored.shard.session.documentId, fixture.frames[0].documentId);
  assert.doesNotMatch(JSON.stringify(stored), /excluded-provisional/);

  const restarted = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: settings },
    sessionData: mock.sessionData,
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  await loadBackground(restarted);
  restarted.initializationGate.release();
  await flushBackgroundWork();
  let recovered = await sendRuntimeMessage(restarted.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  assert.equal(recovered.session.documentId, fixture.frames[0].documentId);
  assert.equal(recovered.requests.at(-1).host, "baseline-collector.example");

  restarted.channels.beforeNavigate.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    timeStamp: Date.now(),
    url: excludedUrl
  });
  restarted.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "excluded-provisional-document",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: excludedUrl
  });
  await flushBackgroundWork();
  restarted.channels.navigationError.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "excluded-provisional-document",
    url: excludedUrl
  });
  await flushBackgroundWork();
  await persistBackgroundNow(restarted);
  recovered = await sendRuntimeMessage(restarted.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  assert.equal(recovered.session.documentId, fixture.frames[0].documentId);
  assert.equal(recovered.requests.at(-1).host, "baseline-collector.example");

  restarted.channels.beforeNavigate.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    timeStamp: Date.now(),
    url: excludedUrl
  });
  restarted.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "excluded-provisional-document",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: excludedUrl
  });
  await flushBackgroundWork();
  restarted.channels.tabUpdated.listeners[0](
    fixture.tab.id,
    { url: excludedUrl },
    { ...restarted.tabs.get(fixture.tab.id), url: excludedUrl }
  );
  await flushBackgroundWork();
  await persistBackgroundNow(restarted);
  stored = storedObservationForTab(restarted, fixture.tab.id);
  assert.equal(stored.shard.session.documentId, fixture.frames[0].documentId);

  restarted.tabs.get(fixture.tab.id).url = excludedUrl;
  restarted.frames.get(fixture.tab.id)[0].url = excludedUrl;
  restarted.frames.get(fixture.tab.id)[0].documentId = "excluded-provisional-document";
  restarted.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "excluded-provisional-document",
    documentLifecycle: "active",
    url: excludedUrl
  });
  await flushBackgroundWork();
  await persistBackgroundNow(restarted);

  stored = storedObservationForTab(restarted, fixture.tab.id);
  assert.equal(stored.indexEntry, undefined);
  assert.equal(stored.shard, undefined);
});

test("a redirect chain older than thirty seconds still restores the original committed page", async () => {
  const fixture = tabFixture(48, "slow-navigation-backup.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);
  const baseline = await sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  await persistBackgroundNow(mock);

  const initialUrl = "https://slow-redirect-start.example/destination";
  const finalUrl = "https://slow-redirect-final.example/destination";
  const originalDateNow = Date.now;
  let currentTime = originalDateNow();
  Date.now = () => currentTime;
  try {
    mock.channels.beforeNavigate.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      timeStamp: currentTime,
      url: initialUrl
    });
    mock.channels.beforeRequest.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: "slow-redirect-start-document",
      documentLifecycle: "active",
      type: "main_frame",
      method: "GET",
      url: initialUrl
    });
    await flushBackgroundWork();

    currentTime += 31_000;
    mock.channels.beforeRequest.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: "slow-redirect-final-document",
      documentLifecycle: "active",
      type: "main_frame",
      method: "GET",
      url: finalUrl
    });
    await flushBackgroundWork();
    await persistBackgroundNow(mock);

    const provisionalStored = storedObservationForTab(mock, fixture.tab.id);
    assert.equal(
      provisionalStored.indexEntry.session.documentId,
      fixture.frames[0].documentId
    );
    assert.equal(provisionalStored.shard.session.documentId, fixture.frames[0].documentId);
    assert.equal(
      provisionalStored.shard.requests.at(-1).host,
      "baseline-collector.example"
    );
    assert.doesNotMatch(JSON.stringify(provisionalStored), /slow-redirect-(?:start|final)/);

    mock.channels.navigationError.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: "slow-redirect-final-document",
      url: finalUrl
    });
    await flushBackgroundWork();
  } finally {
    Date.now = originalDateNow;
  }

  const restored = await sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  assert.equal(restored.session.generation, baseline.session.generation);
  assert.equal(restored.session.documentId, baseline.session.documentId);
  assert.deepEqual(restored.requests, baseline.requests);
});

test("a matching commit older than thirty seconds finalizes the pending page", async () => {
  const fixture = tabFixture(49, "slow-commit-backup.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);
  await persistBackgroundNow(mock);

  const nextUrl = "https://slow-commit-final.example/destination";
  const nextDocumentId = "slow-commit-final-document";
  const originalDateNow = Date.now;
  let currentTime = originalDateNow();
  Date.now = () => currentTime;
  try {
    mock.channels.beforeNavigate.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      timeStamp: currentTime,
      url: nextUrl
    });
    mock.channels.beforeRequest.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: nextDocumentId,
      documentLifecycle: "active",
      type: "main_frame",
      method: "GET",
      url: nextUrl
    });
    await flushBackgroundWork();

    currentTime += 31_000;
    mock.tabs.get(fixture.tab.id).url = nextUrl;
    mock.frames.get(fixture.tab.id)[0].url = nextUrl;
    mock.frames.get(fixture.tab.id)[0].documentId = nextDocumentId;
    mock.channels.committed.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: nextDocumentId,
      documentLifecycle: "active",
      timeStamp: currentTime,
      url: nextUrl
    });
    await flushBackgroundWork();
    await persistBackgroundNow(mock);
  } finally {
    Date.now = originalDateNow;
  }

  let stored = storedObservationForTab(mock, fixture.tab.id);
  assert.equal(stored.indexEntry.session.documentId, nextDocumentId);
  assert.equal(stored.shard.session.documentId, nextDocumentId);
  assert.deepEqual(stored.shard.requests.map((request) => request.host), [
    "slow-commit-final.example"
  ]);

  mock.channels.navigationError.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: nextDocumentId,
    url: nextUrl
  });
  await flushBackgroundWork();
  stored = storedObservationForTab(mock, fixture.tab.id);
  assert.equal(stored.shard.session.documentId, nextDocumentId);
  const activity = await sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  assert.equal(activity.session.documentId, nextDocumentId);
});

test("stalled pending backups expire without extending rich A history through other-tab persistence", async () => {
  const scenarios = [
    { tabId: 65, otherTabId: 75, excludedTarget: false },
    { tabId: 66, otherTabId: 76, excludedTarget: true }
  ];

  for (const scenario of scenarios) {
    const fixture = tabFixture(scenario.tabId, `ttl-backup-a-${scenario.tabId}.example`);
    const other = tabFixture(
      scenario.otherTabId,
      `ttl-persist-other-${scenario.otherTabId}.example`
    );
    const nextUrl = `https://ttl-target-b-${scenario.tabId}.example/destination`;
    const nextDocumentId = `ttl-target-document-${scenario.tabId}`;
    const mock = createChromeMock({
      localData: {
        [OBSERVATION_SETTINGS_KEY]: {
          enabled: true,
          excludedOrigins: scenario.excludedTarget ? [new URL(nextUrl).origin] : []
        }
      },
      tabs: [fixture.tab, other.tab],
      frames: [
        [fixture.tab.id, fixture.frames],
        [other.tab.id, other.frames]
      ]
    });
    await loadBackground(mock);
    mock.initializationGate.release();
    await flushBackgroundWork();
    await establishObservedTopDocument(mock, fixture);
    const baseline = await sendRuntimeMessage(mock.channels.message.listeners[0], {
      type: "GET_NETWORK_ACTIVITY",
      tabId: fixture.tab.id
    });
    await persistBackgroundNow(mock);

    const originalDateNow = Date.now;
    let currentTime = originalDateNow();
    Date.now = () => currentTime;
    try {
      mock.channels.beforeNavigate.listeners[0]({
        tabId: fixture.tab.id,
        frameId: 0,
        timeStamp: currentTime,
        url: nextUrl
      });
      mock.channels.beforeRequest.listeners[0]({
        tabId: fixture.tab.id,
        frameId: 0,
        documentId: nextDocumentId,
        documentLifecycle: "active",
        type: "main_frame",
        method: "GET",
        url: nextUrl
      });
      await flushBackgroundWork();

      currentTime += 60 * 60 * 1000 + 1;
      mock.channels.beforeRequest.listeners[0]({
        tabId: other.tab.id,
        frameId: 0,
        documentId: other.frames[0].documentId,
        documentLifecycle: "active",
        type: "main_frame",
        method: "GET",
        url: other.tab.url
      });
      mock.channels.committed.listeners[0]({
        tabId: other.tab.id,
        frameId: 0,
        documentId: other.frames[0].documentId,
        documentLifecycle: "active",
        url: other.tab.url
      });
      await flushBackgroundWork();
      await persistBackgroundNow(mock);

      const expiredStored = storedObservationForTab(mock, fixture.tab.id);
      assert.equal(expiredStored.indexEntry, undefined);
      assert.equal(expiredStored.shard, undefined);
      assert.ok(storedObservationForTab(mock, other.tab.id).shard);

      mock.channels.navigationError.listeners[0]({
        tabId: fixture.tab.id,
        frameId: 0,
        documentId: nextDocumentId,
        url: nextUrl
      });
      await flushBackgroundWork();
      const recovered = await sendRuntimeMessage(mock.channels.message.listeners[0], {
        type: "GET_NETWORK_ACTIVITY",
        tabId: fixture.tab.id
      });
      assert.equal(recovered.observationEnabled, true);
      assert.equal(recovered.session.documentId, fixture.frames[0].documentId);
      assert.notEqual(recovered.session.generation, baseline.session.generation);
      assert.deepEqual(recovered.requests, []);
      assert.deepEqual(recovered.cookies, []);
      assert.deepEqual(recovered.snapshots, []);
    } finally {
      Date.now = originalDateNow;
    }
  }
});

test("tabs.onUpdated never replaces the committed backup across navigation event orderings", async () => {
  const scenarios = [
    {
      label: "allowed update before navigation events",
      tabId: 50,
      excluded: false,
      steps: ["updated", "beforeNavigate", "beforeRequest"]
    },
    {
      label: "allowed update between navigation and request events",
      tabId: 51,
      excluded: false,
      steps: ["beforeNavigate", "updated", "beforeRequest"]
    },
    {
      label: "excluded update before navigation events",
      tabId: 52,
      excluded: true,
      steps: ["updated", "beforeNavigate", "beforeRequest"]
    },
    {
      label: "excluded update between navigation and request events",
      tabId: 53,
      excluded: true,
      steps: ["beforeNavigate", "updated", "beforeRequest"]
    },
    {
      label: "excluded update after request processing",
      tabId: 54,
      excluded: true,
      steps: ["beforeNavigate", "beforeRequest", "flush", "updated"]
    },
    {
      label: "invalid update after request processing",
      tabId: 55,
      excluded: false,
      updateUrl: "chrome-error://chromewebdata/",
      steps: ["beforeNavigate", "beforeRequest", "flush", "updated"]
    }
  ];

  for (const scenario of scenarios) {
    const fixture = tabFixture(scenario.tabId, `updated-backup-${scenario.tabId}.example`);
    const nextUrl = `https://updated-target-${scenario.tabId}.example/destination`;
    const nextDocumentId = `updated-target-document-${scenario.tabId}`;
    const settings = {
      enabled: true,
      excludedOrigins: scenario.excluded
        ? [`https://updated-target-${scenario.tabId}.example`]
        : []
    };
    const mock = createChromeMock({
      localData: { [OBSERVATION_SETTINGS_KEY]: settings },
      tabs: [fixture.tab],
      frames: [[fixture.tab.id, fixture.frames]]
    });
    await loadBackground(mock);
    mock.initializationGate.release();
    await flushBackgroundWork();
    await establishObservedTopDocument(mock, fixture);
    const baseline = await sendRuntimeMessage(mock.channels.message.listeners[0], {
      type: "GET_NETWORK_ACTIVITY",
      tabId: fixture.tab.id
    });

    for (const step of scenario.steps) {
      if (step === "flush") {
        await flushBackgroundWork();
      } else if (step === "updated") {
        const updateUrl = scenario.updateUrl || nextUrl;
        mock.channels.tabUpdated.listeners[0](
          fixture.tab.id,
          { url: updateUrl },
          { ...fixture.tab, url: updateUrl }
        );
      } else if (step === "beforeNavigate") {
        mock.channels.beforeNavigate.listeners[0]({
          tabId: fixture.tab.id,
          frameId: 0,
          timeStamp: Date.now(),
          url: nextUrl
        });
      } else if (step === "beforeRequest") {
        mock.channels.beforeRequest.listeners[0]({
          tabId: fixture.tab.id,
          frameId: 0,
          documentId: nextDocumentId,
          documentLifecycle: "active",
          type: "main_frame",
          method: "GET",
          url: nextUrl
        });
      }
    }
    await flushBackgroundWork();
    await persistBackgroundNow(mock);
    const provisionalStored = storedObservationForTab(mock, fixture.tab.id);
    assert.equal(
      provisionalStored.shard.session.documentId,
      baseline.session.documentId,
      scenario.label
    );
    assert.equal(
      provisionalStored.shard.requests.at(-1).host,
      "baseline-collector.example",
      scenario.label
    );
    mock.channels.navigationError.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: nextDocumentId,
      url: nextUrl
    });
    await flushBackgroundWork();

    const restored = await sendRuntimeMessage(mock.channels.message.listeners[0], {
      type: "GET_NETWORK_ACTIVITY",
      tabId: fixture.tab.id
    });
    assert.equal(
      restored.session.generation,
      baseline.session.generation,
      scenario.label
    );
    assert.equal(
      restored.session.documentId,
      baseline.session.documentId,
      scenario.label
    );
    assert.deepEqual(restored.requests, baseline.requests, scenario.label);
  }
});

test("excluding only committed A drops its backup while allowed provisional B waits for commit", async () => {
  const fixture = tabFixture(56, "settings-backup-a.example");
  const nextUrl = "https://settings-target-b.example/destination";
  const nextDocumentId = "settings-target-b-document";
  const mock = createChromeMock({
    localData: {
      [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] }
    },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);
  await persistBackgroundNow(mock);

  mock.channels.beforeNavigate.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    timeStamp: Date.now(),
    url: nextUrl
  });
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: nextDocumentId,
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: nextUrl
  });
  await flushBackgroundWork();
  await applyObservationSettingsChange(mock, {
    enabled: true,
    excludedOrigins: ["https://settings-backup-a.example"]
  });
  await persistBackgroundNow(mock);

  let stored = storedObservationForTab(mock, fixture.tab.id);
  assert.equal(stored.indexEntry, undefined);
  assert.equal(stored.shard, undefined);
  assert.equal(
    backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id].session.documentId,
    nextDocumentId
  );

  mock.tabs.get(fixture.tab.id).url = nextUrl;
  mock.frames.get(fixture.tab.id)[0].url = nextUrl;
  mock.frames.get(fixture.tab.id)[0].documentId = nextDocumentId;
  mock.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: nextDocumentId,
    documentLifecycle: "active",
    url: nextUrl
  });
  await flushBackgroundWork();
  await persistBackgroundNow(mock);

  stored = storedObservationForTab(mock, fixture.tab.id);
  assert.equal(stored.shard.session.documentId, nextDocumentId);
  assert.deepEqual(stored.shard.requests.map((request) => request.host), [
    "settings-target-b.example"
  ]);
});

test("excluding only provisional B discards B while retaining A for error and commit boundaries", async () => {
  const fixture = tabFixture(57, "settings-allowed-a.example");
  const nextUrl = "https://settings-excluded-b.example/destination";
  const nextDocumentId = "settings-excluded-b-document";
  const mock = createChromeMock({
    localData: {
      [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] }
    },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);
  const baseline = await sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  await persistBackgroundNow(mock);

  const startExcludedNavigation = async () => {
    mock.channels.beforeNavigate.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      timeStamp: Date.now(),
      url: nextUrl
    });
    mock.channels.beforeRequest.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: nextDocumentId,
      documentLifecycle: "active",
      type: "main_frame",
      method: "GET",
      url: nextUrl
    });
    await flushBackgroundWork();
  };

  await startExcludedNavigation();
  await applyObservationSettingsChange(mock, {
    enabled: true,
    excludedOrigins: ["https://settings-excluded-b.example"]
  });
  await persistBackgroundNow(mock);

  let stored = storedObservationForTab(mock, fixture.tab.id);
  assert.equal(stored.shard.session.documentId, fixture.frames[0].documentId);
  assert.equal(stored.shard.requests.at(-1).host, "baseline-collector.example");
  assert.equal(backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id], undefined);

  mock.channels.navigationError.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: nextDocumentId,
    url: nextUrl
  });
  await flushBackgroundWork();
  const restored = await sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  assert.equal(restored.session.generation, baseline.session.generation);
  assert.deepEqual(restored.requests, baseline.requests);

  await startExcludedNavigation();
  mock.tabs.get(fixture.tab.id).url = nextUrl;
  mock.frames.get(fixture.tab.id)[0].url = nextUrl;
  mock.frames.get(fixture.tab.id)[0].documentId = nextDocumentId;
  mock.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: nextDocumentId,
    documentLifecycle: "active",
    url: nextUrl
  });
  await flushBackgroundWork();
  await persistBackgroundNow(mock);
  stored = storedObservationForTab(mock, fixture.tab.id);
  assert.equal(stored.indexEntry, undefined);
  assert.equal(stored.shard, undefined);
});

test("excluding both navigation sides or globally pausing removes every recovery state", async () => {
  const scenarios = [
    {
      tabId: 58,
      settings(fixture, nextUrl) {
        return {
          enabled: true,
          excludedOrigins: [new URL(fixture.tab.url).origin, new URL(nextUrl).origin]
        };
      }
    },
    {
      tabId: 59,
      settings() {
        return { enabled: false, excludedOrigins: [] };
      }
    }
  ];

  for (const scenario of scenarios) {
    const fixture = tabFixture(scenario.tabId, `settings-remove-a-${scenario.tabId}.example`);
    const nextUrl = `https://settings-remove-b-${scenario.tabId}.example/destination`;
    const nextDocumentId = `settings-remove-document-${scenario.tabId}`;
    const mock = createChromeMock({
      localData: {
        [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] }
      },
      tabs: [fixture.tab],
      frames: [[fixture.tab.id, fixture.frames]]
    });
    await loadBackground(mock);
    mock.initializationGate.release();
    await flushBackgroundWork();
    await establishObservedTopDocument(mock, fixture);
    await persistBackgroundNow(mock);
    mock.channels.beforeNavigate.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      timeStamp: Date.now(),
      url: nextUrl
    });
    mock.channels.beforeRequest.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: nextDocumentId,
      documentLifecycle: "active",
      type: "main_frame",
      method: "GET",
      url: nextUrl
    });
    await flushBackgroundWork();

    await applyObservationSettingsChange(mock, scenario.settings(fixture, nextUrl));
    await persistBackgroundNow(mock);
    const stored = storedObservationForTab(mock, fixture.tab.id);
    assert.equal(stored.indexEntry, undefined);
    assert.equal(stored.shard, undefined);

    mock.channels.navigationError.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: nextDocumentId,
      url: nextUrl
    });
    await flushBackgroundWork();
    const activity = await sendRuntimeMessage(mock.channels.message.listeners[0], {
      type: "GET_NETWORK_ACTIVITY",
      tabId: fixture.tab.id
    });
    assert.equal(activity.observationEnabled, false);
    assert.equal(activity.session, null);
  }
});

test("pending-free invalid URL errors restore eligibility only after a stable double-frame check", async () => {
  const invalidUrls = [
    "chrome-error://chromewebdata/",
    `https://oversized-update.example/${"x".repeat(17 * 1024)}`
  ];

  for (let index = 0; index < invalidUrls.length; index += 1) {
    const fixture = tabFixture(60 + index, `invalid-error-${index}.example`);
    const mock = createChromeMock({
      localData: {
        [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] }
      },
      tabs: [fixture.tab],
      frames: [[fixture.tab.id, fixture.frames]]
    });
    const backgroundModule = await loadBackground(mock);
    mock.initializationGate.release();
    await flushBackgroundWork();
    await establishObservedTopDocument(mock, fixture);
    const beforeCount =
      backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id].requests.length;

    mock.channels.tabUpdated.listeners[0](
      fixture.tab.id,
      { url: invalidUrls[index] },
      { ...fixture.tab, url: invalidUrls[index] }
    );
    await flushBackgroundWork();
    mock.channels.navigationError.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: `invalid-error-document-${index}`,
      url: invalidUrls[index]
    });
    await flushBackgroundWork();

    mock.channels.beforeRequest.listeners[0]({
      tabId: fixture.tab.id,
      frameId: 0,
      documentId: fixture.frames[0].documentId,
      documentLifecycle: "active",
      type: "xmlhttprequest",
      method: "GET",
      url: `https://eligibility-restored-${index}.example/collect`
    });
    await flushBackgroundWork();
    const state = backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id];
    assert.equal(state.requests.length, beforeCount + 1);
    assert.equal(state.requests.at(-1).host, `eligibility-restored-${index}.example`);
  }
});

test("failed top navigation restores the exact prior session and request history", async () => {
  const fixture = tabFixture(41, "stable-top.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);
  const onMessage = mock.channels.message.listeners[0];
  const baseline = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });

  const failedUrl = "https://failed-top.example/destination";
  mock.channels.storageChanged.listeners[0](
    {
      [OBSERVATION_SETTINGS_KEY]: {
        newValue: {
          enabled: true,
          excludedOrigins: ["https://failed-top.example"]
        }
      }
    },
    "local"
  );
  await flushBackgroundWork();
  mock.channels.beforeNavigate.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    timeStamp: Date.now(),
    url: failedUrl
  });
  await flushBackgroundWork();
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "failed-top-document",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: failedUrl
  });
  await flushBackgroundWork();
  assert.equal(backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id], undefined);

  mock.channels.navigationError.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "failed-top-document",
    url: failedUrl
  });
  await flushBackgroundWork();
  const restored = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  assert.equal(restored.session.generation, baseline.session.generation);
  assert.equal(restored.session.documentId, baseline.session.documentId);
  assert.deepEqual(restored.requests, baseline.requests);
  assert.equal(restored.requests.at(-1).host, "baseline-collector.example");
  assert.doesNotMatch(JSON.stringify(restored), /never-retain-value/);
});

test("a committed excluded page cannot lend an old backup to a later failed navigation", async () => {
  const fixture = tabFixture(44, "backup-boundary.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);

  const excludedUrl = "https://excluded-commit.example/private";
  mock.channels.storageChanged.listeners[0](
    {
      [OBSERVATION_SETTINGS_KEY]: {
        newValue: { enabled: true, excludedOrigins: ["https://excluded-commit.example"] }
      }
    },
    "local"
  );
  await flushBackgroundWork();
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "excluded-document",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: excludedUrl
  });
  await flushBackgroundWork();

  mock.tabs.get(fixture.tab.id).url = excludedUrl;
  mock.frames.get(fixture.tab.id)[0].url = excludedUrl;
  mock.frames.get(fixture.tab.id)[0].documentId = "excluded-document";
  mock.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "excluded-document",
    documentLifecycle: "active",
    url: excludedUrl
  });
  await flushBackgroundWork();

  const failedUrl = "https://allowed-after-exclusion.example/destination";
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "later-failed-document",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: failedUrl
  });
  await flushBackgroundWork();
  mock.channels.navigationError.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "later-failed-document",
    url: failedUrl
  });
  await flushBackgroundWork();

  assert.equal(backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id], undefined);
});

test("a late A error cannot roll back a newer pending B navigation", async () => {
  const fixture = tabFixture(42, "late-error.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);
  const baseline = await sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  const beforeRequest = mock.channels.beforeRequest.listeners[0];
  const firstFailedUrl = "https://first-pending.example/a";
  const newerPendingUrl = "https://newer-pending.example/b";
  beforeRequest({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "pending-document-a",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: firstFailedUrl
  });
  beforeRequest({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "pending-document-b",
    documentLifecycle: "active",
    type: "main_frame",
    method: "GET",
    url: newerPendingUrl
  });
  await flushBackgroundWork();
  mock.channels.navigationError.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "pending-document-a",
    url: firstFailedUrl
  });
  await flushBackgroundWork();
  let pendingState = backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id];
  assert.equal(pendingState.session.documentId, "pending-document-b");
  assert.equal(pendingState.requests.length, 1);
  assert.equal(pendingState.requests[0].host, "newer-pending.example");

  mock.channels.navigationError.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 0,
    documentId: "pending-document-b",
    url: newerPendingUrl
  });
  await flushBackgroundWork();
  const restored = await sendRuntimeMessage(mock.channels.message.listeners[0], {
    type: "GET_NETWORK_ACTIVITY",
    tabId: fixture.tab.id
  });
  assert.equal(restored.session.generation, baseline.session.generation);
  assert.deepEqual(restored.requests, baseline.requests);
});

test("a sub-frame webRequest before onBeforeNavigate cannot replace the committed iframe", async () => {
  const fixture = tabFixture(43, "iframe-host.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);
  const oldFrameUrl = "https://frame.example/old";
  mock.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    parentFrameId: 0,
    parentDocumentId: fixture.frames[0].documentId,
    documentId: "iframe-document-old",
    documentLifecycle: "active",
    url: oldFrameUrl
  });
  await flushBackgroundWork();

  const failedFrameUrl = "https://frame.example/new";
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    parentDocumentId: fixture.frames[0].documentId,
    documentId: "iframe-document-new",
    documentLifecycle: "active",
    type: "sub_frame",
    method: "GET",
    url: failedFrameUrl
  });
  await flushBackgroundWork();
  mock.channels.beforeNavigate.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    timeStamp: Date.now(),
    url: failedFrameUrl
  });
  await flushBackgroundWork();
  let frameDocuments = new Map(
    backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id].frameDocuments
  );
  assert.equal(frameDocuments.get(1), "iframe-document-old");
  assert.equal(
    backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id].requests.at(-1).type,
    "sub_frame"
  );

  mock.channels.navigationError.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    documentId: "iframe-document-new",
    url: failedFrameUrl
  });
  await flushBackgroundWork();
  frameDocuments = new Map(
    backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id].frameDocuments
  );
  assert.equal(frameDocuments.get(1), "iframe-document-old");
});

test("redirected iframe provisional documents are dropped or promoted in event order", async () => {
  const fixture = tabFixture(45, "iframe-redirect-host.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);
  mock.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    parentFrameId: 0,
    parentDocumentId: fixture.frames[0].documentId,
    documentId: "iframe-redirect-old",
    documentLifecycle: "active",
    url: "https://redirect-frame.example/old"
  });
  await flushBackgroundWork();

  const firstUrl = "https://redirect-frame.example/start";
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    parentDocumentId: fixture.frames[0].documentId,
    documentId: "iframe-redirect-first",
    documentLifecycle: "active",
    type: "sub_frame",
    method: "GET",
    url: firstUrl
  });
  mock.channels.beforeNavigate.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    timeStamp: Date.now(),
    url: firstUrl
  });
  await flushBackgroundWork();
  mock.channels.navigationError.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    documentId: "iframe-redirect-first",
    url: firstUrl
  });
  await flushBackgroundWork();

  const redirectStartUrl = "https://redirect-frame.example/start-again";
  mock.channels.beforeNavigate.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    timeStamp: Date.now(),
    url: redirectStartUrl
  });
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    parentDocumentId: fixture.frames[0].documentId,
    documentId: "iframe-redirect-start",
    documentLifecycle: "active",
    type: "sub_frame",
    method: "GET",
    url: redirectStartUrl
  });
  const finalUrl = "https://redirect-frame.example/final";
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    parentDocumentId: fixture.frames[0].documentId,
    documentId: "iframe-redirect-final",
    documentLifecycle: "active",
    type: "sub_frame",
    method: "GET",
    url: finalUrl
  });
  await flushBackgroundWork();
  mock.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    parentFrameId: 0,
    parentDocumentId: fixture.frames[0].documentId,
    documentId: "iframe-redirect-final",
    documentLifecycle: "active",
    transitionQualifiers: ["server_redirect"],
    url: finalUrl
  });
  await flushBackgroundWork();

  const state = backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id];
  const frameDocuments = new Map(state.frameDocuments);
  assert.equal(frameDocuments.get(1), "iframe-redirect-final");
  assert.deepEqual(
    state.requests.slice(-3).map((request) => request.host),
    ["redirect-frame.example", "redirect-frame.example", "redirect-frame.example"]
  );
});

test("an iframe commit promotes a missing redirect request only for a connected current parent", async () => {
  const fixture = tabFixture(64, "iframe-authoritative-host.example");
  const mock = createChromeMock({
    localData: { [OBSERVATION_SETTINGS_KEY]: { enabled: true, excludedOrigins: [] } },
    tabs: [fixture.tab],
    frames: [[fixture.tab.id, fixture.frames]]
  });
  const backgroundModule = await loadBackground(mock);
  mock.initializationGate.release();
  await flushBackgroundWork();
  await establishObservedTopDocument(mock, fixture);

  mock.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    parentFrameId: 0,
    parentDocumentId: fixture.frames[0].documentId,
    documentId: "iframe-authoritative-old",
    documentLifecycle: "active",
    url: "https://iframe-authoritative.example/old"
  });
  await flushBackgroundWork();

  const initialUrl = "https://iframe-authoritative.example/redirect-start";
  mock.channels.beforeNavigate.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    timeStamp: Date.now(),
    url: initialUrl
  });
  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    parentDocumentId: fixture.frames[0].documentId,
    documentId: "iframe-authoritative-initial",
    documentLifecycle: "active",
    type: "sub_frame",
    method: "GET",
    url: initialUrl
  });
  await flushBackgroundWork();

  const finalUrl = "https://iframe-authoritative.example/redirect-final";
  mock.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    parentFrameId: 0,
    parentDocumentId: fixture.frames[0].documentId,
    documentId: "iframe-authoritative-final",
    documentLifecycle: "active",
    transitionQualifiers: ["server_redirect"],
    url: finalUrl
  });
  await flushBackgroundWork();

  let state = backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id];
  let frameDocuments = new Map(state.frameDocuments);
  assert.equal(frameDocuments.get(1), "iframe-authoritative-final");
  const requestCountAfterCommit = state.requests.length;

  mock.channels.beforeRequest.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 1,
    documentId: "iframe-authoritative-initial",
    documentLifecycle: "active",
    type: "script",
    method: "GET",
    url: "https://iframe-authoritative.example/stale-script.js"
  });
  mock.channels.committed.listeners[0]({
    tabId: fixture.tab.id,
    frameId: 2,
    parentFrameId: 1,
    parentDocumentId: "iframe-authoritative-old",
    documentId: "iframe-disconnected-child",
    documentLifecycle: "active",
    url: "https://iframe-authoritative.example/disconnected"
  });
  await flushBackgroundWork();

  state = backgroundModule.buildPersistedObservationState().tabs[fixture.tab.id];
  frameDocuments = new Map(state.frameDocuments);
  assert.equal(state.requests.length, requestCountAfterCommit);
  assert.equal(frameDocuments.get(1), "iframe-authoritative-final");
  assert.equal(frameDocuments.has(2), false);
});
