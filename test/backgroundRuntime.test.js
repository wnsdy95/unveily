import assert from "node:assert/strict";
import test from "node:test";
import { analyzePolicy } from "../src/analyzer.js";
import { documentUrlFingerprint } from "../src/backgroundSecurity.js";
import {
  POLICY_CHECK_HEALTH_KEY,
  POLICY_SNAPSHOTS_KEY,
  createPolicySnapshot,
  normalizePolicyUrl
} from "../src/policySnapshots.js";

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

function createChromeMock(options = {}) {
  const tabs = new Map([
    [
      7,
      {
        id: 7,
        status: "complete",
        url: "https://example.com/app?account=one"
      }
    ]
  ]);
  const frames = new Map([
    [
      7,
      [{ frameId: 0, parentFrameId: -1, documentId: "document-one", url: tabs.get(7).url }]
    ]
  ]);
  const localData = {};
  const sessionData = {};
  const sessionSetCalls = [];
  const sessionRemoveCalls = [];
  const tabMessages = [];
  let tabsGetHook = null;
  let tabsGetCallCount = 0;
  let releaseInitialization = () => {};
  const initializationGate = options.blockInitialization
    ? new Promise((resolve) => {
        releaseInitialization = resolve;
      })
    : null;
  const channels = {
    beforeRequest: eventChannel(),
    committed: eventChannel(),
    history: eventChannel(),
    referenceFragment: eventChannel(),
    beforeNavigate: eventChannel(),
    navigationError: eventChannel(),
    message: eventChannel(),
    connect: eventChannel(),
    tabUpdated: eventChannel(),
    suspended: eventChannel()
  };
  const localStorage = {
    async setAccessLevel() {},
    async get(keys) {
      if (initializationGate) await initializationGate;
      return selectStorage(localData, keys);
    },
    async set(values) {
      Object.assign(localData, values);
    }
  };
  const sessionStorage = {
    async get(keys) {
      return structuredClone(selectStorage(sessionData, keys));
    },
    async set(values) {
      const copy = structuredClone(values);
      sessionSetCalls.push(copy);
      Object.assign(sessionData, copy);
    },
    async remove(keys) {
      const normalizedKeys = Array.isArray(keys) ? [...keys] : [keys];
      sessionRemoveCalls.push(normalizedKeys);
      normalizedKeys.forEach((key) => delete sessionData[key]);
    }
  };

  const chrome = {
    runtime: {
      id: "runtime-test-extension",
      lastError: null,
      getURL: (path) => `chrome-extension://runtime-test-extension/${path}`,
      onInstalled: eventChannel(),
      onStartup: eventChannel(),
      onSuspend: channels.suspended,
      onMessage: channels.message,
      onConnect: channels.connect
    },
    webRequest: { onBeforeRequest: channels.beforeRequest },
    webNavigation: {
      onCommitted: channels.committed,
      onHistoryStateUpdated: channels.history,
      onReferenceFragmentUpdated: channels.referenceFragment,
      onBeforeNavigate: channels.beforeNavigate,
      onErrorOccurred: channels.navigationError,
      async getAllFrames({ tabId }) {
        return frames.get(tabId) || [];
      },
      async getFrame({ tabId, frameId }) {
        return (frames.get(tabId) || []).find((frame) => frame.frameId === frameId) || null;
      }
    },
    cookies: {
      onChanged: eventChannel(),
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
        const result = { ...tab };
        tabsGetCallCount += 1;
        tabsGetHook?.({ tabId, callCount: tabsGetCallCount });
        return result;
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
      onChanged: eventChannel()
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
    notifications: {
      onClicked: eventChannel(),
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
    tabs,
    frames,
    localData,
    sessionData,
    sessionSetCalls,
    sessionRemoveCalls,
    tabMessages,
    setTabsGetHook(hook) {
      tabsGetCallCount = 0;
      tabsGetHook = typeof hook === "function" ? hook : null;
    },
    releaseInitialization
  };
}

async function flushBackgroundWork() {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

async function sendRuntimeMessage(listener, message) {
  return sendRuntimeMessageFromSender(listener, message, {
    id: "runtime-test-extension",
    url: "chrome-extension://runtime-test-extension/src/popup.html"
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

async function readCompanionState(mock, onMessage, tabId) {
  const tab = mock.tabs.get(tabId);
  const frame = (mock.frames.get(tabId) || []).find((candidate) => candidate.frameId === 0);
  return sendRuntimeMessageFromSender(
    onMessage,
    { type: "GET_COMPANION_OVERLAY_STATE" },
    {
      id: "runtime-test-extension",
      tab: { ...tab },
      frameId: 0,
      documentId: frame?.documentId,
      documentLifecycle: "active",
      url: tab?.url
    }
  );
}

async function verifyIncrementalPolicyHealth(mock, onMessage) {
  const policyText =
    "Privacy Policy. We collect your name, email address, and IP address to provide the service. " +
    "We may share data with service providers. We retain personal information for 30 days. " +
    "You may request access, correction, and deletion of your personal data. Contact privacy@example.com.";
  const policyAnalysis = analyzePolicy(policyText);
  const firstUrl = "https://example.com/privacy-one";
  const secondUrl = "https://example.com/privacy-two";
  const [firstSnapshot, secondSnapshot] = await Promise.all([
    createPolicySnapshot({
      title: "First privacy policy",
      url: firstUrl,
      text: policyText,
      policyAnalysis
    }),
    createPolicySnapshot({
      title: "Second privacy policy",
      url: secondUrl,
      text: policyText,
      policyAnalysis
    })
  ]);
  mock.localData[POLICY_SNAPSHOTS_KEY] = {
    [firstSnapshot.key]: firstSnapshot,
    [secondSnapshot.key]: secondSnapshot
  };

  const originalFetch = globalThis.fetch;
  let releaseSecondFetch;
  const secondFetch = new Promise((resolve) => {
    releaseSecondFetch = resolve;
  });
  const response = () =>
    new Response(policyText, {
      status: 200,
      headers: { "content-type": "text/plain; charset=utf-8" }
    });
  globalThis.fetch = async (url) => {
    if (url === secondUrl) return secondFetch;
    return response();
  };

  try {
    const resultPromise = sendRuntimeMessage(onMessage, {
      type: "CHECK_SAVED_POLICIES_NOW"
    });
    for (let attempt = 0; attempt < 30; attempt += 1) {
      if (mock.localData[POLICY_CHECK_HEALTH_KEY]?.[firstSnapshot.key]) break;
      await flushBackgroundWork();
    }
    assert.ok(mock.localData[POLICY_CHECK_HEALTH_KEY]?.[firstSnapshot.key]);
    assert.equal(mock.localData[POLICY_CHECK_HEALTH_KEY]?.[secondSnapshot.key], undefined);

    releaseSecondFetch(response());
    const result = await resultPromise;
    assert.equal(result.ok, true);
    assert.equal(result.checked, 2);
    assert.ok(mock.localData[POLICY_CHECK_HEALTH_KEY]?.[secondSnapshot.key]);
  } finally {
    globalThis.fetch = originalFetch;
  }
}

test("background isolates same-route navigations and rejects stale-document request events", async () => {
  const mock = createChromeMock();
  const storedAt = Date.now();
  mock.localData.observationSettings = {
    enabled: true,
    excludedOrigins: ["https://excluded.example"]
  };
  mock.localData.companionOverlayEnabled = true;
  mock.tabs.set(8, {
    id: 8,
    status: "complete",
    url: "https://excluded.example/privacy"
  });
  mock.frames.set(8, [
    {
      frameId: 0,
      parentFrameId: -1,
      documentId: "excluded-document",
      url: mock.tabs.get(8).url
    }
  ]);
  mock.tabs.set(6, {
    id: 6,
    status: "complete",
    url: "https://restore.example/app?scope=current"
  });
  mock.frames.set(6, [
    {
      frameId: 0,
      parentFrameId: -1,
      documentId: "document-six",
      url: mock.tabs.get(6).url
    }
  ]);
  mock.sessionData.observationSessionStateV1 = {
    version: 4,
    layout: "per-tab-v1",
    savedAt: storedAt,
    tabs: {
      6: {
        key: "observationSessionTabV4:6",
        session: {
          generation: 4,
          documentId: "document-six",
          origin: "https://restore.example",
          navigationKey: "https://restore.example/:segment",
          startedAt: storedAt - 1_000,
          lastSeenAt: storedAt
        }
      },
      7: {
        key: "observationSessionTabV4:7",
        session: {
          generation: 9,
          documentId: "stale-document",
          origin: "https://example.com",
          navigationKey: "https://example.com/:segment",
          startedAt: storedAt - 100,
          lastSeenAt: storedAt
        }
      }
    }
  };
  mock.sessionData["observationSessionTabV4:6"] = {
    session: mock.sessionData.observationSessionStateV1.tabs[6].session,
    requests: [
      {
        url: "https://collector.example/collect",
        method: "POST",
        type: "xmlhttprequest",
        timeStamp: storedAt - 50,
        queryKeys: ["event"],
        bodyKeys: ["category"]
      }
    ],
    cookies: [],
    snapshots: [],
    frameDocuments: [[0, "document-six"]],
    riskIndicator: null
  };
  mock.sessionData["observationSessionTabV4:7"] = {
    session: mock.sessionData.observationSessionStateV1.tabs[7].session,
    requests: [
      {
        url: "https://stale.example/collect",
        method: "GET",
        type: "xmlhttprequest",
        timeStamp: storedAt - 50
      }
    ],
    cookies: [],
    snapshots: [],
    frameDocuments: [[0, "stale-document"]],
    riskIndicator: {
      level: "high",
      source: "popup-page",
      url: "https://example.com/:segment",
      updatedAt: storedAt
    }
  };
  mock.sessionData["observationSessionTabV3:999"] = { obsolete: true };
  globalThis.chrome = mock.chrome;
  const backgroundModule = await import(`../src/background.js?runtime-test=${Date.now()}`);
  await flushBackgroundWork();

  const beforeRequest = mock.channels.beforeRequest.listeners[0];
  const onMessage = mock.channels.message.listeners[0];
  assert.equal(typeof beforeRequest, "function");
  assert.equal(typeof onMessage, "function");
  assert.deepEqual(
    await sendRuntimeMessage(onMessage, { type: "GET_COMPANION_OVERLAY_PREFERENCE" }),
    { ok: true, enabled: true }
  );
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
  assert.equal(mock.localData.companionOverlayEnabled, true);
  assert.ok(
    mock.tabMessages.some(
      (entry) =>
        entry.message.type === "COMPANION_OVERLAY_VISIBILITY" &&
        entry.options?.documentId === "document-one"
    )
  );
  mock.tabMessages.length = 0;
  assert.equal(mock.sessionData["observationSessionTabV3:999"], undefined);
  assert.ok(
    mock.sessionRemoveCalls.some((keys) => keys.includes("observationSessionTabV3:999"))
  );

  const hydratedActivity = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: 6
  });
  assert.equal(hydratedActivity.session.documentId, "document-six");
  assert.equal(hydratedActivity.session.generation, 4);
  assert.equal(hydratedActivity.requests.length, 1);
  assert.equal(hydratedActivity.requests[0].host, "collector.example");
  assert.deepEqual(hydratedActivity.requests[0].bodyKeys, []);

  const recoveredActivity = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: 7
  });
  assert.equal(recoveredActivity.session.documentId, "document-one");
  assert.equal(recoveredActivity.requests.length, 0);
  assert.notEqual(recoveredActivity.session.generation, 9);

  const startedAt = Date.now();
  beforeRequest({
    tabId: 7,
    frameId: 0,
    documentId: "document-one",
    type: "main_frame",
    method: "GET",
    timeStamp: startedAt,
    url: "https://example.com/app?account=one"
  });
  beforeRequest({
    tabId: 7,
    frameId: 0,
    documentId: "document-one",
    type: "xmlhttprequest",
    method: "POST",
    timeStamp: startedAt + 1,
    url: "https://metrics.example/collect?email=secret@example.com",
    requestBody: { formData: { email: ["secret@example.com"] } }
  });
  await flushBackgroundWork();

  let activity = await sendRuntimeMessage(onMessage, { type: "GET_NETWORK_ACTIVITY", tabId: 7 });
  assert.equal(activity.ok, true);
  assert.equal(activity.requests.length, 2);
  assert.deepEqual(activity.requests[1].queryKeys, ["email"]);
  assert.deepEqual(activity.requests[1].bodyKeys, []);
  assert.doesNotMatch(JSON.stringify(activity), /secret@example\.com/);
  const firstDocumentFingerprint = activity.session.documentFingerprint;

  mock.tabs.get(7).url = "https://example.com/app?account=two";
  mock.frames.set(7, [
    {
      frameId: 0,
      parentFrameId: -1,
      documentId: "document-two",
      url: mock.tabs.get(7).url
    }
  ]);
  beforeRequest({
    tabId: 7,
    frameId: 0,
    documentId: "document-two",
    type: "main_frame",
    method: "GET",
    timeStamp: startedAt + 10,
    url: mock.tabs.get(7).url
  });
  beforeRequest({
    tabId: 7,
    frameId: 0,
    documentId: "document-one",
    type: "xmlhttprequest",
    method: "GET",
    timeStamp: startedAt + 11,
    url: "https://old.example/collect?old=value"
  });
  await flushBackgroundWork();

  activity = await sendRuntimeMessage(onMessage, { type: "GET_NETWORK_ACTIVITY", tabId: 7 });
  assert.equal(activity.requests.length, 1, JSON.stringify(activity));
  assert.equal(activity.requests[0].type, "main_frame");
  assert.equal(activity.session.navigationKey, "https://example.com/:segment");
  assert.match(activity.session.documentFingerprint, /^[a-f0-9]{32}$/);

  assert.equal(mock.channels.connect.listeners.length, 0);
  assert.equal((await readCompanionState(mock, onMessage, 7)).state.status, "unknown");
  assert.equal((await readCompanionState(mock, onMessage, 8)).state.status, "excluded");
  mock.tabMessages.length = 0;
  const explicitExcludedIndicator = await sendRuntimeMessage(onMessage, {
    type: "SET_RISK_INDICATOR",
    tabId: 8,
    indicator: {
      level: "high",
      score: 75,
      source: "popup-page",
      url: mock.tabs.get(8).url,
      documentFingerprint: documentUrlFingerprint(mock.tabs.get(8).url),
      documentId: "excluded-document"
    }
  });
  assert.equal(explicitExcludedIndicator.ok, true);
  await flushBackgroundWork();
  assert.equal((await readCompanionState(mock, onMessage, 8)).state.status, "ready");
  assert.equal((await readCompanionState(mock, onMessage, 8)).state.score, 75);
  mock.tabMessages.length = 0;

  assert.equal((await readCompanionState(mock, onMessage, 7)).state.status, "unknown");

  const staleIndicator = await sendRuntimeMessage(onMessage, {
    type: "SET_RISK_INDICATOR",
    tabId: 7,
    indicator: {
      level: "high",
      source: "popup-page",
      url: "https://example.com/app",
      documentFingerprint: firstDocumentFingerprint,
      documentId: "document-one"
    }
  });
  assert.equal(staleIndicator.ok, false);
  assert.equal(staleIndicator.error, "Stale page context");
  assert.equal(
    mock.tabMessages.filter((entry) => entry.message.type === "COMPANION_OVERLAY_STATE").length,
    0
  );

  const currentIndicator = await sendRuntimeMessage(onMessage, {
    type: "SET_RISK_INDICATOR",
    tabId: 7,
    indicator: {
      level: "medium",
      score: 40,
      source: "popup-page",
      url: "https://example.com/app",
      documentFingerprint: activity.session.documentFingerprint,
      documentId: "document-two"
    }
  });
  assert.equal(currentIndicator.ok, true);
  await flushBackgroundWork();
  const companionMessage = mock.tabMessages.find(
    (entry) => entry.tabId === 7 && entry.message.type === "COMPANION_OVERLAY_STATE"
  );
  assert.ok(companionMessage);
  assert.equal(companionMessage.options.documentId, "document-two");
  assert.equal(Number.isInteger(companionMessage.message.revision), true);
  assert.deepEqual(
    Object.keys(companionMessage.message.state).sort(),
    ["level", "score", "source", "status", "updatedAt"]
  );
  assert.equal(companionMessage.message.state.status, "ready");
  assert.equal(companionMessage.message.state.level, "medium");
  assert.equal(companionMessage.message.state.score, 40);
  assert.equal(companionMessage.message.state.source, "page-analysis");
  assert.doesNotMatch(
    JSON.stringify(companionMessage.message),
    /https?:|url|title|label|document|fingerprint/i
  );
  const invalidOverlayRequest = await sendRuntimeMessageFromSender(
    onMessage,
    { type: "GET_COMPANION_OVERLAY_STATE", tabId: 7 },
    {
      id: "runtime-test-extension",
      tab: { ...mock.tabs.get(7) },
      frameId: 0,
      documentId: "document-two",
      documentLifecycle: "active",
      url: mock.tabs.get(7).url
    }
  );
  assert.equal(invalidOverlayRequest.ok, false);

  mock.frames.set(7, [
    {
      frameId: 0,
      parentFrameId: -1,
      documentId: "document-three",
      url: mock.tabs.get(7).url
    }
  ]);
  const indicatorFromReloadedDocument = await sendRuntimeMessage(onMessage, {
    type: "SET_RISK_INDICATOR",
    tabId: 7,
    indicator: {
      level: "high",
      source: "popup-page",
      url: "https://example.com/app",
      documentFingerprint: activity.session.documentFingerprint,
      documentId: "document-two"
    }
  });
  assert.equal(indicatorFromReloadedDocument.ok, false);
  assert.equal(indicatorFromReloadedDocument.error, "Stale page context");

  activity = await sendRuntimeMessage(onMessage, { type: "GET_NETWORK_ACTIVITY", tabId: 7 });
  assert.equal(activity.session.documentId, "document-three");
  assert.equal(activity.requests.length, 0);

  mock.tabs.get(7).url = "https://example.com/privacy?lang=ko";
  mock.frames.set(7, [
    {
      frameId: 0,
      parentFrameId: -1,
      documentId: "document-three",
      url: mock.tabs.get(7).url
    }
  ]);
  mock.channels.history.listeners[0]({
    tabId: 7,
    frameId: 0,
    documentId: "document-three",
    url: mock.tabs.get(7).url
  });
  await flushBackgroundWork();

  const currentRouteActivity = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: 7
  });
  const staleContentScan = await sendRuntimeMessageFromSender(
    onMessage,
    {
      type: "PAGE_RISK_SCAN",
      policyLike: false,
      policyConfidence: 0,
      textLength: 0
    },
    {
      id: "runtime-test-extension",
      frameId: 0,
      documentId: "document-three",
      documentLifecycle: "active",
      url: "https://example.com/privacy?lang=ko#previous-section",
      tab: { id: 7, url: "https://example.com/privacy?lang=ko#previous-section" }
    }
  );
  assert.equal(staleContentScan.skipped, true);
  const afterStaleContentScan = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: 7
  });
  assert.equal(
    afterStaleContentScan.session.documentFingerprint,
    currentRouteActivity.session.documentFingerprint
  );
  assert.equal(afterStaleContentScan.session.navigationKey, currentRouteActivity.session.navigationKey);

  const monitoredPolicyUrl = normalizePolicyUrl(mock.tabs.get(7).url);
  const stalePolicySave = await sendRuntimeMessage(onMessage, {
    type: "SAVE_MONITORED_POLICY_SNAPSHOT",
    tabId: 7,
    documentId: "document-two",
    policyUrl: monitoredPolicyUrl,
    title: "Privacy policy"
  });
  assert.equal(stalePolicySave.ok, false);
  assert.equal(stalePolicySave.code, "STALE_PAGE", JSON.stringify(stalePolicySave));
  const mismatchedPolicySave = await sendRuntimeMessage(onMessage, {
    type: "SAVE_MONITORED_POLICY_SNAPSHOT",
    tabId: 7,
    documentId: "document-three",
    policyUrl: "https://example.com/different-policy",
    title: "Privacy policy"
  });
  assert.equal(mismatchedPolicySave.ok, false);
  assert.equal(mismatchedPolicySave.code, "STALE_PAGE");

  const fetchedPolicyText =
    "Privacy Policy. We collect your name, email address, and IP address to provide the service. " +
    "We may share data with service providers. We retain personal information for 30 days. " +
    "You may request access, correction, and deletion of your personal data. Contact privacy@example.com.";
  const originalFetch = globalThis.fetch;
  const policyFetches = [];
  let navigateDuringFetch = true;
  globalThis.fetch = async (url, options) => {
    policyFetches.push({ url, options });
    if (navigateDuringFetch) {
      mock.frames.set(7, [
        {
          frameId: 0,
          parentFrameId: -1,
          documentId: "document-four",
          url: mock.tabs.get(7).url
        }
      ]);
    }
    return new Response(`<main>${fetchedPolicyText}</main>`, {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" }
    });
  };
  let savedPolicy;
  try {
    const racedPolicySave = await sendRuntimeMessage(onMessage, {
      type: "SAVE_MONITORED_POLICY_SNAPSHOT",
      tabId: 7,
      documentId: "document-three",
      policyUrl: monitoredPolicyUrl,
      title: "Privacy policy"
    });
    assert.equal(racedPolicySave.ok, false);
    assert.equal(racedPolicySave.code, "STALE_PAGE");
    assert.equal(mock.localData[POLICY_SNAPSHOTS_KEY], undefined);

    navigateDuringFetch = false;
    mock.frames.set(7, [
      {
        frameId: 0,
        parentFrameId: -1,
        documentId: "document-three",
        url: mock.tabs.get(7).url
      }
    ]);
    savedPolicy = await sendRuntimeMessage(onMessage, {
      type: "SAVE_MONITORED_POLICY_SNAPSHOT",
      tabId: 7,
      documentId: "document-three",
      policyUrl: monitoredPolicyUrl,
      title: "Privacy policy"
    });
  } finally {
    globalThis.fetch = originalFetch;
  }
  assert.equal(savedPolicy.ok, true, JSON.stringify(savedPolicy));
  assert.equal(policyFetches.length, 2);
  assert.equal(policyFetches[1].url, monitoredPolicyUrl);
  assert.equal(policyFetches[1].options.credentials, "omit");
  assert.match(savedPolicy.snapshot.normalizedText, /request access, correction, and deletion/);
  assert.equal(
    mock.localData[POLICY_SNAPSHOTS_KEY][monitoredPolicyUrl].textHash,
    savedPolicy.snapshot.textHash
  );

  beforeRequest({
    tabId: 7,
    frameId: 0,
    documentId: "failed-document",
    type: "main_frame",
    method: "GET",
    url: "https://failed-navigation.example/"
  });
  await flushBackgroundWork();
  mock.channels.navigationError.listeners[0]({
    tabId: 7,
    frameId: 0,
    documentId: "failed-document",
    url: "https://failed-navigation.example/"
  });
  await flushBackgroundWork();
  activity = await sendRuntimeMessage(onMessage, { type: "GET_NETWORK_ACTIVITY", tabId: 7 });
  assert.equal(activity.session.documentId, "document-three");
  assert.equal(activity.session.documentFingerprint, documentUrlFingerprint(mock.tabs.get(7).url));
  assert.equal(activity.requests.length, 0);

  mock.tabs.set(60, { id: 60, status: "complete", url: "https://recovery.example/app" });
  mock.frames.set(60, [
    {
      frameId: 0,
      parentFrameId: -1,
      documentId: "document-sixty",
      url: mock.tabs.get(60).url
    }
  ]);
  beforeRequest({
    tabId: 60,
    frameId: 0,
    documentId: "stale-document-sixty",
    type: "xmlhttprequest",
    method: "GET",
    url: "https://stale.example/collect"
  });
  beforeRequest({
    tabId: 60,
    frameId: 0,
    documentId: "document-sixty",
    type: "xmlhttprequest",
    method: "GET",
    url: "https://current.example/collect"
  });
  await flushBackgroundWork();
  const recoveredConcurrentActivity = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: 60
  });
  assert.equal(recoveredConcurrentActivity.session.documentId, "document-sixty");
  assert.equal(recoveredConcurrentActivity.requests.length, 1);
  assert.equal(recoveredConcurrentActivity.requests[0].host, "current.example");

  const fieldKeys = Array.from(
    { length: 24 },
    (_, index) => `field_${String(index).padStart(2, "0")}_${"x".repeat(30)}`
  );
  const formData = Object.fromEntries(fieldKeys.map((key) => [key, ["never-retain-this-value"]]));
  const query = fieldKeys.map((key) => `${key}=never-retain-this-value`).join("&");
  for (let tabId = 8; tabId <= 55; tabId += 1) {
    const url = `https://site-${tabId}.example/app`;
    mock.tabs.set(tabId, { id: tabId, status: "complete", url });
    mock.frames.set(tabId, [
      { frameId: 0, parentFrameId: -1, documentId: `document-${tabId}`, url }
    ]);
    beforeRequest({
      tabId,
      frameId: 0,
      documentId: `document-${tabId}`,
      type: "main_frame",
      method: "GET",
      url
    });
    mock.channels.committed.listeners[0]({
      tabId,
      frameId: 0,
      documentId: `document-${tabId}`,
      documentLifecycle: "active",
      url
    });
    for (let requestIndex = 0; requestIndex < 299; requestIndex += 1) {
      beforeRequest({
        tabId,
        frameId: 0,
        documentId: `document-${tabId}`,
        type: "xmlhttprequest",
        method: "POST",
        url: `https://collector.example/collect/${requestIndex}?${query}`,
        requestBody: { formData }
      });
    }
  }
  await flushBackgroundWork();

  const persistedState = backgroundModule.buildPersistedObservationState();
  const serializedState = JSON.stringify(persistedState);
  assert.equal(Object.keys(persistedState.tabs).length, 50);
  assert.ok(new TextEncoder().encode(serializedState).byteLength <= 4 * 1024 * 1024);
  assert.doesNotMatch(serializedState, /never-retain-this-value/);
  assert.doesNotMatch(serializedState, /"(?:documentFingerprint|pathFingerprint)"/);

  const onSuspend = mock.channels.suspended.listeners[0];
  assert.equal(typeof onSuspend, "function");
  onSuspend();
  await flushBackgroundWork();

  assert.ok(mock.sessionSetCalls.length >= 1);
  const initialShardedWrite = mock.sessionSetCalls.at(-1);
  const initialWriteKeys = Object.keys(initialShardedWrite);
  assert.ok(initialWriteKeys.includes("observationSessionStateV1"));
  assert.ok(initialWriteKeys.some((key) => key.startsWith("observationSessionTabV4:")));
  assert.equal(initialShardedWrite.observationSessionStateV1.layout, "per-tab-v1");
  assert.equal(Object.keys(initialShardedWrite.observationSessionStateV1.tabs).length, 50);

  const storedObservationState = JSON.stringify(mock.sessionData);
  assert.ok(new TextEncoder().encode(storedObservationState).byteLength <= 4 * 1024 * 1024);
  assert.doesNotMatch(storedObservationState, /never-retain-this-value/);
  assert.doesNotMatch(storedObservationState, /"(?:documentFingerprint|pathFingerprint)"/);

  const callsBeforeIncrementalWrite = mock.sessionSetCalls.length;
  beforeRequest({
    tabId: 55,
    frameId: 0,
    documentId: "document-55",
    type: "xmlhttprequest",
    method: "POST",
    url: "https://collector.example/incremental?token=never-retain-this-value",
    requestBody: { formData: { token: ["never-retain-this-value"] } }
  });
  await flushBackgroundWork();
  onSuspend();
  await flushBackgroundWork();

  assert.equal(mock.sessionSetCalls.length, callsBeforeIncrementalWrite + 1);
  const incrementalWrite = mock.sessionSetCalls.at(-1);
  assert.deepEqual(
    Object.keys(incrementalWrite).sort(),
    ["observationSessionStateV1", "observationSessionTabV4:55"]
  );
  assert.ok(
    new TextEncoder().encode(JSON.stringify(incrementalWrite)).byteLength < 256 * 1024,
    "one dirty tab should not rewrite the multi-megabyte observation history"
  );
  assert.doesNotMatch(JSON.stringify(incrementalWrite), /never-retain-this-value/);

  await verifyIncrementalPolicyHealth(mock, onMessage);

});

test("startup request buffering preserves another tab's main frame under noisy traffic", async () => {
  const mock = createChromeMock({ blockInitialization: true });
  mock.tabs.set(61, {
    id: 61,
    status: "complete",
    url: "https://startup.example/app"
  });
  mock.frames.set(61, [
    {
      frameId: 0,
      parentFrameId: -1,
      documentId: "startup-document",
      url: mock.tabs.get(61).url
    }
  ]);
  globalThis.chrome = mock.chrome;
  await import(`../src/background.js?startup-buffer-test=${Date.now()}`);

  const beforeRequest = mock.channels.beforeRequest.listeners[0];
  const onMessage = mock.channels.message.listeners[0];
  beforeRequest({
    tabId: 61,
    frameId: 0,
    documentId: "startup-document",
    type: "main_frame",
    method: "GET",
    url: mock.tabs.get(61).url
  });
  for (let index = 0; index < 600; index += 1) {
    beforeRequest({
      tabId: 7,
      frameId: 0,
      documentId: "document-one",
      type: "xmlhttprequest",
      method: "GET",
      url: `https://noisy.example/collect/${index}`
    });
  }

  mock.releaseInitialization();
  await flushBackgroundWork();
  await new Promise((resolve) => setTimeout(resolve, 20));

  const protectedActivity = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: 61
  });
  assert.equal(protectedActivity.session.documentId, "startup-document");
  assert.equal(protectedActivity.requests.length, 1);
  assert.equal(protectedActivity.requests[0].type, "main_frame");

  const noisyActivity = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: 7
  });
  assert.ok(noisyActivity.requests.length <= 50);

  const companionUpdate = await readCompanionState(mock, onMessage, 61);
  assert.equal(companionUpdate.enabled, false);
  assert.equal(companionUpdate.state.status, "unknown");

  mock.channels.suspended.listeners[0]();
  await flushBackgroundWork();
});

test("observation actions reject navigation during context sync without mutating the old session", async () => {
  const mock = createChromeMock();
  globalThis.chrome = mock.chrome;
  const backgroundModule = await import(`../src/background.js?action-context-test=${Date.now()}`);
  await flushBackgroundWork();

  const beforeRequest = mock.channels.beforeRequest.listeners[0];
  const onMessage = mock.channels.message.listeners[0];
  const originalUrl = mock.tabs.get(7).url;
  const originalDocumentId = "document-one";
  beforeRequest({
    tabId: 7,
    frameId: 0,
    documentId: originalDocumentId,
    type: "main_frame",
    method: "GET",
    url: originalUrl
  });
  beforeRequest({
    tabId: 7,
    frameId: 0,
    documentId: originalDocumentId,
    type: "xmlhttprequest",
    method: "POST",
    url: "https://collector.example/collect?event=baseline"
  });
  await flushBackgroundWork();

  const activity = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: 7
  });
  assert.equal(activity.requests.length, 2);
  const companionUpdate = await readCompanionState(mock, onMessage, 7);
  assert.equal(companionUpdate.enabled, false);
  assert.equal(companionUpdate.state.status, "unknown");
  const actionContext = {
    tabId: 7,
    documentId: originalDocumentId,
    documentFingerprint: activity.session.documentFingerprint
  };
  const restoreOriginalPage = () => {
    mock.tabs.get(7).url = originalUrl;
    mock.frames.set(7, [
      {
        frameId: 0,
        parentFrameId: -1,
        documentId: originalDocumentId,
        url: originalUrl
      }
    ]);
  };
  const navigateDuringFinalContextRead = (suffix) => {
    mock.setTabsGetHook(({ tabId, callCount }) => {
      if (tabId !== 7 || callCount !== 2) return;
      mock.setTabsGetHook(null);
      const url = `https://new-page.example/${suffix}`;
      mock.tabs.get(7).url = url;
      mock.frames.set(7, [
        {
          frameId: 0,
          parentFrameId: -1,
          documentId: `new-document-${suffix}`,
          url
        }
      ]);
    });
  };

  const beforeStaleSave = structuredClone(
    backgroundModule.buildPersistedObservationState().tabs["7"]
  );
  navigateDuringFinalContextRead("save");
  const staleSave = await sendRuntimeMessage(onMessage, {
    type: "SAVE_OBSERVATION_SNAPSHOT",
    ...actionContext,
    label: "Must not be saved"
  });
  assert.equal(staleSave.ok, false);
  assert.equal(staleSave.code, "STALE_PAGE");
  assert.deepEqual(
    backgroundModule.buildPersistedObservationState().tabs["7"],
    beforeStaleSave
  );

  restoreOriginalPage();
  const beforeStaleClear = structuredClone(
    backgroundModule.buildPersistedObservationState().tabs["7"]
  );
  navigateDuringFinalContextRead("clear");
  const staleClear = await sendRuntimeMessage(onMessage, {
    type: "CLEAR_NETWORK_ACTIVITY",
    ...actionContext
  });
  assert.equal(staleClear.ok, false);
  assert.equal(staleClear.code, "STALE_PAGE");
  assert.deepEqual(
    backgroundModule.buildPersistedObservationState().tabs["7"],
    beforeStaleClear
  );

  restoreOriginalPage();
  mock.setTabsGetHook(null);
  const saved = await sendRuntimeMessage(onMessage, {
    type: "SAVE_OBSERVATION_SNAPSHOT",
    ...actionContext,
    label: "Current document"
  });
  assert.equal(saved.ok, true);
  assert.equal(saved.snapshots.length, 1);

  const cleared = await sendRuntimeMessage(onMessage, {
    type: "CLEAR_NETWORK_ACTIVITY",
    ...actionContext
  });
  assert.equal(cleared.ok, true);
  const clearedActivity = await sendRuntimeMessage(onMessage, {
    type: "GET_NETWORK_ACTIVITY",
    tabId: 7
  });
  assert.equal(clearedActivity.requests.length, 0);
  assert.equal(clearedActivity.snapshots.length, 0);
});
