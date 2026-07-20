import assert from "node:assert/strict";
import test from "node:test";

import {
  COMPANION_OVERLAY_GENERATION_KEY,
  createCompanionOverlayRuntime,
  getCurrentCompanionTopDocument,
  reserveCompanionOverlayGeneration
} from "../src/companionOverlayRuntime.js";

function createHarness() {
  let enabled = false;
  const sent = [];
  const tabs = [{ id: 1 }, { id: 2 }, { id: -1 }, {}];
  const contexts = new Map([
    [1, { documentId: "document-one" }],
    [2, { documentId: "document-two" }]
  ]);
  const states = new Map([
    [1, { status: "ready", score: 25 }],
    [2, { status: "ready", score: 75 }]
  ]);
  const chrome = {
    runtime: { lastError: null },
    tabs: {
      async query() {
        return tabs;
      },
      sendMessage(tabId, message, options, callback) {
        sent.push({ tabId, message: structuredClone(message), options: { ...options } });
        callback?.();
      }
    }
  };
  const runtime = createCompanionOverlayRuntime({
    chrome,
    getCurrentTopDocument: async (tabId) => contexts.get(tabId) || null,
    getState: async (tabId) => states.get(tabId) || { status: "unknown", score: null },
    createUnknownState: () => ({ status: "unknown", score: null }),
    isEnabled: () => enabled,
    generationReady: Promise.resolve(7)
  });
  return {
    chrome,
    contexts,
    runtime,
    sent,
    states,
    setEnabled(value) {
      enabled = value;
    }
  };
}

test("broadcasts display-only visibility and refreshes exact top documents", async () => {
  const harness = createHarness();
  const initial = await harness.runtime.snapshot(1);
  assert.deepEqual(initial, {
    generation: 7,
    revision: 0,
    state: { status: "ready", score: 25 }
  });

  await harness.runtime.broadcast();
  assert.equal(harness.sent.length, 2);
  assert.deepEqual(
    harness.sent.map(({ tabId, message, options }) => ({
      tabId,
      type: message.type,
      enabled: message.enabled,
      status: message.state.status,
      documentId: options.documentId
    })),
    [
      {
        tabId: 1,
        type: "COMPANION_OVERLAY_VISIBILITY",
        enabled: false,
        status: "unknown",
        documentId: "document-one"
      },
      {
        tabId: 2,
        type: "COMPANION_OVERLAY_VISIBILITY",
        enabled: false,
        status: "unknown",
        documentId: "document-two"
      }
    ]
  );

  harness.sent.length = 0;
  await harness.runtime.refresh(1);
  assert.equal(harness.sent.length, 0, "disabled overlays ignore ordinary state refreshes");
  harness.setEnabled(true);
  await harness.runtime.refresh(1);
  assert.equal(harness.sent.length, 1);
  assert.equal(harness.sent[0].message.type, "COMPANION_OVERLAY_STATE");
  assert.equal(harness.sent[0].message.state.score, 25);
  assert.equal(harness.sent[0].options.documentId, "document-one");
  assert.equal(harness.sent[0].message.generation, 7);
  assert.ok(harness.sent[0].message.revision > 0);

  harness.runtime.forget(1);
  assert.equal((await harness.runtime.snapshot(1)).revision, 0);
});

test("drops stale deliveries and handles missing or closed documents", async () => {
  let resolveFirstContext;
  let contextCalls = 0;
  const sent = [];
  const chrome = {
    runtime: { lastError: null },
    tabs: {
      async query() {
        throw new Error("tabs unavailable");
      },
      sendMessage(tabId, message, options, callback) {
        sent.push({ tabId, message, options });
        callback?.();
      }
    }
  };
  const runtime = createCompanionOverlayRuntime({
    chrome,
    getCurrentTopDocument: async () => {
      contextCalls += 1;
      if (contextCalls === 1) {
        return new Promise((resolve) => {
          resolveFirstContext = resolve;
        });
      }
      return { documentId: "new-document" };
    },
    getState: async () => ({ status: "ready", score: 90 }),
    createUnknownState: () => ({ status: "unknown", score: null }),
    isEnabled: () => true,
    generationReady: Promise.resolve(8)
  });

  const stale = runtime.refresh(4);
  const current = runtime.refresh(4);
  await current;
  resolveFirstContext({ documentId: "old-document" });
  await stale;
  assert.equal(sent.length, 1);
  assert.equal(sent[0].options.documentId, "new-document");

  await runtime.broadcast();
  await runtime.refresh(-1);
  assert.equal(sent.length, 1);

  chrome.tabs.sendMessage = () => {
    throw new Error("document closed");
  };
  await runtime.refresh(5);
  assert.equal(sent.length, 1);
});

test("snapshot retries when a newer push wins an in-flight state read", async () => {
  let resolveInitialState;
  let stateCalls = 0;
  const sent = [];
  const runtime = createCompanionOverlayRuntime({
    chrome: {
      runtime: { lastError: null },
      tabs: {
        async query() {
          return [];
        },
        sendMessage(tabId, message, options, callback) {
          sent.push({ tabId, message, options });
          callback?.();
        }
      }
    },
    getCurrentTopDocument: async () => ({ documentId: "current-document" }),
    getState: async () => {
      stateCalls += 1;
      if (stateCalls === 1) {
        return new Promise((resolve) => {
          resolveInitialState = resolve;
        });
      }
      return { status: "ready", score: 80 };
    },
    createUnknownState: () => ({ status: "unknown", score: null }),
    isEnabled: () => true,
    generationReady: Promise.resolve(9)
  });

  const snapshotPromise = runtime.snapshot(7);
  await Promise.resolve();
  await runtime.refresh(7);
  resolveInitialState({ status: "ready", score: 10 });
  const snapshot = await snapshotPromise;
  assert.equal(snapshot.state.score, 80);
  assert.ok(snapshot.revision > 0);
  assert.equal(snapshot.generation, 9);
  assert.equal(sent[0].message.state.score, 80);
});

test("reserves monotonic worker generations and force-disables when reservation fails", async () => {
  const data = { [COMPANION_OVERLAY_GENERATION_KEY]: 4 };
  const storage = {
    async get(key) {
      return { [key]: data[key] };
    },
    async set(values) {
      Object.assign(data, values);
    }
  };
  assert.equal(await reserveCompanionOverlayGeneration(storage), 5);
  assert.equal(data[COMPANION_OVERLAY_GENERATION_KEY], 5);
  assert.equal(await reserveCompanionOverlayGeneration(storage), 6);
  assert.equal(data[COMPANION_OVERLAY_GENERATION_KEY], 6);

  const sent = [];
  const runtime = createCompanionOverlayRuntime({
    chrome: {
      runtime: { lastError: null },
      tabs: {
        async query() {
          return [{ id: 2 }];
        },
        sendMessage(tabId, message, options, callback) {
          sent.push({ tabId, message, options });
          callback?.();
        }
      }
    },
    getCurrentTopDocument: async () => ({ documentId: "document-two" }),
    getState: async () => ({ status: "ready", score: 10 }),
    createUnknownState: () => ({ status: "unknown", score: null }),
    isEnabled: () => true,
    generationReady: Promise.resolve(null)
  });
  await runtime.broadcast();
  assert.deepEqual(sent[0], {
    tabId: 2,
    message: {
      type: "COMPANION_OVERLAY_VISIBILITY",
      enabled: false,
      forceDisable: true,
      state: { status: "unknown", score: null }
    },
    options: { documentId: "document-two" }
  });
  await assert.rejects(runtime.snapshot(2), /generation unavailable/);
});

test("resolves only a stable active top document without enumerating subframes", async () => {
  let tabCalls = 0;
  let frameCalls = 0;
  const chrome = {
    tabs: {
      async get() {
        tabCalls += 1;
        return { id: 4, url: "https://example.com/privacy?version=one" };
      }
    },
    webNavigation: {
      async getFrame(details) {
        frameCalls += 1;
        assert.deepEqual(details, { tabId: 4, frameId: 0 });
        return {
          frameId: 0,
          documentId: "stable-document",
          documentLifecycle: "active",
          url: "https://example.com/privacy?version=one"
        };
      }
    }
  };
  assert.deepEqual(await getCurrentCompanionTopDocument(chrome, 4), {
    tab: { id: 4, url: "https://example.com/privacy?version=one" },
    documentId: "stable-document"
  });
  assert.equal(tabCalls, 2);
  assert.equal(frameCalls, 2);
  assert.equal("getAllFrames" in chrome.webNavigation, false);

  chrome.tabs.get = async () => {
    tabCalls += 1;
    return {
      id: 4,
      url:
        tabCalls % 2 === 1
          ? "https://example.com/privacy?version=one"
          : "https://example.com/privacy?version=two"
    };
  };
  assert.equal(await getCurrentCompanionTopDocument(chrome, 4), null);
  chrome.tabs.get = async () => {
    throw new Error("tab closed");
  };
  assert.equal(await getCurrentCompanionTopDocument(chrome, 4), null);
});

test("bounds startup visibility delivery concurrency", async () => {
  let active = 0;
  let maximumActive = 0;
  let releases = [];
  const sent = [];
  const runtime = createCompanionOverlayRuntime({
    chrome: {
      runtime: { lastError: null },
      tabs: {
        async query() {
          return Array.from({ length: 12 }, (_, index) => ({ id: index + 1 }));
        },
        sendMessage(tabId, message, options, callback) {
          sent.push({ tabId, message, options });
          callback?.();
        }
      }
    },
    getCurrentTopDocument: async (tabId) => {
      active += 1;
      maximumActive = Math.max(maximumActive, active);
      await new Promise((resolve) => releases.push(resolve));
      active -= 1;
      return { documentId: `document-${tabId}` };
    },
    getState: async () => ({ status: "unknown", score: null }),
    createUnknownState: () => ({ status: "unknown", score: null }),
    isEnabled: () => true,
    generationReady: Promise.resolve(12),
    maxBroadcastConcurrency: 3
  });
  const broadcast = runtime.broadcast();
  for (let batch = 0; batch < 4; batch += 1) {
    for (let attempt = 0; attempt < 10 && releases.length < 3; attempt += 1) {
      await new Promise((resolve) => setImmediate(resolve));
    }
    const current = releases;
    releases = [];
    assert.equal(current.length, 3);
    current.forEach((release) => release());
  }
  await broadcast;
  assert.equal(maximumActive, 3);
  assert.equal(sent.length, 12);
});
