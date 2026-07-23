import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const overlaySource = await readFile(
  new URL("../src/companionOverlay.js", import.meta.url),
  "utf8"
);

class FakeStyle {
  constructor() {
    this.values = new Map();
    this.priorities = new Map();
  }

  setProperty(name, value, priority = "") {
    this.values.set(name, String(value));
    this.priorities.set(name, String(priority));
  }

  getPropertyValue(name) {
    return this.values.get(name) || "";
  }

  getPropertyPriority(name) {
    return this.priorities.get(name) || "";
  }
}

class FakeShadowRoot {
  constructor(host, mode) {
    this.host = host;
    this.mode = mode;
    this.children = [];
  }

  append(...nodes) {
    for (const node of nodes) {
      node.parentNode = this;
      node.rootNode = this;
      this.children.push(node);
    }
  }
}

class FakeElement {
  constructor(tagName) {
    this.tagName = String(tagName).toUpperCase();
    this.attributes = new Map();
    this.children = [];
    this.className = "";
    this.parentNode = null;
    this.rootNode = null;
    this.style = new FakeStyle();
    this.textContent = "";
    this.connectedRoot = false;
    this.closedShadow = null;
    this.shadowRoot = null;
  }

  get isConnected() {
    if (this.connectedRoot) return true;
    let current = this.parentNode;
    while (current) {
      if (current.connectedRoot) return true;
      current = current.parentNode || current.host?.parentNode || null;
    }
    return false;
  }

  appendChild(node) {
    node.parentNode = this;
    node.rootNode = this.rootNode;
    this.children.push(node);
    return node;
  }

  attachShadow({ mode }) {
    const root = new FakeShadowRoot(this, mode);
    this.closedShadow = root;
    this.shadowRoot = mode === "open" ? root : null;
    return root;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  getRootNode() {
    return this.rootNode || this;
  }

  remove() {
    const siblings = this.parentNode?.children;
    if (Array.isArray(siblings)) {
      const index = siblings.indexOf(this);
      if (index >= 0) siblings.splice(index, 1);
    }
    this.parentNode = null;
  }
}

class FakeDocument {
  constructor() {
    this.documentElement = new FakeElement("html");
    this.documentElement.connectedRoot = true;
    this.documentElement.rootNode = this;
  }

  createElement(tagName) {
    return new FakeElement(tagName);
  }
}

function readyState(score, source = "page-analysis") {
  return {
    status: "ready",
    level: score >= 67 ? "high" : score >= 34 ? "medium" : "low",
    score,
    source,
    updatedAt: 1_700_000_000_000
  };
}

function executeOverlay({
  initialResponse = {
    ok: true,
    enabled: false,
    revision: 1,
    state: { status: "unknown", level: "unknown", score: null, source: "none" }
  },
  deferInitial = false,
  topFrame = true
} = {}) {
  const withGeneration = (message) =>
    message && Number.isFinite(message.revision) && message.generation === undefined
      ? { ...message, generation: 1 }
      : message;
  const document = new FakeDocument();
  const listeners = [];
  const windowListeners = new Map();
  const requests = [];
  const deferredCallbacks = [];
  let runtimeResponse = initialResponse;
  const runtime = {
    id: "test-extension",
    lastError: null,
    onMessage: {
      addListener(listener) {
        listeners.push(listener);
      }
    },
    sendMessage(message, callback) {
      requests.push(message);
      if (deferInitial) deferredCallbacks.push(callback);
      else callback(withGeneration(runtimeResponse));
    }
  };
  const chrome = {
    i18n: {
      getMessage(key) {
        const messages = {
          companionUnknown: "Unknown does not mean safe.",
          companionAnalyzing: "Analyzing the current page.",
          companionPaused: "Always-on observation is paused.",
          companionExcluded: "The current site is excluded from observation.",
          companionUnsupported: "This page type cannot be analyzed.",
          companionUnavailable: "The companion state is unavailable.",
          companionLowRisk: "Low risk",
          companionCautionRisk: "Caution risk",
          companionHighRisk: "High risk"
        };
        return messages[key] || "";
      }
    },
    runtime
  };
  const sandbox = {
    addEventListener(type, listener) {
      const registered = windowListeners.get(type) || [];
      registered.push(listener);
      windowListeners.set(type, registered);
    },
    chrome,
    document,
    WeakSet,
    console
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.top = topFrame ? sandbox : {};
  vm.runInNewContext(overlaySource, sandbox, { filename: "companionOverlay.js" });

  return {
    chrome,
    document,
    requests,
    sandbox,
    dispatch(message, sender = { id: runtime.id }) {
      let response;
      for (const listener of listeners) {
        listener(withGeneration(message), sender, (value) => {
          response = value;
        });
      }
      return response;
    },
    resolveInitial(response = initialResponse) {
      const callback = deferredCallbacks[0];
      assert.equal(typeof callback, "function");
      deferredCallbacks[0] = null;
      callback(withGeneration(response));
    },
    resolveDeferredRequest(index, response = initialResponse) {
      const callback = deferredCallbacks[index];
      assert.equal(typeof callback, "function");
      deferredCallbacks[index] = null;
      callback(withGeneration(response));
    },
    setRuntimeResponse(response) {
      runtimeResponse = response;
    },
    dispatchWindow(type, event = {}) {
      for (const listener of windowListeners.get(type) || []) listener(event);
    }
  };
}

function overlayHost(harness) {
  return harness.document.documentElement.children[0] || null;
}

test("is a top-frame, display-only classic content script with a closed shadow root", () => {
  assert.doesNotMatch(overlaySource, /^\s*(?:import|export)\s/m);
  assert.match(overlaySource, /window\.top !== window/);
  assert.match(overlaySource, /attachShadow\(\{ mode: "closed" \}\)/);
  assert.match(overlaySource, /pointerEvents: "none"/);
  assert.doesNotMatch(overlaySource, /addEventListener\(["']click/);
  assert.doesNotMatch(overlaySource, /createElement\(["']button/);
  assert.doesNotMatch(overlaySource, /data-(?:status|score|color|source)/i);

  const frameHarness = executeOverlay({ topFrame: false });
  assert.equal(frameHarness.sandbox.__unveilyCompanionOverlay, undefined);
  assert.equal(frameHarness.requests.length, 0);
  assert.equal(overlayHost(frameHarness), null);
});

test("mounts one fixed 56px bottom-left host without exposing state in light DOM", () => {
  const harness = executeOverlay();
  assert.equal(harness.requests.length, 1);
  assert.equal(harness.requests[0]?.type, "GET_COMPANION_OVERLAY_STATE");
  assert.equal(overlayHost(harness), null, "the companion is opt-in");

  const response = harness.dispatch({
    type: "COMPANION_OVERLAY_VISIBILITY",
    enabled: true,
    revision: 2,
    state: { status: "unknown", level: "unknown", score: null, source: "none" }
  });
  assert.equal(response?.ok, true);
  const host = overlayHost(harness);
  assert.ok(host);
  assert.equal(harness.document.documentElement.children.length, 1);
  assert.equal(host.shadowRoot, null);
  assert.equal(host.closedShadow?.mode, "closed");
  assert.equal(host.children.length, 0);
  assert.deepEqual(Array.from(host.attributes), []);
  assert.equal(host.style.getPropertyValue("position"), "fixed");
  assert.equal(host.style.getPropertyValue("left"), "16px");
  assert.equal(host.style.getPropertyValue("bottom"), "16px");
  assert.equal(host.style.getPropertyValue("width"), "56px");
  assert.equal(host.style.getPropertyValue("height"), "56px");
  assert.equal(host.style.getPropertyValue("pointer-events"), "none");
  assert.equal(host.style.getPropertyPriority("pointer-events"), "important");
  assert.equal(harness.sandbox.__unveilyCompanionOverlayOwnedHosts.has(host), true);

  const snapshot = harness.sandbox.__unveilyCompanionOverlay.snapshot();
  assert.equal(snapshot.enabled, true);
  assert.equal(snapshot.mounted, true);
  assert.equal(snapshot.status, "unknown");
  assert.equal(snapshot.score, null);
  assert.equal(snapshot.text, "?");
  assert.equal(snapshot.role, "status");
  assert.equal(snapshot.ariaValueNow, null);
  assert.match(snapshot.ariaValueText, /safe/i);
});

test("renders continuous risk colors, numeric scores, and accessible meter text", () => {
  const harness = executeOverlay({
    initialResponse: { ok: true, enabled: true, revision: 1, state: readyState(0) }
  });
  const expectedColors = new Map([
    [0, "#039855"],
    [25, "#70802C"],
    [50, "#DC6803"],
    [75, "#DB4B12"],
    [100, "#D92D20"]
  ]);
  let revision = 1;
  for (const [score, color] of expectedColors) {
    revision += 1;
    harness.dispatch({
      type: "COMPANION_OVERLAY_STATE",
      revision,
      state: readyState(score, score === 50 ? "cookie-analysis" : "page-analysis")
    });
    const snapshot = harness.sandbox.__unveilyCompanionOverlay.snapshot();
    assert.equal(snapshot.status, "ready");
    assert.equal(snapshot.score, score);
    assert.equal(snapshot.color, color);
    assert.equal(snapshot.text, String(score));
    assert.equal(snapshot.role, "meter");
    assert.equal(snapshot.ariaValueNow, String(score));
    assert.match(snapshot.ariaValueText, new RegExp(`${score}/100`));
    assert.equal(snapshot.source, score === 50 ? "cookie-analysis" : "page-analysis");
  }

  const indicator = overlayHost(harness).closedShadow.children[1];
  assert.equal(indicator.getAttribute("role"), "meter");
  assert.equal(indicator.getAttribute("aria-valuemin"), "0");
  assert.equal(indicator.getAttribute("aria-valuemax"), "100");
  assert.equal(indicator.getAttribute("aria-valuenow"), "100");
  assert.match(indicator.getAttribute("aria-valuetext"), /100\/100/);
});

test("shows analyzing and unavailable states without pretending they are numeric risk", () => {
  const harness = executeOverlay({
    initialResponse: {
      ok: true,
      enabled: true,
      revision: 1,
      state: { status: "analyzing", level: "analyzing", score: null, source: "none" }
    }
  });
  let snapshot = harness.sandbox.__unveilyCompanionOverlay.snapshot();
  assert.equal(snapshot.status, "analyzing");
  assert.equal(snapshot.text, "…");
  assert.equal(snapshot.score, null);
  assert.equal(snapshot.role, "status");
  assert.equal(snapshot.color, "#667085");
  assert.match(snapshot.ariaValueText, /Analyzing/i);

  harness.dispatch({
    type: "COMPANION_OVERLAY_STATE",
    revision: 2,
    state: { status: "unavailable", level: "unknown", score: null, source: "none" }
  });
  snapshot = harness.sandbox.__unveilyCompanionOverlay.snapshot();
  assert.equal(snapshot.status, "unavailable");
  assert.equal(snapshot.text, "!");
  assert.equal(snapshot.ariaValueNow, null);
  const indicator = overlayHost(harness).closedShadow.children[1];
  assert.equal(indicator.getAttribute("aria-valuenow"), null);
  assert.equal(indicator.getAttribute("role"), "status");
});

test("uses worker generations and revisions so stale responses cannot roll state back", () => {
  const harness = executeOverlay({ deferInitial: true });
  harness.dispatch({
    type: "COMPANION_OVERLAY_VISIBILITY",
    enabled: true,
    revision: 8,
    state: readyState(75)
  });
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().score, 75);

  harness.resolveInitial({ ok: true, enabled: true, revision: 4, state: readyState(25) });
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().score, 75);
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().revision, 8);

  harness.dispatch({ type: "COMPANION_OVERLAY_STATE", revision: 7, state: readyState(100) });
  harness.dispatch({ type: "COMPANION_OVERLAY_STATE", revision: 8, state: readyState(100) });
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().score, 75);

  harness.dispatch({ type: "COMPANION_OVERLAY_STATE", revision: 9, state: readyState(100) });
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().score, 100);
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().revision, 9);

  harness.dispatch({
    type: "COMPANION_OVERLAY_STATE",
    generation: 2,
    revision: 1,
    state: readyState(25)
  });
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().score, 25);
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().generation, 2);
  harness.dispatch({
    type: "COMPANION_OVERLAY_STATE",
    generation: 1,
    revision: 10,
    state: readyState(75)
  });
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().score, 25);
});

test("unmounts on disable, ignores state while disabled, and identifies only owned mutations", () => {
  const harness = executeOverlay({
    initialResponse: { ok: true, enabled: true, revision: 1, state: readyState(25) }
  });
  const firstHost = overlayHost(harness);
  const internalIndicator = firstHost.closedShadow.children[1];
  const api = harness.sandbox.__unveilyCompanionOverlay;
  assert.equal(
    api.ownsMutationRecord({
      target: harness.document.documentElement,
      addedNodes: [firstHost],
      removedNodes: []
    }),
    true
  );
  assert.equal(api.ownsMutationRecord({ target: internalIndicator, addedNodes: [], removedNodes: [] }), true);
  assert.equal(
    api.ownsMutationRecord({
      target: harness.document.documentElement,
      addedNodes: [firstHost, new FakeElement("p")],
      removedNodes: []
    }),
    false
  );

  harness.dispatch({
    type: "COMPANION_OVERLAY_VISIBILITY",
    enabled: false,
    revision: 2,
    state: readyState(25)
  });
  assert.equal(overlayHost(harness), null);
  assert.equal(api.snapshot().enabled, false);
  assert.equal(api.snapshot().mounted, false);

  harness.dispatch({ type: "COMPANION_OVERLAY_STATE", revision: 3, state: readyState(100) });
  assert.equal(overlayHost(harness), null, "a state update cannot enable the companion");
  assert.equal(api.snapshot().score, null);

  harness.dispatch({
    type: "COMPANION_OVERLAY_VISIBILITY",
    enabled: true,
    revision: 4,
    state: readyState(50)
  });
  assert.equal(harness.document.documentElement.children.length, 1);
  assert.equal(api.snapshot().score, 50);
  assert.notEqual(overlayHost(harness), firstHost);
});

test("resynchronizes visibility when a state push overtakes the initial response", () => {
  const harness = executeOverlay({ deferInitial: true });
  assert.equal(harness.requests.length, 1);

  harness.dispatch({
    type: "COMPANION_OVERLAY_STATE",
    revision: 2,
    state: readyState(25)
  });
  assert.equal(overlayHost(harness), null, "a state-only push cannot enable the companion");
  assert.equal(harness.requests.length, 2, "the state race must trigger an authoritative retry");

  harness.resolveDeferredRequest(1, {
    ok: true,
    enabled: true,
    revision: 2,
    state: readyState(25)
  });
  assert.ok(overlayHost(harness), "an equal-revision authoritative response enables the companion");
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().score, 25);

  harness.resolveDeferredRequest(0, {
    ok: true,
    enabled: false,
    revision: 1,
    state: readyState(100)
  });
  assert.ok(overlayHost(harness), "the late initial callback cannot undo the retry response");
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().score, 25);
});

test("rejects untrusted senders and malformed revisions", () => {
  const harness = executeOverlay();
  harness.dispatch(
    {
      type: "COMPANION_OVERLAY_VISIBILITY",
      enabled: true,
      revision: 2,
      state: readyState(25)
    },
    { id: "different-extension" }
  );
  assert.equal(overlayHost(harness), null);
  harness.dispatch({
    type: "COMPANION_OVERLAY_VISIBILITY",
    enabled: true,
    revision: 1.5,
    state: readyState(25)
  });
  assert.equal(overlayHost(harness), null);
});

test("force-disables a stale overlay when worker generation storage fails", () => {
  const harness = executeOverlay({
    initialResponse: { ok: true, enabled: true, generation: 4, revision: 8, state: readyState(75) }
  });
  assert.ok(overlayHost(harness));
  harness.dispatch({
    type: "COMPANION_OVERLAY_VISIBILITY",
    enabled: false,
    forceDisable: true,
    state: { status: "unknown", score: null }
  });
  assert.equal(overlayHost(harness), null);
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().protocolFailedClosed, true);
  harness.dispatch({
    type: "COMPANION_OVERLAY_VISIBILITY",
    enabled: true,
    generation: 5,
    revision: 1,
    state: readyState(10)
  });
  assert.equal(overlayHost(harness), null);
});

test("fails closed and resynchronizes when a document returns from BFCache", () => {
  const harness = executeOverlay({
    initialResponse: {
      ok: true,
      enabled: true,
      generation: 3,
      revision: 8,
      state: readyState(75)
    }
  });
  assert.ok(overlayHost(harness));

  harness.dispatchWindow("pagehide", { isTrusted: true, persisted: true });
  assert.equal(overlayHost(harness), null);
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().enabled, false);

  harness.setRuntimeResponse({
    ok: true,
    enabled: false,
    generation: 3,
    revision: 8,
    state: { status: "unknown", level: "unknown", score: null, source: "none" }
  });
  harness.dispatchWindow("pageshow", { isTrusted: true, persisted: true });
  assert.equal(harness.requests.length, 2);
  assert.equal(overlayHost(harness), null, "an OFF preference stays absent after restore");

  harness.setRuntimeResponse({
    ok: true,
    enabled: true,
    generation: 3,
    revision: 8,
    state: readyState(25)
  });
  harness.dispatchWindow("pagehide", { isTrusted: true, persisted: true });
  harness.dispatchWindow("pageshow", { isTrusted: true, persisted: true });
  assert.equal(harness.requests.length, 3);
  assert.equal(harness.sandbox.__unveilyCompanionOverlay.snapshot().score, 25);
  assert.ok(overlayHost(harness), "an unchanged ON preference remounts after restore");

  harness.setRuntimeResponse({
    ok: true,
    enabled: true,
    generation: 3,
    revision: 7,
    state: readyState(100)
  });
  harness.dispatchWindow("pagehide", { isTrusted: true, persisted: true });
  harness.dispatchWindow("pageshow", { isTrusted: true, persisted: true });
  assert.equal(overlayHost(harness), null, "an older response cannot revive a stale overlay");

  const requestCount = harness.requests.length;
  for (let index = 0; index < 100; index += 1) {
    harness.dispatchWindow("pageshow", { isTrusted: false, persisted: true });
    harness.dispatchWindow("pagehide", { isTrusted: false, persisted: true });
  }
  assert.equal(harness.requests.length, requestCount, "synthetic page events cannot trigger runtime work");
  assert.equal(overlayHost(harness), null);
});
