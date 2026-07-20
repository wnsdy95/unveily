import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const contentSource = await readFile(new URL("../src/content.js", import.meta.url), "utf8");

class MockElement {
  constructor(tagName, attributes = {}) {
    this.tagName = tagName.toUpperCase();
    this.nodeType = 1;
    this.childNodes = [];
    this.parentNode = null;
    this.parentElement = null;
    this.hidden = false;
    this.id = String(attributes.id || "");
    this.className = String(attributes.class || "");
    this.labels = [];
    this.type = String(attributes.type || "");
    this.required = false;
    this.checked = false;
    this.isConnected = true;
    this.dataset = {};
    this.isContentEditable = attributes.isContentEditable === true;
    this.attributes = new Map(Object.entries(attributes));
    this._style = {};
  }

  appendChild(node) {
    node.parentNode = this;
    node.parentElement = this;
    this.childNodes.push(node);
    return node;
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  attachShadow() {
    const button = new MockElement("button");
    return {
      innerHTML: "",
      querySelector(selector) {
        return selector === "button" ? button : null;
      }
    };
  }

  remove() {
    if (!this.parentNode) return;
    const index = this.parentNode.childNodes.indexOf(this);
    if (index >= 0) this.parentNode.childNodes.splice(index, 1);
    this.parentNode = null;
    this.parentElement = null;
    this.isConnected = false;
  }

  getRootNode() {
    let current = this;
    while (current?.parentNode) current = current.parentNode;
    return current;
  }

  matches(selector) {
    if (selector === "main, article, section, [role='main'], body") {
      return ["BODY", "MAIN", "ARTICLE", "SECTION"].includes(this.tagName);
    }
    if (selector === "input, textarea, select") {
      return ["INPUT", "TEXTAREA", "SELECT"].includes(this.tagName);
    }
    if (selector.includes("p, li, dt, dd, blockquote")) {
      return ["P", "DIV", "MAIN", "ARTICLE", "SECTION"].includes(this.tagName);
    }
    return false;
  }
}

class MockText {
  constructor(value) {
    this.nodeType = 3;
    this.nodeValue = value;
    this.childNodes = [];
    this.parentNode = null;
    this.parentElement = null;
  }
}

class MockDocument {
  constructor(documentElement, body) {
    this.documentElement = documentElement;
    this.body = body;
    this.title = "Controlled privacy page";
    this.designMode = "off";
    this.visibilityState = "visible";
    this.readyState = "complete";
    this.prerendering = false;
    this.eventListeners = new Map();
  }

  createTreeWalker(root) {
    let current = root;
    return {
      nextNode() {
        if (current?.childNodes?.length) {
          current = current.childNodes[0];
          return current;
        }
        while (current && current !== root) {
          const parent = current.parentNode;
          const index = parent.childNodes.indexOf(current);
          if (index + 1 < parent.childNodes.length) {
            current = parent.childNodes[index + 1];
            return current;
          }
          current = parent;
        }
        current = null;
        return null;
      }
    };
  }

  getElementById() {
    return null;
  }

  createElement(tagName) {
    return new MockElement(tagName);
  }

  addEventListener(type, listener) {
    const listeners = this.eventListeners.get(type) || new Set();
    listeners.add(listener);
    this.eventListeners.set(type, listeners);
  }

  removeEventListener(type, listener) {
    this.eventListeners.get(type)?.delete(listener);
  }

  dispatch(type, event = {}) {
    for (const listener of this.eventListeners.get(type) || []) listener(event);
  }
}

function createContext() {
  const budget = {
    takeNode: () => true,
    takeStyle: () => true,
    check: () => true,
    get exhausted() {
      return false;
    }
  };
  return {
    budget,
    visibilityCache: new WeakMap(),
    closestCache: new WeakMap(),
    textCache: new WeakMap(),
    userInputCache: new WeakMap(),
    userInputStyleCache: new WeakMap(),
    headingHintCount: null
  };
}

function loadContentRuntime(
  document,
  { automaticAllowed = false, deferObservationSettings = false } = {}
) {
  let messageListener = null;
  let currentAutomaticAllowed = automaticAllowed;
  const messages = [];
  const mutationObservers = [];
  const timers = new Map();
  const pendingObservationSettingsCallbacks = [];
  const windowEventListeners = new Map();
  let nextTimerId = 1;
  const emptyStorage = { length: 0, key: () => null };
  const sandbox = {
    Document: MockDocument,
    Element: MockElement,
    Intl,
    Map,
    NodeFilter: { SHOW_ALL: 0xffffffff },
    Set,
    URL,
    WeakMap,
    chrome: {
      runtime: {
        lastError: null,
        onMessage: {
          addListener(listener) {
            messageListener = listener;
          }
        },
        sendMessage(message, callback) {
          messages.push(message);
          if (message?.type === "GET_OBSERVATION_SETTINGS") {
            if (deferObservationSettings) {
              pendingObservationSettingsCallbacks.push(callback);
            } else {
              callback?.({
                ok: true,
                settings: {
                  enabled: currentAutomaticAllowed,
                  allowed: currentAutomaticAllowed
                }
              });
            }
          } else if (message?.type === "PAGE_RISK_SCAN") {
            callback?.({ ok: true, indicator: { level: "unknown" } });
          } else {
            callback?.(null);
          }
        }
      }
    },
    document,
    globalThis: null,
    location: {
      href: "https://content.example/privacy",
      hostname: "content.example",
      origin: "https://content.example",
      pathname: "/privacy"
    },
    navigator: { language: "en", languages: ["en"] },
    MutationObserver: class {
      constructor(callback) {
        this.callback = callback;
        this.options = null;
        this.active = false;
        mutationObservers.push(this);
      }

      observe(_target, options) {
        this.options = options;
        this.active = true;
      }

      disconnect() {
        this.active = false;
      }
    },
    window: {
      getComputedStyle(element) {
        return {
          display: "block",
          visibility: "visible",
          opacity: "1",
          contentVisibility: "visible",
          ...element?._style
        };
      },
      localStorage: emptyStorage,
      sessionStorage: emptyStorage,
      addEventListener(type, listener) {
        const listeners = windowEventListeners.get(type) || new Set();
        listeners.add(listener);
        windowEventListeners.set(type, listeners);
      },
      removeEventListener(type, listener) {
        windowEventListeners.get(type)?.delete(listener);
      },
      clearTimeout(timerId) {
        timers.delete(timerId);
      },
      setTimeout(callback, delay) {
        const timerId = nextTimerId;
        nextTimerId += 1;
        timers.set(timerId, { callback, delay });
        return timerId;
      }
    }
  };
  sandbox.globalThis = sandbox;
  sandbox.__unveilyDomWorkLimits = {
    createContext,
    collectMutationRoots: () => []
  };
  vm.runInNewContext(contentSource, sandbox, { filename: "content-text-privacy-runtime.js" });
  assert.equal(typeof messageListener, "function");
  return {
    messages,
    mutationObservers,
    timers,
    dispatchMessage(message) {
      let response = null;
      const asynchronous = messageListener(message, {}, (value) => {
        response = value;
      });
      return { asynchronous, response };
    },
    dispatchWindow(type, event = {}) {
      for (const listener of windowEventListeners.get(type) || []) listener(event);
    },
    resolveObservationSettings(allowed = currentAutomaticAllowed) {
      const callback = pendingObservationSettingsCallbacks.shift();
      assert.equal(typeof callback, "function");
      callback({ ok: true, settings: { enabled: allowed, allowed } });
    },
    setAutomaticAllowed(allowed) {
      currentAutomaticAllowed = allowed === true;
    },
    readPage() {
    let response = null;
    const asynchronous = messageListener({ type: "GET_PAGE_TEXT" }, {}, (value) => {
      response = value;
    });
    assert.equal(asynchronous, false);
    return response;
    },
    runTimerWithDelay(delay) {
      const entry = Array.from(timers.entries()).find(([, timer]) => timer.delay === delay);
      assert.ok(entry, `timer with delay ${delay} should exist`);
      timers.delete(entry[0]);
      entry[1].callback();
    }
  };
}

test("content page reader omits editable and form-control sentinels but keeps value-free metadata", () => {
  const html = new MockElement("html");
  const body = html.appendChild(new MockElement("body"));
  body.appendChild(
    new MockText(
      `Privacy policy and terms. Personal data retention and third-party sharing are described here. ${"public notice ".repeat(12)}`
    )
  );
  const textarea = body.appendChild(new MockElement("textarea", { name: "draft" }));
  textarea.appendChild(new MockText("CONTENT_TEXTAREA_PRIVATE_SENTINEL"));
  const editor = body.appendChild(new MockElement("div", { contenteditable: "true" }));
  editor.appendChild(new MockElement("span")).appendChild(new MockText("CONTENT_EDITABLE_PRIVATE_SENTINEL"));
  body.appendChild(new MockElement("div", { role: "searchbox" })).appendChild(
    new MockText("CONTENT_ROLE_PRIVATE_SENTINEL")
  );
  const select = body.appendChild(new MockElement("select", { name: "country" }));
  select.appendChild(new MockElement("option")).appendChild(new MockText("CONTENT_OPTION_PRIVATE_SENTINEL"));
  const cssEditor = body.appendChild(new MockElement("div"));
  cssEditor._style.userModify = "read-write-plaintext-only";
  cssEditor.appendChild(new MockText("CONTENT_CSS_EDITOR_PRIVATE_SENTINEL"));

  const runtime = loadContentRuntime(new MockDocument(html, body));
  const result = runtime.readPage();

  assert.match(result.text, /Privacy policy and terms/);
  for (const sentinel of [
    "CONTENT_TEXTAREA_PRIVATE_SENTINEL",
    "CONTENT_EDITABLE_PRIVATE_SENTINEL",
    "CONTENT_ROLE_PRIVATE_SENTINEL",
    "CONTENT_OPTION_PRIVATE_SENTINEL",
    "CONTENT_CSS_EDITOR_PRIVATE_SENTINEL"
  ]) {
    assert.doesNotMatch(result.text, new RegExp(sentinel));
    assert.doesNotMatch(JSON.stringify(result.forms), new RegExp(sentinel));
  }
  assert.deepEqual(
    Array.from(result.forms.fields, (field) => ({ tag: field.tag, name: field.name })),
    [
      { tag: "textarea", name: "draft" },
      { tag: "select", name: "country" }
    ]
  );
});

test("content page reader returns no page text for a design-mode document", () => {
  const html = new MockElement("html");
  const body = html.appendChild(new MockElement("body"));
  body.appendChild(new MockText("CONTENT_DESIGN_MODE_PRIVATE_SENTINEL privacy policy"));
  const document = new MockDocument(html, body);
  document.designMode = "on";

  const result = loadContentRuntime(document).readPage();
  assert.equal(result.text, "");
});

test("content risk observer ignores mutations confined to editable subtrees", () => {
  const html = new MockElement("html");
  const body = html.appendChild(new MockElement("body"));
  const publicText = body.appendChild(
    new MockText(`Privacy policy personal data retention. ${"public policy text ".repeat(80)}`)
  );
  const editor = body.appendChild(new MockElement("div", { contenteditable: "true" }));
  const privateText = editor.appendChild(new MockText("MUTATION_PRIVATE_SENTINEL"));
  const runtime = loadContentRuntime(new MockDocument(html, body), { automaticAllowed: true });

  runtime.runTimerWithDelay(900);
  const riskObserver = runtime.mutationObservers.find(
    (observer) => observer.options?.characterData === true
  );
  assert.ok(riskObserver, "risk mutation observer should be active");

  const timerCountBeforeEditableMutation = runtime.timers.size;
  riskObserver.callback([{ type: "characterData", target: privateText }]);
  assert.equal(runtime.timers.size, timerCountBeforeEditableMutation);

  riskObserver.callback([{ type: "characterData", target: publicText }]);
  assert.equal(runtime.timers.size, timerCountBeforeEditableMutation + 1);
});

test("hidden tabs disconnect automatic DOM observers and resume them when visible", () => {
  const html = new MockElement("html");
  const body = html.appendChild(new MockElement("body"));
  body.appendChild(new MockText(`Privacy policy personal data retention. ${"public policy text ".repeat(80)}`));
  const document = new MockDocument(html, body);
  const runtime = loadContentRuntime(document, { automaticAllowed: true });

  assert.ok(runtime.mutationObservers.some((observer) => observer.active));
  assert.ok(runtime.timers.size >= 1);

  document.visibilityState = "hidden";
  document.dispatch("visibilitychange");

  assert.equal(runtime.mutationObservers.some((observer) => observer.active), false);
  assert.equal(runtime.timers.size, 0);

  document.visibilityState = "visible";
  document.dispatch("visibilitychange");

  assert.ok(runtime.mutationObservers.some((observer) => observer.active));
  assert.ok(Array.from(runtime.timers.values()).some((timer) => timer.delay === 300));
});

test("defers automatic observation until a trusted prerender activation", () => {
  const html = new MockElement("html");
  const body = html.appendChild(new MockElement("body"));
  body.appendChild(new MockText(`Privacy policy personal data retention. ${"public policy text ".repeat(80)}`));
  const document = new MockDocument(html, body);
  document.prerendering = true;
  document.visibilityState = "hidden";
  const runtime = loadContentRuntime(document, { automaticAllowed: true });

  assert.equal(runtime.messages.some((message) => message.type === "GET_OBSERVATION_SETTINGS"), false);
  assert.equal(runtime.mutationObservers.some((observer) => observer.active), false);
  assert.equal(runtime.timers.size, 0);

  document.prerendering = false;
  for (let index = 0; index < 100; index += 1) {
    document.dispatch("prerenderingchange", { isTrusted: false });
  }
  assert.equal(runtime.messages.some((message) => message.type === "GET_OBSERVATION_SETTINGS"), false);

  document.visibilityState = "visible";
  document.dispatch("prerenderingchange", { isTrusted: true });
  assert.equal(
    runtime.messages.filter((message) => message.type === "GET_OBSERVATION_SETTINGS").length,
    1
  );
  assert.ok(runtime.mutationObservers.some((observer) => observer.active));
  assert.ok(Array.from(runtime.timers.values()).some((timer) => timer.delay === 900));

  document.dispatch("prerenderingchange", { isTrusted: true });
  assert.equal(
    runtime.messages.filter((message) => message.type === "GET_OBSERVATION_SETTINGS").length,
    1,
    "the activation listener is removed after the first trusted activation"
  );
});

test("fails closed and reloads observation settings across BFCache restores", () => {
  const enabledHtml = new MockElement("html");
  const enabledBody = enabledHtml.appendChild(new MockElement("body"));
  enabledBody.appendChild(new MockText(`Privacy policy. ${"public policy text ".repeat(80)}`));
  const enabledDocument = new MockDocument(enabledHtml, enabledBody);
  const enabledRuntime = loadContentRuntime(enabledDocument, { automaticAllowed: true });
  assert.ok(enabledRuntime.mutationObservers.some((observer) => observer.active));

  const initialRequestCount = enabledRuntime.messages.length;
  for (let index = 0; index < 100; index += 1) {
    enabledRuntime.dispatchWindow("pagehide", { isTrusted: false, persisted: true });
    enabledRuntime.dispatchWindow("pageshow", { isTrusted: false, persisted: true });
  }
  assert.equal(enabledRuntime.messages.length, initialRequestCount);
  assert.ok(enabledRuntime.mutationObservers.some((observer) => observer.active));

  enabledRuntime.setAutomaticAllowed(false);
  enabledRuntime.dispatchWindow("pagehide", { isTrusted: true, persisted: true });
  assert.equal(enabledRuntime.mutationObservers.some((observer) => observer.active), false);
  assert.equal(enabledRuntime.timers.size, 0);
  enabledRuntime.dispatchWindow("pageshow", { isTrusted: true, persisted: true });
  assert.equal(
    enabledRuntime.messages.filter((message) => message.type === "GET_OBSERVATION_SETTINGS").length,
    2
  );
  assert.equal(enabledRuntime.mutationObservers.some((observer) => observer.active), false);
  assert.equal(enabledRuntime.timers.size, 0);
  assert.equal(enabledRuntime.messages.some((message) => message.type === "PAGE_RISK_SCAN"), false);

  const disabledHtml = new MockElement("html");
  const disabledBody = disabledHtml.appendChild(new MockElement("body"));
  disabledBody.appendChild(new MockText(`Privacy policy. ${"public policy text ".repeat(80)}`));
  const disabledDocument = new MockDocument(disabledHtml, disabledBody);
  const disabledRuntime = loadContentRuntime(disabledDocument, { automaticAllowed: false });
  assert.equal(disabledRuntime.mutationObservers.some((observer) => observer.active), false);

  disabledRuntime.setAutomaticAllowed(true);
  disabledRuntime.dispatchWindow("pagehide", { isTrusted: true, persisted: true });
  disabledRuntime.dispatchWindow("pageshow", { isTrusted: true, persisted: true });
  assert.ok(disabledRuntime.mutationObservers.some((observer) => observer.active));
  assert.ok(Array.from(disabledRuntime.timers.values()).some((timer) => timer.delay === 900));
});

test("ignores an old settings response after a newer settings push", () => {
  const html = new MockElement("html");
  const body = html.appendChild(new MockElement("body"));
  body.appendChild(new MockText(`Privacy policy. ${"public policy text ".repeat(80)}`));
  const runtime = loadContentRuntime(new MockDocument(html, body), {
    automaticAllowed: true,
    deferObservationSettings: true
  });

  assert.equal(runtime.messages.filter((message) => message.type === "GET_OBSERVATION_SETTINGS").length, 1);
  const pushed = runtime.dispatchMessage({
    type: "OBSERVATION_SETTINGS_UPDATE",
    settings: { enabled: false, allowed: false }
  });
  assert.equal(pushed.asynchronous, false);
  assert.equal(pushed.response?.active, false);

  runtime.resolveObservationSettings(true);
  assert.equal(runtime.mutationObservers.some((observer) => observer.active), false);
  assert.equal(runtime.timers.size, 0);
});
