import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const popupSource = await readFile(new URL("../src/popup.js", import.meta.url), "utf8");
const optionsSource = await readFile(new URL("../src/options.js", import.meta.url), "utf8");

class MockClassList {
  constructor() {
    this.values = new Set();
  }

  toggle(name, force) {
    if (force) this.values.add(name);
    else this.values.delete(name);
  }
}

class MockElement {
  constructor(id = "", options = {}) {
    this.id = id;
    this.dataset = { ...(options.dataset || {}) };
    this.hidden = Boolean(options.hidden);
    this.disabled = false;
    this.checked = options.checked ?? false;
    this.value = options.value || "";
    this.textContent = "";
    this.innerHTML = "";
    this.type = options.type || "";
    this.attributes = new Map();
    this.listeners = new Map();
    this.classList = new MockClassList();
  }

  addEventListener(type, listener) {
    const listeners = this.listeners.get(type) || [];
    listeners.push(listener);
    this.listeners.set(type, listeners);
  }

  listenerCount(type) {
    return this.listeners.get(type)?.length || 0;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  focus() {}

  reset() {}

  closest() {
    return null;
  }
}

function createDocument(ids, { modeButtons = [], controls = [], sectionInputs = [] } = {}) {
  const elements = new Map(ids.map((id) => [id, new MockElement(id)]));
  const title = new MockElement("title", { dataset: { i18n: "appName" } });
  const documentElement = new MockElement("documentElement");
  return {
    elements,
    document: {
      documentElement,
      title: "",
      querySelector(selector) {
        if (selector === "title") return title;
        if (selector.startsWith("#")) return elements.get(selector.slice(1)) || null;
        return null;
      },
      querySelectorAll(selector) {
        if (selector === ".mode-button") return modeButtons;
        if (selector === "input, textarea, select, button") return controls;
        if (selector === "input[name='section']" || selector === "input[name='section']:checked") {
          return selector.endsWith(":checked")
            ? sectionInputs.filter((input) => input.checked)
            : sectionInputs;
        }
        return [];
      },
      createElement() {
        return new MockElement();
      }
    }
  };
}

function localStorageFailureHarness() {
  const operations = [];
  const local = {
    async setAccessLevel(details) {
      operations.push(["setAccessLevel", structuredClone(details)]);
      throw new Error("access-level unavailable");
    },
    async get(keys) {
      operations.push(["get", structuredClone(keys)]);
      return {};
    },
    async set(values) {
      operations.push(["set", structuredClone(values)]);
    }
  };
  return { local, operations };
}

function sourceAfterImports(source, marker) {
  const start = source.indexOf(marker);
  assert.ok(start >= 0, `entrypoint marker ${marker} should exist`);
  return source.slice(start);
}

function translated(key, substitutions = []) {
  return `${key}${substitutions.length ? `:${substitutions.join(",")}` : ""}`;
}

test("popup and options import the shared storage gate and no-storage i18n path", () => {
  for (const source of [popupSource, optionsSource]) {
    assert.match(
      source,
      /import \{ ensureTrustedLocalStorage \} from "\.\/trustedLocalStorage\.js";/
    );
    assert.match(source, /applyI18nWithoutStorage/);
  }
});

test("popup fails closed before local reads while keeping value-free analysis available", async () => {
  const popupIds = [
    "analyzePageButton",
    "analyzeCookiesButton",
    "analyzePasteButton",
    "saveSnapshotButton",
    "resetObservationButton",
    "exportMarkdownButton",
    "exportJsonButton",
    "savePolicyButton",
    "deletePolicyButton",
    "checkPoliciesButton",
    "companionOverlayToggleButton",
    "menuToggleButton",
    "actionsPanel",
    "pastePanel",
    "policyText",
    "status",
    "result",
    "sourceLabel",
    "uiLanguageSelect",
    "storageIsolationWarning"
  ];
  const modeButtons = ["analyzePageButton", "analyzeCookiesButton", "analyzePasteButton"].map(
    (id) => new MockElement(id, { dataset: { mode: id.replace("analyze", "").replace("Button", "").toLowerCase() } })
  );
  const { elements, document } = createDocument(popupIds, { modeButtons });
  for (const button of modeButtons) elements.set(button.id, button);
  elements.get("actionsPanel").hidden = false;
  elements.get("storageIsolationWarning").hidden = true;

  const { local, operations } = localStorageFailureHarness();
  const state = {
    noStorageI18nCalls: 0,
    customRuleLoads: 0,
    customRulesPassed: null,
    runtimeMessages: [],
    pageMessageOptions: []
  };
  let finishAnalysis;
  const analysisFinished = new Promise((resolve) => {
    finishAnalysis = resolve;
  });
  const tab = {
    id: 7,
    windowId: 3,
    url: "https://example.com/privacy",
    title: "Privacy",
    status: "complete"
  };
  const pageResponse = {
    title: "Privacy",
    url: tab.url,
    text: "ordinary page text",
    forms: { fields: [] },
    storage: { localStorageKeys: [], sessionStorageKeys: [] },
    consent: { containers: [] },
    jurisdictionSignals: { host: "example.com" }
  };
  const sandbox = {
    AbortController,
    Blob,
    Date,
    Intl,
    Map,
    Math,
    Number,
    Object,
    Promise,
    Set,
    String,
    URL,
    WeakMap,
    console,
    document,
    globalThis: null,
    navigator: { language: "en", languages: ["en"] },
    window: {
      clearTimeout,
      setTimeout,
      URL
    },
    chrome: {
      i18n: { getUILanguage: () => "en", getMessage: () => "" },
      storage: { local },
      runtime: {
        lastError: null,
        async sendMessage(message) {
          state.runtimeMessages.push(structuredClone(message));
          if (message.type === "GET_NETWORK_ACTIVITY") {
            return {
              ok: true,
              observationEnabled: false,
              requests: [],
              cookies: [],
              snapshots: []
            };
          }
          return { ok: true };
        }
      },
      tabs: {
        async query() {
          return [{ ...tab }];
        },
        async get() {
          return { ...tab };
        },
        sendMessage(_tabId, message, options, callback) {
          state.pageMessageOptions.push(structuredClone(options));
          if (message.type === "GET_PAGE_TEXT") callback(pageResponse);
          else callback?.({ ok: true });
        }
      },
      webNavigation: {
        async getFrame() {
          return { frameId: 0, documentId: "document-7", url: tab.url };
        }
      },
      scripting: {
        async executeScript() {}
      }
    },
    async ensureTrustedLocalStorage(storageArea = local) {
      try {
        await storageArea.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
        return true;
      } catch {
        return false;
      }
    },
    async applyI18n() {
      await local.get("locale");
    },
    applyI18nWithoutStorage() {
      state.noStorageI18nCalls += 1;
    },
    async getLocalePreference() {
      await local.get("locale");
      return "auto";
    },
    async setLocalePreference(value) {
      await local.set({ locale: value });
    },
    localeCode: () => "en",
    t: translated,
    async loadCustomVendorRules() {
      state.customRuleLoads += 1;
      await local.get("customRules");
      return [{ id: "persisted-rule" }];
    },
    async deletePolicySnapshot() {
      await local.set({ deleted: true });
      return true;
    },
    normalizePolicyUrl: () => "",
    documentUrlFingerprint: () => "0".repeat(32),
    sanitizeNetworkUrl: () => ({ url: "https://example.com/:segment" }),
    analyzePolicy: () => ({ ok: false, message: "not policy", level: "unknown", score: 0 }),
    analyzeNetworkActivity(_text, _requests, _url, customRules) {
      state.customRulesPassed = structuredClone(customRules);
      finishAnalysis();
      return { requestCount: 0, thirdPartyHosts: [], trackerHosts: [], vendorSummary: [], findings: [] };
    },
    analyzeFormFields: () => ({ fieldCount: 0, sensitiveFieldCount: 0, categories: [], findings: [] }),
    analyzeClientStorage: () => ({
      localStorageKeyCount: 0,
      sessionStorageKeyCount: 0,
      cookieCount: 0,
      thirdPartyCookieCount: 0,
      classifiedStorage: [],
      findings: []
    }),
    analyzeConsentCompliance: () => ({ trackingRequestCount: 0, trackingCookieCount: 0 }),
    analyzeObservationDelta: () => ({ hasSnapshot: false, findings: [] }),
    analyzeJurisdictionCompliance: () => ({ findings: [] }),
    analyzeBehaviorPolicyAlignment: () => ({ findings: [] }),
    buildReportPayload: () => ({}),
    buildJsonReport: () => "",
    buildMarkdownReport: () => "",
    buildReportFileName: () => "report.txt",
    downloadTextFile() {}
  };
  sandbox.globalThis = sandbox;

  const startup = vm.runInNewContext(sourceAfterImports(popupSource, "let latestSource"), sandbox, {
    filename: "popup-storage-gate-runtime.js"
  });
  await startup;
  await analysisFinished;

  assert.deepEqual(operations, [
    ["setAccessLevel", { accessLevel: "TRUSTED_CONTEXTS" }]
  ]);
  assert.equal(state.noStorageI18nCalls, 1);
  assert.equal(state.customRuleLoads, 0);
  assert.deepEqual(state.customRulesPassed, []);
  assert.deepEqual(state.pageMessageOptions, [{ documentId: "document-7" }]);
  assert.equal(elements.get("storageIsolationWarning").hidden, false);
  for (const id of [
    "uiLanguageSelect",
    "saveSnapshotButton",
    "resetObservationButton",
    "savePolicyButton",
    "deletePolicyButton",
    "checkPoliciesButton",
    "companionOverlayToggleButton"
  ]) {
    assert.equal(elements.get(id).disabled, true, `${id} should stay disabled`);
  }
  assert.equal(elements.get("uiLanguageSelect").listenerCount("change"), 0);
  assert.equal(elements.get("saveSnapshotButton").listenerCount("click"), 0);
  assert.equal(elements.get("resetObservationButton").listenerCount("click"), 0);
  assert.equal(elements.get("savePolicyButton").listenerCount("click"), 0);
  assert.equal(elements.get("deletePolicyButton").listenerCount("click"), 0);
  assert.equal(elements.get("checkPoliciesButton").listenerCount("click"), 0);
  assert.equal(elements.get("analyzePageButton").listenerCount("click"), 1);
  assert.equal(elements.get("analyzeCookiesButton").listenerCount("click"), 1);
  assert.equal(elements.get("analyzePasteButton").listenerCount("click"), 1);
  assert.equal(elements.get("companionOverlayToggleButton").disabled, true);
  assert.equal(elements.get("companionOverlayToggleButton").getAttribute("aria-pressed"), "false");
  assert.equal(elements.get("companionOverlayToggleButton").listenerCount("click"), 0);
  assert.equal(
    state.runtimeMessages.some((message) =>
      ["GET_COMPANION_OVERLAY_PREFERENCE", "SET_COMPANION_OVERLAY_PREFERENCE"].includes(message.type)
    ),
    false
  );
});

test("options fails closed before local reads and leaves every form control inert", async () => {
  const optionIds = [
    "ruleForm",
    "ruleId",
    "vendor",
    "patterns",
    "category",
    "risk",
    "ruleList",
    "snapshotList",
    "status",
    "cancelEditButton",
    "uiLanguageSelect",
    "observationEnabled",
    "excludedOrigins",
    "saveObservationSettingsButton"
  ];
  const sectionInputs = ["processors", "purpose", "security"].map(
    (value) => new MockElement(`section-${value}`, { value, checked: true, type: "checkbox" })
  );
  const { elements, document } = createDocument(optionIds, { sectionInputs });
  elements.get("observationEnabled").checked = true;
  elements.get("excludedOrigins").value = "https://sensitive.example";
  const submitButton = new MockElement("ruleSubmit", { type: "submit" });
  const controls = [
    elements.get("ruleId"),
    elements.get("vendor"),
    elements.get("patterns"),
    elements.get("category"),
    elements.get("risk"),
    ...sectionInputs,
    submitButton,
    elements.get("cancelEditButton"),
    elements.get("uiLanguageSelect"),
    elements.get("observationEnabled"),
    elements.get("excludedOrigins"),
    elements.get("saveObservationSettingsButton")
  ];
  const originalQuerySelectorAll = document.querySelectorAll;
  document.querySelectorAll = (selector) => {
    if (selector === "input, textarea, select, button") return controls;
    return originalQuerySelectorAll.call(document, selector);
  };

  const { local, operations } = localStorageFailureHarness();
  const state = { noStorageI18nCalls: 0 };
  const sandbox = {
    Date,
    Intl,
    Map,
    Number,
    Object,
    Promise,
    Set,
    String,
    URL,
    console,
    document,
    globalThis: null,
    confirm: () => false,
    chrome: {
      i18n: { getUILanguage: () => "en", getMessage: () => "" },
      storage: { local }
    },
    async ensureTrustedLocalStorage(storageArea = local) {
      try {
        await storageArea.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
        return true;
      } catch {
        return false;
      }
    },
    async applyI18n() {
      await local.get("locale");
    },
    applyI18nWithoutStorage() {
      state.noStorageI18nCalls += 1;
    },
    async getLocalePreference() {
      await local.get("locale");
      return "auto";
    },
    async setLocalePreference(value) {
      await local.set({ locale: value });
    },
    t: translated,
    async loadCustomVendorRules() {
      await local.get("customRules");
      return [];
    },
    async saveCustomVendorRules() {
      await local.set({ customRules: [] });
      return [];
    },
    normalizeCustomVendorRule: () => ({}),
    isValidCustomVendorRule: () => false,
    async loadPolicySnapshots() {
      await local.get("policySnapshots");
      return {};
    },
    async loadPolicyCheckHealth() {
      await local.get("policyCheckHealth");
      return {};
    },
    async deletePolicySnapshot() {
      await local.set({ deleted: true });
      return true;
    },
    async loadObservationSettings() {
      await local.get("observationSettings");
      return { enabled: true, excludedOrigins: [] };
    },
    async saveObservationSettings() {
      await local.set({ observationSettings: {} });
      return { enabled: true, excludedOrigins: [] };
    },
    validateObservationSettingsInput: () => ({ ok: true, settings: {} }),
    OBSERVATION_SETTINGS_VALIDATION_ERRORS: {
      TOO_MANY_EXCLUDED_ORIGINS: "too_many"
    }
  };
  sandbox.globalThis = sandbox;

  const startup = vm.runInNewContext(sourceAfterImports(optionsSource, "const ruleForm"), sandbox, {
    filename: "options-storage-gate-runtime.js"
  });
  await startup;

  assert.deepEqual(operations, [
    ["setAccessLevel", { accessLevel: "TRUSTED_CONTEXTS" }]
  ]);
  assert.equal(state.noStorageI18nCalls, 1);
  assert.equal(elements.get("status").textContent, "statusStorageIsolationUnavailable");
  assert.equal(elements.get("status").classList.values.has("error"), true);
  assert.equal(elements.get("observationEnabled").checked, false);
  assert.equal(elements.get("excludedOrigins").value, "");
  for (const control of controls) assert.equal(control.disabled, true, `${control.id} should be disabled`);
  assert.equal(elements.get("ruleForm").listenerCount("submit"), 0);
  assert.equal(elements.get("ruleList").listenerCount("click"), 0);
  assert.equal(elements.get("snapshotList").listenerCount("click"), 0);
  assert.equal(elements.get("cancelEditButton").listenerCount("click"), 0);
  assert.equal(elements.get("uiLanguageSelect").listenerCount("change"), 0);
  assert.equal(elements.get("saveObservationSettingsButton").listenerCount("click"), 0);
});
