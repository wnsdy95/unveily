import assert from "node:assert/strict";
import test from "node:test";

import {
  ANALYSIS_MODE_PREFERENCE_KEY,
  DEFAULT_ANALYSIS_MODE,
  loadAnalysisModePreference,
  normalizeAnalysisModePreference,
  saveAnalysisModePreference
} from "../src/analysisModePreference.js";

function installChrome(t, local) {
  const previous = Object.getOwnPropertyDescriptor(globalThis, "chrome");
  Object.defineProperty(globalThis, "chrome", {
    configurable: true,
    value: { storage: { local } }
  });
  t.after(() => {
    if (previous) Object.defineProperty(globalThis, "chrome", previous);
    else delete globalThis.chrome;
  });
}

function createTrustedStorage(initial = {}) {
  const values = structuredClone(initial);
  const operations = [];
  const local = {
    async setAccessLevel(details) {
      operations.push(["setAccessLevel", structuredClone(details)]);
    },
    async get(key) {
      operations.push(["get", key]);
      return Object.hasOwn(values, key) ? { [key]: structuredClone(values[key]) } : {};
    },
    async set(update) {
      operations.push(["set", structuredClone(update)]);
      Object.assign(values, structuredClone(update));
    }
  };
  return { local, operations, values };
}

test("normalizes the bounded versioned analysis-mode preference", () => {
  assert.equal(ANALYSIS_MODE_PREFERENCE_KEY, "analysisModePreferenceV1");
  assert.equal(DEFAULT_ANALYSIS_MODE, "page");
  assert.equal(normalizeAnalysisModePreference("page"), "page");
  assert.equal(normalizeAnalysisModePreference("cookies"), "cookies");
  for (const malformed of ["paste", "cookie", "PAGE", "", null, undefined, {}, []]) {
    assert.equal(normalizeAnalysisModePreference(malformed), "page");
  }
});

test("persists the selected analysis mode across fresh extension-page lifecycles", async (t) => {
  const { local, operations, values } = createTrustedStorage();
  installChrome(t, local);

  assert.equal(await loadAnalysisModePreference(), "page");
  assert.equal(await saveAnalysisModePreference("cookies"), "cookies");

  const freshModule = await import(
    `../src/analysisModePreference.js?fresh-lifecycle=${Date.now()}-${Math.random()}`
  );
  assert.equal(await freshModule.loadAnalysisModePreference(), "cookies");
  assert.equal(values[ANALYSIS_MODE_PREFERENCE_KEY], "cookies");
  assert.deepEqual(operations, [
    ["setAccessLevel", { accessLevel: "TRUSTED_CONTEXTS" }],
    ["get", ANALYSIS_MODE_PREFERENCE_KEY],
    ["set", { [ANALYSIS_MODE_PREFERENCE_KEY]: "cookies" }],
    ["get", ANALYSIS_MODE_PREFERENCE_KEY]
  ]);
});

test("normalizes malformed stored state without expanding the storage schema", async (t) => {
  const { local, operations } = createTrustedStorage({
    [ANALYSIS_MODE_PREFERENCE_KEY]: {
      mode: "cookies",
      unrelated: "untrusted"
    }
  });
  installChrome(t, local);

  assert.equal(await loadAnalysisModePreference(), "page");
  assert.deepEqual(operations, [
    ["setAccessLevel", { accessLevel: "TRUSTED_CONTEXTS" }],
    ["get", ANALYSIS_MODE_PREFERENCE_KEY]
  ]);
});

test("fails closed before preference reads when trusted storage isolation fails", async (t) => {
  const operations = [];
  const local = {
    async setAccessLevel(details) {
      operations.push(["setAccessLevel", structuredClone(details)]);
      throw new Error("isolation unavailable");
    },
    async get() {
      operations.push(["get"]);
      throw new Error("must not read");
    },
    async set() {
      operations.push(["set"]);
      throw new Error("must not write");
    }
  };
  installChrome(t, local);

  await assert.rejects(loadAnalysisModePreference(), /Trusted local storage access is unavailable/);
  assert.deepEqual(operations, [
    ["setAccessLevel", { accessLevel: "TRUSTED_CONTEXTS" }]
  ]);
});
