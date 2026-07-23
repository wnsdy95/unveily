import assert from "node:assert/strict";
import test from "node:test";
import {
  createObservationMatcher,
  DEFAULT_OBSERVATION_SETTINGS,
  isObservationAllowed,
  loadObservationSettings,
  MAX_EXCLUDED_ORIGINS,
  normalizeObservationOrigin,
  normalizeObservationSettings,
  OBSERVATION_SETTINGS_VALIDATION_ERRORS,
  saveObservationSettings,
  validateObservationSettingsInput
} from "../src/observationSettings.js";

test("normalizes and deduplicates excluded observation origins", () => {
  assert.deepEqual(
    normalizeObservationSettings({
      enabled: false,
      excludedOrigins: ["example.com/private", "https://example.com/other", "javascript:alert(1)"]
    }),
    {
      enabled: false,
      excludedOrigins: ["https://example.com"]
    }
  );
  assert.equal(normalizeObservationOrigin("http://example.com/path?q=1"), "http://example.com");
  assert.equal(normalizeObservationOrigin("ftp://example.com/private"), "");
  assert.equal(normalizeObservationOrigin("mailto:user@example.com"), "");
});

test("rejects oversized exclusion entries and returns independent defaults", () => {
  assert.equal(normalizeObservationOrigin(`https://${"a".repeat(2050)}.example`), "");
  const settings = normalizeObservationSettings();
  settings.excludedOrigins.push("https://example.com");
  assert.deepEqual(DEFAULT_OBSERVATION_SETTINGS.excludedOrigins, []);
  assert.equal(normalizeObservationSettings({ enabled: "false" }).enabled, false);
  assert.equal(normalizeObservationSettings({ enabled: 1 }).enabled, false);
});

test("validates new exclusion saves without silently dropping or widening entries", () => {
  assert.deepEqual(
    validateObservationSettingsInput({
      enabled: false,
      excludedOrigins: ["example.com", "https://example.com/", "http://other.example"]
    }),
    {
      ok: true,
      settings: {
        enabled: false,
        excludedOrigins: ["https://example.com", "http://other.example"]
      }
    }
  );

  for (const invalidOrigin of [
    "ftp://example.com",
    "javascript:alert(1)",
    "https://user:secret@example.com",
    "https://example.com/private",
    "https://example.com/?token=secret",
    "https://example.com/#section"
  ]) {
    assert.deepEqual(validateObservationSettingsInput({ excludedOrigins: [invalidOrigin] }), {
      ok: false,
      error: OBSERVATION_SETTINGS_VALIDATION_ERRORS.INVALID_EXCLUDED_ORIGIN
    });
  }
});

test("rejects more than one hundred exclusion inputs instead of truncating them", async () => {
  const values = Array.from(
    { length: MAX_EXCLUDED_ORIGINS + 1 },
    (_, index) => `https://site-${index}.example`
  );
  assert.deepEqual(validateObservationSettingsInput({ excludedOrigins: values }), {
    ok: false,
    error: OBSERVATION_SETTINGS_VALIDATION_ERRORS.TOO_MANY_EXCLUDED_ORIGINS
  });

  let setCalls = 0;
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {
          throw new Error("validation must finish before storage access");
        },
        async set() {
          setCalls += 1;
        }
      }
    }
  };
  await assert.rejects(
    saveObservationSettings({ excludedOrigins: values }),
    (error) =>
      error?.code === OBSERVATION_SETTINGS_VALIDATION_ERRORS.TOO_MANY_EXCLUDED_ORIGINS
  );
  assert.equal(setCalls, 0);
  delete globalThis.chrome;
});

test("fails closed before direct observation-setting reads or writes", async () => {
  const calls = { access: 0, get: 0, set: 0 };
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {
          calls.access += 1;
          throw new Error("denied");
        },
        async get() {
          calls.get += 1;
          return {};
        },
        async set() {
          calls.set += 1;
        }
      }
    }
  };

  try {
    await assert.rejects(loadObservationSettings(), /Trusted local storage access is unavailable/);
    await assert.rejects(
      saveObservationSettings({ enabled: false, excludedOrigins: [] }),
      /Trusted local storage access is unavailable/
    );
    assert.deepEqual(calls, { access: 2, get: 0, set: 0 });
  } finally {
    delete globalThis.chrome;
  }
});

test("preserves observation-setting fallbacks when local storage is absent", async () => {
  delete globalThis.chrome;
  assert.deepEqual(await loadObservationSettings(), DEFAULT_OBSERVATION_SETTINGS);
  assert.deepEqual(
    await saveObservationSettings({ enabled: false, excludedOrigins: ["example.com"] }),
    { enabled: false, excludedOrigins: ["https://example.com"] }
  );
});

test("fails explicitly when the observation storage getter throws", async () => {
  globalThis.chrome = {
    storage: Object.defineProperty({}, "local", {
      get() {
        throw new Error("getter denied");
      }
    })
  };
  try {
    await assert.rejects(loadObservationSettings(), /Trusted local storage access is unavailable/);
  } finally {
    delete globalThis.chrome;
  }
});

test("applies global pause and exact-origin exclusions", () => {
  assert.equal(isObservationAllowed("https://example.com/page", { enabled: false }), false);
  assert.equal(
    isObservationAllowed("https://example.com/page", {
      enabled: true,
      excludedOrigins: ["https://example.com"]
    }),
    false
  );
  assert.equal(
    isObservationAllowed("https://sub.example.com/page", {
      enabled: true,
      excludedOrigins: ["https://example.com"]
    }),
    true
  );
});

test("compiles repeated hot-path checks to an exact-origin set", () => {
  const matcher = createObservationMatcher({
    enabled: true,
    excludedOrigins: ["https://example.com/path", "https://example.com/other"]
  });

  assert.equal(matcher("https://example.com/page"), false);
  assert.equal(matcher("https://sub.example.com/page"), true);
  assert.equal(matcher("not a url"), false);
});
