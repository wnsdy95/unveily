import assert from "node:assert/strict";
import test from "node:test";
import {
  isValidCustomVendorRule,
  loadCustomVendorRules,
  normalizeCustomVendorRule,
  saveCustomVendorRules
} from "../src/customRulesStorage.js";

test("normalizes custom vendor rules to bounded domain patterns", () => {
  const rule = normalizeCustomVendorRule({
    vendor: "  Example Identity  ",
    patterns: "https://Login.Example.com/path, .api.example.com.",
    category: "authentication",
    risk: "processor",
    expectedPolicySections: ["processors", "purpose", "not-a-section"]
  });

  assert.equal(rule.vendor, "Example Identity");
  assert.deepEqual(rule.patterns, ["login.example.com", "api.example.com"]);
  assert.deepEqual(rule.expectedPolicySections, ["processors", "purpose"]);
  assert.equal(isValidCustomVendorRule(rule), true);
});

test("rejects path fragments and invalid custom rule values", () => {
  const rule = normalizeCustomVendorRule({
    vendor: "Bad rule",
    patterns: "stripe.com/path, javascript:alert(1)",
    category: "unexpected",
    risk: "critical",
    expectedPolicySections: ["unknown-section"]
  });

  assert.equal(rule.category, "unknown");
  assert.equal(rule.risk, "unknown");
  assert.equal(isValidCustomVendorRule(rule), false);
});

test("ignores malformed stored-rule shapes and overlong domain patterns", () => {
  const malformed = normalizeCustomVendorRule(null);
  assert.equal(isValidCustomVendorRule(malformed), false);

  const overlong = normalizeCustomVendorRule({
    vendor: "Too long",
    patterns: `safe.example.${"a".repeat(260)}`,
    expectedPolicySections: ["processors"]
  });
  assert.deepEqual(overlong.patterns, []);
  assert.equal(isValidCustomVendorRule(overlong), false);
});

test("deduplicates patterns and accepts a valid punycode hostname", () => {
  const rule = normalizeCustomVendorRule({
    vendor: "IDN vendor",
    patterns: "api.example.com, API.EXAMPLE.COM, service.xn--p1ai",
    expectedPolicySections: ["processors"]
  });

  assert.deepEqual(rule.patterns, ["api.example.com", "service.xn--p1ai"]);
  assert.equal(isValidCustomVendorRule(rule), true);
});

test("bounds oversized pattern collections before normalization", () => {
  const rule = normalizeCustomVendorRule({
    vendor: "Bounded vendor",
    patterns: Array.from({ length: 5000 }, (_item, index) => `host-${index}.example.com`),
    expectedPolicySections: Array.from({ length: 5000 }, () => "processors")
  });

  assert.equal(rule.patterns.length, 20);
  assert.deepEqual(rule.expectedPolicySections, ["processors"]);
});

test("fails closed before direct custom-rule storage reads or writes", async () => {
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
    await assert.rejects(loadCustomVendorRules(), /Trusted local storage access is unavailable/);
    await assert.rejects(saveCustomVendorRules([]), /Trusted local storage access is unavailable/);
    assert.deepEqual(calls, { access: 2, get: 0, set: 0 });
  } finally {
    delete globalThis.chrome;
  }
});

test("preserves custom-rule fallbacks when local storage is absent", async () => {
  delete globalThis.chrome;
  assert.deepEqual(await loadCustomVendorRules(), []);
  assert.deepEqual(await saveCustomVendorRules([]), []);
});

test("fails explicitly when the custom-rule storage getter throws", async () => {
  globalThis.chrome = {
    storage: Object.defineProperty({}, "local", {
      get() {
        throw new Error("getter denied");
      }
    })
  };
  try {
    await assert.rejects(loadCustomVendorRules(), /Trusted local storage access is unavailable/);
  } finally {
    delete globalThis.chrome;
  }
});
