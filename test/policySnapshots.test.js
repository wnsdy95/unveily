import assert from "node:assert/strict";
import test from "node:test";
import {
  POLICY_CHECK_ERROR_CATEGORIES,
  POLICY_CHECK_HEALTH_KEY,
  comparePolicySnapshot,
  createPolicySnapshot,
  deletePolicySnapshot,
  hashText,
  hashTextSecure,
  loadPolicyCheckHealth,
  loadPolicySnapshot,
  loadPolicySnapshots,
  normalizePolicyUrl,
  normalizePolicyText,
  originFromUrl,
  prunePolicySnapshots,
  recordPolicyCheckResults,
  savePolicySnapshot,
  withPolicyStorageLock
} from "../src/policySnapshots.js";

test("creates compact policy snapshots with origin and hashes", async () => {
  const snapshot = await createPolicySnapshot({
    title: "Privacy",
    url: "https://service.example.com/privacy",
    text: "  We collect   email.  ",
    policyAnalysis: {
      level: "주의",
      score: 30,
      risks: [{ id: "retention_unclear" }],
      policySections: [
        {
          id: "collected_data",
          label: "수집 항목",
          found: true,
          evidence: [{ excerpt: "We collect email." }]
        }
      ]
    }
  });

  assert.equal(snapshot.origin, "https://service.example.com");
  assert.equal(snapshot.key, "https://service.example.com/privacy");
  assert.equal(snapshot.url, "https://service.example.com/privacy");
  assert.equal(snapshot.normalizedText, "We collect email.");
  assert.equal(snapshot.hashAlgorithm, "sha256");
  assert.equal(snapshot.textHash, "fcaa519a8ac6e50ccb2af8210983b956049d2f2d7eae2d7a56b91886f4b3b492");
  assert.equal(snapshot.policySections[0].hash, snapshot.textHash);
  assert.equal(snapshot.legacyTextHash, hashText("We collect email."));
  assert.equal(snapshot.policySections[0].legacyHash, hashText("We collect email."));
  assert.equal(await hashTextSecure("We collect email."), snapshot.textHash);
});

test("falls back to the legacy bounded hash when Web Crypto is unavailable", async () => {
  const cryptoDescriptor = Object.getOwnPropertyDescriptor(globalThis, "crypto");
  Object.defineProperty(globalThis, "crypto", { configurable: true, value: undefined });
  try {
    assert.equal(await hashTextSecure("fallback"), hashText("fallback"));
  } finally {
    if (cryptoDescriptor) Object.defineProperty(globalThis, "crypto", cryptoDescriptor);
    else delete globalThis.crypto;
  }
});

test("compares policy snapshots for section and risk changes", () => {
  const previous = {
    capturedAt: "2026-05-01T00:00:00.000Z",
    textHash: "old",
    policySections: [
      { id: "collected_data", label: "수집 항목", found: true, hash: "a", excerpt: "We collect email." }
    ],
    riskSummary: {
      riskIds: []
    }
  };
  const current = {
    textHash: "new",
    policySections: [
      { id: "collected_data", label: "수집 항목", found: true, hash: "b", excerpt: "We collect email and phone." },
      { id: "third_party", label: "제3자 제공", found: true, hash: "c", excerpt: "We share with partners." }
    ],
    riskSummary: {
      riskIds: ["broad_data_sharing"]
    }
  };

  const result = comparePolicySnapshot(previous, current);

  assert.equal(result.hasPrevious, true);
  assert.equal(result.changed, true);
  assert.ok(result.sectionChanges.some((change) => change.id === "collected_data" && change.changeType === "modified"));
  assert.ok(result.sectionChanges.some((change) => change.id === "third_party" && change.changeType === "added"));
  assert.ok(result.findings.some((finding) => finding.id === "policy_new_risks_added"));
  assert.ok(result.findings.some((finding) => finding.id === "policy_sections_changed" && finding.severity === "high"));
});

test("normalizes text and extracts origin safely", () => {
  assert.equal(normalizePolicyText(" A\n\n B\tC "), "A B C");
  assert.equal(originFromUrl("https://example.com/privacy?a=1"), "https://example.com");
  assert.equal(originFromUrl("not a url"), "");
  assert.equal(
    normalizePolicyUrl("https://user:password@example.com/privacy?token=secret#section"),
    ""
  );
  assert.equal(
    normalizePolicyUrl("https://example.com/privacy?v=2026.07&locale=ko-KR"),
    "https://example.com/privacy?v=2026.07&locale=ko-KR"
  );
  assert.equal(
    normalizePolicyUrl("https://example.com/privacy?locale=ko-KR&v=2026.07"),
    "https://example.com/privacy?locale=ko-KR&v=2026.07"
  );
  assert.equal(normalizePolicyUrl("https://example.com/privacy?utm_source=mail"), "");
  assert.equal(normalizePolicyUrl("https://example.com/privacy?gclid=variant-a"), "");
  assert.equal(normalizePolicyUrl("https://example.com/legal?document=privacy"), "");
  assert.equal(normalizePolicyUrl("https://example.com/privacy?return_to=%2Faccount"), "");
  assert.equal(normalizePolicyUrl("https://example.com/privacy?token=secret"), "");
  assert.equal(normalizePolicyUrl("https://example.com/privacy#section"), "");
  assert.equal(
    normalizePolicyUrl("https://example.com/privacy?lang=ko&lang=en&version=2026-07-19"),
    ""
  );
  assert.equal(
    normalizePolicyUrl("https://example.com/privacy?locale=../../private&version="),
    ""
  );
  assert.equal(normalizePolicyUrl("https://example.com/privacy?Lang=ko"), "");
  assert.equal(
    normalizePolicyUrl("https://example.com/privacy?hl=ko&lang=en&locale=ko-KR&v=2&version=2026"),
    ""
  );
  assert.equal(
    normalizePolicyUrl("https://example.com/privacy?locale=ko-KR&version=2026-07-19"),
    "https://example.com/privacy?locale=ko-KR&version=2026-07-19"
  );
  assert.notEqual(
    normalizePolicyUrl("https://example.com/privacy?lang=ko"),
    normalizePolicyUrl("https://example.com/privacy?lang=en")
  );
  assert.equal(normalizePolicyUrl("chrome://settings"), "");
  assert.equal(normalizePolicyUrl("http://example.com/privacy"), "");
  assert.equal(normalizePolicyUrl(`https://example.com/${"a".repeat(2050)}`), "");
});

test("hashes the complete policy even when the stored excerpt is truncated", async () => {
  const prefix = "a".repeat(80000);
  const policyAnalysis = { level: "low", score: 0, risks: [], policySections: [] };
  const before = await createPolicySnapshot({
    title: "Privacy",
    url: "https://example.com/privacy",
    text: `${prefix} before`,
    policyAnalysis
  });
  const after = await createPolicySnapshot({
    title: "Privacy",
    url: "https://example.com/privacy",
    text: `${prefix} after`,
    policyAnalysis
  });

  assert.equal(before.normalizedText.length, 80000);
  assert.equal(before.textTruncated, true);
  assert.notEqual(before.textHash, after.textHash);
  assert.equal(comparePolicySnapshot(before, after).changed, true);
});

test("compares legacy FNV baselines with SHA-256 snapshots without a migration false positive", async () => {
  const text = "We collect email.";
  const excerpt = "We collect email.";
  const current = await createPolicySnapshot({
    title: "Privacy",
    url: "https://example.com/privacy?lang=en",
    text,
    policyAnalysis: {
      level: "low",
      score: 0,
      risks: [],
      policySections: [
        { id: "collected_data", label: "Collected data", found: true, evidence: [{ excerpt }] }
      ]
    }
  });
  const legacy = {
    ...current,
    textHash: hashText(text),
    hashAlgorithm: "fnv1a64",
    legacyTextHash: "",
    policySections: current.policySections.map((section) => ({
      ...section,
      hash: hashText(excerpt),
      legacyHash: ""
    }))
  };

  const comparison = comparePolicySnapshot(legacy, current);
  assert.equal(comparison.changed, false);
  assert.deepEqual(comparison.sectionChanges, []);
});

test("does not let a legacy-hash collision override different SHA-256 digests", () => {
  const sharedLegacyHash = "0123456789abcdef";
  const comparison = comparePolicySnapshot(
    {
      capturedAt: "2026-07-18T00:00:00.000Z",
      textHash: "a".repeat(64),
      legacyTextHash: sharedLegacyHash,
      policySections: [],
      riskSummary: { riskIds: [] }
    },
    {
      textHash: "b".repeat(64),
      legacyTextHash: sharedLegacyHash,
      policySections: [],
      riskSummary: { riskIds: [] }
    }
  );

  assert.equal(comparison.changed, true);
  assert.ok(comparison.findings.some((finding) => finding.id === "policy_text_changed"));
});

test("migrates legacy origin-keyed snapshots to normalized policy URL keys", async () => {
  let migratedValue;
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {},
        get: async () => ({
          policySnapshots: {
            "https://example.com": {
              origin: "https://example.com",
              url: "https://example.com/privacy?lang=ko",
              capturedAt: "2026-05-01T00:00:00.000Z"
            }
          }
        }),
        set: async (value) => {
          migratedValue = value;
        }
      }
    }
  };

  const snapshots = await loadPolicySnapshots();
  assert.ok(snapshots["https://example.com/privacy?lang=ko"]);
  assert.equal(snapshots["https://example.com/privacy?lang=ko"].url, "https://example.com/privacy?lang=ko");
  assert.ok(migratedValue.policySnapshots["https://example.com/privacy?lang=ko"]);
  delete globalThis.chrome;
});

test("fails closed before direct policy storage reads or writes", async () => {
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
    await assert.rejects(loadPolicySnapshots(), /Trusted local storage access is unavailable/);
    await assert.rejects(
      savePolicySnapshot({ key: "https://example.com/privacy", url: "https://example.com/privacy" }),
      /Trusted local storage access is unavailable/
    );
    assert.deepEqual(calls, { access: 2, get: 0, set: 0 });
  } finally {
    delete globalThis.chrome;
  }
});

test("preserves policy-storage fallbacks when local storage is absent", async () => {
  delete globalThis.chrome;
  assert.deepEqual(await loadPolicySnapshots(), {});
  assert.equal(await savePolicySnapshot({}), undefined);
  assert.deepEqual(await recordPolicyCheckResults([], "not-a-timestamp"), {});
});

test("fails explicitly when the policy storage getter throws", async () => {
  globalThis.chrome = {
    storage: Object.defineProperty({}, "local", {
      get() {
        throw new Error("getter denied");
      }
    })
  };
  try {
    await assert.rejects(loadPolicySnapshots(), /Trusted local storage access is unavailable/);
  } finally {
    delete globalThis.chrome;
  }
});

test("upgrades a complete untruncated legacy FNV text hash to SHA-256 on load", async () => {
  const normalizedText = "We collect email.";
  let storedSnapshots = {
    "https://example.com/privacy": {
      key: "https://example.com/privacy",
      origin: "https://example.com",
      url: "https://example.com/privacy",
      capturedAt: "2026-05-01T00:00:00.000Z",
      textHash: hashText(normalizedText),
      hashAlgorithm: "fnv1a64",
      textLength: normalizedText.length,
      textTruncated: false,
      normalizedText,
      policySections: [],
      riskSummary: { riskIds: [] }
    }
  };
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {},
        async get() {
          return { policySnapshots: storedSnapshots };
        },
        async set(value) {
          if (value.policySnapshots) storedSnapshots = value.policySnapshots;
        }
      }
    }
  };

  const snapshots = await loadPolicySnapshots();
  const migrated = snapshots["https://example.com/privacy"];
  assert.equal(migrated.textHash, await hashTextSecure(normalizedText));
  assert.equal(migrated.textHash.length, 64);
  assert.equal(migrated.hashAlgorithm, "sha256");
  assert.equal(migrated.legacyTextHash, hashText(normalizedText));
  assert.equal(storedSnapshots["https://example.com/privacy"].textHash, migrated.textHash);
  delete globalThis.chrome;
});

test("does not upgrade a truncated or unverifiable legacy text baseline", async () => {
  const normalizedText = "partial policy";
  let setCalls = 0;
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {},
        async get() {
          return {
            policySnapshots: {
              "https://example.com/privacy": {
                key: "https://example.com/privacy",
                url: "https://example.com/privacy",
                capturedAt: "2026-05-01T00:00:00.000Z",
                textHash: hashText(normalizedText),
                textLength: normalizedText.length + 10,
                textTruncated: true,
                normalizedText
              }
            }
          };
        },
        async set() {
          setCalls += 1;
        }
      }
    }
  };

  const snapshot = (await loadPolicySnapshots())["https://example.com/privacy"];
  assert.equal(snapshot.textHash, hashText(normalizedText));
  assert.equal(snapshot.hashAlgorithm, "fnv1a64");
  assert.equal(setCalls, 0);
  delete globalThis.chrome;
});

test("serializes concurrent policy snapshot read-modify-write operations", async () => {
  let policySnapshots = {};
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {},
        async get(key) {
          await new Promise((resolve) => setTimeout(resolve, 5));
          if (key === "policySnapshots") return { policySnapshots: structuredClone(policySnapshots) };
          if (key === "notifiedPolicyChanges") return { notifiedPolicyChanges: {} };
          return {};
        },
        async set(value) {
          await new Promise((resolve) => setTimeout(resolve, 5));
          if (value.policySnapshots) policySnapshots = structuredClone(value.policySnapshots);
        }
      }
    }
  };

  await Promise.all([
    savePolicySnapshot({ key: "https://a.example/privacy", url: "https://a.example/privacy" }),
    savePolicySnapshot({ key: "https://b.example/privacy", url: "https://b.example/privacy" })
  ]);

  assert.deepEqual(Object.keys(policySnapshots).sort(), [
    "https://a.example/privacy",
    "https://b.example/privacy"
  ]);
  delete globalThis.chrome;
});

test("records privacy-minimized policy check health for the exact current baseline", async () => {
  const snapshotKey = "https://example.com/privacy?lang=ko";
  const baselineCapturedAt = "2026-07-19T00:00:00.000Z";
  const stored = {
    policySnapshots: {
      [snapshotKey]: {
        key: snapshotKey,
        url: snapshotKey,
        capturedAt: baselineCapturedAt
      }
    }
  };
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {},
        async get(keys) {
          const requestedKeys = Array.isArray(keys) ? keys : [keys];
          return Object.fromEntries(
            requestedKeys
              .filter((key) => Object.prototype.hasOwnProperty.call(stored, key))
              .map((key) => [key, structuredClone(stored[key])])
          );
        },
        async set(value) {
          Object.assign(stored, structuredClone(value));
        }
      }
    }
  };

  try {
    let health = await recordPolicyCheckResults(
      [{
        snapshotKey,
        baselineCapturedAt,
        ok: false,
        errorCategory: "timeout",
        error: "secret response detail that must not be stored"
      }],
      "2026-07-19T01:00:00Z"
    );
    assert.deepEqual(health[snapshotKey], {
      lastAttemptAt: "2026-07-19T01:00:00.000Z",
      lastSuccessAt: "",
      consecutiveFailures: 1,
      errorCategory: "timeout"
    });
    assert.equal(JSON.stringify(stored[POLICY_CHECK_HEALTH_KEY]).includes("secret response"), false);

    health = await recordPolicyCheckResults(
      [{ snapshotKey, baselineCapturedAt, ok: false, errorCategory: "arbitrary raw failure" }],
      "2026-07-19T02:00:00Z"
    );
    assert.equal(health[snapshotKey].consecutiveFailures, 2);
    assert.equal(health[snapshotKey].errorCategory, "unknown");

    health = await recordPolicyCheckResults(
      [{ snapshotKey, baselineCapturedAt, ok: true }],
      "2026-07-19T03:00:00Z"
    );
    assert.deepEqual(health[snapshotKey], {
      lastAttemptAt: "2026-07-19T03:00:00.000Z",
      lastSuccessAt: "2026-07-19T03:00:00.000Z",
      consecutiveFailures: 0,
      errorCategory: ""
    });
    assert.ok(POLICY_CHECK_ERROR_CATEGORIES.includes("not_policy"));
  } finally {
    delete globalThis.chrome;
  }
});

test("ignores stale results and prunes malformed or orphaned policy health", async () => {
  const snapshotKey = "https://example.com/privacy";
  const baselineCapturedAt = "2026-07-19T00:00:00.000Z";
  const stored = {
    policySnapshots: {
      [snapshotKey]: { key: snapshotKey, url: snapshotKey, capturedAt: baselineCapturedAt }
    },
    [POLICY_CHECK_HEALTH_KEY]: {
      [snapshotKey]: {
        lastAttemptAt: "2026-07-19T00:30:00Z",
        lastSuccessAt: "",
        consecutiveFailures: 1,
        errorCategory: "network",
        rawError: "must be removed"
      },
      "https://orphan.example/privacy": {
        lastAttemptAt: "2026-07-19T00:30:00Z",
        lastSuccessAt: "",
        consecutiveFailures: 1,
        errorCategory: "timeout"
      },
      "http://example.com/privacy": {
        lastAttemptAt: "2026-07-19T00:30:00Z",
        lastSuccessAt: "",
        consecutiveFailures: 1,
        errorCategory: "timeout"
      }
    }
  };
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {},
        async get(keys) {
          const requestedKeys = Array.isArray(keys) ? keys : [keys];
          return Object.fromEntries(
            requestedKeys
              .filter((key) => Object.prototype.hasOwnProperty.call(stored, key))
              .map((key) => [key, structuredClone(stored[key])])
          );
        },
        async set(value) {
          Object.assign(stored, structuredClone(value));
        }
      }
    }
  };

  try {
    const sanitized = await loadPolicyCheckHealth();
    assert.deepEqual(Object.keys(sanitized), [snapshotKey]);
    assert.deepEqual(Object.keys(sanitized[snapshotKey]), [
      "lastAttemptAt",
      "lastSuccessAt",
      "consecutiveFailures",
      "errorCategory"
    ]);

    const afterStaleResult = await recordPolicyCheckResults(
      [{
        snapshotKey,
        baselineCapturedAt: "2026-07-18T00:00:00.000Z",
        ok: true
      }],
      "2026-07-19T02:00:00Z"
    );
    assert.equal(afterStaleResult[snapshotKey].lastAttemptAt, "2026-07-19T00:30:00.000Z");
    assert.equal(afterStaleResult[snapshotKey].consecutiveFailures, 1);
  } finally {
    delete globalThis.chrome;
  }
});

test("saving or deleting a policy baseline clears its check health and prunes orphans", async () => {
  const firstKey = "https://a.example/privacy";
  const secondKey = "https://b.example/privacy";
  const capturedAt = "2026-07-19T00:00:00.000Z";
  const stored = {
    policySnapshots: {
      [firstKey]: { key: firstKey, url: firstKey, capturedAt },
      [secondKey]: { key: secondKey, url: secondKey, capturedAt }
    },
    notifiedPolicyChanges: {},
    [POLICY_CHECK_HEALTH_KEY]: Object.fromEntries(
      [firstKey, secondKey].map((key) => [key, {
        lastAttemptAt: "2026-07-19T01:00:00.000Z",
        lastSuccessAt: "",
        consecutiveFailures: 1,
        errorCategory: "network"
      }])
    )
  };
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {},
        async get(keys) {
          const requestedKeys = Array.isArray(keys) ? keys : [keys];
          return Object.fromEntries(
            requestedKeys
              .filter((key) => Object.prototype.hasOwnProperty.call(stored, key))
              .map((key) => [key, structuredClone(stored[key])])
          );
        },
        async set(value) {
          Object.assign(stored, structuredClone(value));
        }
      }
    }
  };

  try {
    await savePolicySnapshot({ key: firstKey, url: firstKey, capturedAt: "2026-07-19T02:00:00Z" });
    assert.equal(stored[POLICY_CHECK_HEALTH_KEY][firstKey], undefined);
    assert.equal(stored[POLICY_CHECK_HEALTH_KEY][secondKey].consecutiveFailures, 1);

    assert.equal(await deletePolicySnapshot(secondKey), true);
    assert.deepEqual(stored[POLICY_CHECK_HEALTH_KEY], {});
  } finally {
    delete globalThis.chrome;
  }
});

test("uses the browser-wide Web Lock when navigator.locks is available", async () => {
  const navigatorDescriptor = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  const requests = [];
  Object.defineProperty(globalThis, "navigator", {
    configurable: true,
    value: {
      locks: {
        async request(name, options, task) {
          requests.push({ name, options });
          return task();
        }
      }
    }
  });
  try {
    assert.equal(await withPolicyStorageLock(async () => "done"), "done");
    assert.deepEqual(requests, [
      { name: "unveily-policy-snapshots", options: { mode: "exclusive" } }
    ]);
  } finally {
    if (navigatorDescriptor) Object.defineProperty(globalThis, "navigator", navigatorDescriptor);
    else delete globalThis.navigator;
  }
});

test("does not compare a different policy path merely because the origin matches", async () => {
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {},
        get: async () => ({
          policySnapshots: {
            "https://example.com/privacy": {
              key: "https://example.com/privacy",
              origin: "https://example.com",
              url: "https://example.com/privacy",
              capturedAt: "2026-05-01T00:00:00.000Z"
            }
          }
        }),
        set: async () => {}
      }
    }
  };

  assert.equal(await loadPolicySnapshot("https://example.com/terms"), null);
  assert.equal((await loadPolicySnapshot("https://example.com/privacy"))?.key, "https://example.com/privacy");
  delete globalThis.chrome;
});

test("never treats a root URL as an origin-wide lookup or delete command", async () => {
  let policySnapshots = {
    "https://example.com/privacy": {
      key: "https://example.com/privacy",
      url: "https://example.com/privacy",
      capturedAt: "2026-05-01T00:00:00.000Z"
    },
    "https://example.com/terms": {
      key: "https://example.com/terms",
      url: "https://example.com/terms",
      capturedAt: "2026-05-02T00:00:00.000Z"
    }
  };
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {},
        async get(key) {
          if (key === "policySnapshots") return { policySnapshots };
          if (key === "notifiedPolicyChanges") return { notifiedPolicyChanges: {} };
          return {};
        },
        async set(value) {
          if (value.policySnapshots) policySnapshots = value.policySnapshots;
        }
      }
    }
  };

  assert.equal(await loadPolicySnapshot("https://example.com/"), null);
  assert.equal(await deletePolicySnapshot("https://example.com/"), false);
  assert.deepEqual(Object.keys(policySnapshots).sort(), [
    "https://example.com/privacy",
    "https://example.com/terms"
  ]);
  assert.equal(await deletePolicySnapshot("https://example.com/privacy"), true);
  assert.deepEqual(Object.keys(policySnapshots), ["https://example.com/terms"]);
  delete globalThis.chrome;
});

test("drops malformed snapshot keys instead of trusting local storage object keys", async () => {
  let migratedValue;
  globalThis.chrome = {
    storage: {
      local: {
        async setAccessLevel() {},
        get: async () => ({
          policySnapshots: {
            __proto_pollution_attempt__: { key: "__proto__", url: "javascript:alert(1)" }
          }
        }),
        set: async (value) => {
          migratedValue = value;
        }
      }
    }
  };

  assert.deepEqual(await loadPolicySnapshots(), {});
  assert.deepEqual(migratedValue.policySnapshots, {});
  delete globalThis.chrome;
});

test("prunes old policy snapshots to avoid local storage growth", () => {
  const snapshots = Object.fromEntries(
    Array.from({ length: 4 }, (_value, index) => [
      `https://example-${index}.com`,
      {
        origin: `https://example-${index}.com`,
        capturedAt: `2026-05-0${index + 1}T00:00:00.000Z`
      }
    ])
  );

  const pruned = prunePolicySnapshots(snapshots, 2);

  assert.equal(Object.keys(pruned).length, 2);
  assert.ok(pruned["https://example-3.com"]);
  assert.ok(pruned["https://example-2.com"]);
});

test("prunes snapshots by serialized byte budget as well as count", () => {
  const snapshots = {
    "https://old.example/privacy": {
      capturedAt: "2026-05-01T00:00:00.000Z",
      normalizedText: "가".repeat(120)
    },
    "https://new.example/privacy": {
      capturedAt: "2026-05-02T00:00:00.000Z",
      normalizedText: "나".repeat(120)
    }
  };

  const pruned = prunePolicySnapshots(snapshots, 50, 500);
  assert.deepEqual(Object.keys(pruned), ["https://new.example/privacy"]);
});
