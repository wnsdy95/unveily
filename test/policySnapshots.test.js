import assert from "node:assert/strict";
import test from "node:test";
import {
  comparePolicySnapshot,
  createPolicySnapshot,
  hashText,
  normalizePolicyText,
  originFromUrl,
  prunePolicySnapshots
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
  assert.equal(snapshot.normalizedText, "We collect email.");
  assert.equal(snapshot.textHash, hashText("We collect email."));
  assert.equal(snapshot.policySections[0].hash, hashText("We collect email."));
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
