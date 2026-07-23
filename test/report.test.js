import assert from "node:assert/strict";
import test from "node:test";
import { buildJsonReport, buildMarkdownReport, buildReportFileName, buildReportPayload } from "../src/report.js";

test("builds JSON and Markdown reports from analysis payload", () => {
  const payload = buildReportPayload({
    source: {
      title: "Example Terms",
      url: "https://service.example.com/privacy"
    },
    policyAnalysis: {
      level: "주의",
      score: 42,
      summary: "위험도는 주의입니다.",
      risks: [{ id: "risk", title: "제3자 제공", severity: "medium", advice: "확인하세요." }],
      policySections: [{ id: "collected_data", label: "수집 항목", found: true, evidence: [{ excerpt: "We collect email." }] }]
    },
    networkAnalysis: {
      vendorSummary: [{ vendor: "Stripe", category: "payment", host: "js.stripe.com", missingPolicySections: ["processors"] }]
    },
    jurisdictionAnalysis: {
      jurisdiction: { label: "GDPR/EU" },
      findings: [{ id: "gdpr", title: "법적 근거 누락", severity: "high", detail: "법적 근거가 없습니다." }]
    },
    alignmentAnalysis: {
      score: 67,
      findings: [{ id: "alignment", title: "보유 기간 근거 부족", severity: "medium", detail: "보유 기간 없음" }]
    },
    policyChangeAnalysis: {
      findings: [{ id: "policy_text_changed", title: "정책 원문 변경 감지", severity: "medium", detail: "이전 저장본과 다름" }],
      sectionChanges: [
        {
          label: "제3자 제공",
          changeType: "modified",
          before: "We do not share personal data.",
          after: "We may share personal data with partners."
        }
      ]
    }
  });

  const json = buildJsonReport(payload);
  const markdown = buildMarkdownReport(payload);

  assert.equal(JSON.parse(json).source.url, "https://service.example.com/privacy");
  assert.match(markdown, /unveily Report/);
  assert.match(markdown, /Stripe/);
  assert.match(markdown, /GDPR\/EU/);
  assert.match(markdown, /정책 원문 변경 감지/);
  assert.match(markdown, /Before: We do not share personal data/);
  assert.match(markdown, /After: We may share personal data with partners/);
});

test("builds safe report file names", () => {
  const fileName = buildReportFileName(
    {
      url: "https://Service.Example.com/privacy?a=1"
    },
    "md",
    new Date("2026-05-12T00:00:00.000Z")
  );

  assert.equal(fileName, "unveily-report-service.example.com-2026-05-12.md");
});

test("falls back to a stable filename when the source title has no ASCII slug", () => {
  assert.equal(
    buildReportFileName({ title: "붙여넣은 텍스트", url: "" }, "json", new Date("2026-01-02T00:00:00.000Z")),
    "unveily-report-report-2026-01-02.json"
  );
});

test("removes credentials and query secrets from report sources", () => {
  const payload = buildReportPayload({
    source: {
      title: "Private report",
      url: "https://user:password@example.com/privacy?access_token=secret#account"
    }
  });

  assert.deepEqual(payload.source, {
    title: "example.com",
    url: "https://example.com/privacy"
  });
  assert.doesNotMatch(buildJsonReport(payload), /password|access_token|secret/);
});

test("aggregates page identifiers out of exported report metadata", () => {
  const payload = buildReportPayload({
    source: {
      title: "Alice's private dashboard",
      url: "https://example.com/users/alice?account=alice#profile"
    },
    networkAnalysis: {
      requestCount: 1,
      thirdPartyHosts: [],
      trackerHosts: [],
      vendorSummary: [],
      sensitiveFields: ["user_alice"]
    },
    formAnalysis: {
      fieldCount: 1,
      sensitiveFieldCount: 1,
      categories: [{ id: "contact", label: "Contact", fields: [{ name: "email_alice", descriptor: "Alice email", required: true }] }],
      findings: [{ id: "form", severity: "high", title: "Form metadata", detail: "email_alice", advice: "Review" }]
    },
    storageAnalysis: {
      localStorageKeyCount: 1,
      sessionStorageKeyCount: 0,
      cookieCount: 0,
      thirdPartyCookieCount: 0,
      classifiedStorage: [{ category: "account", label: "Account", keys: ["session_alice"] }],
      findings: [{ id: "storage", severity: "medium", title: "Storage metadata", detail: "session_alice", advice: "Review" }]
    },
    consentAnalysis: {
      detected: true,
      choiceAnalyses: [{ type: "accept_all", label: "Accept for Alice", allowedCategories: [], concerns: [], summary: "Accept all", riskLevel: "high" }],
      findings: []
    }
  });
  const json = buildJsonReport(payload);

  assert.equal(payload.source.title, "example.com");
  assert.equal(payload.source.url, "https://example.com/users/:segment");
  assert.deepEqual(payload.analysis.form.categories[0], {
    id: "contact",
    label: "Contact",
    fieldCount: 1,
    requiredCount: 1
  });
  assert.deepEqual(payload.analysis.storage.classifiedStorage[0], {
    category: "account",
    label: "Account",
    keyCount: 1
  });
  assert.equal(payload.analysis.network.sensitiveFieldCount, 1);
  assert.doesNotMatch(json, /alice|email_alice|session_alice|Alice's private dashboard/i);
});

test("escapes page-controlled Markdown syntax in exported findings", () => {
  const markdown = buildMarkdownReport(
    buildReportPayload({
      source: { title: "![tracker](https://attacker.test/pixel)", url: "https://example.com" },
      policyAnalysis: {
        level: "low",
        score: 0,
        risks: [
          {
            title: "[deceptive link](https://attacker.test)",
            severity: "low",
            evidence: "<img src=https://attacker.test/pixel>",
            advice: "review"
          }
        ],
        policySections: []
      }
    })
  );

  assert.doesNotMatch(markdown, /!\[tracker\]\(https:\/\/attacker\.test\/pixel\)/);
  assert.doesNotMatch(markdown, /<img src=/);
  assert.match(markdown, /- Source: example\\\.com/);
});
