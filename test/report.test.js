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
