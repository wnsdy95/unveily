import { sanitizeNetworkUrl } from "./backgroundSecurity.js";

export function buildReportPayload(input) {
  return {
    generatedAt: new Date().toISOString(),
    source: normalizeReportSource(input.source),
    analysis: {
      policy: input.policyAnalysis || null,
      network: sanitizeNetworkReport(input.networkAnalysis),
      form: sanitizeFormReport(input.formAnalysis),
      storage: sanitizeStorageReport(input.storageAnalysis),
      consent: sanitizeConsentReport(input.consentAnalysis),
      delta: input.deltaAnalysis || null,
      jurisdiction: input.jurisdictionAnalysis || null,
      alignment: input.alignmentAnalysis || null,
      policyChange: input.policyChangeAnalysis || null
    }
  };
}

export function buildJsonReport(payload) {
  return JSON.stringify(payload, null, 2);
}

export function buildMarkdownReport(payload) {
  const source = payload.source || {};
  const analysis = payload.analysis || {};
  const policy = analysis.policy || {};
  const network = analysis.network || {};
  const jurisdiction = analysis.jurisdiction || {};
  const alignment = analysis.alignment || {};
  const policyChange = analysis.policyChange || {};

  return [
    "# unveily Report",
    "",
    `- Generated: ${payload.generatedAt}`,
    `- Source: ${markdownInline(source.title || "Untitled")}`,
    `- URL: ${markdownInline(source.url || "N/A")}`,
    "",
    "## Summary",
    "",
    `- Risk level: ${markdownInline(policy.level || "N/A")}`,
    `- Risk score: ${markdownInline(policy.score ?? "N/A")}`,
    `- Behavior-policy alignment: ${markdownInline(alignment.score ?? "N/A")}${alignment.score === undefined ? "" : "%"}`,
    `- Applied jurisdiction: ${markdownInline(jurisdiction.jurisdiction?.label || "N/A")}`,
    "",
    markdownInline(policy.summary || ""),
    "",
    "## Key Risks",
    "",
    markdownFindings(policy.risks, "No key policy risks detected."),
    "",
    "## Jurisdiction Findings",
    "",
    markdownFindings(jurisdiction.findings, "No jurisdiction-specific findings detected."),
    "",
    "## Behavior Alignment Findings",
    "",
    markdownFindings(alignment.findings, "Observed behavior appears aligned with policy evidence."),
    "",
    "## Policy Change Findings",
    "",
    markdownFindings(policyChange.findings, "No saved policy change findings detected."),
    "",
    "## Policy Section Diffs",
    "",
    markdownSectionDiffs(policyChange.sectionChanges),
    "",
    "## Network Vendors",
    "",
    markdownVendors(network.vendorSummary),
    "",
    "## Policy Evidence Sections",
    "",
    markdownPolicySections(policy.policySections),
    "",
    "## Notes",
    "",
    "This is a rule-based first-pass review. It is not legal advice or a complete security audit."
  ].join("\n");
}

export function buildReportFileName(source, extension, date = new Date()) {
  const host = safeFilePart(hostFromUrl(source?.url) || source?.title || "report");
  const datePart = date.toISOString().slice(0, 10);
  return `unveily-report-${host}-${datePart}.${extension}`;
}

export function downloadTextFile(content, fileName, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  link.click();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

function markdownFindings(findings, emptyMessage) {
  if (!Array.isArray(findings) || findings.length === 0) return `- ${emptyMessage}`;

  return findings
    .map((finding) => {
      const severity = finding.severity ? ` (${finding.severity})` : "";
      const detail = finding.detail || finding.evidence || "";
      const advice = finding.advice ? `\n  - Advice: ${finding.advice}` : "";
      return `- ${markdownInline(finding.title || finding.id)}${markdownInline(severity)}\n  - Detail: ${markdownInline(detail)}${
        advice ? `\n  - Advice: ${markdownInline(finding.advice)}` : ""
      }`;
    })
    .join("\n");
}

function markdownVendors(vendors) {
  if (!Array.isArray(vendors) || vendors.length === 0) return "- No third-party vendors classified.";

  return vendors
    .map(
      (vendor) =>
        `- ${markdownInline(vendor.vendor)} (${markdownInline(vendor.category)})\n  - Host: ${markdownInline(vendor.host)}\n  - Missing policy sections: ${
          markdownInline(vendor.missingPolicySections?.join(", ") || "None")
        }`
    )
    .join("\n");
}

function markdownPolicySections(sections) {
  if (!Array.isArray(sections) || sections.length === 0) return "- No policy sections extracted.";

  return sections
    .filter((section) => section.found)
    .map((section) => `- ${markdownInline(section.label)}\n  - ${markdownInline(section.evidence?.[0]?.excerpt || "")}`)
    .join("\n");
}

function markdownSectionDiffs(sectionChanges) {
  if (!Array.isArray(sectionChanges) || sectionChanges.length === 0) return "- No section-level diffs available.";

  return sectionChanges
    .map((change) => {
      const before = change.before ? `\n  - Before: ${markdownInline(change.before)}` : "";
      const after = change.after ? `\n  - After: ${markdownInline(change.after)}` : "";
      return `- ${markdownInline(change.label)} (${markdownInline(change.changeType)})${before}${after}`;
    })
    .join("\n");
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function safeFilePart(value) {
  const safeValue = String(value || "report")
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
  return safeValue || "report";
}

function normalizeReportSource(source = {}) {
  const url = sanitizeReportUrl(source?.url);
  return {
    title: url ? hostFromUrl(url) : String(source?.title || "").slice(0, 300),
    url
  };
}

function sanitizeReportUrl(url) {
  return sanitizeNetworkUrl(url, { maxSegments: 6, maxLength: 240 })?.url || "";
}

function sanitizeNetworkReport(analysis) {
  if (!analysis || typeof analysis !== "object") return null;
  return {
    requestCount: boundedCount(analysis.requestCount),
    thirdPartyHosts: boundedStrings(analysis.thirdPartyHosts, 100, 255),
    trackerHosts: boundedStrings(analysis.trackerHosts, 100, 255),
    vendorSummary: Array.isArray(analysis.vendorSummary)
      ? analysis.vendorSummary.slice(0, 100).map((vendor) => ({
          vendor: String(vendor?.vendor || "").slice(0, 160),
          host: String(vendor?.host || "").slice(0, 255),
          category: String(vendor?.category || "").slice(0, 80),
          risk: String(vendor?.risk || "").slice(0, 40),
          missingPolicySections: boundedStrings(vendor?.missingPolicySections, 40, 120)
        }))
      : [],
    sensitiveFieldCount: Array.isArray(analysis.sensitiveFields)
      ? Math.min(1_000, analysis.sensitiveFields.length)
      : boundedCount(analysis.sensitiveFieldCount),
    findings: sanitizeMetadataFindings(analysis.findings)
  };
}

function sanitizeFormReport(analysis) {
  if (!analysis || typeof analysis !== "object") return null;
  return {
    fieldCount: boundedCount(analysis.fieldCount),
    sensitiveFieldCount: boundedCount(analysis.sensitiveFieldCount),
    categories: Array.isArray(analysis.categories)
      ? analysis.categories.slice(0, 40).map((category) => {
          const fields = Array.isArray(category?.fields) ? category.fields.slice(0, 1_000) : [];
          return {
            id: String(category?.id || "").slice(0, 120),
            label: String(category?.label || "").slice(0, 160),
            fieldCount: fields.length,
            requiredCount: fields.filter((field) => field?.required).length
          };
        })
      : [],
    findings: sanitizeMetadataFindings(analysis.findings)
  };
}

function sanitizeStorageReport(analysis) {
  if (!analysis || typeof analysis !== "object") return null;
  return {
    localStorageKeyCount: boundedCount(analysis.localStorageKeyCount),
    sessionStorageKeyCount: boundedCount(analysis.sessionStorageKeyCount),
    cookieCount: boundedCount(analysis.cookieCount),
    thirdPartyCookieCount: boundedCount(analysis.thirdPartyCookieCount),
    classifiedStorage: Array.isArray(analysis.classifiedStorage)
      ? analysis.classifiedStorage.slice(0, 40).map((item) => ({
          category: String(item?.category || "").slice(0, 120),
          label: String(item?.label || "").slice(0, 160),
          keyCount: Array.isArray(item?.keys) ? Math.min(1_000, item.keys.length) : 0
        }))
      : [],
    findings: sanitizeMetadataFindings(analysis.findings)
  };
}

function sanitizeConsentReport(analysis) {
  if (!analysis || typeof analysis !== "object") return null;
  const scalarKeys = [
    "detected",
    "bannerCount",
    "rejectAvailable",
    "acceptAvailable",
    "preferenceAvailable",
    "trackingRequestCount",
    "trackingCookieCount",
    "preChoiceTrackingRequestCount",
    "preChoiceTrackingCookieCount",
    "postChoiceTrackingRequestCount",
    "postChoiceTrackingCookieCount",
    "unclassifiedTrackingRequestCount",
    "unclassifiedTrackingCookieCount",
    "ignoredPreObservationTrackingRequestCount",
    "ignoredPreObservationTrackingCookieCount",
    "choiceKind",
    "disabledTrackingToggleCount"
  ];
  const result = Object.fromEntries(
    scalarKeys
      .filter((key) => ["boolean", "number", "string"].includes(typeof analysis[key]))
      .map((key) => [key, typeof analysis[key] === "number" ? boundedCount(analysis[key]) : analysis[key]])
  );
  result.consentCategories = Array.isArray(analysis.consentCategories)
    ? analysis.consentCategories.slice(0, 20).map(sanitizeConsentCategory)
    : [];
  result.choiceAnalyses = Array.isArray(analysis.choiceAnalyses)
    ? analysis.choiceAnalyses.slice(0, 20).map((choice) => ({
        type: String(choice?.type || "").slice(0, 80),
        riskLevel: String(choice?.riskLevel || "").slice(0, 40),
        safetyLabel: String(choice?.safetyLabel || "").slice(0, 160),
        allowedCategories: Array.isArray(choice?.allowedCategories)
          ? choice.allowedCategories.slice(0, 20).map(sanitizeConsentCategory)
          : [],
        concerns: boundedStrings(choice?.concerns, 20, 500),
        summary: String(choice?.summary || "").slice(0, 1_000)
      }))
    : [];
  result.timing = sanitizeConsentTiming(analysis.timing);
  result.findings = sanitizeMetadataFindings(analysis.findings);
  return result;
}

function sanitizeConsentCategory(category) {
  return {
    id: String(category?.id || "").slice(0, 120),
    label: String(category?.label || "").slice(0, 160),
    risk: String(category?.risk || "").slice(0, 40),
    reason: String(category?.reason || "").slice(0, 500),
    defaultEnabled: Boolean(category?.defaultEnabled)
  };
}

function sanitizeConsentTiming(timing) {
  if (!timing || typeof timing !== "object") return null;
  return Object.fromEntries(
    ["observationStartedAt", "snapshotAt", "choiceAt", "boundaryAt", "choiceKind", "boundarySource"]
      .filter((key) => ["number", "string"].includes(typeof timing[key]))
      .map((key) => [key, typeof timing[key] === "string" ? timing[key].slice(0, 120) : timing[key]])
  );
}

function sanitizeMetadataFindings(findings) {
  if (!Array.isArray(findings)) return [];
  return findings.slice(0, 100).map((finding) => ({
    id: String(finding?.id || "").slice(0, 160),
    severity: String(finding?.severity || "").slice(0, 40),
    confidence: String(finding?.confidence || "").slice(0, 40),
    title: String(finding?.title || "").slice(0, 500),
    advice: String(finding?.advice || "").slice(0, 1_000)
  }));
}

function boundedStrings(values, maxItems, maxLength) {
  return Array.isArray(values)
    ? values.slice(0, maxItems).map((value) => String(value || "").slice(0, maxLength)).filter(Boolean)
    : [];
}

function boundedCount(value) {
  return Number.isFinite(Number(value))
    ? Math.max(0, Math.min(1_000_000, Math.trunc(Number(value))))
    : 0;
}

function markdownInline(value) {
  return String(value ?? "")
    .replace(/[\r\n]+/g, " ")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\\/g, "\\\\")
    .replace(/([`*_{}\[\]#+.!|-])/g, "\\$1")
    .trim();
}
