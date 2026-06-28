export function buildReportPayload(input) {
  return {
    generatedAt: new Date().toISOString(),
    source: input.source || {},
    analysis: {
      policy: input.policyAnalysis || null,
      network: input.networkAnalysis || null,
      form: input.formAnalysis || null,
      storage: input.storageAnalysis || null,
      consent: input.consentAnalysis || null,
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
    `- Source: ${source.title || "Untitled"}`,
    `- URL: ${source.url || "N/A"}`,
    "",
    "## Summary",
    "",
    `- Risk level: ${policy.level || "N/A"}`,
    `- Risk score: ${policy.score ?? "N/A"}`,
    `- Behavior-policy alignment: ${alignment.score ?? "N/A"}${alignment.score === undefined ? "" : "%"}`,
    `- Applied jurisdiction: ${jurisdiction.jurisdiction?.label || "N/A"}`,
    "",
    policy.summary || "",
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
  URL.revokeObjectURL(url);
}

function markdownFindings(findings, emptyMessage) {
  if (!Array.isArray(findings) || findings.length === 0) return `- ${emptyMessage}`;

  return findings
    .map((finding) => {
      const severity = finding.severity ? ` (${finding.severity})` : "";
      const detail = finding.detail || finding.evidence || "";
      const advice = finding.advice ? `\n  - Advice: ${finding.advice}` : "";
      return `- ${finding.title || finding.id}${severity}\n  - Detail: ${detail}${advice}`;
    })
    .join("\n");
}

function markdownVendors(vendors) {
  if (!Array.isArray(vendors) || vendors.length === 0) return "- No third-party vendors classified.";

  return vendors
    .map(
      (vendor) =>
        `- ${vendor.vendor} (${vendor.category})\n  - Host: ${vendor.host}\n  - Missing policy sections: ${
          vendor.missingPolicySections?.join(", ") || "None"
        }`
    )
    .join("\n");
}

function markdownPolicySections(sections) {
  if (!Array.isArray(sections) || sections.length === 0) return "- No policy sections extracted.";

  return sections
    .filter((section) => section.found)
    .map((section) => `- ${section.label}\n  - ${section.evidence?.[0]?.excerpt || ""}`)
    .join("\n");
}

function markdownSectionDiffs(sectionChanges) {
  if (!Array.isArray(sectionChanges) || sectionChanges.length === 0) return "- No section-level diffs available.";

  return sectionChanges
    .map((change) => {
      const before = change.before ? `\n  - Before: ${change.before}` : "";
      const after = change.after ? `\n  - After: ${change.after}` : "";
      return `- ${change.label} (${change.changeType})${before}${after}`;
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
  return String(value || "report")
    .toLowerCase()
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80);
}
