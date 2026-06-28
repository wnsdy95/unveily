import {
  analyzeClientStorage,
  analyzeConsentCompliance,
  analyzeBehaviorPolicyAlignment,
  analyzeFormFields,
  analyzeJurisdictionCompliance,
  analyzeNetworkActivity,
  analyzeObservationDelta,
  analyzePolicy
} from "./analyzer.js";
import { loadCustomVendorRules } from "./customRulesStorage.js";
import {
  buildJsonReport,
  buildMarkdownReport,
  buildReportFileName,
  buildReportPayload,
  downloadTextFile
} from "./report.js";
import {
  comparePolicySnapshot,
  createPolicySnapshot,
  deletePolicySnapshot,
  loadPolicySnapshot,
  originFromUrl,
  savePolicySnapshot
} from "./policySnapshots.js";
import { applyI18n, getLocalePreference, localeCode, setLocalePreference, t } from "./i18n.js";

let latestSourceText = "";
let latestSource = null;
let latestReportPayload = null;
let latestPolicySnapshot = null;
let latestAnalysisMode = "page";

const analyzePageButton = document.querySelector("#analyzePageButton");
const analyzeCookiesButton = document.querySelector("#analyzeCookiesButton");
const analyzePasteButton = document.querySelector("#analyzePasteButton");
const saveSnapshotButton = document.querySelector("#saveSnapshotButton");
const resetObservationButton = document.querySelector("#resetObservationButton");
const exportMarkdownButton = document.querySelector("#exportMarkdownButton");
const exportJsonButton = document.querySelector("#exportJsonButton");
const savePolicyButton = document.querySelector("#savePolicyButton");
const deletePolicyButton = document.querySelector("#deletePolicyButton");
const checkPoliciesButton = document.querySelector("#checkPoliciesButton");
const menuToggleButton = document.querySelector("#menuToggleButton");
const actionsPanel = document.querySelector("#actionsPanel");
const modeButtons = Array.from(document.querySelectorAll(".mode-button"));
const pastePanel = document.querySelector("#pastePanel");
const policyText = document.querySelector("#policyText");
const statusEl = document.querySelector("#status");
const resultEl = document.querySelector("#result");
const sourceLabel = document.querySelector("#sourceLabel");
const languageSelect = document.querySelector("#uiLanguageSelect");

function setActionMenuExpanded(isExpanded) {
  actionsPanel.hidden = !isExpanded;
  menuToggleButton.setAttribute("aria-expanded", String(isExpanded));
  const label = isExpanded ? t("menuCollapse") : t("menuExpand");
  menuToggleButton.setAttribute("aria-label", label);
  menuToggleButton.textContent = label;
}

function setActiveAnalysisMode(mode) {
  latestAnalysisMode = mode;
  for (const button of modeButtons) {
    button.setAttribute("aria-pressed", String(button.dataset.mode === mode));
  }
}

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle("error", isError);
}

function severityLabel(severity) {
  if (severity === "high") return t("severityHigh");
  if (severity === "medium") return t("severityMedium");
  return t("severityLow");
}

function formatNumber(value) {
  const numericValue = Number(value);
  if (!Number.isFinite(numericValue)) return t("notAvailable");
  return new Intl.NumberFormat(localeCode()).format(numericValue);
}

function formatDate(value) {
  if (!value) return t("notAvailable");
  try {
    return new Intl.DateTimeFormat(localeCode(), {
      dateStyle: "medium",
      timeStyle: "short"
    }).format(new Date(value));
  } catch {
    return new Date(value).toLocaleString(localeCode());
  }
}

function changeTypeLabel(changeType) {
  switch (changeType) {
    case "added":
      return t("changeTypeAdded");
    case "removed":
      return t("changeTypeRemoved");
    case "modified":
      return t("changeTypeModified");
    default:
      return changeType || t("notAvailable");
  }
}

function renderAnalysis(
  analysis,
  networkAnalysis = null,
  formAnalysis = null,
  storageAnalysis = null,
  consentAnalysis = null,
  deltaAnalysis = null,
  jurisdictionAnalysis = null,
  alignmentAnalysis = null,
  policyChangeAnalysis = null
) {
  if (!analysis.ok) {
    resultEl.innerHTML = "";
    setStatus(analysis.message, true);
    return;
  }

  setStatus(t("statusAnalysisComplete", [formatNumber(analysis.wordCount)]));

  const dataItems = analysis.dataCategories.length
    ? analysis.dataCategories
        .map((item) => `<li><strong>${item.label}</strong><span>${item.matched.join(", ")}</span></li>`)
        .join("")
    : `<li>${t("noDetectedDataCategories")}</li>`;

  const risks = analysis.risks.length
    ? analysis.risks
        .map(
          (risk) => `
            <article class="risk ${risk.severity}">
              <div class="risk-heading">
                <strong>${risk.title}</strong>
                <span>${severityLabel(risk.severity)}</span>
              </div>
              ${risk.evidence ? `<blockquote>${escapeHtml(risk.evidence)}</blockquote>` : ""}
              <p>${risk.advice}</p>
            </article>
          `
        )
        .join("")
    : `<p class="empty">${t("noPolicyRisks")}</p>`;

  const positives = analysis.positives.length
    ? analysis.positives.map((item) => `<li>${item}</li>`).join("")
    : `<li>${t("noPositiveSignals")}</li>`;
  const policyEvidenceSection = renderPolicyEvidence(analysis.policySections || []);
  const networkSection = networkAnalysis ? renderNetworkAnalysis(networkAnalysis) : "";
  const formSection = formAnalysis ? renderFormAnalysis(formAnalysis) : "";
  const storageSection = storageAnalysis ? renderStorageAnalysis(storageAnalysis) : "";
  const consentSection = consentAnalysis ? renderConsentAnalysis(consentAnalysis) : "";
  const deltaSection = deltaAnalysis ? renderDeltaAnalysis(deltaAnalysis) : "";
  const jurisdictionSection = jurisdictionAnalysis ? renderJurisdictionAnalysis(jurisdictionAnalysis) : "";
  const alignmentSection = alignmentAnalysis ? renderAlignmentAnalysis(alignmentAnalysis) : "";
  const policyChangeSection = policyChangeAnalysis ? renderPolicyChangeAnalysis(policyChangeAnalysis) : "";

  resultEl.innerHTML = `
    <section class="score-card level-${analysis.level}">
      <div>
        <span>${t("riskLevelTitle")}</span>
        <strong>${escapeHtml(analysis.levelLabel || analysis.level)}</strong>
      </div>
      <meter min="0" max="100" value="${analysis.score}"></meter>
      <p>${analysis.summary}</p>
    </section>

    <section class="panel">
      <h2>${t("dataCategoriesTitle")}</h2>
      <ul class="data-list">${dataItems}</ul>
    </section>

    <section class="panel">
      <h2>${t("riskClausesTitle")}</h2>
      <div class="risk-list">${risks}</div>
    </section>

    <section class="panel">
      <h2>${t("protectionsTitle")}</h2>
      <ul>${positives}</ul>
    </section>

    ${policyEvidenceSection}

    ${networkSection}

    ${formSection}

    ${storageSection}

    ${consentSection}

    ${deltaSection}

    ${jurisdictionSection}

    ${alignmentSection}

    ${policyChangeSection}
  `;
}

function renderPolicyChangeAnalysis(policyChangeAnalysis) {
  if (!policyChangeAnalysis.hasPrevious) {
    return `
      <section class="panel">
        <h2>${t("policyChangeTitle")}</h2>
        <p class="empty">${t("noSavedPolicySnapshot")}</p>
      </section>
    `;
  }

  const findings = policyChangeAnalysis.findings.length
    ? policyChangeAnalysis.findings
        .map(
          (finding) => `
            <article class="risk ${finding.severity}">
              <div class="risk-heading">
                <strong>${escapeHtml(finding.title)}</strong>
                <span>${severityLabel(finding.severity)}</span>
              </div>
              <blockquote>${escapeHtml(finding.detail)}</blockquote>
              <p>${escapeHtml(finding.advice)}</p>
            </article>
          `
        )
        .join("")
    : `<p class="empty">${t("noPolicyChanges")}</p>`;
  const sectionDiffs = policyChangeAnalysis.sectionChanges?.length
    ? policyChangeAnalysis.sectionChanges
        .slice(0, 5)
        .map(
          (change) => `
            <article class="diff-item">
              <strong>${escapeHtml(change.label)} · ${escapeHtml(changeTypeLabel(change.changeType))}</strong>
              ${change.before ? `<p><span>${t("before")}</span>${escapeHtml(change.before)}</p>` : ""}
              ${change.after ? `<p><span>${t("after")}</span>${escapeHtml(change.after)}</p>` : ""}
            </article>
          `
        )
        .join("")
    : "";

  return `
    <section class="panel">
      <h2>${t("policyChangeTitle")}</h2>
      <div class="metric-row">
        <span>${t("previousSavedAt")}</span>
        <strong>${escapeHtml(formatDate(policyChangeAnalysis.previousCapturedAt))}</strong>
      </div>
      <div class="metric-row">
        <span>${t("changeStatus")}</span>
        <strong>${policyChangeAnalysis.changed ? t("changed") : t("unchanged")}</strong>
      </div>
      <div class="risk-list">${findings}</div>
      ${sectionDiffs ? `<h2 class="subheading">${t("sectionDiffsTitle")}</h2><div class="diff-list">${sectionDiffs}</div>` : ""}
    </section>
  `;
}

function renderAlignmentAnalysis(alignmentAnalysis) {
  const findings = alignmentAnalysis.findings.length
    ? alignmentAnalysis.findings
        .map(
          (finding) => `
            <article class="risk ${finding.severity}">
              <div class="risk-heading">
                <strong>${escapeHtml(finding.title)}</strong>
                <span>${severityLabel(finding.severity)}</span>
              </div>
              <blockquote>${escapeHtml(finding.detail)}</blockquote>
              <p>${escapeHtml(finding.advice)}</p>
            </article>
          `
        )
        .join("")
    : `<p class="empty">${t("noAlignmentFindings")}</p>`;

  return `
    <section class="panel">
      <h2>${t("behaviorAlignmentTitle")}</h2>
      <div class="metric-row">
        <span>${t("alignmentScore")}</span>
        <strong>${alignmentAnalysis.score}%</strong>
      </div>
      <div class="metric-row">
        <span>${t("level")}</span>
        <strong>${escapeHtml(alignmentAnalysis.levelLabel || alignmentAnalysis.level)}</strong>
      </div>
      <div class="risk-list">${findings}</div>
    </section>
  `;
}

function renderJurisdictionAnalysis(jurisdictionAnalysis) {
  const findings = jurisdictionAnalysis.findings.length
    ? jurisdictionAnalysis.findings
        .map(
          (finding) => `
            <article class="risk ${finding.severity}">
              <div class="risk-heading">
                <strong>${escapeHtml(finding.title)}</strong>
                <span>${severityLabel(finding.severity)}</span>
              </div>
              <blockquote>${escapeHtml(finding.detail)}</blockquote>
              <p>${escapeHtml(finding.advice)}</p>
            </article>
          `
        )
        .join("")
    : `<p class="empty">${t("noJurisdictionFindings")}</p>`;

  return `
    <section class="panel">
      <h2>${t("jurisdictionTitle")}</h2>
      <div class="metric-row">
        <span>${t("jurisdiction")}</span>
        <strong>${escapeHtml(jurisdictionAnalysis.jurisdiction.label)}</strong>
      </div>
      <div class="metric-row">
        <span>${t("confidence")}</span>
        <strong>${escapeHtml(jurisdictionAnalysis.jurisdiction.confidence)}</strong>
      </div>
      <blockquote>${escapeHtml(jurisdictionAnalysis.jurisdiction.basis)}</blockquote>
      <div class="risk-list">${findings}</div>
    </section>
  `;
}

function renderPolicyEvidence(policySections) {
  const importantSections = policySections
    .filter((section) => section.found)
    .slice(0, 8)
    .map(
      (section) => `
        <article class="evidence-item">
          <strong>${escapeHtml(section.label)}</strong>
          <p>${escapeHtml(section.evidence[0]?.excerpt || "")}</p>
        </article>
      `
    )
    .join("");

  const missingSections = policySections
    .filter((section) => !section.found)
    .slice(0, 6)
    .map((section) => `<li>${escapeHtml(section.label)}</li>`)
    .join("");

  return `
    <section class="panel">
      <h2>${t("policyEvidenceTitle")}</h2>
      <div class="evidence-list">
        ${importantSections || `<p class="empty">${t("noPolicyEvidence")}</p>`}
      </div>
      ${missingSections ? `<h2 class="subheading">${t("missingEvidenceTitle")}</h2><ul>${missingSections}</ul>` : ""}
    </section>
  `;
}

function renderDeltaAnalysis(deltaAnalysis) {
  if (!deltaAnalysis.hasSnapshot) {
    return `
      <section class="panel">
        <h2>${t("snapshotComparisonTitle")}</h2>
        <p class="empty">${t("noSnapshot")}</p>
      </section>
    `;
  }

  const findings = deltaAnalysis.findings.length
    ? deltaAnalysis.findings
        .map(
          (finding) => `
            <article class="risk ${finding.severity}">
              <div class="risk-heading">
                <strong>${escapeHtml(finding.title)}</strong>
                <span>${severityLabel(finding.severity)}</span>
              </div>
              <blockquote>${escapeHtml(finding.detail)}</blockquote>
              <p>${escapeHtml(finding.advice)}</p>
            </article>
          `
        )
        .join("")
    : `<p class="empty">${t("noDeltaTracking")}</p>`;

  return `
    <section class="panel">
      <h2>${t("snapshotComparisonTitle")}</h2>
      <div class="metric-row">
        <span>${t("snapshotBaseline")}</span>
        <strong>${escapeHtml(deltaAnalysis.snapshotLabel || t("snapshotBaseline"))}</strong>
      </div>
      <div class="metric-row">
        <span>${t("additionalRequests")}</span>
        <strong>${formatNumber(deltaAnalysis.requestDelta)}</strong>
      </div>
      <div class="metric-row">
        <span>${t("additionalCookies")}</span>
        <strong>${formatNumber(deltaAnalysis.cookieDelta)}</strong>
      </div>
      <div class="risk-list">${findings}</div>
    </section>
  `;
}

function renderConsentAnalysis(consentAnalysis) {
  const findings = consentAnalysis.findings.length
    ? consentAnalysis.findings
        .map(
          (finding) => `
            <article class="risk ${finding.severity}">
              <div class="risk-heading">
                <strong>${escapeHtml(finding.title)}</strong>
                <span>${severityLabel(finding.severity)}</span>
              </div>
              <blockquote>${escapeHtml(finding.detail)}</blockquote>
              <p>${escapeHtml(finding.advice)}</p>
            </article>
          `
        )
        .join("")
    : `<p class="empty">${t("noConsentConflict")}</p>`;
  const choiceAnalyses = consentAnalysis.choiceAnalyses?.length
    ? consentAnalysis.choiceAnalyses.map((choice) => renderConsentChoice(choice)).join("")
    : `<p class="empty">${t("noCookieChoiceClassified")}</p>`;

  return `
    <section class="panel">
      <h2>${t("consentComparisonTitle")}</h2>
      <div class="metric-row">
        <span>${t("consentUi")}</span>
        <strong>${consentAnalysis.detected ? t("detected") : t("notDetected")}</strong>
      </div>
      <div class="metric-row">
        <span>${t("rejectOption")}</span>
        <strong>${consentAnalysis.rejectAvailable ? t("exists") : t("unclear")}</strong>
      </div>
      <div class="metric-row">
        <span>${t("trackingActions")}</span>
        <strong>${formatNumber(consentAnalysis.trackingRequestCount + consentAnalysis.trackingCookieCount)}</strong>
      </div>
      <h2 class="subheading">${t("cookieChoicesTitle")}</h2>
      <div class="risk-list">${choiceAnalyses}</div>
      <h2 class="subheading">${t("warningSignalsTitle")}</h2>
      <div class="risk-list">${findings}</div>
    </section>
  `;
}

function renderConsentChoice(choice) {
  const categories = choice.allowedCategories?.length
    ? choice.allowedCategories
        .map(
          (category) => `
            <li>
              <strong>${escapeHtml(category.label)}</strong>
              <span>${escapeHtml(category.reason)}${category.defaultEnabled ? escapeHtml(t("cookieDefaultEnabledSuffix")) : ""}${category.inferred ? escapeHtml(t("cookieInferredSuffix")) : ""}</span>
            </li>
          `
        )
        .join("")
    : `<li>${t("noAllowedItems")}</li>`;
  const concerns = choice.concerns?.length
    ? choice.concerns.map((concern) => `<li>${escapeHtml(concern)}</li>`).join("")
    : `<li>${t("noExtraConcerns")}</li>`;

  return `
    <article class="risk ${escapeHtml(choice.riskLevel)}">
      <div class="risk-heading">
        <strong>${escapeHtml(choice.label)}</strong>
        <span>${t("riskLevelTitle")} ${escapeHtml(choice.safetyLabel)}</span>
      </div>
      <p>${escapeHtml(choice.summary)}</p>
      <h2 class="microheading">${t("allowedItemsTitle")}</h2>
      <ul class="data-list">${categories}</ul>
      <h2 class="microheading">${t("checkPointsTitle")}</h2>
      <ul>${concerns}</ul>
    </article>
  `;
}

function renderStorageAnalysis(storageAnalysis) {
  const findings = storageAnalysis.findings.length
    ? storageAnalysis.findings
        .map(
          (finding) => `
            <article class="risk ${finding.severity}">
              <div class="risk-heading">
                <strong>${escapeHtml(finding.title)}</strong>
                <span>${severityLabel(finding.severity)}</span>
              </div>
              <blockquote>${escapeHtml(finding.detail)}</blockquote>
              <p>${escapeHtml(finding.advice)}</p>
            </article>
          `
        )
        .join("")
    : `<p class="empty">${t("noStorageConflict")}</p>`;

  return `
    <section class="panel">
      <h2>${t("cookieStorageTitle")}</h2>
      <div class="metric-row">
        <span>${t("cookieChanges")}</span>
        <strong>${formatNumber(storageAnalysis.cookieCount)}</strong>
      </div>
      <div class="metric-row">
        <span>${t("storageKeys")}</span>
        <strong>${formatNumber(storageAnalysis.localStorageKeyCount + storageAnalysis.sessionStorageKeyCount)}</strong>
      </div>
      <div class="risk-list">${findings}</div>
    </section>
  `;
}

function renderFormAnalysis(formAnalysis) {
  const findings = formAnalysis.findings.length
    ? formAnalysis.findings
        .map(
          (finding) => `
            <article class="risk ${finding.severity}">
              <div class="risk-heading">
                <strong>${escapeHtml(finding.title)}</strong>
                <span>${severityLabel(finding.severity)}</span>
              </div>
              <blockquote>${escapeHtml(finding.detail)}</blockquote>
              <p>${escapeHtml(finding.advice)}</p>
            </article>
          `
        )
        .join("")
    : `<p class="empty">${t("noFormConflict")}</p>`;

  const categories = formAnalysis.categories.length
    ? formAnalysis.categories
        .map(
          (category) => `
            <li>
              <strong>${escapeHtml(category.label)}</strong>
              <span>${category.fields.slice(0, 6).map((field) => escapeHtml(field.name)).join(", ")}</span>
            </li>
          `
        )
        .join("")
    : `<li>${t("noSensitiveFormFields")}</li>`;

  return `
    <section class="panel">
      <h2>${t("signupFormTitle")}</h2>
      <div class="metric-row">
        <span>${t("allFields")}</span>
        <strong>${formatNumber(formAnalysis.fieldCount)}</strong>
      </div>
      <div class="metric-row">
        <span>${t("sensitiveFields")}</span>
        <strong>${formatNumber(formAnalysis.sensitiveFieldCount)}</strong>
      </div>
      <div class="risk-list">${findings}</div>
      <h2 class="subheading">${t("detectedFieldsTitle")}</h2>
      <ul class="data-list">${categories}</ul>
    </section>
  `;
}

function renderNetworkAnalysis(networkAnalysis) {
  const findings = networkAnalysis.findings.length
    ? networkAnalysis.findings
        .map(
          (finding) => `
            <article class="risk ${finding.severity}">
              <div class="risk-heading">
                <strong>${escapeHtml(finding.title)}</strong>
                <span>${severityLabel(finding.severity)}</span>
              </div>
              <blockquote>${escapeHtml(finding.detail)}</blockquote>
              <p>${escapeHtml(finding.advice)}</p>
            </article>
          `
        )
        .join("")
    : `<p class="empty">${t("noNetworkConflict")}</p>`;

  const thirdPartyHosts = networkAnalysis.thirdPartyHosts.length
    ? networkAnalysis.thirdPartyHosts.slice(0, 10).map((host) => `<li>${escapeHtml(host)}</li>`).join("")
    : `<li>${t("noThirdPartyDomain")}</li>`;
  const vendors = networkAnalysis.vendorSummary?.length
    ? networkAnalysis.vendorSummary
        .slice(0, 10)
        .map(
          (vendor) => `
            <li>
              <strong>${escapeHtml(vendor.vendor)}</strong>
              <span>${escapeHtml(vendor.host)} · ${escapeHtml(vendor.category)}</span>
            </li>
          `
        )
        .join("")
    : `<li>${t("noVendors")}</li>`;

  return `
    <section class="panel">
      <h2>${t("networkTitle")}</h2>
      <div class="metric-row">
        <span>${t("observedRequests")}</span>
        <strong>${formatNumber(networkAnalysis.requestCount)}</strong>
      </div>
      <div class="metric-row">
        <span>${t("thirdPartyDomains")}</span>
        <strong>${formatNumber(networkAnalysis.thirdPartyHosts.length)}</strong>
      </div>
      <div class="risk-list">${findings}</div>
      <h2 class="subheading">${t("vendorClassificationTitle")}</h2>
      <ul class="data-list">${vendors}</ul>
      <h2 class="subheading">${t("detectedThirdPartyDomainsTitle")}</h2>
      <ul>${thirdPartyHosts}</ul>
    </section>
  `;
}

function renderCookieFocusedAnalysis(source, consentAnalysis, storageAnalysis, networkAnalysis) {
  const riskLevel = summarizeCookieRisk(consentAnalysis, storageAnalysis, networkAnalysis);
  const score = scoreForRiskLevel(riskLevel);
  const levelLabel = severityLabel(riskLevel);

  setStatus(
    t("statusCookieComplete", [
      consentAnalysis.detected ? t("detected") : t("notDetected"),
      formatNumber(storageAnalysis.cookieCount)
    ])
  );

  resultEl.innerHTML = `
    <section class="score-card level-${escapeHtml(riskLevel)}">
      <div>
        <span>${t("cookieRiskTitle")}</span>
        <strong>${escapeHtml(levelLabel)}</strong>
      </div>
      <meter min="0" max="100" value="${score}"></meter>
      <p>${escapeHtml(cookieRiskSummaryText(riskLevel, consentAnalysis, storageAnalysis, networkAnalysis))}</p>
    </section>

    <section class="panel">
      <h2>${t("targetTitle")}</h2>
      <div class="metric-row">
        <span>${t("page")}</span>
        <strong>${escapeHtml(source.title || t("currentPageSource"))}</strong>
      </div>
      <div class="metric-row">
        <span>${t("cookieChoicesCount")}</span>
        <strong>${formatNumber(consentAnalysis.choiceAnalyses?.length || 0)}</strong>
      </div>
      <div class="metric-row">
        <span>${t("trackingActions")}</span>
        <strong>${formatNumber(consentAnalysis.trackingRequestCount + consentAnalysis.trackingCookieCount)}</strong>
      </div>
    </section>

    ${renderConsentAnalysis(consentAnalysis)}
    ${renderStorageAnalysis(storageAnalysis)}
    ${renderNetworkAnalysis(networkAnalysis)}
  `;
}

function summarizeCookieRisk(consentAnalysis, storageAnalysis, networkAnalysis) {
  const severities = [
    ...(consentAnalysis.findings || []).map((finding) => finding.severity),
    ...(storageAnalysis.findings || []).map((finding) => finding.severity),
    ...(networkAnalysis.findings || []).map((finding) => finding.severity),
    ...(consentAnalysis.choiceAnalyses || []).map((choice) => choice.riskLevel)
  ];

  if (severities.includes("high")) return "high";
  if (severities.includes("medium")) return "medium";
  return "low";
}

function scoreForRiskLevel(riskLevel) {
  return riskLevel === "high" ? 82 : riskLevel === "medium" ? 52 : 18;
}

function cookieRiskSummaryText(riskLevel, consentAnalysis, storageAnalysis, networkAnalysis) {
  if (riskLevel === "high") {
    return t("cookieBeforeChoiceSummaryHigh");
  }

  if (riskLevel === "medium") {
    return t("cookieBeforeChoiceSummaryMedium");
  }

  if (!consentAnalysis.detected && storageAnalysis.cookieCount === 0 && networkAnalysis.requestCount <= 1) {
    return t("cookieBeforeChoiceSummaryLowEmpty");
  }

  return t("cookieBeforeChoiceSummaryLow");
}

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function isHttpOrHttpsTab(tab) {
  if (!tab?.url) return false;
  try {
    const protocol = new URL(tab.url).protocol;
    return protocol === "http:" || protocol === "https:";
  } catch {
    return false;
  }
}

function requestPageText(tabId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(tabId, { type: "GET_PAGE_TEXT" }, (response) => {
      const error = chrome.runtime.lastError;
      if (error) {
        reject(error);
        return;
      }

      if (!response || typeof response !== "object" || !("text" in response)) {
        reject(new Error("no page text response"));
        return;
      }

      resolve(response);
    });
  });
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isReceivingEndError(error) {
  const message = String(error?.message || error || "").toLowerCase();
  return (
    message.includes("receiving end does not exist") ||
    message.includes("could not establish connection") ||
    message.includes("no receiver for message")
  );
}

function isLoadError(error) {
  const message = String(error?.message || error || "").toLowerCase();
  return message.includes("cannot access contents of");
}

async function ensureContentScriptInjected(tabId) {
  await chrome.scripting.executeScript({
    target: { tabId },
    files: ["src/content.js"]
  });
}

async function waitForTabComplete(tabId) {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    try {
      const currentTab = await chrome.tabs.get(tabId);
      if (currentTab.status !== "loading") return true;
    } catch {
      return false;
    }

    await sleep(250);
  }

  return false;
}

async function requestPageTextWithRetry(tabId) {
  let lastError;

  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      await ensureContentScriptInjected(tabId);
      return await requestPageText(tabId);
    } catch (error) {
      lastError = error;

      if (!isReceivingEndError(error) || attempt >= 1) {
        break;
      }

      await sleep(300);
    }
  }

  try {
    return await collectPageDataByScripting(tabId);
  } catch (fallbackError) {
    if (!lastError) throw fallbackError;
    throw lastError;
  }
}

function extractTextFallbackFromPage() {
  const BLOCKED_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "SVG", "CANVAS"]);
  const CONSENT_HINTS = [
    "cookie",
    "cookies",
    "consent",
    "privacy",
    "tracking",
    "advertising",
    "analytics",
    "쿠키",
    "동의",
    "개인정보",
    "추적",
    "광고",
    "분석"
  ];

  function isVisible(element) {
    const style = window.getComputedStyle(element);
    return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
  }

  function normalizeText(text) {
    return text
      .replace(/\u00a0/g, " ")
      .replace(/[ \t]+/g, " ")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  }

  function getBestReadableText() {
    const candidates = Array.from(document.querySelectorAll("main, article, section, [role='main'], body"))
      .filter((element) => !BLOCKED_TAGS.has(element.tagName) && isVisible(element))
      .map((element) => ({ element, score: normalizeText(element.innerText || "").length }))
      .sort((a, b) => b.score - a.score);

    const best = candidates[0]?.element || document.body;
    return normalizeText(best.innerText || document.body.innerText || "");
  }

  function getStorageKeys(storage) {
    try {
      return Array.from({ length: storage.length }, (_value, index) => storage.key(index)).filter(Boolean).slice(0, 80);
    } catch {
      return [];
    }
  }

  function getStorageSnapshot() {
    return {
      localStorageKeys: getStorageKeys(window.localStorage),
      sessionStorageKeys: getStorageKeys(window.sessionStorage)
    };
  }

  function getLabelText(input) {
    const labels = Array.from(input.labels || []).map((label) => normalizeText(label.innerText || ""));
    if (labels.length > 0) return labels.join(" ");

    const ariaLabel = input.getAttribute("aria-label");
    if (ariaLabel) return ariaLabel;

    const labelledBy = input.getAttribute("aria-labelledby");
    if (labelledBy) {
      return labelledBy
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.innerText || "")
        .filter(Boolean)
        .join(" ");
    }

    const wrapper = input.closest("label, .field, .form-group, .form, .input, .control, li, p, div");
    if (!wrapper) return "";

    const wrapperText = normalizeText(wrapper.innerText || "");
    return wrapperText.length > 120 ? wrapperText.slice(0, 120) : wrapperText;
  }

  function getFormFields() {
    return Array.from(document.querySelectorAll("input, textarea, select"))
      .filter((input) => {
        const style = window.getComputedStyle(input);
        if (style.display === "none" || style.visibility === "hidden" || style.opacity === "0") return false;
        return !["hidden", "submit", "button", "reset", "image"].includes(input.type);
      })
      .map((input) => ({
        tag: input.tagName.toLowerCase(),
        type: input.getAttribute("type") || input.tagName.toLowerCase(),
        name: input.getAttribute("name") || "",
        id: input.id || "",
        autocomplete: input.getAttribute("autocomplete") || "",
        placeholder: input.getAttribute("placeholder") || "",
        label: getLabelText(input),
        required: Boolean(input.required || input.getAttribute("aria-required") === "true")
      }))
      .slice(0, 120);
  }

  function looksLikeConsentElement(element) {
    const attrs = `${element.id || ""} ${element.className || ""} ${element.getAttribute("aria-label") || ""}`.toLowerCase();
    const text = normalizeText(element.innerText || "").toLowerCase();
    const haystack = `${attrs} ${text}`;
    return CONSENT_HINTS.some((hint) => haystack.includes(hint)) && text.length < 3000;
  }

  function getConsentButtons(container) {
    return Array.from(container.querySelectorAll("button, [role='button'], a"))
      .filter((button) => {
        const style = window.getComputedStyle(button);
        return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
      })
      .map(
        (button) => normalizeText(button.innerText || button.getAttribute("aria-label") || button.getAttribute("title") || "")
      )
      .filter(Boolean)
      .slice(0, 16);
  }

  function getConsentToggles(container) {
    return Array.from(container.querySelectorAll("input[type='checkbox'], input[type='radio'], [role='switch']"))
      .filter((input) => {
        const style = window.getComputedStyle(input);
        return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
      })
      .map((input) => ({
        label: getLabelText(input),
        checked: Boolean(input.checked || input.getAttribute("aria-checked") === "true"),
        name: input.getAttribute("name") || "",
        id: input.id || ""
      }))
      .slice(0, 20);
  }

  function getConsentSnapshot() {
    const containers = Array.from(
      document.querySelectorAll("[id], [class], [role='dialog'], [aria-label], section, aside, footer")
    )
      .filter((element) => looksLikeConsentElement(element))
      .slice(0, 8)
      .map((element) => {
        const text = normalizeText(element.innerText || "");
        return {
          text: text.slice(0, 600),
          buttons: getConsentButtons(element),
          toggles: getConsentToggles(element)
        };
      })
      .filter((item) => item.text || item.buttons.length || item.toggles.length);

    return {
      detected: containers.length > 0,
      containers
    };
  }

  return {
    title: document.title,
    url: location.href,
    text: getBestReadableText().slice(0, 120000),
    forms: { fields: getFormFields() },
    storage: getStorageSnapshot(),
    consent: getConsentSnapshot(),
    jurisdictionSignals: {
      language: navigator.language || "",
      languages: Array.from(navigator.languages || []),
      timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
      host: location.hostname,
      url: location.href
    }
  };
}

function collectPageDataByScripting(tabId) {
  return new Promise((resolve, reject) => {
    chrome.scripting.executeScript(
      {
        target: { tabId },
        func: extractTextFallbackFromPage
      },
      (results) => {
        const error = chrome.runtime.lastError;
        if (error) {
          reject(error);
          return;
        }

        const firstResult = results?.[0]?.result;
        if (!firstResult) {
          reject(new Error("no direct page extraction result"));
          return;
        }

        resolve(firstResult);
      }
    );
  });
}

function classifyPageReadFailure(error, tab) {
  const message = String(error?.message || error || "").toLowerCase();

  if (!tab?.id) return "statusNoActiveTab";
  if (!isHttpOrHttpsTab(tab)) return "statusUnsupportedPageScheme";
  if (isLoadError(error)) return "statusUnsupportedPageScheme";
  if (message.includes("receiving end does not exist") || message.includes("chrome.runtime.lastError")) {
    return "statusPageScriptUnavailable";
  }
  if (message.includes("no page text response")) {
    return "statusNoPagePayload";
  }
  return "statusPageReadFailed";
}

function getPageReadFailureMessage(error, tab) {
  return t(classifyPageReadFailure(error, tab));
}

function getCookieFailureMessage(error, tab) {
  const reason = classifyPageReadFailure(error, tab);
  if (reason === "statusPageReadFailed" || reason === "statusNoPagePayload") return t("statusCookieFailed");
  return t(reason);
}

function tabContextLabel(tab) {
  if (!tab?.url) return "";
  try {
    return ` (${new URL(tab.url).hostname})`;
  } catch {
    return "";
  }
}

function withTabHint(message, tab) {
  if (!tab?.url) return message;
  return `${message}${tabContextLabel(tab)}`;
}

async function getActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab;
}

async function updateFloatingRiskIndicator(tabId, indicator) {
  if (!tabId) return;
  try {
    await chrome.runtime.sendMessage({
      type: "SET_RISK_INDICATOR",
      tabId,
      indicator
    });
  } catch {
    // Some pages cannot host content scripts, so the popup report remains the source of truth.
  }
}

async function analyzeCurrentPage() {
  setActiveAnalysisMode("page");
  pastePanel.hidden = true;
  sourceLabel.textContent = t("currentPageSource");
  setStatus(t("statusAnalyzingPage"));
  resultEl.innerHTML = "";

  try {
    const tab = await getActiveTab();
    if (!tab?.id) throw new Error("No active tab");
    if (!isHttpOrHttpsTab(tab)) {
      setStatus(t("statusUnsupportedPageScheme"), true);
      return;
    }
    if (tab.status === "loading") {
      await waitForTabComplete(tab.id);
    }
    void updateFloatingRiskIndicator(tab.id, {
      level: "analyzing",
      source: "popup-page",
      title: tab.title || "",
      url: tab.url || ""
    });

    const response = await requestPageTextWithRetry(tab.id);
    const network = await chrome.runtime.sendMessage({ type: "GET_NETWORK_ACTIVITY", tabId: tab.id });
    const customVendorRules = await loadCustomVendorRules();
    sourceLabel.textContent = response.title || response.url || t("currentPageSource");
    const policyAnalysis = analyzePolicy(response.text || "");
    const networkAnalysis = analyzeNetworkActivity(
      response.text || "",
      network?.requests || [],
      response.url || tab.url || "",
      customVendorRules
    );
    const formAnalysis = analyzeFormFields(response.text || "", response.forms?.fields || []);
    const storageAnalysis = analyzeClientStorage(response.text || "", response.storage || {}, network?.cookies || [], response.url || tab.url || "");
    const consentAnalysis = analyzeConsentCompliance(response.consent || {}, network?.requests || [], network?.cookies || []);
    const latestSnapshot = (network?.snapshots || []).at(-1) || null;
    const deltaAnalysis = analyzeObservationDelta(latestSnapshot, network?.requests || [], network?.cookies || []);
    const observedSignals = buildObservedSignals(networkAnalysis, formAnalysis, storageAnalysis, consentAnalysis);
    const jurisdictionAnalysis = analyzeJurisdictionCompliance(response.text || "", {
      signals: response.jurisdictionSignals || {},
      observed: observedSignals
    });
    const alignmentAnalysis = analyzeBehaviorPolicyAlignment(response.text || "", observedSignals);
    latestSourceText = response.text || "";
    latestSource = {
      title: response.title || tab.title || "",
      url: response.url || tab.url || ""
    };
    latestPolicySnapshot = await createPolicySnapshot({
      title: latestSource.title,
      url: latestSource.url,
      text: latestSourceText,
      policyAnalysis
    });
    const previousPolicySnapshot = await loadPolicySnapshot(latestPolicySnapshot.origin);
    const policyChangeAnalysis = comparePolicySnapshot(previousPolicySnapshot, latestPolicySnapshot);
    latestReportPayload = buildReportPayload({
      source: latestSource,
      policyAnalysis,
      networkAnalysis,
      formAnalysis,
      storageAnalysis,
      consentAnalysis,
      deltaAnalysis,
      jurisdictionAnalysis,
      alignmentAnalysis,
      policyChangeAnalysis
    });
    renderAnalysis(
      policyAnalysis,
      networkAnalysis,
      formAnalysis,
      storageAnalysis,
      consentAnalysis,
      deltaAnalysis,
      jurisdictionAnalysis,
      alignmentAnalysis,
      policyChangeAnalysis
    );
    await updateFloatingRiskIndicator(tab.id, {
      level: policyAnalysis.level,
      score: policyAnalysis.score,
      label: policyAnalysis.levelLabel || policyAnalysis.level,
      source: "popup-page",
      title: latestSource.title,
      url: latestSource.url
    });
  } catch (error) {
    const tab = await getActiveTab();
    setStatus(withTabHint(getPageReadFailureMessage(error, tab), tab), true);
  }
}

async function analyzeCookies() {
  setActiveAnalysisMode("cookies");
  pastePanel.hidden = true;
  sourceLabel.textContent = t("cookieAnalysisSource");
  setStatus(t("statusCookieAnalyzing"));
  resultEl.innerHTML = "";

  try {
    const tab = await getActiveTab();
    if (!tab?.id) throw new Error("No active tab");
    if (!isHttpOrHttpsTab(tab)) {
      setStatus(t("statusUnsupportedPageScheme"), true);
      return;
    }
    if (tab.status === "loading") {
      await waitForTabComplete(tab.id);
    }
    void updateFloatingRiskIndicator(tab.id, {
      level: "analyzing",
      source: "popup-cookie",
      title: tab.title || "",
      url: tab.url || ""
    });

    const response = await requestPageTextWithRetry(tab.id);
    const network = await chrome.runtime.sendMessage({ type: "GET_NETWORK_ACTIVITY", tabId: tab.id });
    const customVendorRules = await loadCustomVendorRules();
    const source = {
      title: response.title || tab.title || "",
      url: response.url || tab.url || ""
    };
    sourceLabel.textContent = source.title || source.url || t("cookieAnalysisSource");
    const policyAnalysis = analyzePolicy(response.text || "");
    const networkAnalysis = analyzeNetworkActivity(
      response.text || "",
      network?.requests || [],
      source.url,
      customVendorRules
    );
    const storageAnalysis = analyzeClientStorage(response.text || "", response.storage || {}, network?.cookies || [], source.url);
    const consentAnalysis = analyzeConsentCompliance(response.consent || {}, network?.requests || [], network?.cookies || []);

    latestReportPayload = buildReportPayload({
      source,
      policyAnalysis,
      networkAnalysis,
      storageAnalysis,
      consentAnalysis
    });
    renderCookieFocusedAnalysis(source, consentAnalysis, storageAnalysis, networkAnalysis);
    const cookieRiskLevel = summarizeCookieRisk(consentAnalysis, storageAnalysis, networkAnalysis);
    await updateFloatingRiskIndicator(tab.id, {
      level: cookieRiskLevel,
      score: scoreForRiskLevel(cookieRiskLevel),
      label: severityLabel(cookieRiskLevel),
      source: "popup-cookie",
      title: source.title,
      url: source.url
    });
  } catch (error) {
    const tab = await getActiveTab();
    setStatus(withTabHint(getCookieFailureMessage(error, tab), tab), true);
  }
}

async function saveCurrentPolicySnapshot() {
  if (!latestPolicySnapshot) {
    setStatus(t("statusNeedPageAnalysis"), true);
    return;
  }

  await savePolicySnapshot(latestPolicySnapshot);
  setStatus(t("statusPolicySaved"));
}

async function deleteCurrentPolicySnapshot() {
  const origin = latestPolicySnapshot?.origin || originFromUrl(latestSource?.url);
  if (!origin) {
    setStatus(t("statusPolicyDeleteFailed"), true);
    return;
  }

  await deletePolicySnapshot(origin);
  setStatus(t("statusPolicyDeleted"));
}

async function checkSavedPoliciesNow() {
  setStatus(t("statusCheckingPolicies"));
  try {
    const result = await chrome.runtime.sendMessage({ type: "CHECK_SAVED_POLICIES_NOW" });
    setStatus(
      t("statusPoliciesChecked", [result.checked || 0, result.changed || 0, result.notified || 0])
    );
  } catch {
    setStatus(t("statusPoliciesCheckFailed"), true);
  }
}

function exportLatestReport(format) {
  if (!latestReportPayload) {
    setStatus(t("statusNeedPageAnalysis"), true);
    return;
  }

  if (format === "json") {
    const content = buildJsonReport(latestReportPayload);
    const fileName = buildReportFileName(latestReportPayload.source, "json");
    downloadTextFile(content, fileName, "application/json;charset=utf-8");
    setStatus(t("statusJsonSaved"));
    return;
  }

  const content = buildMarkdownReport(latestReportPayload);
  const fileName = buildReportFileName(latestReportPayload.source, "md");
  downloadTextFile(content, fileName, "text/markdown;charset=utf-8");
  setStatus(t("statusMarkdownSaved"));
}

function buildObservedSignals(networkAnalysis, formAnalysis, storageAnalysis, consentAnalysis) {
  const sensitiveCategories = new Set([
    ...(formAnalysis?.categories || []).map((category) => category.id),
    ...(storageAnalysis?.classifiedStorage || []).map((category) => category.category)
  ]);

  return {
    hasThirdParty: Boolean(networkAnalysis?.thirdPartyHosts?.length || storageAnalysis?.thirdPartyCookieCount),
    hasTracking: Boolean(
      networkAnalysis?.trackerHosts?.length ||
        consentAnalysis?.trackingRequestCount ||
        consentAnalysis?.trackingCookieCount
    ),
    hasSensitiveData: ["payment", "biometric", "location"].some((category) => sensitiveCategories.has(category)),
    hasOverseasTransfer: Boolean(networkAnalysis?.thirdPartyHosts?.some((host) => !host.endsWith(".kr"))),
    hasFormData: Boolean(formAnalysis?.sensitiveFieldCount),
    hasStorage: Boolean(storageAnalysis?.localStorageKeyCount || storageAnalysis?.sessionStorageKeyCount || storageAnalysis?.cookieCount),
    hasAuthStorage: Boolean(storageAnalysis?.classifiedStorage?.some((category) => category.category === "account")),
    hasProfiling: Boolean(networkAnalysis?.trackerHosts?.length || consentAnalysis?.trackingRequestCount),
    vendorSummary: networkAnalysis?.vendorSummary || []
  };
}

async function saveObservationSnapshot() {
  try {
    const tab = await getActiveTab();
    if (!tab?.id) throw new Error("No active tab");

    await chrome.runtime.sendMessage({ type: "SAVE_OBSERVATION_SNAPSHOT", tabId: tab.id, label: t("snapshotUserBaseline") });
    setStatus(t("statusObservationSaved"));
  } catch {
    setStatus(t("statusObservationSaveFailed"), true);
  }
}

async function resetObservation() {
  try {
    const tab = await getActiveTab();
    if (!tab?.id) throw new Error("No active tab");

    await chrome.runtime.sendMessage({ type: "CLEAR_NETWORK_ACTIVITY", tabId: tab.id });
    resultEl.innerHTML = "";
    setStatus(t("statusObservationReset"));
  } catch {
    setStatus(t("statusObservationResetFailed"), true);
  }
}

function analyzePastedText() {
  setActiveAnalysisMode("paste");
  pastePanel.hidden = false;
  sourceLabel.textContent = t("pastedTextSource");
  renderAnalysis(analyzePolicy(policyText.value));
}

async function handleLanguageChange(event) {
  const selectedLocale = event.target.value;
  await setLocalePreference(selectedLocale);
  await applyI18n();
  setStatus(t("statusLanguageUpdated"));
}

function bindPopupEvents() {
  analyzePageButton.addEventListener("click", analyzeCurrentPage);
  analyzeCookiesButton.addEventListener("click", analyzeCookies);
  analyzePasteButton.addEventListener("click", () => {
    pastePanel.hidden = false;
    policyText.focus();
    analyzePastedText();
  });
  menuToggleButton.addEventListener("click", () => setActionMenuExpanded(actionsPanel.hidden));
  saveSnapshotButton.addEventListener("click", saveObservationSnapshot);
  resetObservationButton.addEventListener("click", resetObservation);
  exportMarkdownButton.addEventListener("click", () => exportLatestReport("markdown"));
  exportJsonButton.addEventListener("click", () => exportLatestReport("json"));
  savePolicyButton.addEventListener("click", saveCurrentPolicySnapshot);
  deletePolicyButton.addEventListener("click", deleteCurrentPolicySnapshot);
  checkPoliciesButton.addEventListener("click", checkSavedPoliciesNow);
  policyText.addEventListener("input", analyzePastedText);
  languageSelect?.addEventListener("change", handleLanguageChange);
}

function initializePopupUi() {
  getLocalePreference().then((savedLocale) => {
    if (languageSelect) languageSelect.value = savedLocale;
  });
  analyzeCurrentPage();
}

async function startPopup() {
  await applyI18n();
  const savedLocale = await getLocalePreference();
  if (languageSelect) languageSelect.value = savedLocale;
  bindPopupEvents();
  setActionMenuExpanded(!actionsPanel.hidden);
  initializePopupUi();
}

startPopup();
