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
  deletePolicySnapshot,
  normalizePolicyUrl
} from "./policySnapshots.js";
import {
  applyI18n,
  applyI18nWithoutStorage,
  getLocalePreference,
  localeCode,
  setLocalePreference,
  t
} from "./i18n.js";
import { documentUrlFingerprint, sanitizeNetworkUrl } from "./backgroundSecurity.js";
import { ensureTrustedLocalStorage } from "./trustedLocalStorage.js";
import {
  DEFAULT_ANALYSIS_MODE,
  normalizeAnalysisModePreference
} from "./analysisModePreference.js";

let latestSource = null;
let latestReportPayload = null;
let latestPolicySaveContext = null;
let latestPolicyMonitoringRequiresHttps = false;
let latestAnalysisMode = "page";
let analysisGeneration = 0;
let pastedAnalysisTimer = null;
let trustedLocalStorageAvailable = false;
let companionOverlayEnabled = false;
let companionOverlayPreferenceAvailable = false;

const MAX_PASTED_POLICY_LENGTH = 120_000;
const PASTED_ANALYSIS_DELAY_MS = 150;

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
const companionOverlayToggleButton = document.querySelector("#companionOverlayToggleButton");
const openObservationSettingsButton = document.querySelector("#openObservationSettingsButton");
const menuToggleButton = document.querySelector("#menuToggleButton");
const actionsPanel = document.querySelector("#actionsPanel");
const modeButtons = Array.from(document.querySelectorAll(".mode-button"));
const pastePanel = document.querySelector("#pastePanel");
const policyText = document.querySelector("#policyText");
const statusEl = document.querySelector("#status");
const resultEl = document.querySelector("#result");
const sourceLabel = document.querySelector("#sourceLabel");
const languageSelect = document.querySelector("#uiLanguageSelect");
const storageIsolationWarning = document.querySelector("#storageIsolationWarning");

const localStorageControls = [
  languageSelect,
  saveSnapshotButton,
  resetObservationButton,
  savePolicyButton,
  deletePolicyButton,
  checkPoliciesButton,
  companionOverlayToggleButton
].filter(Boolean);

function setLocalStorageControlsEnabled(enabled) {
  for (const control of localStorageControls) control.disabled = !enabled;
}

async function loadAnalysisVendorRules() {
  return trustedLocalStorageAvailable ? loadCustomVendorRules() : [];
}

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

function clearLatestAnalysisState() {
  latestSource = null;
  latestReportPayload = null;
  latestPolicySaveContext = null;
  latestPolicyMonitoringRequiresHttps = false;
}

function beginAnalysis(mode) {
  if (mode !== "paste") {
    window.clearTimeout(pastedAnalysisTimer);
    pastedAnalysisTimer = null;
  }
  analysisGeneration += 1;
  setActiveAnalysisMode(mode);
  clearLatestAnalysisState();
  return analysisGeneration;
}

function rememberAnalysisMode(mode) {
  if (!trustedLocalStorageAvailable || normalizeAnalysisModePreference(mode) !== mode) return;
  let request;
  try {
    request = chrome.runtime.sendMessage({
      type: "SET_ANALYSIS_MODE_PREFERENCE",
      mode
    });
  } catch {
    if (latestAnalysisMode === mode) setStatus(t("statusStorageFailed"), true);
    return;
  }
  void Promise.resolve(request)
    .then((response) => {
      if (response?.ok === true && response.mode === mode) return;
      if (latestAnalysisMode === mode) setStatus(t("statusStorageFailed"), true);
    })
    .catch(() => {
      if (latestAnalysisMode === mode) setStatus(t("statusStorageFailed"), true);
    });
}

function selectCurrentPageAnalysis() {
  rememberAnalysisMode("page");
  return analyzeCurrentPage();
}

function selectCookieAnalysis() {
  rememberAnalysisMode("cookies");
  return analyzeCookies();
}

function isCurrentAnalysis(generation) {
  return generation === analysisGeneration;
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

function documentUrlIdentity(value) {
  try {
    const parsed = new URL(String(value || ""));
    if (!['http:', 'https:'].includes(parsed.protocol)) return "";
    parsed.hash = "";
    return parsed.href;
  } catch {
    return "";
  }
}

function indicatorUrl(value) {
  try {
    const parsed = new URL(String(value || ""));
    if (!['http:', 'https:'].includes(parsed.protocol)) return "";
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    if (parsed.href.length <= 2048) return parsed.href;
    return sanitizeNetworkUrl(parsed.href)?.url || parsed.origin;
  } catch {
    return "";
  }
}

async function requireCurrentPageContext(tabId, expectedUrl, expectedDocumentId) {
  const [currentTab, currentFrame] = await Promise.all([
    chrome.tabs.get(tabId),
    chrome.webNavigation.getFrame({ tabId, frameId: 0 })
  ]);
  const expected = documentUrlIdentity(expectedUrl);
  const current = documentUrlIdentity(currentTab?.url);
  const frameUrl = documentUrlIdentity(currentFrame?.url);
  const expectedFingerprint = expectedUrl ? documentUrlFingerprint(expectedUrl) : "";
  const currentFingerprint = documentUrlFingerprint(currentTab?.url);
  const documentId = typeof currentFrame?.documentId === "string" ? currentFrame.documentId : "";
  if (
    !current ||
    !documentId ||
    frameUrl !== current ||
    (expected && expected !== current) ||
    (expectedFingerprint && expectedFingerprint !== currentFingerprint) ||
    (expectedDocumentId && expectedDocumentId !== documentId)
  ) {
    throw new Error("page context changed during analysis");
  }
  return { ...currentTab, documentId };
}

function validateNetworkContext(network, pageUrl, documentId) {
  if (!network?.ok) throw new Error(network?.error || "network observation unavailable");
  if (!network.observationEnabled || !network.session) return;
  const page = sanitizeNetworkUrl(pageUrl);
  if (
    !page ||
    page.url !== network.session.navigationKey ||
    documentUrlFingerprint(pageUrl) !== network.session.documentFingerprint ||
    !documentId ||
    network.session.documentId !== documentId
  ) {
    throw new Error("page context changed during analysis");
  }
}

function requestPageText(tabId, documentId) {
  return new Promise((resolve, reject) => {
    chrome.tabs.sendMessage(
      tabId,
      { type: "GET_PAGE_TEXT" },
      { documentId },
      (response) => {
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
      }
    );
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

async function ensureContentScriptInjected(tabId, documentId) {
  await chrome.scripting.executeScript({
    target: { tabId, documentIds: [documentId] },
    files: ["src/domWorkLimits.js", "src/content.js", "src/companionOverlay.js"]
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

async function requestPageTextWithRetry(tabId, documentId) {
  let lastError;

  try {
    return await requestPageText(tabId, documentId);
  } catch (error) {
    lastError = error;

    if (isReceivingEndError(error)) {
      await sleep(300);

      try {
        await ensureContentScriptInjected(tabId, documentId);
        return await requestPageText(tabId, documentId);
      } catch (retryError) {
        lastError = retryError;
      }
    }
  }

  try {
    return await collectPageDataByScripting(tabId, documentId);
  } catch (fallbackError) {
    if (!lastError) throw fallbackError;
    throw lastError;
  }
}

function extractTextFallbackFromPage() {
  const BLOCKED_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "SVG", "CANVAS"]);
  const USER_INPUT_TAGS = new Set(["INPUT", "TEXTAREA", "SELECT", "OPTION"]);
  const USER_INPUT_ROLES = new Set(["textbox", "searchbox", "combobox"]);
  const MAX_PAGE_TEXT_LENGTH = 120000;
  const MAX_READABLE_CANDIDATES = 80;
  const MAX_FORM_CANDIDATES = 500;
  const MAX_CONSENT_CANDIDATES = 240;
  const MAX_DOM_NODES_VISITED = 20000;
  const MAX_CONTAINER_NODES_VISITED = 2000;
  const MAX_TEXT_NODES_VISITED = 50000;
  const MAX_FALLBACK_TOTAL_NODES = 100000;
  const MAX_FALLBACK_STYLE_READS = 30000;
  const MAX_FALLBACK_TIME_MS = 250;
  const CONSENT_HINTS = [
    "cookie",
    "cookies",
    "consent",
    "쿠키",
    "동의"
  ];
  const CONSENT_CHOICE_PATTERN =
    /(?:accept(?:\s+all)?|allow(?:\s+all)?|agree|reject(?:\s+all)?|decline|deny|necessary\s+only|essential\s+only|save\s+(?:my\s+)?(?:choices?|preferences?)|쿠키\s*(?:모두\s*)?(?:허용|수락)|모두\s*(?:허용|동의|거부)|동의|거부|필수\s*(?:쿠키\s*)?만|선택\s*저장)/i;
  const CONSENT_CANDIDATE_SELECTOR = [
    "dialog",
    "[role='dialog']",
    "aside",
    "[aria-label*='cookie' i]",
    "[aria-label*='consent' i]",
    "[id*='cookie' i]",
    "[class*='cookie' i]",
    "[id*='consent' i]",
    "[class*='consent' i]",
    "[id*='cmp' i]",
    "[class*='cmp' i]",
    "[id*='onetrust' i]",
    "[class*='onetrust' i]"
  ].join(", ");
  const fallbackVisibilityCache = new WeakMap();
  const fallbackClosestCache = new WeakMap();
  const fallbackTextCache = new WeakMap();
  const fallbackUserInputCache = new WeakMap();
  const fallbackUserInputStyleCache = new WeakMap();
  const fallbackStartedAt =
    typeof globalThis.performance?.now === "function" ? globalThis.performance.now() : Date.now();
  let fallbackNodesVisited = 0;
  let fallbackStyleReads = 0;
  let fallbackBudgetExhausted = false;

  function fallbackNow() {
    return typeof globalThis.performance?.now === "function"
      ? globalThis.performance.now()
      : Date.now();
  }

  function fallbackWorkAvailable() {
    if (fallbackBudgetExhausted) return false;
    try {
      if (fallbackNow() - fallbackStartedAt >= MAX_FALLBACK_TIME_MS) {
        fallbackBudgetExhausted = true;
        return false;
      }
    } catch {
      fallbackBudgetExhausted = true;
      return false;
    }
    return true;
  }

  function takeFallbackNode() {
    if (!fallbackWorkAvailable() || fallbackNodesVisited >= MAX_FALLBACK_TOTAL_NODES) {
      fallbackBudgetExhausted = true;
      return false;
    }
    fallbackNodesVisited += 1;
    return true;
  }

  function takeFallbackStyle() {
    if (!fallbackWorkAvailable() || fallbackStyleReads >= MAX_FALLBACK_STYLE_READS) {
      fallbackBudgetExhausted = true;
      return false;
    }
    fallbackStyleReads += 1;
    return true;
  }

  function shadowIncludingParentElement(element) {
    if (!(element instanceof Element)) return null;
    if (element.parentElement instanceof Element) return element.parentElement;
    try {
      const root = element.getRootNode?.();
      return root?.host instanceof Element ? root.host : null;
    } catch {
      return null;
    }
  }

  function documentIsEditable() {
    try {
      return String(document.designMode || "").toLowerCase() === "on";
    } catch {
      return true;
    }
  }

  function styleAllowsUserEditing(style) {
    return [style?.userModify, style?.webkitUserModify].some((value) =>
      String(value || "").toLowerCase().startsWith("read-write")
    );
  }

  function elementMarksUserInput(element) {
    if (!(element instanceof Element)) return false;
    try {
      if (element.isContentEditable === true) return true;
      if (USER_INPUT_TAGS.has(element.tagName)) return true;
      const contentEditable = element.getAttribute("contenteditable");
      if (contentEditable !== null && String(contentEditable).toLowerCase() !== "false") return true;
      const roles = String(element.getAttribute("role") || "")
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean);
      if (roles.some((role) => USER_INPUT_ROLES.has(role))) return true;
      return fallbackUserInputStyleCache.get(element) === true;
    } catch {
      return true;
    }
  }

  function isUserInputSubtree(node) {
    if (documentIsEditable()) return true;
    let current = node instanceof Element ? node : node?.parentElement;
    if (!(current instanceof Element)) return false;
    if (fallbackUserInputCache.has(current)) return fallbackUserInputCache.get(current);

    const traversed = [];
    let excluded = false;
    let depth = 0;
    while (current && depth < 40) {
      if (fallbackUserInputCache.has(current)) {
        excluded = fallbackUserInputCache.get(current);
        current = null;
        break;
      }
      traversed.push(current);
      if (elementMarksUserInput(current)) {
        excluded = true;
        current = null;
        break;
      }
      current = shadowIncludingParentElement(current);
      depth += 1;
    }
    if (current) excluded = true;
    for (const element of traversed) fallbackUserInputCache.set(element, excluded);
    return excluded;
  }

  function isVisible(element) {
    if (!(element instanceof Element) || !fallbackWorkAvailable()) return false;
    if (fallbackVisibilityCache.has(element)) return fallbackVisibilityCache.get(element);
    const ancestors = [];
    let current = element;
    let visible = true;
    let reachedKnownAncestor = false;
    for (let depth = 0; current && depth < 40; depth += 1) {
      if (fallbackVisibilityCache.has(current)) {
        visible = fallbackVisibilityCache.get(current);
        reachedKnownAncestor = true;
        break;
      }
      if (!takeFallbackNode() || !takeFallbackStyle()) {
        visible = false;
        break;
      }
      ancestors.push(current);
      try {
        const style = window.getComputedStyle(current);
        fallbackUserInputStyleCache.set(current, styleAllowsUserEditing(style));
        if (
          BLOCKED_TAGS.has(current.tagName) ||
          current.tagName === "TEMPLATE" ||
          current.hidden ||
          current.getAttribute("aria-hidden") === "true" ||
          style.display === "none" ||
          ["hidden", "collapse"].includes(style.visibility) ||
          Number.parseFloat(style.opacity) === 0 ||
          style.contentVisibility === "hidden"
        ) {
          visible = false;
          break;
        }
      } catch {
        visible = false;
        break;
      }
      current = shadowIncludingParentElement(current);
    }
    if (current && !reachedKnownAncestor && ancestors.length >= 40) visible = false;
    for (const ancestor of ancestors) fallbackVisibilityCache.set(ancestor, visible);
    return visible;
  }

  function normalizeText(text) {
    return text
      .replace(/\u00a0/g, " ")
      .replace(/[ \t]+/g, " ")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  }

  function boundedClosest(element, selector, maxAncestors = 40) {
    if (!(element instanceof Element) || !fallbackWorkAvailable()) return null;
    let selectorCache = fallbackClosestCache.get(element);
    if (selectorCache?.has(selector)) return selectorCache.get(selector);
    let match = null;
    let current = element;
    for (let depth = 0; current && depth < maxAncestors; depth += 1) {
      if (!takeFallbackNode()) break;
      if (current.matches(selector)) {
        match = current;
        break;
      }
      current = shadowIncludingParentElement(current);
    }
    if (!selectorCache) {
      selectorCache = new Map();
      fallbackClosestCache.set(element, selectorCache);
    }
    selectorCache.set(selector, match);
    return match;
  }

  function boundedElements(root, selector, maxMatches, maxVisited = MAX_DOM_NODES_VISITED) {
    const start = root instanceof Document ? root.documentElement : root;
    if (
      !(start instanceof Element) ||
      maxMatches <= 0 ||
      maxVisited <= 0 ||
      !fallbackWorkAvailable()
    ) {
      return [];
    }

    const matches = [];
    const walker = document.createTreeWalker(start, NodeFilter.SHOW_ALL);
    let node = start;
    let visited = 0;
    while (node && visited < maxVisited && matches.length < maxMatches) {
      if (!takeFallbackNode()) break;
      visited += 1;
      if (node instanceof Element && node.matches(selector)) matches.push(node);
      node = walker.nextNode();
    }
    return matches;
  }

  function cachedFallbackText(root, maxLength, maxVisited) {
    const cache = fallbackTextCache.get(root);
    const exact = cache?.get(`${maxLength}:${maxVisited}`);
    if (exact) return exact;
    if (!cache) return null;
    for (const [, cached] of cache) {
      if (cached.complete && cached.text.length <= maxLength) return cached;
    }
    return null;
  }

  function rememberFallbackText(root, maxLength, maxVisited, result) {
    let cache = fallbackTextCache.get(root);
    if (!cache) {
      cache = new Map();
      fallbackTextCache.set(root, cache);
    }
    cache.set(`${maxLength}:${maxVisited}`, result);
  }

  function boundedTextResult(root, maxLength, maxVisited = MAX_TEXT_NODES_VISITED) {
    if (
      !(root instanceof Element) ||
      maxLength <= 0 ||
      maxVisited <= 0 ||
      !fallbackWorkAvailable()
    ) {
      return { text: "", complete: false };
    }
    const cached = cachedFallbackText(root, maxLength, maxVisited);
    if (cached) return cached;
    const chunks = [];
    let length = 0;
    let visited = 0;
    let lastBlock = null;
    let textTruncated = false;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ALL);
    let node = walker.nextNode();
    while (node && visited < maxVisited && length < maxLength) {
      if (!takeFallbackNode()) break;
      visited += 1;
      if (node.nodeType !== 3) {
        node = walker.nextNode();
        continue;
      }
      const parent = node.parentElement;
      if (isVisible(parent) && !isUserInputSubtree(parent)) {
        const block = boundedClosest(
          parent,
          "p, li, dt, dd, blockquote, pre, h1, h2, h3, h4, h5, h6, div, main, section, article"
        );
        const separator = chunks.length > 0 ? (block && block !== lastBlock ? "\n\n" : " ") : "";
        const remaining = Math.max(0, maxLength - length - separator.length);
        const nodeValue = typeof node.nodeValue === "string" ? node.nodeValue : "";
        if (nodeValue.length > remaining) textTruncated = true;
        const nodeText = nodeValue.slice(0, remaining);
        const chunk = `${separator}${nodeText}`.slice(0, maxLength - length);
        chunks.push(chunk);
        length += chunk.length;
        lastBlock = block;
      }
      node = walker.nextNode();
    }
    const result = {
      text: normalizeText(chunks.join("")),
      complete: !node && !textTruncated && fallbackWorkAvailable()
    };
    rememberFallbackText(root, maxLength, maxVisited, result);
    return result;
  }

  function boundedText(root, maxLength, maxVisited = MAX_TEXT_NODES_VISITED) {
    return boundedTextResult(root, maxLength, maxVisited).text;
  }

  function getBestReadableText() {
    const candidates = boundedElements(document, "main, article, section, [role='main'], body", MAX_READABLE_CANDIDATES)
      .filter((element) => !BLOCKED_TAGS.has(element.tagName) && isVisible(element))
      .map((element) => {
        const textResult = boundedTextResult(element, 20000, MAX_CONTAINER_NODES_VISITED);
        return { element, score: textResult.text.length, textResult };
      })
      .sort((a, b) => b.score - a.score);

    const bestCandidate = candidates[0];
    const best = bestCandidate?.element || document.body;
    if (bestCandidate?.textResult.complete) return bestCandidate.textResult.text;
    return boundedText(best || document.documentElement, MAX_PAGE_TEXT_LENGTH);
  }

  function getStorageKeys(storage) {
    try {
      const keys = [];
      const length = Math.min(Number(storage.length) || 0, 80);
      for (let index = 0; index < length; index += 1) {
        const key = storage.key(index);
        if (key) keys.push(String(key).slice(0, 160));
      }
      return keys;
    } catch {
      return [];
    }
  }

  function getStorageSnapshot() {
    function keysFor(property) {
      try {
        return getStorageKeys(window[property]);
      } catch {
        return [];
      }
    }

    return {
      localStorageKeys: keysFor("localStorage"),
      sessionStorageKeys: keysFor("sessionStorage")
    };
  }

  function getLabelText(input) {
    const labels = Array.from(input.labels || [])
      .slice(0, 8)
      .map((label) => boundedText(label, 240, 200));
    if (labels.length > 0) return labels.join(" ").slice(0, 240);

    const ariaLabel = input.getAttribute("aria-label");
    if (ariaLabel) return ariaLabel.slice(0, 240);

    const labelledBy = input.getAttribute("aria-labelledby");
    if (labelledBy) {
      return labelledBy
        .split(/\s+/)
        .slice(0, 8)
        .map((id) => boundedText(document.getElementById(id), 240, 200))
        .filter(Boolean)
        .join(" ")
        .slice(0, 240);
    }

    const wrapper = boundedClosest(
      input,
      "label, .field, .form-group, .form, .input, .control, li, p, div"
    );
    if (!wrapper) return "";

    const wrapperText = boundedText(wrapper, 240, 400);
    return wrapperText.length > 120 ? wrapperText.slice(0, 120) : wrapperText;
  }

  function getFormFields() {
    return boundedElements(document, "input, textarea, select", MAX_FORM_CANDIDATES)
      .filter((input) => {
        if (!isVisible(input)) return false;
        return !["hidden", "submit", "button", "reset", "image"].includes(input.type);
      })
      .map((input) => ({
        tag: input.tagName.toLowerCase(),
        type: String(input.getAttribute("type") || input.tagName.toLowerCase()).slice(0, 40),
        name: String(input.getAttribute("name") || "").slice(0, 160),
        id: String(input.id || "").slice(0, 160),
        autocomplete: String(input.getAttribute("autocomplete") || "").slice(0, 160),
        placeholder: String(input.getAttribute("placeholder") || "").slice(0, 240),
        label: getLabelText(input),
        required: Boolean(input.required || input.getAttribute("aria-required") === "true")
      }))
      .slice(0, 120);
  }

  function looksLikeConsentElement(element) {
    const attrs = `${String(element.id || "").slice(0, 160)} ${String(element.className || "").slice(0, 320)} ${String(
      element.getAttribute("aria-label") || ""
    ).slice(0, 240)}`.toLowerCase();
    const text = boundedText(element, 3001, MAX_CONTAINER_NODES_VISITED).toLowerCase();
    const haystack = `${attrs} ${text}`;
    if (!CONSENT_HINTS.some((hint) => haystack.includes(hint)) || text.length >= 3000) return false;
    const managerMarker = /(?:cookie|consent|cmp|onetrust)/i.test(attrs);
    const choiceControl = boundedElements(
      element,
      "button, [role='button'], a",
      24,
      MAX_CONTAINER_NODES_VISITED
    ).some((control) =>
      CONSENT_CHOICE_PATTERN.test(
        `${boundedText(control, 160, 120)} ${String(control.getAttribute("aria-label") || "").slice(0, 160)}`
      )
    );
    if (!fallbackWorkAvailable()) return false;
    return managerMarker || choiceControl;
  }

  function getConsentButtons(container) {
    return boundedElements(container, "button, [role='button'], a", 100, MAX_CONTAINER_NODES_VISITED)
      .filter(isVisible)
      .map(
        (button) =>
          normalizeText(
            `${boundedText(button, 240, 200)} ${button.getAttribute("aria-label") || ""} ${button.getAttribute("title") || ""}`.slice(0, 240)
          )
      )
      .filter(Boolean)
      .slice(0, 16);
  }

  function getConsentToggles(container) {
    return boundedElements(
      container,
      "input[type='checkbox'], input[type='radio'], [role='switch']",
      100,
      MAX_CONTAINER_NODES_VISITED
    )
      .filter(isVisible)
      .map((input) => ({
        label: getLabelText(input),
        checked: Boolean(input.checked || input.getAttribute("aria-checked") === "true"),
        name: String(input.getAttribute("name") || "").slice(0, 160),
        id: String(input.id || "").slice(0, 160)
      }))
      .slice(0, 20);
  }

  function getConsentSnapshot() {
    const containers = [];
    const candidates = boundedElements(
      document,
      CONSENT_CANDIDATE_SELECTOR,
      MAX_CONSENT_CANDIDATES
    );
    for (const element of candidates) {
      if (!isVisible(element) || !looksLikeConsentElement(element)) continue;
      const text = boundedText(element, 3001, MAX_CONTAINER_NODES_VISITED);
      const item = {
        text: text.slice(0, 600),
        buttons: getConsentButtons(element),
        toggles: getConsentToggles(element)
      };
      if (item.text || item.buttons.length || item.toggles.length) containers.push(item);
      if (containers.length >= 8) break;
    }

    return {
      detected: containers.length > 0,
      detectedAt: containers.length > 0 ? new Date().toISOString() : null,
      choiceAt: null,
      containers
    };
  }

  let pageUrl = String(location.href || "");
  try {
    const parsed = new URL(pageUrl);
    if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("unsupported URL");
    parsed.username = "";
    parsed.password = "";
    parsed.search = "";
    parsed.hash = "";
    pageUrl = parsed.href.length <= 4096 ? parsed.href : parsed.origin;
  } catch {
    pageUrl = "";
  }

  return {
    title: String(document.title || "").slice(0, 512),
    url: pageUrl,
    text: getBestReadableText(),
    forms: { fields: getFormFields() },
    storage: getStorageSnapshot(),
    consent: getConsentSnapshot(),
    jurisdictionSignals: {
      language: String(navigator.language || "").slice(0, 40),
      languages: Array.from(navigator.languages || []).slice(0, 20).map((language) => String(language).slice(0, 40)),
      timeZone: String(Intl.DateTimeFormat().resolvedOptions().timeZone || "").slice(0, 100),
      host: String(location.hostname || "").slice(0, 255),
      url: pageUrl
    }
  };
}

function collectPageDataByScripting(tabId, documentId) {
  return new Promise((resolve, reject) => {
    chrome.scripting.executeScript(
      {
        target: { tabId, documentIds: [documentId] },
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
  if (message.includes("page context changed")) return "statusPageChangedDuringAnalysis";
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

function renderCompanionOverlayPreference() {
  if (!companionOverlayToggleButton) return;
  companionOverlayToggleButton.setAttribute("aria-pressed", String(companionOverlayEnabled));
  companionOverlayToggleButton.textContent = t(
    companionOverlayEnabled ? "disableCompanionOverlay" : "enableCompanionOverlay"
  );
  companionOverlayToggleButton.disabled = !(
    trustedLocalStorageAvailable && companionOverlayPreferenceAvailable
  );
}

async function loadCompanionOverlayPreference() {
  companionOverlayEnabled = false;
  companionOverlayPreferenceAvailable = false;
  renderCompanionOverlayPreference();
  try {
    const response = await chrome.runtime.sendMessage({
      type: "GET_COMPANION_OVERLAY_PREFERENCE"
    });
    if (response?.ok !== true || typeof response.enabled !== "boolean") return;
    companionOverlayEnabled = response.enabled;
    companionOverlayPreferenceAvailable = true;
  } catch {
    // Keep the persisted overlay setting unavailable when it cannot be read safely.
  }
  renderCompanionOverlayPreference();
}

async function toggleCompanionOverlay() {
  if (
    !trustedLocalStorageAvailable ||
    !companionOverlayPreferenceAvailable ||
    !companionOverlayToggleButton
  ) {
    return;
  }

  const enabled = !companionOverlayEnabled;
  companionOverlayToggleButton.disabled = true;
  try {
    const response = await chrome.runtime.sendMessage({
      type: "SET_COMPANION_OVERLAY_PREFERENCE",
      enabled
    });
    if (response?.ok !== true || response.enabled !== enabled) {
      throw new Error("invalid companion overlay preference response");
    }
    companionOverlayEnabled = enabled;
    setStatus(t(enabled ? "statusCompanionOverlayEnabled" : "statusCompanionOverlayDisabled"));
  } catch {
    companionOverlayPreferenceAvailable = false;
    setStatus(t("statusCompanionOverlayUpdateFailed"), true);
  }
  renderCompanionOverlayPreference();
}

async function openObservationSettings() {
  if (!openObservationSettingsButton) return;
  openObservationSettingsButton.disabled = true;
  try {
    await chrome.runtime.openOptionsPage();
  } catch {
    openObservationSettingsButton.disabled = false;
    setStatus(t("statusObservationSettingsOpenFailed"), true);
  }
}

async function updateToolbarRiskIndicator(tabId, indicator) {
  if (!tabId) return;
  try {
    const documentId =
      typeof indicator?.documentId === "string" && indicator.documentId
        ? indicator.documentId
        : (await chrome.webNavigation.getFrame({ tabId, frameId: 0 }))?.documentId;
    if (!documentId) return;
    await chrome.runtime.sendMessage({
      type: "SET_RISK_INDICATOR",
      tabId,
      indicator: {
        ...indicator,
        title: "",
        url: indicatorUrl(indicator?.url),
        documentFingerprint: documentUrlFingerprint(indicator?.url),
        documentId
      }
    });
  } catch {
    // Some pages cannot host content scripts, so the popup report remains the source of truth.
  }
}

async function analyzeCurrentPage() {
  const generation = beginAnalysis("page");
  pastePanel.hidden = true;
  sourceLabel.textContent = t("currentPageSource");
  setStatus(t("statusAnalyzingPage"));
  resultEl.innerHTML = "";
  let tab = null;

  try {
    tab = await getActiveTab();
    if (!isCurrentAnalysis(generation)) return;
    if (!tab?.id) throw new Error("No active tab");
    if (!isHttpOrHttpsTab(tab)) {
      setStatus(t("statusUnsupportedPageScheme"), true);
      return;
    }
    if (tab.status === "loading") {
      await waitForTabComplete(tab.id);
      if (!isCurrentAnalysis(generation)) return;
    }
    tab = await requireCurrentPageContext(tab.id);
    if (!isCurrentAnalysis(generation)) return;
    const documentUrl = tab.url || "";
    const documentId = tab.documentId;
    if (!isCurrentAnalysis(generation)) return;
    await updateToolbarRiskIndicator(tab.id, {
      level: "analyzing",
      source: "popup-page",
      title: tab.title || "",
      url: tab.url || "",
      documentId
    });
    if (!isCurrentAnalysis(generation)) return;

    const response = await requestPageTextWithRetry(tab.id, documentId);
    if (!isCurrentAnalysis(generation)) return;
    tab = await requireCurrentPageContext(tab.id, documentUrl, documentId);
    if (!isCurrentAnalysis(generation)) return;
    const sourceUrl = indicatorUrl(documentUrl);
    const network = await chrome.runtime.sendMessage({ type: "GET_NETWORK_ACTIVITY", tabId: tab.id });
    if (!isCurrentAnalysis(generation)) return;
    validateNetworkContext(network, documentUrl, documentId);
    tab = await requireCurrentPageContext(tab.id, documentUrl, documentId);
    if (!isCurrentAnalysis(generation)) return;
    const customVendorRules = await loadAnalysisVendorRules();
    if (!isCurrentAnalysis(generation)) return;
    const policyAnalysis = analyzePolicy(response.text || "");
    const networkAnalysis = analyzeNetworkActivity(
      response.text || "",
      network?.requests || [],
      sourceUrl,
      customVendorRules
    );
    const formAnalysis = analyzeFormFields(response.text || "", response.forms?.fields || []);
    const storageAnalysis = analyzeClientStorage(response.text || "", response.storage || {}, network?.cookies || [], sourceUrl);
    const latestSnapshot = (network?.snapshots || []).at(-1) || null;
    const consentAnalysis = analyzeConsentCompliance(
      {
        ...(response.consent || {}),
        observationStartedAt: network?.observationStartedAt,
        snapshotAt: latestSnapshot?.createdAt
      },
      network?.requests || [],
      network?.cookies || []
    );
    const deltaAnalysis = analyzeObservationDelta(latestSnapshot, network?.requests || [], network?.cookies || []);
    const source = {
      title: response.title || tab.title || "",
      url: sourceUrl,
      type: "page"
    };
    const observedSignals = buildObservedSignals(
      networkAnalysis,
      formAnalysis,
      storageAnalysis,
      consentAnalysis,
      response.jurisdictionSignals || {},
      source.url
    );
    const jurisdictionAnalysis = analyzeJurisdictionCompliance(response.text || "", {
      signals: response.jurisdictionSignals || {},
      observed: observedSignals
    });
    const alignmentAnalysis = analyzeBehaviorPolicyAlignment(response.text || "", observedSignals);
    const policyChangeAnalysis = null;
    const normalizedPolicyUrl = policyAnalysis.ok ? normalizePolicyUrl(documentUrl) : "";
    const policyMonitoringRequiresHttps = policyAnalysis.ok && !normalizedPolicyUrl;
    tab = await requireCurrentPageContext(tab.id, documentUrl, documentId);
    if (!isCurrentAnalysis(generation)) return;
    const reportPayload = buildReportPayload({
      source,
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

    latestSource = source;
    latestPolicySaveContext = policyAnalysis.ok && normalizedPolicyUrl
      ? {
          tabId: tab.id,
          documentId,
          policyUrl: normalizedPolicyUrl,
          title: String(source.title || "").slice(0, 512)
        }
      : null;
    latestPolicyMonitoringRequiresHttps = policyMonitoringRequiresHttps;
    latestReportPayload = policyAnalysis.ok ? reportPayload : null;
    sourceLabel.textContent = source.title || source.url || t("currentPageSource");
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
    if (policyAnalysis.ok && network?.observationEnabled === false) {
      setStatus(t("statusAnalysisCompleteNoObservation", [formatNumber(policyAnalysis.wordCount)]));
    }
    if (!isCurrentAnalysis(generation)) return;
    await updateToolbarRiskIndicator(tab.id, {
      level: policyAnalysis.level,
      score: policyAnalysis.score,
      label: policyAnalysis.levelLabel || policyAnalysis.level,
      source: "popup-page",
      title: source.title,
      url: documentUrl,
      documentId
    });
    if (!isCurrentAnalysis(generation)) return;
  } catch (error) {
    if (!isCurrentAnalysis(generation)) return;
    if (!tab) {
      tab = await getActiveTab();
      if (!isCurrentAnalysis(generation)) return;
    }
    if (!isCurrentAnalysis(generation)) return;
    await updateToolbarRiskIndicator(tab?.id, {
      level: "unknown",
      source: "popup-error",
      title: "",
      url: tab?.url || ""
    });
    if (!isCurrentAnalysis(generation)) return;
    setStatus(withTabHint(getPageReadFailureMessage(error, tab), tab), true);
  }
}

async function analyzeCookies() {
  const generation = beginAnalysis("cookies");
  pastePanel.hidden = true;
  sourceLabel.textContent = t("cookieAnalysisSource");
  setStatus(t("statusCookieAnalyzing"));
  resultEl.innerHTML = "";
  let tab = null;

  try {
    tab = await getActiveTab();
    if (!isCurrentAnalysis(generation)) return;
    if (!tab?.id) throw new Error("No active tab");
    if (!isHttpOrHttpsTab(tab)) {
      setStatus(t("statusUnsupportedPageScheme"), true);
      return;
    }
    if (tab.status === "loading") {
      await waitForTabComplete(tab.id);
      if (!isCurrentAnalysis(generation)) return;
    }
    tab = await requireCurrentPageContext(tab.id);
    if (!isCurrentAnalysis(generation)) return;
    const documentUrl = tab.url || "";
    const documentId = tab.documentId;
    if (!isCurrentAnalysis(generation)) return;
    await updateToolbarRiskIndicator(tab.id, {
      level: "analyzing",
      source: "popup-cookie",
      title: tab.title || "",
      url: tab.url || "",
      documentId
    });
    if (!isCurrentAnalysis(generation)) return;

    const response = await requestPageTextWithRetry(tab.id, documentId);
    if (!isCurrentAnalysis(generation)) return;
    tab = await requireCurrentPageContext(tab.id, documentUrl, documentId);
    if (!isCurrentAnalysis(generation)) return;
    const sourceUrl = indicatorUrl(documentUrl);
    const network = await chrome.runtime.sendMessage({ type: "GET_NETWORK_ACTIVITY", tabId: tab.id });
    if (!isCurrentAnalysis(generation)) return;
    validateNetworkContext(network, documentUrl, documentId);
    tab = await requireCurrentPageContext(tab.id, documentUrl, documentId);
    if (!isCurrentAnalysis(generation)) return;
    const customVendorRules = await loadAnalysisVendorRules();
    if (!isCurrentAnalysis(generation)) return;
    const source = {
      title: response.title || tab.title || "",
      url: sourceUrl,
      type: "page-cookie"
    };
    const policyAnalysis = analyzePolicy(response.text || "");
    const networkAnalysis = analyzeNetworkActivity(
      response.text || "",
      network?.requests || [],
      source.url,
      customVendorRules
    );
    const storageAnalysis = analyzeClientStorage(response.text || "", response.storage || {}, network?.cookies || [], source.url);
    const latestSnapshot = (network?.snapshots || []).at(-1) || null;
    const consentAnalysis = analyzeConsentCompliance(
      {
        ...(response.consent || {}),
        observationStartedAt: network?.observationStartedAt,
        snapshotAt: latestSnapshot?.createdAt
      },
      network?.requests || [],
      network?.cookies || []
    );

    const reportPayload = buildReportPayload({
      source,
      policyAnalysis,
      networkAnalysis,
      storageAnalysis,
      consentAnalysis
    });

    tab = await requireCurrentPageContext(tab.id, documentUrl, documentId);
    if (!isCurrentAnalysis(generation)) return;
    latestSource = source;
    latestPolicySaveContext = null;
    latestReportPayload = reportPayload;
    sourceLabel.textContent = source.title || source.url || t("cookieAnalysisSource");
    renderCookieFocusedAnalysis(source, consentAnalysis, storageAnalysis, networkAnalysis);
    if (network?.observationEnabled === false) {
      setStatus(t("statusCookieObservationUnavailable"), true);
    }
    const cookieRiskLevel = summarizeCookieRisk(consentAnalysis, storageAnalysis, networkAnalysis);
    if (!isCurrentAnalysis(generation)) return;
    await updateToolbarRiskIndicator(tab.id, {
      level: cookieRiskLevel,
      score: scoreForRiskLevel(cookieRiskLevel),
      label: severityLabel(cookieRiskLevel),
      source: "popup-cookie",
      title: source.title,
      url: documentUrl,
      documentId
    });
    if (!isCurrentAnalysis(generation)) return;
  } catch (error) {
    if (!isCurrentAnalysis(generation)) return;
    if (!tab) {
      tab = await getActiveTab();
      if (!isCurrentAnalysis(generation)) return;
    }
    if (!isCurrentAnalysis(generation)) return;
    await updateToolbarRiskIndicator(tab?.id, {
      level: "unknown",
      source: "popup-error",
      title: "",
      url: tab?.url || ""
    });
    if (!isCurrentAnalysis(generation)) return;
    setStatus(withTabHint(getCookieFailureMessage(error, tab), tab), true);
  }
}

async function saveCurrentPolicySnapshot() {
  if (latestSource && (latestSource.type === "pasted-text" || !latestSource.url)) {
    setStatus(t("statusPolicyRequiresUrl"), true);
    return;
  }

  if (latestPolicyMonitoringRequiresHttps) {
    setStatus(t("statusPolicyRequiresHttps"), true);
    return;
  }

  if (!latestPolicySaveContext) {
    setStatus(t(latestSource?.type === "page" ? "statusNeedPolicyAnalysis" : "statusNeedPageAnalysis"), true);
    return;
  }

  try {
    const response = await chrome.runtime.sendMessage({
      type: "SAVE_MONITORED_POLICY_SNAPSHOT",
      ...latestPolicySaveContext
    });
    if (!response?.ok) {
      if (response?.code === "STALE_PAGE") {
        setStatus(t("statusPageChangedDuringAnalysis"), true);
      } else if (response?.code === "STORAGE_FAILED") {
        setStatus(t("statusStorageFailed"), true);
      } else {
        setStatus(t("statusPolicyRefetchFailed"), true);
      }
      return;
    }
    setStatus(t("statusPolicySaved"));
  } catch {
    setStatus(t("statusPolicyRefetchFailed"), true);
  }
}

async function deleteCurrentPolicySnapshot() {
  const snapshotKey = latestPolicySaveContext?.policyUrl;
  if (!snapshotKey) {
    setStatus(t("statusPolicyDeleteFailed"), true);
    return;
  }

  try {
    const deleted = await deletePolicySnapshot(snapshotKey);
    setStatus(t(deleted ? "statusPolicyDeleted" : "statusPolicyDeleteFailed"), !deleted);
  } catch {
    setStatus(t("statusStorageFailed"), true);
  }
}

async function checkSavedPoliciesNow() {
  setStatus(t("statusCheckingPolicies"));
  try {
    const result = await chrome.runtime.sendMessage({ type: "CHECK_SAVED_POLICIES_NOW" });
    if (!result?.ok) throw new Error(result?.error || "Policy check failed");
    const failed = result.failed || 0;
    setStatus(
      t("statusPoliciesChecked", [result.checked || 0, result.changed || 0, result.notified || 0, failed]),
      failed > 0
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

const RELIABLE_COUNTRY_TLD_CODES = Object.freeze({
  kr: "KR",
  us: "US",
  uk: "GB",
  de: "DE",
  fr: "FR",
  jp: "JP",
  cn: "CN",
  ca: "CA",
  au: "AU",
  nz: "NZ",
  sg: "SG",
  in: "IN",
  br: "BR",
  mx: "MX",
  es: "ES",
  it: "IT",
  nl: "NL",
  be: "BE",
  se: "SE",
  no: "NO",
  dk: "DK",
  fi: "FI",
  pl: "PL",
  at: "AT",
  ch: "CH",
  cz: "CZ",
  pt: "PT",
  gr: "GR",
  ie: "IE"
});

function countryCodeFromHost(host) {
  const normalizedHost = String(host || "")
    .toLowerCase()
    .replace(/^\.+|\.+$/g, "");
  const topLevelLabel = normalizedHost.split(".").at(-1) || "";
  return RELIABLE_COUNTRY_TLD_CODES[topLevelLabel] || null;
}

function explicitSourceCountry(jurisdictionSignals, sourceUrl) {
  const explicitCountry = String(jurisdictionSignals?.countryCode || jurisdictionSignals?.ipCountryCode || "").toUpperCase();
  if (/^[A-Z]{2}$/.test(explicitCountry)) return explicitCountry;

  let sourceHost = jurisdictionSignals?.host || "";
  if (!sourceHost && sourceUrl) {
    try {
      sourceHost = new URL(sourceUrl).hostname;
    } catch {
      sourceHost = "";
    }
  }
  return countryCodeFromHost(sourceHost);
}

function inferOverseasTransfer(thirdPartyHosts, jurisdictionSignals, sourceUrl) {
  const sourceCountry = explicitSourceCountry(jurisdictionSignals, sourceUrl);
  const hosts = Array.isArray(thirdPartyHosts) ? thirdPartyHosts : [];
  const hostCountries = hosts.map(countryCodeFromHost).filter(Boolean);

  if (!sourceCountry || hosts.length === 0 || hostCountries.length === 0) {
    return { detected: false, status: "unknown" };
  }
  if (hostCountries.some((country) => country !== sourceCountry)) {
    return { detected: true, status: "detected" };
  }
  if (hostCountries.length !== hosts.length) {
    return { detected: false, status: "unknown" };
  }
  return { detected: false, status: "not_detected" };
}

function buildObservedSignals(
  networkAnalysis,
  formAnalysis,
  storageAnalysis,
  consentAnalysis,
  jurisdictionSignals = {},
  sourceUrl = ""
) {
  const sensitiveCategories = new Set([
    ...(formAnalysis?.categories || []).map((category) => category.id),
    ...(storageAnalysis?.classifiedStorage || []).map((category) => category.category)
  ]);
  const overseasTransfer = inferOverseasTransfer(
    networkAnalysis?.thirdPartyHosts,
    jurisdictionSignals,
    sourceUrl
  );

  return {
    hasThirdParty: Boolean(networkAnalysis?.thirdPartyHosts?.length || storageAnalysis?.thirdPartyCookieCount),
    hasTracking: Boolean(
      networkAnalysis?.trackerHosts?.length ||
        consentAnalysis?.trackingRequestCount ||
        consentAnalysis?.trackingCookieCount
    ),
    hasSensitiveData: ["payment", "biometric", "location"].some((category) => sensitiveCategories.has(category)),
    hasOverseasTransfer: overseasTransfer.detected,
    overseasTransferStatus: overseasTransfer.status,
    hasFormData: Boolean(formAnalysis?.sensitiveFieldCount),
    hasStorage: Boolean(storageAnalysis?.localStorageKeyCount || storageAnalysis?.sessionStorageKeyCount || storageAnalysis?.cookieCount),
    hasAuthStorage: Boolean(storageAnalysis?.classifiedStorage?.some((category) => category.category === "account")),
    hasProfiling: Boolean(networkAnalysis?.trackerHosts?.length || consentAnalysis?.trackingRequestCount),
    vendorSummary: networkAnalysis?.vendorSummary || []
  };
}

async function resetContentConsentTiming(tabId, fullReset = false, documentId = "") {
  try {
    await chrome.tabs.sendMessage(
      tabId,
      { type: fullReset ? "RESET_CONSENT_TIMELINE" : "RESET_CONSENT_CHOICE" },
      documentId ? { documentId } : undefined
    );
  } catch {
    // Restricted pages may not have a content script; the network baseline still resets.
  }
}

async function saveObservationSnapshot() {
  const generation = analysisGeneration;
  try {
    const tab = await getActiveTab();
    if (!isCurrentAnalysis(generation)) return;
    if (!tab?.id) throw new Error("No active tab");
    const pageContext = await requireCurrentPageContext(tab.id);
    if (!isCurrentAnalysis(generation)) return;
    const documentFingerprint = documentUrlFingerprint(pageContext.url);

    const response = await chrome.runtime.sendMessage({
      type: "SAVE_OBSERVATION_SNAPSHOT",
      tabId: tab.id,
      documentId: pageContext.documentId,
      documentFingerprint,
      label: t("snapshotUserBaseline")
    });
    if (!isCurrentAnalysis(generation)) return;
    if (response?.code === "STALE_PAGE") {
      setStatus(t("statusPageChangedDuringAnalysis"), true);
      return;
    }
    if (!response?.ok) throw new Error(response?.error || "Snapshot save failed");
    await requireCurrentPageContext(tab.id, pageContext.url, pageContext.documentId);
    if (!isCurrentAnalysis(generation)) return;
    await resetContentConsentTiming(tab.id, false, pageContext.documentId);
    if (!isCurrentAnalysis(generation)) return;
    setStatus(t("statusObservationSaved"));
  } catch (error) {
    if (!isCurrentAnalysis(generation)) return;
    const stale = String(error?.message || "").includes("page context changed");
    setStatus(t(stale ? "statusPageChangedDuringAnalysis" : "statusObservationSaveFailed"), true);
  }
}

async function resetObservation() {
  const generation = analysisGeneration + 1;
  analysisGeneration = generation;

  try {
    const tab = await getActiveTab();
    if (!isCurrentAnalysis(generation)) return;
    if (!tab?.id) throw new Error("No active tab");
    const pageContext = await requireCurrentPageContext(tab.id);
    if (!isCurrentAnalysis(generation)) return;
    const documentFingerprint = documentUrlFingerprint(pageContext.url);

    const response = await chrome.runtime.sendMessage({
      type: "CLEAR_NETWORK_ACTIVITY",
      tabId: tab.id,
      documentId: pageContext.documentId,
      documentFingerprint
    });
    if (!isCurrentAnalysis(generation)) return;
    if (response?.code === "STALE_PAGE") {
      setStatus(t("statusPageChangedDuringAnalysis"), true);
      return;
    }
    if (!response?.ok) throw new Error(response?.error || "Observation reset failed");
    await requireCurrentPageContext(tab.id, pageContext.url, pageContext.documentId);
    if (!isCurrentAnalysis(generation)) return;
    clearLatestAnalysisState();
    resultEl.innerHTML = "";
    sourceLabel.textContent = t("popupSourceDefault");
    await resetContentConsentTiming(tab.id, true, pageContext.documentId);
    if (!isCurrentAnalysis(generation)) return;
    setStatus(t("statusObservationReset"));
  } catch (error) {
    if (!isCurrentAnalysis(generation)) return;
    const stale = String(error?.message || "").includes("page context changed");
    setStatus(t(stale ? "statusPageChangedDuringAnalysis" : "statusObservationResetFailed"), true);
  }
}

function analyzePastedText() {
  window.clearTimeout(pastedAnalysisTimer);
  pastedAnalysisTimer = null;
  beginAnalysis("paste");
  pastePanel.hidden = false;
  const sourceTitle = t("pastedTextSource");
  const text = String(policyText.value || "").slice(0, MAX_PASTED_POLICY_LENGTH);
  const policyAnalysis = analyzePolicy(text);
  const source = {
    title: sourceTitle,
    url: "",
    type: "pasted-text"
  };

  latestSource = source;
  latestPolicySaveContext = null;
  latestReportPayload = policyAnalysis.ok
    ? buildReportPayload({
        source,
        policyAnalysis
      })
    : null;
  sourceLabel.textContent = sourceTitle;
  renderAnalysis(policyAnalysis);
}

function queuePastedTextAnalysis() {
  window.clearTimeout(pastedAnalysisTimer);
  pastedAnalysisTimer = window.setTimeout(analyzePastedText, PASTED_ANALYSIS_DELAY_MS);
}

async function handleLanguageChange(event) {
  const selectedLocale = event.target.value;
  await setLocalePreference(selectedLocale);
  await applyI18n();
  renderCompanionOverlayPreference();
  setStatus(t("statusLanguageUpdated"));
}

function bindPopupEvents() {
  analyzePageButton.addEventListener("click", selectCurrentPageAnalysis);
  analyzeCookiesButton.addEventListener("click", selectCookieAnalysis);
  analyzePasteButton.addEventListener("click", () => {
    pastePanel.hidden = false;
    policyText.focus();
    analyzePastedText();
  });
  menuToggleButton.addEventListener("click", () => setActionMenuExpanded(actionsPanel.hidden));
  exportMarkdownButton.addEventListener("click", () => exportLatestReport("markdown"));
  exportJsonButton.addEventListener("click", () => exportLatestReport("json"));
  policyText.addEventListener("input", queuePastedTextAnalysis);
  openObservationSettingsButton?.addEventListener("click", openObservationSettings);
}

function bindTrustedLocalStorageEvents() {
  saveSnapshotButton.addEventListener("click", saveObservationSnapshot);
  resetObservationButton.addEventListener("click", resetObservation);
  savePolicyButton.addEventListener("click", saveCurrentPolicySnapshot);
  deletePolicyButton.addEventListener("click", deleteCurrentPolicySnapshot);
  checkPoliciesButton.addEventListener("click", checkSavedPoliciesNow);
  companionOverlayToggleButton?.addEventListener("click", toggleCompanionOverlay);
  languageSelect?.addEventListener("change", handleLanguageChange);
}

function initializePopupUi(mode = DEFAULT_ANALYSIS_MODE) {
  if (normalizeAnalysisModePreference(mode) === "cookies") {
    analyzeCookies();
    return;
  }
  analyzeCurrentPage();
}

async function loadInitialAnalysisMode() {
  try {
    const response = await chrome.runtime.sendMessage({
      type: "GET_ANALYSIS_MODE_PREFERENCE"
    });
    if (
      response?.ok === true &&
      normalizeAnalysisModePreference(response.mode) === response.mode
    ) {
      return response.mode;
    }
  } catch {
    // The default analysis remains available without persisted local state.
  }
  return DEFAULT_ANALYSIS_MODE;
}

async function startPopup() {
  let initialAnalysisMode = DEFAULT_ANALYSIS_MODE;
  setLocalStorageControlsEnabled(false);
  trustedLocalStorageAvailable = await ensureTrustedLocalStorage();
  if (trustedLocalStorageAvailable) {
    await applyI18n();
    const savedLocale = await getLocalePreference();
    if (languageSelect) languageSelect.value = savedLocale;
    initialAnalysisMode = await loadInitialAnalysisMode();
    void loadCompanionOverlayPreference();
    bindTrustedLocalStorageEvents();
  } else {
    applyI18nWithoutStorage();
    if (storageIsolationWarning) storageIsolationWarning.hidden = false;
  }
  bindPopupEvents();
  setLocalStorageControlsEnabled(trustedLocalStorageAvailable);
  renderCompanionOverlayPreference();
  setActionMenuExpanded(!actionsPanel.hidden);
  initializePopupUi(initialAnalysisMode);
}

startPopup();
