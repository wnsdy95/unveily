import {
  loadCustomVendorRules,
  normalizeCustomVendorRule,
  saveCustomVendorRules,
  isValidCustomVendorRule
} from "./customRulesStorage.js";
import {
  deletePolicySnapshot,
  loadPolicyCheckHealth,
  loadPolicySnapshots
} from "./policySnapshots.js";
import {
  loadObservationSettings,
  OBSERVATION_SETTINGS_VALIDATION_ERRORS,
  saveObservationSettings,
  validateObservationSettingsInput
} from "./observationSettings.js";
import {
  applyI18n,
  applyI18nWithoutStorage,
  getLocalePreference,
  setLocalePreference,
  t
} from "./i18n.js";
import { ensureTrustedLocalStorage } from "./trustedLocalStorage.js";

const ruleForm = document.querySelector("#ruleForm");
const ruleId = document.querySelector("#ruleId");
const vendor = document.querySelector("#vendor");
const patterns = document.querySelector("#patterns");
const category = document.querySelector("#category");
const risk = document.querySelector("#risk");
const ruleList = document.querySelector("#ruleList");
const snapshotList = document.querySelector("#snapshotList");
const statusEl = document.querySelector("#status");
const cancelEditButton = document.querySelector("#cancelEditButton");
const languageSelect = document.querySelector("#uiLanguageSelect");
const observationEnabled = document.querySelector("#observationEnabled");
const excludedOrigins = document.querySelector("#excludedOrigins");
const saveObservationSettingsButton = document.querySelector("#saveObservationSettingsButton");

let rules = [];
let snapshots = {};
let policyCheckHealth = {};

const POLICY_HEALTH_ERROR_MESSAGE_KEYS = {
  network: "policyCheckErrorNetwork",
  timeout: "policyCheckErrorTimeout",
  http_status: "policyCheckErrorHttpStatus",
  redirect: "policyCheckErrorRedirect",
  content_type: "policyCheckErrorContentType",
  response_too_large: "policyCheckErrorResponseTooLarge",
  invalid_url: "policyCheckErrorInvalidUrl",
  not_policy: "policyCheckErrorNotPolicy",
  unknown: "policyCheckErrorUnknown"
};

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle("error", isError);
}

function setOptionsControlsEnabled(enabled) {
  document.querySelectorAll("input, textarea, select, button").forEach((control) => {
    control.disabled = !enabled;
  });
}

function getSelectedSections() {
  return Array.from(document.querySelectorAll("input[name='section']:checked")).map((input) => input.value);
}

function setSelectedSections(sections) {
  document.querySelectorAll("input[name='section']").forEach((input) => {
    input.checked = sections.includes(input.value);
  });
}

function resetForm() {
  ruleForm.reset();
  ruleId.value = "";
  setSelectedSections(["processors", "purpose", "security"]);
}

function renderRules() {
  if (rules.length === 0) {
    ruleList.innerHTML = `<p class="empty">${t("noSavedRules")}</p>`;
    return;
  }

  ruleList.innerHTML = rules
    .map(
      (rule) => `
        <article class="rule-item">
          <div>
            <strong>${escapeHtml(rule.vendor)}</strong>
            <p>${escapeHtml(rule.patterns.join(", "))}</p>
            <span>${escapeHtml(rule.category)} · ${escapeHtml(rule.risk)} · ${escapeHtml(rule.expectedPolicySections.join(", "))}</span>
          </div>
          <div class="rule-actions">
            <button type="button" data-action="edit" data-id="${escapeHtml(rule.id)}" class="secondary">${t("edit")}</button>
            <button type="button" data-action="delete" data-id="${escapeHtml(rule.id)}" class="secondary danger">${t("delete")}</button>
          </div>
        </article>
      `
    )
    .join("");
}

function escapeHtml(value) {
  return String(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatPolicyCheckTimestamp(value) {
  const date = new Date(value || 0);
  if (!Number.isFinite(date.getTime())) return t("notAvailable");
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short"
  }).format(date);
}

function policyCheckStatus(snapshot) {
  const health = policyCheckHealth[snapshot.key];
  if (!health) return { error: false, text: t("policyCheckNeverAttempted") };
  if (health.consecutiveFailures > 0) {
    const errorMessageKey = POLICY_HEALTH_ERROR_MESSAGE_KEYS[health.errorCategory] || "policyCheckErrorUnknown";
    return {
      error: true,
      text: t("policyCheckLastFailed", [
        formatPolicyCheckTimestamp(health.lastAttemptAt),
        health.consecutiveFailures,
        t(errorMessageKey)
      ])
    };
  }
  return {
    error: false,
    text: t("policyCheckLastSucceeded", [
      formatPolicyCheckTimestamp(health.lastSuccessAt || health.lastAttemptAt)
    ])
  };
}

async function loadRules() {
  rules = await loadCustomVendorRules();
  renderRules();
}

function renderSnapshots() {
  const items = Object.values(snapshots);
  if (items.length === 0) {
    snapshotList.innerHTML = `<p class="empty">${t("noSavedSnapshots")}</p>`;
    return;
  }

  snapshotList.innerHTML = items
    .sort((a, b) => String(b.capturedAt).localeCompare(String(a.capturedAt)))
    .map((snapshot) => {
      const checkStatus = policyCheckStatus(snapshot);
      return `
        <article class="rule-item">
          <div>
            <strong>${escapeHtml(snapshot.origin)}</strong>
            <p>${escapeHtml(snapshot.title || snapshot.url)}</p>
            <code class="snapshot-url" title="${escapeHtml(snapshot.url || "")}">${escapeHtml(snapshot.url || "")}</code>
            <span>${escapeHtml(snapshot.capturedAt || "")} · ${t("riskLevelTitle")} ${escapeHtml(snapshot.riskSummary?.level || t("notAvailable"))}</span>
            <span class="snapshot-health${checkStatus.error ? " error" : ""}">${escapeHtml(checkStatus.text)}</span>
          </div>
          <div class="rule-actions">
            <button type="button" data-action="delete-snapshot" data-key="${escapeHtml(snapshot.key || snapshot.origin)}" class="secondary danger">${t("delete")}</button>
          </div>
        </article>
      `;
    })
    .join("");
}

async function loadSnapshots() {
  [snapshots, policyCheckHealth] = await Promise.all([
    loadPolicySnapshots(),
    loadPolicyCheckHealth()
  ]);
  renderSnapshots();
}

async function handleLanguageChange(event) {
  const selectedLocale = event.target.value;
  await setLocalePreference(selectedLocale);
  await applyI18n();
  renderRules();
  renderSnapshots();
  setStatus(t("statusLanguageUpdated"));
}

async function loadObservationControls() {
  const settings = await loadObservationSettings();
  observationEnabled.checked = settings.enabled;
  excludedOrigins.value = settings.excludedOrigins.join("\n");
}

async function persistObservationControls() {
  const validation = validateObservationSettingsInput({
    enabled: observationEnabled.checked,
    excludedOrigins: excludedOrigins.value.split(/[\n,]+/)
  });
  if (!validation.ok) {
    const messageKey =
      validation.error ===
      OBSERVATION_SETTINGS_VALIDATION_ERRORS.TOO_MANY_EXCLUDED_ORIGINS
        ? "statusObservationOriginsTooMany"
        : "statusObservationOriginInvalid";
    setStatus(t(messageKey), true);
    return;
  }
  try {
    const settings = await saveObservationSettings(validation.settings);
    excludedOrigins.value = settings.excludedOrigins.join("\n");
    setStatus(t("statusObservationSettingsSaved"));
  } catch {
    setStatus(t("statusStorageFailed"), true);
  }
}

async function persistRules(nextRules) {
  rules = await saveCustomVendorRules(nextRules);
  renderRules();
}

async function handleRuleSubmit(event) {
  event.preventDefault();

  const normalized = normalizeCustomVendorRule({
    id: ruleId.value,
    vendor: vendor.value,
    patterns: patterns.value,
    category: category.value,
    risk: risk.value,
    expectedPolicySections: getSelectedSections()
  });

  if (!isValidCustomVendorRule(normalized)) {
    setStatus(t("statusRuleInvalid"), true);
    return;
  }

  const nextRules = [...rules];
  const index = nextRules.findIndex((rule) => rule.id === normalized.id);
  if (index >= 0) {
    nextRules[index] = normalized;
  } else {
    nextRules.push(normalized);
  }

  try {
    await persistRules(nextRules);
    resetForm();
    setStatus(t("statusRuleSaved"));
  } catch {
    setStatus(t("statusStorageFailed"), true);
  }
}

async function handleRuleListClick(event) {
  const button = event.target.closest("button[data-action]");
  if (!button) return;

  const selectedRule = rules.find((rule) => rule.id === button.dataset.id);
  if (!selectedRule) return;

  if (button.dataset.action === "delete") {
    if (!globalThis.confirm(t("confirmDeleteRule"))) return;
    try {
      await persistRules(rules.filter((rule) => rule.id !== selectedRule.id));
      setStatus(t("statusRuleDeleted"));
    } catch {
      setStatus(t("statusStorageFailed"), true);
    }
    return;
  }

  ruleId.value = selectedRule.id;
  vendor.value = selectedRule.vendor;
  patterns.value = selectedRule.patterns.join(", ");
  category.value = selectedRule.category;
  risk.value = selectedRule.risk;
  setSelectedSections(selectedRule.expectedPolicySections);
  setStatus(t("statusRuleLoaded"));
}

async function handleSnapshotListClick(event) {
  const button = event.target.closest("button[data-action='delete-snapshot']");
  if (!button) return;

  if (!globalThis.confirm(t("confirmDeleteSnapshot"))) return;
  try {
    const deleted = await deletePolicySnapshot(button.dataset.key);
    await loadSnapshots();
    setStatus(t(deleted ? "statusSnapshotDeleted" : "statusPolicyDeleteFailed"), !deleted);
  } catch {
    setStatus(t("statusStorageFailed"), true);
  }
}

function handleCancelEdit() {
  resetForm();
  setStatus("");
}

function bindOptionsEvents() {
  ruleForm.addEventListener("submit", handleRuleSubmit);
  ruleList.addEventListener("click", handleRuleListClick);
  snapshotList.addEventListener("click", handleSnapshotListClick);
  cancelEditButton.addEventListener("click", handleCancelEdit);
  languageSelect?.addEventListener("change", handleLanguageChange);
  saveObservationSettingsButton?.addEventListener("click", persistObservationControls);
}

async function startOptions() {
  setOptionsControlsEnabled(false);
  const trustedLocalStorageAvailable = await ensureTrustedLocalStorage();
  if (!trustedLocalStorageAvailable) {
    applyI18nWithoutStorage();
    observationEnabled.checked = false;
    excludedOrigins.value = "";
    setStatus(t("statusStorageIsolationUnavailable"), true);
    return;
  }

  try {
    await applyI18n();
    const savedLocale = await getLocalePreference();
    if (languageSelect) languageSelect.value = savedLocale;
    await loadObservationControls();
    await loadRules();
    await loadSnapshots();
    setOptionsControlsEnabled(true);
    bindOptionsEvents();
  } catch {
    setStatus(t("statusStorageFailed"), true);
  }
}

startOptions();
