import {
  loadCustomVendorRules,
  normalizeCustomVendorRule,
  saveCustomVendorRules,
  isValidCustomVendorRule
} from "./customRulesStorage.js";
import { deletePolicySnapshot, loadPolicySnapshots } from "./policySnapshots.js";
import { applyI18n, getLocalePreference, setLocalePreference, t } from "./i18n.js";

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

let rules = [];
let snapshots = {};

function setStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle("error", isError);
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
    .map(
      (snapshot) => `
        <article class="rule-item">
          <div>
            <strong>${escapeHtml(snapshot.origin)}</strong>
            <p>${escapeHtml(snapshot.title || snapshot.url)}</p>
            <span>${escapeHtml(snapshot.capturedAt || "")} · ${t("riskLevelTitle")} ${escapeHtml(snapshot.riskSummary?.level || t("notAvailable"))}</span>
          </div>
          <div class="rule-actions">
            <button type="button" data-action="delete-snapshot" data-origin="${escapeHtml(snapshot.origin)}" class="secondary danger">${t("delete")}</button>
          </div>
        </article>
      `
    )
    .join("");
}

async function loadSnapshots() {
  snapshots = await loadPolicySnapshots();
  renderSnapshots();
}

async function handleLanguageChange(event) {
  const selectedLocale = event.target.value;
  await setLocalePreference(selectedLocale);
  await applyI18n();
  setStatus(t("statusLanguageUpdated"));
}

async function persistRules() {
  await saveCustomVendorRules(rules);
  renderRules();
}

ruleForm.addEventListener("submit", async (event) => {
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

  const index = rules.findIndex((rule) => rule.id === normalized.id);
  if (index >= 0) {
    rules[index] = normalized;
  } else {
    rules.push(normalized);
  }

  await persistRules();
  resetForm();
  setStatus(t("statusRuleSaved"));
});

ruleList.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;

  const selectedRule = rules.find((rule) => rule.id === button.dataset.id);
  if (!selectedRule) return;

  if (button.dataset.action === "delete") {
    rules = rules.filter((rule) => rule.id !== selectedRule.id);
    await persistRules();
    setStatus(t("statusRuleDeleted"));
    return;
  }

  ruleId.value = selectedRule.id;
  vendor.value = selectedRule.vendor;
  patterns.value = selectedRule.patterns.join(", ");
  category.value = selectedRule.category;
  risk.value = selectedRule.risk;
  setSelectedSections(selectedRule.expectedPolicySections);
  setStatus(t("statusRuleLoaded"));
});

snapshotList.addEventListener("click", async (event) => {
  const button = event.target.closest("button[data-action='delete-snapshot']");
  if (!button) return;

  await deletePolicySnapshot(button.dataset.origin);
  await loadSnapshots();
  setStatus(t("statusSnapshotDeleted"));
});

cancelEditButton.addEventListener("click", () => {
  resetForm();
  setStatus("");
});

async function startOptions() {
  await applyI18n();
  const savedLocale = await getLocalePreference();
  if (languageSelect) languageSelect.value = savedLocale;
  languageSelect?.addEventListener("change", handleLanguageChange);
  await loadRules();
  await loadSnapshots();
}

startOptions();
