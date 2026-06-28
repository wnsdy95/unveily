import { localeCode, t } from "./i18n.js";

export const POLICY_SNAPSHOTS_KEY = "policySnapshots";
const MAX_TEXT_LENGTH = 80000;
const MAX_POLICY_SNAPSHOTS = 50;
const IMPORTANT_SECTION_IDS = new Set(["third_party", "cookies_tracking", "overseas_transfer", "retention", "legal_basis", "security", "processors"]);

export async function loadPolicySnapshots() {
  if (!globalThis.chrome?.storage?.local) return {};
  const result = await chrome.storage.local.get(POLICY_SNAPSHOTS_KEY);
  return result[POLICY_SNAPSHOTS_KEY] && typeof result[POLICY_SNAPSHOTS_KEY] === "object"
    ? result[POLICY_SNAPSHOTS_KEY]
    : {};
}

export async function savePolicySnapshot(snapshot) {
  if (!globalThis.chrome?.storage?.local) return;
  const snapshots = await loadPolicySnapshots();
  snapshots[snapshot.origin] = snapshot;
  await chrome.storage.local.set({ [POLICY_SNAPSHOTS_KEY]: prunePolicySnapshots(snapshots) });
}

export async function loadPolicySnapshot(origin) {
  const snapshots = await loadPolicySnapshots();
  return snapshots[origin] || null;
}

export async function deletePolicySnapshot(origin) {
  if (!globalThis.chrome?.storage?.local) return;
  const snapshots = await loadPolicySnapshots();
  delete snapshots[origin];
  await chrome.storage.local.set({ [POLICY_SNAPSHOTS_KEY]: snapshots });
}

export async function createPolicySnapshot({ title, url, text, policyAnalysis }) {
  const normalizedText = normalizePolicyText(text).slice(0, MAX_TEXT_LENGTH);
  const policySections = (policyAnalysis?.policySections || []).map((section) => ({
    id: section.id,
    label: section.label,
    found: section.found,
    hash: hashText(section.evidence?.map((item) => item.excerpt).join("\n") || ""),
    excerpt: section.evidence?.[0]?.excerpt || ""
  }));

  return {
    origin: originFromUrl(url),
    title: title || "",
    url: url || "",
    capturedAt: new Date().toISOString(),
    textHash: hashText(normalizedText),
    normalizedText,
    policySections,
    riskSummary: {
      level: policyAnalysis?.level || "",
      score: policyAnalysis?.score ?? null,
      riskIds: (policyAnalysis?.risks || []).map((risk) => risk.id)
    }
  };
}

export function comparePolicySnapshot(previous, current) {
  if (!previous) {
    return {
      hasPrevious: false,
      changed: false,
      findings: []
    };
  }

  const sectionChanges = compareSections(previous.policySections || [], current.policySections || []);
  const riskChanges = compareRiskIds(previous.riskSummary?.riskIds || [], current.riskSummary?.riskIds || []);
  const changed = previous.textHash !== current.textHash || sectionChanges.length > 0 || riskChanges.added.length > 0;
  const findings = [];

  if (previous.textHash !== current.textHash) {
    findings.push({
      id: "policy_text_changed",
      severity: "medium",
      title: t("policyTextChangedTitle"),
      detail: `${t("previousSavedAt")}: ${formatDate(previous.capturedAt)}`,
      advice: t("policyTextChangedAdvice")
    });
  }

  if (sectionChanges.length > 0) {
    findings.push({
      id: "policy_sections_changed",
      severity: sectionChanges.some((change) => isHighImpactSectionChange(change)) ? "high" : "medium",
      title: t("policySectionChangedTitle"),
      detail: sectionChanges.map((change) => `${change.label}: ${localizedChangeType(change.changeType)}`).join(" / "),
      advice: t("policySectionChangedAdvice")
    });
  }

  if (riskChanges.added.length > 0) {
    findings.push({
      id: "policy_new_risks_added",
      severity: "high",
      title: t("policyNewRiskTitle"),
      detail: riskChanges.added.join(", "),
      advice: t("policyNewRiskAdvice")
    });
  }

  return {
    hasPrevious: true,
    changed,
    previousCapturedAt: previous.capturedAt,
    sectionChanges,
    riskChanges,
    findings
  };
}

function formatDate(value) {
  if (!value) return t("notAvailable");
  try {
    return new Intl.DateTimeFormat(localeCode(), {
      dateStyle: "medium",
      timeStyle: "short"
    }).format(new Date(value));
  } catch {
    return String(value);
  }
}

function localizedChangeType(changeType) {
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

function isHighImpactSectionChange(change) {
  if (IMPORTANT_SECTION_IDS.has(change.id)) return true;
  const before = String(change.before || "").toLowerCase();
  const after = String(change.after || "").toLowerCase();
  const expandedPermission = /(not|never|않|아니|없).{0,20}(share|provide|sell|제공|공유|판매)/.test(before) &&
    /(may|can|share|provide|sell|partner|third|제공|공유|판매|파트너|제3자|수탁)/.test(after);
  const newTracking = !/(cookie|tracking|advertis|analytics|쿠키|추적|광고|분석|행태정보)/.test(before) &&
    /(cookie|tracking|advertis|analytics|쿠키|추적|광고|분석|행태정보)/.test(after);

  return expandedPermission || newTracking;
}

export function originFromUrl(url) {
  try {
    return new URL(url).origin;
  } catch {
    return "";
  }
}

export function normalizePolicyText(text) {
  return String(text || "")
    .replace(/\u00a0/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function hashText(text) {
  let hash = 2166136261;
  const value = String(text || "");

  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }

  return (hash >>> 0).toString(16).padStart(8, "0");
}

export function prunePolicySnapshots(snapshots, maxCount = MAX_POLICY_SNAPSHOTS) {
  const entries = Object.entries(snapshots || {});
  if (entries.length <= maxCount) return snapshots;

  return Object.fromEntries(
    entries
      .sort(([, a], [, b]) => String(b.capturedAt || "").localeCompare(String(a.capturedAt || "")))
      .slice(0, maxCount)
  );
}

function compareSections(previousSections, currentSections) {
  const previousById = new Map(previousSections.map((section) => [section.id, section]));
  const currentById = new Map(currentSections.map((section) => [section.id, section]));
  const ids = new Set([...previousById.keys(), ...currentById.keys()]);

  return Array.from(ids)
    .map((id) => {
      const previous = previousById.get(id);
      const current = currentById.get(id);

      if (!previous && current?.found) return { id, label: current.label, changeType: "added" };
      if (previous?.found && !current?.found) return { id, label: previous.label, changeType: "removed" };
      if (previous?.found && current?.found && previous.hash !== current.hash) {
        return { id, label: current.label, changeType: "modified", before: previous.excerpt, after: current.excerpt };
      }

      return null;
    })
    .filter(Boolean);
}

function compareRiskIds(previousRiskIds, currentRiskIds) {
  const previous = new Set(previousRiskIds);
  const current = new Set(currentRiskIds);

  return {
    added: Array.from(current).filter((id) => !previous.has(id)),
    removed: Array.from(previous).filter((id) => !current.has(id))
  };
}
