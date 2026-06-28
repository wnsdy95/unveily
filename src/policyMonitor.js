import { t } from "./i18n.js";

const IMPORTANT_SECTION_IDS = new Set([
  "third_party",
  "cookies_tracking",
  "overseas_transfer",
  "retention",
  "legal_basis",
  "security",
  "processors"
]);

export function extractPolicyTextFromHtml(html) {
  return String(html || "")
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, " ")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/gi, " ")
    .replace(/&amp;/gi, "&")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&quot;/gi, "\"")
    .replace(/&#039;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

export function shouldNotifyPolicyChange(changeAnalysis) {
  if (!changeAnalysis?.hasPrevious || !changeAnalysis.changed) return false;

  const hasImportantSectionChange = (changeAnalysis.sectionChanges || []).some((change) =>
    IMPORTANT_SECTION_IDS.has(change.id)
  );
  const hasNewRisk = (changeAnalysis.riskChanges?.added || []).length > 0;

  return hasImportantSectionChange || hasNewRisk;
}

export function buildPolicyChangeNotification(snapshot, changeAnalysis) {
  const changedSections = (changeAnalysis.sectionChanges || [])
    .filter((change) => IMPORTANT_SECTION_IDS.has(change.id))
    .map((change) => change.label)
    .slice(0, 4);
  const newRisks = (changeAnalysis.riskChanges?.added || []).slice(0, 3);
  const parts = [];

  if (changedSections.length > 0) {
    parts.push(`${t("policyNotificationChangedSection")}: ${changedSections.join(", ")}`);
  }

  if (newRisks.length > 0) {
    parts.push(`${t("policyNotificationNewRisk")}: ${newRisks.join(", ")}`);
  }

  return {
    title: t("policyChangeTitle"),
    message: `${hostFromUrl(snapshot.url) || snapshot.origin} - ${parts.join(" / ") || t("policyNotificationDefault")}`
  };
}

export function buildPolicyChangeDedupeKey(origin, changeAnalysis, currentSnapshot) {
  const sectionPart = (changeAnalysis.sectionChanges || [])
    .map((change) => `${change.id}:${change.changeType}`)
    .sort()
    .join("|");
  const riskPart = (changeAnalysis.riskChanges?.added || []).sort().join("|");
  return `${origin}:${currentSnapshot.textHash}:${sectionPart}:${riskPart}`;
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}
