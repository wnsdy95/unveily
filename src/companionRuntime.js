const COMPANION_RISK_SOURCES = new Map([
  ["page-scan", "automatic-policy"],
  ["popup-page", "page-analysis"],
  ["popup-cookie", "cookie-analysis"]
]);

const COMPANION_STATUSES = new Set([
  "ready",
  "unknown",
  "analyzing",
  "paused",
  "excluded",
  "unsupported",
  "unavailable"
]);

export function createCompanionState(indicator = {}, statusOverride = "", now = Date.now()) {
  const level = ["unknown", "analyzing", "low", "medium", "high"].includes(indicator.level)
    ? indicator.level
    : "unknown";
  const score = Number.isFinite(indicator.score)
    ? Math.max(0, Math.min(100, Math.round(indicator.score)))
    : null;
  const inferredStatus = level === "analyzing" ? "analyzing" : score === null ? "unknown" : "ready";
  const status = COMPANION_STATUSES.has(statusOverride) ? statusOverride : inferredStatus;
  return {
    status,
    level,
    score,
    source: COMPANION_RISK_SOURCES.get(indicator.source) || "none",
    updatedAt:
      Number.isFinite(indicator.updatedAt) && indicator.updatedAt >= 0
        ? indicator.updatedAt
        : now
  };
}
