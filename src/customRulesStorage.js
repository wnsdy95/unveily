import { ensureTrustedLocalStorage } from "./trustedLocalStorage.js";

export const CUSTOM_VENDOR_RULES_KEY = "customVendorRules";
const MAX_CUSTOM_RULES = 100;
const MAX_PATTERNS_PER_RULE = 20;
const MAX_VENDOR_LENGTH = 120;
const MAX_PATTERN_LENGTH = 253;
const ALLOWED_CATEGORIES = new Set([
  "authentication",
  "payment",
  "analytics",
  "advertising",
  "support",
  "error_monitoring",
  "cdn_security",
  "hosting",
  "security",
  "unknown"
]);
const ALLOWED_RISKS = new Set(["processor", "tracking", "infrastructure", "unknown"]);
const ALLOWED_POLICY_SECTIONS = new Set([
  "processors",
  "purpose",
  "security",
  "cookies_tracking",
  "third_party",
  "overseas_transfer"
]);

export function normalizeCustomVendorRule(input = {}) {
  if (!input || typeof input !== "object" || Array.isArray(input)) input = {};
  const category = String(input.category || "unknown").trim();
  const risk = String(input.risk || "processor").trim();
  return {
    id: String(input.id || `${Date.now()}-${Math.random().toString(36).slice(2)}`).slice(0, 128),
    vendor: String(input.vendor || "").trim().slice(0, MAX_VENDOR_LENGTH),
    patterns: Array.from(
      new Set(
        normalizeList(input.patterns, MAX_PATTERNS_PER_RULE * 5, MAX_PATTERN_LENGTH * MAX_PATTERNS_PER_RULE * 5)
          .map(normalizeDomainPattern)
          .filter(Boolean)
      )
    ).slice(0, MAX_PATTERNS_PER_RULE),
    category: ALLOWED_CATEGORIES.has(category) ? category : "unknown",
    risk: ALLOWED_RISKS.has(risk) ? risk : "unknown",
    expectedPolicySections: Array.from(
      new Set(
        normalizeList(input.expectedPolicySections, ALLOWED_POLICY_SECTIONS.size * 5, 2_000)
          .filter((section) => ALLOWED_POLICY_SECTIONS.has(section))
      )
    ).slice(0, ALLOWED_POLICY_SECTIONS.size)
  };
}

export function isValidCustomVendorRule(rule) {
  return Boolean(
    rule.vendor &&
      Array.isArray(rule.patterns) &&
      rule.patterns.length > 0 &&
      rule.patterns.every((pattern) => isValidDomainPattern(pattern)) &&
      Array.isArray(rule.expectedPolicySections) &&
      rule.expectedPolicySections.length > 0
  );
}

export async function loadCustomVendorRules() {
  const storage = await trustedCustomRulesStorage();
  if (!storage) return [];
  const result = await storage.get(CUSTOM_VENDOR_RULES_KEY);
  return Array.isArray(result[CUSTOM_VENDOR_RULES_KEY])
    ? normalizeRuleCollection(result[CUSTOM_VENDOR_RULES_KEY])
    : [];
}

export async function saveCustomVendorRules(rules) {
  const storage = await trustedCustomRulesStorage();
  if (!storage) return [];
  const normalizedRules = normalizeRuleCollection(rules);
  await storage.set({ [CUSTOM_VENDOR_RULES_KEY]: normalizedRules });
  return normalizedRules;
}

async function trustedCustomRulesStorage() {
  let storage;
  try {
    storage = globalThis.chrome?.storage?.local;
  } catch {
    throw new Error("Trusted local storage access is unavailable.");
  }
  if (!storage) return null;
  if (!(await ensureTrustedLocalStorage(storage))) {
    throw new Error("Trusted local storage access is unavailable.");
  }
  return storage;
}

function normalizeDomainPattern(value) {
  const pattern = String(value || "").trim().toLowerCase();
  if (pattern.length > MAX_PATTERN_LENGTH) return "";
  if (!pattern) return "";
  try {
    if (/^https?:\/\//.test(pattern)) return new URL(pattern).hostname.replace(/^\./, "");
  } catch {
    return "";
  }
  return pattern.replace(/^\./, "").replace(/\.$/, "");
}

function isValidDomainPattern(pattern) {
  return (
    typeof pattern === "string" &&
    pattern.length > 0 &&
    pattern.length <= MAX_PATTERN_LENGTH &&
    /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{2,59})$/.test(pattern)
  );
}

function normalizeRuleCollection(value) {
  const normalizedRules = [];
  const seenIds = new Set();
  for (const input of (Array.isArray(value) ? value : []).slice(0, MAX_CUSTOM_RULES * 5)) {
    const rule = normalizeCustomVendorRule(input);
    if (!isValidCustomVendorRule(rule) || seenIds.has(rule.id)) continue;
    seenIds.add(rule.id);
    normalizedRules.push(rule);
    if (normalizedRules.length >= MAX_CUSTOM_RULES) break;
  }
  return normalizedRules;
}

function normalizeList(value, maxItems = 100, maxStringLength = 25_000) {
  if (Array.isArray(value)) {
    return value.slice(0, maxItems).map((item) => String(item).trim()).filter(Boolean);
  }

  return String(value || "")
    .slice(0, maxStringLength)
    .split(",")
    .slice(0, maxItems)
    .map((item) => item.trim())
    .filter(Boolean);
}
