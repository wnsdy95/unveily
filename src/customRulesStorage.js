export const CUSTOM_VENDOR_RULES_KEY = "customVendorRules";

export function normalizeCustomVendorRule(input) {
  return {
    id: input.id || `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    vendor: String(input.vendor || "").trim(),
    patterns: normalizeList(input.patterns),
    category: String(input.category || "unknown").trim(),
    risk: String(input.risk || "processor").trim(),
    expectedPolicySections: normalizeList(input.expectedPolicySections)
  };
}

export function isValidCustomVendorRule(rule) {
  return Boolean(
    rule.vendor &&
      Array.isArray(rule.patterns) &&
      rule.patterns.length > 0 &&
      rule.patterns.every(Boolean) &&
      Array.isArray(rule.expectedPolicySections) &&
      rule.expectedPolicySections.length > 0
  );
}

export async function loadCustomVendorRules() {
  if (!globalThis.chrome?.storage?.local) return [];
  const result = await chrome.storage.local.get(CUSTOM_VENDOR_RULES_KEY);
  return Array.isArray(result[CUSTOM_VENDOR_RULES_KEY]) ? result[CUSTOM_VENDOR_RULES_KEY] : [];
}

export async function saveCustomVendorRules(rules) {
  if (!globalThis.chrome?.storage?.local) return;
  await chrome.storage.local.set({ [CUSTOM_VENDOR_RULES_KEY]: rules });
}

function normalizeList(value) {
  if (Array.isArray(value)) {
    return value.map((item) => String(item).trim()).filter(Boolean);
  }

  return String(value || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}
