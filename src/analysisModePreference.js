import { ensureTrustedLocalStorage } from "./trustedLocalStorage.js";

export const ANALYSIS_MODE_PREFERENCE_KEY = "analysisModePreferenceV1";
export const DEFAULT_ANALYSIS_MODE = "page";

const PERSISTED_ANALYSIS_MODES = new Set([DEFAULT_ANALYSIS_MODE, "cookies"]);

export function normalizeAnalysisModePreference(value) {
  return PERSISTED_ANALYSIS_MODES.has(value) ? value : DEFAULT_ANALYSIS_MODE;
}

export async function loadAnalysisModePreference() {
  const storage = await trustedAnalysisModeStorage();
  if (!storage) return DEFAULT_ANALYSIS_MODE;
  const stored = await storage.get(ANALYSIS_MODE_PREFERENCE_KEY);
  return normalizeAnalysisModePreference(stored?.[ANALYSIS_MODE_PREFERENCE_KEY]);
}

export async function saveAnalysisModePreference(mode) {
  const normalizedMode = normalizeAnalysisModePreference(mode);
  const storage = await trustedAnalysisModeStorage();
  if (storage) {
    await storage.set({ [ANALYSIS_MODE_PREFERENCE_KEY]: normalizedMode });
  }
  return normalizedMode;
}

async function trustedAnalysisModeStorage() {
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
