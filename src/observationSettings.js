import { ensureTrustedLocalStorage } from "./trustedLocalStorage.js";

export const OBSERVATION_SETTINGS_KEY = "observationSettings";
export const DEFAULT_OBSERVATION_SETTINGS = Object.freeze({
  enabled: true,
  excludedOrigins: []
});

export const MAX_EXCLUDED_ORIGINS = 100;
export const OBSERVATION_SETTINGS_VALIDATION_ERRORS = Object.freeze({
  TOO_MANY_EXCLUDED_ORIGINS: "too_many_excluded_origins",
  INVALID_EXCLUDED_ORIGIN: "invalid_excluded_origin"
});

function parsedObservationOrigin(value, { exactOrigin = false } = {}) {
  const text = String(value || "").trim();
  if (!text || text.length > 2_048) return "";
  const explicitScheme = text.match(/^([a-z][a-z0-9+.-]*):/i);
  if (explicitScheme && !/^https?:\/\//i.test(text)) return "";
  try {
    const url = new URL(explicitScheme ? text : `https://${text}`);
    if (!["http:", "https:"].includes(url.protocol)) return "";
    if (
      exactOrigin &&
      (url.username || url.password || url.pathname !== "/" || url.search || url.hash)
    ) {
      return "";
    }
    return url.origin;
  } catch {
    return "";
  }
}

export function normalizeObservationSettings(value = {}) {
  const excludedOrigins = Array.from(
    new Set(
      (Array.isArray(value?.excludedOrigins) ? value.excludedOrigins : [])
        .slice(0, MAX_EXCLUDED_ORIGINS * 5)
        .map(normalizeObservationOrigin)
        .filter(Boolean)
    )
  ).slice(0, MAX_EXCLUDED_ORIGINS);

  return {
    enabled: value?.enabled === undefined ? true : value.enabled === true,
    excludedOrigins
  };
}

export function normalizeObservationOrigin(value) {
  return parsedObservationOrigin(value);
}

export function validateObservationSettingsInput(value = {}) {
  if (value?.excludedOrigins !== undefined && !Array.isArray(value.excludedOrigins)) {
    return {
      ok: false,
      error: OBSERVATION_SETTINGS_VALIDATION_ERRORS.INVALID_EXCLUDED_ORIGIN
    };
  }
  const candidates = Array.isArray(value?.excludedOrigins) ? value.excludedOrigins : [];
  const origins = [];
  const seenOrigins = new Set();
  let nonEmptyCount = 0;

  for (const candidate of candidates) {
    if (typeof candidate !== "string") {
      return {
        ok: false,
        error: OBSERVATION_SETTINGS_VALIDATION_ERRORS.INVALID_EXCLUDED_ORIGIN
      };
    }
    const text = candidate.trim();
    if (!text) continue;
    nonEmptyCount += 1;
    if (nonEmptyCount > MAX_EXCLUDED_ORIGINS) {
      return {
        ok: false,
        error: OBSERVATION_SETTINGS_VALIDATION_ERRORS.TOO_MANY_EXCLUDED_ORIGINS
      };
    }
    const origin = parsedObservationOrigin(text, { exactOrigin: true });
    if (!origin) {
      return {
        ok: false,
        error: OBSERVATION_SETTINGS_VALIDATION_ERRORS.INVALID_EXCLUDED_ORIGIN
      };
    }
    if (!seenOrigins.has(origin)) {
      seenOrigins.add(origin);
      origins.push(origin);
    }
  }

  return {
    ok: true,
    settings: {
      enabled: value?.enabled === undefined ? true : value.enabled === true,
      excludedOrigins: origins
    }
  };
}

export function isObservationAllowed(url, settings = DEFAULT_OBSERVATION_SETTINGS) {
  return createObservationMatcher(settings)(url);
}

export function createObservationMatcher(settings = DEFAULT_OBSERVATION_SETTINGS) {
  const normalized = normalizeObservationSettings(settings);
  const excludedOrigins = new Set(normalized.excludedOrigins);

  return (url) => {
    if (!normalized.enabled) return false;
    try {
      return !excludedOrigins.has(new URL(url).origin);
    } catch {
      return false;
    }
  };
}

export async function loadObservationSettings() {
  const storage = await trustedObservationStorage();
  if (!storage) return { enabled: true, excludedOrigins: [] };
  const stored = await storage.get(OBSERVATION_SETTINGS_KEY);
  return normalizeObservationSettings(stored[OBSERVATION_SETTINGS_KEY]);
}

export async function saveObservationSettings(settings) {
  const validation = validateObservationSettingsInput(settings);
  if (!validation.ok) {
    const error = new TypeError(validation.error);
    error.code = validation.error;
    throw error;
  }
  const normalized = validation.settings;
  const storage = await trustedObservationStorage();
  if (storage) await storage.set({ [OBSERVATION_SETTINGS_KEY]: normalized });
  return normalized;
}

async function trustedObservationStorage() {
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
