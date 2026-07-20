export const COMPANION_OVERLAY_ENABLED_KEY = "companionOverlayEnabled";

export function normalizeCompanionOverlayEnabled(value) {
  return value === true;
}

export async function loadCompanionOverlayEnabled(storageArea = globalThis.chrome?.storage?.local) {
  try {
    const stored = await storageArea.get(COMPANION_OVERLAY_ENABLED_KEY);
    return normalizeCompanionOverlayEnabled(stored?.[COMPANION_OVERLAY_ENABLED_KEY]);
  } catch {
    return false;
  }
}

export function companionStorageUnavailableResponse() {
  return {
    ok: false,
    enabled: false,
    code: "STORAGE_ISOLATION_UNAVAILABLE",
    error: "Trusted local storage is unavailable"
  };
}
