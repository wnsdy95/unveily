const trustedAccessPromises = new WeakMap();
const DEFAULT_ACCESS_LEVEL_TIMEOUT_MS = 5_000;

function defaultLocalStorageArea() {
  try {
    return globalThis.chrome?.storage?.local;
  } catch {
    return undefined;
  }
}

function canCacheStorageArea(storageArea) {
  return storageArea !== null &&
    (typeof storageArea === "object" || typeof storageArea === "function");
}

/**
 * Restrict extension-local storage to trusted extension contexts before it is
 * used. In-flight and successful decisions are shared per StorageArea;
 * failures are removed after resolving so a later invocation can retry.
 */
export function ensureTrustedLocalStorage(
  storageArea = defaultLocalStorageArea(),
  { timeoutMs = DEFAULT_ACCESS_LEVEL_TIMEOUT_MS } = {}
) {
  if (!canCacheStorageArea(storageArea)) return Promise.resolve(false);

  const existing = trustedAccessPromises.get(storageArea);
  if (existing) return existing;

  const accessOperation = Promise.resolve().then(async () => {
    try {
      if (typeof storageArea.setAccessLevel !== "function") return false;
      await storageArea.setAccessLevel({ accessLevel: "TRUSTED_CONTEXTS" });
      return true;
    } catch {
      return false;
    }
  });
  const boundedTimeoutMs = Number.isFinite(timeoutMs)
    ? Math.max(1, Math.min(30_000, Math.trunc(timeoutMs)))
    : DEFAULT_ACCESS_LEVEL_TIMEOUT_MS;
  let timeoutId;
  const timeout = new Promise((resolve) => {
    try {
      if (typeof globalThis.setTimeout !== "function") {
        resolve(false);
        return;
      }
      timeoutId = globalThis.setTimeout(() => resolve(false), boundedTimeoutMs);
    } catch {
      resolve(false);
    }
  });
  const accessPromise = Promise.race([accessOperation, timeout]).finally(() => {
    try {
      if (timeoutId !== undefined && typeof globalThis.clearTimeout === "function") {
        globalThis.clearTimeout(timeoutId);
      }
    } catch {
      // The access decision is already fail-closed even if timer cleanup fails.
    }
  });
  trustedAccessPromises.set(storageArea, accessPromise);
  void accessPromise.then((trusted) => {
    if (!trusted && trustedAccessPromises.get(storageArea) === accessPromise) {
      trustedAccessPromises.delete(storageArea);
    }
  });
  return accessPromise;
}

/**
 * Run a local-storage operation only after the trusted-context boundary has
 * been confirmed. The unavailable callback must not read or write storage.
 */
export async function withTrustedLocalStorage(
  task,
  {
    storageArea = defaultLocalStorageArea(),
    onUnavailable = () => undefined,
    timeoutMs = DEFAULT_ACCESS_LEVEL_TIMEOUT_MS
  } = {}
) {
  if (typeof task !== "function" || typeof onUnavailable !== "function") {
    throw new TypeError("Trusted local-storage callbacks must be functions");
  }
  if (!(await ensureTrustedLocalStorage(storageArea, { timeoutMs }))) return onUnavailable();
  return task(storageArea);
}
