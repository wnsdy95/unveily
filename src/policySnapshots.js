import { localeCode, t } from "./i18n.js";
import { ensureTrustedLocalStorage } from "./trustedLocalStorage.js";

export const POLICY_SNAPSHOTS_KEY = "policySnapshots";
export const POLICY_CHECK_HEALTH_KEY = "policyCheckHealth";
export const POLICY_CHECK_ERROR_CATEGORIES = Object.freeze([
  "network",
  "timeout",
  "http_status",
  "redirect",
  "content_type",
  "response_too_large",
  "invalid_url",
  "not_policy",
  "unknown"
]);
const MAX_TEXT_LENGTH = 80000;
const MAX_POLICY_SNAPSHOTS = 50;
const MAX_POLICY_SNAPSHOT_BYTES = 6 * 1024 * 1024;
const MAX_CONSECUTIVE_POLICY_FAILURES = 10_000;
const NOTIFIED_POLICY_CHANGES_KEY = "notifiedPolicyChanges";
const IMPORTANT_SECTION_IDS = new Set(["third_party", "cookies_tracking", "overseas_transfer", "retention", "legal_basis", "security", "processors"]);
const SAFE_POLICY_QUERY_KEYS = new Set(["hl", "lang", "locale", "v", "version"]);
const SAFE_POLICY_LOCALE_VALUE = /^[a-z]{2,3}(?:[-_][a-z]{2,4}){0,2}$/i;
const SAFE_POLICY_VERSION_VALUE = /^v?\d{1,4}(?:[._-]\d{1,4}){0,4}$/i;
const MAX_SAFE_POLICY_QUERY_PARAMS = 4;
const POLICY_STORAGE_LOCK_NAME = "unveily-policy-snapshots";
const ALLOWED_POLICY_CHECK_ERROR_CATEGORIES = new Set(POLICY_CHECK_ERROR_CATEGORIES);
let fallbackPolicyStorageQueue = Promise.resolve();

export async function loadPolicySnapshots() {
  return (await withPolicyStorageLock(loadPolicySnapshotsUnlocked)) || {};
}

async function loadPolicySnapshotsUnlocked() {
  const result = await readPolicyStorage(POLICY_SNAPSHOTS_KEY);
  if (!result) return null;
  const stored = result[POLICY_SNAPSHOTS_KEY];
  if (!stored || typeof stored !== "object" || Array.isArray(stored)) return {};

  let migrated = false;
  const snapshots = {};
  for (const [storedKey, snapshot] of Object.entries(stored).slice(0, MAX_POLICY_SNAPSHOTS * 5)) {
    const normalizedSnapshot = sanitizePolicySnapshot(snapshot, storedKey);
    if (!normalizedSnapshot) {
      migrated = true;
      continue;
    }
    if (canUpgradeLegacyTextHash(snapshot, normalizedSnapshot)) {
      const secureHash = await hashTextSecure(normalizedSnapshot.normalizedText);
      if (/^[a-f0-9]{64}$/.test(secureHash)) {
        normalizedSnapshot.legacyTextHash = normalizedSnapshot.textHash;
        normalizedSnapshot.textHash = secureHash;
        normalizedSnapshot.hashAlgorithm = "sha256";
        migrated = true;
      }
    }
    const key = normalizedSnapshot.key;
    migrated ||=
      key !== storedKey ||
      snapshot.key !== key ||
      snapshot.url !== normalizedSnapshot.url ||
      snapshots[key] !== undefined;
    snapshots[key] = normalizedSnapshot;
  }

  const prunedSnapshots = prunePolicySnapshots(snapshots);
  if (migrated || Object.keys(prunedSnapshots).length !== Object.keys(snapshots).length) {
    await writePolicyStorage({ [POLICY_SNAPSHOTS_KEY]: prunedSnapshots });
  }
  return prunedSnapshots;
}

export async function savePolicySnapshot(snapshot) {
  return withPolicyStorageLock(async () => {
    const snapshots = await loadPolicySnapshotsUnlocked();
    if (!snapshots) return;
    const normalizedSnapshot = sanitizePolicySnapshot(snapshot, snapshot?.key || snapshot?.origin);
    if (!normalizedSnapshot) throw new Error("A valid HTTPS policy URL is required.");
    snapshots[normalizedSnapshot.key] = normalizedSnapshot;
    const prunedSnapshots = prunePolicySnapshots(snapshots);
    const stored = await readPolicyStorage([
      NOTIFIED_POLICY_CHANGES_KEY,
      POLICY_CHECK_HEALTH_KEY
    ]);
    if (!stored) return;
    const notifiedChanges = sanitizeNotificationDedupe(stored[NOTIFIED_POLICY_CHANGES_KEY]);
    const policyCheckHealth = sanitizePolicyCheckHealth(
      stored[POLICY_CHECK_HEALTH_KEY],
      prunedSnapshots
    );
    delete notifiedChanges[normalizedSnapshot.key];
    delete policyCheckHealth[normalizedSnapshot.key];
    for (const key of Object.keys(notifiedChanges)) {
      if (!prunedSnapshots[key]) delete notifiedChanges[key];
    }
    await writePolicyStorage({
      [POLICY_SNAPSHOTS_KEY]: prunedSnapshots,
      [NOTIFIED_POLICY_CHANGES_KEY]: notifiedChanges,
      [POLICY_CHECK_HEALTH_KEY]: policyCheckHealth
    });
  });
}

export async function loadPolicySnapshot(keyOrOrigin) {
  const snapshots = await loadPolicySnapshots();
  const canonicalKey = normalizePolicyUrl(keyOrOrigin);
  return canonicalKey ? snapshots[canonicalKey] || null : null;
}

export async function deletePolicySnapshot(keyOrOrigin) {
  return withPolicyStorageLock(async () => {
    const snapshots = await loadPolicySnapshotsUnlocked();
    if (!snapshots) return false;
    const canonicalKey = normalizePolicyUrl(keyOrOrigin);
    const keysToDelete = canonicalKey && snapshots[canonicalKey] ? [canonicalKey] : [];
    keysToDelete.forEach((key) => delete snapshots[key]);

    const stored = await readPolicyStorage([
      NOTIFIED_POLICY_CHANGES_KEY,
      POLICY_CHECK_HEALTH_KEY
    ]);
    if (!stored) return false;
    const notifiedChanges = sanitizeNotificationDedupe(stored[NOTIFIED_POLICY_CHANGES_KEY]);
    const policyCheckHealth = sanitizePolicyCheckHealth(
      stored[POLICY_CHECK_HEALTH_KEY],
      snapshots
    );
    keysToDelete.forEach((key) => delete notifiedChanges[key]);
    keysToDelete.forEach((key) => delete policyCheckHealth[key]);
    delete notifiedChanges[String(keyOrOrigin || "")];

    await writePolicyStorage({
      [POLICY_SNAPSHOTS_KEY]: snapshots,
      [NOTIFIED_POLICY_CHANGES_KEY]: notifiedChanges,
      [POLICY_CHECK_HEALTH_KEY]: policyCheckHealth
    });
    return keysToDelete.length > 0;
  });
}

export async function loadPolicyCheckHealth() {
  return withPolicyStorageLock(async () => {
    const snapshots = await loadPolicySnapshotsUnlocked();
    if (!snapshots) return {};
    const stored = await readPolicyStorage(POLICY_CHECK_HEALTH_KEY);
    if (!stored) return {};
    const rawHealth = stored[POLICY_CHECK_HEALTH_KEY];
    const policyCheckHealth = sanitizePolicyCheckHealth(rawHealth, snapshots);
    if (!policyCheckHealthMatchesStoredValue(rawHealth, policyCheckHealth)) {
      await writePolicyStorage({ [POLICY_CHECK_HEALTH_KEY]: policyCheckHealth });
    }
    return policyCheckHealth;
  });
}

export async function recordPolicyCheckResults(results, checkedAt) {
  return withPolicyStorageLock(async () => {
    const snapshots = await loadPolicySnapshotsUnlocked();
    if (!snapshots) return {};
    const attemptAt = normalizeHealthTimestamp(checkedAt);
    if (!attemptAt) throw new TypeError("A valid policy check timestamp is required.");

    const stored = await readPolicyStorage(POLICY_CHECK_HEALTH_KEY);
    if (!stored) return {};
    const policyCheckHealth = sanitizePolicyCheckHealth(
      stored[POLICY_CHECK_HEALTH_KEY],
      snapshots
    );
    const resultsByKey = new Map();

    for (const result of (Array.isArray(results) ? results : []).slice(0, MAX_POLICY_SNAPSHOTS * 5)) {
      if (!result || typeof result !== "object" || Array.isArray(result)) continue;
      const rawSnapshotKey = String(result.snapshotKey || "");
      const snapshotKey = normalizePolicyUrl(rawSnapshotKey);
      const baseline = snapshotKey ? snapshots[snapshotKey] : null;
      if (
        !snapshotKey ||
        snapshotKey !== rawSnapshotKey ||
        !baseline ||
        String(result.baselineCapturedAt || "") !== String(baseline.capturedAt || "")
      ) {
        continue;
      }
      resultsByKey.set(snapshotKey, result);
    }

    for (const [snapshotKey, result] of resultsByKey) {
      const previous = policyCheckHealth[snapshotKey];
      if (result.ok === true) {
        policyCheckHealth[snapshotKey] = {
          lastAttemptAt: attemptAt,
          lastSuccessAt: attemptAt,
          consecutiveFailures: 0,
          errorCategory: ""
        };
        continue;
      }

      const errorCategory = ALLOWED_POLICY_CHECK_ERROR_CATEGORIES.has(result.errorCategory)
        ? result.errorCategory
        : "unknown";
      policyCheckHealth[snapshotKey] = {
        lastAttemptAt: attemptAt,
        lastSuccessAt: normalizeHealthTimestamp(previous?.lastSuccessAt),
        consecutiveFailures: Math.min(
          MAX_CONSECUTIVE_POLICY_FAILURES,
          Math.max(0, Number(previous?.consecutiveFailures) || 0) + 1
        ),
        errorCategory
      };
    }

    const prunedHealth = sanitizePolicyCheckHealth(policyCheckHealth, snapshots);
    await writePolicyStorage({ [POLICY_CHECK_HEALTH_KEY]: prunedHealth });
    return prunedHealth;
  });
}

async function trustedPolicyStorage() {
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

async function readPolicyStorage(keys) {
  const storage = await trustedPolicyStorage();
  return storage ? storage.get(keys) : null;
}

async function writePolicyStorage(value) {
  const storage = await trustedPolicyStorage();
  if (storage) await storage.set(value);
}

export async function withPolicyStorageLock(task) {
  if (typeof task !== "function") throw new TypeError("A policy storage task is required.");

  const locks = globalThis.navigator?.locks;
  if (typeof locks?.request === "function") {
    return locks.request(POLICY_STORAGE_LOCK_NAME, { mode: "exclusive" }, task);
  }

  const previousTask = fallbackPolicyStorageQueue;
  let releaseCurrentTask;
  fallbackPolicyStorageQueue = new Promise((resolve) => {
    releaseCurrentTask = resolve;
  });
  await previousTask.catch(() => {});
  try {
    return await task();
  } finally {
    releaseCurrentTask();
  }
}

export async function createPolicySnapshot({ title, url, text, policyAnalysis }) {
  const canonicalUrl = normalizePolicyUrl(url);
  const completeNormalizedText = normalizePolicyText(text);
  const normalizedText = completeNormalizedText.slice(0, MAX_TEXT_LENGTH);
  const policySections = await Promise.all(
    (Array.isArray(policyAnalysis?.policySections) ? policyAnalysis.policySections : [])
      .slice(0, 40)
      .map(async (section) => {
        const evidenceText = (Array.isArray(section?.evidence) ? section.evidence : [])
          .slice(0, 20)
          .map((item) => String(item?.excerpt || "").slice(0, 1_200))
          .join("\n");
        return {
          id: section?.id,
          label: section?.label,
          found: section?.found,
          hash: await hashTextSecure(evidenceText),
          legacyHash: hashText(evidenceText),
          excerpt: String(section?.evidence?.[0]?.excerpt || "").slice(0, 1_200)
        };
      })
  );
  const textHash = await hashTextSecure(completeNormalizedText);

  return {
    key: canonicalUrl,
    origin: originFromUrl(canonicalUrl),
    title: title || "",
    url: canonicalUrl,
    capturedAt: new Date().toISOString(),
    textHash,
    hashAlgorithm: textHash.length === 64 ? "sha256" : "fnv1a64",
    legacyTextHash: hashText(completeNormalizedText),
    textLength: completeNormalizedText.length,
    textTruncated: completeNormalizedText.length > MAX_TEXT_LENGTH,
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
  const textChanged = !compatibleHashesEqual(
    previous.textHash,
    current.textHash,
    previous.legacyTextHash,
    current.legacyTextHash
  );
  const changed =
    textChanged ||
    sectionChanges.length > 0 ||
    riskChanges.added.length > 0 ||
    riskChanges.removed.length > 0;
  const findings = [];

  if (textChanged) {
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

export function normalizePolicyUrl(url) {
  try {
    const rawUrl = String(url || "");
    if (!rawUrl || rawUrl.length > 2_048) return "";
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== "https:") return "";
    if (parsed.username || parsed.password || parsed.hash) return "";
    const safeQuery = new Map();
    for (const [rawKey, rawValue] of parsed.searchParams) {
      const exactKey = String(rawKey || "");
      const key = exactKey.trim().toLowerCase();
      const value = String(rawValue || "").trim();
      if (exactKey !== key) return "";
      if (!SAFE_POLICY_QUERY_KEYS.has(key)) return "";
      if (safeQuery.has(key) || safeQuery.size >= MAX_SAFE_POLICY_QUERY_PARAMS) return "";
      const isValidValue = key === "hl" || key === "lang" || key === "locale"
        ? SAFE_POLICY_LOCALE_VALUE.test(value)
        : SAFE_POLICY_VERSION_VALUE.test(value);
      if (!isValidValue) return "";
      safeQuery.set(key, value);
    }
    // Preserve the browser's original parameter order. Even validated keys can
    // be interpreted by a non-conforming server in order-dependent ways, so a
    // canonical baseline must fetch the exact URL the user opened.
    return parsed.href;
  } catch {
    return "";
  }
}

function canUpgradeLegacyTextHash(sourceSnapshot, normalizedSnapshot) {
  if (!/^[a-f0-9]{16}$/.test(normalizedSnapshot.textHash)) return false;
  if (normalizedSnapshot.textTruncated) return false;
  if (!Object.prototype.hasOwnProperty.call(sourceSnapshot, "normalizedText")) return false;
  if (typeof sourceSnapshot.normalizedText !== "string") return false;
  if (normalizedSnapshot.normalizedText.length !== normalizedSnapshot.textLength) return false;
  return hashText(normalizedSnapshot.normalizedText) === normalizedSnapshot.textHash;
}

export function normalizePolicyText(text) {
  return String(text || "")
    .replace(/\u00a0/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

export function hashText(text) {
  let hash = 0xcbf29ce484222325n;
  const value = String(text || "");

  for (let index = 0; index < value.length; index += 1) {
    hash ^= BigInt(value.charCodeAt(index));
    hash = BigInt.asUintN(64, hash * 0x100000001b3n);
  }

  return hash.toString(16).padStart(16, "0");
}

export async function hashTextSecure(text) {
  const value = String(text || "");
  try {
    const subtle = globalThis.crypto?.subtle;
    if (!subtle?.digest) return hashText(value);
    const digest = await subtle.digest("SHA-256", new TextEncoder().encode(value));
    return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
  } catch {
    // Older or restricted extension runtimes can still compare snapshots with the bounded legacy hash.
    return hashText(value);
  }
}

export function prunePolicySnapshots(
  snapshots,
  maxCount = MAX_POLICY_SNAPSHOTS,
  maxBytes = MAX_POLICY_SNAPSHOT_BYTES
) {
  const entries = Object.entries(snapshots || {})
    .sort(([, a], [, b]) => String(b.capturedAt || "").localeCompare(String(a.capturedAt || "")))
    .slice(0, Math.max(0, maxCount));
  const selected = [];
  let byteCount = 2;

  for (const entry of entries) {
    const entryBytes = jsonByteLength({ [entry[0]]: entry[1] });
    if (selected.length > 0 && byteCount + entryBytes > maxBytes) continue;
    if (entryBytes > maxBytes) continue;
    selected.push(entry);
    byteCount += entryBytes;
  }

  return Object.fromEntries(selected);
}

function sanitizePolicySnapshot(snapshot, fallbackUrl = "") {
  if (!snapshot || typeof snapshot !== "object" || Array.isArray(snapshot)) return null;
  const canonicalUrl = normalizePolicyUrl(snapshot.url || snapshot.key || fallbackUrl);
  if (!canonicalUrl) return null;
  const policySections = (Array.isArray(snapshot.policySections) ? snapshot.policySections : [])
    .slice(0, 40)
    .filter((section) => section && typeof section === "object" && !Array.isArray(section))
    .map((section) => {
      const excerpt = String(section.excerpt || "").slice(0, 1_200);
      const storedHash = String(section.hash || "");
      const normalizedHash = /^(?:[a-f0-9]{16}|[a-f0-9]{64})$/i.test(storedHash)
        ? storedHash.toLowerCase()
        : hashText(excerpt);
      const storedLegacyHash = String(section.legacyHash || "");
      return {
        id: String(section.id || "").slice(0, 80),
        label: String(section.label || "").slice(0, 160),
        found: Boolean(section.found),
        hash: normalizedHash,
        legacyHash: /^[a-f0-9]{16}$/i.test(storedLegacyHash)
          ? storedLegacyHash.toLowerCase()
          : normalizedHash.length === 16
            ? normalizedHash
            : "",
        excerpt
      };
    })
    .filter((section) => section.id);
  const riskSummary = snapshot.riskSummary && typeof snapshot.riskSummary === "object"
    ? snapshot.riskSummary
    : {};
  const normalizedText = String(snapshot.normalizedText || "").slice(0, MAX_TEXT_LENGTH);
  const rawTextLength = Number(snapshot.textLength);
  const textLength = Number.isFinite(rawTextLength)
    ? Math.max(0, Math.min(10_000_000, rawTextLength))
    : normalizedText.length;
  const rawRiskScore = Number(riskSummary.score);
  const rawCapturedAt = new Date(snapshot.capturedAt || 0);
  const capturedAt = Number.isFinite(rawCapturedAt.getTime())
    ? rawCapturedAt.toISOString()
    : new Date(0).toISOString();
  const storedTextHash = String(snapshot.textHash || "");
  const normalizedTextHash = /^(?:[a-f0-9]{16}|[a-f0-9]{64})$/i.test(storedTextHash)
    ? storedTextHash.toLowerCase()
    : hashText(normalizedText);
  const storedLegacyTextHash = String(snapshot.legacyTextHash || "");

  return {
    key: canonicalUrl,
    origin: originFromUrl(canonicalUrl),
    title: String(snapshot.title || "").slice(0, 300),
    url: canonicalUrl,
    capturedAt,
    textHash: normalizedTextHash,
    hashAlgorithm: normalizedTextHash.length === 64 ? "sha256" : "fnv1a64",
    legacyTextHash: /^[a-f0-9]{16}$/i.test(storedLegacyTextHash)
      ? storedLegacyTextHash.toLowerCase()
      : normalizedTextHash.length === 16
        ? normalizedTextHash
        : "",
    textLength,
    textTruncated: Boolean(snapshot.textTruncated || textLength > normalizedText.length),
    normalizedText,
    policySections,
    riskSummary: {
      level: String(riskSummary.level || "").slice(0, 40),
      score: Number.isFinite(rawRiskScore) ? Math.max(0, Math.min(100, rawRiskScore)) : null,
      riskIds: Array.from(
        new Set(
          (Array.isArray(riskSummary.riskIds) ? riskSummary.riskIds : [])
            .slice(0, 100)
            .map((id) => String(id).slice(0, 120))
            .filter(Boolean)
        )
      )
    }
  };
}

export function sanitizeNotificationDedupe(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return Object.fromEntries(
    Object.entries(value)
      .slice(0, MAX_POLICY_SNAPSHOTS * 2)
      .filter(([key, dedupe]) => normalizePolicyUrl(key) && typeof dedupe === "string")
      .map(([key, dedupe]) => [normalizePolicyUrl(key), dedupe.slice(0, 512)])
  );
}

function sanitizePolicyCheckHealth(value, snapshots) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  const availableSnapshots = snapshots && typeof snapshots === "object" && !Array.isArray(snapshots)
    ? snapshots
    : {};
  const entries = [];

  for (const [storedKey, record] of Object.entries(value).slice(0, MAX_POLICY_SNAPSHOTS * 5)) {
    const canonicalKey = normalizePolicyUrl(storedKey);
    if (
      !canonicalKey ||
      canonicalKey !== storedKey ||
      !availableSnapshots[canonicalKey] ||
      !record ||
      typeof record !== "object" ||
      Array.isArray(record)
    ) {
      continue;
    }

    const lastAttemptAt = normalizeHealthTimestamp(record.lastAttemptAt);
    if (!lastAttemptAt) continue;
    const consecutiveFailures = Math.min(
      MAX_CONSECUTIVE_POLICY_FAILURES,
      Math.max(0, Math.trunc(Number(record.consecutiveFailures) || 0))
    );
    const errorCategory = consecutiveFailures > 0
      ? ALLOWED_POLICY_CHECK_ERROR_CATEGORIES.has(record.errorCategory)
        ? record.errorCategory
        : "unknown"
      : "";
    entries.push([
      canonicalKey,
      {
        lastAttemptAt,
        lastSuccessAt: normalizeHealthTimestamp(record.lastSuccessAt),
        consecutiveFailures,
        errorCategory
      }
    ]);
  }

  return Object.fromEntries(entries.slice(0, MAX_POLICY_SNAPSHOTS));
}

function normalizeHealthTimestamp(value) {
  if (typeof value !== "string" && typeof value !== "number" && !(value instanceof Date)) return "";
  const date = new Date(value);
  return Number.isFinite(date.getTime()) ? date.toISOString() : "";
}

function policyCheckHealthMatchesStoredValue(stored, sanitized) {
  if (!stored || typeof stored !== "object" || Array.isArray(stored)) {
    return Object.keys(sanitized).length === 0 && stored === undefined;
  }
  const storedEntries = Object.entries(stored);
  const sanitizedEntries = Object.entries(sanitized);
  if (storedEntries.length !== sanitizedEntries.length) return false;
  return sanitizedEntries.every(([key, record]) => {
    const storedRecord = stored[key];
    return Boolean(
      storedRecord &&
      typeof storedRecord === "object" &&
      !Array.isArray(storedRecord) &&
      Object.keys(storedRecord).length === 4 &&
      storedRecord.lastAttemptAt === record.lastAttemptAt &&
      storedRecord.lastSuccessAt === record.lastSuccessAt &&
      storedRecord.consecutiveFailures === record.consecutiveFailures &&
      storedRecord.errorCategory === record.errorCategory
    );
  });
}

function jsonByteLength(value) {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
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
      if (
        previous?.found &&
        current?.found &&
        !compatibleHashesEqual(previous.hash, current.hash, previous.legacyHash, current.legacyHash)
      ) {
        return { id, label: current.label, changeType: "modified", before: previous.excerpt, after: current.excerpt };
      }

      return null;
    })
    .filter(Boolean);
}

function compatibleHashesEqual(previousHash, currentHash, previousLegacyHash = "", currentLegacyHash = "") {
  const previous = String(previousHash || "").toLowerCase();
  const current = String(currentHash || "").toLowerCase();
  if (previous && previous === current) return true;

  const previousLegacy = String(previousLegacyHash || "").toLowerCase();
  const currentLegacy = String(currentLegacyHash || "").toLowerCase();
  if (/^[a-f0-9]{16}$/.test(previous) && previous === currentLegacy) return true;
  if (/^[a-f0-9]{16}$/.test(current) && current === previousLegacy) return true;
  return false;
}

function compareRiskIds(previousRiskIds, currentRiskIds) {
  const previous = new Set(previousRiskIds);
  const current = new Set(currentRiskIds);

  return {
    added: Array.from(current).filter((id) => !previous.has(id)),
    removed: Array.from(previous).filter((id) => !current.has(id))
  };
}
