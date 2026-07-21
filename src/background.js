import { MAX_POLICY_ANALYSIS_CHARS, analyzePolicy } from "./analyzer.js";
import {
  POLICY_SNAPSHOTS_KEY,
  comparePolicySnapshot,
  createPolicySnapshot,
  hashText,
  loadPolicyCheckHealth,
  loadPolicySnapshots,
  normalizePolicyUrl,
  normalizePolicyText,
  recordPolicyCheckResults,
  savePolicySnapshot,
  sanitizeNotificationDedupe,
  withPolicyStorageLock
} from "./policySnapshots.js";
import {
  buildPolicyChangeDedupeKey,
  buildPolicyChangeNotification,
  extractPolicyTextFromHtml,
  shouldNotifyPolicyChange
} from "./policyMonitor.js";
import {
  documentUrlFingerprint,
  cookieIdentity,
  fetchPolicyDocument,
  getCookieAttributionTabIds,
  isObservationSessionCurrent,
  isRequestEventInSession,
  mapPolicyChecksWithConcurrency,
  reconcileCookieRecords,
  sanitizeCookieRecord,
  sanitizeFieldKeys,
  sanitizeNetworkUrl,
  sanitizeRequestDetails,
  sameDocumentUrl,
  validatePolicyFetchUrl,
  validateRuntimeMessage
} from "./backgroundSecurity.js";
import { getLocalePreference, setLocalePreference, t } from "./i18n.js";
import { createCompanionState } from "./companionRuntime.js";
import {
  COMPANION_OVERLAY_ENABLED_KEY,
  companionStorageUnavailableResponse,
  loadCompanionOverlayEnabled,
  normalizeCompanionOverlayEnabled
} from "./companionSettings.js";
import {
  createCompanionOverlayRuntime,
  reserveCompanionOverlayGeneration
} from "./companionOverlayRuntime.js";
import {
  OBSERVATION_SETTINGS_KEY,
  createObservationMatcher,
  normalizeObservationSettings
} from "./observationSettings.js";
import { createCookieChangeQueue, createTabRequestTokenBucket } from "./runtimeLimits.js";
import { riskColorForScore } from "./riskColor.js";
import { ensureTrustedLocalStorage } from "./trustedLocalStorage.js";
import {
  ANALYSIS_MODE_PREFERENCE_KEY,
  DEFAULT_ANALYSIS_MODE,
  loadAnalysisModePreference,
  normalizeAnalysisModePreference,
  saveAnalysisModePreference
} from "./analysisModePreference.js";

const MAX_REQUESTS_PER_TAB = 300;
const MAX_COOKIES_PER_TAB = 120;
const MAX_SNAPSHOTS_PER_TAB = 5;
const MAX_TRACKED_FRAME_DOCUMENTS = 64;
const MAX_LIVE_FRAMES_INSPECTED = 512;
const MAX_OBSERVED_TABS = 50;
const MAX_PERSISTED_TABS = MAX_OBSERVED_TABS;
const MAX_PERSISTED_STATE_BYTES = 4 * 1024 * 1024;
const OBSERVATION_TTL_MS = 60 * 60 * 1000;
const SESSION_PERSIST_DELAY_MS = 2_000;
const SESSION_PERSIST_MAX_RETRIES = 3;
const COOKIE_CHANGE_BATCH_DELAY_MS = 100;
const MAX_PENDING_COOKIE_CHANGES = 500;
const MAX_PENDING_COOKIE_CHANGES_PER_DOMAIN = 50;
const MAX_PENDING_INITIAL_REQUESTS = 500;
const MAX_PENDING_INITIAL_REQUESTS_PER_TAB = 50;
const SUBRESOURCE_REQUEST_BURST_CAPACITY = 300;
const SUBRESOURCE_REQUEST_REFILL_PER_SECOND = 60;
const MAX_REQUEST_RATE_BUCKETS = 256;
const REQUEST_RATE_BUCKET_IDLE_TTL_MS = 10 * 60 * 1000;
const OBSERVATION_SESSION_KEY = "observationSessionStateV1";
const OBSERVATION_SESSION_VERSION = 4;
const OBSERVATION_SESSION_LAYOUT = "per-tab-v1";
const OBSERVATION_SESSION_SHARD_PREFIX = "observationSessionTabV4:";
const MAX_PERSISTED_INDEX_BYTES = 256 * 1024;
const MAX_PERSISTED_TAB_SHARD_BYTES = Math.floor(
  (MAX_PERSISTED_STATE_BYTES - MAX_PERSISTED_INDEX_BYTES) / MAX_PERSISTED_TABS
);
const tabRequests = new Map();
const tabCookies = new Map();
const tabObservationStartedAt = new Map();
const tabSnapshots = new Map();
const tabRiskIndicators = new Map();
const tabTransientCompanionStates = new Map();
const tabSessions = new Map();
const tabGenerations = new Map();
const tabFrameDocuments = new Map();
const tabProvisionalFrameDocuments = new Map();
const pendingMainFrameNavigations = new Map();
const pendingFrameNavigations = new Map();
const tabRecoveryPromises = new Map();
const tabEligibility = new Map();
const tabRateLimitMainRequestIds = new Map();
const initializationNavigationTabs = new Set();
const POLICY_CHECK_ALARM = "policy-snapshot-check";
const OBSERVATION_TTL_ALARM = "observation-session-expiry";
const NOTIFIED_POLICY_CHANGES_KEY = "notifiedPolicyChanges";
const POLICY_CHECK_INTERVAL_MINUTES = 360;
const POLICY_CHECK_INTERVAL_MS = POLICY_CHECK_INTERVAL_MINUTES * 60 * 1000;
const EXPLICIT_INDICATOR_PRIORITY_MS = 5 * 60 * 1000;
const EXPLICIT_INDICATOR_SOURCES = new Set(["popup-page", "popup-cookie"]);
const RISK_LEVELS = new Set(["unknown", "analyzing", "low", "medium", "high"]);
let persistTimer = null;
let persistInFlight = null;
let persistFailureCount = 0;
let cookieFlushTimer = null;
let cookieFlushInFlight = null;
const subresourceRequestLimiter = createTabRequestTokenBucket({
  capacity: SUBRESOURCE_REQUEST_BURST_CAPACITY,
  refillPerSecond: SUBRESOURCE_REQUEST_REFILL_PER_SECOND,
  maxEntries: MAX_REQUEST_RATE_BUCKETS,
  idleTtlMs: REQUEST_RATE_BUCKET_IDLE_TTL_MS
});
const pendingCookieChanges = createCookieChangeQueue({
  maxSize: MAX_PENDING_COOKIE_CHANGES,
  maxPerDomain: MAX_PENDING_COOKIE_CHANGES_PER_DOMAIN,
  identityOf: (changeInfo) => cookieIdentity(changeInfo?.cookie),
  domainOf: queuedCookieDomain,
  merge: mergeQueuedCookieChanges
});
const pendingInitializationRequests = [];
const dirtyPersistedTabRevisions = new Map();
const deletedPersistedTabRevisions = new Map();
const knownPersistedTabKeys = new Map();
let stateRevision = 0;
let persistedRevision = 0;
let persistenceLayoutDirtyRevision = 0;
let observationSettings = normalizeObservationSettings();
let observationMatcher = createObservationMatcher(observationSettings);
let observationRuntimeState = "initializing";
let localStorageTrustedContextsOnly = false;
let companionOverlayEnabled = false;
let analysisModePreference = DEFAULT_ANALYSIS_MODE;
let analysisModePreferenceWrite = Promise.resolve();
const companionOverlayGenerationReady = reserveCompanionOverlayGeneration(
  chrome.storage.session
).catch(() => null);
let policyCheckInFlight = null;
let policyCheckInFlightForced = false;
let forcedPolicyCheckQueued = null;
let observationSequence = 0;
let observationTtlAlarmScheduledFor = null;
let observationTtlAlarmKnownCleared = false;
let observationTtlEnforcementInFlight = null;

function nextObservationSequence() {
  observationSequence += 1;
  return observationSequence;
}

function applyObservationSettings(value) {
  observationSettings = normalizeObservationSettings(value);
  observationMatcher = createObservationMatcher(observationSettings);
  return observationSettings;
}

function observationRuntimeIsStarting() {
  return observationRuntimeState === "initializing" || observationRuntimeState === "flushing";
}

function markInitializationNavigation(tabId, frameId = 0) {
  if (
    observationRuntimeIsStarting() &&
    frameId === 0 &&
    Number.isInteger(tabId) &&
    tabId >= 0
  ) {
    initializationNavigationTabs.add(tabId);
  }
}

function captureTabObservationBackup(tabId) {
  const session = getLiveTabSession(tabId);
  if (!session) return null;
  return {
    session: { ...session },
    generation: tabGenerations.has(tabId) ? tabGenerations.get(tabId) : null,
    requests: [...(tabRequests.get(tabId) || [])],
    cookies: [...(tabCookies.get(tabId) || [])],
    observationStartedAt: tabObservationStartedAt.get(tabId),
    snapshots: [...(tabSnapshots.get(tabId) || [])],
    riskIndicator: tabRiskIndicators.has(tabId) ? { ...tabRiskIndicators.get(tabId) } : null,
    frameDocuments: new Map(tabFrameDocuments.get(tabId) || []),
    eligible: tabEligibility.get(tabId)
  };
}

function restoreTabObservationBackup(tabId, backup) {
  if (
    !backup?.session ||
    sessionExpired(backup.session) ||
    !observationMatcher(backup.session.origin)
  ) {
    return false;
  }
  tabSessions.set(tabId, { ...backup.session });
  if (Number.isFinite(backup.generation)) tabGenerations.set(tabId, backup.generation);
  else tabGenerations.delete(tabId);
  tabRequests.set(tabId, [...backup.requests]);
  tabCookies.set(tabId, [...backup.cookies]);
  if (Number.isFinite(backup.observationStartedAt)) {
    tabObservationStartedAt.set(tabId, backup.observationStartedAt);
  } else {
    tabObservationStartedAt.delete(tabId);
  }
  tabSnapshots.set(tabId, [...backup.snapshots]);
  tabFrameDocuments.set(tabId, new Map(backup.frameDocuments));
  tabProvisionalFrameDocuments.delete(tabId);
  if (backup.riskIndicator) {
    publishRiskIndicator(tabId, backup.riskIndicator);
  } else {
    tabTransientCompanionStates.delete(tabId);
    tabRiskIndicators.delete(tabId);
    clearActionBadge(tabId);
  }
  tabEligibility.set(tabId, typeof backup.eligible === "boolean" ? backup.eligible : true);
  scheduleObservationStatePersist(tabId);
  return true;
}

function normalizedNavigationTarget(url) {
  const normalized = sanitizeNetworkUrl(url);
  const documentFingerprint = documentUrlFingerprint(url);
  return normalized && documentFingerprint
    ? { navigationKey: normalized.url, documentFingerprint }
    : null;
}

function currentPendingMainBackup(tabId) {
  const pending = pendingMainFrameNavigations.get(tabId);
  // Duration is not a commit signal. Slow responses and redirect chains must
  // keep the last authoritative document as their recovery/persistence base.
  if (!pending) return captureTabObservationBackup(tabId);
  if (!pending.backup || !sessionExpired(pending.backup.session)) {
    return pending.backup || null;
  }
  pending.backup = null;
  pendingMainFrameNavigations.set(tabId, pending);
  scheduleObservationStatePersist(tabId);
  return null;
}

function rememberPendingMainNavigation(tabId, url, options = {}) {
  const explicitNavigation = sanitizeNetworkUrl(options.navigationKey);
  const explicitFingerprint =
    typeof options.documentFingerprint === "string" && options.documentFingerprint.length <= 64
      ? options.documentFingerprint
      : "";
  const target =
    explicitNavigation && explicitFingerprint
      ? {
          navigationKey: explicitNavigation.url,
          documentFingerprint: explicitFingerprint
        }
      : normalizedNavigationTarget(url);
  if (!target) return null;
  const previous = pendingMainFrameNavigations.get(tabId);
  const candidateBackup =
    Object.hasOwn(options, "backup")
      ? options.backup
      : previous
        ? currentPendingMainBackup(tabId)
        : captureTabObservationBackup(tabId);
  const backup =
    candidateBackup?.session && !sessionExpired(candidateBackup.session)
      ? candidateBackup
      : null;
  const pending = {
    ...target,
    documentId:
      typeof options.documentId === "string" ? options.documentId.slice(0, 128) : "",
    timeStamp: Number.isFinite(options.timeStamp) ? options.timeStamp : Date.now(),
    sequence: Number.isFinite(options.sequence) ? options.sequence : nextObservationSequence(),
    capturedAt: Date.now(),
    backup
  };
  pendingMainFrameNavigations.set(tabId, pending);
  while (pendingMainFrameNavigations.size > MAX_OBSERVED_TABS) {
    const oldestTabId = Array.from(pendingMainFrameNavigations.entries()).sort(
      ([, left], [, right]) => left.capturedAt - right.capturedAt
    )[0]?.[0];
    if (oldestTabId === undefined) break;
    pendingMainFrameNavigations.delete(oldestTabId);
  }
  // Persistence uses the committed-page backup while this navigation remains
  // provisional. Reclassify the tab after the pending boundary is installed;
  // rotate/drop may have marked the provisional state immediately beforehand.
  scheduleObservationStatePersist(tabId);
  return pending;
}

function navigationTargetMatchesPending(details, pending) {
  if (!pending) return false;
  const target = normalizedNavigationTarget(details?.url || "");
  if (
    !target ||
    target.navigationKey !== pending.navigationKey ||
    target.documentFingerprint !== pending.documentFingerprint
  ) {
    return false;
  }
  return true;
}

function navigationMatchesPending(details, pending) {
  if (!navigationTargetMatchesPending(details, pending)) return false;
  const documentId =
    typeof details?.documentId === "string" ? details.documentId.slice(0, 128) : "";
  return !documentId || !pending.documentId || documentId === pending.documentId;
}

function rememberPendingFrameNavigation(details, sequence) {
  const { tabId, frameId } = details;
  if (!getLiveTabSession(tabId)) return;
  const target = normalizedNavigationTarget(details.url || "");
  if (!target) return;
  const tabPending = pendingFrameNavigations.get(tabId) || new Map();
  tabPending.set(frameId, {
    ...target,
    sequence,
    capturedAt: Date.now()
  });
  while (tabPending.size > MAX_TRACKED_FRAME_DOCUMENTS) {
    tabPending.delete(tabPending.keys().next().value);
  }
  pendingFrameNavigations.set(tabId, tabPending);
}

function forgetPendingFrameNavigation(tabId, frameId) {
  const tabPending = pendingFrameNavigations.get(tabId);
  if (!tabPending) return;
  tabPending.delete(frameId);
  if (tabPending.size === 0) pendingFrameNavigations.delete(tabId);
}

function takeMatchingPendingFrameNavigation(details) {
  const tabPending = pendingFrameNavigations.get(details.tabId);
  const pending = tabPending?.get(details.frameId);
  if (!pending || !navigationMatchesPending(details, pending)) return null;
  forgetPendingFrameNavigation(details.tabId, details.frameId);
  return pending;
}

function captureRequestEvent(details) {
  if (details.documentLifecycle && details.documentLifecycle !== "active") return null;
  const request = sanitizeRequestDetails(details);
  if (!request) return null;
  const observedAt = Date.now();
  request.timeStamp = observedAt;
  const documentId = typeof details.documentId === "string" ? details.documentId.slice(0, 128) : "";
  if (request.type !== "main_frame" && !documentId) return null;
  return {
    tabId: details.tabId,
    type: request.type,
    frameId: Number.isInteger(details.frameId) ? details.frameId : -1,
    documentId,
    parentDocumentId:
      typeof details.parentDocumentId === "string" ? details.parentDocumentId.slice(0, 128) : "",
    documentFingerprint:
      request.type === "main_frame" ? documentUrlFingerprint(details.url) : "",
    timeStamp: observedAt,
    sequence: nextObservationSequence(),
    request
  };
}

function requestCaptureAllowedByRateLimit(details) {
  return details?.type === "main_frame" || subresourceRequestLimiter.allow(details?.tabId);
}

function resetSubresourceRateLimitForMainFrame(details) {
  if (details?.type !== "main_frame" || !Number.isInteger(details.tabId) || details.tabId < 0) {
    return;
  }
  const requestId =
    typeof details.requestId === "string" ? details.requestId.slice(0, 128) : "";
  if (requestId && tabRateLimitMainRequestIds.get(details.tabId) === requestId) return;
  subresourceRequestLimiter.delete(details.tabId);
  if (requestId) tabRateLimitMainRequestIds.set(details.tabId, requestId);
  else tabRateLimitMainRequestIds.delete(details.tabId);
}

function enqueueInitializationRequest(event) {
  const sameTabIndexes = [];
  for (let index = 0; index < pendingInitializationRequests.length; index += 1) {
    if (pendingInitializationRequests[index].tabId === event.tabId) sameTabIndexes.push(index);
  }

  if (sameTabIndexes.length >= MAX_PENDING_INITIAL_REQUESTS_PER_TAB) {
    const nonMainIndex = sameTabIndexes.find(
      (index) => pendingInitializationRequests[index].type !== "main_frame"
    );
    if (nonMainIndex === undefined && event.type !== "main_frame") return;
    pendingInitializationRequests.splice(nonMainIndex ?? sameTabIndexes[0], 1);
  }

  pendingInitializationRequests.push(event);
  if (pendingInitializationRequests.length <= MAX_PENDING_INITIAL_REQUESTS) return;
  const nonMainIndex = pendingInitializationRequests.findIndex(
    (pending) => pending.type !== "main_frame"
  );
  pendingInitializationRequests.splice(nonMainIndex >= 0 ? nonMainIndex : 0, 1);
}

function recoveredSessionStartedSequence(tabId) {
  let earliestSequence = Number.POSITIVE_INFINITY;
  for (const event of pendingInitializationRequests) {
    if (event.tabId !== tabId || !Number.isFinite(event.sequence)) continue;
    earliestSequence = Math.min(earliestSequence, event.sequence);
  }
  return Number.isFinite(earliestSequence) ? earliestSequence : nextObservationSequence();
}

function rememberRequest(event) {
  const session = getLiveTabSession(event.tabId);
  if (!session) return;
  const topLevelUrl = event.type === "main_frame" ? event.request.url : session.navigationKey;
  if (!observationMatcher(topLevelUrl)) return;
  if (!requestBelongsToSession(event, session)) return;
  if (!touchSession(event.tabId)) return;

  const requests = tabRequests.get(event.tabId) || [];
  requests.push(event.request);

  if (requests.length > MAX_REQUESTS_PER_TAB) {
    requests.splice(0, requests.length - MAX_REQUESTS_PER_TAB);
  }

  tabRequests.set(event.tabId, requests);
  scheduleObservationStatePersist(event.tabId);
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (observationRuntimeState === "paused") return;
    resetSubresourceRateLimitForMainFrame(details);
    if (observationRuntimeIsStarting()) {
      if (!requestCaptureAllowedByRateLimit(details)) return;
      const event = captureRequestEvent(details);
      if (!event) return;
      if (event.type === "main_frame") markInitializationNavigation(event.tabId, 0);
      enqueueInitializationRequest(event);
      return;
    }
    if (details.type === "main_frame") {
      const allowed = observationMatcher(details.url);
      tabEligibility.set(details.tabId, allowed);
      if (!allowed) {
        const event = captureRequestEvent(details);
        if (event) void processCapturedRequest(event).catch(() => {});
        else void observationStateReady.then(() => dropTabObservation(details.tabId)).catch(() => {});
        return;
      }
    } else if (tabEligibility.get(details.tabId) === false) {
      return;
    }
    if (!requestCaptureAllowedByRateLimit(details)) return;
    const event = captureRequestEvent(details);
    if (!event) return;
    void processCapturedRequest(event).catch(() => {});
  },
  { urls: ["http://*/*", "https://*/*"] }
);

async function processCapturedRequest(event) {
  await observationStateReady;
  return processCapturedRequestAfterInitialization(event);
}

async function processCapturedRequestAfterInitialization(event) {
  if (event.type === "main_frame") {
    if (!observationMatcher(event.request.url)) {
      const backup = currentPendingMainBackup(event.tabId);
      tabEligibility.set(event.tabId, false);
      dropTabObservation(event.tabId);
      rememberPendingMainNavigation(event.tabId, event.request.url, {
        backup,
        documentId: event.documentId,
        documentFingerprint: event.documentFingerprint,
        navigationKey: event.request.url,
        timeStamp: event.timeStamp,
        sequence: event.sequence
      });
      return;
    }
    tabEligibility.set(event.tabId, true);
    const current = tabSessions.get(event.tabId);
    if (current && event.sequence < current.startedSequence) return;
    const backup = currentPendingMainBackup(event.tabId);
    const session = rotateTabObservation(event.tabId, event.request.url, event.documentId, {
      documentFingerprint: event.documentFingerprint,
      startedAt: event.timeStamp,
      startedSequence: event.sequence
    });
    if (!session) return;
    rememberPendingMainNavigation(event.tabId, event.request.url, {
      backup,
      documentId: event.documentId,
      documentFingerprint: event.documentFingerprint,
      navigationKey: event.request.url,
      timeStamp: event.timeStamp,
      sequence: event.sequence
    });
  } else if (!getLiveTabSession(event.tabId)) {
    const recovered = await recoverTabObservation(event);
    if (!recovered) return;
  }

  const documentIds = knownFrameDocumentIds(event.tabId);
  if (
    event.type === "sub_frame" &&
    event.documentId &&
    event.parentDocumentId &&
    documentIds.has(event.parentDocumentId)
  ) {
    rememberProvisionalDocumentId(event.tabId, event.frameId, event.documentId);
  }
  rememberRequest(event);
}

async function recoverTabObservation(event) {
  if (tabEligibility.get(event.tabId) === false) return null;
  if (tabRecoveryPromises.has(event.tabId)) return tabRecoveryPromises.get(event.tabId);
  const recovery = recoverTabObservationOnce(event.tabId, {
    startedAt: event.timeStamp,
    startedSequence: event.sequence
  }).finally(() => {
    if (tabRecoveryPromises.get(event.tabId) === recovery) tabRecoveryPromises.delete(event.tabId);
  });
  tabRecoveryPromises.set(event.tabId, recovery);
  return recovery;
}

async function recoverTabObservationOnce(tabId, recoveryBoundary = {}) {
  const context = await getCurrentTabFrameContext(tabId);
  if (!context) return null;
  const { tab, documentId, frameDocuments } = context;
  const allowed = observationMatcher(tab?.url || "");
  tabEligibility.set(tabId, allowed);
  if (!allowed) return null;
  const expectedFingerprint = documentUrlFingerprint(tab.url);
  if (!expectedFingerprint) return null;

  const existing = getLiveTabSession(tabId);
  if (
    existing &&
    existing.documentId === documentId &&
    existing.documentFingerprint === expectedFingerprint
  ) {
    tabFrameDocuments.set(tabId, frameDocuments);
    tabProvisionalFrameDocuments.delete(tabId);
    return existing;
  }

  const session = rotateTabObservation(tabId, tab.url, documentId, {
    documentFingerprint: expectedFingerprint,
    startedAt: recoveryBoundary.startedAt,
    startedSequence: recoveryBoundary.startedSequence
  });
  if (!session) return null;
  tabFrameDocuments.set(tabId, frameDocuments);
  tabProvisionalFrameDocuments.delete(tabId);
  return session;
}

async function getCurrentTabFrameContext(tabId) {
  let initialTab;
  let frames;
  try {
    [initialTab, frames] = await Promise.all([
      chrome.tabs.get(tabId),
      chrome.webNavigation.getAllFrames({ tabId })
    ]);
  } catch {
    return null;
  }

  const eligibleFrames = (Array.isArray(frames) ? frames : []).filter(
    (frame) =>
      Number.isInteger(frame?.frameId) &&
      (!frame.documentLifecycle || frame.documentLifecycle === "active") &&
      typeof frame.documentId === "string" &&
      frame.documentId.length > 0 &&
      frame.documentId.length <= 128
  );
  const topFrame = eligibleFrames.find(
    (frame) => frame.frameId === 0 && sameDocumentUrl(frame.url, initialTab?.url)
  );
  if (!topFrame) return null;
  const activeFrames = [
    topFrame,
    ...eligibleFrames
      .filter((frame) => frame.frameId !== 0)
      .slice(0, MAX_LIVE_FRAMES_INSPECTED - 1)
  ];

  let currentTab;
  let currentTopFrame;
  try {
    [currentTab, currentTopFrame] = await Promise.all([
      chrome.tabs.get(tabId),
      chrome.webNavigation.getFrame({ tabId, frameId: 0 })
    ]);
  } catch {
    return null;
  }
  const documentId =
    typeof currentTopFrame?.documentId === "string"
      ? currentTopFrame.documentId.slice(0, 128)
      : "";
  if (
    !documentId ||
    (currentTopFrame.documentLifecycle && currentTopFrame.documentLifecycle !== "active") ||
    topFrame.documentId !== documentId ||
    !sameDocumentUrl(initialTab?.url, currentTab?.url) ||
    !sameDocumentUrl(topFrame.url, currentTab?.url) ||
    !sameDocumentUrl(currentTopFrame.url, currentTab?.url)
  ) {
    return null;
  }

  const connectedFrameIds = new Set([0]);
  let changed = true;
  while (changed) {
    changed = false;
    for (const frame of activeFrames) {
      if (connectedFrameIds.has(frame.frameId)) continue;
      if (connectedFrameIds.has(frame.parentFrameId)) {
        connectedFrameIds.add(frame.frameId);
        changed = true;
      }
    }
  }
  const frameDocuments = new Map(
    activeFrames
      .filter((frame) => frame.frameId !== 0 && connectedFrameIds.has(frame.frameId))
      .slice(0, MAX_TRACKED_FRAME_DOCUMENTS - 1)
      .map((frame) => [frame.frameId, frame.documentId.slice(0, 128)])
  );
  frameDocuments.set(0, documentId);
  return { tab: currentTab, documentId, frameDocuments };
}

function rememberDocumentId(tabId, frameId, documentId) {
  if (!Number.isInteger(frameId) || frameId < 0 || !documentId) return;
  const frameDocuments = tabFrameDocuments.get(tabId) || new Map();
  frameDocuments.set(frameId, documentId.slice(0, 128));
  while (frameDocuments.size > MAX_TRACKED_FRAME_DOCUMENTS) {
    const removable = Array.from(frameDocuments.keys()).find((id) => id !== 0);
    if (removable === undefined) break;
    frameDocuments.delete(removable);
  }
  tabFrameDocuments.set(tabId, frameDocuments);
}

function rememberProvisionalDocumentId(tabId, frameId, documentId) {
  if (!Number.isInteger(frameId) || frameId <= 0 || !documentId) return;
  const frameDocuments = tabProvisionalFrameDocuments.get(tabId) || new Map();
  const documentIds = frameDocuments.get(frameId) || new Set();
  documentIds.add(documentId.slice(0, 128));
  while (documentIds.size > 4) documentIds.delete(documentIds.values().next().value);
  frameDocuments.set(frameId, documentIds);
  while (frameDocuments.size > MAX_TRACKED_FRAME_DOCUMENTS) {
    frameDocuments.delete(frameDocuments.keys().next().value);
  }
  tabProvisionalFrameDocuments.set(tabId, frameDocuments);
}

function forgetProvisionalDocumentId(tabId, frameId, documentId = "") {
  const frameDocuments = tabProvisionalFrameDocuments.get(tabId);
  if (!frameDocuments) return;
  if (!documentId) {
    frameDocuments.delete(frameId);
  } else {
    const documentIds = frameDocuments.get(frameId);
    documentIds?.delete(documentId.slice(0, 128));
    if (documentIds?.size === 0) frameDocuments.delete(frameId);
  }
  if (frameDocuments.size === 0) tabProvisionalFrameDocuments.delete(tabId);
}

function provisionalDocumentIds(tabId) {
  return Array.from(tabProvisionalFrameDocuments.get(tabId)?.values() || []).flatMap(
    (documentIds) => Array.from(documentIds)
  );
}

function knownFrameDocumentIds(tabId) {
  return new Set([
    ...(tabFrameDocuments.get(tabId) || new Map()).values(),
    ...provisionalDocumentIds(tabId)
  ]);
}

chrome.runtime.onInstalled.addListener((details) => {
  if (details?.reason === "install") {
    const opening = chrome.runtime.openOptionsPage?.();
    opening?.catch?.(() => {});
  }
  void reconcilePolicyCheckSchedule();
});

chrome.runtime.onStartup.addListener(() => {
  void reconcilePolicyCheckSchedule();
});

chrome.runtime.onSuspend?.addListener(() => {
  if (persistTimer) {
    clearTimeout(persistTimer);
    persistTimer = null;
  }
  if (cookieFlushTimer) {
    clearTimeout(cookieFlushTimer);
    cookieFlushTimer = null;
    void flushSanitizedCookieChanges();
  }
  void persistObservationState();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === POLICY_CHECK_ALARM) {
    void runSavedPolicyChecks().catch(() => {});
    return;
  }
  if (alarm.name === OBSERVATION_TTL_ALARM) {
    observationTtlAlarmScheduledFor = null;
    observationTtlAlarmKnownCleared = true;
    void enforceObservationTtlFromAlarm().catch(() => {});
  }
});

chrome.notifications.onClicked.addListener((notificationId) => {
  if (!notificationId.startsWith("policy-change:")) return;
  const token = notificationId.slice("policy-change:".length);
  void observationStateReady
    .then(() => {
      if (!localStorageTrustedContextsOnly) return null;
      return loadPolicySnapshots();
    })
    .then((snapshots) => {
      if (!snapshots) return;
      let snapshotKey = Object.keys(snapshots).find((key) => hashText(key) === token) || "";
      if (!snapshotKey) {
        try {
          const legacyKey = decodeURIComponent(token);
          if (snapshots[legacyKey]) snapshotKey = legacyKey;
        } catch {
          return;
        }
      }
      const candidateUrl = snapshots[snapshotKey]?.url;
      if (!candidateUrl) return;
      try {
        const url = validatePolicyFetchUrl(candidateUrl).href;
        const createdTab = chrome.tabs.create({ url });
        createdTab?.catch?.(() => {});
      } catch {
        // Ignore stale or unsafe notification targets.
      }
    })
    .catch(() => {});
});

function schedulePolicyChecks() {
  const creating = chrome.alarms.create(POLICY_CHECK_ALARM, {
    delayInMinutes: 1,
    periodInMinutes: POLICY_CHECK_INTERVAL_MINUTES
  });
  creating?.catch?.(() => {});
}

async function ensurePolicyChecksScheduled() {
  let existing = null;
  try {
    existing = await chrome.alarms.get(POLICY_CHECK_ALARM);
  } catch {
    // Recreate best-effort when existence cannot be confirmed.
  }
  if (existing?.periodInMinutes !== POLICY_CHECK_INTERVAL_MINUTES) schedulePolicyChecks();
}

async function clearPolicyCheckSchedule() {
  try {
    await chrome.alarms.clear(POLICY_CHECK_ALARM);
  } catch {
    // A failed clear cannot permit a network check while the storage gate is closed.
  }
}

async function reconcilePolicyCheckSchedule() {
  if (await ensureTrustedLocalStorage()) {
    await ensurePolicyChecksScheduled();
    return;
  }
  await clearPolicyCheckSchedule();
}

void reconcilePolicyCheckSchedule();

function earliestObservationTtlDeadline() {
  if (!observationSettings.enabled) return null;
  let earliest = Number.POSITIVE_INFINITY;
  for (const session of tabSessions.values()) {
    if (!Number.isFinite(session?.lastSeenAt)) continue;
    earliest = Math.min(earliest, session.lastSeenAt + OBSERVATION_TTL_MS);
  }
  for (const pending of pendingMainFrameNavigations.values()) {
    const lastSeenAt = pending.backup?.session?.lastSeenAt;
    if (!Number.isFinite(lastSeenAt)) continue;
    earliest = Math.min(earliest, lastSeenAt + OBSERVATION_TTL_MS);
  }
  return Number.isFinite(earliest) ? earliest : null;
}

function scheduleObservationTtlAlarm() {
  if (!chrome.alarms) return;
  const deadline = earliestObservationTtlDeadline();
  if (!Number.isFinite(deadline)) {
    observationTtlAlarmScheduledFor = null;
    if (!observationTtlAlarmKnownCleared) {
      observationTtlAlarmKnownCleared = true;
      const clearing = chrome.alarms.clear?.(OBSERVATION_TTL_ALARM);
      clearing?.catch?.(() => {
        observationTtlAlarmKnownCleared = false;
      });
    }
    return;
  }

  const now = Date.now();
  if (
    Number.isFinite(observationTtlAlarmScheduledFor) &&
    observationTtlAlarmScheduledFor > now &&
    observationTtlAlarmScheduledFor <= deadline
  ) {
    return;
  }
  const when = Math.max(now, deadline);
  observationTtlAlarmScheduledFor = when;
  observationTtlAlarmKnownCleared = false;
  const creating = chrome.alarms.create(OBSERVATION_TTL_ALARM, { when });
  creating?.catch?.(() => {
    if (observationTtlAlarmScheduledFor === when) {
      observationTtlAlarmScheduledFor = null;
      observationTtlAlarmKnownCleared = false;
    }
  });
}

function enforceObservationTtlFromAlarm() {
  if (observationTtlEnforcementInFlight) return observationTtlEnforcementInFlight;
  observationTtlEnforcementInFlight = (async () => {
    // A one-shot alarm can wake a fresh worker before hydration finishes.
    // Base pruning and the next reservation on the hydrated session maps.
    await observationStateReady.catch(() => {});
    if (!observationSettings.enabled) {
      scheduleObservationTtlAlarm();
      return;
    }
    pruneExpiredObservationState(Date.now(), true);
    await persistObservationState();
    scheduleObservationTtlAlarm();
  })().finally(() => {
    observationTtlEnforcementInFlight = null;
  });
  return observationTtlEnforcementInFlight;
}

chrome.tabs.onRemoved.addListener((tabId) => {
  subresourceRequestLimiter.delete(tabId);
  tabRateLimitMainRequestIds.delete(tabId);
  companionOverlayRuntime.forget(tabId);
  void observationStateReady.then(() => {
    dropTabObservation(tabId);
    tabGenerations.delete(tabId);
    tabEligibility.delete(tabId);
    tabRecoveryPromises.delete(tabId);
  }).catch(() => {});
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (!changeInfo.url) return;
  markInitializationNavigation(tabId, 0);
  const sequence = nextObservationSequence();
  const rawUrl = changeInfo.url || tab?.url || "";
  const normalizedUpdateUrl = sanitizeNetworkUrl(rawUrl);
  void observationStateReady.then(() => {
    const current = getLiveTabSession(tabId);
    const previousPending = pendingMainFrameNavigations.get(tabId);
    if (
      (current && sequence < current.startedSequence) ||
      (previousPending && sequence < previousPending.sequence)
    ) {
      return;
    }
    const allowed = Boolean(normalizedUpdateUrl && observationMatcher(rawUrl));
    tabEligibility.set(tabId, allowed);
    if (!normalizedUpdateUrl) {
      // URL update notifications can expose an error/interstitial URL before
      // the attempted navigation fails. They are not a commit boundary, so an
      // existing A backup must remain available to onErrorOccurred.
      return;
    }

    const documentFingerprint = documentUrlFingerprint(rawUrl);
    if (
      allowed &&
      current?.navigationKey === normalizedUpdateUrl.url &&
      current.documentFingerprint === documentFingerprint
    ) {
      return;
    }
    const backup = currentPendingMainBackup(tabId);
    rememberPendingMainNavigation(tabId, rawUrl, {
      backup,
      documentId: previousPending?.documentId,
      timeStamp: previousPending?.timeStamp,
      sequence
    });
  }).catch(() => {});
});

function handleCommittedNavigation(details, authoritativeDocumentCommit = false) {
  if (!Number.isInteger(details?.tabId) || details.tabId < 0) return;
  if (details.documentLifecycle && details.documentLifecycle !== "active") return;
  markInitializationNavigation(details.tabId, details.frameId);
  const sequence = nextObservationSequence();
  void observationStateReady.then(() => {
    const documentId = typeof details.documentId === "string" ? details.documentId.slice(0, 128) : "";
    if (details.frameId !== 0) {
      const tabPending = pendingFrameNavigations.get(details.tabId);
      const pendingFrame = tabPending?.get(details.frameId);
      const frameDocuments = tabFrameDocuments.get(details.tabId);
      const parentFrameId = Number.isInteger(details.parentFrameId)
        ? details.parentFrameId
        : -1;
      const parentDocumentId =
        typeof details.parentDocumentId === "string" ? details.parentDocumentId.slice(0, 128) : "";
      if (
        !documentId ||
        !parentDocumentId ||
        frameDocuments?.get(parentFrameId) !== parentDocumentId ||
        (!authoritativeDocumentCommit && frameDocuments?.get(details.frameId) !== documentId)
      ) {
        return;
      }
      // An active commit with a currently connected parent is authoritative,
      // even if a redirect's final webRequest was unavailable or rate-limited.
      rememberDocumentId(details.tabId, details.frameId, documentId);
      // A commit terminates the whole provisional chain for this frame. This
      // also covers redirects whose final URL differs from onBeforeNavigate.
      forgetProvisionalDocumentId(details.tabId, details.frameId);
      if (pendingFrame) forgetPendingFrameNavigation(details.tabId, details.frameId);
      return;
    }

    if (!observationMatcher(details.url || "")) {
      // The provisional navigation is now final. Its backup belongs to the
      // page that was replaced and must never be reused by a later attempt.
      pendingMainFrameNavigations.delete(details.tabId);
      pendingFrameNavigations.delete(details.tabId);
      tabEligibility.set(details.tabId, false);
      dropTabObservation(details.tabId);
      return;
    }
    tabEligibility.set(details.tabId, true);
    const normalized = sanitizeNetworkUrl(details.url);
    const documentFingerprint = documentUrlFingerprint(details.url);
    if (!normalized || !documentFingerprint) {
      pendingMainFrameNavigations.delete(details.tabId);
      pendingFrameNavigations.delete(details.tabId);
      dropTabObservation(details.tabId);
      return;
    }
    const current = getLiveTabSession(details.tabId);
    if (current && sequence < current.startedSequence) return;
    const pending = pendingMainFrameNavigations.get(details.tabId);
    const belongsToPending =
      pending &&
      navigationTargetMatchesPending(details, pending) &&
      pending.sequence <= sequence;
    if (pending && !belongsToPending) return;
    if (
      current &&
      current.navigationKey === normalized.url &&
      current.documentFingerprint === documentFingerprint &&
      (belongsToPending || !current.documentId || current.documentId === documentId)
    ) {
      const documentChanged = Boolean(
        current.documentId && documentId && current.documentId !== documentId
      );
      if (documentId) current.documentId = documentId;
      if (documentChanged) {
        tabFrameDocuments.set(details.tabId, new Map([[0, documentId]]));
        tabProvisionalFrameDocuments.delete(details.tabId);
      } else if (documentId) {
        rememberDocumentId(details.tabId, 0, documentId);
      }
      pendingMainFrameNavigations.delete(details.tabId);
      if (touchSession(details.tabId)) {
        scheduleObservationStatePersist(details.tabId);
        return;
      }
    }

    pendingMainFrameNavigations.delete(details.tabId);
    rotateTabObservation(details.tabId, details.url, documentId, {
      documentFingerprint,
      startedAt: Date.now(),
      startedSequence: sequence
    });
  }).catch(() => {});
}

chrome.webNavigation.onCommitted.addListener((details) =>
  handleCommittedNavigation(details, true)
);
chrome.webNavigation.onHistoryStateUpdated.addListener((details) =>
  handleCommittedNavigation(details, false)
);
chrome.webNavigation.onReferenceFragmentUpdated?.addListener((details) =>
  handleCommittedNavigation(details, false)
);
chrome.webNavigation.onBeforeNavigate?.addListener((details) => {
  if (!Number.isInteger(details?.tabId) || !Number.isInteger(details?.frameId) || details.frameId < 0) {
    return;
  }
  markInitializationNavigation(details.tabId, details.frameId);
  const sequence = nextObservationSequence();
  void observationStateReady.then(() => {
    if (observationRuntimeState !== "active") return;
    if (details.frameId === 0) {
      const current = getLiveTabSession(details.tabId);
      if (current && sequence < current.startedSequence) return;
      rememberPendingMainNavigation(details.tabId, details.url, {
        documentId: details.documentId,
        timeStamp: details.timeStamp,
        sequence
      });
      return;
    }
    rememberPendingFrameNavigation(details, sequence);
  }).catch(() => {});
});
chrome.webNavigation.onErrorOccurred?.addListener((details) => {
  if (!Number.isInteger(details?.tabId) || !Number.isInteger(details?.frameId)) return;
  markInitializationNavigation(details.tabId, details.frameId);
  void observationStateReady.then(() => {
    if (details.frameId === 0) {
      const pending = pendingMainFrameNavigations.get(details.tabId);
      if (!pending) {
        void restoreTabObservationAfterNavigationError(details.tabId).catch(() => {});
        return;
      }
      if (!navigationMatchesPending(details, pending)) return;
      pendingMainFrameNavigations.delete(details.tabId);
      if (restoreTabObservationBackup(details.tabId, pending.backup)) return;
      void restoreTabObservationAfterNavigationError(details.tabId).catch(() => {});
      return;
    }
    if (details.frameId < 0) return;
    takeMatchingPendingFrameNavigation(details);
    forgetProvisionalDocumentId(details.tabId, details.frameId, details.documentId || "");
  }).catch(() => {});
});

async function restoreTabObservationAfterNavigationError(tabId) {
  let firstFrame;
  let currentFrame;
  try {
    firstFrame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 });
    currentFrame = await chrome.webNavigation.getFrame({ tabId, frameId: 0 });
  } catch {
    if (pendingMainFrameNavigations.has(tabId)) return;
    dropTabObservation(tabId);
    return;
  }
  if (pendingMainFrameNavigations.has(tabId)) return;
  const documentId =
    typeof currentFrame?.documentId === "string" ? currentFrame.documentId.slice(0, 128) : "";
  const stableFrame =
    documentId &&
    firstFrame?.documentId === documentId &&
    sameDocumentUrl(firstFrame?.url, currentFrame?.url) &&
    (!currentFrame.documentLifecycle || currentFrame.documentLifecycle === "active");
  const allowed = stableFrame && observationMatcher(currentFrame.url || "");
  tabEligibility.set(tabId, Boolean(allowed));
  if (!allowed) {
    dropTabObservation(tabId);
    return;
  }
  const documentFingerprint = documentUrlFingerprint(currentFrame.url);
  const current = getLiveTabSession(tabId);
  if (
    current?.documentId === documentId &&
    current.documentFingerprint === documentFingerprint &&
    current.navigationKey === sanitizeNetworkUrl(currentFrame.url)?.url
  ) {
    rememberDocumentId(tabId, 0, documentId);
    if (touchSession(tabId)) {
      scheduleObservationStatePersist(tabId);
      return;
    }
  }
  rotateTabObservation(tabId, currentFrame.url, documentId, { documentFingerprint });
}

chrome.cookies.onChanged.addListener((changeInfo) => {
  if (observationRuntimeState === "paused") return;
  const observedAt = Date.now();
  const cookie = sanitizeCookieRecord(changeInfo.cookie, {
    cause: changeInfo.cause,
    timingConfidence: "unknown"
  });
  if (!cookie?.domain) return;
  const sanitizedChangeInfo = {
    cookie,
    removed: Boolean(changeInfo.removed),
    cause: typeof changeInfo.cause === "string" ? changeInfo.cause.slice(0, 40) : "",
    observedAt,
    firstEventAt: observedAt,
    lastEventAt: observedAt,
    firstSetObservedAt: changeInfo.removed ? undefined : observedAt,
    lastSetObservedAt: changeInfo.removed ? undefined : observedAt,
    deletedAt: changeInfo.removed ? observedAt : undefined
  };
  enqueueSanitizedCookieChange(sanitizedChangeInfo);
});

function enqueueSanitizedCookieChange(changeInfo) {
  if (pendingCookieChanges.push(changeInfo)) scheduleCookieChangeFlush();
}

function queuedCookieDomain(changeInfo) {
  return String(changeInfo?.cookie?.domain || "").toLowerCase().replace(/^\./, "");
}

function mergeQueuedCookieChanges(previous, incoming) {
  const earliest = (...values) => {
    const candidates = values.filter(Number.isFinite);
    return candidates.length > 0 ? Math.min(...candidates) : undefined;
  };
  const latest = (...values) => {
    const candidates = values.filter(Number.isFinite);
    return candidates.length > 0 ? Math.max(...candidates) : undefined;
  };
  const previousFirstSet = Number.isFinite(previous?.firstSetObservedAt)
    ? previous.firstSetObservedAt
    : !previous?.removed
      ? previous?.firstObservedAt ?? previous?.observedAt
      : undefined;
  const incomingFirstSet = Number.isFinite(incoming?.firstSetObservedAt)
    ? incoming.firstSetObservedAt
    : !incoming?.removed
      ? incoming?.firstObservedAt ?? incoming?.observedAt
      : undefined;
  const previousLastSet = Number.isFinite(previous?.lastSetObservedAt)
    ? previous.lastSetObservedAt
    : !previous?.removed
      ? previous?.lastObservedAt ?? previous?.observedAt
      : undefined;
  const incomingLastSet = Number.isFinite(incoming?.lastSetObservedAt)
    ? incoming.lastSetObservedAt
    : !incoming?.removed
      ? incoming?.lastObservedAt ?? incoming?.observedAt
      : undefined;
  const firstEventAt = earliest(
    previous?.firstEventAt,
    previous?.observedAt,
    incoming?.firstEventAt,
    incoming?.observedAt
  );
  const lastEventAt = latest(
    previous?.lastEventAt,
    previous?.observedAt,
    incoming?.lastEventAt,
    incoming?.observedAt
  );
  return {
    ...incoming,
    observedAt: lastEventAt,
    firstEventAt,
    lastEventAt,
    firstSetObservedAt: earliest(previousFirstSet, incomingFirstSet),
    lastSetObservedAt: latest(previousLastSet, incomingLastSet),
    deletedAt: latest(previous?.deletedAt, incoming?.deletedAt)
  };
}

function scheduleCookieChangeFlush() {
  if (cookieFlushTimer || cookieFlushInFlight || pendingCookieChanges.size === 0) return;
  cookieFlushTimer = setTimeout(() => {
    cookieFlushTimer = null;
    void flushSanitizedCookieChanges();
  }, COOKIE_CHANGE_BATCH_DELAY_MS);
}

async function flushSanitizedCookieChanges() {
  if (cookieFlushInFlight) return cookieFlushInFlight;
  const changes = pendingCookieChanges.drain(MAX_PENDING_COOKIE_CHANGES);
  if (changes.length === 0) return;
  const operation = processSanitizedCookieChanges(changes).finally(() => {
    if (cookieFlushInFlight === operation) cookieFlushInFlight = null;
    scheduleCookieChangeFlush();
  });
  cookieFlushInFlight = operation;
  return operation;
}

async function processSanitizedCookieChanges(changes) {
  await observationStateReady;
  if (observationRuntimeState !== "active" || !observationSettings.enabled) return;
  let tabs;
  try {
    tabs = await chrome.tabs.query({ url: ["http://*/*", "https://*/*"] });
  } catch {
    return;
  }
  if (!Array.isArray(tabs)) return;
  const eligibleTabs = tabs
    .map((tab) => ({ id: tab.id, url: sanitizeNetworkUrl(tab.url) ? tab.url : "" }))
    .filter((tab) => tab.url);
  const eligibleTabsById = new Map(eligibleTabs.map((tab) => [tab.id, tab]));
  const allowedTabIds = new Set(
    eligibleTabs.filter((tab) => observationMatcher(tab.url)).map((tab) => tab.id)
  );
  eligibleTabs.forEach((tab) => tabEligibility.set(tab.id, allowedTabIds.has(tab.id)));
  const contextPromises = new Map();

  for (const changeInfo of changes) {
    // Determine ambiguity against every candidate first. Excluding a tab must not make
    // an otherwise ambiguous domain cookie appear uniquely attributable to another tab.
    const attributedTabIds = getCookieAttributionTabIds(changeInfo, eligibleTabs);
    const safelyPartitionAttributed = Boolean(
      changeInfo.cookie?.partitionKey?.topLevelSite && attributedTabIds.length === 1
    );
    for (const tabId of attributedTabIds) {
      if (!allowedTabIds.has(tabId)) continue;
      const tab = eligibleTabsById.get(tabId);
      if (!tab) continue;
      const session = await ensureCookieObservation(tab, changeInfo, contextPromises);
      if (!session) continue;
      rememberCookieChange(tab.id, changeInfo, {
        observedAt: changeInfo.lastEventAt,
        causalFirstSetObservedAt: safelyPartitionAttributed
          ? changeInfo.firstSetObservedAt
          : undefined,
        causalLastSetObservedAt: safelyPartitionAttributed
          ? changeInfo.lastSetObservedAt
          : undefined,
        causalDeletedAt: safelyPartitionAttributed
          ? changeInfo.deletedAt
          : undefined
      });
    }
  }
}

async function ensureCookieObservation(tab, changeInfo, contextPromises) {
  const expectedUrl = sanitizeNetworkUrl(tab.url);
  const expectedFingerprint = documentUrlFingerprint(tab.url);
  if (!expectedUrl || !expectedFingerprint || !observationMatcher(tab.url)) return null;

  const existing = getLiveTabSession(tab.id);
  if (existing) {
    return existing.navigationKey === expectedUrl.url &&
      existing.documentFingerprint === expectedFingerprint
      ? existing
      : null;
  }

  const expectedGeneration = existing?.generation || tabGenerations.get(tab.id) || 0;
  const contextCacheKey = [
    tab.id,
    expectedGeneration,
    expectedFingerprint,
    expectedUrl.url
  ].join("\u0000");
  if (!contextPromises.has(contextCacheKey)) {
    contextPromises.set(contextCacheKey, getCurrentTabFrameContext(tab.id));
  }
  const context = await contextPromises.get(contextCacheKey);
  const currentUrl = sanitizeNetworkUrl(context?.tab?.url);
  const currentFingerprint = documentUrlFingerprint(context?.tab?.url);
  if (
    !context?.documentId ||
    !currentUrl ||
    currentUrl.url !== expectedUrl.url ||
    currentFingerprint !== expectedFingerprint ||
    !observationMatcher(context.tab.url)
  ) {
    return null;
  }

  const afterLookup = tabSessions.get(tab.id);
  if ((afterLookup?.generation || tabGenerations.get(tab.id) || 0) !== expectedGeneration) {
    return null;
  }
  if (afterLookup && !sessionExpired(afterLookup)) {
    return afterLookup.navigationKey === currentUrl.url &&
      afterLookup.documentFingerprint === currentFingerprint &&
      afterLookup.documentId === context.documentId
      ? afterLookup
      : null;
  }

  return rotateTabObservation(tab.id, context.tab.url, context.documentId, {
    documentFingerprint: currentFingerprint,
    startedAt: Number.isFinite(changeInfo.firstEventAt)
      ? changeInfo.firstEventAt
      : Date.now()
  });
}

function rememberCookieChange(tabId, changeInfo, options = {}) {
  const session = getLiveTabSession(tabId);
  if (!session) return;
  if (
    Number.isFinite(options.observedAt) &&
    Number.isFinite(session.startedAt) &&
    options.observedAt < session.startedAt
  ) {
    return;
  }
  if (!touchSession(tabId)) return;
  const causalFirstSetObservedAt =
    Number.isFinite(options.causalFirstSetObservedAt) &&
    (!Number.isFinite(session.startedAt) || options.causalFirstSetObservedAt >= session.startedAt)
      ? options.causalFirstSetObservedAt
      : Number.isFinite(options.causalLastSetObservedAt) &&
          (!Number.isFinite(session.startedAt) || options.causalLastSetObservedAt >= session.startedAt)
        ? options.causalLastSetObservedAt
        : undefined;
  const causalLastSetObservedAt =
    Number.isFinite(options.causalLastSetObservedAt) &&
    (!Number.isFinite(session.startedAt) || options.causalLastSetObservedAt >= session.startedAt)
      ? options.causalLastSetObservedAt
      : causalFirstSetObservedAt;
  const causalDeletedAt =
    Number.isFinite(options.causalDeletedAt) &&
    (!Number.isFinite(session.startedAt) || options.causalDeletedAt >= session.startedAt)
      ? options.causalDeletedAt
      : undefined;
  tabCookies.set(
    tabId,
    reconcileCookieRecords(tabCookies.get(tabId), changeInfo, {
      maxRecords: MAX_COOKIES_PER_TAB,
      firstSetObservedAt: causalFirstSetObservedAt,
      lastSetObservedAt: causalLastSetObservedAt,
      deletedAt: causalDeletedAt
    })
  );
  scheduleObservationStatePersist(tabId);
}

function requestBelongsToSession(event, session) {
  if (!isRequestEventInSession(event, session)) return false;
  if (event.type === "main_frame" || !event.documentId) return true;
  const documentIds = knownFrameDocumentIds(event.tabId);
  if (documentIds.has(event.documentId)) return true;
  if (event.frameId === 0 && !session.documentId) {
    session.documentId = event.documentId;
    rememberDocumentId(event.tabId, 0, event.documentId);
    return true;
  }
  return false;
}

function createTabSession(tabId, url, documentId, previousGeneration = 0, options = {}) {
  const normalized = sanitizeNetworkUrl(url);
  if (!normalized || !Number.isInteger(tabId) || tabId < 0) return null;
  const now = Date.now();
  const startedAt = Number.isFinite(options.startedAt) ? options.startedAt : now;
  return {
    generation: Math.max(0, Number(previousGeneration) || 0) + 1,
    documentId: typeof documentId === "string" ? documentId.slice(0, 128) : "",
    documentFingerprint:
      typeof options.documentFingerprint === "string" && options.documentFingerprint.length <= 64
        ? options.documentFingerprint
        : documentUrlFingerprint(url),
    origin: normalized.origin,
    navigationKey: normalized.url,
    startedAt,
    startedSequence: Number.isFinite(options.startedSequence)
      ? options.startedSequence
      : nextObservationSequence(),
    lastSeenAt: now
  };
}

function rotateTabObservation(tabId, url, documentId, options = {}) {
  if (!Number.isInteger(tabId) || tabId < 0 || !observationMatcher(url)) {
    dropTabObservation(tabId);
    return null;
  }
  const previousGeneration = Math.max(
    tabSessions.get(tabId)?.generation || 0,
    tabGenerations.get(tabId) || 0
  );
  const session = createTabSession(tabId, url, documentId, previousGeneration, options);
  if (!session) return null;

  tabRequests.set(tabId, []);
  tabCookies.set(tabId, []);
  tabSnapshots.set(tabId, []);
  tabTransientCompanionStates.delete(tabId);
  tabRiskIndicators.delete(tabId);
  clearActionBadge(tabId);
  tabObservationStartedAt.set(tabId, session.startedAt);
  tabSessions.set(tabId, session);
  tabFrameDocuments.set(tabId, new Map(session.documentId ? [[0, session.documentId]] : []));
  tabProvisionalFrameDocuments.delete(tabId);
  pendingMainFrameNavigations.delete(tabId);
  pendingFrameNavigations.delete(tabId);
  tabGenerations.set(tabId, session.generation);
  publishRiskIndicator(tabId, {
    level: "unknown",
    source: "navigation",
    url
  });
  enforceObservedTabLimit();
  scheduleObservationStatePersist(tabId);
  return session;
}

function sessionExpired(session, now = Date.now()) {
  return !Number.isFinite(session?.lastSeenAt) || now - session.lastSeenAt >= OBSERVATION_TTL_MS;
}

function pruneExpiredTabObservationState(tabId, now = Date.now(), markPersistenceChanges = false) {
  let changed = false;
  let pending = pendingMainFrameNavigations.get(tabId);
  if (pending?.backup?.session && sessionExpired(pending.backup.session, now)) {
    pending.backup = null;
    pendingMainFrameNavigations.set(tabId, pending);
    changed = true;
  }

  const session = tabSessions.get(tabId);
  if (session && sessionExpired(session, now)) {
    pending = pendingMainFrameNavigations.get(tabId);
    deleteTabState(tabId);
    if (pending) pendingMainFrameNavigations.set(tabId, pending);
    changed = true;
  }

  if (changed && markPersistenceChanges) markObservationStateChanged(tabId);
  return changed;
}

function discardExpiredTabObservationState(tabId, now = Date.now()) {
  if (!pruneExpiredTabObservationState(tabId, now, true)) return false;
  scheduleObservationStatePersist(tabId, false);
  return true;
}

function getLiveTabSession(tabId, now = Date.now()) {
  discardExpiredTabObservationState(tabId, now);
  return tabSessions.get(tabId) || null;
}

function ensureObservation(tabId, url = "", documentId = "", options = {}) {
  if (!Number.isInteger(tabId) || tabId < 0) return null;
  const current = getLiveTabSession(tabId);
  const normalized = sanitizeNetworkUrl(url);
  const documentFingerprint = options.documentFingerprint || documentUrlFingerprint(url);
  if (!current) {
    return normalized
      ? rotateTabObservation(tabId, url, documentId, { ...options, documentFingerprint })
      : null;
  }
  if (
    normalized &&
    (current.navigationKey !== normalized.url ||
      (documentFingerprint && current.documentFingerprint !== documentFingerprint) ||
      (documentId && current.documentId && current.documentId !== documentId))
  ) {
    return rotateTabObservation(tabId, url, documentId, { ...options, documentFingerprint });
  }
  if (documentId && !current.documentId) {
    current.documentId = documentId.slice(0, 128);
    rememberDocumentId(tabId, 0, current.documentId);
  }
  if (!tabObservationStartedAt.has(tabId)) tabObservationStartedAt.set(tabId, current.startedAt || Date.now());
  return current;
}

function touchSession(tabId) {
  const now = Date.now();
  const session = getLiveTabSession(tabId, now);
  if (!session) return false;
  session.lastSeenAt = now;
  tabSessions.set(tabId, session);
  enforceObservedTabLimit();
  return true;
}

function deleteTabState(tabId) {
  tabRequests.delete(tabId);
  tabCookies.delete(tabId);
  tabObservationStartedAt.delete(tabId);
  tabSnapshots.delete(tabId);
  tabTransientCompanionStates.delete(tabId);
  tabRiskIndicators.delete(tabId);
  tabSessions.delete(tabId);
  tabFrameDocuments.delete(tabId);
  tabProvisionalFrameDocuments.delete(tabId);
  pendingMainFrameNavigations.delete(tabId);
  pendingFrameNavigations.delete(tabId);
  clearActionBadge(tabId);
}

function deleteLiveTabStatePreservingPendingMain(tabId) {
  const pending = pendingMainFrameNavigations.get(tabId);
  if (!pending) {
    dropTabObservation(tabId);
    return;
  }
  deleteTabState(tabId);
  pendingMainFrameNavigations.set(tabId, pending);
  scheduleObservationStatePersist(tabId);
}

function dropTabObservation(tabId) {
  deleteTabState(tabId);
  scheduleObservationStatePersist(tabId);
}

function enforceObservedTabLimit() {
  if (tabSessions.size <= MAX_OBSERVED_TABS) return;
  const oldest = Array.from(tabSessions.entries())
    .sort(([, left], [, right]) => (left.lastSeenAt || 0) - (right.lastSeenAt || 0))
    .slice(0, tabSessions.size - MAX_OBSERVED_TABS);
  oldest.forEach(([tabId]) => {
    deleteTabState(tabId);
    scheduleObservationStatePersist(tabId);
  });
}

function sanitizeStoredRequest(record, tabId) {
  if (!record || typeof record !== "object") return null;
  const sanitized = sanitizeRequestDetails({
    tabId,
    url: record.url,
    method: record.method,
    type: record.type,
    timeStamp: record.timeStamp
  });
  if (!sanitized) return null;
  sanitized.queryKeys = sanitizeFieldKeys(record.queryKeys);
  sanitized.bodyKeys = [];
  return sanitized;
}

function sanitizeStoredSnapshot(snapshot) {
  if (!snapshot || typeof snapshot !== "object") return null;
  const createdAt = Number(snapshot.createdAt);
  if (!Number.isFinite(createdAt)) return null;
  return {
    id: typeof snapshot.id === "string" ? snapshot.id.slice(0, 120) : `${createdAt}`,
    label: typeof snapshot.label === "string" ? snapshot.label.slice(0, 120) : "",
    createdAt,
    requestCount: Math.max(0, Math.min(MAX_REQUESTS_PER_TAB, Number(snapshot.requestCount) || 0)),
    cookieCount: Math.max(0, Math.min(MAX_COOKIES_PER_TAB, Number(snapshot.cookieCount) || 0))
  };
}

function pruneExpiredObservationState(now = Date.now(), markPersistenceChanges = false) {
  const tabIds = new Set([
    ...pendingMainFrameNavigations.keys(),
    ...tabSessions.keys()
  ]);
  for (const tabId of tabIds) {
    pruneExpiredTabObservationState(tabId, now, markPersistenceChanges);
  }
}

function persistedSessionState(session) {
  return {
    generation: Math.max(1, Number(session.generation) || 1),
    documentId: typeof session.documentId === "string" ? session.documentId.slice(0, 128) : "",
    origin: session.origin,
    navigationKey: session.navigationKey,
    startedAt: Number(session.startedAt) || Date.now(),
    lastSeenAt: Number(session.lastSeenAt) || Date.now()
  };
}

function persistedTabState(tabId, session) {
  return {
    session: persistedSessionState(session),
    requests: (tabRequests.get(tabId) || []).slice(-MAX_REQUESTS_PER_TAB),
    cookies: (tabCookies.get(tabId) || []).slice(-MAX_COOKIES_PER_TAB).map((cookie) => {
      const { pathFingerprint: _transientPathFingerprint, ...persistedCookie } = cookie;
      return persistedCookie;
    }),
    snapshots: (tabSnapshots.get(tabId) || []).slice(-MAX_SNAPSHOTS_PER_TAB),
    frameDocuments: Array.from(tabFrameDocuments.get(tabId) || []).slice(
      0,
      MAX_TRACKED_FRAME_DOCUMENTS
    ),
    riskIndicator: tabRiskIndicators.get(tabId) || null
  };
}

function persistedBackupTabState(backup) {
  return {
    session: persistedSessionState(backup.session),
    requests: (Array.isArray(backup.requests) ? backup.requests : []).slice(
      -MAX_REQUESTS_PER_TAB
    ),
    cookies: (Array.isArray(backup.cookies) ? backup.cookies : [])
      .slice(-MAX_COOKIES_PER_TAB)
      .map((cookie) => {
        const { pathFingerprint: _transientPathFingerprint, ...persistedCookie } = cookie;
        return persistedCookie;
      }),
    snapshots: (Array.isArray(backup.snapshots) ? backup.snapshots : []).slice(
      -MAX_SNAPSHOTS_PER_TAB
    ),
    frameDocuments: Array.from(backup.frameDocuments || []).slice(
      0,
      MAX_TRACKED_FRAME_DOCUMENTS
    ),
    riskIndicator: backup.riskIndicator || null
  };
}

function persistedObservationSession(tabId) {
  const pending = pendingMainFrameNavigations.get(tabId);
  if (pending) {
    const backup = pending.backup;
    if (
      !backup?.session ||
      sessionExpired(backup.session) ||
      !observationMatcher(backup.session.origin)
    ) {
      return null;
    }
    return backup.session;
  }
  const session = tabSessions.get(tabId);
  if (!session || !observationMatcher(session.origin)) return null;
  return session;
}

function persistedObservationSource(tabId) {
  const session = persistedObservationSession(tabId);
  if (!session) return null;
  const pending = pendingMainFrameNavigations.get(tabId);
  return {
    session,
    fullState: pending
      ? persistedBackupTabState(pending.backup)
      : persistedTabState(tabId, session)
  };
}

function hasPersistedObservationSource(tabId) {
  return Boolean(persistedObservationSession(tabId));
}

function persistedObservationCandidates() {
  const tabIds = new Set([
    ...tabSessions.keys(),
    ...pendingMainFrameNavigations.keys()
  ]);
  return Array.from(tabIds)
    .map((tabId) => {
      const session = persistedObservationSession(tabId);
      return session ? { tabId, session } : null;
    })
    .filter(Boolean)
    .sort((left, right) =>
      (right.session.lastSeenAt || 0) - (left.session.lastSeenAt || 0)
    )
    .slice(0, MAX_PERSISTED_TABS);
}

function jsonByteLength(value) {
  return new TextEncoder().encode(JSON.stringify(value)).byteLength;
}

function persistedTabEntryByteLength(tabKey, tabState) {
  return jsonByteLength({ [tabKey]: tabState }) - 2;
}

function metadataOnlyPersistedTab(fullState) {
  const topFrame = (Array.isArray(fullState.frameDocuments) ? fullState.frameDocuments : []).find(
    ([frameId]) => frameId === 0
  );
  return {
    session: fullState.session,
    requests: [],
    cookies: [],
    snapshots: [],
    frameDocuments: topFrame ? [topFrame] : [],
    riskIndicator: null
  };
}

export function buildPersistedObservationState() {
  pruneExpiredObservationState();
  const state = {
    version: OBSERVATION_SESSION_VERSION,
    savedAt: Date.now(),
    tabs: {}
  };
  const candidates = Array.from(tabSessions.entries())
    .filter(([, session]) => observationMatcher(session.origin))
    .sort(([, left], [, right]) => (right.lastSeenAt || 0) - (left.lastSeenAt || 0))
    .slice(0, MAX_PERSISTED_TABS)
    .map(([tabId, session]) => {
      const tabKey = String(tabId);
      const fullState = persistedTabState(tabId, session);
      return { tabKey, fullState, metadataState: metadataOnlyPersistedTab(fullState) };
    });

  // Reserve a small document-identity record for every observed tab first.
  for (const { tabKey, metadataState } of candidates) {
    state.tabs[tabKey] = metadataState;
  }
  let stateBytes = jsonByteLength(state);

  // Spend the remaining budget on the most recent tabs without repeatedly serializing the whole state.
  for (const { tabKey, fullState, metadataState } of candidates) {
    const compactState = {
      ...fullState,
      requests: fullState.requests.slice(-50),
      cookies: fullState.cookies.slice(-30)
    };
    const currentEntryBytes = persistedTabEntryByteLength(tabKey, metadataState);
    for (const candidateState of [fullState, compactState]) {
      const candidateEntryBytes = persistedTabEntryByteLength(tabKey, candidateState);
      const candidateTotal = stateBytes - currentEntryBytes + candidateEntryBytes;
      if (candidateTotal <= MAX_PERSISTED_STATE_BYTES) {
        state.tabs[tabKey] = candidateState;
        stateBytes = candidateTotal;
        break;
      }
    }
  }

  return state;
}

function observationSessionShardKey(tabId) {
  return `${OBSERVATION_SESSION_SHARD_PREFIX}${tabId}`;
}

function isOwnedObservationShardKey(key) {
  return /^observationSessionTabV\d+:\d+$/.test(String(key || ""));
}

function boundedPersistedTabState(tabId, fullState) {
  const variants = [
    fullState,
    { ...fullState, requests: fullState.requests.slice(-100), cookies: fullState.cookies.slice(-60) },
    { ...fullState, requests: fullState.requests.slice(-50), cookies: fullState.cookies.slice(-30) },
    { ...fullState, requests: fullState.requests.slice(-20), cookies: fullState.cookies.slice(-15) },
    { ...fullState, requests: fullState.requests.slice(-5), cookies: fullState.cookies.slice(-5) },
    metadataOnlyPersistedTab(fullState)
  ];
  const key = observationSessionShardKey(tabId);
  return (
    variants.find((candidate) => jsonByteLength({ [key]: candidate }) <= MAX_PERSISTED_TAB_SHARD_BYTES) ||
    metadataOnlyPersistedTab(fullState)
  );
}

function buildObservationSessionIndex() {
  const tabs = {};
  for (const { tabId, session } of persistedObservationCandidates()) {
    tabs[String(tabId)] = {
      key: observationSessionShardKey(tabId),
      session: persistedSessionState(session)
    };
  }
  return {
    version: OBSERVATION_SESSION_VERSION,
    layout: OBSERVATION_SESSION_LAYOUT,
    savedAt: Date.now(),
    tabs
  };
}

function markObservationStateChanged(tabId) {
  stateRevision += 1;
  if (Number.isInteger(tabId) && tabId >= 0) {
    if (hasPersistedObservationSource(tabId)) {
      dirtyPersistedTabRevisions.set(tabId, stateRevision);
      deletedPersistedTabRevisions.delete(tabId);
    } else {
      deletedPersistedTabRevisions.set(tabId, stateRevision);
      dirtyPersistedTabRevisions.delete(tabId);
    }
  } else {
    persistenceLayoutDirtyRevision = stateRevision;
  }
}

function hasPendingObservationPersistence() {
  return (
    dirtyPersistedTabRevisions.size > 0 ||
    deletedPersistedTabRevisions.size > 0 ||
    persistenceLayoutDirtyRevision > persistedRevision
  );
}

function scheduleObservationStatePersist(tabId, markChanged = true) {
  if (markChanged) markObservationStateChanged(tabId);
  scheduleObservationTtlAlarm();
  if (persistTimer || !chrome.storage?.session) return;
  persistTimer = setTimeout(() => {
    persistTimer = null;
    void persistObservationState();
  }, SESSION_PERSIST_DELAY_MS);
}

function persistObservationState() {
  if (persistInFlight) return persistInFlight;
  const operation = persistObservationStateOnce().finally(() => {
    if (persistInFlight === operation) persistInFlight = null;
    scheduleObservationTtlAlarm();
  });
  persistInFlight = operation;
  return operation;
}

async function persistObservationStateOnce() {
  if (!chrome.storage?.session || !hasPendingObservationPersistence()) return;
  pruneExpiredObservationState(Date.now(), true);
  const revision = stateRevision;
  const dirtyEntries = Array.from(dirtyPersistedTabRevisions.entries()).filter(
    ([, changedAt]) => changedAt <= revision
  );
  const deletedEntries = Array.from(deletedPersistedTabRevisions.entries()).filter(
    ([, changedAt]) => changedAt <= revision
  );
  const index = buildObservationSessionIndex();
  const values = {};
  for (const [tabId] of dirtyEntries) {
    const source = persistedObservationSource(tabId);
    if (!source) continue;
    values[observationSessionShardKey(tabId)] = boundedPersistedTabState(
      tabId,
      source.fullState
    );
  }
  if (Object.keys(index.tabs).length > 0) values[OBSERVATION_SESSION_KEY] = index;
  const activeTabIds = new Set(Object.keys(index.tabs).map(Number));
  const keysToRemove = new Set();
  for (const [tabId] of deletedEntries) {
    keysToRemove.add(knownPersistedTabKeys.get(tabId) || observationSessionShardKey(tabId));
  }
  for (const [tabId, key] of knownPersistedTabKeys) {
    if (!activeTabIds.has(tabId)) keysToRemove.add(key);
  }
  if (Object.keys(index.tabs).length === 0) keysToRemove.add(OBSERVATION_SESSION_KEY);

  try {
    if (Object.keys(values).length > 0) await chrome.storage.session.set(values);
    if (keysToRemove.size > 0) await chrome.storage.session.remove(Array.from(keysToRemove));
    for (const [tabId] of dirtyEntries) {
      if (persistedObservationSource(tabId)) {
        knownPersistedTabKeys.set(tabId, observationSessionShardKey(tabId));
      }
    }
    for (const [tabId] of deletedEntries) knownPersistedTabKeys.delete(tabId);
    for (const [tabId, changedAt] of dirtyEntries) {
      if (dirtyPersistedTabRevisions.get(tabId) === changedAt) dirtyPersistedTabRevisions.delete(tabId);
    }
    for (const [tabId, changedAt] of deletedEntries) {
      if (deletedPersistedTabRevisions.get(tabId) === changedAt) deletedPersistedTabRevisions.delete(tabId);
    }
    if (persistenceLayoutDirtyRevision <= revision) persistenceLayoutDirtyRevision = 0;
    persistedRevision = revision;
    persistFailureCount = 0;
  } catch {
    // Keep the in-memory revision dirty and retry a few times without a tight failure loop.
    persistFailureCount += 1;
    if (persistFailureCount <= SESSION_PERSIST_MAX_RETRIES && !persistTimer) {
      persistTimer = setTimeout(() => {
        persistTimer = null;
        void persistObservationState();
      }, SESSION_PERSIST_DELAY_MS * persistFailureCount);
    }
    return;
  }
  if (hasPendingObservationPersistence()) scheduleObservationStatePersist(undefined, false);
}

function observationStorageKeys(stored) {
  return Object.keys(stored || {}).filter(
    (key) => key === OBSERVATION_SESSION_KEY || isOwnedObservationShardKey(key)
  );
}

async function removeObservationStorageKeys(keys) {
  if (keys.length === 0) return;
  try {
    await chrome.storage.session.remove(keys);
  } catch {
    // Stale recovery data is ignored in memory when best-effort cleanup fails.
  }
}

function metadataStateFromIndex(indexEntry) {
  return {
    session: indexEntry?.session,
    requests: [],
    cookies: [],
    snapshots: [],
    frameDocuments: [],
    riskIndicator: null
  };
}

async function hydrateObservationState() {
  if (!chrome.storage?.session) return;
  if (!observationSettings.enabled) {
    try {
      const stored = await chrome.storage.session.get(null);
      await chrome.storage.session.remove(observationStorageKeys(stored));
    } catch {
      // Fail closed in memory even when stale session cleanup is unavailable.
    }
    return;
  }
  let stored;
  let openTabs;
  try {
    [stored, openTabs] = await Promise.all([
      chrome.storage.session.get(null),
      chrome.tabs.query({ url: ["http://*/*", "https://*/*"] })
    ]);
  } catch {
    return;
  }
  openTabs.forEach((tab) =>
    tabEligibility.set(tab.id, observationMatcher(tab?.url || ""))
  );

  const state = stored?.[OBSERVATION_SESSION_KEY];
  const now = Date.now();
  if (
    !state ||
    state.version !== OBSERVATION_SESSION_VERSION ||
    !state.tabs ||
    typeof state.tabs !== "object" ||
    !Number.isFinite(state.savedAt) ||
    now - state.savedAt >= OBSERVATION_TTL_MS ||
    state.savedAt > now + 60_000
  ) {
    await removeObservationStorageKeys(observationStorageKeys(stored));
    return;
  }

  const shardedLayout = state.layout === OBSERVATION_SESSION_LAYOUT;
  const inlineLayout = !state.layout;
  if (!shardedLayout && !inlineLayout) {
    await removeObservationStorageKeys(observationStorageKeys(stored));
    return;
  }

  const rawEntries = Object.entries(state.tabs).slice(0, MAX_PERSISTED_TABS);
  let indexNeedsRewrite = Object.keys(state.tabs).length > MAX_PERSISTED_TABS;
  const referencedShardKeys = new Set();
  if (shardedLayout) {
    for (const [rawTabId, indexEntry] of rawEntries) {
      const tabId = Number(rawTabId);
      if (!Number.isInteger(tabId) || tabId < 0) {
        indexNeedsRewrite = true;
        continue;
      }
      const key = observationSessionShardKey(tabId);
      if (
        indexEntry?.key !== key ||
        !indexEntry.session ||
        typeof indexEntry.session !== "object" ||
        Boolean(indexEntry.session.documentFingerprint)
      ) {
        indexNeedsRewrite = true;
      }
      referencedShardKeys.add(key);
      knownPersistedTabKeys.set(tabId, key);
    }
  }
  const obsoleteShardKeys = Object.keys(stored).filter(
    (key) => isOwnedObservationShardKey(key) && !referencedShardKeys.has(key)
  );
  await removeObservationStorageKeys(obsoleteShardKeys);

  const openTabIds = new Set(openTabs.map((tab) => tab.id));
  const entries = rawEntries.map(([rawTabId, indexEntry]) => {
    const tabId = Number(rawTabId);
    if (!shardedLayout || !Number.isInteger(tabId) || tabId < 0) {
      return [rawTabId, indexEntry, { missingShard: false, needsRewrite: inlineLayout }];
    }
    const key = observationSessionShardKey(tabId);
    const shard = stored[key];
    const missingShard = !shard || typeof shard !== "object";
    const storedTab = missingShard ? metadataStateFromIndex(indexEntry) : shard;
    const needsRewrite =
      missingShard ||
      jsonByteLength({ [key]: storedTab }) > MAX_PERSISTED_TAB_SHARD_BYTES ||
      Boolean(storedTab?.session?.documentFingerprint) ||
      (Array.isArray(storedTab?.cookies) &&
        storedTab.cookies.some(
          (cookie) =>
            cookie &&
            ("pathFingerprint" in cookie ||
              cookie.identityStable !== true ||
              (cookie.timingConfidence === "observed" &&
                !Number.isFinite(cookie.firstSetObservedAt)))
        ));
    return [rawTabId, storedTab, { missingShard, needsRewrite }];
  });
  const liveEntries = await mapPolicyChecksWithConcurrency(
    entries,
    async ([rawTabId, storedTab, persistence]) => {
      const tabId = Number(rawTabId);
      if (!Number.isInteger(tabId) || !openTabIds.has(tabId)) {
        return { tabId, storedTab, persistence, context: null };
      }
      return { tabId, storedTab, persistence, context: await getCurrentTabFrameContext(tabId) };
    },
    4
  );
  for (const { tabId, storedTab, persistence, context } of liveEntries) {
    const tab = context?.tab;
    const currentUrl = sanitizeNetworkUrl(tab?.url);
    const currentDocumentFingerprint = documentUrlFingerprint(tab?.url);
    const storedNavigation = sanitizeNetworkUrl(storedTab?.session?.navigationKey);
    const storedDocumentId =
      typeof storedTab?.session?.documentId === "string"
        ? storedTab.session.documentId.slice(0, 128)
        : "";
    const lastSeenAt = Number(storedTab?.session?.lastSeenAt);
    if (
      !Number.isInteger(tabId) ||
      initializationNavigationTabs.has(tabId) ||
      !context ||
      !currentUrl ||
      !storedNavigation ||
      currentUrl.url !== storedNavigation.url ||
      !currentDocumentFingerprint ||
      !storedDocumentId ||
      storedDocumentId !== context.documentId ||
      !observationMatcher(tab.url) ||
      !Number.isFinite(lastSeenAt) ||
      now - lastSeenAt >= OBSERVATION_TTL_MS ||
      lastSeenAt > now + 60_000
    ) {
      if (Number.isInteger(tabId) && tabId >= 0) scheduleObservationStatePersist(tabId);
      continue;
    }

    const startedAt = Number(storedTab?.session?.startedAt);
    const session = {
      generation: Math.max(1, Number(storedTab?.session?.generation) || 1),
      documentId: context.documentId,
      documentFingerprint: currentDocumentFingerprint,
      origin: currentUrl.origin,
      navigationKey: currentUrl.url,
      startedAt: Number.isFinite(startedAt) && startedAt <= now + 60_000 ? startedAt : now,
      startedSequence: recoveredSessionStartedSequence(tabId),
      lastSeenAt
    };
    const requests = (Array.isArray(storedTab.requests) ? storedTab.requests : [])
      .slice(-MAX_REQUESTS_PER_TAB)
      .map((request) => sanitizeStoredRequest(request, tabId))
      .filter(Boolean);
    const cookies = (Array.isArray(storedTab.cookies) ? storedTab.cookies : [])
      .slice(-MAX_COOKIES_PER_TAB)
      // Raw name/path fingerprints are deliberately not persisted. Only
      // records whose minimized display identity was unchanged can therefore
      // be recovered without risking a stale duplicate or failed deletion.
      .filter((cookie) => cookie?.identityStable === true)
      .map((cookie) => sanitizeCookieRecord(cookie, cookie))
      .filter(
        (cookie) =>
          cookie.domain &&
          (!cookie.removed ||
            (cookie.timingConfidence === "observed" &&
              Number.isFinite(cookie.firstSetObservedAt))) &&
          getCookieAttributionTabIds(
            { cookie, removed: Boolean(cookie.removed) },
            [tab]
          ).includes(tabId)
      );
    const snapshots = (Array.isArray(storedTab.snapshots) ? storedTab.snapshots : [])
      .slice(-MAX_SNAPSHOTS_PER_TAB)
      .map(sanitizeStoredSnapshot)
      .filter(Boolean);

    tabSessions.set(tabId, session);
    tabGenerations.set(tabId, session.generation);
    tabObservationStartedAt.set(tabId, session.startedAt);
    tabRequests.set(tabId, requests);
    tabCookies.set(tabId, cookies);
    tabSnapshots.set(tabId, snapshots);
    tabFrameDocuments.set(tabId, context.frameDocuments);
    if (storedTab.riskIndicator) {
      const indicator = createRiskIndicator(storedTab.riskIndicator);
      if (indicator.url === session.navigationKey) {
        tabRiskIndicators.set(tabId, indicator);
        updateActionBadge(tabId, indicator);
      }
    }
    if (persistence?.needsRewrite) scheduleObservationStatePersist(tabId);
  }
  enforceObservedTabLimit();
  if (inlineLayout) {
    scheduleObservationStatePersist(undefined);
    for (const tabId of tabSessions.keys()) scheduleObservationStatePersist(tabId);
  } else if (indexNeedsRewrite) {
    scheduleObservationStatePersist(undefined);
  }
  if (!hasPendingObservationPersistence()) persistedRevision = stateRevision;
}

async function loadObservationSettingsCache() {
  try {
    const stored = await chrome.storage.local.get(OBSERVATION_SETTINGS_KEY);
    applyObservationSettings(stored?.[OBSERVATION_SETTINGS_KEY]);
  } catch {
    applyObservationSettings({ enabled: false });
  }
}

function sessionMatchesObservationBackup(session, backup) {
  const backupSession = backup?.session;
  return Boolean(
    session &&
      backupSession &&
      session.generation === backupSession.generation &&
      session.documentId === backupSession.documentId &&
      session.navigationKey === backupSession.navigationKey &&
      session.documentFingerprint === backupSession.documentFingerprint
  );
}

function observationSessionAllowed(session) {
  return Boolean(session && observationMatcher(session.navigationKey || session.origin || ""));
}

function reconcileTabObservationWithSettings(tabId, fallbackUrl = "") {
  const pending = pendingMainFrameNavigations.get(tabId);
  const current = getLiveTabSession(tabId);
  const hasState = Boolean(
    pending ||
      current ||
      knownPersistedTabKeys.has(tabId) ||
      dirtyPersistedTabRevisions.has(tabId)
  );
  if (!observationSettings.enabled) {
    tabEligibility.set(tabId, false);
    if (hasState) {
      deleteTabState(tabId);
      scheduleObservationStatePersist(tabId);
    }
    subresourceRequestLimiter.delete(tabId);
    tabRateLimitMainRequestIds.delete(tabId);
    return false;
  }

  if (pending) {
    const targetAllowed = observationMatcher(pending.navigationKey || "");
    const backupAllowed = observationSessionAllowed(pending.backup?.session);
    let changed = false;

    if (pending.backup && !backupAllowed) {
      pending.backup = null;
      pendingMainFrameNavigations.set(tabId, pending);
      changed = true;
    }

    if (!targetAllowed && !backupAllowed) {
      tabEligibility.set(tabId, false);
      deleteTabState(tabId);
      scheduleObservationStatePersist(tabId);
      subresourceRequestLimiter.delete(tabId);
      tabRateLimitMainRequestIds.delete(tabId);
      return false;
    }

    if (!targetAllowed) {
      if (current && !sessionMatchesObservationBackup(current, pending.backup)) {
        deleteLiveTabStatePreservingPendingMain(tabId);
        changed = false;
      }
      subresourceRequestLimiter.delete(tabId);
      tabRateLimitMainRequestIds.delete(tabId);
    } else if (!backupAllowed && current && !observationSessionAllowed(current)) {
      deleteLiveTabStatePreservingPendingMain(tabId);
      changed = false;
    }

    tabEligibility.set(tabId, targetAllowed || backupAllowed);
    if (changed) scheduleObservationStatePersist(tabId);
    return targetAllowed || backupAllowed;
  }

  const allowed = current
    ? observationSessionAllowed(current)
    : observationMatcher(fallbackUrl || "");
  tabEligibility.set(tabId, allowed);
  if (!allowed && (current || knownPersistedTabKeys.has(tabId))) {
    deleteTabState(tabId);
    scheduleObservationStatePersist(tabId);
  }
  if (!allowed) {
    subresourceRequestLimiter.delete(tabId);
    tabRateLimitMainRequestIds.delete(tabId);
  }
  return allowed;
}

function purgeDisallowedObservationState() {
  const tabIds = new Set([
    ...tabSessions.keys(),
    ...pendingMainFrameNavigations.keys(),
    ...knownPersistedTabKeys.keys()
  ]);
  for (const tabId of tabIds) reconcileTabObservationWithSettings(tabId);
}

function contentObservationSettingsForUrl(url) {
  const enabled = observationSettings.enabled === true;
  return {
    enabled,
    allowed: enabled && observationMatcher(url || "")
  };
}

async function broadcastObservationSettings() {
  let tabs = [];
  try {
    tabs = await chrome.tabs.query({ url: ["http://*/*", "https://*/*"] });
  } catch {
    return;
  }
  tabs.forEach((tab) => {
    if (!Number.isInteger(tab.id)) return;
    reconcileTabObservationWithSettings(tab.id, tab.url || "");
    chrome.tabs.sendMessage(
      tab.id,
      {
        type: "OBSERVATION_SETTINGS_UPDATE",
        settings: contentObservationSettingsForUrl(tab.url)
      },
      () => void chrome.runtime.lastError
    );
    void companionOverlayRuntime.refresh(tab.id);
  });
}

async function initializeObservationRuntime() {
  localStorageTrustedContextsOnly = await ensureTrustedLocalStorage();
  if (!localStorageTrustedContextsOnly) {
    // Do not load persisted settings or observation state when local storage
    // cannot be hidden from content scripts. Explicit page analysis remains available.
    applyObservationSettings({ enabled: false });
    companionOverlayEnabled = false;
    analysisModePreference = DEFAULT_ANALYSIS_MODE;
    observationRuntimeState = "paused";
    pendingInitializationRequests.length = 0;
    initializationNavigationTabs.clear();
    pendingCookieChanges.clear();
    subresourceRequestLimiter.clear();
    tabRateLimitMainRequestIds.clear();
    if (cookieFlushTimer) clearTimeout(cookieFlushTimer);
    cookieFlushTimer = null;
    try {
      const storedSession = await chrome.storage.session.get(null);
      await removeObservationStorageKeys(observationStorageKeys(storedSession));
    } catch {
      // In-memory state remains paused even if best-effort session cleanup fails.
    }
    return;
  }
  try {
    await Promise.all([
      loadObservationSettingsCache(),
      loadCompanionOverlayEnabled(chrome.storage.local).then((enabled) => {
        companionOverlayEnabled = enabled;
      }),
      loadAnalysisModePreference()
        .then((mode) => {
          analysisModePreference = normalizeAnalysisModePreference(mode);
        })
        .catch(() => {
          analysisModePreference = DEFAULT_ANALYSIS_MODE;
        }),
      getLocalePreference()
    ]);
    await hydrateObservationState();
    observationRuntimeState = observationSettings.enabled ? "flushing" : "paused";
  } catch {
    applyObservationSettings({ enabled: false });
    observationRuntimeState = "paused";
  }
}

async function flushInitializationRequests() {
  if (observationRuntimeState !== "flushing" || !observationSettings.enabled) {
    pendingInitializationRequests.length = 0;
    initializationNavigationTabs.clear();
    observationRuntimeState = "paused";
    return;
  }
  while (pendingInitializationRequests.length > 0) {
    const events = pendingInitializationRequests.splice(0, MAX_PENDING_INITIAL_REQUESTS);
    for (const event of events) {
      if (!observationSettings.enabled || observationRuntimeState === "paused") {
        pendingInitializationRequests.length = 0;
        initializationNavigationTabs.clear();
        observationRuntimeState = "paused";
        return;
      }
      try {
        await processCapturedRequestAfterInitialization(event);
      } catch {
        // A closed or replaced tab should not stop later startup events from being checked.
      }
    }
  }
  initializationNavigationTabs.clear();
  observationRuntimeState = observationSettings.enabled ? "active" : "paused";
}

const observationStateReady = initializeObservationRuntime().then(flushInitializationRequests);
const companionOverlayRuntime = createCompanionOverlayRuntime({
  chrome,
  getState: getCompanionState,
  createUnknownState: () => createCompanionState({}, "unknown"),
  isEnabled: () => companionOverlayEnabled,
  generationReady: companionOverlayGenerationReady
});

void observationStateReady.then(() => companionOverlayRuntime.broadcast()).catch(() => {});

void observationStateReady.then(scheduleObservationTtlAlarm).catch(() => {
  scheduleObservationTtlAlarm();
});

void observationStateReady.catch(() => {
  pendingInitializationRequests.length = 0;
  initializationNavigationTabs.clear();
  observationRuntimeState = "paused";
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== "local" || !localStorageTrustedContextsOnly) return;
  if (changes[OBSERVATION_SETTINGS_KEY]) {
    applyObservationSettings(
      localStorageTrustedContextsOnly
        ? changes[OBSERVATION_SETTINGS_KEY].newValue
        : { enabled: false }
    );
    if (!observationSettings.enabled) observationRuntimeState = "paused";
    else if (!observationRuntimeIsStarting()) observationRuntimeState = "active";
    if (!observationSettings.enabled) {
      pendingInitializationRequests.length = 0;
      pendingCookieChanges.clear();
      subresourceRequestLimiter.clear();
      tabRateLimitMainRequestIds.clear();
      if (cookieFlushTimer) clearTimeout(cookieFlushTimer);
      cookieFlushTimer = null;
    }
    void observationStateReady.then(() => {
      purgeDisallowedObservationState();
      void broadcastObservationSettings();
    }).catch(() => {});
  }
  if (changes[COMPANION_OVERLAY_ENABLED_KEY]) {
    const nextEnabled = normalizeCompanionOverlayEnabled(
      changes[COMPANION_OVERLAY_ENABLED_KEY].newValue
    );
    if (nextEnabled !== companionOverlayEnabled) {
      companionOverlayEnabled = nextEnabled;
      void companionOverlayRuntime.broadcast();
    }
  }
  if (changes[ANALYSIS_MODE_PREFERENCE_KEY]) {
    analysisModePreference = normalizeAnalysisModePreference(
      changes[ANALYSIS_MODE_PREFERENCE_KEY].newValue
    );
  }
  if (changes.uiLocaleOverride) {
    void setLocalePreference(changes.uiLocaleOverride.newValue);
  }
});

function createSnapshot(tabId, label = t("snapshotBaseline")) {
  if (!ensureObservation(tabId)) return null;
  if (!touchSession(tabId)) return null;
  const requests = tabRequests.get(tabId) || [];
  const cookies = tabCookies.get(tabId) || [];
  const snapshot = {
    id: `${Date.now()}-${Math.random().toString(36).slice(2)}`,
    label,
    createdAt: Date.now(),
    requestCount: requests.length,
    cookieCount: cookies.filter((cookie) => !cookie.removed).length
  };
  const snapshots = tabSnapshots.get(tabId) || [];
  snapshots.push(snapshot);

  if (snapshots.length > MAX_SNAPSHOTS_PER_TAB) {
    snapshots.splice(0, snapshots.length - MAX_SNAPSHOTS_PER_TAB);
  }

  tabSnapshots.set(tabId, snapshots);
  scheduleObservationStatePersist(tabId);
  return snapshot;
}

function normalizeRiskLevel(level) {
  return RISK_LEVELS.has(level) ? level : "unknown";
}

function createRiskIndicator(indicator = {}) {
  const normalizedUrl = sanitizeNetworkUrl(indicator.url);
  const now = Date.now();
  const suppliedUpdatedAt = Number(indicator.updatedAt);
  return {
    level: normalizeRiskLevel(indicator.level),
    score: Number.isFinite(indicator.score) ? Math.max(0, Math.min(100, Math.round(indicator.score))) : null,
    label: typeof indicator.label === "string" ? indicator.label.slice(0, 240) : "",
    source: typeof indicator.source === "string" ? indicator.source.slice(0, 40) : "unknown",
    title: "",
    url: normalizedUrl?.url || "",
    updatedAt:
      Number.isFinite(suppliedUpdatedAt) && suppliedUpdatedAt >= 0 && suppliedUpdatedAt <= now + 60_000
        ? suppliedUpdatedAt
        : now
  };
}

async function getCompanionState(tabId) {
  let tab;
  try {
    tab = await chrome.tabs.get(tabId);
  } catch {
    return createCompanionState({}, "unsupported");
  }
  const normalized = sanitizeNetworkUrl(tab?.url);
  if (!normalized) return createCompanionState({}, "unsupported");

  const fingerprint = documentUrlFingerprint(tab.url);
  const transient = tabTransientCompanionStates.get(tabId);
  if (transient?.documentFingerprint === fingerprint) return transient.state;
  if (transient) tabTransientCompanionStates.delete(tabId);

  if (!localStorageTrustedContextsOnly || !observationSettings.enabled) {
    return createCompanionState({}, "paused");
  }
  if (!observationMatcher(tab.url)) return createCompanionState({}, "excluded");

  const indicator = tabRiskIndicators.get(tabId);
  if (indicator?.url === normalized.url) return createCompanionState(indicator);
  return createCompanionState({}, "unknown");
}

function createRiskIndicatorFromPolicy(policyAnalysis, metadata = {}) {
  if (!policyAnalysis?.ok) {
    return createRiskIndicator({
      ...metadata,
      level: "unknown",
      score: null,
      label: policyAnalysis?.message || ""
    });
  }

  return createRiskIndicator({
    ...metadata,
    level: policyAnalysis.level,
    score: policyAnalysis.score,
    label: policyAnalysis.levelLabel || policyAnalysis.level
  });
}

function rememberRiskIndicator(tabId, indicator) {
  if (!Number.isInteger(tabId) || tabId < 0) return null;
  const normalized = createRiskIndicator(indicator);
  tabTransientCompanionStates.delete(tabId);
  tabRiskIndicators.set(tabId, normalized);
  scheduleObservationStatePersist(tabId);
  return normalized;
}

function badgePresentation(indicator = {}) {
  const level = normalizeRiskLevel(indicator.level);
  const scoreColor = riskColorForScore(indicator.score);
  if (level === "analyzing") return { text: "…", color: "#667085" };
  if (level === "low") return { text: "L", color: scoreColor || "#039855" };
  if (level === "medium") return { text: "!", color: scoreColor || "#dc6803" };
  if (level === "high") return { text: "H", color: scoreColor || "#d92d20" };
  return { text: "", color: "#667085" };
}

function updateActionBadge(tabId, indicator) {
  if (!Number.isInteger(tabId) || tabId < 0 || !chrome.action) return;
  const badge = badgePresentation(indicator);
  try {
    const textUpdate = chrome.action.setBadgeText({ tabId, text: badge.text });
    textUpdate?.catch?.(() => {});
    if (badge.text) {
      const colorUpdate = chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
      colorUpdate?.catch?.(() => {});
    }
  } catch {
    // The tab may have closed between analysis and badge publication.
  }
}

function clearActionBadge(tabId) {
  if (!Number.isInteger(tabId) || tabId < 0 || !chrome.action) return;
  try {
    const update = chrome.action.setBadgeText({ tabId, text: "" });
    update?.catch?.(() => {});
  } catch {
    // Badges disappear automatically when their tab closes.
  }
  void companionOverlayRuntime.refresh(tabId);
}

function publishRiskIndicator(tabId, indicator) {
  const normalized = rememberRiskIndicator(tabId, indicator);
  if (!normalized) return null;

  updateActionBadge(tabId, normalized);
  void companionOverlayRuntime.refresh(tabId);

  if (normalized.source === "navigation") {
    chrome.tabs.sendMessage(tabId, { type: "PAGE_CONTEXT_CHANGED" }, () => {
      // The content script may not be available on restricted or not-yet-ready pages.
      void chrome.runtime.lastError;
    });
  }
  return normalized;
}

function publishTransientRiskIndicator(tabId, indicator) {
  if (!Number.isInteger(tabId) || tabId < 0) return null;
  const normalized = createRiskIndicator(indicator);
  const documentFingerprint = documentUrlFingerprint(normalized.url);
  if (documentFingerprint) {
    tabTransientCompanionStates.set(tabId, {
      documentFingerprint,
      state: createCompanionState(normalized)
    });
  }
  updateActionBadge(tabId, normalized);
  void companionOverlayRuntime.refresh(tabId);
  return normalized;
}

async function getCurrentTabDocument(tabId) {
  return companionOverlayRuntime.currentTopDocument(tabId);
}

function extractFetchedPolicyText(document) {
  const mimeType = String(document.contentType || "").split(";", 1)[0].trim().toLowerCase();
  return mimeType === "text/plain"
    ? normalizePolicyText(document.text)
    : extractPolicyTextFromHtml(document.text);
}

function boundedFetchedPolicyAnalysisText(text) {
  return String(text || "").slice(0, MAX_POLICY_ANALYSIS_CHARS);
}

async function getMatchingPolicySaveContext(tabId, documentId, policyUrl) {
  const context = await getCurrentTabDocument(tabId);
  if (!context || context.documentId !== documentId) return null;
  const currentPolicyUrl = normalizePolicyUrl(context.tab?.url);
  if (!currentPolicyUrl || currentPolicyUrl !== policyUrl) return null;
  return context;
}

function observationActionContextMatches(context, documentId, documentFingerprint) {
  return Boolean(
    context &&
      context.documentId === documentId &&
      documentUrlFingerprint(context.tab?.url) === documentFingerprint
  );
}

function syncTabObservationFromContext(tabId, context) {
  if (!context) return null;
  const { tab, documentId, frameDocuments } = context;
  if (!observationMatcher(tab?.url || "")) {
    dropTabObservation(tabId);
    return null;
  }

  const normalized = sanitizeNetworkUrl(tab.url);
  if (!normalized) return null;
  const documentFingerprint = documentUrlFingerprint(tab.url);
  const current = getLiveTabSession(tabId);
  if (
    !current ||
    current.navigationKey !== normalized.url ||
    current.documentFingerprint !== documentFingerprint ||
    (current.documentId && current.documentId !== documentId)
  ) {
    rotateTabObservation(tabId, tab.url, documentId, { documentFingerprint });
  } else {
    current.documentId = documentId;
    tabFrameDocuments.set(tabId, frameDocuments);
    if (touchSession(tabId)) {
      scheduleObservationStatePersist(tabId);
    } else {
      rotateTabObservation(tabId, tab.url, documentId, { documentFingerprint });
    }
  }
  return { ...tab, documentId };
}

async function syncTabObservation(tabId) {
  const context = await getCurrentTabFrameContext(tabId);
  return syncTabObservationFromContext(tabId, context);
}

async function refreshCurrentCookies(tabId, tab) {
  const expectedSession = getLiveTabSession(tabId);
  if (!expectedSession) return;
  const expectedGeneration = {
    generation: expectedSession.generation,
    navigationKey: expectedSession.navigationKey,
    origin: expectedSession.origin,
    documentFingerprint: expectedSession.documentFingerprint
  };
  let currentCookies;
  try {
    const topLevelSite = new URL(tab.url).origin;
    const [unpartitioned, partitioned] = await Promise.all([
      chrome.cookies.getAll({ url: tab.url }),
      chrome.cookies.getAll({ partitionKey: { topLevelSite } })
    ]);
    currentCookies = [...unpartitioned, ...partitioned];
  } catch {
    return;
  }

  const afterFetchSession = getLiveTabSession(tabId);
  if (!isObservationSessionCurrent(expectedGeneration, afterFetchSession)) return;

  const inventory = [];
  for (const cookie of currentCookies) {
    const inventoryCookie = sanitizeCookieRecord(cookie, {
      cause: "inventory",
      timingConfidence: "unknown"
    });
    if (!getCookieAttributionTabIds({ cookie: inventoryCookie, removed: false }, [tab]).includes(tabId)) {
      continue;
    }
    inventory.push(inventoryCookie);
  }
  const inventoryIds = new Set(inventory.map(cookieIdentity));
  let reconciled = (tabCookies.get(tabId) || []).filter(
    (cookie) =>
      (cookie.removed &&
        cookie.timingConfidence === "observed" &&
        Number.isFinite(cookie.firstSetObservedAt)) ||
      inventoryIds.has(cookieIdentity(cookie))
  );
  for (const cookie of inventory) {
    reconciled = reconcileCookieRecords(
      reconciled,
      { cookie, removed: false, cause: "inventory" },
      { maxRecords: MAX_COOKIES_PER_TAB }
    );
  }
  const beforeMutationSession = getLiveTabSession(tabId);
  if (!isObservationSessionCurrent(expectedGeneration, beforeMutationSession)) return;
  if (!touchSession(tabId)) return;
  tabCookies.set(tabId, reconciled);
  scheduleObservationStatePersist(tabId);
}

function ensureContentSenderSession(sender) {
  const tabId = sender.tab?.id;
  const senderUrl = sender.url || sender.tab?.url || "";
  const normalizedSenderUrl = sanitizeNetworkUrl(senderUrl);
  const normalizedTabUrl = sanitizeNetworkUrl(sender.tab?.url || senderUrl);
  const documentFingerprint = documentUrlFingerprint(senderUrl);
  const senderDocumentId =
    typeof sender.documentId === "string" ? sender.documentId.slice(0, 128) : "";
  if (
    (sender.documentLifecycle && sender.documentLifecycle !== "active") ||
    !senderDocumentId ||
    !normalizedSenderUrl ||
    !normalizedTabUrl ||
    !documentFingerprint ||
    normalizedSenderUrl.url !== normalizedTabUrl.url ||
    !sameDocumentUrl(senderUrl, sender.tab?.url || senderUrl) ||
    !observationMatcher(senderUrl)
  ) {
    return null;
  }

  const current = getLiveTabSession(tabId);
  if (!current) {
    return rotateTabObservation(tabId, senderUrl, senderDocumentId, { documentFingerprint });
  }
  if (current.documentId && current.documentId !== senderDocumentId) return null;
  // Navigation events are authoritative for an existing live session. A
  // content message created just before an SPA transition can arrive after
  // the new route was committed; never let that stale sender roll state back.
  if (
    current.navigationKey !== normalizedSenderUrl.url ||
    current.documentFingerprint !== documentFingerprint
  ) {
    return null;
  }
  if (!current.documentId) {
    current.documentId = senderDocumentId;
    rememberDocumentId(tabId, 0, senderDocumentId);
  }
  return touchSession(tabId) ? current : null;
}

function analysisModeStorageUnavailableResponse() {
  return {
    ok: false,
    mode: DEFAULT_ANALYSIS_MODE,
    code: "STORAGE_ISOLATION_UNAVAILABLE",
    error: "Trusted local storage access is unavailable"
  };
}

function queueAnalysisModePreferenceWrite(mode) {
  const normalizedMode = normalizeAnalysisModePreference(mode);
  const operation = analysisModePreferenceWrite.then(async () => {
    const savedMode = await saveAnalysisModePreference(normalizedMode);
    analysisModePreference = normalizeAnalysisModePreference(savedMode);
    return analysisModePreference;
  });
  analysisModePreferenceWrite = operation.catch(() => undefined);
  return operation;
}

async function currentAnalysisModePreference() {
  await analysisModePreferenceWrite;
  return normalizeAnalysisModePreference(analysisModePreference);
}

async function handleRuntimeMessage(message, sender, validation) {
  await observationStateReady;

  if (message?.type === "GET_COMPANION_OVERLAY_STATE") {
    const context = await companionOverlayRuntime.currentTopDocument(validation.tabId);
    if (
      !context ||
      context.documentId !== sender.documentId ||
      !sameDocumentUrl(context.tab?.url || "", sender.url || "")
    ) {
      return { ok: false, error: "Stale companion overlay document" };
    }
    const snapshot = await companionOverlayRuntime.snapshot(validation.tabId);
    return {
      ok: true,
      enabled: localStorageTrustedContextsOnly && companionOverlayEnabled,
      generation: snapshot.generation,
      revision: snapshot.revision,
      state: snapshot.state
    };
  }

  if (message?.type === "GET_COMPANION_OVERLAY_PREFERENCE") {
    if (!localStorageTrustedContextsOnly) return companionStorageUnavailableResponse();
    return {
      ok: true,
      enabled: companionOverlayEnabled
    };
  }

  if (message?.type === "SET_COMPANION_OVERLAY_PREFERENCE") {
    if (!localStorageTrustedContextsOnly) {
      companionOverlayEnabled = false;
      return companionStorageUnavailableResponse();
    }
    const nextEnabled = normalizeCompanionOverlayEnabled(message.enabled);
    try {
      await chrome.storage.local.set({ [COMPANION_OVERLAY_ENABLED_KEY]: nextEnabled });
    } catch {
      return { ok: false, enabled: companionOverlayEnabled, error: "Preference could not be saved" };
    }
    const changed = nextEnabled !== companionOverlayEnabled;
    companionOverlayEnabled = nextEnabled;
    if (changed) await companionOverlayRuntime.broadcast();
    return { ok: true, enabled: companionOverlayEnabled };
  }

  if (message?.type === "GET_ANALYSIS_MODE_PREFERENCE") {
    if (!localStorageTrustedContextsOnly) return analysisModeStorageUnavailableResponse();
    return {
      ok: true,
      mode: await currentAnalysisModePreference()
    };
  }

  if (message?.type === "SET_ANALYSIS_MODE_PREFERENCE") {
    if (!localStorageTrustedContextsOnly) return analysisModeStorageUnavailableResponse();
    try {
      const mode = await queueAnalysisModePreferenceWrite(message.mode);
      return { ok: true, mode };
    } catch {
      return {
        ok: false,
        mode: await currentAnalysisModePreference(),
        code: "STORAGE_FAILED",
        error: "Analysis mode preference could not be saved"
      };
    }
  }

  if (message?.type === "GET_OBSERVATION_SETTINGS") {
    return {
      ok: true,
      settings: contentObservationSettingsForUrl(sender.tab?.url || sender.url)
    };
  }

  if (message?.type === "GET_NETWORK_ACTIVITY") {
    const tab = await syncTabObservation(validation.tabId);
    if (tab) await refreshCurrentCookies(validation.tabId, tab);
    const session = tab ? getLiveTabSession(validation.tabId) : null;
    return {
      ok: true,
      observationEnabled: Boolean(tab && session),
      requests: session ? tabRequests.get(validation.tabId) || [] : [],
      cookies: session ? tabCookies.get(validation.tabId) || [] : [],
      observationStartedAt: session ? tabObservationStartedAt.get(validation.tabId) : undefined,
      snapshots: session ? tabSnapshots.get(validation.tabId) || [] : [],
      session: session
        ? {
            generation: session.generation,
            origin: session.origin,
            navigationKey: session.navigationKey,
            documentFingerprint: session.documentFingerprint,
            documentId: session.documentId,
            startedAt: session.startedAt
          }
        : null
    };
  }

  if (message?.type === "CLEAR_NETWORK_ACTIVITY") {
    const context = await getCurrentTabFrameContext(validation.tabId);
    if (
      !observationActionContextMatches(
        context,
        message.documentId,
        message.documentFingerprint
      )
    ) {
      return { ok: false, code: "STALE_PAGE", error: "Page context changed" };
    }
    const { tab, documentId } = context;
    if (!observationMatcher(tab?.url || "")) {
      dropTabObservation(validation.tabId);
      return { ok: true, observationEnabled: false };
    }
    const session = rotateTabObservation(validation.tabId, tab.url, documentId, {
      documentFingerprint: message.documentFingerprint
    });
    return {
      ok: Boolean(session),
      observationEnabled: Boolean(session),
      observationStartedAt: session?.startedAt
    };
  }

  if (message?.type === "SAVE_OBSERVATION_SNAPSHOT") {
    const context = await getCurrentTabFrameContext(validation.tabId);
    if (
      !observationActionContextMatches(
        context,
        message.documentId,
        message.documentFingerprint
      )
    ) {
      return { ok: false, code: "STALE_PAGE", error: "Page context changed" };
    }
    const tab = syncTabObservationFromContext(validation.tabId, context);
    if (!tab) return { ok: false, error: "Observation is disabled for this tab" };
    const snapshot = createSnapshot(validation.tabId, message.label || t("snapshotBaseline"));
    return { ok: Boolean(snapshot), snapshot, snapshots: tabSnapshots.get(validation.tabId) || [] };
  }

  if (message?.type === "SAVE_MONITORED_POLICY_SNAPSHOT") {
    if (!localStorageTrustedContextsOnly) {
      return {
        ok: false,
        code: "STORAGE_ISOLATION_UNAVAILABLE",
        error: "Trusted local storage is unavailable"
      };
    }
    const requestedPolicyUrl = normalizePolicyUrl(message.policyUrl);
    if (!requestedPolicyUrl || requestedPolicyUrl !== message.policyUrl) {
      return { ok: false, code: "INVALID_URL", error: "Policy URL is not canonical" };
    }
    const initialContext = await getMatchingPolicySaveContext(
      validation.tabId,
      message.documentId,
      requestedPolicyUrl
    );
    if (!initialContext) {
      return { ok: false, code: "STALE_PAGE", error: "Page context changed" };
    }

    let document;
    try {
      document = await fetchPolicyDocument(requestedPolicyUrl);
    } catch {
      return { ok: false, code: "FETCH_FAILED", error: "Policy could not be fetched safely" };
    }

    const text = extractFetchedPolicyText(document);
    const policyAnalysis = analyzePolicy(boundedFetchedPolicyAnalysisText(text));
    if (!policyAnalysis?.ok) {
      return { ok: false, code: "NOT_POLICY", error: "Fetched document was not recognized as a policy" };
    }

    const snapshot = await createPolicySnapshot({
      title: String(message.title || initialContext.tab?.title || "").slice(0, 512),
      url: requestedPolicyUrl,
      text,
      policyAnalysis
    });
    const finalContext = await getMatchingPolicySaveContext(
      validation.tabId,
      message.documentId,
      requestedPolicyUrl
    );
    if (!finalContext) {
      return { ok: false, code: "STALE_PAGE", error: "Page context changed" };
    }

    try {
      await savePolicySnapshot(snapshot);
    } catch {
      return { ok: false, code: "STORAGE_FAILED", error: "Policy snapshot could not be stored" };
    }
    return { ok: true, snapshot };
  }

  if (message?.type === "PAGE_RISK_SCAN") {
    const tabId = validation.tabId;
    const session = ensureContentSenderSession(sender);
    if (!session) {
      return { ok: true, skipped: true, indicator: createRiskIndicator({ level: "unknown" }) };
    }
    const existingIndicator = tabRiskIndicators.get(tabId);
    if (
      EXPLICIT_INDICATOR_SOURCES.has(existingIndicator?.source) &&
      Date.now() - existingIndicator.updatedAt < EXPLICIT_INDICATOR_PRIORITY_MS
    ) {
      return { ok: true, skipped: true, indicator: existingIndicator };
    }
    if (!message.policyLike) {
      const indicator = publishRiskIndicator(tabId, {
        level: "unknown",
        source: "page-scan",
        url: sender.url || sender.tab?.url
      });
      return { ok: true, skipped: true, indicator };
    }
    const policyAnalysis = analyzePolicy(message.text || "");
    const indicator = publishRiskIndicator(
      tabId,
      createRiskIndicatorFromPolicy(policyAnalysis, {
        source: "page-scan",
        url: sender.url || sender.tab?.url
      })
    );
    return { ok: true, indicator };
  }

  if (message?.type === "SET_RISK_INDICATOR") {
    const tabId = validation.tabId;
    const context = await getCurrentTabDocument(tabId);
    if (!context) {
      return { ok: false, error: "Tab is unavailable" };
    }
    const { tab, documentId } = context;
    const normalizedTabUrl = sanitizeNetworkUrl(tab?.url);
    if (!normalizedTabUrl) return { ok: false, error: "Unsupported tab URL" };
    const normalizedIndicatorUrl = sanitizeNetworkUrl(message.indicator?.url);
    const tabDocumentFingerprint = documentUrlFingerprint(tab.url);
    if (
      !normalizedIndicatorUrl ||
      normalizedIndicatorUrl.url !== normalizedTabUrl.url ||
      message.indicator?.documentFingerprint !== tabDocumentFingerprint ||
      message.indicator?.documentId !== documentId
    ) {
      return { ok: false, error: "Stale page context" };
    }
    const payload = {
      ...(message.indicator || {}),
      title: "",
      url: tab.url
    };
    const observationAllowed = observationMatcher(tab.url);
    const session = observationAllowed
      ? ensureObservation(tabId, tab.url, documentId, { documentFingerprint: tabDocumentFingerprint })
      : null;
    const canPersist =
      observationAllowed &&
      session?.navigationKey === normalizedTabUrl.url &&
      session.documentFingerprint === tabDocumentFingerprint &&
      session.documentId === documentId;
    const indicator = canPersist
      ? publishRiskIndicator(tabId, payload)
      : publishTransientRiskIndicator(tabId, payload);
    return { ok: Boolean(indicator), indicator };
  }

  if (message?.type === "CHECK_SAVED_POLICIES_NOW") {
    return runSavedPolicyChecks({ force: true });
  }

  return { ok: false, error: "Unsupported message type" };
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  const validation = validateRuntimeMessage(message, sender, chrome.runtime.id);
  if (!validation.ok) {
    sendResponse({ ok: false, error: validation.error });
    return false;
  }

  void handleRuntimeMessage(message, sender, validation)
    .then(sendResponse)
    .catch(() => sendResponse({ ok: false, error: "Background request failed" }));
  return true;
});

function automaticPolicyCheckDue(snapshot, health, now = Date.now()) {
  const lastAttemptAt = Date.parse(health?.lastAttemptAt || snapshot?.capturedAt || "");
  return !Number.isFinite(lastAttemptAt) || now - lastAttemptAt >= POLICY_CHECK_INTERVAL_MS;
}

async function checkSavedPoliciesForChanges({ force = false } = {}) {
  await getLocalePreference();
  const snapshots = await loadPolicySnapshots();
  const health = force ? {} : await loadPolicyCheckHealth();
  const entries = Object.entries(snapshots).filter(
    ([snapshotKey, snapshot]) =>
      snapshot?.url && (force || automaticPolicyCheckDue(snapshot, health[snapshotKey]))
  );
  const results = await mapPolicyChecksWithConcurrency(entries, async ([snapshotKey, previousSnapshot]) => {
    let result;
    try {
      result = {
        ...(await checkSinglePolicy(snapshotKey, previousSnapshot)),
        baselineCapturedAt: previousSnapshot.capturedAt
      };
    } catch (error) {
      result = {
        snapshotKey,
        origin: previousSnapshot.origin || "",
        baselineCapturedAt: previousSnapshot.capturedAt,
        ok: false,
        errorCategory: policyCheckErrorCategory(error)
      };
    }

    try {
      await recordPolicyCheckResults([result], new Date().toISOString());
    } catch {
      // Keep this policy's check result usable if its health metadata could not be stored.
    }
    return result;
  }, 4);

  return {
    ok: true,
    checked: results.length,
    changed: results.filter((result) => result.changed).length,
    notified: results.filter((result) => result.notified).length,
    failed: results.filter((result) => !result.ok).length,
    results
  };
}

function policyCheckErrorCategory(error) {
  const message = String(error?.message || error || "").toLowerCase();
  if (message.includes("timed out") || error?.name === "AbortError") return "timeout";
  if (message.includes("redirect")) return "redirect";
  if (message.includes("content type")) return "content_type";
  if (message.includes("size limit") || message.includes("too large")) return "response_too_large";
  if (
    message.includes("invalid policy url") ||
    message.includes("policy url scheme") ||
    message.includes("https policy") ||
    message.includes("private policy host") ||
    message.includes("policy url credentials") ||
    message.includes("sensitive policy url")
  ) {
    return "invalid_url";
  }
  if (/policy fetch failed:\s*\d{3}/.test(message)) return "http_status";
  if (message.includes("fetch") || message.includes("network")) return "network";
  return "unknown";
}

function runSavedPolicyChecks({ force = false } = {}) {
  if (policyCheckInFlight) {
    if (!force || policyCheckInFlightForced) return policyCheckInFlight;
    if (!forcedPolicyCheckQueued) {
      forcedPolicyCheckQueued = policyCheckInFlight
        .catch(() => {})
        .then(() => runSavedPolicyChecks({ force: true }))
        .finally(() => {
          forcedPolicyCheckQueued = null;
        });
    }
    return forcedPolicyCheckQueued;
  }
  policyCheckInFlightForced = force;
  let currentRun;
  currentRun = (async () => {
    await observationStateReady;
    if (!localStorageTrustedContextsOnly) {
      return {
        ok: false,
        code: "STORAGE_ISOLATION_UNAVAILABLE",
        error: "Trusted local storage is unavailable",
        checked: 0,
        changed: 0,
        notified: 0,
        failed: 0,
        results: []
      };
    }
    return checkSavedPoliciesForChanges({ force });
  })().finally(() => {
    if (policyCheckInFlight === currentRun) {
      policyCheckInFlight = null;
      policyCheckInFlightForced = false;
    }
  });
  policyCheckInFlight = currentRun;
  return currentRun;
}

async function checkSinglePolicy(snapshotKey, previousSnapshot) {
  const document = await fetchPolicyDocument(previousSnapshot.url);
  const text = extractFetchedPolicyText(document);
  const policyAnalysis = analyzePolicy(boundedFetchedPolicyAnalysisText(text));
  if (!policyAnalysis?.ok) {
    return {
      snapshotKey,
      origin: previousSnapshot.origin || "",
      ok: false,
      skipped: true,
      changed: false,
      notified: false,
      errorCategory: "not_policy"
    };
  }
  const currentSnapshot = await createPolicySnapshot({
    title: previousSnapshot.title,
    url: previousSnapshot.url,
    text,
    policyAnalysis
  });
  const changeAnalysis = comparePolicySnapshot(previousSnapshot, currentSnapshot);

  if (!changeAnalysis.changed) {
    return {
      snapshotKey,
      origin: previousSnapshot.origin || currentSnapshot.origin,
      ok: true,
      changed: false,
      notified: false
    };
  }

  const notified = await maybeNotifyPolicyChange(
    snapshotKey,
    previousSnapshot,
    currentSnapshot,
    changeAnalysis
  );
  return {
    snapshotKey,
    origin: previousSnapshot.origin || currentSnapshot.origin,
    ok: true,
    changed: true,
    notified
  };
}

async function maybeNotifyPolicyChange(snapshotKey, previousSnapshot, currentSnapshot, changeAnalysis) {
  if (!shouldNotifyPolicyChange(changeAnalysis)) return false;

  return withPolicyStorageLock(async () => {
    const stored = await chrome.storage.local.get([
      POLICY_SNAPSHOTS_KEY,
      NOTIFIED_POLICY_CHANGES_KEY
    ]);
    const liveBaseline = stored?.[POLICY_SNAPSHOTS_KEY]?.[snapshotKey];
    if (
      !liveBaseline ||
      String(liveBaseline.textHash || "").toLowerCase() !==
        String(previousSnapshot.textHash || "").toLowerCase() ||
      String(liveBaseline.capturedAt || "") !== String(previousSnapshot.capturedAt || "")
    ) {
      return false;
    }

    const dedupeKey = buildPolicyChangeDedupeKey(snapshotKey, changeAnalysis, currentSnapshot);
    const notifiedChanges = sanitizeNotificationDedupe(
      stored[NOTIFIED_POLICY_CHANGES_KEY]
    );
    if (notifiedChanges[snapshotKey] === dedupeKey) return false;

    const notification = buildPolicyChangeNotification(currentSnapshot, changeAnalysis);
    await chrome.notifications.create(`policy-change:${hashText(snapshotKey)}`, {
      type: "basic",
      iconUrl: chrome.runtime.getURL("icons/icon.png"),
      title: notification.title,
      message: notification.message,
      priority: 2
    });

    notifiedChanges[snapshotKey] = dedupeKey;
    await chrome.storage.local.set({ [NOTIFIED_POLICY_CHANGES_KEY]: notifiedChanges });
    return true;
  });
}
