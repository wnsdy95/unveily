import { sameDocumentUrl } from "./backgroundSecurity.js";

export const COMPANION_OVERLAY_GENERATION_KEY = "companionOverlayWorkerGenerationV1";
const DEFAULT_BROADCAST_CONCURRENCY = 4;

export async function reserveCompanionOverlayGeneration(storageArea) {
  const stored = await storageArea.get(COMPANION_OVERLAY_GENERATION_KEY);
  const previous = stored?.[COMPANION_OVERLAY_GENERATION_KEY];
  const generation =
    Number.isSafeInteger(previous) && previous >= 0 ? previous + 1 : 1;
  if (!Number.isSafeInteger(generation)) throw new Error("Companion generation exhausted");
  await storageArea.set({ [COMPANION_OVERLAY_GENERATION_KEY]: generation });
  return generation;
}

export async function getCurrentCompanionTopDocument(chrome, tabId) {
  let initialTab;
  let initialFrame;
  try {
    [initialTab, initialFrame] = await Promise.all([
      chrome.tabs.get(tabId),
      chrome.webNavigation.getFrame({ tabId, frameId: 0 })
    ]);
  } catch {
    return null;
  }
  const initialDocumentId =
    typeof initialFrame?.documentId === "string" && initialFrame.documentId.length <= 128
      ? initialFrame.documentId
      : "";
  if (
    !initialDocumentId ||
    (initialFrame.documentLifecycle && initialFrame.documentLifecycle !== "active") ||
    !sameDocumentUrl(initialTab?.url || "", initialFrame?.url || "")
  ) {
    return null;
  }

  let currentTab;
  let currentFrame;
  try {
    [currentTab, currentFrame] = await Promise.all([
      chrome.tabs.get(tabId),
      chrome.webNavigation.getFrame({ tabId, frameId: 0 })
    ]);
  } catch {
    return null;
  }
  if (
    currentFrame?.documentId !== initialDocumentId ||
    (currentFrame.documentLifecycle && currentFrame.documentLifecycle !== "active") ||
    !sameDocumentUrl(initialTab?.url || "", currentTab?.url || "") ||
    !sameDocumentUrl(currentTab?.url || "", currentFrame?.url || "")
  ) {
    return null;
  }
  return { tab: currentTab, documentId: initialDocumentId };
}

export function createCompanionOverlayRuntime({
  chrome,
  getCurrentTopDocument = (tabId) => getCurrentCompanionTopDocument(chrome, tabId),
  getState,
  createUnknownState,
  isEnabled,
  generationReady,
  maxBroadcastConcurrency = DEFAULT_BROADCAST_CONCURRENCY
}) {
  const revisions = new Map();
  let nextRevision = 0;
  const broadcastConcurrency = Math.max(1, Math.min(8, Math.floor(maxBroadcastConcurrency) || 1));

  function currentRevision(tabId) {
    return revisions.get(tabId) || 0;
  }

  async function advanceRevision(tabId) {
    const generation = await generationReady;
    if (!Number.isSafeInteger(generation) || generation < 1) {
      throw new Error("Companion generation unavailable");
    }
    nextRevision += 1;
    if (!Number.isSafeInteger(nextRevision)) throw new Error("Companion revision exhausted");
    const revision = nextRevision;
    revisions.set(tabId, revision);
    return { generation, revision };
  }

  async function snapshot(tabId) {
    const generation = await generationReady;
    if (!Number.isSafeInteger(generation) || generation < 1) {
      throw new Error("Companion generation unavailable");
    }
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const revision = currentRevision(tabId);
      const state = await getState(tabId);
      if (revision === currentRevision(tabId)) return { generation, revision, state };
    }
    return { generation, revision: currentRevision(tabId), state: await getState(tabId) };
  }

  function send(tabId, documentId, message) {
    try {
      chrome.tabs.sendMessage(tabId, message, { documentId }, () => {
        void chrome.runtime.lastError;
      });
    } catch {
      // Restricted, closed, or replaced documents have no overlay receiver.
    }
  }

  async function forceDisable(tabId) {
    const context = await getCurrentTopDocument(tabId);
    if (!context) return;
    send(tabId, context.documentId, {
      type: "COMPANION_OVERLAY_VISIBILITY",
      enabled: false,
      forceDisable: true,
      state: createUnknownState()
    });
  }

  async function deliver(tabId, type, enabled = isEnabled()) {
    if (!Number.isInteger(tabId) || tabId < 0) return;
    let stamp;
    try {
      stamp = await advanceRevision(tabId);
    } catch {
      await forceDisable(tabId);
      return;
    }
    const context = await getCurrentTopDocument(tabId);
    if (!context || stamp.revision !== currentRevision(tabId)) return;
    const state = enabled ? await getState(tabId) : createUnknownState();
    if (stamp.revision !== currentRevision(tabId)) return;
    send(
      tabId,
      context.documentId,
      type === "COMPANION_OVERLAY_VISIBILITY"
        ? { type, enabled, ...stamp, state }
        : { type, ...stamp, state }
    );
  }

  async function refresh(tabId) {
    if (!isEnabled()) return;
    await deliver(tabId, "COMPANION_OVERLAY_STATE", true);
  }

  async function broadcast() {
    let tabs;
    try {
      tabs = await chrome.tabs.query({ url: ["http://*/*", "https://*/*"] });
    } catch {
      return;
    }
    const enabled = isEnabled();
    const tabIds = tabs
      .filter((tab) => Number.isInteger(tab?.id) && tab.id >= 0)
      .map((tab) => tab.id);
    let nextIndex = 0;
    async function worker() {
      while (nextIndex < tabIds.length) {
        const tabId = tabIds[nextIndex];
        nextIndex += 1;
        await deliver(tabId, "COMPANION_OVERLAY_VISIBILITY", enabled);
      }
    }
    await Promise.all(
      Array.from({ length: Math.min(broadcastConcurrency, tabIds.length) }, () => worker())
    );
  }

  function forget(tabId) {
    revisions.delete(tabId);
  }

  return Object.freeze({
    broadcast,
    currentTopDocument: getCurrentTopDocument,
    forget,
    refresh,
    snapshot
  });
}
