(() => {
  if (window.top !== window || globalThis.__unveilyCompanionOverlay) return;

  const ownedHosts =
    globalThis.__unveilyCompanionOverlayOwnedHosts instanceof WeakSet
      ? globalThis.__unveilyCompanionOverlayOwnedHosts
      : new WeakSet();
  globalThis.__unveilyCompanionOverlayOwnedHosts = ownedHosts;

  const FALLBACK_MESSAGES = Object.freeze({
    companionUnknown: "아직 완료된 분석 결과가 없습니다. 알 수 없음은 안전 판정이 아닙니다.",
    companionAnalyzing: "현재 페이지를 분석하는 중입니다.",
    companionPaused: "상시 관찰이 일시 중지되었습니다.",
    companionExcluded: "현재 사이트가 관찰 제외 목록에 있습니다.",
    companionUnsupported: "이 페이지 형식은 분석할 수 없습니다.",
    companionUnavailable: "컴패니언 상태를 불러올 수 없습니다.",
    companionLowRisk: "낮은 위험",
    companionCautionRisk: "주의 위험",
    companionHighRisk: "높은 위험"
  });
  const STATUS_MESSAGES = Object.freeze({
    unknown: "companionUnknown",
    analyzing: "companionAnalyzing",
    paused: "companionPaused",
    excluded: "companionExcluded",
    unsupported: "companionUnsupported",
    unavailable: "companionUnavailable"
  });
  const STATUS_SYMBOLS = Object.freeze({
    unknown: "?",
    analyzing: "…",
    paused: "Ⅱ",
    excluded: "×",
    unsupported: "—",
    unavailable: "!"
  });
  const RISK_COLOR_STOPS = Object.freeze([
    Object.freeze({ score: 0, rgb: Object.freeze([3, 152, 85]) }),
    Object.freeze({ score: 50, rgb: Object.freeze([220, 104, 3]) }),
    Object.freeze({ score: 100, rgb: Object.freeze([217, 45, 32]) })
  ]);
  const AVAILABLE_STATUSES = new Set(["ready", "available", "complete"]);
  const KNOWN_STATUSES = new Set(Object.keys(STATUS_MESSAGES));
  const KNOWN_SOURCES = new Set([
    "automatic-policy",
    "page-analysis",
    "cookie-analysis",
    "none"
  ]);
  const NEUTRAL_COLOR = "#667085";

  let enabled = false;
  let host = null;
  let shadow = null;
  let indicator = null;
  let currentSnapshot = Object.freeze({
    enabled: false,
    mounted: false,
    status: "unknown",
    score: null,
    source: "none",
    color: NEUTRAL_COLOR,
    text: "?",
    role: "status",
    ariaValueNow: null,
    ariaValueText: ""
  });
  let latestGeneration = -1;
  let latestRevision = -1;
  let protocolFailedClosed = false;
  let stateRequestSequence = 0;

  function t(key) {
    try {
      return chrome.i18n?.getMessage(key) || FALLBACK_MESSAGES[key] || key;
    } catch {
      return FALLBACK_MESSAGES[key] || key;
    }
  }

  function normalizedScore(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) return null;
    return Math.max(0, Math.min(100, value));
  }

  function channelHex(channel) {
    return channel.toString(16).padStart(2, "0").toUpperCase();
  }

  function riskColorForScore(value) {
    const score = normalizedScore(value);
    if (score === null) return NEUTRAL_COLOR;
    const upperIndex = score <= 50 ? 1 : 2;
    const lower = RISK_COLOR_STOPS[upperIndex - 1];
    const upper = RISK_COLOR_STOPS[upperIndex];
    const progress = (score - lower.score) / (upper.score - lower.score);
    const rgb = lower.rgb.map((channel, index) =>
      Math.round(channel + (upper.rgb[index] - channel) * progress)
    );
    return `#${rgb.map(channelHex).join("")}`;
  }

  function riskMessageKey(level, score) {
    const normalizedLevel = typeof level === "string" ? level.toLowerCase() : "";
    if (normalizedLevel === "high" || score >= 67) return "companionHighRisk";
    if (normalizedLevel === "medium" || score >= 34) return "companionCautionRisk";
    return "companionLowRisk";
  }

  function contrastColor(hexColor) {
    const channels = [1, 3, 5].map((index) => Number.parseInt(hexColor.slice(index, index + 2), 16));
    const luminance = channels
      .map((channel) => channel / 255)
      .map((channel) => (channel <= 0.03928 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4))
      .reduce((total, channel, index) => total + channel * [0.2126, 0.7152, 0.0722][index], 0);
    const whiteContrast = 1.05 / (luminance + 0.05);
    const darkContrast = (luminance + 0.05) / 0.05;
    return whiteContrast >= darkContrast ? "#FFFFFF" : "#101828";
  }

  function setHostStyles(element) {
    const declarations = {
      all: "initial",
      position: "fixed",
      left: "16px",
      bottom: "16px",
      width: "56px",
      height: "56px",
      display: "block",
      margin: "0",
      padding: "0",
      border: "0",
      zIndex: "2147483647",
      pointerEvents: "none",
      userSelect: "none",
      contain: "layout style paint",
      isolation: "isolate"
    };
    for (const [property, value] of Object.entries(declarations)) {
      const cssProperty = property.replace(/[A-Z]/g, (letter) => `-${letter.toLowerCase()}`);
      element.style.setProperty(cssProperty, value, "important");
    }
  }

  function buildOverlayHost() {
    const nextHost = document.createElement("div");
    setHostStyles(nextHost);
    ownedHosts.add(nextHost);
    const nextShadow = nextHost.attachShadow({ mode: "closed" });

    const style = document.createElement("style");
    style.textContent = `
      :host { all: initial; }
      .indicator {
        align-items: center;
        border: 3px solid #fff;
        border-radius: 50%;
        box-shadow: 0 2px 9px rgb(16 24 40 / 38%), 0 0 0 1px rgb(16 24 40 / 24%);
        box-sizing: border-box;
        display: flex;
        font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
        font-size: 16px;
        font-variant-numeric: tabular-nums;
        font-weight: 800;
        height: 56px;
        justify-content: center;
        letter-spacing: -0.02em;
        line-height: 1;
        overflow: hidden;
        pointer-events: none;
        text-align: center;
        width: 56px;
      }
    `;
    const nextIndicator = document.createElement("div");
    nextIndicator.className = "indicator";
    nextIndicator.setAttribute("aria-live", "polite");
    nextIndicator.setAttribute("aria-atomic", "true");
    nextShadow.append(style, nextIndicator);

    host = nextHost;
    shadow = nextShadow;
    indicator = nextIndicator;
    return nextHost;
  }

  function mount() {
    if (!enabled || !document.documentElement) return false;
    if (!host) buildOverlayHost();
    if (!host.isConnected) document.documentElement.appendChild(host);
    return host.isConnected;
  }

  function unmount() {
    if (host?.isConnected) host.remove();
    host = null;
    shadow = null;
    indicator = null;
  }

  function renderUnavailable(status) {
    if (!mount() || !indicator) return;
    const normalizedStatus = KNOWN_STATUSES.has(status) ? status : "unknown";
    const message = t(STATUS_MESSAGES[normalizedStatus]);
    const symbol = STATUS_SYMBOLS[normalizedStatus] || "?";
    indicator.textContent = symbol;
    indicator.style.backgroundColor = NEUTRAL_COLOR;
    indicator.style.color = contrastColor(NEUTRAL_COLOR);
    indicator.setAttribute("role", "status");
    indicator.setAttribute("aria-label", message);
    indicator.removeAttribute("aria-valuemin");
    indicator.removeAttribute("aria-valuemax");
    indicator.removeAttribute("aria-valuenow");
    indicator.removeAttribute("aria-valuetext");
    currentSnapshot = Object.freeze({
      enabled,
      mounted: host.isConnected,
      status: normalizedStatus,
      score: null,
      source: "none",
      color: NEUTRAL_COLOR,
      text: symbol,
      role: "status",
      ariaValueNow: null,
      ariaValueText: message
    });
  }

  function renderState(state) {
    if (!enabled) return;
    const status = typeof state?.status === "string" ? state.status.toLowerCase() : "unknown";
    const score = normalizedScore(state?.score);
    if (!AVAILABLE_STATUSES.has(status) || score === null) {
      renderUnavailable(status);
      return;
    }
    if (!mount() || !indicator) return;

    const displayedScore = Math.round(score);
    const color = riskColorForScore(score);
    const source = KNOWN_SOURCES.has(state?.source) ? state.source : "none";
    const riskDescription = t(riskMessageKey(state?.level, score));
    const valueText = `${riskDescription}, ${displayedScore}/100`;
    indicator.textContent = String(displayedScore);
    indicator.style.backgroundColor = color;
    indicator.style.color = contrastColor(color);
    indicator.setAttribute("role", "meter");
    indicator.setAttribute("aria-label", valueText);
    indicator.setAttribute("aria-valuemin", "0");
    indicator.setAttribute("aria-valuemax", "100");
    indicator.setAttribute("aria-valuenow", String(score));
    indicator.setAttribute("aria-valuetext", valueText);
    currentSnapshot = Object.freeze({
      enabled,
      mounted: host.isConnected,
      status: "ready",
      score,
      source,
      color,
      text: String(displayedScore),
      role: "meter",
      ariaValueNow: String(score),
      ariaValueText: valueText
    });
  }

  function setVisibility(nextEnabled, state) {
    enabled = nextEnabled === true;
    if (!enabled) {
      unmount();
      currentSnapshot = Object.freeze({
        enabled: false,
        mounted: false,
        status: "unknown",
        score: null,
        source: "none",
        color: NEUTRAL_COLOR,
        text: "?",
        role: "status",
        ariaValueNow: null,
        ariaValueText: ""
      });
      return;
    }
    renderState(state);
  }

  function applyRevision(generation, revision, update, { allowEqual = false } = {}) {
    if (
      protocolFailedClosed ||
      !Number.isSafeInteger(generation) ||
      generation < 1 ||
      !Number.isSafeInteger(revision) ||
      revision < 0 ||
      generation < latestGeneration ||
      (generation === latestGeneration &&
        (allowEqual ? revision < latestRevision : revision <= latestRevision)) ||
      typeof update !== "function"
    ) {
      return false;
    }
    latestGeneration = generation;
    latestRevision = revision;
    update();
    return true;
  }

  function requestAuthoritativeState({ allowEqual = false } = {}) {
    const requestSequence = ++stateRequestSequence;
    try {
      chrome.runtime.sendMessage({ type: "GET_COMPANION_OVERLAY_STATE" }, (response) => {
        if (
          requestSequence !== stateRequestSequence ||
          chrome.runtime.lastError ||
          response?.ok !== true
        ) {
          return;
        }
        applyRevision(
          response.generation,
          response.revision,
          () => setVisibility(response.enabled, response.state),
          { allowEqual }
        );
      });
    } catch {
      // The overlay is opt-in and therefore remains absent when synchronization fails.
    }
  }

  function handlePageHide(event) {
    if (event?.isTrusted !== true || event.persisted !== true) return;
    stateRequestSequence += 1;
    setVisibility(false);
  }

  function handlePageShow(event) {
    if (event?.isTrusted !== true || event.persisted !== true || protocolFailedClosed) return;
    // A BFCache document keeps its JavaScript heap but does not receive runtime
    // broadcasts while frozen. Hide first, then accept an equal trusted stamp so
    // an OFF preference cannot restore a stale indicator and an unchanged ON
    // preference can be mounted again.
    setVisibility(false);
    requestAuthoritativeState({ allowEqual: true });
  }

  function isOwnedNode(node) {
    if (!node) return false;
    if (ownedHosts.has(node)) return true;
    try {
      return ownedHosts.has(node.getRootNode?.().host);
    } catch {
      return false;
    }
  }

  function ownsMutationRecord(record) {
    if (!record) return false;
    if (isOwnedNode(record.target)) return true;
    const changedNodes = [...(record.addedNodes || []), ...(record.removedNodes || [])];
    return changedNodes.length > 0 && changedNodes.every(isOwnedNode);
  }

  function validBackgroundSender(sender) {
    return sender?.id === chrome.runtime.id && !sender.tab;
  }

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (!validBackgroundSender(sender) || !message || typeof message !== "object") return false;
    if (message.type === "COMPANION_OVERLAY_VISIBILITY") {
      if (message.forceDisable === true && message.enabled === false) {
        protocolFailedClosed = true;
        setVisibility(false, message.state);
        sendResponse?.({ ok: true });
        return false;
      }
      applyRevision(message.generation, message.revision, () =>
        setVisibility(message.enabled, message.state)
      );
      sendResponse?.({ ok: true });
      return false;
    }
    if (message.type === "COMPANION_OVERLAY_STATE") {
      const applied = applyRevision(message.generation, message.revision, () =>
        renderState(message.state)
      );
      if (applied && !enabled) {
        // A state-only push can overtake the initial visibility response. It
        // must not enable the companion by itself, but it also must not make
        // the authoritative response stale forever. Re-read visibility and
        // allow the equal snapshot revision produced by that state push.
        requestAuthoritativeState({ allowEqual: true });
      }
      sendResponse?.({ ok: true });
      return false;
    }
    return false;
  });

  const api = Object.freeze({
    ownsMutationRecord,
    snapshot: () => ({
      ...currentSnapshot,
      generation: latestGeneration,
      revision: latestRevision,
      protocolFailedClosed
    })
  });
  globalThis.__unveilyCompanionOverlay = api;

  window.addEventListener("pagehide", handlePageHide);
  window.addEventListener("pageshow", handlePageShow);
  requestAuthoritativeState();
})();
