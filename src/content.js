(() => {
  if (globalThis.__unveilyContentScriptLoaded) return;
  globalThis.__unveilyContentScriptLoaded = true;

  const RISK_INDICATOR_HOST_ID = "unveily-risk-indicator-host";
  const RISK_LEVELS = new Set(["unknown", "analyzing", "low", "medium", "high"]);
  const RISK_SCAN_DELAY_MS = 900;
  const MAX_RISK_SCAN_TEXT_LENGTH = 120000;
  const BLOCKED_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "SVG", "CANVAS"]);
  const POLICY_HINTS = [
    "terms",
    "privacy",
    "policy",
    "agreement",
    "condition",
    "약관",
    "개인정보",
    "처리방침",
    "이용약관",
    "동의"
  ];
  const CONSENT_HINTS = [
    "cookie",
    "cookies",
    "consent",
    "privacy",
    "tracking",
    "advertising",
    "analytics",
    "쿠키",
    "동의",
    "개인정보",
    "추적",
    "광고",
    "분석"
  ];
  let riskScanTimer = null;
  let lastRiskScanFingerprint = "";

  function isVisible(element) {
    const style = window.getComputedStyle(element);
    return style.display !== "none" && style.visibility !== "hidden" && style.opacity !== "0";
  }

  function normalizeText(text) {
    return text
      .replace(/\u00a0/g, " ")
      .replace(/[ \t]+/g, " ")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  }

  function scoreElement(element) {
    const text = normalizeText(element.innerText || "");
    if (text.length < 120) return 0;

    const attrs = `${element.id || ""} ${element.className || ""} ${element.getAttribute("aria-label") || ""}`.toLowerCase();
    const hintScore = POLICY_HINTS.reduce((score, hint) => score + (attrs.includes(hint) ? 3 : 0), 0);
    const textScore = POLICY_HINTS.reduce((score, hint) => score + (text.toLowerCase().includes(hint) ? 1 : 0), 0);

    return Math.min(text.length / 1000, 20) + hintScore + textScore;
  }

  function getBestReadableText() {
    const candidates = Array.from(document.querySelectorAll("main, article, section, [role='main'], body"))
      .filter((element) => !BLOCKED_TAGS.has(element.tagName) && isVisible(element))
      .map((element) => ({ element, score: scoreElement(element) }))
      .sort((a, b) => b.score - a.score);

    const best = candidates[0]?.element || document.body;
    return normalizeText(best.innerText || document.body.innerText || "");
  }

  function getLabelText(input) {
    const labels = Array.from(input.labels || []).map((label) => normalizeText(label.innerText || ""));
    if (labels.length > 0) return labels.join(" ");

    const ariaLabel = input.getAttribute("aria-label");
    if (ariaLabel) return ariaLabel;

    const labelledBy = input.getAttribute("aria-labelledby");
    if (labelledBy) {
      return labelledBy
        .split(/\s+/)
        .map((id) => document.getElementById(id)?.innerText || "")
        .filter(Boolean)
        .join(" ");
    }

    const wrapper = input.closest("label, .field, .form-group, .input, .control, li, p, div");
    if (!wrapper) return "";

    const wrapperText = normalizeText(wrapper.innerText || "");
    return wrapperText.length > 120 ? wrapperText.slice(0, 120) : wrapperText;
  }

  function getFormFields() {
    return Array.from(document.querySelectorAll("input, textarea, select"))
      .filter((input) => isVisible(input) && !["hidden", "submit", "button", "reset", "image"].includes(input.type))
      .map((input) => ({
        tag: input.tagName.toLowerCase(),
        type: input.getAttribute("type") || input.tagName.toLowerCase(),
        name: input.getAttribute("name") || "",
        id: input.id || "",
        autocomplete: input.getAttribute("autocomplete") || "",
        placeholder: input.getAttribute("placeholder") || "",
        label: getLabelText(input),
        required: Boolean(input.required || input.getAttribute("aria-required") === "true")
      }))
      .slice(0, 120);
  }

  function getStorageSnapshot() {
    return {
      localStorageKeys: getStorageKeys(window.localStorage),
      sessionStorageKeys: getStorageKeys(window.sessionStorage)
    };
  }

  function getStorageKeys(storage) {
    try {
      return Array.from({ length: storage.length }, (_value, index) => storage.key(index)).filter(Boolean).slice(0, 80);
    } catch {
      return [];
    }
  }

  function getConsentSnapshot() {
    const containers = Array.from(
      document.querySelectorAll("[id], [class], [role='dialog'], [aria-label], section, aside, footer")
    )
      .filter((element) => isVisible(element) && looksLikeConsentElement(element))
      .map((element) => {
        const text = normalizeText(element.innerText || "");
        return {
          text: text.slice(0, 600),
          buttons: getConsentButtons(element),
          toggles: getConsentToggles(element)
        };
      })
      .filter((item) => item.text || item.buttons.length || item.toggles.length)
      .slice(0, 8);

    return {
      detected: containers.length > 0,
      containers
    };
  }

  function getJurisdictionSignals() {
    return {
      language: navigator.language || "",
      languages: Array.from(navigator.languages || []),
      timeZone: Intl.DateTimeFormat().resolvedOptions().timeZone || "",
      host: location.hostname,
      url: location.href
    };
  }

  function looksLikeConsentElement(element) {
    const attrs = `${element.id || ""} ${element.className || ""} ${element.getAttribute("aria-label") || ""}`.toLowerCase();
    const text = normalizeText(element.innerText || "").toLowerCase();
    const haystack = `${attrs} ${text}`;
    return CONSENT_HINTS.some((hint) => haystack.includes(hint)) && text.length < 3000;
  }

  function getConsentButtons(container) {
    return Array.from(container.querySelectorAll("button, [role='button'], a"))
      .filter((button) => isVisible(button))
      .map((button) => normalizeText(button.innerText || button.getAttribute("aria-label") || button.getAttribute("title") || ""))
      .filter(Boolean)
      .slice(0, 16);
  }

  function getConsentToggles(container) {
    return Array.from(container.querySelectorAll("input[type='checkbox'], input[type='radio'], [role='switch']"))
      .filter((input) => isVisible(input))
      .map((input) => ({
        label: getLabelText(input),
        checked: Boolean(input.checked || input.getAttribute("aria-checked") === "true"),
        name: input.getAttribute("name") || "",
        id: input.id || ""
      }))
      .slice(0, 20);
  }

  function isKoreanUi() {
    return [navigator.language, ...(navigator.languages || [])].filter(Boolean).some((language) => language.toLowerCase().startsWith("ko"));
  }

  function normalizeRiskLevel(level) {
    return RISK_LEVELS.has(level) ? level : "unknown";
  }

  function riskIndicatorLabel(indicator) {
    const labels = isKoreanUi()
      ? {
          unknown: "분석 전",
          analyzing: "분석 중",
          low: "낮음",
          medium: "주의",
          high: "높음"
        }
      : {
          unknown: "Not analyzed",
          analyzing: "Analyzing",
          low: "Low",
          medium: "Caution",
          high: "High"
        };
    const level = normalizeRiskLevel(indicator?.level);
    const score = Number.isFinite(indicator?.score) ? ` ${Math.round(indicator.score)}` : "";
    return isKoreanUi() ? `unveily 위험도: ${labels[level]}${score}` : `unveily risk: ${labels[level]}${score}`;
  }

  function getOrCreateRiskIndicator() {
    let host = document.getElementById(RISK_INDICATOR_HOST_ID);
    if (host?.shadowRoot) return host.shadowRoot.querySelector("button");

    host = document.createElement("div");
    host.id = RISK_INDICATOR_HOST_ID;
    const shadow = host.attachShadow({ mode: "open" });
    shadow.innerHTML = `
      <style>
        :host {
          all: initial;
          position: fixed;
          right: max(18px, env(safe-area-inset-right));
          bottom: max(18px, env(safe-area-inset-bottom));
          z-index: 2147483647;
          width: 54px;
          height: 54px;
          pointer-events: none;
        }

        button {
          --risk-rgb: 107, 114, 128;
          --risk-ring-rgb: 75, 85, 99;
          width: 54px;
          height: 54px;
          border: 0;
          border-radius: 999px;
          padding: 0;
          background:
            radial-gradient(
              circle at center,
              rgba(var(--risk-rgb), 0.98) 0%,
              rgba(var(--risk-rgb), 0.8) 30%,
              rgba(var(--risk-rgb), 0.34) 54%,
              rgba(var(--risk-rgb), 0.1) 68%,
              rgba(var(--risk-rgb), 0) 80%
            );
          box-shadow:
            0 0 0 1px rgba(var(--risk-ring-rgb), 0.22),
            0 8px 26px rgba(var(--risk-ring-rgb), 0.28),
            0 0 36px rgba(var(--risk-rgb), 0.34);
          cursor: default;
          outline: none;
          pointer-events: auto;
          position: relative;
        }

        button::before {
          content: "";
          position: absolute;
          left: 50%;
          top: 50%;
          width: 13px;
          height: 13px;
          border-radius: 999px;
          background: rgba(var(--risk-rgb), 1);
          box-shadow: 0 0 14px rgba(var(--risk-rgb), 0.88);
          transform: translate(-50%, -50%);
        }

        button[data-risk-level="analyzing"] {
          --risk-rgb: 37, 99, 235;
          --risk-ring-rgb: 29, 78, 216;
        }

        button[data-risk-level="low"] {
          --risk-rgb: 22, 163, 74;
          --risk-ring-rgb: 21, 128, 61;
        }

        button[data-risk-level="medium"] {
          --risk-rgb: 245, 158, 11;
          --risk-ring-rgb: 217, 119, 6;
        }

        button[data-risk-level="high"] {
          --risk-rgb: 220, 38, 38;
          --risk-ring-rgb: 185, 28, 28;
        }

        button:focus-visible {
          box-shadow:
            0 0 0 3px rgba(255, 255, 255, 0.92),
            0 0 0 5px rgba(var(--risk-ring-rgb), 0.8),
            0 8px 26px rgba(var(--risk-ring-rgb), 0.28),
            0 0 36px rgba(var(--risk-rgb), 0.34);
        }
      </style>
      <button type="button" data-risk-level="unknown" aria-label="unveily risk: Not analyzed" title="unveily risk: Not analyzed"></button>
    `;
    document.documentElement.appendChild(host);
    return shadow.querySelector("button");
  }

  function applyRiskIndicator(indicator = {}) {
    const button = getOrCreateRiskIndicator();
    if (!button) return;

    const level = normalizeRiskLevel(indicator.level);
    const label = riskIndicatorLabel({ ...indicator, level });
    button.dataset.riskLevel = level;
    button.setAttribute("aria-label", label);
    button.setAttribute("title", label);
  }

  function riskScanFingerprint(text) {
    let hash = 0;
    for (let index = 0; index < text.length; index += 64) {
      hash = (hash * 31 + text.charCodeAt(index)) >>> 0;
    }
    return `${location.href}|${text.length}|${hash}`;
  }

  function sendRuntimeMessage(message, callback) {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) return;
        callback?.(response);
      });
    } catch {
      // The extension context can be invalidated while a page is still open.
    }
  }

  function scanPageRisk() {
    const text = getBestReadableText().slice(0, MAX_RISK_SCAN_TEXT_LENGTH);
    const fingerprint = riskScanFingerprint(text);
    if (fingerprint === lastRiskScanFingerprint) return;

    lastRiskScanFingerprint = fingerprint;
    applyRiskIndicator({ level: "analyzing" });
    sendRuntimeMessage(
      {
        type: "PAGE_RISK_SCAN",
        title: document.title,
        url: location.href,
        text
      },
      (response) => {
        if (response?.indicator) applyRiskIndicator(response.indicator);
      }
    );
  }

  function queueRiskScan(delay = RISK_SCAN_DELAY_MS) {
    window.clearTimeout(riskScanTimer);
    riskScanTimer = window.setTimeout(scanPageRisk, delay);
  }

  function initializeRiskIndicator() {
    applyRiskIndicator({ level: "unknown" });
    sendRuntimeMessage({ type: "GET_RISK_INDICATOR", url: location.href }, (response) => {
      if (response?.indicator) applyRiskIndicator(response.indicator);
    });
    queueRiskScan();
    window.addEventListener("load", () => queueRiskScan(300), { once: true });
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === "RISK_INDICATOR_UPDATE") {
      applyRiskIndicator(message.indicator);
      sendResponse({ ok: true });
      return false;
    }

    if (message?.type !== "GET_PAGE_TEXT") return false;

    const text = getBestReadableText();
    sendResponse({
      title: document.title,
      url: location.href,
      text: text.slice(0, 120000),
      forms: {
        fields: getFormFields()
      },
      storage: getStorageSnapshot(),
      consent: getConsentSnapshot(),
      jurisdictionSignals: getJurisdictionSignals()
    });

    return false;
  });

  initializeRiskIndicator();
})();
