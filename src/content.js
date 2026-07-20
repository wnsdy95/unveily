(() => {
  if (globalThis.__unveilyContentScriptLoaded) return;
  const createDomWorkContext = globalThis.__unveilyDomWorkLimits?.createContext;
  const collectMutationRoots = globalThis.__unveilyDomWorkLimits?.collectMutationRoots;
  if (typeof createDomWorkContext !== "function" || typeof collectMutationRoots !== "function") return;
  globalThis.__unveilyContentScriptLoaded = true;

  const RISK_SCAN_DELAY_MS = 900;
  const RISK_RESCAN_MIN_INTERVAL_MS = 15000;
  const MAX_POLICY_GATE_TEXT_LENGTH = 120000;
  const MAX_POLICY_AUTO_SCAN_TEXT_LENGTH = 80000;
  const MAX_READABLE_CANDIDATES = 80;
  const MAX_SCORE_TEXT_LENGTH = 20000;
  const MAX_FORM_CANDIDATES = 500;
  const MAX_CONSENT_CANDIDATES = 120;
  const MAX_DOM_NODES_VISITED = 20000;
  const MAX_CONTAINER_NODES_VISITED = 2000;
  const MAX_TEXT_NODES_VISITED = 50000;
  const MAX_MUTATION_ROOTS = 8;
  const MAX_MUTATION_RECORDS = 64;
  const MAX_MUTATION_ADDED_NODES = 64;
  const MAX_MUTATION_CONSENT_CANDIDATES = 24;
  const MAX_MUTATION_NODES_VISITED = 600;
  const MAX_MUTATION_FILTER_NODES = 4096;
  const MAX_MUTATION_FILTER_STYLES = 4096;
  const MAX_MUTATION_FILTER_TIME_MS = 25;
  const MAX_VISIBILITY_ANCESTORS = 64;
  const MAX_AUTOMATIC_SCAN_NODES = 50_000;
  const MAX_AUTOMATIC_SCAN_STYLES = 12_000;
  const MAX_AUTOMATIC_SCAN_TIME_MS = 75;
  const MAX_EXPLICIT_SCAN_NODES = 120_000;
  const MAX_EXPLICIT_SCAN_STYLES = 30_000;
  const MAX_EXPLICIT_SCAN_TIME_MS = 200;
  const MAX_CONSENT_SCAN_NODES = 30_000;
  const MAX_CONSENT_SCAN_STYLES = 8_000;
  const MAX_CONSENT_SCAN_TIME_MS = 50;
  const CONSENT_ATTRIBUTE_WATCH_MS = 30000;
  const CONSENT_CANDIDATE_SELECTOR = [
    "[role='dialog']",
    "dialog",
    "aside[id*='cookie' i]",
    "aside[class*='cookie' i]",
    "footer[id*='cookie' i]",
    "footer[class*='cookie' i]",
    "[aria-label*='cookie' i]",
    "[aria-label*='consent' i]",
    "[id*='cookie' i]",
    "[class*='cookie' i]",
    "[id*='consent' i]",
    "[class*='consent' i]",
    "[id*='cmp' i]",
    "[class*='cmp' i]",
    "[id*='onetrust' i]",
    "[class*='onetrust' i]",
    "[id*='cookiebot' i]",
    "[class*='cookiebot' i]",
    "[id*='didomi' i]",
    "[class*='didomi' i]",
    "[id*='quantcast' i]",
    "[class*='quantcast' i]",
    "[id*='trustarc' i]",
    "[class*='trustarc' i]",
    "[id*='gdpr' i]",
    "[class*='gdpr' i]",
    "[data-testid*='cookie' i]",
    "[data-testid*='consent' i]",
    "[data-consent]"
  ].join(", ");
  const BLOCKED_TAGS = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "SVG", "CANVAS"]);
  const USER_INPUT_TAGS = new Set(["INPUT", "TEXTAREA", "SELECT", "OPTION"]);
  const USER_INPUT_ROLES = new Set(["textbox", "searchbox", "combobox"]);
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
    "privacy choices",
    "do not sell",
    "opt out",
    "쿠키",
    "동의",
    "개인정보 선택",
    "판매 거부"
  ];
  const STRONG_POLICY_HINTS = [
    "privacy policy",
    "privacy notice",
    "terms of service",
    "terms and conditions",
    "개인정보처리방침",
    "개인정보 처리방침",
    "서비스 이용약관",
    "이용약관"
  ];
  const SUPPORTING_POLICY_HINTS = [
    "personal data",
    "personal information",
    "data controller",
    "retention period",
    "third parties",
    "수집하는 개인정보",
    "개인정보 보호책임자",
    "보유 및 이용기간",
    "제3자 제공",
    "처리 목적"
  ];
  let riskScanTimer = null;
  let riskMutationObserver = null;
  let lastRiskScanAt = 0;
  let riskNavigationGeneration = 0;
  let lastRiskScanFingerprint = "";
  let consentDetectedAt = null;
  let consentChoiceAt = null;
  let consentChoice = null;
  let detectedConsentContainer = null;
  let consentPresenceObserver = null;
  let consentPresenceTimer = null;
  let consentAttributeWatchTimer = null;
  const pendingConsentRoots = new Set();
  let automaticObservationActive = false;
  let prerenderActivationListenerRegistered = false;
  let settingsSyncSequence = 0;

  function automaticScanContext() {
    return createDomWorkContext({
      maxNodes: MAX_AUTOMATIC_SCAN_NODES,
      maxStyles: MAX_AUTOMATIC_SCAN_STYLES,
      maxElapsedMs: MAX_AUTOMATIC_SCAN_TIME_MS
    });
  }

  function explicitScanContext() {
    return createDomWorkContext({
      maxNodes: MAX_EXPLICIT_SCAN_NODES,
      maxStyles: MAX_EXPLICIT_SCAN_STYLES,
      maxElapsedMs: MAX_EXPLICIT_SCAN_TIME_MS
    });
  }

  function consentScanContext() {
    return createDomWorkContext({
      maxNodes: MAX_CONSENT_SCAN_NODES,
      maxStyles: MAX_CONSENT_SCAN_STYLES,
      maxElapsedMs: MAX_CONSENT_SCAN_TIME_MS
    });
  }

  function mutationFilterContext() {
    return createDomWorkContext({
      maxNodes: MAX_MUTATION_FILTER_NODES,
      maxStyles: MAX_MUTATION_FILTER_STYLES,
      maxElapsedMs: MAX_MUTATION_FILTER_TIME_MS
    });
  }

  function takeDomNode(context) {
    return context?.budget?.takeNode() !== false;
  }

  function takeStyleRead(context) {
    return context?.budget?.takeStyle() !== false;
  }

  function domWorkAvailable(context) {
    return context?.budget?.check() !== false;
  }

  function shadowIncludingParentElement(element) {
    if (!(element instanceof Element)) return null;
    if (element.parentElement instanceof Element) return element.parentElement;
    try {
      const root = element.getRootNode?.();
      return root?.host instanceof Element ? root.host : null;
    } catch {
      return null;
    }
  }

  function documentIsEditable() {
    try {
      return String(document.designMode || "").toLowerCase() === "on";
    } catch {
      return true;
    }
  }

  function styleAllowsUserEditing(style) {
    return [style?.userModify, style?.webkitUserModify].some((value) =>
      String(value || "").toLowerCase().startsWith("read-write")
    );
  }

  function elementMarksUserInput(element, context = null) {
    if (!(element instanceof Element)) return false;
    try {
      if (element.isContentEditable === true) return true;
      if (USER_INPUT_TAGS.has(element.tagName)) return true;
      const contentEditable = element.getAttribute("contenteditable");
      if (contentEditable !== null && String(contentEditable).toLowerCase() !== "false") return true;
      const roles = String(element.getAttribute("role") || "")
        .toLowerCase()
        .split(/\s+/)
        .filter(Boolean);
      if (roles.some((role) => USER_INPUT_ROLES.has(role))) return true;
      return context?.userInputStyleCache?.get(element) === true;
    } catch {
      return true;
    }
  }

  function isUserInputSubtree(node, context = null) {
    if (documentIsEditable()) return true;
    let current = node instanceof Element ? node : node?.parentElement;
    if (!(current instanceof Element)) return false;
    const cache = context?.userInputCache || null;
    if (cache?.has(current)) return cache.get(current);

    const traversed = [];
    let excluded = false;
    let depth = 0;
    while (current && depth < MAX_VISIBILITY_ANCESTORS) {
      if (cache?.has(current)) {
        excluded = cache.get(current);
        current = null;
        break;
      }
      traversed.push(current);
      if (elementMarksUserInput(current, context)) {
        excluded = true;
        current = null;
        break;
      }
      current = shadowIncludingParentElement(current);
      depth += 1;
    }
    if (current) excluded = true;
    if (cache) {
      for (const element of traversed) cache.set(element, excluded);
    }
    return excluded;
  }

  function isVisible(element, context) {
    return isElementTreeVisible(element, context);
  }

  function isElementTreeVisible(element, context = null) {
    if (!(element instanceof Element)) return false;
    if (!domWorkAvailable(context)) return false;
    const visibilityCache = context?.visibilityCache || null;
    const ancestors = [];
    let current = element;
    let visible = true;
    let reachedKnownAncestor = false;

    while (current && ancestors.length < MAX_VISIBILITY_ANCESTORS) {
      if (visibilityCache?.has(current)) {
        visible = visibilityCache.get(current);
        reachedKnownAncestor = true;
        break;
      }
      if (!takeDomNode(context) || !takeStyleRead(context)) {
        visible = false;
        break;
      }
      ancestors.push(current);
      try {
        const style = window.getComputedStyle(current);
        context?.userInputStyleCache?.set(current, styleAllowsUserEditing(style));
        if (
          current.hidden ||
          String(current.getAttribute("aria-hidden") || "").toLowerCase() === "true" ||
          ["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE", "SVG", "CANVAS"].includes(current.tagName) ||
          style.display === "none" ||
          ["hidden", "collapse"].includes(style.visibility) ||
          Number.parseFloat(style.opacity) === 0 ||
          style.contentVisibility === "hidden"
        ) {
          visible = false;
          break;
        }
      } catch {
        visible = false;
        break;
      }
      current = shadowIncludingParentElement(current);
    }

    if (current && !reachedKnownAncestor && ancestors.length >= MAX_VISIBILITY_ANCESTORS) visible = false;
    if (visibilityCache) {
      for (const ancestor of ancestors) visibilityCache.set(ancestor, visible);
    }
    return visible;
  }

  function normalizeText(text) {
    return text
      .replace(/\u00a0/g, " ")
      .replace(/[ \t]+/g, " ")
      .replace(/\n{3,}/g, "\n\n")
      .trim();
  }

  function elementAttributeSummary(element, maxLength = 600) {
    if (!(element instanceof Element)) return "";
    try {
      return ["id", "class", "aria-label", "title"]
        .map((name) => String(element.getAttribute(name) || "").slice(0, 200))
        .join(" ")
        .slice(0, Math.max(0, Math.min(Number(maxLength) || 0, 1200)));
    } catch {
      return "";
    }
  }

  function boundedClosest(element, selector, context, maxAncestors = MAX_VISIBILITY_ANCESTORS) {
    if (!(element instanceof Element) || !domWorkAvailable(context)) return null;
    let selectorCache = context?.closestCache?.get(element);
    if (selectorCache?.has(selector)) return selectorCache.get(selector);

    let match = null;
    let current = element;
    for (let depth = 0; current && depth < maxAncestors; depth += 1) {
      if (!takeDomNode(context)) break;
      if (current.matches(selector)) {
        match = current;
        break;
      }
      current = shadowIncludingParentElement(current);
    }

    if (context?.closestCache) {
      if (!selectorCache) {
        selectorCache = new Map();
        context.closestCache.set(element, selectorCache);
      }
      selectorCache.set(selector, match);
    }
    return match;
  }

  function boundedElements(
    root,
    selector,
    maxMatches,
    maxVisited = MAX_DOM_NODES_VISITED,
    context = null
  ) {
    const start = root instanceof Document ? root.documentElement : root;
    if (
      !(start instanceof Element) ||
      maxMatches <= 0 ||
      maxVisited <= 0 ||
      !domWorkAvailable(context)
    ) {
      return [];
    }

    const matches = [];
    const walker = document.createTreeWalker(start, NodeFilter.SHOW_ALL);
    let node = start;
    let visited = 0;
    while (node && visited < maxVisited && matches.length < maxMatches) {
      if (!takeDomNode(context)) break;
      visited += 1;
      if (node instanceof Element && node.matches(selector)) matches.push(node);
      node = walker.nextNode();
    }
    return matches;
  }

  function cachedTextResult(context, root, maxLength, maxVisited) {
    const cache = context?.textCache?.get(root);
    const exact = cache?.get(`${maxLength}:${maxVisited}`);
    if (exact) return exact;
    if (!cache) return null;
    for (const [, cached] of cache) {
      if (cached.complete && cached.text.length <= maxLength) return cached;
    }
    return null;
  }

  function rememberTextResult(context, root, maxLength, maxVisited, result) {
    if (!context?.textCache) return;
    let cache = context.textCache.get(root);
    if (!cache) {
      cache = new Map();
      context.textCache.set(root, cache);
    }
    cache.set(`${maxLength}:${maxVisited}`, result);
  }

  function boundedTextResult(root, maxLength, maxVisited = MAX_TEXT_NODES_VISITED, context = null) {
    if (
      !(root instanceof Element) ||
      maxLength <= 0 ||
      maxVisited <= 0 ||
      !domWorkAvailable(context)
    ) {
      return { text: "", complete: false };
    }
    const cached = cachedTextResult(context, root, maxLength, maxVisited);
    if (cached) return cached;
    const chunks = [];
    let length = 0;
    let visited = 0;
    let lastBlock = null;
    let textTruncated = false;
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ALL);
    let node = walker.nextNode();
    while (node && visited < maxVisited && length < maxLength) {
      if (!takeDomNode(context)) break;
      visited += 1;
      if (node.nodeType !== 3) {
        node = walker.nextNode();
        continue;
      }
      const parent = node.parentElement;
      if (isElementTreeVisible(parent, context) && !isUserInputSubtree(parent, context)) {
        const block = boundedClosest(
          parent,
          "p, li, dt, dd, blockquote, pre, h1, h2, h3, h4, h5, h6, div, main, section, article",
          context
        );
        const separator = chunks.length > 0 ? (block && block !== lastBlock ? "\n\n" : " ") : "";
        const remaining = Math.max(0, maxLength - length - separator.length);
        const nodeValue = typeof node.nodeValue === "string" ? node.nodeValue : "";
        if (nodeValue.length > remaining) textTruncated = true;
        const nodeText = nodeValue.slice(0, remaining);
        const chunk = `${separator}${nodeText}`.slice(0, maxLength - length);
        chunks.push(chunk);
        length += chunk.length;
        lastBlock = block;
      }
      node = walker.nextNode();
    }
    const result = Object.freeze({
      text: normalizeText(chunks.join("")),
      complete: !node && !textTruncated && domWorkAvailable(context)
    });
    rememberTextResult(context, root, maxLength, maxVisited, result);
    return result;
  }

  function boundedText(root, maxLength, maxVisited = MAX_TEXT_NODES_VISITED, context = null) {
    return boundedTextResult(root, maxLength, maxVisited, context).text;
  }

  function boundedPageUrl() {
    try {
      const parsed = new URL(String(location.href || ""));
      if (!["http:", "https:"].includes(parsed.protocol)) return "";
      parsed.username = "";
      parsed.password = "";
      parsed.search = "";
      parsed.hash = "";
      return parsed.href.length <= 4096 ? parsed.href : parsed.origin;
    } catch {
      return "";
    }
  }

  function scoreElement(element, context) {
    const textResult = boundedTextResult(
      element,
      MAX_SCORE_TEXT_LENGTH,
      MAX_CONTAINER_NODES_VISITED,
      context
    );
    const text = textResult.text;
    if (text.length < 120) return { score: 0, textResult };

    const attrs = elementAttributeSummary(element).toLowerCase();
    const hintScore = POLICY_HINTS.reduce((score, hint) => score + (attrs.includes(hint) ? 3 : 0), 0);
    const textScore = POLICY_HINTS.reduce((score, hint) => score + (text.toLowerCase().includes(hint) ? 1 : 0), 0);

    return { score: Math.min(text.length / 1000, 20) + hintScore + textScore, textResult };
  }

  function getBestReadableText(context = explicitScanContext()) {
    const candidates = boundedElements(
      document,
      "main, article, section, [role='main'], body",
      MAX_READABLE_CANDIDATES,
      MAX_DOM_NODES_VISITED,
      context
    )
      .filter((element) => !BLOCKED_TAGS.has(element.tagName) && isVisible(element, context))
      .map((element) => ({ element, ...scoreElement(element, context) }))
      .sort((a, b) => b.score - a.score);

    const bestCandidate = candidates[0];
    const best = bestCandidate?.element || document.body;
    if (bestCandidate?.textResult.complete) return bestCandidate.textResult.text;
    return boundedText(
      best || document.documentElement,
      MAX_POLICY_GATE_TEXT_LENGTH,
      MAX_TEXT_NODES_VISITED,
      context
    );
  }

  function getLabelText(input, context) {
    const labels = Array.from(input.labels || [])
      .slice(0, 8)
      .map((label) => boundedText(label, 240, 200, context));
    if (labels.length > 0) return labels.join(" ").slice(0, 240);

    const ariaLabel = input.getAttribute("aria-label");
    if (ariaLabel) return ariaLabel.slice(0, 240);

    const labelledBy = input.getAttribute("aria-labelledby");
    if (labelledBy) {
      return labelledBy
        .split(/\s+/)
        .slice(0, 8)
        .map((id) => boundedText(document.getElementById(id), 240, 200, context))
        .filter(Boolean)
        .join(" ")
        .slice(0, 240);
    }

    const wrapper = boundedClosest(
      input,
      "label, .field, .form-group, .input, .control, li, p, div",
      context
    );
    if (!wrapper) return "";

    const wrapperText = boundedText(wrapper, 240, 400, context);
    return wrapperText.length > 120 ? wrapperText.slice(0, 120) : wrapperText;
  }

  function getFormFields(context = explicitScanContext()) {
    return boundedElements(
      document,
      "input, textarea, select",
      MAX_FORM_CANDIDATES,
      MAX_DOM_NODES_VISITED,
      context
    )
      .filter(
        (input) =>
          isVisible(input, context) &&
          !["hidden", "submit", "button", "reset", "image"].includes(input.type)
      )
      .map((input) => ({
        tag: input.tagName.toLowerCase(),
        type: String(input.getAttribute("type") || input.tagName.toLowerCase()).slice(0, 40),
        name: String(input.getAttribute("name") || "").slice(0, 160),
        id: String(input.id || "").slice(0, 160),
        autocomplete: String(input.getAttribute("autocomplete") || "").slice(0, 160),
        placeholder: String(input.getAttribute("placeholder") || "").slice(0, 240),
        label: getLabelText(input, context),
        required: Boolean(input.required || input.getAttribute("aria-required") === "true")
      }))
      .slice(0, 120);
  }

  function getStorageSnapshot() {
    return {
      localStorageKeys: getWindowStorageKeys("localStorage"),
      sessionStorageKeys: getWindowStorageKeys("sessionStorage")
    };
  }

  function getWindowStorageKeys(storageName) {
    try {
      return getStorageKeys(window[storageName]);
    } catch {
      return [];
    }
  }

  function getStorageKeys(storage) {
    try {
      const keys = [];
      const length = Math.min(Number(storage.length) || 0, 80);
      for (let index = 0; index < length; index += 1) {
        const key = storage.key(index);
        if (key) keys.push(String(key).slice(0, 160));
      }
      return keys;
    } catch {
      return [];
    }
  }

  function getConsentSnapshot(context = consentScanContext()) {
    const containers = [];
    const candidates = boundedElements(
      document,
      CONSENT_CANDIDATE_SELECTOR,
      MAX_CONSENT_CANDIDATES,
      MAX_DOM_NODES_VISITED,
      context
    );
    if (detectedConsentContainer?.isConnected && !candidates.includes(detectedConsentContainer)) {
      candidates.unshift(detectedConsentContainer);
      if (candidates.length > MAX_CONSENT_CANDIDATES) candidates.pop();
    } else if (detectedConsentContainer && !detectedConsentContainer.isConnected) {
      detectedConsentContainer = null;
    }
    for (const element of candidates) {
      if (!isVisible(element, context) || !looksLikeConsentElement(element, context)) continue;
      const text = boundedText(element, 3001, MAX_CONTAINER_NODES_VISITED, context);
      const item = {
        text: text.slice(0, 600),
        buttons: getConsentButtons(element, context),
        toggles: getConsentToggles(element, context)
      };
      if (item.text || item.buttons.length || item.toggles.length) containers.push(item);
      if (!detectedConsentContainer) detectedConsentContainer = element;
      if (containers.length >= 8) break;
    }

    if (containers.length > 0 && !consentDetectedAt) {
      consentDetectedAt = new Date().toISOString();
      stopConsentPresenceObservation();
    }

    return {
      detected: Boolean(consentDetectedAt || containers.length > 0),
      detectedAt: consentDetectedAt,
      choiceAt: consentChoice?.at || consentChoiceAt,
      choiceKind: consentChoice?.kind || null,
      choice: consentChoice,
      containers
    };
  }

  function getJurisdictionSignals() {
    return {
      language: String(navigator.language || "").slice(0, 40),
      languages: Array.from(navigator.languages || []).slice(0, 20).map((language) => String(language).slice(0, 40)),
      timeZone: String(Intl.DateTimeFormat().resolvedOptions().timeZone || "").slice(0, 100),
      host: String(location.hostname || "").slice(0, 255),
      url: boundedPageUrl()
    };
  }

  function looksLikeConsentElement(element, context) {
    if (!domWorkAvailable(context)) return false;
    const attrs = elementAttributeSummary(element).toLowerCase();
    const text = boundedText(element, 3001, MAX_CONTAINER_NODES_VISITED, context).toLowerCase();
    const haystack = `${attrs} ${text}`;
    const hasConsentLanguage = CONSENT_HINTS.some((hint) => haystack.includes(hint));
    const hasManagerMarker = /(?:^|[^a-z])(?:cmp|cookiebot|didomi|onetrust|quantcast|trustarc)(?:$|[^a-z])/.test(attrs);
    const hasDialogSemantics = element.getAttribute("role") === "dialog" || element.tagName === "DIALOG";
    const hasChoiceControl = boundedElements(
      element,
      "button, [role='button'], a",
      24,
      600,
      context
    ).some((control) => Boolean(consentChoiceKind(control, context)));
    if (!domWorkAvailable(context)) return false;
    return (
      text.length < 3000 &&
      (hasConsentLanguage || hasManagerMarker) &&
      (hasChoiceControl || hasDialogSemantics || hasManagerMarker)
    );
  }

  function findConsentContainer(target, context) {
    if (!(target instanceof Element)) return null;

    let candidate = target;
    for (let depth = 0; candidate && depth < 8; depth += 1, candidate = candidate.parentElement) {
      if (!takeDomNode(context)) return null;
      if (looksLikeConsentElement(candidate, context)) return candidate;
    }
    return null;
  }

  function recordConsentChoice(event) {
    if (!event.isTrusted || !(event.target instanceof Element)) return;
    const context = consentScanContext();
    const control = boundedClosest(event.target, "button, [role='button'], a", context, 16);
    const kind = control && consentChoiceKind(control, context);
    if (!control || !kind) return;
    const container = findConsentContainer(control, context);
    if (!container) return;
    const at = new Date().toISOString();
    if (!consentDetectedAt) consentDetectedAt = at;
    detectedConsentContainer = container;
    stopConsentPresenceObservation();
    consentChoiceAt = at;
    consentChoice = {
      kind,
      at,
      toggles: kind === "save_preferences" ? getConsentToggles(container, context) : []
    };
  }

  function consentChoiceKind(control, context) {
    const controlText = normalizeText(
      `${boundedText(control, 240, 200, context)} ${elementAttributeSummary(control, 400)}`
    ).toLowerCase();
    if (!controlText) return "";
    if (
      /\b(?:reject|reject all|decline|decline all|deny|deny all|refuse|essential only|necessary only|only necessary|do not accept|opt[ -]?out)\b|(?:모두|전체)?\s*(?:거부|거절)|필수만|필수\s*(?:쿠키)?만/.test(
        controlText
      )
    ) {
      return "reject_all";
    }
    if (
      /\b(?:accept all|allow all|agree all|accept|agree|allow)\b|(?:모두|전체|전부)\s*(?:허용|동의|수락)|수락|허용|^동의$/.test(
        controlText
      )
    ) {
      return "accept_all";
    }
    if (
      /\b(?:save|apply)\s+(?:my\s+)?(?:preferences|settings|choices?|selections?)\b|\bconfirm\s+(?:my\s+)?(?:preferences|settings|choices?|selections?)\b|(?:설정|선택)\s*(?:저장|적용)|저장\s*(?:및\s*)?(?:닫기|종료)?$/.test(
        controlText
      )
    ) {
      return "save_preferences";
    }
    return "";
  }

  function consentCandidates(root, maxMatches, maxVisited, context) {
    const candidates = boundedElements(
      root,
      CONSENT_CANDIDATE_SELECTOR,
      maxMatches,
      maxVisited,
      context
    );
    if (root instanceof Element && !candidates.includes(root)) candidates.unshift(root);
    return candidates.slice(0, maxMatches);
  }

  function markConsentPresence(roots = [document]) {
    if (consentDetectedAt || !automaticObservationActive) return Boolean(consentDetectedAt);
    const context = consentScanContext();
    let detectedContainer = null;
    for (const root of roots) {
      detectedContainer = consentCandidates(
        root,
        root === document ? MAX_CONSENT_CANDIDATES : MAX_MUTATION_CONSENT_CANDIDATES,
        root === document ? MAX_DOM_NODES_VISITED : MAX_MUTATION_NODES_VISITED,
        context
      ).find(
        (element) =>
          isVisible(element, context) && looksLikeConsentElement(element, context)
      );
      if (detectedContainer) break;
      if (!domWorkAvailable(context)) break;
    }
    if (detectedContainer) {
      detectedConsentContainer = detectedContainer;
      consentDetectedAt = new Date().toISOString();
      stopConsentPresenceObservation();
    }
    return Boolean(detectedContainer);
  }

  function queueConsentPresenceCheck(delay = 200, roots = []) {
    if (!automaticObservationActive || consentDetectedAt) return;
    for (const root of roots) {
      if (pendingConsentRoots.size >= MAX_MUTATION_ROOTS) break;
      if (root instanceof Element) pendingConsentRoots.add(root);
    }
    window.clearTimeout(consentPresenceTimer);
    consentPresenceTimer = window.setTimeout(() => {
      const pendingRoots = Array.from(pendingConsentRoots);
      pendingConsentRoots.clear();
      markConsentPresence(pendingRoots.length > 0 ? pendingRoots : [document]);
    }, delay);
  }

  function mutationsOnlyAddOrRemoveCompanionHosts(records) {
    const ownedHosts = globalThis.__unveilyCompanionOverlayOwnedHosts;
    if (!ownedHosts || !records || records.length === 0) return false;
    for (const record of records) {
      if (record?.type !== "childList") return false;
      const changedNodes = [...(record.addedNodes || []), ...(record.removedNodes || [])];
      if (changedNodes.length === 0 || changedNodes.some((node) => !ownedHosts.has(node))) {
        return false;
      }
    }
    return true;
  }

  function startConsentPresenceObservation() {
    if (!automaticObservationActive || document.visibilityState === "hidden") return;
    if (markConsentPresence() || consentPresenceObserver || !document.documentElement) return;
    consentPresenceObserver = new MutationObserver((records) => {
      if (mutationsOnlyAddOrRemoveCompanionHosts(records)) return;
      const roots = collectMutationRoots(records, (node) => node instanceof Element, {
        maxRecords: MAX_MUTATION_RECORDS,
        maxAddedNodes: MAX_MUTATION_ADDED_NODES,
        maxRoots: MAX_MUTATION_ROOTS
      });
      if (roots.length > 0) queueConsentPresenceCheck(200, roots);
    });
    observeConsentMutations(true);
    window.clearTimeout(consentAttributeWatchTimer);
    consentAttributeWatchTimer = window.setTimeout(() => {
      consentAttributeWatchTimer = null;
      if (!automaticObservationActive || consentDetectedAt || !consentPresenceObserver) return;
      observeConsentMutations(false);
    }, CONSENT_ATTRIBUTE_WATCH_MS);
  }

  function stopConsentPresenceObservation() {
    consentPresenceObserver?.disconnect();
    consentPresenceObserver = null;
    window.clearTimeout(consentAttributeWatchTimer);
    consentAttributeWatchTimer = null;
  }

  function observeConsentMutations(includeAttributes) {
    if (!consentPresenceObserver || !document.documentElement) return;
    consentPresenceObserver.disconnect();
    consentPresenceObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
      ...(includeAttributes
        ? {
            attributes: true,
            attributeFilter: ["class", "style", "hidden", "aria-hidden"]
          }
        : {})
    });
  }

  function getConsentButtons(container, context) {
    return boundedElements(
      container,
      "button, [role='button'], a",
      100,
      MAX_CONTAINER_NODES_VISITED,
      context
    )
      .filter((button) => isVisible(button, context))
      .map((button) =>
        normalizeText(
          `${boundedText(button, 240, 200, context)} ${button.getAttribute("aria-label") || ""} ${button.getAttribute("title") || ""}`.slice(0, 240)
        )
      )
      .filter(Boolean)
      .slice(0, 16);
  }

  function getConsentToggles(container, context) {
    return boundedElements(
      container,
      "input[type='checkbox'], input[type='radio'], [role='switch']",
      100,
      MAX_CONTAINER_NODES_VISITED,
      context
    )
      .filter((input) => isVisible(input, context))
      .map((input) => ({
        label: getLabelText(input, context),
        checked: Boolean(input.checked || input.getAttribute("aria-checked") === "true"),
        name: String(input.getAttribute("name") || "").slice(0, 160),
        id: String(input.id || "").slice(0, 160)
      }))
      .slice(0, 20);
  }

  function riskScanFingerprint(text) {
    let hash = 0x811c9dc5;
    for (let index = 0; index < text.length; index += 1) {
      hash = Math.imul(hash ^ text.charCodeAt(index), 0x01000193) >>> 0;
    }
    return `${riskNavigationGeneration}|${text.length}|${hash.toString(16).padStart(8, "0")}`;
  }

  function countHints(haystack, hints) {
    return hints.reduce((count, hint) => count + (haystack.includes(hint) ? 1 : 0), 0);
  }

  function policyHeadingHintCount(context) {
    if (Number.isInteger(context?.headingHintCount)) return context.headingHintCount;
    const count = boundedElements(
      document,
      "h1, h2, h3",
      80,
      MAX_DOM_NODES_VISITED,
      context
    ).reduce((total, heading) => {
      const headingText = boundedText(heading, 500, 300, context).toLowerCase();
      return total + (countHints(headingText, STRONG_POLICY_HINTS) > 0 ? 1 : 0);
    }, 0);
    if (context) context.headingHintCount = count;
    return count;
  }

  function assessPolicyLikelihood(text, context) {
    const normalizedText = text.toLowerCase();
    let decodedPath = String(location.pathname || "").slice(0, 4096).toLowerCase();
    try {
      decodedPath = decodeURIComponent(decodedPath);
    } catch {
      // A malformed path is still safe to score in its encoded form.
    }

    const title = String(document.title || "").slice(0, 512).toLowerCase();
    const pathHintCount = countHints(decodedPath, STRONG_POLICY_HINTS.concat(["privacy", "terms", "policy", "약관", "개인정보"]));
    const titleHintCount = countHints(title, STRONG_POLICY_HINTS);
    const leadingPolicyHintCount = countHints(normalizedText.slice(0, 800), STRONG_POLICY_HINTS);
    const strongTextHintCount = countHints(normalizedText, STRONG_POLICY_HINTS);
    const supportingHintCount = countHints(normalizedText, SUPPORTING_POLICY_HINTS);
    const headingHintCount = policyHeadingHintCount(context);

    const score =
      Math.min(pathHintCount, 1) * 4 +
      Math.min(titleHintCount, 1) * 3 +
      Math.min(leadingPolicyHintCount, 1) * 4 +
      Math.min(strongTextHintCount, 3) * 1.5 +
      Math.min(supportingHintCount, 4) * 0.75 +
      Math.min(headingHintCount, 2) * 1.5 +
      (text.length >= 1200 ? 0.5 : 0);
    const confidence = Math.round(Math.min(0.99, score / 10) * 100) / 100;

    return {
      policyLike:
        text.length >= 600 &&
        score >= 4 &&
        (titleHintCount > 0 ||
          leadingPolicyHintCount > 0 ||
          supportingHintCount >= 2 ||
          headingHintCount > 0),
      confidence
    };
  }

  function sendRuntimeMessage(message, callback) {
    try {
      chrome.runtime.sendMessage(message, (response) => {
        if (chrome.runtime.lastError) {
          callback?.(null);
          return;
        }
        callback?.(response);
      });
    } catch {
      // The extension context can be invalidated while a page is still open.
      callback?.(null);
    }
  }

  function scanPageRisk() {
    riskScanTimer = null;
    if (!automaticObservationActive || document.visibilityState === "hidden") return;
    lastRiskScanAt = Date.now();
    const context = automaticScanContext();
    const preflightText = boundedText(
      document.body || document.documentElement,
      12000,
      5000,
      context
    );
    let text = preflightText;
    let policyAssessment = assessPolicyLikelihood(preflightText, context);
    if (policyAssessment.policyLike) {
      text = getBestReadableText(context).slice(0, MAX_POLICY_GATE_TEXT_LENGTH);
      policyAssessment = assessPolicyLikelihood(text, context);
    }
    if (context.budget.exhausted) {
      text = "";
      policyAssessment = { policyLike: false, confidence: 0 };
    }
    const fingerprint = riskScanFingerprint(text);
    if (fingerprint === lastRiskScanFingerprint) return;

    lastRiskScanFingerprint = fingerprint;
    sendRuntimeMessage(
      {
        type: "PAGE_RISK_SCAN",
        policyLike: policyAssessment.policyLike,
        policyConfidence: policyAssessment.confidence,
        textLength: text.length,
        ...(policyAssessment.policyLike ? { text: text.slice(0, MAX_POLICY_AUTO_SCAN_TEXT_LENGTH) } : {})
      }
    );
  }

  function queueRiskScan(delay = RISK_SCAN_DELAY_MS) {
    if (!automaticObservationActive || riskScanTimer || document.visibilityState === "hidden") return;
    const minimumWait = Math.max(0, lastRiskScanAt + RISK_RESCAN_MIN_INTERVAL_MS - Date.now());
    riskScanTimer = window.setTimeout(scanPageRisk, Math.max(delay, minimumWait));
  }

  function mutationsOnlyAffectUserInput(records) {
    if (!records || records.length === 0 || records.length > MAX_MUTATION_RECORDS) return false;
    const context = mutationFilterContext();
    for (const record of records) {
      const target = record?.target instanceof Element ? record.target : record?.target?.parentElement;
      if (!(target instanceof Element)) return false;
      // Populate the bounded computed-style cache so CSS user-modify editors are covered
      // without adding unbudgeted style reads to the mutation hot path.
      isElementTreeVisible(target, context);
      if (!domWorkAvailable(context) || !isUserInputSubtree(target, context)) return false;
    }
    return true;
  }

  function startRiskMutationObservation() {
    if (
      !automaticObservationActive ||
      document.visibilityState === "hidden" ||
      riskMutationObserver ||
      !document.documentElement
    ) {
      return;
    }
    riskMutationObserver = new MutationObserver((records) => {
      if (mutationsOnlyAddOrRemoveCompanionHosts(records)) return;
      if (!mutationsOnlyAffectUserInput(records)) queueRiskScan();
    });
    riskMutationObserver.observe(document.documentElement, {
      childList: true,
      characterData: true,
      subtree: true
    });
  }

  function stopRiskMutationObservation() {
    riskMutationObserver?.disconnect();
    riskMutationObserver = null;
  }

  function suspendAutomaticDomWork() {
    window.clearTimeout(riskScanTimer);
    window.clearTimeout(consentPresenceTimer);
    window.clearTimeout(consentAttributeWatchTimer);
    riskScanTimer = null;
    consentPresenceTimer = null;
    consentAttributeWatchTimer = null;
    stopConsentPresenceObservation();
    stopRiskMutationObservation();
    pendingConsentRoots.clear();
  }

  function resumeAutomaticDomWork(delay = 300) {
    if (!automaticObservationActive || document.visibilityState === "hidden") return;
    startConsentPresenceObservation();
    startRiskMutationObservation();
    queueRiskScan(delay);
  }

  function handleVisibilityChange() {
    if (!automaticObservationActive) return;
    if (document.visibilityState === "hidden") {
      suspendAutomaticDomWork();
      return;
    }
    resumeAutomaticDomWork();
  }

  function automaticObservationAllowed(settings) {
    return settings?.enabled === true && settings?.allowed === true;
  }

  function handlePrerenderingChange(event) {
    if (event?.isTrusted !== true || document.prerendering === true) return;
    document.removeEventListener("prerenderingchange", handlePrerenderingChange);
    prerenderActivationListenerRegistered = false;
    initializeAutomaticObservation();
  }

  function startAutomaticObservation() {
    if (automaticObservationActive || document.prerendering === true) return;
    automaticObservationActive = true;
    document.addEventListener("click", recordConsentChoice, true);
    document.addEventListener("visibilitychange", handleVisibilityChange);
    resumeAutomaticDomWork(RISK_SCAN_DELAY_MS);
    if (document.readyState !== "complete") {
      window.addEventListener("load", () => automaticObservationActive && queueRiskScan(300), {
        once: true
      });
    }
  }

  function stopAutomaticObservation() {
    automaticObservationActive = false;
    suspendAutomaticDomWork();
    document.removeEventListener("click", recordConsentChoice, true);
    document.removeEventListener("visibilitychange", handleVisibilityChange);
    lastRiskScanFingerprint = "";
    lastRiskScanAt = 0;
    riskNavigationGeneration = 0;
    consentDetectedAt = null;
    consentChoiceAt = null;
    consentChoice = null;
    detectedConsentContainer = null;
  }

  function handleObservationPageHide(event) {
    if (event?.isTrusted !== true || event.persisted !== true) return;
    settingsSyncSequence += 1;
    stopAutomaticObservation();
  }

  function handleObservationPageShow(event) {
    if (event?.isTrusted !== true || event.persisted !== true) return;
    settingsSyncSequence += 1;
    stopAutomaticObservation();
    initializeAutomaticObservation();
  }

  function initializeAutomaticObservation() {
    if (document.prerendering === true) {
      if (!prerenderActivationListenerRegistered) {
        prerenderActivationListenerRegistered = true;
        document.addEventListener("prerenderingchange", handlePrerenderingChange);
      }
      return;
    }
    const requestSequence = ++settingsSyncSequence;
    sendRuntimeMessage({ type: "GET_OBSERVATION_SETTINGS" }, (settingsResponse) => {
      if (requestSequence !== settingsSyncSequence || document.prerendering === true) return;
      if (settingsResponse?.ok && automaticObservationAllowed(settingsResponse.settings)) {
        startAutomaticObservation();
      } else {
        stopAutomaticObservation();
      }
    });
  }

  chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (message?.type === "RESET_CONSENT_TIMELINE") {
      consentDetectedAt = null;
      consentChoiceAt = null;
      consentChoice = null;
      detectedConsentContainer = null;
      startConsentPresenceObservation();
      sendResponse({ ok: true });
      return false;
    }

    if (message?.type === "RESET_CONSENT_CHOICE") {
      consentChoiceAt = null;
      consentChoice = null;
      sendResponse({ ok: true });
      return false;
    }

    if (message?.type === "OBSERVATION_SETTINGS_UPDATE") {
      settingsSyncSequence += 1;
      if (automaticObservationAllowed(message.settings)) startAutomaticObservation();
      else stopAutomaticObservation();
      sendResponse({ ok: true, active: automaticObservationActive });
      return false;
    }

    if (message?.type === "PAGE_CONTEXT_CHANGED") {
      if (automaticObservationActive) {
        riskNavigationGeneration += 1;
        lastRiskScanFingerprint = "";
        queueRiskScan(300);
      }
      sendResponse({ ok: automaticObservationActive });
      return false;
    }

    if (message?.type !== "GET_PAGE_TEXT") return false;

    const textContext = explicitScanContext();
    const formContext = explicitScanContext();
    const consentContext = consentScanContext();
    const text = getBestReadableText(textContext);
    sendResponse({
      title: String(document.title || "").slice(0, 512),
      url: boundedPageUrl(),
      text: text.slice(0, 120000),
      forms: {
        fields: getFormFields(formContext)
      },
      storage: getStorageSnapshot(),
      consent: getConsentSnapshot(consentContext),
      jurisdictionSignals: getJurisdictionSignals()
    });

    return false;
  });

  window.addEventListener("pagehide", handleObservationPageHide);
  window.addEventListener("pageshow", handleObservationPageShow);
  initializeAutomaticObservation();
})();
