import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const popupSource = await readFile(new URL("../src/popup.js", import.meta.url), "utf8");
const popupHtml = await readFile(new URL("../src/popup.html", import.meta.url), "utf8");
const popupCss = await readFile(new URL("../src/popup.css", import.meta.url), "utf8");

function loadPageTextRetry(chrome) {
  const start = popupSource.indexOf("function requestPageText(tabId, documentId) {");
  const end = popupSource.indexOf("\nfunction extractTextFallbackFromPage", start);
  assert.ok(start >= 0 && end > start, "page text request helpers should be present");
  const sandbox = {
    Error,
    Promise,
    chrome,
    collectPageDataByScripting: async () => ({ text: "fallback" }),
    setTimeout(callback) {
      callback();
      return 1;
    }
  };
  vm.runInNewContext(
    `${popupSource.slice(start, end)}\nglobalThis.pageTextRetry = requestPageTextWithRetry;`,
    sandbox,
    { filename: "popup-page-text-retry-runtime.js" }
  );
  return sandbox.pageTextRetry;
}

test("hides the paste panel when switching back to current page analysis", () => {
  const match = popupSource.match(/async function analyzeCurrentPage\(\) \{([\s\S]*?)\n\}\n\nasync function analyzeCookies/);

  assert.ok(match, "analyzeCurrentPage function should be present");
  assert.match(match[1], /pastePanel\.hidden\s*=\s*true;/);
  assert.ok(
    match[1].indexOf('beginAnalysis("page")') < match[1].indexOf("pastePanel.hidden = true;"),
    "page analysis should invalidate stale state before changing the panel"
  );
  assert.ok(
    match[1].indexOf("pastePanel.hidden = true;") < match[1].indexOf("try {"),
    "paste panel should be hidden before page analysis starts"
  );
});

test("invalidates stale analysis state and ignores superseded async results", () => {
  assert.match(popupSource, /let analysisGeneration\s*=\s*0;/);
  assert.match(popupSource, /function clearLatestAnalysisState\(\)/);
  assert.match(popupSource, /latestReportPayload\s*=\s*null;/);
  assert.match(popupSource, /latestPolicySaveContext\s*=\s*null;/);
  assert.match(popupSource, /function beginAnalysis\(mode\)/);
  assert.match(popupSource, /function isCurrentAnalysis\(generation\)/);

  const generationGuards = popupSource.match(/if \(!isCurrentAnalysis\(generation\)\) return;/g) || [];
  assert.ok(generationGuards.length >= 8, "async page and cookie analysis should guard awaited results");
});

test("builds an exportable URL-less report for pasted text without retaining a page snapshot", () => {
  const match = popupSource.match(/function analyzePastedText\(\) \{([\s\S]*?)\n\}/);
  assert.ok(match, "analyzePastedText function should be present");
  assert.match(match[1], /beginAnalysis\("paste"\);/);
  assert.match(match[1], /type:\s*"pasted-text"/);
  assert.match(match[1], /url:\s*""/);
  assert.match(match[1], /latestSource\s*=\s*source;/);
  assert.match(match[1], /latestPolicySaveContext\s*=\s*null;/);
  assert.match(match[1], /latestReportPayload\s*=\s*policyAnalysis\.ok/);
  assert.match(match[1], /buildReportPayload\(/);
  assert.doesNotMatch(popupSource, /latestSourceText/);
  assert.match(popupHtml, /id="policyText"[^>]*maxlength="120000"/);
  assert.match(popupSource, /slice\(0, MAX_PASTED_POLICY_LENGTH\)/);
  assert.match(popupSource, /policyText\.addEventListener\("input", queuePastedTextAnalysis\)/);
});

test("requires a URL and delegates canonical policy snapshots to the background", () => {
  assert.match(popupSource, /latestSource\.type === "pasted-text" \|\| !latestSource\.url/);
  assert.match(popupSource, /statusPolicyRequiresUrl/);
  assert.match(popupSource, /latestSource\?\.type === "page" \? "statusNeedPolicyAnalysis"/);
  assert.match(popupSource, /const normalizedPolicyUrl = policyAnalysis\.ok \? normalizePolicyUrl\(documentUrl\) : "";/);
  assert.match(popupSource, /latestPolicyMonitoringRequiresHttps = policyMonitoringRequiresHttps;/);
  assert.match(popupSource, /if \(latestPolicyMonitoringRequiresHttps\) \{\s*setStatus\(t\("statusPolicyRequiresHttps"\), true\)/);
  assert.match(popupSource, /latestPolicySaveContext = policyAnalysis\.ok && normalizedPolicyUrl/);
  assert.match(popupSource, /tabId:\s*tab\.id,\s*\n\s*documentId,\s*\n\s*policyUrl:\s*normalizedPolicyUrl/);
  assert.match(popupSource, /type:\s*"SAVE_MONITORED_POLICY_SNAPSHOT"/);
  assert.match(popupSource, /const snapshotKey = latestPolicySaveContext\?\.policyUrl;/);
  assert.doesNotMatch(popupSource, /createPolicySnapshot|comparePolicySnapshot|loadPolicySnapshot/);
  assert.doesNotMatch(popupSource, /let latestPolicySnapshot/);
  assert.doesNotMatch(popupSource, /savePolicySnapshot/);
  assert.doesNotMatch(popupSource, /originFromUrl\(latestSource\?\.url\)/);
});

test("discloses the network and schedule effects beside policy monitoring consent", () => {
  assert.match(
    popupHtml,
    /id="savePolicyButton"[\s\S]*?aria-describedby="policyMonitoringDisclosure"[\s\S]*?>정책 변경 감시 시작<\/button>/
  );
  assert.match(popupHtml, /id="policyMonitoringDisclosure"/);
  assert.match(popupHtml, /최대 6시간에 한 번/);
  assert.match(popupHtml, /6시간 안에도 다시 접속/);
  assert.match(popupHtml, /IP 주소/);
  assert.match(popupHtml, /User-Agent/);
  assert.match(popupHtml, /요청 시각/);
  assert.match(popupHtml, /삭제하면 이 URL의 감시가 중지/);
  assert.match(popupHtml, /data-i18n="deletePolicy">감시 중지 및 저장본 삭제<\/button>/);
  assert.match(popupSource, /setStatus\(t\("statusPolicySaved"\)\)/);
  assert.match(popupSource, /setStatus\(t\(deleted \? "statusPolicyDeleted"/);
});

test("infers overseas transfer only from explicit, comparable country signals", () => {
  assert.match(popupSource, /function inferOverseasTransfer\(/);
  assert.match(popupSource, /function explicitSourceCountry\(/);
  assert.match(popupSource, /overseasTransferStatus:\s*overseasTransfer\.status/);
  assert.doesNotMatch(popupSource, /thirdPartyHosts\?\.some\(\(host\) => !host\.endsWith\("\.kr"\)\)/);
});

test("passes observation and user-choice boundaries into consent analysis", () => {
  assert.match(popupSource, /observationStartedAt:\s*network\?\.observationStartedAt/);
  assert.match(popupSource, /snapshotAt:\s*latestSnapshot\?\.createdAt/);
  assert.match(popupSource, /analyzeConsentCompliance\(\s*\{\s*\.\.\.\(response\.consent \|\| \{\}\)/);
});

test("binds observation save and reset actions to the clicked document context", () => {
  const saveMatch = popupSource.match(
    /async function saveObservationSnapshot\(\) \{([\s\S]*?)\n\}\n\nasync function resetObservation/
  );
  const resetMatch = popupSource.match(
    /async function resetObservation\(\) \{([\s\S]*?)\n\}\n\nfunction analyzePastedText/
  );
  assert.ok(saveMatch);
  assert.ok(resetMatch);

  for (const actionSource of [saveMatch[1], resetMatch[1]]) {
    assert.match(actionSource, /const pageContext = await requireCurrentPageContext\(tab\.id\)/);
    assert.match(actionSource, /\n\s*documentFingerprint(?:\s*:\s*documentFingerprint)?,?\s*\n/);
    assert.match(actionSource, /documentId:\s*pageContext\.documentId/);
    assert.match(actionSource, /response\?\.code === "STALE_PAGE"/);
    assert.match(actionSource, /statusPageChangedDuringAnalysis/);
  }
  assert.ok(
    resetMatch[1].indexOf('response?.code === "STALE_PAGE"') <
      resetMatch[1].indexOf("clearLatestAnalysisState()"),
    "a stale reset response must not clear the current popup result"
  );
  assert.match(
    popupSource,
    /resetContentConsentTiming\(tab\.id, (?:false|true), pageContext\.documentId\)/
  );
  assert.match(
    popupSource,
    /chrome\.tabs\.sendMessage\([\s\S]*?documentId \? \{ documentId \} : undefined/
  );
});

test("has a collapsible action menu in the popup", () => {
  assert.match(popupHtml, /id="menuToggleButton"/);
  assert.match(popupHtml, /aria-controls="actionsPanel"/);
  assert.match(popupHtml, /id="actionsPanel"/);
  assert.match(popupSource, /function setActionMenuExpanded\(isExpanded\)/);
  assert.match(popupSource, /actionsPanel\.hidden\s*=\s*!isExpanded;/);
  assert.match(popupSource, /menuToggleButton\.addEventListener\("click"/);
});

test("toggles the global companion overlay only through the trusted preference contract", () => {
  assert.match(popupHtml, /id="companionOverlayToggleButton"/);
  assert.match(popupHtml, /aria-pressed="false"/);
  assert.match(popupHtml, /aria-describedby="companionOverlayDisclosure"/);
  assert.match(popupHtml, /모든 지원 HTTP\(S\) 페이지/);
  assert.match(popupHtml, /웹사이트 DOM/);
  assert.match(popupSource, /type:\s*"GET_COMPANION_OVERLAY_PREFERENCE"/);
  assert.match(
    popupSource,
    /type:\s*"SET_COMPANION_OVERLAY_PREFERENCE",\s*\n\s*enabled/
  );
  assert.match(popupSource, /typeof response\.enabled !== "boolean"/);
  assert.match(popupSource, /response\.enabled !== enabled/);
  assert.match(
    popupSource,
    /trustedLocalStorageAvailable && companionOverlayPreferenceAvailable/
  );
  assert.doesNotMatch(popupSource, /chrome\.sidePanel/);

  const generalBindings = popupSource.match(/function bindPopupEvents\(\) \{([\s\S]*?)\n\}/);
  const trustedBindings = popupSource.match(
    /function bindTrustedLocalStorageEvents\(\) \{([\s\S]*?)\n\}/
  );
  assert.ok(generalBindings);
  assert.ok(trustedBindings);
  assert.doesNotMatch(generalBindings[1], /companionOverlayToggleButton/);
  assert.match(
    trustedBindings[1],
    /companionOverlayToggleButton\?\.addEventListener\("click", toggleCompanionOverlay\)/
  );
  assert.match(popupSource, /void loadCompanionOverlayPreference\(\);/);
});

test("scrolls the whole popup without collapsing long analysis results", () => {
  const bodyRule = popupCss.match(/body\s*\{([^}]*)\}/)?.[1] || "";
  const appRule = popupCss.match(/\.app\s*\{([^}]*)\}/)?.[1] || "";
  const resultRule = popupCss.match(/\.result\s*\{([^}]*)\}/)?.[1] || "";

  assert.match(bodyRule, /overflow-y:\s*auto/);
  assert.doesNotMatch(bodyRule, /overflow:\s*hidden/);
  assert.match(appRule, /min-height:\s*600px/);
  assert.match(appRule, /overflow:\s*visible/);
  assert.doesNotMatch(appRule, /^\s*height:\s*600px/m);
  assert.match(resultRule, /flex:\s*1 0 auto/);
  assert.match(resultRule, /min-height:\s*120px/);
  assert.match(resultRule, /overflow:\s*visible/);
  assert.doesNotMatch(resultRule, /overflow-y:\s*auto/);

  let braceDepth = 0;
  for (const character of popupCss) {
    if (character === "{") braceDepth += 1;
    if (character === "}") braceDepth -= 1;
    assert.ok(braceDepth >= 0, "popup CSS must not contain a stray closing brace");
  }
  assert.equal(braceDepth, 0, "popup CSS blocks must be balanced");
});

test("has a dedicated cookie analysis menu action", () => {
  assert.match(popupHtml, /id="analyzeCookiesButton"/);
  assert.match(popupHtml, />쿠키 분석<\/button>/);
  assert.match(popupSource, /const analyzeCookiesButton = document\.querySelector\("#analyzeCookiesButton"\);/);
  assert.match(popupSource, /async function analyzeCookies\(\)/);
  assert.match(popupSource, /function renderCookieFocusedAnalysis/);
  assert.match(popupSource, /analyzeCookiesButton\.addEventListener\("click", analyzeCookies\);/);
});

test("adds page-readability guards for unsupported schemes and content-script failures", () => {
  assert.match(popupSource, /function isHttpOrHttpsTab\(tab\)/);
  assert.match(popupSource, /statusUnsupportedPageScheme/);
  assert.match(popupSource, /requestPageTextWithRetry/);
  assert.match(popupSource, /statusPageScriptUnavailable/);
  assert.match(
    popupSource,
    /files:\s*\["src\/domWorkLimits\.js", "src\/content\.js", "src\/companionOverlay\.js"\]/
  );
  assert.match(
    popupSource,
    /chrome\.tabs\.sendMessage\(\s*tabId,\s*\{ type: "GET_PAGE_TEXT" \},\s*\{ documentId \}/
  );
  assert.match(
    popupSource,
    /target:\s*\{ tabId, documentIds: \[documentId\] \}/
  );

  const retryMatch = popupSource.match(
    /async function requestPageTextWithRetry\(tabId, documentId\) \{([\s\S]*?)\n\}\n\nfunction extractTextFallbackFromPage/
  );
  assert.ok(retryMatch, "page text retry flow should be present");
  assert.ok(
    retryMatch[1].indexOf("return await requestPageText(tabId, documentId)") <
      retryMatch[1].indexOf("await ensureContentScriptInjected(tabId, documentId)"),
    "the popup should use an existing content-script listener before attempting reinjection"
  );
  assert.match(
    retryMatch[1],
    /if \(isReceivingEndError\(error\)\) \{[\s\S]*?await ensureContentScriptInjected\(tabId, documentId\)/,
    "reinjection should only recover a missing receiving end"
  );
  assert.match(retryMatch[1], /collectPageDataByScripting\(tabId, documentId\)/);
  assert.equal(
    (popupSource.match(/requestPageTextWithRetry\(tab\.id, documentId\)/g) || []).length,
    2,
    "page and cookie analysis must bind reads to their captured document"
  );
});

test("queries an existing page reader before reinjecting only for a missing receiver", async () => {
  const directCalls = { messages: 0, injections: 0, options: [] };
  const directChrome = {
    runtime: { lastError: null },
    tabs: {
      sendMessage(_tabId, _message, options, callback) {
        directCalls.messages += 1;
        directCalls.options.push({ ...options });
        callback({ text: "direct page text" });
      }
    },
    scripting: {
      async executeScript() {
        directCalls.injections += 1;
      }
    }
  };
  const directResult = await loadPageTextRetry(directChrome)(7, "active-document-7");
  assert.equal(directResult.text, "direct page text");
  assert.deepEqual(directCalls, {
    messages: 1,
    injections: 0,
    options: [{ documentId: "active-document-7" }]
  });

  const recoveryCalls = { messages: 0, injections: 0, files: [], options: [], targets: [] };
  const recoveryChrome = {
    runtime: { lastError: null },
    tabs: {
      sendMessage(_tabId, _message, options, callback) {
        recoveryCalls.messages += 1;
        recoveryCalls.options.push({ ...options });
        if (recoveryCalls.messages === 1) {
          recoveryChrome.runtime.lastError = new Error(
            "Could not establish connection. Receiving end does not exist."
          );
          callback();
          recoveryChrome.runtime.lastError = null;
          return;
        }
        callback({ text: "recovered page text" });
      }
    },
    scripting: {
      async executeScript(details) {
        recoveryCalls.injections += 1;
        recoveryCalls.files = [...details.files];
        recoveryCalls.targets.push(structuredClone(details.target));
      }
    }
  };
  const recoveryResult = await loadPageTextRetry(recoveryChrome)(11, "active-document-11");
  assert.equal(recoveryResult.text, "recovered page text");
  assert.equal(recoveryCalls.messages, 2);
  assert.equal(recoveryCalls.injections, 1);
  assert.deepEqual(recoveryCalls.files, [
    "src/domWorkLimits.js",
    "src/content.js",
    "src/companionOverlay.js"
  ]);
  assert.deepEqual(recoveryCalls.options, [
    { documentId: "active-document-11" },
    { documentId: "active-document-11" }
  ]);
  assert.deepEqual(recoveryCalls.targets, [
    { tabId: 11, documentIds: ["active-document-11"] }
  ]);
});

test("discards page and observation results when navigation changes mid-analysis", () => {
  assert.match(popupSource, /function documentUrlIdentity\(value\)/);
  assert.match(
    popupSource,
    /async function requireCurrentPageContext\(tabId, expectedUrl, expectedDocumentId\)/
  );
  assert.match(popupSource, /function validateNetworkContext\(network, pageUrl, documentId\)/);
  assert.match(popupSource, /page\.url !== network\.session\.navigationKey/);
  assert.match(popupSource, /network\.session\.documentId !== documentId/);
  assert.match(popupSource, /statusPageChangedDuringAnalysis/);
  const contextChecks =
    popupSource.match(/requireCurrentPageContext\(tab\.id, documentUrl, documentId\)/g) || [];
  assert.ok(contextChecks.length >= 6, "page and cookie analysis should re-check the document after awaits");
  assert.doesNotMatch(popupSource, /const sourceUrl = response\.url/);
  const finalIndicatorUrls = popupSource.match(/source:\s*"popup-(?:page|cookie)",[\s\S]{0,180}?url:\s*documentUrl/g) || [];
  assert.equal(finalIndicatorUrls.length, 2);
});

test("sanitizes indicator URLs and bounds fallback DOM traversal", () => {
  assert.match(popupSource, /function indicatorUrl\(value\)/);
  assert.match(popupSource, /parsed\.username = ""/);
  assert.match(popupSource, /parsed\.search = ""/);
  assert.match(popupSource, /url:\s*indicatorUrl\(indicator\?\.url\)/);
  assert.match(popupSource, /function boundedElements\(/);
  assert.match(popupSource, /function boundedText\(/);
  assert.match(popupSource, /MAX_DOM_NODES_VISITED\s*=\s*20000/);
  assert.match(popupSource, /MAX_READABLE_CANDIDATES\s*=\s*80/);
  assert.match(popupSource, /MAX_FALLBACK_TOTAL_NODES\s*=\s*100000/);
  assert.match(popupSource, /MAX_FALLBACK_STYLE_READS\s*=\s*30000/);
  assert.match(popupSource, /MAX_FALLBACK_TIME_MS\s*=\s*250/);
  assert.match(popupSource, /const fallbackVisibilityCache = new WeakMap\(\)/);
  assert.match(popupSource, /function takeFallbackNode\(\)/);
  assert.match(popupSource, /function boundedClosest\(/);
  assert.match(popupSource, /NodeFilter\.SHOW_ALL/);
  assert.match(popupSource, /nodeValue\.slice\(0, remaining\)/);
  assert.doesNotMatch(popupSource, /\$\{separator\}\$\{String\(node\.nodeValue/);
  assert.match(popupSource, /CONSENT_CANDIDATE_SELECTOR/);
  assert.doesNotMatch(popupSource, /"\[id\], \[class\], \[role='dialog'\]/);
  assert.match(popupSource, /return getStorageKeys\(window\[property\]\);/);
  assert.match(popupSource, /current\.getAttribute\("aria-hidden"\) === "true"/);
});

test("clears an in-progress page badge after analysis failures", () => {
  const errorIndicators = popupSource.match(/source:\s*"popup-error"/g) || [];
  assert.equal(errorIndicators.length, 2);
  assert.match(popupSource, /level:\s*"unknown",\s*\n\s*source:\s*"popup-error"/);
  const guardedErrorUpdates = popupSource.match(
    /if \(!isCurrentAnalysis\(generation\)\) return;\s*await updateToolbarRiskIndicator\([\s\S]{0,180}?source:\s*"popup-error"[\s\S]{0,180}?\);\s*if \(!isCurrentAnalysis\(generation\)\) return;/g
  ) || [];
  assert.equal(guardedErrorUpdates.length, 2, "stale failures must not replace the current analysis status");
});

test("highlights only the active analysis mode", () => {
  assert.match(popupHtml, /id="analyzePageButton"[^>]*class="secondary mode-button"[^>]*data-mode="page"[^>]*aria-pressed="true"/);
  assert.match(popupHtml, /id="analyzeCookiesButton"[^>]*class="secondary mode-button"[^>]*data-mode="cookies"[^>]*aria-pressed="false"/);
  assert.match(popupHtml, /id="analyzePasteButton"[^>]*class="secondary mode-button"[^>]*data-mode="paste"[^>]*aria-pressed="false"/);
  assert.match(popupSource, /function setActiveAnalysisMode\(mode\)/);
  assert.match(popupSource, /beginAnalysis\("page"\);/);
  assert.match(popupSource, /beginAnalysis\("cookies"\);/);
  assert.match(popupSource, /beginAnalysis\("paste"\);/);
});
