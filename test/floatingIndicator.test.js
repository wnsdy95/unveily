import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contentSource = await readFile(new URL("../src/content.js", import.meta.url), "utf8");
const overlaySource = await readFile(new URL("../src/companionOverlay.js", import.meta.url), "utf8");
const domWorkLimitsSource = await readFile(new URL("../src/domWorkLimits.js", import.meta.url), "utf8");
const backgroundSource = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
const popupSource = await readFile(new URL("../src/popup.js", import.meta.url), "utf8");

test("keeps the page companion display-only and isolates its owned DOM mutations", () => {
  assert.match(contentSource, /__unveilyContentScriptLoaded/);
  assert.doesNotMatch(contentSource, /document\.createElement|attachShadow|appendChild/);
  assert.match(overlaySource, /__unveilyCompanionOverlayOwnedHosts/);
  assert.match(overlaySource, /new WeakSet\(\)/);
  assert.match(overlaySource, /function ownsMutationRecord\(record\)/);
  assert.match(overlaySource, /attachShadow\(\{ mode: "closed" \}\)/);
  assert.match(overlaySource, /pointerEvents: "none"/);
  assert.doesNotMatch(overlaySource, /addEventListener\(["']click/);
  assert.doesNotMatch(overlaySource, /innerHTML/);
  assert.match(backgroundSource, /chrome\.action\.setBadgeText/);
  assert.match(backgroundSource, /chrome\.action\.setBadgeBackgroundColor/);
});

test("updates the trusted toolbar badge from automatic scans and popup analysis", () => {
  assert.match(contentSource, /PAGE_RISK_SCAN/);
  assert.match(contentSource, /function assessPolicyLikelihood\(text, context\)/);
  assert.match(contentSource, /policyLike:\s*policyAssessment\.policyLike/);
  assert.match(contentSource, /policyConfidence:\s*policyAssessment\.confidence/);
  assert.match(contentSource, /policyAssessment\.policyLike \? \{ text:/);
  assert.doesNotMatch(contentSource, /type:\s*"PAGE_RISK_SCAN",\s*title:/);
  assert.doesNotMatch(`${contentSource}\n${backgroundSource}`, /GET_RISK_INDICATOR|RISK_INDICATOR_UPDATE/);
  assert.match(contentSource, /PAGE_CONTEXT_CHANGED/);
  assert.match(backgroundSource, /const tabRiskIndicators = new Map\(\);/);
  assert.match(backgroundSource, /message\?\.type === "PAGE_RISK_SCAN"/);
  assert.match(backgroundSource, /message\?\.type === "SET_RISK_INDICATOR"/);
  assert.match(backgroundSource, /normalizedIndicatorUrl\.url !== normalizedTabUrl\.url/);
  assert.match(backgroundSource, /chrome\.tabs\.sendMessage\(tabId,\s*\{\s*type:\s*"PAGE_CONTEXT_CHANGED"\s*\}/);
  assert.doesNotMatch(backgroundSource, /PAGE_CONTEXT_CHANGED[\s\S]{0,120}indicator/);
  assert.match(popupSource, /async function updateToolbarRiskIndicator\(tabId, indicator\)/);
  assert.match(popupSource, /type:\s*"SET_RISK_INDICATOR"/);
  assert.match(popupSource, /source:\s*"popup-page"/);
  assert.match(popupSource, /source:\s*"popup-cookie"/);
});

test("checks observation settings before any automatic page scan", () => {
  assert.match(contentSource, /type:\s*"GET_OBSERVATION_SETTINGS"/);
  assert.match(contentSource, /function automaticObservationAllowed\(settings\)/);
  assert.match(contentSource, /settings\?\.enabled === true && settings\?\.allowed === true/);
  assert.doesNotMatch(contentSource, /excludedOrigins/);

  const initialize = contentSource.match(/function initializeAutomaticObservation\(\) \{([\s\S]*?)\n  \}/);
  assert.ok(initialize, "automatic observation initialization should be present");
  assert.ok(
    initialize[1].indexOf('type: "GET_OBSERVATION_SETTINGS"') < initialize[1].indexOf("startAutomaticObservation()"),
    "automatic scanning must wait for the observation settings response"
  );
  assert.doesNotMatch(initialize[1], /applyRiskIndicator|queueRiskScan|getOrCreateRiskIndicator/);
  assert.match(initialize[1], /settingsResponse\?\.ok && automaticObservationAllowed\(settingsResponse\.settings\)/);
  assert.match(contentSource, /function stopAutomaticObservation\(\)/);
  assert.doesNotMatch(contentSource, /riskIndicatorHost|riskIndicatorButton|applyRiskIndicator/);
  assert.match(contentSource, /OBSERVATION_SETTINGS_UPDATE/);
});

test("excludes user-input subtrees from automatic and explicit page text", () => {
  assert.match(contentSource, /USER_INPUT_TAGS = new Set\(\["INPUT", "TEXTAREA", "SELECT", "OPTION"\]\)/);
  assert.match(contentSource, /USER_INPUT_ROLES = new Set\(\["textbox", "searchbox", "combobox"\]\)/);
  assert.match(contentSource, /function isUserInputSubtree\(node, context = null\)/);
  assert.match(contentSource, /element\.isContentEditable === true/);
  assert.match(contentSource, /document\.designMode/);
  assert.match(contentSource, /\[style\?\.userModify, style\?\.webkitUserModify\]\.some/);
  assert.match(contentSource, /root\?\.host instanceof Element \? root\.host : null/);
  assert.match(
    contentSource,
    /isElementTreeVisible\(parent, context\) && !isUserInputSubtree\(parent, context\)/
  );
  assert.match(domWorkLimitsSource, /userInputCache:\s*new WeakMap\(\)/);
  assert.match(domWorkLimitsSource, /userInputStyleCache:\s*new WeakMap\(\)/);
  assert.match(contentSource, /function mutationsOnlyAddOrRemoveCompanionHosts\(records\)/);
  assert.match(contentSource, /const ownedHosts = globalThis\.__unveilyCompanionOverlayOwnedHosts/);
  assert.match(contentSource, /function mutationsOnlyAffectUserInput\(records\)/);
  assert.match(
    contentSource,
    /new MutationObserver\(\(records\) => \{\s*if \(mutationsOnlyAddOrRemoveCompanionHosts\(records\)\) return;\s*if \(!mutationsOnlyAffectUserInput\(records\)\) queueRiskScan\(\);/
  );
});

test("records consent timing metadata without reading field or cookie values", () => {
  assert.match(contentSource, /let consentDetectedAt\s*=\s*null;/);
  assert.match(contentSource, /let consentChoiceAt\s*=\s*null;/);
  assert.match(contentSource, /document\.addEventListener\("click", recordConsentChoice, true\)/);
  assert.match(contentSource, /if \(!event\.isTrusted/);
  assert.match(
    contentSource,
    /boundedClosest\(event\.target, "button, \[role='button'\], a", context, 16\)/
  );
  assert.match(
    contentSource,
    /kind === "save_preferences" \? getConsentToggles\(container, context\) : \[\]/
  );
  assert.match(contentSource, /return "reject_all"/);
  assert.match(contentSource, /return "accept_all"/);
  assert.match(contentSource, /return "save_preferences"/);
  assert.match(contentSource, /detected:\s*Boolean\(consentDetectedAt \|\| containers\.length > 0\)/);
  assert.match(contentSource, /detectedAt:\s*consentDetectedAt/);
  assert.match(contentSource, /choiceAt:\s*consentChoice\?\.at \|\| consentChoiceAt/);
  assert.match(contentSource, /choiceKind:\s*consentChoice\?\.kind \|\| null/);
  assert.doesNotMatch(contentSource, /\.value/);
});

test("bounds automatic DOM work and reads full text only after a policy-like preflight", () => {
  assert.match(contentSource, /MAX_DOM_NODES_VISITED\s*=\s*20000/);
  assert.match(contentSource, /MAX_TEXT_NODES_VISITED\s*=\s*50000/);
  assert.match(contentSource, /function boundedElements\(/);
  assert.match(contentSource, /function boundedText\(/);
  assert.match(contentSource, /const preflightText = boundedText\(/);
  assert.match(contentSource, /if \(policyAssessment\.policyLike\) \{\s*text = getBestReadableText/);
  assert.doesNotMatch(contentSource, /document\.querySelectorAll/);
  assert.match(contentSource, /CONSENT_CANDIDATE_SELECTOR/);
  assert.match(contentSource, /MAX_CONSENT_CANDIDATES\s*=\s*120/);
  assert.match(contentSource, /MAX_MUTATION_CONSENT_CANDIDATES\s*=\s*24/);
  assert.match(contentSource, /MAX_MUTATION_RECORDS\s*=\s*64/);
  assert.match(contentSource, /MAX_MUTATION_ADDED_NODES\s*=\s*64/);
  assert.match(contentSource, /collectMutationRoots\(records,/);
  assert.doesNotMatch(contentSource, /"\[id\], \[class\]/);
  assert.match(contentSource, /MAX_VISIBILITY_ANCESTORS\s*=\s*64/);
  assert.match(contentSource, /MAX_AUTOMATIC_SCAN_NODES\s*=\s*50_000/);
  assert.match(contentSource, /MAX_AUTOMATIC_SCAN_STYLES\s*=\s*12_000/);
  assert.match(contentSource, /MAX_AUTOMATIC_SCAN_TIME_MS\s*=\s*75/);
  assert.match(contentSource, /const context = automaticScanContext\(\);/);
  assert.match(contentSource, /boundedText\([\s\S]*?context[\s\S]*?assessPolicyLikelihood\(preflightText, context\)/);
  assert.match(contentSource, /getBestReadableText\(context\)/);
  assert.match(contentSource, /context\.budget\.exhausted/);
  assert.match(domWorkLimitsSource, /visibilityCache:\s*new WeakMap\(\)/);
  assert.match(domWorkLimitsSource, /textCache:\s*new WeakMap\(\)/);
  assert.match(contentSource, /function boundedTextResult\(/);
  assert.match(contentSource, /bestCandidate\?\.textResult\.complete/);
  assert.match(contentSource, /nodeValue\.slice\(0, remaining\)/);
  assert.doesNotMatch(contentSource, /\$\{separator\}\$\{String\(node\.nodeValue/);
  assert.match(contentSource, /function boundedClosest\(/);
  assert.match(contentSource, /document\.createTreeWalker\(start, NodeFilter\.SHOW_ALL\)/);
  assert.match(contentSource, /document\.createTreeWalker\(root, NodeFilter\.SHOW_ALL\)/);
  assert.match(contentSource, /closestCache\?\.get\(element\)/);
  assert.match(contentSource, /if \(!takeDomNode\(context\)\) break;/);
  assert.doesNotMatch(contentSource, /parent\.closest\(/);
  assert.match(contentSource, /const context = consentScanContext\(\);[\s\S]*?for \(const root of roots\)/);
  assert.match(contentSource, /CONSENT_ATTRIBUTE_WATCH_MS\s*=\s*30000/);
  assert.match(contentSource, /observeConsentMutations\(false\)/);
  assert.match(contentSource, /childList:\s*true/);
  assert.match(contentSource, /attributeFilter:\s*\["class", "style", "hidden", "aria-hidden"\]/);
  assert.match(contentSource, /getWindowStorageKeys\("localStorage"\)/);
  assert.doesNotMatch(contentSource, /getStorageKeys\(window\.localStorage\)/);
});

test("rescans changing visible SPA documents with throttling and navigation guards", () => {
  assert.match(contentSource, /RISK_RESCAN_MIN_INTERVAL_MS\s*=\s*15000/);
  assert.match(contentSource, /let riskNavigationGeneration\s*=\s*0/);
  assert.match(contentSource, /riskMutationObserver\.observe\(document\.documentElement, \{[\s\S]*?childList: true,[\s\S]*?characterData: true,[\s\S]*?subtree: true/);
  assert.match(contentSource, /document\.visibilityState === "hidden"/);
  assert.match(
    contentSource,
    /message\?\.type === "PAGE_CONTEXT_CHANGED"[\s\S]*?riskNavigationGeneration \+= 1;[\s\S]*?lastRiskScanFingerprint = "";[\s\S]*?queueRiskScan\(300\)/
  );
});

test("does not restart consent DOM observation while automatic observation is paused", () => {
  assert.match(
    contentSource,
    /function startConsentPresenceObservation\(\) \{\s*if \(!automaticObservationActive \|\| document\.visibilityState === "hidden"\) return;/
  );
  assert.match(contentSource, /function suspendAutomaticDomWork\(\)[\s\S]*?stopConsentPresenceObservation\(\);[\s\S]*?stopRiskMutationObservation\(\);/);
  assert.match(
    contentSource,
    /message\?\.type === "RESET_CONSENT_TIMELINE"[\s\S]*?startConsentPresenceObservation\(\)/
  );
});

test("fingerprints all bounded scan text without retaining a route URL", () => {
  const fingerprintFunction = contentSource.match(/function riskScanFingerprint\(text\) \{([\s\S]*?)\n  \}/);
  assert.ok(fingerprintFunction, "risk scan fingerprint function should be present");
  assert.match(fingerprintFunction[1], /index < text\.length; index \+= 1/);
  assert.match(fingerprintFunction[1], /Math\.imul\(hash \^ text\.charCodeAt\(index\), 0x01000193\)/);
  assert.match(fingerprintFunction[1], /riskNavigationGeneration/);
  assert.doesNotMatch(fingerprintFunction[1], /boundedPageUrl|location|href|search/);
  assert.doesNotMatch(fingerprintFunction[1], /index \+= 64/);

  const fingerprint = new Function("text", "riskNavigationGeneration", fingerprintFunction[1]);
  const original = "a".repeat(130);
  const changedBetweenOldSamples = `${original.slice(0, 1)}b${original.slice(2)}`;
  assert.notEqual(fingerprint(original, 4), fingerprint(changedBetweenOldSamples, 4));
  assert.notEqual(fingerprint(original, 4), fingerprint(original, 5));
  assert.doesNotMatch(fingerprint("secret?token=raw#fragment", 6), /secret|token|raw|fragment/);
});

test("uses the committed PNG icon for runtime notifications", () => {
  assert.doesNotMatch(backgroundSource, /icon128\.svg/);
  assert.match(backgroundSource, /chrome\.runtime\.getURL\("icons\/icon\.png"\)/);
});
