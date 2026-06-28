import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const popupSource = await readFile(new URL("../src/popup.js", import.meta.url), "utf8");
const popupHtml = await readFile(new URL("../src/popup.html", import.meta.url), "utf8");

test("hides the paste panel when switching back to current page analysis", () => {
  const match = popupSource.match(/async function analyzeCurrentPage\(\) \{([\s\S]*?)\n\}\n\nasync function saveCurrentPolicySnapshot/);

  assert.ok(match, "analyzeCurrentPage function should be present");
  assert.match(match[1], /pastePanel\.hidden\s*=\s*true;/);
  assert.ok(
    match[1].indexOf("pastePanel.hidden = true;") < match[1].indexOf("try {"),
    "paste panel should be hidden before page analysis starts"
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
});

test("highlights only the active analysis mode", () => {
  assert.match(popupHtml, /id="analyzePageButton"[^>]*class="secondary mode-button"[^>]*data-mode="page"[^>]*aria-pressed="true"/);
  assert.match(popupHtml, /id="analyzeCookiesButton"[^>]*class="secondary mode-button"[^>]*data-mode="cookies"[^>]*aria-pressed="false"/);
  assert.match(popupHtml, /id="analyzePasteButton"[^>]*class="secondary mode-button"[^>]*data-mode="paste"[^>]*aria-pressed="false"/);
  assert.match(popupSource, /function setActiveAnalysisMode\(mode\)/);
  assert.match(popupSource, /setActiveAnalysisMode\("page"\);/);
  assert.match(popupSource, /setActiveAnalysisMode\("cookies"\);/);
  assert.match(popupSource, /setActiveAnalysisMode\("paste"\);/);
});
