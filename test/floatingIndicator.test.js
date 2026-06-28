import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const contentSource = await readFile(new URL("../src/content.js", import.meta.url), "utf8");
const backgroundSource = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
const popupSource = await readFile(new URL("../src/popup.js", import.meta.url), "utf8");

test("injects a bottom-right fading risk indicator on webpages", () => {
  assert.match(contentSource, /__unveilyContentScriptLoaded/);
  assert.match(contentSource, /RISK_INDICATOR_HOST_ID\s*=\s*"unveily-risk-indicator-host"/);
  assert.match(contentSource, /attachShadow\(\{\s*mode:\s*"open"\s*\}\)/);
  assert.match(contentSource, /position:\s*fixed;/);
  assert.match(contentSource, /right:\s*max\(18px,\s*env\(safe-area-inset-right\)\);/);
  assert.match(contentSource, /bottom:\s*max\(18px,\s*env\(safe-area-inset-bottom\)\);/);
  assert.match(contentSource, /radial-gradient\(\s*circle at center,/);
  assert.match(contentSource, /button\[data-risk-level="high"\]/);
  assert.match(contentSource, /button\[data-risk-level="medium"\]/);
  assert.match(contentSource, /button\[data-risk-level="low"\]/);
});

test("updates the floating indicator from automatic scans and popup analysis", () => {
  assert.match(contentSource, /PAGE_RISK_SCAN/);
  assert.match(contentSource, /RISK_INDICATOR_UPDATE/);
  assert.match(backgroundSource, /const tabRiskIndicators = new Map\(\);/);
  assert.match(backgroundSource, /message\?\.type === "PAGE_RISK_SCAN"/);
  assert.match(backgroundSource, /analyzePolicy\(message\.text \|\| ""\)/);
  assert.match(backgroundSource, /message\?\.type === "SET_RISK_INDICATOR"/);
  assert.match(backgroundSource, /chrome\.tabs\.sendMessage\(tabId,\s*\{\s*type:\s*"RISK_INDICATOR_UPDATE"/);
  assert.match(popupSource, /async function updateFloatingRiskIndicator\(tabId, indicator\)/);
  assert.match(popupSource, /type:\s*"SET_RISK_INDICATOR"/);
  assert.match(popupSource, /source:\s*"popup-page"/);
  assert.match(popupSource, /source:\s*"popup-cookie"/);
});

test("uses the committed PNG icon for runtime notifications", () => {
  assert.doesNotMatch(backgroundSource, /icon128\.svg/);
  assert.match(backgroundSource, /chrome\.runtime\.getURL\("icons\/icon\.png"\)/);
});
