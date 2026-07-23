import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const optionsHtml = await readFile(new URL("../src/options.html", import.meta.url), "utf8");
const optionsSource = await readFile(new URL("../src/options.js", import.meta.url), "utf8");

test("provides global pause and exact-origin observation controls", () => {
  assert.match(optionsHtml, /상시 관찰은 기본으로 켜져 있습니다/);
  assert.match(optionsHtml, /값 없는 요청·쿠키 메타데이터/);
  assert.match(optionsHtml, /사용자 입력·편집 영역을 제외한 제한된 표시 텍스트/);
  assert.match(optionsHtml, /정책으로 보일 때만 제한된 발췌문이 서비스 워커로 전달/);
  assert.match(optionsHtml, /관찰 기록이나 원격 서버에는 저장·전송되지 않습니다/);
  assert.match(optionsHtml, /텍스트 스캔은 아래에서 함께 끄거나 사이트별로 제외/);
  assert.match(optionsHtml, /id="observationEnabled"/);
  assert.match(optionsHtml, /id="excludedOrigins"/);
  assert.match(optionsHtml, /id="saveObservationSettingsButton"/);
  assert.match(optionsSource, /loadObservationSettings/);
  assert.match(optionsSource, /saveObservationSettings/);
  assert.match(optionsSource, /validateObservationSettingsInput/);
  assert.match(optionsSource, /excludedOrigins\.value\.split/);
  assert.doesNotMatch(optionsSource, /excludedOrigins\.value\.slice/);
  assert.match(optionsSource, /statusObservationOriginsTooMany/);
  assert.match(optionsSource, /statusObservationOriginInvalid/);
  assert.match(optionsHtml, /id="excludedOrigins"[^>]*maxlength="50000"/);
});

test("uses URL-specific snapshot keys in the options list", () => {
  assert.match(optionsHtml, />저장된 정책 변경 감시<\/h2>/);
  assert.match(optionsSource, /snapshot\.key \|\| snapshot\.origin/);
  assert.match(optionsSource, /deletePolicySnapshot\(button\.dataset\.key\)/);
  assert.match(optionsSource, /class="snapshot-url"/);
  assert.match(optionsSource, /escapeHtml\(snapshot\.url \|\| ""\)/);
});

test("shows privacy-minimized automatic policy check health for each saved URL", () => {
  assert.match(optionsSource, /loadPolicyCheckHealth/);
  assert.match(optionsSource, /policyCheckHealth\[snapshot\.key\]/);
  assert.match(optionsSource, /health\.consecutiveFailures > 0/);
  assert.match(optionsSource, /POLICY_HEALTH_ERROR_MESSAGE_KEYS/);
  assert.match(optionsSource, /class="snapshot-health/);
  assert.doesNotMatch(optionsSource, /health\.error\b/);
});
