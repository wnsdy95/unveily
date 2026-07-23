import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const koMessages = JSON.parse(await readFile(new URL("../_locales/ko/messages.json", import.meta.url), "utf8"));
const enMessages = JSON.parse(await readFile(new URL("../_locales/en/messages.json", import.meta.url), "utf8"));

test("provides Chrome i18n manifest messages for Korean and English", () => {
  for (const key of [
    "appName",
    "appDescription",
    "actionTitle",
    "enableCompanionOverlay",
    "disableCompanionOverlay",
    "companionOverlayDisclosure",
    "statusCompanionOverlayEnabled",
    "statusCompanionOverlayDisabled",
    "statusCompanionOverlayUpdateFailed",
    "observationControlsTitle",
    "observationControlsDescription",
    "statusObservationSettingsOpenFailed",
    "companionTitle",
    "companionUnknown",
    "companionUnavailable",
    "companionSourceAutomatic"
  ]) {
    assert.equal(typeof koMessages[key]?.message, "string");
    assert.equal(typeof enMessages[key]?.message, "string");
    assert.notEqual(koMessages[key].message.length, 0);
    assert.notEqual(enMessages[key].message.length, 0);
  }
});

test("manifest descriptions disclose default all-site value-free local observation", () => {
  const koreanDescription = koMessages.appDescription.message;
  const englishDescription = enMessages.appDescription.message;

  assert.match(koreanDescription, /기본적으로/);
  assert.match(koreanDescription, /모든 HTTP\(S\) 사이트/);
  assert.match(koreanDescription, /값 없는 요청·쿠키 메타데이터/);
  assert.match(koreanDescription, /로컬/);
  assert.match(englishDescription, /By default/);
  assert.match(englishDescription, /all HTTP\(S\) sites/);
  assert.match(englishDescription, /value-free request and cookie metadata/);
  assert.match(englishDescription, /locally/);
  assert.ok(koreanDescription.length <= 132);
  assert.ok(englishDescription.length <= 132);
});

test("localizes the global website overlay toggle and its trust boundary", () => {
  assert.match(koMessages.enableCompanionOverlay.message, /켜기/);
  assert.match(koMessages.disableCompanionOverlay.message, /끄기/);
  assert.match(koMessages.companionOverlayDisclosure.message, /모든 지원 HTTP\(S\) 페이지/);
  assert.match(koMessages.companionOverlayDisclosure.message, /웹사이트 DOM/);
  assert.match(koMessages.companionOverlayDisclosure.message, /감지하거나 가릴 수/);
  assert.match(koMessages.companionOverlayDisclosure.message, /안전 판정이 아닙니다/);

  assert.match(enMessages.enableCompanionOverlay.message, /Turn on/);
  assert.match(enMessages.disableCompanionOverlay.message, /Turn off/);
  assert.match(enMessages.companionOverlayDisclosure.message, /every supported HTTP\(S\) page/);
  assert.match(enMessages.companionOverlayDisclosure.message, /website DOM/);
  assert.match(enMessages.companionOverlayDisclosure.message, /detect or cover/);
  assert.match(enMessages.companionOverlayDisclosure.message, /unknown does not mean safe/);
});

test("localizes the popup entry point for global pause and exact-origin exclusions", () => {
  assert.match(koMessages.appDescription.message, /기본적으로/);
  assert.match(koMessages.appDescription.message, /모든 HTTP\(S\) 사이트/);
  assert.equal(koMessages.observationControlsTitle.message, "상시 관찰 제어");
  assert.match(koMessages.observationControlsDescription.message, /관찰을 끄거나/);
  assert.match(koMessages.observationControlsDescription.message, /정확한 origin을 제외/);

  assert.match(enMessages.appDescription.message, /By default/);
  assert.match(enMessages.appDescription.message, /all HTTP\(S\) sites/);
  assert.equal(enMessages.observationControlsTitle.message, "Always-on observation controls");
  assert.match(enMessages.observationControlsDescription.message, /Pausing observation/);
  assert.match(enMessages.observationControlsDescription.message, /excluding an exact origin/);
  assert.match(koMessages.statusObservationSettingsOpenFailed.message, /설정 화면을 열지 못했습니다/);
  assert.match(enMessages.statusObservationSettingsOpenFailed.message, /Could not open observation settings/);
});

test("falls back to local UI messages outside Chrome", async () => {
  globalThis.chrome = { i18n: { getUILanguage: () => "ko" } };
  const { t } = await import("../src/i18n.js");

  assert.equal(t("analyzeCookies"), "쿠키 분석");
  assert.equal(t("enableCompanionOverlay"), "컴패니언 오버레이 켜기");
  assert.match(t("appDescription"), /모든 HTTP\(S\) 사이트/);
  assert.equal(
    t("statusPoliciesChecked", [2, 1, 1, 0]),
    "정책 확인 완료: 2개 확인, 1개 변경, 1개 알림, 0개 실패"
  );
  delete globalThis.chrome;
});

test("applies fallback UI text without touching local storage", async () => {
  let accessCalls = 0;
  let getCalls = 0;
  let setCalls = 0;
  globalThis.chrome = {
    i18n: {
      getUILanguage: () => "en-US",
      getMessage: () => ""
    },
    storage: {
      local: {
        async setAccessLevel() {
          accessCalls += 1;
        },
        async get() {
          getCalls += 1;
          return { uiLocaleOverride: "ko" };
        },
        async set() {
          setCalls += 1;
        }
      }
    }
  };

  const title = { dataset: { i18n: "appName" } };
  const translatedElement = { dataset: { i18n: "analyzeCookies" }, textContent: "" };
  const root = {
    documentElement: {
      lang: "",
      setAttribute(name, value) {
        if (name === "lang") this.lang = value;
      }
    },
    title: "",
    querySelector(selector) {
      return selector === "title" ? title : null;
    },
    querySelectorAll(selector) {
      return selector === "[data-i18n]" ? [translatedElement] : [];
    }
  };

  try {
    const moduleUrl = new URL("../src/i18n.js", import.meta.url);
    moduleUrl.searchParams.set("no-storage-test", `${Date.now()}-${Math.random()}`);
    const { applyI18nWithoutStorage } = await import(moduleUrl.href);

    applyI18nWithoutStorage(root);

    assert.equal(accessCalls, 0);
    assert.equal(getCalls, 0);
    assert.equal(setCalls, 0);
    assert.equal(root.documentElement.lang, "en");
    assert.equal(translatedElement.textContent, "Cookie analysis");
  } finally {
    delete globalThis.chrome;
  }
});

test("respects manual locale override", async () => {
  globalThis.chrome = {
    i18n: { getUILanguage: () => "ko" },
    storage: {
      local: {
        async setAccessLevel() {},
        get: async () => ({ uiLocaleOverride: "en" }),
        set: async () => {}
      }
    }
  };

  const { t, setLocalePreference } = await import("../src/i18n.js");

  await setLocalePreference("en");
  assert.equal(t("analyzeCookies"), "Cookie analysis");
  assert.match(t("appDescription"), /all HTTP\(S\) sites/);
  assert.equal(t("statusPageReadFailed"), "Could not read the current page. Refresh and retry, or use paste analysis.");
  assert.match(t("statusPageChangedDuringAnalysis"), /stale result was discarded/);
  assert.equal(t("observationControlsTitle"), "Always-on observation controls");
  assert.match(t("statusObservationOriginsTooMany"), /at most 100/);
  assert.match(t("statusObservationOriginInvalid"), /HTTP\(S\) origin or host/);
  assert.match(t("statusStorageIsolationUnavailable"), /trusted contexts/);
  assert.match(t("optionsDescription"), /enabled by default/);
  assert.match(t("optionsDescription"), /value-free request and cookie metadata/);
  assert.match(t("optionsDescription"), /bounded visible text that excludes user-input and editable areas/);
  assert.match(t("optionsDescription"), /bounded excerpt from policy-like pages is sent to the service worker/);
  assert.match(t("optionsDescription"), /not stored in observation history or sent to a remote server/);
  assert.match(t("statusPolicyRequiresUrl"), /Pasted text has no URL/);
  assert.match(t("statusPolicyRequiresHttps"), /safe HTTPS policy URL/);
  assert.match(t("statusPolicyRefetchFailed"), /could not be fetched safely/);
  assert.equal(t("savePolicy"), "Start policy monitoring");
  assert.equal(t("enableCompanionOverlay"), "Turn on companion overlay");
  assert.equal(t("disableCompanionOverlay"), "Turn off companion overlay");
  assert.match(t("companionOverlayDisclosure"), /website DOM/);
  assert.match(t("statusCompanionOverlayEnabled"), /all supported websites/);
  assert.match(t("statusCompanionOverlayUpdateFailed"), /Reopen the popup/);
  assert.match(t("statusObservationSettingsOpenFailed"), /Could not open observation settings/);
  assert.match(t("policyMonitoringDisclosure"), /refetches this policy host now/);
  assert.match(t("policyMonitoringDisclosure"), /at most once every six hours/);
  assert.match(t("policyMonitoringDisclosure"), /within six hours/);
  assert.match(t("policyMonitoringDisclosure"), /IP address/);
  assert.match(t("policyMonitoringDisclosure"), /User-Agent/);
  assert.match(t("policyMonitoringDisclosure"), /request time/);
  assert.match(t("policyMonitoringDisclosure"), /stops monitoring that URL/);
  assert.match(t("statusPolicySaved"), /monitoring started/);
  assert.match(t("statusPolicyDeleted"), /stopped monitoring this URL/);
  assert.match(t("statusSnapshotDeleted"), /stopped monitoring that URL/);
  assert.match(t("statusStorageIsolationUnavailable"), /cookie, and pasted-text analysis/);
  assert.match(t("statusStorageIsolationUnavailable"), /report export remain available/);
  assert.match(t("statusStorageIsolationUnavailable"), /comparisons are empty/);
  assert.equal(t("savedSnapshots"), "Saved policy monitoring");
  assert.match(t("noSavedSnapshots"), /monitoring is active/);
  assert.equal(
    t("policyCheckLastFailed", ["Jul 19", 2, t("policyCheckErrorTimeout")]),
    "Last automatic check failed: Jul 19 · 2 consecutive failures · Cause: Response timeout"
  );

  await setLocalePreference("ko");
  assert.equal(t("analyzeCookies"), "쿠키 분석");
  assert.match(t("appDescription"), /모든 HTTP\(S\) 사이트/);
  assert.match(t("optionsDescription"), /사용자 입력·편집 영역을 제외한 제한된 표시 텍스트/);
  assert.match(t("optionsDescription"), /정책으로 보일 때만 제한된 발췌문이 서비스 워커로 전달/);
  assert.match(t("optionsDescription"), /관찰 기록이나 원격 서버에는 저장·전송되지 않습니다/);
  assert.equal(
    t("statusPoliciesChecked", [2, 1, 1, 0]),
    "정책 확인 완료: 2개 확인, 1개 변경, 1개 알림, 0개 실패"
  );
  assert.equal(t("observationControlsTitle"), "상시 관찰 제어");
  assert.match(t("statusObservationOriginsTooMany"), /최대 100개/);
  assert.match(t("statusObservationOriginInvalid"), /HTTP\(S\) origin 또는 호스트/);
  assert.match(t("statusStorageIsolationUnavailable"), /신뢰 컨텍스트/);
  assert.match(t("optionsDescription"), /기본으로 켜져/);
  assert.match(t("optionsDescription"), /값 없는 요청·쿠키 메타데이터/);
  assert.match(t("statusPolicyRequiresHttps"), /안전한 HTTPS 정책 URL/);
  assert.match(t("statusPolicyRefetchFailed"), /안전하게 다시 불러오지 못해/);
  assert.equal(t("savePolicy"), "정책 변경 감시 시작");
  assert.equal(t("enableCompanionOverlay"), "컴패니언 오버레이 켜기");
  assert.equal(t("disableCompanionOverlay"), "컴패니언 오버레이 끄기");
  assert.match(t("companionOverlayDisclosure"), /웹사이트 DOM/);
  assert.match(t("statusCompanionOverlayEnabled"), /모든 지원 웹페이지/);
  assert.match(t("statusCompanionOverlayUpdateFailed"), /팝업을 다시 열어/);
  assert.match(t("statusObservationSettingsOpenFailed"), /설정 화면을 열지 못했습니다/);
  assert.match(t("policyMonitoringDisclosure"), /지금 정책 호스트에 다시 접속/);
  assert.match(t("policyMonitoringDisclosure"), /최대 6시간에 한 번/);
  assert.match(t("policyMonitoringDisclosure"), /6시간 안에도 다시 접속/);
  assert.match(t("policyMonitoringDisclosure"), /IP 주소/);
  assert.match(t("policyMonitoringDisclosure"), /User-Agent/);
  assert.match(t("policyMonitoringDisclosure"), /요청 시각/);
  assert.match(t("policyMonitoringDisclosure"), /감시가 중지/);
  assert.match(t("statusPolicySaved"), /변경 감시를 시작/);
  assert.match(t("statusPolicyDeleted"), /변경 감시를 중지/);
  assert.match(t("statusSnapshotDeleted"), /변경 감시를 중지/);
  assert.match(t("statusStorageIsolationUnavailable"), /현재 페이지·쿠키·붙여넣기 분석/);
  assert.match(t("statusStorageIsolationUnavailable"), /결과 내보내기/);
  assert.match(t("statusStorageIsolationUnavailable"), /누적 관찰 비교는 비어/);
  assert.equal(t("savedSnapshots"), "저장된 정책 변경 감시");
  assert.match(t("noSavedSnapshots"), /변경 감시가 없습니다/);
  assert.equal(
    t("policyCheckLastSucceeded", ["7월 19일"]),
    "마지막 자동 확인 성공: 7월 19일"
  );

  delete globalThis.chrome;
});

test("loads legacy locale preference keys and normalizes legacy locale values", async () => {
  globalThis.chrome = {
    i18n: { getUILanguage: () => "en-US" },
    storage: {
      local: {
        async setAccessLevel() {},
        get: async () => ({ language: "en-US", locale: "ko-KR", languagePreference: "en-US" }),
        set: async () => {}
      }
    }
  };

  const moduleUrl = new URL("../src/i18n.js", import.meta.url);
  moduleUrl.searchParams.set("legacy-locale-test", `${Date.now()}-${Math.random()}`);
  const { getLocalePreference, t, setLocalePreference } = await import(moduleUrl.href);

  // When legacy ko-KR is present, it should be normalized and applied as Korean.
  assert.equal(await getLocalePreference(), "ko");
  assert.equal(t("analyzeCookies"), "쿠키 분석");

  // After changing preference, standard normalization should still work.
  await setLocalePreference("en-US");
  assert.equal(t("analyzeCookies"), "Cookie analysis");

  delete globalThis.chrome;
});

test("falls back to auto locale without reading or writing when the storage gate fails", async () => {
  const calls = { access: 0, get: 0, set: 0 };
  globalThis.chrome = {
    i18n: {
      getUILanguage: () => "en-US",
      getMessage: () => ""
    },
    storage: {
      local: {
        async setAccessLevel() {
          calls.access += 1;
          throw new Error("denied");
        },
        async get() {
          calls.get += 1;
          return { uiLocaleOverride: "ko" };
        },
        async set() {
          calls.set += 1;
        }
      }
    }
  };

  try {
    const moduleUrl = new URL("../src/i18n.js", import.meta.url);
    moduleUrl.searchParams.set("storage-gate-failure", `${Date.now()}-${Math.random()}`);
    const { getLocalePreference, setLocalePreference, t } = await import(moduleUrl.href);

    assert.equal(await getLocalePreference(), "auto");
    assert.equal(t("analyzeCookies"), "Cookie analysis");
    await setLocalePreference("ko");
    assert.equal(await getLocalePreference(), "auto");
    assert.equal(t("analyzeCookies"), "Cookie analysis");
    assert.deepEqual(calls, { access: 2, get: 0, set: 0 });
  } finally {
    delete globalThis.chrome;
  }
});
