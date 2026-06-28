import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const koMessages = JSON.parse(await readFile(new URL("../_locales/ko/messages.json", import.meta.url), "utf8"));
const enMessages = JSON.parse(await readFile(new URL("../_locales/en/messages.json", import.meta.url), "utf8"));

test("provides Chrome i18n manifest messages for Korean and English", () => {
  for (const key of ["appName", "appDescription", "actionTitle"]) {
    assert.equal(typeof koMessages[key]?.message, "string");
    assert.equal(typeof enMessages[key]?.message, "string");
    assert.notEqual(koMessages[key].message.length, 0);
    assert.notEqual(enMessages[key].message.length, 0);
  }
});

test("falls back to local UI messages outside Chrome", async () => {
  globalThis.chrome = { i18n: { getUILanguage: () => "ko" } };
  const { t } = await import("../src/i18n.js");

  assert.equal(t("analyzeCookies"), "쿠키 분석");
  assert.equal(t("statusPoliciesChecked", [2, 1, 1]), "정책 확인 완료: 2개 확인, 1개 변경, 1개 알림");
  delete globalThis.chrome;
});

test("respects manual locale override", async () => {
  globalThis.chrome = {
    i18n: { getUILanguage: () => "ko" },
    storage: {
      local: {
        get: async () => ({ uiLocaleOverride: "en" }),
        set: async () => {}
      }
    }
  };

  const { t, setLocalePreference } = await import("../src/i18n.js");

  await setLocalePreference("en");
  assert.equal(t("analyzeCookies"), "Cookie analysis");
  assert.equal(t("statusPageReadFailed"), "Could not read the current page. Refresh and retry, or use paste analysis.");

  await setLocalePreference("ko");
  assert.equal(t("analyzeCookies"), "쿠키 분석");
  assert.equal(t("statusPoliciesChecked", [2, 1, 1]), "정책 확인 완료: 2개 확인, 1개 변경, 1개 알림");

  delete globalThis.chrome;
});

test("loads legacy locale preference keys and normalizes legacy locale values", async () => {
  globalThis.chrome = {
    i18n: { getUILanguage: () => "en-US" },
    storage: {
      local: {
        get: async () => ({ language: "en-US", locale: "ko-KR", languagePreference: "en-US" }),
        set: async () => {}
      }
    }
  };

  const { t, setLocalePreference } = await import("../src/i18n.js");

  // When legacy ko-KR is present, it should be normalized and applied as Korean.
  assert.equal(t("analyzeCookies"), "쿠키 분석");

  // After changing preference, standard normalization should still work.
  await setLocalePreference("en-US");
  assert.equal(t("analyzeCookies"), "Cookie analysis");

  delete globalThis.chrome;
});
