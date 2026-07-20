import assert from "node:assert/strict";
import test from "node:test";

import { createCompanionState } from "../src/companionRuntime.js";
import {
  COMPANION_OVERLAY_ENABLED_KEY,
  companionStorageUnavailableResponse,
  loadCompanionOverlayEnabled,
  normalizeCompanionOverlayEnabled
} from "../src/companionSettings.js";

test("normalizes companion states without forwarding labels or internal source names", () => {
  assert.deepEqual(createCompanionState({}, "", 123), {
    status: "unknown",
    level: "unknown",
    score: null,
    source: "none",
    updatedAt: 123
  });
  assert.deepEqual(
    createCompanionState(
      {
        level: "high",
        score: 74.6,
        source: "popup-page",
        updatedAt: 456,
        label: "must not pass",
        url: "https://must-not-pass.example"
      },
      ""
    ),
    {
      status: "ready",
      level: "high",
      score: 75,
      source: "page-analysis",
      updatedAt: 456
    }
  );
  assert.equal(createCompanionState({ level: "analyzing" }, "", 1).status, "analyzing");
  assert.equal(createCompanionState({ score: -50 }, "", 1).score, 0);
  assert.equal(createCompanionState({ score: 500 }, "", 1).score, 100);
  assert.equal(createCompanionState({ score: 25, source: "page-controlled" }, "", 1).source, "none");
  assert.equal(createCompanionState({ score: 25 }, "excluded", 1).status, "excluded");
  assert.equal(createCompanionState({ score: 25 }, "invalid", 1).status, "ready");
});

test("loads only a strict companion opt-in boolean and fails closed", async () => {
  assert.equal(normalizeCompanionOverlayEnabled(true), true);
  assert.equal(normalizeCompanionOverlayEnabled(1), false);
  assert.equal(
    await loadCompanionOverlayEnabled({
      async get(key) {
        assert.equal(key, COMPANION_OVERLAY_ENABLED_KEY);
        return { [key]: true };
      }
    }),
    true
  );
  assert.equal(
    await loadCompanionOverlayEnabled({
      async get() {
        throw new Error("storage unavailable");
      }
    }),
    false
  );
  assert.deepEqual(companionStorageUnavailableResponse(), {
    ok: false,
    enabled: false,
    code: "STORAGE_ISOLATION_UNAVAILABLE",
    error: "Trusted local storage is unavailable"
  });
});
