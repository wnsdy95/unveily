import assert from "node:assert/strict";
import test from "node:test";

import { normalizeRiskScore, riskColorForScore } from "../src/riskColor.js";

test("uses the green, orange, and red risk anchors", () => {
  assert.equal(riskColorForScore(0), "#039855");
  assert.equal(riskColorForScore(50), "#DC6803");
  assert.equal(riskColorForScore(100), "#D92D20");
});

test("interpolates and rounds RGB channels between risk anchors", () => {
  assert.equal(riskColorForScore(25), "#70802C");
  assert.equal(riskColorForScore(75), "#DB4B12");
});

test("clamps finite numeric scores and rejects invalid values", () => {
  assert.equal(normalizeRiskScore(-10), 0);
  assert.equal(normalizeRiskScore(125), 100);
  assert.equal(normalizeRiskScore(12.5), 12.5);
  assert.equal(riskColorForScore(-1), "#039855");
  assert.equal(riskColorForScore(101), "#D92D20");

  for (const value of [null, undefined, "50", Number.NaN, Infinity, -Infinity, {}, []]) {
    assert.equal(normalizeRiskScore(value), null);
    assert.equal(riskColorForScore(value), null);
  }
});
