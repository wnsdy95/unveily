import assert from "node:assert/strict";
import test from "node:test";

import {
  PUBLIC_SUFFIX_LIST_COMMIT,
  PUBLIC_SUFFIX_LIST_VERSION,
  registrableDomain
} from "../src/publicSuffixRules.js";

test("pins ICANN and PRIVATE public suffix rules for site boundaries", () => {
  assert.match(PUBLIC_SUFFIX_LIST_VERSION, /^\d{4}-\d{2}-\d{2}_/);
  assert.match(PUBLIC_SUFFIX_LIST_COMMIT, /^[a-f0-9]{40}$/);
  assert.equal(registrableDomain("api.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("bob.appspot.com"), "bob.appspot.com");
  assert.equal(registrableDomain("BOB.APPspot.com."), "bob.appspot.com");
  assert.equal(registrableDomain("www.ck"), "www.ck");
  assert.equal(registrableDomain("a.b.ck"), "a.b.ck");
  assert.equal(registrableDomain("127.0.0.1"), "127.0.0.1");
  assert.equal(registrableDomain("[::1]"), "[::1]");
  assert.equal(registrableDomain("bücher.example"), "xn--bcher-kva.example");
});

test("falls back to exact host identity for a suffix absent from the pinned list", () => {
  assert.equal(registrableDomain("alice.not-a-real-tld"), "alice.not-a-real-tld");
  assert.equal(registrableDomain("bob.not-a-real-tld"), "bob.not-a-real-tld");
});
