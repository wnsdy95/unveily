import assert from "node:assert/strict";
import test from "node:test";
import {
  buildPolicyChangeDedupeKey,
  buildPolicyChangeNotification,
  extractPolicyTextFromHtml,
  shouldNotifyPolicyChange
} from "../src/policyMonitor.js";

test("extracts readable policy text from html", () => {
  const text = extractPolicyTextFromHtml(`
    <html>
      <head><style>.x{}</style><script>track()</script></head>
      <body><main><h1>Privacy Policy</h1><p>We collect email &amp; cookies.</p></main></body>
    </html>
  `);

  assert.equal(text, "Privacy Policy We collect email & cookies.");
});

test("notifies only important policy changes", () => {
  assert.equal(
    shouldNotifyPolicyChange({
      hasPrevious: true,
      changed: true,
      sectionChanges: [{ id: "third_party", label: "제3자 제공", changeType: "modified" }],
      riskChanges: { added: [] }
    }),
    true
  );

  assert.equal(
    shouldNotifyPolicyChange({
      hasPrevious: true,
      changed: true,
      sectionChanges: [{ id: "purpose", label: "수집 목적", changeType: "modified" }],
      riskChanges: { added: [] }
    }),
    false
  );

  assert.equal(
    shouldNotifyPolicyChange({
      hasPrevious: true,
      changed: true,
      sectionChanges: [],
      riskChanges: { added: ["broad_data_sharing"] }
    }),
    true
  );
});

test("builds notification message and dedupe key", () => {
  const snapshot = {
    origin: "https://example.com",
    url: "https://example.com/privacy",
    textHash: "abc"
  };
  const change = {
    sectionChanges: [{ id: "cookies_tracking", label: "쿠키/행태정보", changeType: "added" }],
    riskChanges: { added: ["behavioral_ads"] }
  };

  const notification = buildPolicyChangeNotification(snapshot, change);
  const key = buildPolicyChangeDedupeKey(snapshot.origin, change, snapshot);

  assert.match(notification.message, /example.com/);
  assert.match(notification.message, /쿠키\/행태정보/);
  assert.match(key, /https:\/\/example.com:abc/);
});
