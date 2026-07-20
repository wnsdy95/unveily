import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import test from "node:test";
import {
  buildPolicyChangeDedupeKey,
  buildPolicyChangeNotification,
  extractPolicyTextFromHtml,
  shouldNotifyPolicyChange
} from "../src/policyMonitor.js";
import { normalizePolicyText } from "../src/policySnapshots.js";

test("extracts readable policy text from html", () => {
  const text = extractPolicyTextFromHtml(`
    <html>
      <head><style>.x{}</style><script>track()</script></head>
      <body><main><h1>Privacy Policy</h1><p>We collect email &amp; cookies.</p></main></body>
    </html>
  `);

  assert.equal(text, "Privacy Policy We collect email & cookies.");
});

test("prefers the main policy region and decodes numeric entities", () => {
  const text = extractPolicyTextFromHtml(`
    <html><body>
      <nav>Unrelated navigation and marketing</nav>
      <main><h1>Privacy &#38; Cookies</h1><p>Retention is 30&nbsp;days.</p></main>
      <footer>Unrelated footer</footer>
    </body></html>
  `);

  assert.equal(text, "Privacy & Cookies Retention is 30 days.");
});

test("matches rendered DOM text for common entities and ignores statically hidden policy text", () => {
  const extracted = extractPolicyTextFromHtml(`
    <main>
      <p>Privacy &mdash; we call this &ldquo;clear notice&rdquo;&hellip;</p>
      <aside hidden>We secretly sell everything.</aside>
      <div aria-hidden="true">Hidden tracking copy</div>
      <div style="display: none">Invisible retention copy</div>
    </main>
  `);

  assert.equal(extracted, normalizePolicyText("Privacy — we call this “clear notice”…"));
  assert.doesNotMatch(extracted, /secretly|tracking|retention/i);
});

test("skips non-rendered element subtrees while retaining the readable semantic region", () => {
  const extracted = extractPolicyTextFromHtml(`
    <body>
      <script>secretScript()</script>
      <style>.secret { display: block }</style>
      <noscript>secret noscript fallback</noscript>
      <template><main>secret template policy</main></template>
      <svg><text>secret vector label</text></svg>
      <article>Visible policy &copy; 2026</article>
    </body>
  `);

  assert.equal(extracted, "Visible policy © 2026");
  assert.doesNotMatch(extracted, /secret/i);
});

test("treats self-closing syntax on non-void HTML elements as an opening tag", () => {
  const scriptText = extractPolicyTextFromHtml("<main>Visible<script/>SECRET</main>");
  const hiddenText = extractPolicyTextFromHtml("<main>Visible<div hidden/>HIDDEN</main>");

  assert.equal(scriptText, "Visible");
  assert.equal(hiddenText, "Visible");
});

test("handles a megabyte of malformed hidden semantic tags with bounded work", () => {
  const malformedTag = "<main hidden>secret-policy-value ";
  const malformedHtml = malformedTag.repeat(Math.ceil((1024 * 1024) / malformedTag.length));
  const startedAt = performance.now();
  const extracted = extractPolicyTextFromHtml(malformedHtml);
  const elapsedMilliseconds = performance.now() - startedAt;

  assert.equal(extracted, "");
  assert.ok(elapsedMilliseconds < 5_000, `malformed HTML scan took ${elapsedMilliseconds.toFixed(0)}ms`);
});

test("caps extracted output from a megabyte-scale malformed main region", () => {
  const malformedHtml = `<main>${"visible policy text ".repeat(70_000)}`;
  const extracted = extractPolicyTextFromHtml(malformedHtml);

  assert.match(extracted, /^visible policy text/);
  assert.ok(extracted.length <= 256 * 1024);
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
    true
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
  assert.match(key, /^[a-f0-9]{16}$/);
  assert.equal(key, buildPolicyChangeDedupeKey(snapshot.origin, change, snapshot));
});
