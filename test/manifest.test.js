import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));

test("uses the toolbar action popup instead of tab navigation", () => {
  assert.equal(manifest.manifest_version, 3);
  assert.equal(manifest.minimum_chrome_version, "140");
  assert.equal(manifest.default_locale, "ko");
  assert.equal(manifest.name, "__MSG_appName__");
  assert.equal(manifest.description, "__MSG_appDescription__");
  assert.equal(manifest.action.default_popup, "src/popup.html");
  assert.equal(manifest.action.default_title, "__MSG_actionTitle__");
  assert.deepEqual(manifest.action.default_icon, {
    "16": "icons/icon.png",
    "48": "icons/icon.png",
    "128": "icons/icon.png"
  });
});

test("keeps always-on observation explicit while disabling incognito access", () => {
  assert.equal(manifest.incognito, "not_allowed");
  assert.ok(manifest.host_permissions.includes("http://*/*"));
  assert.ok(manifest.host_permissions.includes("https://*/*"));
  assert.ok(manifest.permissions.includes("webRequest"));
  assert.equal(manifest.content_security_policy.extension_pages, "script-src 'self'; object-src 'none';");
  assert.deepEqual(manifest.content_scripts[0].js, [
    "src/domWorkLimits.js",
    "src/content.js",
    "src/companionOverlay.js"
  ]);
});

test("registers the opt-in companion overlay without retaining side-panel authority", () => {
  assert.equal(manifest.permissions.includes("sidePanel"), false);
  assert.equal(Object.hasOwn(manifest, "side_panel"), false);
  assert.equal(manifest.content_scripts[0].js.at(-1), "src/companionOverlay.js");
  assert.equal(manifest.action.default_popup, "src/popup.html");
});
