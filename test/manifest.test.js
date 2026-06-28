import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const manifest = JSON.parse(await readFile(new URL("../manifest.json", import.meta.url), "utf8"));

test("uses the toolbar action popup instead of tab navigation", () => {
  assert.equal(manifest.manifest_version, 3);
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
