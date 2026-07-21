import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repositoryRoot = new URL("../", import.meta.url);
const packageScript = new URL("../scripts/package-extension.mjs", import.meta.url);
const packageJson = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const packagePath = new URL(`../dist/unveily-${packageJson.version}.zip`, import.meta.url);

function runPackager(...args) {
  return execFileSync(process.execPath, [fileURLToPath(packageScript), ...args], {
    cwd: fileURLToPath(repositoryRoot),
    encoding: "utf8"
  });
}

function archiveEntries(archive) {
  const endOffset = archive.length - 22;
  assert.equal(archive.readUInt32LE(endOffset), 0x06054b50);
  const count = archive.readUInt16LE(endOffset + 10);
  let offset = archive.readUInt32LE(endOffset + 16);
  const entries = new Map();
  for (let index = 0; index < count; index += 1) {
    assert.equal(archive.readUInt32LE(offset), 0x02014b50);
    const size = archive.readUInt32LE(offset + 20);
    const nameLength = archive.readUInt16LE(offset + 28);
    const extraLength = archive.readUInt16LE(offset + 30);
    const commentLength = archive.readUInt16LE(offset + 32);
    const localOffset = archive.readUInt32LE(offset + 42);
    const name = archive.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");
    const localNameLength = archive.readUInt16LE(localOffset + 26);
    const localExtraLength = archive.readUInt16LE(localOffset + 28);
    const dataOffset = localOffset + 30 + localNameLength + localExtraLength;
    entries.set(name, archive.subarray(dataOffset, dataOffset + size));
    offset += 46 + nameLength + extraLength + commentLength;
  }
  return entries;
}

test("builds a reproducible allowlisted extension ZIP", () => {
  assert.match(runPackager(), new RegExp(`Created .*unveily-${packageJson.version.replaceAll(".", "\\.")}\\.zip`));
  const first = readFileSync(fileURLToPath(packagePath));
  assert.match(runPackager("--verify"), new RegExp(`Verified .*unveily-${packageJson.version.replaceAll(".", "\\.")}\\.zip`));
  runPackager();
  const second = readFileSync(fileURLToPath(packagePath));
  assert.deepEqual(second, first);

  const entries = archiveEntries(first);
  for (const required of [
    "manifest.json",
    "LICENSE",
    "THIRD_PARTY_NOTICES.md",
    "icons/icon.png",
    "_locales/ko/messages.json",
    "_locales/en/messages.json",
    "src/background.js",
    "src/content.js",
    "src/popup.html"
  ]) {
    assert.ok(entries.has(required), `missing packaged file ${required}`);
  }
  for (const name of entries.keys()) {
    assert.doesNotMatch(name, /(?:^|\/)(?:test|node_modules|scripts|\.git)(?:\/|$)/);
    assert.notEqual(name, "package.json");
    assert.notEqual(name, "package-lock.json");
  }

  const manifest = JSON.parse(entries.get("manifest.json").toString("utf8"));
  assert.equal(manifest.version, packageJson.version);
  assert.equal(manifest.background.service_worker, "src/background.js");
  assert.equal(manifest.action.default_popup, "src/popup.html");
});
