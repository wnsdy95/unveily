import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { lstat, mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname, join, posix, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const REPOSITORY_ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const FIXED_DOS_TIME = 0;
const FIXED_DOS_DATE = 0x21; // 1980-01-01, the earliest ZIP timestamp.
const UTF8_FLAG = 0x0800;
const STORED_METHOD = 0;

const EXTENSION_FILES = Object.freeze([
  "LICENSE",
  "THIRD_PARTY_NOTICES.md",
  "_locales/en/messages.json",
  "_locales/ko/messages.json",
  "icons/icon.png",
  "manifest.json",
  "src/analyzer.js",
  "src/background.js",
  "src/backgroundSecurity.js",
  "src/companionOverlay.js",
  "src/companionOverlayRuntime.js",
  "src/companionRuntime.js",
  "src/companionSettings.js",
  "src/content.js",
  "src/customRulesStorage.js",
  "src/domWorkLimits.js",
  "src/i18n.js",
  "src/observationSettings.js",
  "src/options.css",
  "src/options.html",
  "src/options.js",
  "src/policyMonitor.js",
  "src/policySnapshots.js",
  "src/popup.css",
  "src/popup.html",
  "src/popup.js",
  "src/publicSuffixRules.js",
  "src/report.js",
  "src/riskColor.js",
  "src/runtimeLimits.js",
  "src/trustedLocalStorage.js",
  "src/vendorRules.js"
].sort());

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = value & 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(buffer) {
  let crc = 0xffffffff;
  for (const byte of buffer) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function safeArchivePath(value) {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    value.length <= 240 &&
    !value.startsWith("/") &&
    !value.includes("\\") &&
    !value.split("/").includes("..") &&
    posix.normalize(value) === value
  );
}

function manifestReferences(manifest) {
  const references = new Set();
  const add = (value) => {
    if (typeof value === "string" && value) references.add(value);
  };
  add(manifest.background?.service_worker);
  add(manifest.action?.default_popup);
  add(manifest.options_page);
  for (const value of Object.values(manifest.action?.default_icon || {})) add(value);
  for (const value of Object.values(manifest.icons || {})) add(value);
  for (const contentScript of manifest.content_scripts || []) {
    for (const value of contentScript?.js || []) add(value);
    for (const value of contentScript?.css || []) add(value);
  }
  return references;
}

function relativeCodeReferences(fileName, source) {
  const references = new Set();
  const patterns = [
    /(?:from\s+|import\s*\()\s*["'](\.[^"']+)["']/g,
    /\bimport\s*["'](\.[^"']+)["']/g,
    /<(?:script|link)\b[^>]*(?:src|href)=["']([^"']+)["']/gi
  ];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) {
      const reference = match[1];
      if (!reference.startsWith(".")) continue;
      references.add(posix.normalize(posix.join(posix.dirname(fileName), reference)));
    }
  }
  return references;
}

async function loadExtensionEntries() {
  const packageJson = JSON.parse(await readFile(join(REPOSITORY_ROOT, "package.json"), "utf8"));
  const manifest = JSON.parse(await readFile(join(REPOSITORY_ROOT, "manifest.json"), "utf8"));
  assert.equal(manifest.version, packageJson.version, "package and manifest versions must match");

  const expected = new Set(EXTENSION_FILES);
  for (const reference of manifestReferences(manifest)) {
    assert.ok(expected.has(reference), `manifest reference is missing from the package: ${reference}`);
  }

  const entries = [];
  for (const name of EXTENSION_FILES) {
    assert.ok(safeArchivePath(name), `unsafe package path: ${name}`);
    const sourcePath = resolve(REPOSITORY_ROOT, name);
    const metadata = await lstat(sourcePath);
    assert.ok(metadata.isFile() && !metadata.isSymbolicLink(), `package entry must be a regular file: ${name}`);
    const data = await readFile(sourcePath);
    assert.ok(data.length <= 12 * 1024 * 1024, `package file is unexpectedly large: ${name}`);
    entries.push({ name, data });
  }

  for (const entry of entries) {
    if (!/\.(?:html|js)$/u.test(entry.name)) continue;
    const source = entry.data.toString("utf8");
    for (const reference of relativeCodeReferences(entry.name, source)) {
      assert.ok(expected.has(reference), `${entry.name} references unpackaged file ${reference}`);
    }
  }
  return { entries, version: packageJson.version };
}

function localHeader(name, data) {
  const nameBuffer = Buffer.from(name, "utf8");
  const header = Buffer.alloc(30);
  header.writeUInt32LE(0x04034b50, 0);
  header.writeUInt16LE(20, 4);
  header.writeUInt16LE(UTF8_FLAG, 6);
  header.writeUInt16LE(STORED_METHOD, 8);
  header.writeUInt16LE(FIXED_DOS_TIME, 10);
  header.writeUInt16LE(FIXED_DOS_DATE, 12);
  header.writeUInt32LE(crc32(data), 14);
  header.writeUInt32LE(data.length, 18);
  header.writeUInt32LE(data.length, 22);
  header.writeUInt16LE(nameBuffer.length, 26);
  header.writeUInt16LE(0, 28);
  return Buffer.concat([header, nameBuffer, data]);
}

function centralHeader(name, data, localOffset) {
  const nameBuffer = Buffer.from(name, "utf8");
  const header = Buffer.alloc(46);
  header.writeUInt32LE(0x02014b50, 0);
  header.writeUInt16LE(0x0314, 4);
  header.writeUInt16LE(20, 6);
  header.writeUInt16LE(UTF8_FLAG, 8);
  header.writeUInt16LE(STORED_METHOD, 10);
  header.writeUInt16LE(FIXED_DOS_TIME, 12);
  header.writeUInt16LE(FIXED_DOS_DATE, 14);
  header.writeUInt32LE(crc32(data), 16);
  header.writeUInt32LE(data.length, 20);
  header.writeUInt32LE(data.length, 24);
  header.writeUInt16LE(nameBuffer.length, 28);
  header.writeUInt16LE(0, 30);
  header.writeUInt16LE(0, 32);
  header.writeUInt16LE(0, 34);
  header.writeUInt16LE(0, 36);
  header.writeUInt32LE((0o100644 << 16) >>> 0, 38);
  header.writeUInt32LE(localOffset, 42);
  return Buffer.concat([header, nameBuffer]);
}

function createArchive(entries) {
  assert.ok(entries.length > 0 && entries.length < 0xffff, "invalid package entry count");
  const localParts = [];
  const centralParts = [];
  let localOffset = 0;
  for (const { name, data } of entries) {
    const local = localHeader(name, data);
    localParts.push(local);
    centralParts.push(centralHeader(name, data, localOffset));
    localOffset += local.length;
  }
  const centralDirectory = Buffer.concat(centralParts);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(0, 4);
  end.writeUInt16LE(0, 6);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralDirectory.length, 12);
  end.writeUInt32LE(localOffset, 16);
  end.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, centralDirectory, end]);
}

function validateArchive(archive, expectedEntries) {
  assert.ok(archive.length >= 22, "package is not a ZIP archive");
  const endOffset = archive.length - 22;
  assert.equal(archive.readUInt32LE(endOffset), 0x06054b50, "ZIP end record is missing");
  const entryCount = archive.readUInt16LE(endOffset + 10);
  const centralSize = archive.readUInt32LE(endOffset + 12);
  const centralOffset = archive.readUInt32LE(endOffset + 16);
  assert.equal(entryCount, expectedEntries.length, "ZIP entry count mismatch");
  assert.equal(centralOffset + centralSize, endOffset, "ZIP central directory bounds mismatch");

  const expectedByName = new Map(expectedEntries.map((entry) => [entry.name, entry.data]));
  const names = [];
  let offset = centralOffset;
  for (let index = 0; index < entryCount; index += 1) {
    assert.equal(archive.readUInt32LE(offset), 0x02014b50, "invalid central directory entry");
    assert.equal(archive.readUInt16LE(offset + 10), STORED_METHOD, "unexpected ZIP compression");
    const checksum = archive.readUInt32LE(offset + 16);
    const compressedSize = archive.readUInt32LE(offset + 20);
    const uncompressedSize = archive.readUInt32LE(offset + 24);
    const nameLength = archive.readUInt16LE(offset + 28);
    const extraLength = archive.readUInt16LE(offset + 30);
    const commentLength = archive.readUInt16LE(offset + 32);
    const localOffset = archive.readUInt32LE(offset + 42);
    const name = archive.subarray(offset + 46, offset + 46 + nameLength).toString("utf8");
    assert.ok(safeArchivePath(name), `unsafe ZIP entry: ${name}`);
    assert.equal(archive.readUInt32LE(localOffset), 0x04034b50, `invalid local entry: ${name}`);
    const localNameLength = archive.readUInt16LE(localOffset + 26);
    const localExtraLength = archive.readUInt16LE(localOffset + 28);
    const localName = archive
      .subarray(localOffset + 30, localOffset + 30 + localNameLength)
      .toString("utf8");
    assert.equal(localName, name, `ZIP entry name mismatch: ${name}`);
    const dataOffset = localOffset + 30 + localNameLength + localExtraLength;
    const data = archive.subarray(dataOffset, dataOffset + compressedSize);
    assert.equal(compressedSize, uncompressedSize, `stored entry size mismatch: ${name}`);
    assert.equal(crc32(data), checksum, `ZIP checksum mismatch: ${name}`);
    assert.deepEqual(data, expectedByName.get(name), `ZIP content mismatch: ${name}`);
    names.push(name);
    offset += 46 + nameLength + extraLength + commentLength;
  }
  assert.deepEqual(names, expectedEntries.map((entry) => entry.name), "ZIP entries are not deterministic");
  assert.equal(offset, endOffset, "ZIP central directory was not consumed exactly");
}

const { entries, version } = await loadExtensionEntries();
const archive = createArchive(entries);
validateArchive(archive, entries);
const outputPath = join(REPOSITORY_ROOT, "dist", `unveily-${version}.zip`);

if (process.argv.includes("--verify")) {
  const existing = await readFile(outputPath);
  validateArchive(existing, entries);
  assert.deepEqual(existing, archive, "existing package is not reproducible from the current source");
} else {
  await mkdir(dirname(outputPath), { recursive: true });
  const temporaryPath = `${outputPath}.${process.pid}.tmp`;
  try {
    await writeFile(temporaryPath, archive, { flag: "wx" });
    await rename(temporaryPath, outputPath);
  } finally {
    await rm(temporaryPath, { force: true });
  }
}

const digest = createHash("sha256").update(archive).digest("hex");
process.stdout.write(
  `${process.argv.includes("--verify") ? "Verified" : "Created"} ${outputPath} (${entries.length} files, sha256 ${digest})\n`
);
