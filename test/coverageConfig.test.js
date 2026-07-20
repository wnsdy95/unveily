import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const packageJson = JSON.parse(await readFile(new URL("../package.json", import.meta.url), "utf8"));
const workflow = await readFile(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8");
const backgroundGate = await readFile(
  new URL("../scripts/check-background-coverage.mjs", import.meta.url),
  "utf8"
);

test("keeps the core coverage gate and separately measures the background entrypoint", () => {
  assert.match(packageJson.scripts["test:coverage"], /--test-coverage-lines=80/);
  assert.match(packageJson.scripts["test:coverage"], /--test-coverage-branches=70/);
  assert.match(packageJson.scripts["test:coverage"], /--test-coverage-functions=80/);
  assert.match(packageJson.scripts["test:coverage"], /--test-coverage-exclude='src\/background\.js'/);
  assert.equal(
    packageJson.scripts["test:coverage:background"],
    "node scripts/check-background-coverage.mjs"
  );

  assert.match(backgroundGate, /--test-coverage-include=src\/background\.js/);
  assert.match(backgroundGate, /--test-concurrency=1/);
  assert.match(backgroundGate, /lines:\s*39/);
  assert.match(backgroundGate, /branches:\s*38/);
  assert.match(backgroundGate, /functions:\s*44/);
  assert.match(backgroundGate, /test\/backgroundRuntime\.test\.js/);
  assert.match(backgroundGate, /test\/backgroundCookieRuntime\.test\.js/);
  assert.match(backgroundGate, /test\/backgroundInitializationRuntime\.test\.js/);
  assert.match(backgroundGate, /background\\\.js\\s\*\\\|/);
  assert.match(backgroundGate, /all files\\s\*\\\|/);
  assert.match(backgroundGate, /Background coverage gate verified background\.js aggregate/);

  assert.match(workflow, /run:\s*npm run test:coverage\s/);
  assert.match(workflow, /run:\s*npm run test:coverage:background/);
});

test("syntax-checks extension sources and repository scripts with a portable shell loop", () => {
  assert.match(packageJson.scripts.check, /for file in src\/\*\.js scripts\/\*\.mjs/);
  assert.match(packageJson.scripts.check, /\[ -f \"\$file\" \] \|\| continue/);
  assert.match(packageJson.scripts.check, /node --check \"\$file\" \|\| exit 1/);
  assert.match(workflow, /run:\s*npm run check/);
});
