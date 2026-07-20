import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { promisify } from "node:util";
import test from "node:test";

const execFileAsync = promisify(execFile);

const ENTRYPOINTS = [
  ["popup", new URL("../src/popup.js", import.meta.url)],
  ["options", new URL("../src/options.js", import.meta.url)]
];

const ESM_IMPORT_HARNESS = String.raw`
const entrypointUrl = process.argv.at(-1);
const calls = [];
const propertyReads = [];

class ElementStub {
  constructor() {
    this.attributes = new Map();
    this.checked = false;
    this.classList = { toggle() {} };
    this.dataset = {};
    this.disabled = false;
    this.hidden = false;
    this.innerHTML = "";
    this.textContent = "";
    this.value = "";
  }

  addEventListener() {}
  closest() { return null; }
  focus() {}
  getAttribute(name) { return this.attributes.get(name) ?? null; }
  reset() {}
  setAttribute(name, value) { this.attributes.set(name, String(value)); }
}

const elements = new Map();
const elementFor = (selector) => {
  if (!elements.has(selector)) elements.set(selector, new ElementStub());
  return elements.get(selector);
};
const titleElement = elementFor("title");
titleElement.dataset.i18n = "appName";

globalThis.document = {
  documentElement: new ElementStub(),
  title: "",
  createElement: () => new ElementStub(),
  querySelector(selector) {
    if (selector === "title" || selector.startsWith("#")) return elementFor(selector);
    return null;
  },
  querySelectorAll(selector) {
    if (selector === "input, textarea, select, button") return [...elements.values()];
    return [];
  }
};
globalThis.window = globalThis;
Object.defineProperty(globalThis, "navigator", {
  configurable: true,
  value: { language: "en-US", languages: ["en-US"] }
});
globalThis.confirm = () => false;

const implementations = {
  async setAccessLevel(details) {
    calls.push({ method: "setAccessLevel", args: [details] });
    throw new Error("simulated access-level failure");
  },
  async get(...args) {
    calls.push({ method: "get", args });
    return {};
  },
  async set(...args) {
    calls.push({ method: "set", args });
  },
  async remove(...args) {
    calls.push({ method: "remove", args });
  },
  async clear(...args) {
    calls.push({ method: "clear", args });
  }
};
const local = new Proxy({}, {
  get(_target, property) {
    if (typeof property === "string" && Object.hasOwn(implementations, property)) {
      propertyReads.push(property);
      return implementations[property];
    }
    return undefined;
  }
});

globalThis.chrome = {
  i18n: {
    getMessage: () => "",
    getUILanguage: () => "en-US"
  },
  runtime: { lastError: null },
  storage: { local },
  tabs: { query: async () => [] }
};

await import(entrypointUrl);
await new Promise((resolve) => setTimeout(resolve, 25));
process.stdout.write(JSON.stringify({ calls, propertyReads }));
`;

test("extension pages import the shared gate from its real ESM module", async () => {
  for (const [name, entrypointUrl] of ENTRYPOINTS) {
    const source = await readFile(entrypointUrl, "utf8");
    assert.match(
      source,
      /import\s*\{\s*ensureTrustedLocalStorage\s*\}\s*from\s*["']\.\/trustedLocalStorage\.js["']\s*;/,
      `${name} must import ensureTrustedLocalStorage directly from the shared helper`
    );
  }
});

for (const [name, entrypointUrl] of ENTRYPOINTS) {
  test(`${name} linked ESM graph reaches the gate before local-storage data APIs`, async () => {
    const { stdout, stderr } = await execFileAsync(
      process.execPath,
      ["--input-type=module", "--eval", ESM_IMPORT_HARNESS, entrypointUrl.href],
      { maxBuffer: 1024 * 1024 }
    );
    assert.equal(stderr, "");

    const { calls, propertyReads } = JSON.parse(stdout);
    assert.deepEqual(calls, [
      {
        method: "setAccessLevel",
        args: [{ accessLevel: "TRUSTED_CONTEXTS" }]
      }
    ]);
    assert.equal(propertyReads[0], "setAccessLevel");
    assert.equal(propertyReads.includes("get"), false);
    assert.equal(propertyReads.includes("set"), false);
    assert.equal(propertyReads.includes("remove"), false);
    assert.equal(propertyReads.includes("clear"), false);
  });
}
