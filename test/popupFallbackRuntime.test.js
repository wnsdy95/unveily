import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const popupSource = await readFile(new URL("../src/popup.js", import.meta.url), "utf8");

class MockElement {
  constructor(tagName, attributes = {}) {
    this.tagName = tagName.toUpperCase();
    this.nodeType = 1;
    this.childNodes = [];
    this.parentNode = null;
    this.parentElement = null;
    this.hidden = false;
    this.id = "";
    this.className = "";
    this.labels = [];
    this.type = "";
    this.required = false;
    this.checked = false;
    this.attributes = new Map(Object.entries(attributes));
    this.isContentEditable = attributes.isContentEditable === true;
    this._style = {};
  }

  appendChild(node) {
    node.parentNode = this;
    node.parentElement = this;
    this.childNodes.push(node);
    return node;
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  getRootNode() {
    let current = this;
    while (current?.parentNode) current = current.parentNode;
    return current;
  }

  matches(selector) {
    if (selector.includes("main, article, section")) {
      return this.tagName === "BODY" || this.tagName === "SECTION";
    }
    if (selector === "input, textarea, select") {
      return ["INPUT", "TEXTAREA", "SELECT"].includes(this.tagName);
    }
    return false;
  }
}

class MockText {
  constructor(value) {
    this.nodeType = 3;
    this.nodeValue = value;
    this.childNodes = [];
    this.parentNode = null;
    this.parentElement = null;
  }
}

class MockDocument {
  constructor(documentElement, body, counter) {
    this.documentElement = documentElement;
    this.body = body;
    this.title = "Fallback stress page";
    this.counter = counter;
    this.designMode = "off";
  }

  createTreeWalker(root) {
    let current = root;
    const counter = this.counter;
    return {
      nextNode() {
        counter.walkerCalls += 1;
        if (current?.childNodes?.length) {
          current = current.childNodes[0];
          return current;
        }
        while (current && current !== root) {
          const parent = current.parentNode;
          const index = parent.childNodes.indexOf(current);
          if (index + 1 < parent.childNodes.length) {
            current = parent.childNodes[index + 1];
            return current;
          }
          current = parent;
        }
        current = null;
        return null;
      }
    };
  }

  getElementById() {
    return null;
  }
}

function executeFallback(document, counter) {
  const start = popupSource.indexOf("function extractTextFallbackFromPage() {");
  const end = popupSource.indexOf("\nfunction collectPageDataByScripting", start);
  assert.ok(start >= 0 && end > start, "fallback extractor source should be available");
  const emptyStorage = {
    length: 0,
    key() {
      return null;
    }
  };
  const sandbox = {
    Date,
    Document: MockDocument,
    Element: MockElement,
    Intl,
    Map,
    NodeFilter: { SHOW_ALL: 0xffffffff },
    URL,
    WeakMap,
    document,
    globalThis: null,
    location: {
      href: "https://fallback.example/privacy",
      hostname: "fallback.example"
    },
    navigator: { language: "en", languages: ["en"] },
    performance: { now: () => 0 },
    window: {
      getComputedStyle(element) {
        counter.styleReads += 1;
        return {
          display: "block",
          visibility: "visible",
          opacity: "1",
          contentVisibility: "visible",
          ...element?._style
        };
      },
      localStorage: emptyStorage,
      sessionStorage: emptyStorage
    }
  };
  sandbox.globalThis = sandbox;
  const extract = vm.runInNewContext(`(${popupSource.slice(start, end)})`, sandbox, {
    filename: "popup-fallback-runtime.js"
  });
  return extract();
}

test("popup fallback enforces one total budget across adversarial nested readable candidates", () => {
  const counter = { walkerCalls: 0, styleReads: 0 };
  const html = new MockElement("html");
  const body = html.appendChild(new MockElement("body"));
  let current = body;
  for (let index = 0; index < 80; index += 1) {
    current = current.appendChild(new MockElement("section"));
  }
  for (let index = 0; index < 5_000; index += 1) {
    current = current.appendChild(new MockElement("div"));
  }
  current.appendChild(new MockText("privacy policy personal data retention period"));
  const document = new MockDocument(html, body, counter);
  const result = executeFallback(document, counter);

  assert.equal(result.url, "https://fallback.example/privacy");
  assert.ok(counter.walkerCalls <= 100_000, `walker calls exceeded cap: ${counter.walkerCalls}`);
  assert.ok(counter.styleReads <= 30_000, `style reads exceeded cap: ${counter.styleReads}`);
  assert.equal(Array.isArray(result.forms.fields), true);
  assert.equal(Array.isArray(result.consent.containers), true);
});

test("popup fallback slices a huge text node before joining bounded output", () => {
  const counter = { walkerCalls: 0, styleReads: 0 };
  const html = new MockElement("html");
  const body = html.appendChild(new MockElement("body"));
  body.appendChild(new MockText(`privacy policy ${"x".repeat(2_000_000)}`));
  const result = executeFallback(new MockDocument(html, body, counter), counter);

  assert.equal(result.text.length, 120_000);
  assert.match(result.text, /^privacy policy /);
  assert.ok(counter.walkerCalls < 100, `unexpected repeated traversal: ${counter.walkerCalls}`);
});

test("popup fallback omits editable and form-control text while retaining value-free form metadata", () => {
  const counter = { walkerCalls: 0, styleReads: 0 };
  const html = new MockElement("html");
  const body = html.appendChild(new MockElement("body"));
  body.appendChild(new MockText("Privacy policy. We explain personal data retention and third-party sharing."));

  const textarea = body.appendChild(new MockElement("textarea", { name: "message" }));
  textarea.appendChild(new MockText("TEXTAREA_PRIVATE_SENTINEL"));
  const inheritedEditor = body.appendChild(new MockElement("div", { contenteditable: "true" }));
  inheritedEditor.appendChild(new MockElement("span")).appendChild(new MockText("EDITABLE_PRIVATE_SENTINEL"));
  body.appendChild(new MockElement("div", { role: "textbox" })).appendChild(new MockText("ROLE_PRIVATE_SENTINEL"));
  const select = body.appendChild(new MockElement("select", { name: "region" }));
  select.appendChild(new MockElement("option")).appendChild(new MockText("OPTION_PRIVATE_SENTINEL"));
  const cssEditor = body.appendChild(new MockElement("div"));
  cssEditor._style.webkitUserModify = "read-write";
  cssEditor.appendChild(new MockText("CSS_EDITOR_PRIVATE_SENTINEL"));

  const result = executeFallback(new MockDocument(html, body, counter), counter);

  assert.match(result.text, /Privacy policy/);
  for (const sentinel of [
    "TEXTAREA_PRIVATE_SENTINEL",
    "EDITABLE_PRIVATE_SENTINEL",
    "ROLE_PRIVATE_SENTINEL",
    "OPTION_PRIVATE_SENTINEL",
    "CSS_EDITOR_PRIVATE_SENTINEL"
  ]) {
    assert.doesNotMatch(result.text, new RegExp(sentinel));
    assert.doesNotMatch(JSON.stringify(result.forms), new RegExp(sentinel));
  }
  assert.deepEqual(
    Array.from(result.forms.fields, (field) => ({ tag: field.tag, name: field.name })),
    [
      { tag: "textarea", name: "message" },
      { tag: "select", name: "region" }
    ]
  );
});

test("popup fallback omits all page text in document design mode", () => {
  const counter = { walkerCalls: 0, styleReads: 0 };
  const html = new MockElement("html");
  const body = html.appendChild(new MockElement("body"));
  body.appendChild(new MockText("DESIGN_MODE_PRIVATE_SENTINEL privacy policy"));
  const document = new MockDocument(html, body, counter);
  document.designMode = "on";

  const result = executeFallback(document, counter);
  assert.equal(result.text, "");
});
