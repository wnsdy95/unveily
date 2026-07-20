import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import vm from "node:vm";

const source = await readFile(new URL("../src/domWorkLimits.js", import.meta.url), "utf8");

function loadDomWorkLimits() {
  const sandbox = {};
  vm.runInNewContext(source, sandbox, { filename: "domWorkLimits.js" });
  return sandbox.__unveilyDomWorkLimits;
}

test("DOM work contexts enforce one aggregate node, style, and elapsed-time budget", () => {
  const api = loadDomWorkLimits();
  const nodeContext = api.createContext({
    maxNodes: 25,
    maxStyles: 10,
    maxElapsedMs: 100,
    now: () => 0
  });

  let accepted = 0;
  for (let candidate = 0; candidate < 80; candidate += 1) {
    for (let visited = 0; visited < 2_000; visited += 1) {
      if (!nodeContext.budget.takeNode()) break;
      accepted += 1;
    }
  }
  assert.equal(accepted, 25);
  assert.deepEqual({ ...nodeContext.budget.snapshot() }, {
    nodes: 25,
    styles: 0,
    maxNodes: 25,
    maxStyles: 10,
    maxElapsedMs: 100,
    exhausted: true,
    reason: "nodes"
  });

  const styleContext = api.createContext({
    maxNodes: 100,
    maxStyles: 3,
    maxElapsedMs: 100,
    now: () => 0
  });
  assert.equal(styleContext.budget.takeStyle(), true);
  assert.equal(styleContext.budget.takeStyle(), true);
  assert.equal(styleContext.budget.takeStyle(), true);
  assert.equal(styleContext.budget.takeStyle(), false);
  assert.equal(styleContext.budget.reason, "styles");

  let now = 0;
  const timedContext = api.createContext({
    maxNodes: 100,
    maxStyles: 100,
    maxElapsedMs: 10,
    now: () => now
  });
  assert.equal(timedContext.budget.takeNode(), true);
  now = 10;
  assert.equal(timedContext.budget.check(), false);
  assert.equal(timedContext.budget.reason, "time");
});

test("shared visibility cache and budget fail safely on maliciously deep candidate trees", () => {
  const api = loadDomWorkLimits();

  function inspectVisibility(element, context) {
    const ancestors = [];
    let current = element;
    while (current) {
      if (context.visibilityCache.has(current)) {
        return context.visibilityCache.get(current);
      }
      if (!context.budget.takeNode() || !context.budget.takeStyle()) return false;
      ancestors.push(current);
      current = current.parent;
    }
    ancestors.forEach((ancestor) => context.visibilityCache.set(ancestor, true));
    return true;
  }

  let shallow = null;
  for (let depth = 0; depth < 30; depth += 1) shallow = { parent: shallow };
  const cachedContext = api.createContext({
    maxNodes: 100,
    maxStyles: 100,
    maxElapsedMs: 100,
    now: () => 0
  });
  assert.equal(inspectVisibility(shallow, cachedContext), true);
  const firstSnapshot = { ...cachedContext.budget.snapshot() };
  assert.equal(inspectVisibility(shallow, cachedContext), true);
  assert.deepEqual({ ...cachedContext.budget.snapshot() }, firstSnapshot);

  let malicious = null;
  for (let depth = 0; depth < 10_000; depth += 1) malicious = { parent: malicious };
  const boundedContext = api.createContext({
    maxNodes: 80,
    maxStyles: 64,
    maxElapsedMs: 100,
    now: () => 0
  });
  for (let candidate = 0; candidate < 80; candidate += 1) {
    assert.equal(inspectVisibility(malicious, boundedContext), false);
  }
  const snapshot = boundedContext.budget.snapshot();
  assert.ok(snapshot.nodes <= 80);
  assert.ok(snapshot.styles <= 64);
  assert.equal(snapshot.exhausted, true);
  assert.equal(snapshot.reason, "styles");
});

test("mutation root collection bounds records and added nodes even when none are elements", () => {
  const api = loadDomWorkLimits();
  let addedNodesReads = 0;
  const records = Array.from({ length: 10_000 }, () => ({
    type: "childList",
    get addedNodes() {
      addedNodesReads += 1;
      return Array.from({ length: 10_000 }, () => ({ nodeType: 3 }));
    }
  }));

  const roots = api.collectMutationRoots(records, (node) => node?.nodeType === 1, {
    maxRecords: 64,
    maxAddedNodes: 64,
    maxRoots: 8
  });
  assert.deepEqual(Array.from(roots), []);
  assert.equal(addedNodesReads, 1);

  const elementRoots = Array.from({ length: 100 }, (_, index) => ({
    type: "attributes",
    target: { nodeType: 1, index },
    addedNodes: []
  }));
  assert.equal(
    api.collectMutationRoots(elementRoots, (node) => node?.nodeType === 1, {
      maxRecords: 64,
      maxAddedNodes: 64,
      maxRoots: 8
    }).length,
    8
  );
});

test("mutation root collection rechecks a childList parent when text or controls are inserted", () => {
  const api = loadDomWorkLimits();
  const container = { nodeType: 1, id: "cookie-banner" };
  const button = { nodeType: 1, id: "reject-button" };
  const roots = api.collectMutationRoots(
    [
      { type: "childList", target: container, addedNodes: [{ nodeType: 3 }] },
      { type: "childList", target: container, addedNodes: [button] }
    ],
    (node) => node?.nodeType === 1,
    { maxRecords: 64, maxAddedNodes: 64, maxRoots: 8 }
  );

  assert.deepEqual(Array.from(roots), [container, button]);
});
