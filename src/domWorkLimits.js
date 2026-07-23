(() => {
  if (
    globalThis.__unveilyDomWorkLimits?.createContext &&
    globalThis.__unveilyDomWorkLimits?.collectMutationRoots
  ) {
    return;
  }

  function positiveLimit(value, fallback) {
    const numeric = Number(value);
    return Number.isFinite(numeric) && numeric > 0 ? Math.floor(numeric) : fallback;
  }

  function defaultNow() {
    try {
      if (typeof globalThis.performance?.now === "function") return globalThis.performance.now();
    } catch {
      // Date.now remains available in older or restricted execution contexts.
    }
    return Date.now();
  }

  function createBudget(options = {}) {
    const maxNodes = positiveLimit(options.maxNodes, 50_000);
    const maxStyles = positiveLimit(options.maxStyles, 12_000);
    const maxElapsedMs = positiveLimit(options.maxElapsedMs, 75);
    const now = typeof options.now === "function" ? options.now : defaultNow;
    let startedAt = 0;
    let initialClockFailure = false;
    try {
      startedAt = Number(now());
      if (!Number.isFinite(startedAt)) initialClockFailure = true;
    } catch {
      initialClockFailure = true;
    }
    let nodes = 0;
    let styles = 0;
    let exhaustedReason = initialClockFailure ? "time" : "";

    function withinTime() {
      if (exhaustedReason) return false;
      let elapsed;
      try {
        elapsed = Math.max(0, Number(now()) - Number(startedAt));
      } catch {
        exhaustedReason = "time";
        return false;
      }
      if (!Number.isFinite(elapsed) || elapsed >= maxElapsedMs) {
        exhaustedReason = "time";
        return false;
      }
      return true;
    }

    function take(kind, count = 1) {
      const amount = positiveLimit(count, 1);
      if (!withinTime()) return false;
      if (kind === "nodes") {
        if (nodes + amount > maxNodes) {
          exhaustedReason = "nodes";
          return false;
        }
        nodes += amount;
        return true;
      }
      if (styles + amount > maxStyles) {
        exhaustedReason = "styles";
        return false;
      }
      styles += amount;
      return true;
    }

    return Object.freeze({
      takeNode(count) {
        return take("nodes", count);
      },
      takeStyle(count) {
        return take("styles", count);
      },
      check() {
        return withinTime();
      },
      snapshot() {
        withinTime();
        return Object.freeze({
          nodes,
          styles,
          maxNodes,
          maxStyles,
          maxElapsedMs,
          exhausted: Boolean(exhaustedReason),
          reason: exhaustedReason || null
        });
      },
      get exhausted() {
        return !withinTime();
      },
      get reason() {
        withinTime();
        return exhaustedReason || null;
      }
    });
  }

  function createContext(options = {}) {
    return {
      budget: createBudget(options),
      visibilityCache: new WeakMap(),
      closestCache: new WeakMap(),
      textCache: new WeakMap(),
      userInputCache: new WeakMap(),
      userInputStyleCache: new WeakMap(),
      headingHintCount: null
    };
  }

  function collectMutationRoots(records, isElement, options = {}) {
    if (typeof isElement !== "function") return [];
    const maxRecords = positiveLimit(options.maxRecords, 64);
    const maxAddedNodes = positiveLimit(options.maxAddedNodes, 64);
    const maxRoots = positiveLimit(options.maxRoots, 8);
    const roots = [];
    const seenRoots = new Set();
    let inspectedRecords = 0;
    let inspectedAddedNodes = 0;

    function addRoot(node) {
      if (!isElement(node) || seenRoots.has(node) || roots.length >= maxRoots) return;
      seenRoots.add(node);
      roots.push(node);
    }

    for (const record of records || []) {
      if (inspectedRecords >= maxRecords || roots.length >= maxRoots) break;
      inspectedRecords += 1;
      if (record?.type === "attributes" || record?.type === "childList") {
        addRoot(record.target);
      }
      if (inspectedAddedNodes >= maxAddedNodes || roots.length >= maxRoots) continue;
      for (const node of record?.addedNodes || []) {
        if (inspectedAddedNodes >= maxAddedNodes || roots.length >= maxRoots) break;
        inspectedAddedNodes += 1;
        addRoot(node);
      }
    }
    return roots;
  }

  const api = Object.freeze({ createBudget, createContext, collectMutationRoots });
  try {
    Object.defineProperty(globalThis, "__unveilyDomWorkLimits", {
      value: api,
      configurable: false,
      enumerable: false,
      writable: false
    });
  } catch {
    globalThis.__unveilyDomWorkLimits = api;
  }
})();
