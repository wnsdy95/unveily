import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import test from "node:test";

import { createCookieChangeQueue, createTabRequestTokenBucket } from "../src/runtimeLimits.js";

test("tab request buckets bound bursts, refill gradually, and evict idle or oldest tabs", () => {
  const limiter = createTabRequestTokenBucket({
    capacity: 3,
    refillPerSecond: 2,
    maxEntries: 2,
    idleTtlMs: 1_000
  });

  assert.equal(limiter.allow(1, 0), true);
  assert.equal(limiter.allow(1, 0), true);
  assert.equal(limiter.allow(1, 0), true);
  assert.equal(limiter.allow(1, 0), false);
  assert.equal(limiter.allow(1, 499), false);
  assert.equal(limiter.allow(1, 500), true);

  assert.equal(limiter.allow(2, 600), true);
  assert.equal(limiter.size, 2);
  assert.equal(limiter.allow(3, 700), true);
  assert.equal(limiter.size, 2);
  assert.equal(limiter.allow(1, 700), true, "the oldest evicted tab should receive a fresh bounded burst");
  assert.equal(limiter.size, 2);

  assert.equal(limiter.allow(4, 2_000), true);
  assert.equal(limiter.size, 1, "idle buckets should be removed when a new tab arrives");
  assert.equal(limiter.delete(4), true);
  assert.equal(limiter.allow(-1, 2_000), false);
  limiter.clear();
  assert.equal(limiter.size, 0);
});

test("cookie queue coalesces in O(1) indexes and preserves per-domain and fair global caps", () => {
  let identityCalls = 0;
  let domainCalls = 0;
  const queue = createCookieChangeQueue({
    maxSize: 5,
    maxPerDomain: 2,
    identityOf(value) {
      identityCalls += 1;
      return `${value.domain}:${value.id}`;
    },
    domainOf(value) {
      domainCalls += 1;
      return value.domain;
    }
  });

  queue.push({ domain: "quiet.test", id: "sentinel", removed: false });
  queue.push({ domain: "busy-a.test", id: "a", removed: false });
  queue.push({ domain: "busy-a.test", id: "b", removed: false });
  queue.push({ domain: "busy-b.test", id: "a", removed: false });
  queue.push({ domain: "busy-b.test", id: "b", removed: false });
  queue.push({ domain: "busy-a.test", id: "c", removed: false });
  queue.push({ domain: "busy-c.test", id: "a", removed: false });
  queue.push({ domain: "busy-b.test", id: "b", removed: true });

  assert.equal(identityCalls, 8);
  assert.equal(domainCalls, 8);
  assert.equal(queue.size, 5);
  assert.ok(queue.domainSize("busy-a.test") <= 2);
  assert.ok(queue.domainSize("busy-b.test") <= 2);

  const drained = queue.drain();
  assert.equal(drained.some((value) => value.id === "sentinel"), true);
  assert.equal(
    drained.filter((value) => value.domain === "busy-b.test" && value.id === "b").length,
    1
  );
  assert.equal(
    drained.find((value) => value.domain === "busy-b.test" && value.id === "b")?.removed,
    true
  );
  assert.equal(queue.size, 0);
});

test("cookie queue optionally merges repeated identities while defaulting to the latest value", () => {
  const queue = createCookieChangeQueue({
    maxSize: 5,
    maxPerDomain: 5,
    identityOf: (value) => `${value.domain}:${value.id}`,
    domainOf: (value) => value.domain,
    merge(existing, incoming) {
      return {
        ...incoming,
        firstObservedAt: Math.min(existing.firstObservedAt, incoming.firstObservedAt),
        lastObservedAt: Math.max(existing.lastObservedAt, incoming.lastObservedAt)
      };
    }
  });

  queue.push({
    domain: "merge.test",
    id: "session",
    firstObservedAt: 20,
    lastObservedAt: 30,
    removed: false
  });
  queue.push({
    domain: "merge.test",
    id: "session",
    firstObservedAt: 40,
    lastObservedAt: 50,
    removed: true
  });

  assert.deepEqual(queue.drain(), [
    {
      domain: "merge.test",
      id: "session",
      firstObservedAt: 20,
      lastObservedAt: 50,
      removed: true
    }
  ]);
});

test("cookie queue keeps high-volume enqueue work bounded", { timeout: 5_000 }, () => {
  let identityCalls = 0;
  let domainCalls = 0;
  const queue = createCookieChangeQueue({
    maxSize: 500,
    maxPerDomain: 50,
    identityOf(value) {
      identityCalls += 1;
      return `${value.domain}:${value.id}`;
    },
    domainOf(value) {
      domainCalls += 1;
      return value.domain;
    }
  });
  const iterations = 100_000;
  const startedAt = performance.now();
  for (let index = 0; index < iterations; index += 1) {
    queue.push({ domain: `queue${index % 11}.test`, id: String(index), removed: false });
  }
  const elapsedMilliseconds = performance.now() - startedAt;

  assert.equal(identityCalls, iterations);
  assert.equal(domainCalls, iterations);
  assert.equal(queue.size, 500);
  assert.ok(elapsedMilliseconds < 2_500, `cookie queue took ${elapsedMilliseconds.toFixed(0)}ms`);
});
