import assert from "node:assert/strict";
import test from "node:test";

import {
  ensureTrustedLocalStorage,
  withTrustedLocalStorage
} from "../src/trustedLocalStorage.js";

test("sets the trusted-context access level before a local-storage task", async () => {
  const operations = [];
  const storageArea = {
    async setAccessLevel(details) {
      operations.push(["setAccessLevel", details]);
    },
    async get(key) {
      operations.push(["get", key]);
      return { [key]: true };
    }
  };

  const value = await withTrustedLocalStorage(
    async (trustedStorage) => (await trustedStorage.get("sentinel")).sentinel,
    { storageArea }
  );

  assert.equal(value, true);
  assert.deepEqual(operations, [
    ["setAccessLevel", { accessLevel: "TRUSTED_CONTEXTS" }],
    ["get", "sentinel"]
  ]);
});

test("caches the access decision per storage area", async () => {
  let calls = 0;
  const storageArea = {
    async setAccessLevel() {
      calls += 1;
    }
  };

  const [first, second, third] = await Promise.all([
    ensureTrustedLocalStorage(storageArea),
    ensureTrustedLocalStorage(storageArea),
    ensureTrustedLocalStorage(storageArea)
  ]);

  assert.deepEqual([first, second, third], [true, true, true]);
  assert.equal(calls, 1);
});

test("fails closed without invoking a trusted task when access restriction fails", async () => {
  const operations = [];
  let trustedTaskCalls = 0;
  const storageArea = {
    async setAccessLevel() {
      operations.push("setAccessLevel");
      throw new Error("unavailable");
    },
    async get() {
      operations.push("get");
    },
    async set() {
      operations.push("set");
    }
  };

  const value = await withTrustedLocalStorage(
    async (trustedStorage) => {
      trustedTaskCalls += 1;
      await trustedStorage.get("secret");
      await trustedStorage.set({ secret: true });
      return "trusted";
    },
    {
      storageArea,
      onUnavailable: () => "unavailable"
    }
  );

  assert.equal(value, "unavailable");
  assert.equal(trustedTaskCalls, 0);
  assert.deepEqual(operations, ["setAccessLevel"]);
  assert.equal(await ensureTrustedLocalStorage(storageArea), false);
  assert.deepEqual(operations, ["setAccessLevel", "setAccessLevel"]);
});

test("fails closed when the storage area or access-level API is missing", async () => {
  assert.equal(await ensureTrustedLocalStorage(undefined), false);
  assert.equal(await ensureTrustedLocalStorage({}), false);
});

test("fails closed when the access-level capability cannot be inspected", async () => {
  const storageArea = Object.defineProperty({}, "setAccessLevel", {
    get() {
      throw new Error("blocked capability lookup");
    }
  });

  assert.equal(await ensureTrustedLocalStorage(storageArea), false);
});

test("fails closed when the default local-storage area cannot be inspected", async () => {
  const originalChrome = globalThis.chrome;
  globalThis.chrome = Object.defineProperty({}, "storage", {
    get() {
      throw new Error("blocked storage lookup");
    }
  });

  try {
    assert.equal(await ensureTrustedLocalStorage(), false);
  } finally {
    if (originalChrome === undefined) delete globalThis.chrome;
    else globalThis.chrome = originalChrome;
  }
});

test("fails closed within a bounded time when access-level enforcement never settles", async () => {
  let calls = 0;
  const storageArea = {
    setAccessLevel() {
      calls += 1;
      return calls === 1 ? new Promise(() => {}) : Promise.resolve();
    }
  };

  assert.equal(
    await ensureTrustedLocalStorage(storageArea, { timeoutMs: 10 }),
    false
  );
  assert.equal(calls, 1);
  assert.equal(await ensureTrustedLocalStorage(storageArea), true);
  assert.equal(calls, 2);
});
