import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  MAX_RAW_NETWORK_URL_LENGTH,
  cookieIdentity,
  documentUrlFingerprint,
  fetchPolicyDocument,
  getCookieAttributionTabIds,
  isObservationSessionCurrent,
  isRequestEventInSession,
  mapPolicyChecksWithConcurrency,
  minimizeDynamicIdentifier,
  reconcileCookieRecords,
  sanitizeCookieRecord,
  sanitizeFieldKeys,
  sanitizeNetworkUrl,
  sanitizeRequestDetails,
  sameDocumentUrl,
  validatePolicyFetchUrl,
  validateRuntimeMessage
} from "../src/backgroundSecurity.js";
import { normalizePolicyText } from "../src/policySnapshots.js";
import { classifyVendorHost } from "../src/vendorRules.js";

test("network records discard credentials, query values, fragments, and token-like path segments", () => {
  const normalized = sanitizeNetworkUrl(
    "https://alice:secret@example.com/reset/123e4567-e89b-12d3-a456-426614174000/more/ignored?email=user%40example.com&token=secret#private"
  );

  assert.equal(normalized.host, "example.com");
  assert.equal(normalized.origin, "https://example.com");
  assert.equal(normalized.url, "https://example.com/reset/:redacted/:segment");
  assert.deepEqual(normalized.queryKeys, ["email", "token"]);
  assert.doesNotMatch(JSON.stringify(normalized), /alice|secret|user%40example|private|ignored/);
});

test("route shaping redacts ordinary user identifiers while retaining static endpoint semantics", () => {
  const profile = sanitizeNetworkUrl("https://example.com/users/john-smith/profile");
  const tracker = sanitizeNetworkUrl("https://metrics.example.com/v2/events/847293");

  assert.equal(profile.url, "https://example.com/users/:segment/profile");
  assert.equal(tracker.url, "https://metrics.example.com/v2/events/:id");
  assert.doesNotMatch(JSON.stringify(profile), /john|smith/);
});

test("document identity separates query navigations without retaining the URL", () => {
  const first = "https://example.com/app?account=first#one";
  const second = "https://example.com/app?account=second#two";

  assert.match(documentUrlFingerprint(first), /^[a-f0-9]{32}$/);
  assert.notEqual(documentUrlFingerprint(first), documentUrlFingerprint(second));
  assert.notEqual(
    documentUrlFingerprint(first),
    documentUrlFingerprint("https://example.com/app?account=first#different")
  );
  assert.equal(sameDocumentUrl(first, "https://example.com/app?account=first#other"), true);
  assert.equal(sameDocumentUrl(first, second), false);
  assert.doesNotMatch(documentUrlFingerprint(first), /account|first/);
});

test("oversized network URLs fail closed before parsing or fingerprinting", () => {
  const oversizedUrl = `https://example.com/collect?payload=${"a".repeat(MAX_RAW_NETWORK_URL_LENGTH)}`;

  assert.equal(sanitizeNetworkUrl(oversizedUrl), null);
  assert.equal(documentUrlFingerprint(oversizedUrl), "");
  assert.equal(sameDocumentUrl(oversizedUrl, oversizedUrl), false);
  assert.equal(
    sanitizeRequestDetails({
      tabId: 1,
      type: "xmlhttprequest",
      method: "GET",
      url: oversizedUrl
    }),
    null
  );
});

test("route shaping preserves the reCAPTCHA endpoint needed by built-in vendor classification", () => {
  const normalized = sanitizeNetworkUrl("https://www.google.com/recaptcha/api2/anchor?k=private");
  const classification = classifyVendorHost(normalized.url);

  assert.equal(normalized.path, "/recaptcha/:segment/:segment");
  assert.equal(classification.vendor, "reCAPTCHA");
});

test("field-key minimization skips overlong keys instead of retaining misleading prefixes", () => {
  assert.deepEqual(
    sanitizeFieldKeys(["a".repeat(49), "email", "profile_name"], { maxLength: 48 }),
    ["email", "profile_name"]
  );
});

test("dynamic cookie names and request field keys retain semantics without retaining identifiers", () => {
  const uuid = "123e4567-e89b-42d3-a456-426614174000";
  const token = "AbCdEfGhIjKlMnOpQrStUvWxYz123456";
  const base64UrlToken = "AbCdEf12_GhIjKl34_MnOpQr56_StUvWx78";
  const letterOnlyBase64 = "AbCdEfGhIjKlMnOpQrStUvWxYzABCDEF";
  const cookie = sanitizeCookieRecord({
    name: `customer_1234567890_${uuid}_${token}`,
    domain: "example.test",
    path: "/"
  });
  const keys = sanitizeFieldKeys([
    "email",
    "customer_1234567890",
    `profile_${uuid}`,
    `event_${token}`,
    `visitor_${base64UrlToken}`,
    `session_${letterOnlyBase64}`,
    "request_deadbeefcafebabe"
  ]);

  assert.equal(minimizeDynamicIdentifier("analytics_cookie"), "analytics_cookie");
  assert.equal(cookie.name, "customer___number_____uuid_____token__");
  assert.deepEqual(keys, [
    "email",
    "customer___number__",
    "profile___uuid__",
    "event___token__",
    "visitor___token__",
    "session___token__",
    "request___hex__"
  ]);
  assert.doesNotMatch(
    JSON.stringify({ cookie, keys }),
    /1234567890|123e4567|AbCdEfGh|AbCdEf12|deadbeef/
  );

  const anotherCustomer = sanitizeCookieRecord({
    name: "customer_9999999999",
    domain: "example.test",
    path: "/"
  });
  const firstCustomer = sanitizeCookieRecord({
    name: "customer_1234567890",
    domain: "example.test",
    path: "/"
  });
  assert.notEqual(cookieIdentity(firstCustomer), cookieIdentity(anotherCustomer));
  let collisionRecords = reconcileCookieRecords(
    [],
    { cookie: firstCustomer, removed: false, cause: "explicit" }
  );
  collisionRecords = reconcileCookieRecords(
    collisionRecords,
    { cookie: anotherCustomer, removed: false, cause: "explicit" }
  );
  assert.equal(collisionRecords.length, 2);
  assert.deepEqual(collisionRecords.map((record) => record.name), [
    "customer___number__",
    "customer___number__"
  ]);
  assert.doesNotMatch(JSON.stringify(collisionRecords), /1234567890|9999999999/);
});

test("known tracking-cookie families retain only a static semantic placeholder", () => {
  const rawNames = [
    "_ga_ABC123",
    "_gac_UA-123456-7",
    "_gcl_aw_987654321",
    "ajs_anonymous_id_customer42",
    "amplitude_id_123e4567-e89b-42d3-a456-426614174000",
    "mixpanel_distinct_AbCdEf123456",
    "mp_0123456789abcdef0123456789abcdef_mixpanel",
    "__utma"
  ];
  const minimized = rawNames.map((name) => minimizeDynamicIdentifier(name));

  assert.deepEqual(minimized, [
    "_ga___identifier__",
    "_gac___identifier__",
    "_gcl___identifier__",
    "ajs___identifier__",
    "amplitude___identifier__",
    "mixpanel___identifier__",
    "mp___identifier___mixpanel",
    "__utma"
  ]);
  assert.doesNotMatch(
    JSON.stringify(minimized),
    /ABC123|UA-123456|987654321|customer42|123e4567|AbCdEf|0123456789abcdef/
  );
});

test("short account-scoped identifiers are minimized while semantic keys remain useful", () => {
  assert.equal(minimizeDynamicIdentifier("user_alice"), "user___identifier__");
  assert.equal(minimizeDynamicIdentifier("uid_alice"), "uid___identifier__");
  assert.equal(minimizeDynamicIdentifier("user.alice"), "user.__identifier__");
  assert.equal(minimizeDynamicIdentifier("customer_12345"), "customer___identifier__");
  assert.equal(minimizeDynamicIdentifier("profile_jane_doe"), "profile___identifier__");
  assert.equal(minimizeDynamicIdentifier("__Host-user_alice"), "__Host-user___identifier__");
  assert.equal(minimizeDynamicIdentifier("alice"), "__identifier__");
  assert.equal(minimizeDynamicIdentifier("user_email"), "user_email");
  assert.equal(minimizeDynamicIdentifier("session_token"), "session_token");

  const request = sanitizeRequestDetails({
    tabId: 3,
    url: "https://example.com/collect?user_alice=1&user_email=hidden",
    method: "POST",
    type: "xmlhttprequest",
    requestBody: { formData: { profile_jane_doe: ["hidden"] } }
  });
  assert.deepEqual(request.queryKeys, ["user___identifier__", "user_email"]);
  assert.deepEqual(request.bodyKeys, []);
});

test("request sanitization never inspects the request-body view", () => {
  const details = {
    tabId: 7,
    url: "https://api.example.test/collect?campaign=spring&email=a%40b.test",
    method: "post",
    type: "xmlhttprequest",
    timeStamp: 123
  };
  Object.defineProperty(details, "requestBody", {
    get() {
      throw new Error("request-body data must not cross the sanitizer boundary");
    }
  });
  let request;
  assert.doesNotThrow(() => {
    request = sanitizeRequestDetails(details);
  });

  assert.deepEqual(request.queryKeys, ["campaign", "email"]);
  assert.deepEqual(request.bodyKeys, []);
  assert.equal(request.url, "https://api.example.test/collect");
  assert.doesNotMatch(JSON.stringify(request), /spring/);
});

test("the all-site webRequest listener does not request request-body data", async () => {
  const backgroundSource = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
  assert.match(backgroundSource, /chrome\.webRequest\.onBeforeRequest\.addListener/);
  assert.doesNotMatch(backgroundSource, /["']requestBody["']/);
});

test("cookie reconciliation deduplicates identities and physically removes deleted cookies", () => {
  const cookie = {
    name: "_ga",
    domain: ".example.com",
    path: "/",
    storeId: "0",
    secure: true,
    sameSite: "lax"
  };
  const partitioned = {
    ...cookie,
    partitionKey: { topLevelSite: "https://shop.example.com" }
  };

  let records = reconcileCookieRecords([], { cookie, removed: false, cause: "explicit" }, { now: 10 });
  records = reconcileCookieRecords(records, { cookie: { ...cookie, httpOnly: true }, removed: false }, { now: 20 });
  records = reconcileCookieRecords(records, { cookie: partitioned, removed: false }, { now: 30 });

  assert.equal(records.length, 2);
  assert.notEqual(cookieIdentity(cookie), cookieIdentity(partitioned));
  assert.equal(records.find((record) => !record.partitionKey).httpOnly, true);

  records = reconcileCookieRecords(records, { cookie, removed: true, cause: "expired" }, { now: 40 });
  assert.equal(records.length, 1);
  assert.equal(records[0].partitionKey.topLevelSite, "https://shop.example.com");
  assert.equal(records.some((record) => record.removed), false);
  assert.equal("value" in records[0], false);
});

test("partitioned cookie updates and deletion retain bounded first-observation evidence", () => {
  const cookie = {
    name: "_ga",
    domain: ".analytics.test",
    hostOnly: false,
    path: "/",
    storeId: "0",
    partitionKey: { topLevelSite: "https://shop.example.com" }
  };

  let records = reconcileCookieRecords(
    [],
    { cookie, removed: false, cause: "explicit" },
    { firstObservedAt: 1_000, lastObservedAt: 1_000 }
  );
  records = reconcileCookieRecords(
    records,
    { cookie: { ...cookie, secure: true }, removed: false, cause: "overwrite" },
    { firstObservedAt: 5_000, lastObservedAt: 5_000 }
  );
  records = reconcileCookieRecords(
    records,
    { cookie, removed: true, cause: "explicit" },
    { deletedAt: 6_000 }
  );

  assert.equal(records.length, 1);
  assert.equal(records[0].removed, true);
  assert.equal(records[0].timingConfidence, "observed");
  assert.equal(records[0].firstSetObservedAt, 1_000);
  assert.equal(records[0].lastSetObservedAt, 5_000);
  assert.equal(records[0].firstObservedAt, 1_000);
  assert.equal(records[0].lastObservedAt, 5_000);
  assert.equal(records[0].deletedAt, 6_000);
  assert.equal(records[0].timeStamp, 1_000);

  records = reconcileCookieRecords(
    records,
    { cookie, removed: false, cause: "inventory" }
  );
  assert.equal(records[0].removed, false);
  assert.equal(records[0].firstObservedAt, 1_000);
  assert.equal(records[0].lastObservedAt, 5_000);
  assert.equal(records[0].deletedAt, 6_000);
});

test("coalesced cookie transitions keep set/update evidence separate from deletion", () => {
  const cookie = {
    name: "_ga",
    domain: ".analytics.test",
    path: "/",
    partitionKey: { topLevelSite: "https://shop.example.com" }
  };

  const deleteOnly = reconcileCookieRecords(
    [],
    { cookie, removed: true, cause: "explicit" },
    { deletedAt: 1_000 }
  );
  assert.deepEqual(deleteOnly, []);

  const deleteThenSet = reconcileCookieRecords(
    [],
    { cookie, removed: false, cause: "explicit" },
    { firstSetObservedAt: 2_000, lastSetObservedAt: 2_000, deletedAt: 1_000 }
  );
  assert.equal(deleteThenSet[0].removed, false);
  assert.equal(deleteThenSet[0].firstSetObservedAt, 2_000);
  assert.equal(deleteThenSet[0].lastSetObservedAt, 2_000);
  assert.equal(deleteThenSet[0].deletedAt, 1_000);

  const setThenDelete = reconcileCookieRecords(
    [],
    { cookie, removed: true, cause: "explicit" },
    { firstSetObservedAt: 3_000, lastSetObservedAt: 3_000, deletedAt: 4_000 }
  );
  assert.equal(setThenDelete[0].removed, true);
  assert.equal(setThenDelete[0].firstSetObservedAt, 3_000);
  assert.equal(setThenDelete[0].lastSetObservedAt, 3_000);
  assert.equal(setThenDelete[0].deletedAt, 4_000);

  const setThenUpdate = reconcileCookieRecords(
    [],
    { cookie, removed: false, cause: "overwrite" },
    { firstSetObservedAt: 5_000, lastSetObservedAt: 6_000 }
  );
  assert.equal(setThenUpdate[0].removed, false);
  assert.equal(setThenUpdate[0].firstSetObservedAt, 5_000);
  assert.equal(setThenUpdate[0].lastSetObservedAt, 6_000);
  assert.equal("deletedAt" in setThenUpdate[0], false);
});

test("legacy delete-only tombstones cannot migrate deletion time into set evidence", () => {
  const deletedAt = 5_000;
  const legacy = {
    name: "_ga",
    domain: ".analytics.test",
    path: "/",
    identityStable: true,
    removed: true,
    timingConfidence: "observed",
    firstObservedAt: deletedAt,
    lastObservedAt: deletedAt,
    timeStamp: deletedAt,
    deletedAt,
    partitionKey: { topLevelSite: "https://shop.example.com" }
  };

  const migrated = sanitizeCookieRecord(legacy, legacy);
  assert.equal(migrated.removed, true);
  assert.equal(migrated.timingConfidence, "unknown");
  assert.equal("firstSetObservedAt" in migrated, false);
  assert.equal("lastSetObservedAt" in migrated, false);
  assert.equal("firstObservedAt" in migrated, false);
  assert.equal("lastObservedAt" in migrated, false);
  assert.equal("timeStamp" in migrated, false);
  assert.equal(migrated.deletedAt, deletedAt);

  const reconciled = reconcileCookieRecords(
    [legacy],
    {
      cookie: { name: "session", domain: ".shop.example.com", path: "/" },
      removed: false,
      cause: "inventory"
    }
  );
  assert.deepEqual(reconciled.map((cookie) => cookie.name), ["session"]);
});

test("bounded cookie evidence never displaces current inventory", () => {
  const partitionKey = { topLevelSite: "https://shop.example.com" };
  let records = reconcileCookieRecords(
    [],
    {
      cookie: { name: "_ga_first", domain: ".analytics.test", path: "/", partitionKey },
      removed: false,
      cause: "explicit"
    },
    { firstSetObservedAt: 1_000, lastSetObservedAt: 1_000, maxRecords: 2 }
  );
  records = reconcileCookieRecords(
    records,
    {
      cookie: { name: "_ga_first", domain: ".analytics.test", path: "/", partitionKey },
      removed: true,
      cause: "explicit"
    },
    { deletedAt: 1_500, maxRecords: 2 }
  );
  records = reconcileCookieRecords(
    records,
    {
      cookie: { name: "_ga_second", domain: ".analytics.test", path: "/", partitionKey },
      removed: false,
      cause: "explicit"
    },
    { firstSetObservedAt: 2_000, lastSetObservedAt: 2_000, maxRecords: 2 }
  );
  records = reconcileCookieRecords(
    records,
    {
      cookie: { name: "_ga_second", domain: ".analytics.test", path: "/", partitionKey },
      removed: true,
      cause: "explicit"
    },
    { deletedAt: 2_500, maxRecords: 2 }
  );
  records = reconcileCookieRecords(
    records,
    {
      cookie: { name: "session", domain: ".shop.example.com", path: "/" },
      removed: false,
      cause: "inventory"
    },
    { maxRecords: 2 }
  );

  assert.equal(records.length, 2);
  assert.equal(records.some((cookie) => cookie.name === "session" && !cookie.removed), true);
  assert.equal(records.filter((cookie) => cookie.removed).length, 1);
});

test("cookie records mark whether identity can be reconstructed without persisted fingerprints", () => {
  const stable = sanitizeCookieRecord({
    name: "_ga",
    domain: ".example.com",
    path: "/",
    storeId: "0"
  });
  const minimized = sanitizeCookieRecord({
    name: "customer_1234567890",
    domain: ".example.com",
    path: "/users/987654",
    storeId: "0"
  });

  assert.equal(stable.identityStable, true);
  assert.equal(minimized.identityStable, false);
  assert.doesNotMatch(JSON.stringify(minimized), /1234567890|987654/);
});

test("cookie identity redacts raw paths and includes complete partition semantics", () => {
  const first = sanitizeCookieRecord({
    name: "session",
    domain: ".example.com",
    path: "/users/alice/private",
    partitionKey: { topLevelSite: "https://shop.example", hasCrossSiteAncestor: false }
  });
  const second = sanitizeCookieRecord({
    name: "session",
    domain: ".example.com",
    path: "/users/bob/private",
    partitionKey: { topLevelSite: "https://shop.example", hasCrossSiteAncestor: true }
  });

  assert.equal(first.path, "/users/:segment/:segment");
  assert.equal(second.path, "/users/:segment/:segment");
  assert.notEqual(cookieIdentity(first), cookieIdentity(second));
  assert.doesNotMatch(JSON.stringify([first, second]), /alice|bob/);
});

test("cookie sanitization preserves host-only scope and attribution requires an exact host", () => {
  const hostOnlyCookie = sanitizeCookieRecord({
    name: "session",
    domain: "example.com",
    hostOnly: true,
    path: "/"
  });
  const tabs = [
    { id: 1, url: "https://example.com/account" },
    { id: 2, url: "https://www.example.com/account" }
  ];

  assert.equal(hostOnlyCookie.hostOnly, true);
  assert.deepEqual(
    getCookieAttributionTabIds({ cookie: hostOnlyCookie, removed: false }, tabs),
    [1]
  );
  assert.deepEqual(
    getCookieAttributionTabIds(
      { cookie: { ...hostOnlyCookie, hostOnly: false }, removed: true },
      tabs
    ),
    [1, 2]
  );
});

test("unpartitioned cookies never retain causal timing while partition-attributed changes can", () => {
  const cookie = { name: "_ga", domain: ".example.com", path: "/", storeId: "0" };
  const inventoryCookie = sanitizeCookieRecord(cookie, {
    cause: "inventory",
    timingConfidence: "unknown"
  });
  let inventory = reconcileCookieRecords([], {
    cookie: inventoryCookie,
    removed: false,
    cause: "inventory"
  });

  assert.equal(inventory[0].timingConfidence, "unknown");
  assert.equal("timeStamp" in inventory[0], false);

  let observed = reconcileCookieRecords([], { cookie, removed: false, cause: "explicit" }, { now: 1234 });
  assert.equal(observed[0].timingConfidence, "unknown");
  assert.equal("timeStamp" in observed[0], false);

  observed = reconcileCookieRecords(observed, {
    cookie: inventoryCookie,
    removed: false,
    cause: "inventory"
  });
  assert.equal(observed[0].timingConfidence, "unknown");
  assert.equal("timeStamp" in observed[0], false);

  const partitioned = {
    ...cookie,
    partitionKey: { topLevelSite: "https://shop.example.com" }
  };
  const safelyObserved = reconcileCookieRecords(
    [],
    { cookie: partitioned, removed: false, cause: "explicit" },
    { now: 5678 }
  );
  assert.equal(safelyObserved[0].timingConfidence, "observed");
  assert.equal(safelyObserved[0].timeStamp, 5678);
});

test("cookie attribution honors partition top-level sites and does not guess third-party tabs", () => {
  const tabs = [
    { id: 1, url: "https://www.shop.example.com/cart" },
    { id: 2, url: "http://shop.example.com/cart" },
    { id: 3, url: "https://tracker.test/dashboard" },
    { id: 4, url: "https://unrelated.test/" }
  ];

  const partitionedIds = getCookieAttributionTabIds(
    {
      cookie: {
        name: "id",
        domain: ".tracker.test",
        partitionKey: { topLevelSite: "https://shop.example.com" }
      }
    },
    tabs
  );
  assert.deepEqual(partitionedIds, [1]);

  const unpartitionedIds = getCookieAttributionTabIds(
    { cookie: { name: "id", domain: ".tracker.test" } },
    tabs
  );
  assert.deepEqual(unpartitionedIds, [3]);
});

test("non-removed cookie changes are skipped when multiple top-level tabs are plausible", () => {
  const tabs = [
    { id: 1, url: "https://shop.example.com/cart" },
    { id: 2, url: "https://www.shop.example.com/checkout" },
    { id: 3, url: "https://tracker.test/one" },
    { id: 4, url: "https://tracker.test/two" }
  ];
  const partitioned = {
    cookie: {
      name: "id",
      domain: ".tracker.test",
      partitionKey: { topLevelSite: "https://shop.example.com" }
    },
    removed: false
  };
  const firstParty = {
    cookie: { name: "id", domain: ".tracker.test" },
    removed: false
  };

  assert.deepEqual(getCookieAttributionTabIds(partitioned, tabs), []);
  assert.deepEqual(getCookieAttributionTabIds(firstParty, tabs), []);
  assert.deepEqual(getCookieAttributionTabIds({ ...partitioned, removed: true }, tabs), [1, 2]);
  assert.deepEqual(getCookieAttributionTabIds({ ...firstParty, removed: true }, tabs), [3, 4]);
});

test("observation generation and strict event timestamps reject stale async results", () => {
  const session = {
    generation: 3,
    origin: "https://example.com",
    navigationKey: "https://example.com/privacy",
    documentId: "new-document",
    startedAt: 1000
  };

  assert.equal(
    isRequestEventInSession(
      { type: "xmlhttprequest", frameId: 0, documentId: "new-document", timeStamp: 999 },
      session
    ),
    false
  );
  assert.equal(
    isRequestEventInSession(
      { type: "xmlhttprequest", frameId: 0, documentId: "new-document", timeStamp: 1000 },
      session
    ),
    true
  );
  assert.equal(
    isRequestEventInSession(
      { type: "xmlhttprequest", frameId: 0, documentId: "old-document", timeStamp: 1001 },
      session
    ),
    false
  );
  assert.equal(isObservationSessionCurrent(session, { ...session }), true);
  assert.equal(isObservationSessionCurrent(session, { ...session, generation: 4 }), false);
});

test("request sequence remains authoritative while document IDs reject prior-page events", () => {
  const session = {
    documentId: "current-document",
    startedAt: 5_000,
    startedSequence: 40
  };

  assert.equal(
    isRequestEventInSession(
      {
        type: "xmlhttprequest",
        frameId: 0,
        documentId: "current-document",
        sequence: 39,
        timeStamp: 6_000
      },
      session
    ),
    false
  );
  assert.equal(
    isRequestEventInSession(
      {
        type: "xmlhttprequest",
        frameId: 0,
        documentId: "current-document",
        sequence: 40,
        timeStamp: 1
      },
      session
    ),
    true
  );
  assert.equal(
    isRequestEventInSession(
      {
        type: "xmlhttprequest",
        frameId: 0,
        documentId: "prior-document",
        sequence: 41,
        timeStamp: 6_000
      },
      session
    ),
    false
  );
});

test("runtime message validation separates content and extension-page authority", () => {
  const runtimeId = "extension-id";
  const contentSender = {
    id: runtimeId,
    frameId: 0,
    tab: { id: 9 },
    url: "https://example.com/privacy"
  };

  assert.deepEqual(
    validateRuntimeMessage(
      {
        type: "PAGE_RISK_SCAN",
        tabId: 999,
        policyLike: false,
        policyConfidence: 0.2,
        textLength: 400
      },
      contentSender,
      runtimeId
    ),
    { ok: true, type: "PAGE_RISK_SCAN", source: "content", tabId: 9 }
  );
  assert.equal(
    validateRuntimeMessage({ type: "CHECK_SAVED_POLICIES_NOW" }, contentSender, runtimeId).ok,
    false
  );
  assert.equal(
    validateRuntimeMessage(
      { type: "GET_NETWORK_ACTIVITY", tabId: 9 },
      { id: runtimeId, url: `chrome-extension://${runtimeId}/src/popup.html` },
      runtimeId
    ).ok,
    true
  );
  const extensionSender = {
    id: runtimeId,
    url: `chrome-extension://${runtimeId}/src/popup.html`
  };
  const observationPageContext = {
    tabId: 9,
    documentId: "current-document",
    documentFingerprint: documentUrlFingerprint("https://example.com/privacy")
  };
  for (const type of ["SAVE_OBSERVATION_SNAPSHOT", "CLEAR_NETWORK_ACTIVITY"]) {
    assert.equal(
      validateRuntimeMessage(
        { type, ...observationPageContext },
        extensionSender,
        runtimeId
      ).ok,
      true
    );
  }
  for (const invalidContext of [
    {},
    { documentId: "", documentFingerprint: observationPageContext.documentFingerprint },
    { documentId: "x".repeat(129), documentFingerprint: observationPageContext.documentFingerprint },
    { documentId: "current-document", documentFingerprint: "not-a-fingerprint" },
    { documentId: "current-document", documentFingerprint: "A".repeat(32) }
  ]) {
    assert.equal(
      validateRuntimeMessage(
        { type: "CLEAR_NETWORK_ACTIVITY", tabId: 9, ...invalidContext },
        extensionSender,
        runtimeId
      ).ok,
      false
    );
  }
  assert.deepEqual(
    validateRuntimeMessage(
      {
        type: "SAVE_MONITORED_POLICY_SNAPSHOT",
        tabId: 9,
        documentId: "current-document",
        policyUrl: "https://example.com/privacy?lang=ko",
        title: "Privacy policy"
      },
      extensionSender,
      runtimeId
    ),
    {
      ok: true,
      type: "SAVE_MONITORED_POLICY_SNAPSHOT",
      source: "extension-page",
      tabId: 9
    }
  );
  for (const invalidMessage of [
    {
      type: "SAVE_MONITORED_POLICY_SNAPSHOT",
      tabId: 9,
      documentId: "current-document",
      policyUrl: "http://example.com/privacy"
    },
    {
      type: "SAVE_MONITORED_POLICY_SNAPSHOT",
      tabId: 9,
      documentId: "",
      policyUrl: "https://example.com/privacy"
    },
    {
      type: "SAVE_MONITORED_POLICY_SNAPSHOT",
      tabId: 9,
      documentId: "current-document",
      policyUrl: "https://example.com/privacy#section"
    },
    {
      type: "SAVE_MONITORED_POLICY_SNAPSHOT",
      tabId: 9,
      documentId: "current-document",
      policyUrl: "https://example.com/privacy"
    },
    {
      type: "SAVE_MONITORED_POLICY_SNAPSHOT",
      tabId: 9,
      documentId: "current-document",
      policyUrl: "https://example.com/privacy",
      title: "x".repeat(513)
    },
    {
      type: "SAVE_MONITORED_POLICY_SNAPSHOT",
      tabId: 9,
      documentId: "current-document",
      policyUrl: "https://example.com/privacy",
      title: "Privacy policy",
      text: "popup DOM text must not be accepted as the monitored baseline"
    }
  ]) {
    assert.equal(validateRuntimeMessage(invalidMessage, extensionSender, runtimeId).ok, false);
  }
  assert.equal(
    validateRuntimeMessage(
      { type: "GET_NETWORK_ACTIVITY", tabId: 9 },
      { id: "different-extension" },
      runtimeId
    ).ok,
    false
  );
  assert.equal(
    validateRuntimeMessage(
      {
        type: "SET_RISK_INDICATOR",
        tabId: 9,
        indicator: {
          level: "medium",
          score: 40,
          source: "popup-page",
          url: "https://example.com/privacy",
          documentFingerprint: documentUrlFingerprint("https://example.com/privacy"),
          documentId: "current-document"
        }
      },
      { id: runtimeId, url: `chrome-extension://${runtimeId}/src/popup.html` },
      runtimeId
    ).ok,
    true
  );
  assert.equal(
    validateRuntimeMessage(
      { type: "SET_RISK_INDICATOR", tabId: 9, indicator: { level: "high" } },
      { id: runtimeId, url: `chrome-extension://${runtimeId}/src/popup.html` },
      runtimeId
    ).ok,
    false
  );
});

test("companion overlay messages derive document authority from the top-level content sender", () => {
  const runtimeId = "extension-id";
  const validSender = {
    id: runtimeId,
    tab: { id: 9, url: "https://example.com/privacy?account=one" },
    frameId: 0,
    documentId: "current-document",
    documentLifecycle: "active",
    url: "https://example.com/privacy?account=one"
  };
  assert.deepEqual(
    validateRuntimeMessage({ type: "GET_COMPANION_OVERLAY_STATE" }, validSender, runtimeId),
    {
    ok: true,
      type: "GET_COMPANION_OVERLAY_STATE",
      source: "content",
      tabId: 9
    }
  );

  for (const [message, sender] of [
    [{ type: "GET_COMPANION_OVERLAY_STATE", tabId: 9 }, validSender],
    [{ type: "GET_COMPANION_OVERLAY_STATE", url: validSender.url }, validSender],
    [{ type: "GET_COMPANION_OVERLAY_STATE" }, { ...validSender, frameId: 1 }],
    [{ type: "GET_COMPANION_OVERLAY_STATE" }, { ...validSender, documentId: "" }],
    [{ type: "GET_COMPANION_OVERLAY_STATE" }, { ...validSender, documentLifecycle: "cached" }],
    [
      { type: "GET_COMPANION_OVERLAY_STATE" },
      { ...validSender, tab: { ...validSender.tab, url: "https://other.example/privacy" } }
    ],
    [{ type: "GET_COMPANION_OVERLAY_STATE" }, { ...validSender, id: "other-extension" }]
  ]) {
    assert.equal(validateRuntimeMessage(message, sender, runtimeId).ok, false);
  }

  const popupSender = { id: runtimeId, url: `chrome-extension://${runtimeId}/src/popup.html` };
  assert.equal(
    validateRuntimeMessage({ type: "GET_COMPANION_OVERLAY_PREFERENCE" }, popupSender, runtimeId).ok,
    true
  );
  assert.equal(
    validateRuntimeMessage(
      { type: "SET_COMPANION_OVERLAY_PREFERENCE", enabled: true },
      popupSender,
      runtimeId
    ).ok,
    true
  );
  assert.equal(
    validateRuntimeMessage({ type: "GET_ANALYSIS_MODE_PREFERENCE" }, popupSender, runtimeId).ok,
    true
  );
  assert.equal(
    validateRuntimeMessage(
      { type: "SET_ANALYSIS_MODE_PREFERENCE", mode: "cookies" },
      popupSender,
      runtimeId
    ).ok,
    true
  );
  for (const message of [
    { type: "GET_COMPANION_OVERLAY_PREFERENCE", extra: true },
    { type: "SET_COMPANION_OVERLAY_PREFERENCE" },
    { type: "SET_COMPANION_OVERLAY_PREFERENCE", enabled: "yes" },
    { type: "SET_COMPANION_OVERLAY_PREFERENCE", enabled: true, tabId: 9 }
  ]) {
    assert.equal(validateRuntimeMessage(message, popupSender, runtimeId).ok, false);
  }
  for (const message of [
    { type: "GET_ANALYSIS_MODE_PREFERENCE", extra: true },
    { type: "SET_ANALYSIS_MODE_PREFERENCE" },
    { type: "SET_ANALYSIS_MODE_PREFERENCE", mode: "paste" },
    { type: "SET_ANALYSIS_MODE_PREFERENCE", mode: "COOKIES" },
    { type: "SET_ANALYSIS_MODE_PREFERENCE", mode: "page", extra: true }
  ]) {
    assert.equal(validateRuntimeMessage(message, popupSender, runtimeId).ok, false);
  }
  for (const sender of [
    { id: runtimeId },
    { id: runtimeId, url: "https://example.com/popup.html" },
    { id: runtimeId, url: "chrome-extension://other-extension/src/popup.html" },
    validSender
  ]) {
    assert.equal(
      validateRuntimeMessage({ type: "GET_ANALYSIS_MODE_PREFERENCE" }, sender, runtimeId).ok,
      false
    );
  }
});

test("policy fetching omits credentials, rejects redirects, and enforces content limits", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return new Response("<main>Privacy policy</main>", {
      status: 200,
      headers: { "content-type": "text/html; charset=utf-8" }
    });
  };

  const result = await fetchPolicyDocument("https://example.com/policy#section", {
    fetchImpl,
    maxBytes: 1000,
    timeoutMs: 1000
  });

  assert.equal(result.text, "<main>Privacy policy</main>");
  assert.equal(calls.length, 1);
  assert.equal(calls[0].options.credentials, "omit");
  assert.equal(calls[0].options.redirect, "error");
  assert.equal(calls[0].url, "https://example.com/policy");

  await assert.rejects(
    () =>
      fetchPolicyDocument("https://example.com/policy", {
        fetchImpl: async () =>
          new Response(null, {
            status: 302,
            headers: { location: "https://www.example.com/privacy" }
          })
      }),
    /redirects are not allowed/
  );

  await assert.rejects(
    () =>
      fetchPolicyDocument("https://example.com/policy", {
        maxBytes: 4,
        fetchImpl: async () =>
          new Response("too large", { headers: { "content-type": "text/plain" } })
      }),
    /size limit/
  );
});

test("policy URLs reject credentials, sensitive parameters, private hosts, and every redirect", async () => {
  assert.throws(() => validatePolicyFetchUrl("https://user:pass@example.com/policy"), /credentials/);
  assert.throws(() => validatePolicyFetchUrl("https://example.com/policy?access_token=secret"), /Sensitive/);
  assert.throws(() => validatePolicyFetchUrl("https://example.com/policy?authToken=secret"), /Sensitive/);
  assert.throws(() => validatePolicyFetchUrl("http://example.com/policy"), /HTTPS/);
  assert.throws(() => validatePolicyFetchUrl("http://127.0.0.1/policy"), /Private/);
  assert.throws(() => validatePolicyFetchUrl("http://router/policy"), /Private/);
  assert.throws(() => validatePolicyFetchUrl("http://intranet/policy"), /Private/);
  assert.throws(() => validatePolicyFetchUrl("http://100.64.0.1/policy"), /Private/);
  assert.throws(() => validatePolicyFetchUrl("http://[fe80::1]/policy"), /Private/);
  assert.throws(() => validatePolicyFetchUrl("http://[fd00::1]/policy"), /Private/);

  await assert.rejects(
    () =>
      fetchPolicyDocument("https://example.com/policy", {
        fetchImpl: async () =>
          new Response(null, { status: 302, headers: { location: "http://example.com/policy" } })
      }),
    /redirects are not allowed/
  );
});

test("policy URLs reject local-domain aliases and non-global or private-embedded IPv6", () => {
  const blockedUrls = [
    "http://localhost.localdomain/policy",
    "http://service.localdomain/policy",
    "http://[::]/policy",
    "http://[::1]/policy",
    "http://[fe80::1]/policy",
    "http://[fc00::1]/policy",
    "http://[ff02::1]/policy",
    "http://[2001:db8::1]/policy",
    "http://[3fff::1]/policy",
    "http://[::127.0.0.1]/policy",
    "http://[::10.0.0.1]/policy",
    "http://[::169.254.1.2]/policy",
    "http://[::ffff:10.0.0.1]/policy",
    "http://[::ffff:192.168.1.2]/policy",
    "http://[::ffff:0:10.0.0.1]/policy",
    "http://[64:ff9b::10.0.0.1]/policy",
    "http://[2002:0a00:0001::]/policy",
    "http://[2001:4860::5efe:10.0.0.1]/policy"
  ];

  for (const url of blockedUrls) {
    assert.throws(() => validatePolicyFetchUrl(url), /Private/, url);
  }

  assert.equal(
    validatePolicyFetchUrl("https://[2001:4860:4860::8888]/policy").hostname,
    "[2001:4860:4860::8888]"
  );
  assert.equal(
    validatePolicyFetchUrl("https://[2606:4700:4700::1111]/policy").hostname,
    "[2606:4700:4700::1111]"
  );
});

test("invalid policy URLs fail before a fetch timeout is scheduled", async () => {
  const originalSetTimeout = globalThis.setTimeout;
  let scheduledTimeouts = 0;
  globalThis.setTimeout = () => {
    scheduledTimeouts += 1;
    return 1;
  };

  try {
    await assert.rejects(
      () => fetchPolicyDocument("not a valid URL", { fetchImpl: async () => assert.fail("must not fetch") }),
      /Invalid policy URL/
    );
  } finally {
    globalThis.setTimeout = originalSetTimeout;
  }

  assert.equal(scheduledTimeouts, 0);
});

test("saved-policy worker pool preserves result order and never exceeds four active checks", async () => {
  let active = 0;
  let maximumActive = 0;
  const entries = Array.from({ length: 11 }, (_value, index) => index);

  const results = await mapPolicyChecksWithConcurrency(entries, async (value) => {
    active += 1;
    maximumActive = Math.max(maximumActive, active);
    await new Promise((resolve) => setTimeout(resolve, 5));
    active -= 1;
    return value * 2;
  }, 99);

  assert.equal(maximumActive, 4);
  assert.deepEqual(results, entries.map((value) => value * 2));
});

test("background policy checks preserve plain-text angle brackets and enforce safety gates", async () => {
  const backgroundSource = await readFile(new URL("../src/background.js", import.meta.url), "utf8");
  const plainText = normalizePolicyText(
    "Contact the controller at <privacy@example.com>.\nWe do not sell personal data."
  );

  assert.match(plainText, /<privacy@example\.com>/);
  assert.match(backgroundSource, /mimeType === "text\/plain"[\s\S]*normalizePolicyText\(document\.text\)/);
  assert.match(backgroundSource, /extractFetchedPolicyText\(document\)/);
  assert.match(
    backgroundSource,
    /function boundedFetchedPolicyAnalysisText\(text\)[\s\S]*slice\(0, MAX_POLICY_ANALYSIS_CHARS\)/
  );
  assert.equal(
    (backgroundSource.match(/analyzePolicy\(boundedFetchedPolicyAnalysisText\(text\)\)/g) || []).length,
    2
  );
  assert.match(backgroundSource, /if \(!policyAnalysis\?\.ok\)/);
  assert.match(
    backgroundSource,
    /if \(policyCheckInFlight\) \{[\s\S]*?policyCheckInFlightForced[\s\S]*?return policyCheckInFlight/
  );
  assert.match(backgroundSource, /automaticPolicyCheckDue\(snapshot, health\[snapshotKey\]/);
  assert.match(backgroundSource, /CHECK_SAVED_POLICIES_NOW[\s\S]*?force: true/);
  assert.match(backgroundSource, /runSavedPolicyChecks\(\)\.catch\(\(\) => \{\}\)/);
  assert.match(backgroundSource, /const liveBaseline = stored\?\.\[POLICY_SNAPSHOTS_KEY\]\?\.\[snapshotKey\]/);
  assert.match(backgroundSource, /liveBaseline\.capturedAt/);
  assert.match(backgroundSource, /recordPolicyCheckResults\(\[result\], new Date\(\)\.toISOString\(\)\)/);
  assert.match(backgroundSource, /baselineCapturedAt: previousSnapshot\.capturedAt/);
  assert.match(backgroundSource, /applyObservationSettings\(\{ enabled: false \}\)/);
  assert.match(backgroundSource, /title: ""/);
  assert.doesNotMatch(backgroundSource, /event\.timeStamp \+ 1_000/);
});
