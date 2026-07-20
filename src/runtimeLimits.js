function positiveInteger(value, fallback) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric >= 1 ? Math.floor(numeric) : fallback;
}

function positiveNumber(value, fallback) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? numeric : fallback;
}

export function createTabRequestTokenBucket(options = {}) {
  const capacity = positiveInteger(options.capacity, 300);
  const refillPerSecond = positiveNumber(options.refillPerSecond, 60);
  const maxEntries = positiveInteger(options.maxEntries, 256);
  const idleTtlMs = positiveInteger(options.idleTtlMs, 10 * 60 * 1000);
  const refillPerMillisecond = refillPerSecond / 1000;
  const buckets = new Map();

  function evictIdleAndOldest(now) {
    for (const [tabId, bucket] of buckets) {
      if (now - bucket.lastSeenAt > idleTtlMs) buckets.delete(tabId);
    }
    while (buckets.size >= maxEntries) {
      let oldestTabId;
      let oldestSeenAt = Number.POSITIVE_INFINITY;
      for (const [tabId, bucket] of buckets) {
        if (bucket.lastSeenAt < oldestSeenAt) {
          oldestSeenAt = bucket.lastSeenAt;
          oldestTabId = tabId;
        }
      }
      if (oldestTabId === undefined) break;
      buckets.delete(oldestTabId);
    }
  }

  return {
    allow(tabId, suppliedNow = Date.now()) {
      if (!Number.isInteger(tabId) || tabId < 0) return false;
      const now = Number.isFinite(suppliedNow) ? suppliedNow : Date.now();
      let bucket = buckets.get(tabId);
      if (!bucket) {
        evictIdleAndOldest(now);
        bucket = {
          tokens: capacity,
          refilledAt: now,
          lastSeenAt: now
        };
        buckets.set(tabId, bucket);
      } else {
        const elapsed = Math.max(0, now - bucket.refilledAt);
        bucket.tokens = Math.min(capacity, bucket.tokens + elapsed * refillPerMillisecond);
        if (now >= bucket.refilledAt) bucket.refilledAt = now;
        bucket.lastSeenAt = Math.max(bucket.lastSeenAt, now);
      }

      if (bucket.tokens < 1) return false;
      bucket.tokens -= 1;
      return true;
    },

    delete(tabId) {
      return buckets.delete(tabId);
    },

    clear() {
      buckets.clear();
    },

    get size() {
      return buckets.size;
    }
  };
}

export function createCookieChangeQueue(options = {}) {
  const maxSize = positiveInteger(options.maxSize, 500);
  const maxPerDomain = Math.min(maxSize, positiveInteger(options.maxPerDomain, 50));
  const merge = typeof options.merge === "function" ? options.merge : null;
  if (typeof options.identityOf !== "function" || typeof options.domainOf !== "function") {
    throw new TypeError("Cookie queue identity and domain functions are required");
  }

  const entries = new Map();
  const entriesByDomain = new Map();
  const domainsByCount = Array.from({ length: maxPerDomain + 1 }, () => new Set());
  let largestDomainCount = 0;

  function moveDomainCount(domain, previousCount, nextCount) {
    if (previousCount > 0) domainsByCount[previousCount].delete(domain);
    if (nextCount > 0) domainsByCount[nextCount].add(domain);
    if (nextCount > largestDomainCount) largestDomainCount = nextCount;
    while (largestDomainCount > 0 && domainsByCount[largestDomainCount].size === 0) {
      largestDomainCount -= 1;
    }
  }

  function removeIdentity(identity) {
    const entry = entries.get(identity);
    if (!entry) return false;
    entries.delete(identity);
    const domainEntries = entriesByDomain.get(entry.domain);
    if (!domainEntries) return true;
    const previousCount = domainEntries.size;
    domainEntries.delete(identity);
    const nextCount = domainEntries.size;
    moveDomainCount(entry.domain, previousCount, nextCount);
    if (nextCount === 0) entriesByDomain.delete(entry.domain);
    return true;
  }

  function addEntry(identity, domain, value) {
    let domainEntries = entriesByDomain.get(domain);
    if (!domainEntries) {
      domainEntries = new Map();
      entriesByDomain.set(domain, domainEntries);
    }
    const previousCount = domainEntries.size;
    const entry = { domain, value };
    entries.set(identity, entry);
    domainEntries.set(identity, true);
    moveDomainCount(domain, previousCount, domainEntries.size);
  }

  function evictOldestFromDomain(domain) {
    const identity = entriesByDomain.get(domain)?.keys().next().value;
    if (identity !== undefined) removeIdentity(identity);
  }

  function evictFairly() {
    const domain = domainsByCount[largestDomainCount]?.values().next().value;
    if (domain !== undefined) evictOldestFromDomain(domain);
  }

  return {
    push(value) {
      const identity = String(options.identityOf(value) || "");
      const domain = String(options.domainOf(value) || "");
      if (!identity || !domain) return false;

      const existingEntry = entries.get(identity);
      const queuedValue = existingEntry && merge ? merge(existingEntry.value, value) : value;
      removeIdentity(identity);
      if ((entriesByDomain.get(domain)?.size || 0) >= maxPerDomain) {
        evictOldestFromDomain(domain);
      }
      addEntry(identity, domain, queuedValue);
      if (entries.size > maxSize) evictFairly();
      return true;
    },

    drain(limit = maxSize) {
      const boundedLimit = Math.min(maxSize, positiveInteger(limit, maxSize));
      const identities = Array.from(entries.keys()).slice(0, boundedLimit);
      const values = identities.map((identity) => entries.get(identity)?.value).filter(Boolean);
      identities.forEach(removeIdentity);
      return values;
    },

    clear() {
      entries.clear();
      entriesByDomain.clear();
      domainsByCount.forEach((domains) => domains.clear());
      largestDomainCount = 0;
    },

    domainSize(domain) {
      return entriesByDomain.get(String(domain || ""))?.size || 0;
    },

    get size() {
      return entries.size;
    }
  };
}
