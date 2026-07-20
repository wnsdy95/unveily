const DEFAULT_MAX_FIELD_KEYS = 24;
const DEFAULT_MAX_FIELD_KEY_LENGTH = 48;
const DEFAULT_MAX_PATH_SEGMENTS = 3;
const DEFAULT_MAX_PATH_LENGTH = 180;
const DEFAULT_POLICY_MAX_BYTES = 1024 * 1024;
const DEFAULT_POLICY_TIMEOUT_MS = 12_000;
export const MAX_RAW_NETWORK_URL_LENGTH = 16 * 1024;

const ALLOWED_MESSAGE_TYPES = new Set([
  "GET_NETWORK_ACTIVITY",
  "CLEAR_NETWORK_ACTIVITY",
  "SAVE_OBSERVATION_SNAPSHOT",
  "SAVE_MONITORED_POLICY_SNAPSHOT",
  "GET_OBSERVATION_SETTINGS",
  "GET_COMPANION_OVERLAY_STATE",
  "GET_COMPANION_OVERLAY_PREFERENCE",
  "SET_COMPANION_OVERLAY_PREFERENCE",
  "PAGE_RISK_SCAN",
  "SET_RISK_INDICATOR",
  "CHECK_SAVED_POLICIES_NOW"
]);

const POPUP_MESSAGE_TYPES = new Set([
  "GET_NETWORK_ACTIVITY",
  "CLEAR_NETWORK_ACTIVITY",
  "SAVE_OBSERVATION_SNAPSHOT",
  "SAVE_MONITORED_POLICY_SNAPSHOT",
  "GET_COMPANION_OVERLAY_PREFERENCE",
  "SET_COMPANION_OVERLAY_PREFERENCE",
  "SET_RISK_INDICATOR",
  "CHECK_SAVED_POLICIES_NOW"
]);

const CONTENT_MESSAGE_TYPES = new Set([
  "GET_OBSERVATION_SETTINGS",
  "GET_COMPANION_OVERLAY_STATE",
  "PAGE_RISK_SCAN"
]);
const SENSITIVE_QUERY_KEY = /(?:^|[_.\[-])(access|auth|code|credential|jwt|key|nonce|otp|pass|password|secret|session|signature|ticket|token)(?:$|[_.\]-])/i;
const TOKEN_LIKE_PATH = /^(?:[a-f\d]{8}-[a-f\d-]{27,}|[a-f\d]{24,}|eyJ[a-zA-Z\d_-]{16,}|[a-zA-Z\d_-]{32,})$/;
const UUID_IDENTIFIER = /(?<![a-z\d])[a-f\d]{8}(?:-[a-f\d]{4}){3}-[a-f\d]{12}(?![a-z\d])/gi;
const LONG_HEX_IDENTIFIER = /(?<![a-z0-9])[a-f\d]{16,}(?![a-z0-9])/gi;
const LONG_NUMBER_IDENTIFIER = /\d{6,}/g;
const LONG_TOKEN_IDENTIFIER = /[a-z\d][a-z\d_-]{23,}/gi;
const SEMANTIC_IDENTIFIER_PREFIXES = new Set([
  "account",
  "analytics",
  "auth",
  "client",
  "cookie",
  "customer",
  "device",
  "event",
  "field",
  "installation",
  "marketing",
  "member",
  "org",
  "organization",
  "profile",
  "property",
  "request",
  "session",
  "tracking",
  "tenant",
  "uid",
  "user",
  "userid",
  "visitor"
]);
const SAFE_SEMANTIC_IDENTIFIER_SUFFIX_WORDS = new Set([
  "access",
  "account",
  "action",
  "ad",
  "ads",
  "address",
  "age",
  "analytics",
  "auth",
  "browser",
  "birth",
  "campaign",
  "card",
  "cart",
  "category",
  "city",
  "client",
  "company",
  "consent",
  "cookie",
  "country",
  "created",
  "csrf",
  "currency",
  "device",
  "date",
  "email",
  "enabled",
  "event",
  "field",
  "flag",
  "gender",
  "id",
  "identifier",
  "in",
  "ip",
  "key",
  "lang",
  "language",
  "locale",
  "location",
  "logged",
  "login",
  "logout",
  "marketing",
  "medium",
  "name",
  "number",
  "order",
  "page",
  "password",
  "payment",
  "phone",
  "postal",
  "preference",
  "preferences",
  "profile",
  "property",
  "purpose",
  "query",
  "refresh",
  "region",
  "referrer",
  "remember",
  "request",
  "role",
  "session",
  "source",
  "status",
  "state",
  "storage",
  "time",
  "timestamp",
  "token",
  "tracking",
  "type",
  "updated",
  "user",
  "uuid",
  "value",
  "version",
  "visitor",
  "hex",
  "xsrf",
  "zip"
]);
const SAFE_STANDALONE_IDENTIFIER_NAME = /^(?:_ga|_gid|_gat|_fbp|_fbc|amp_token|cookieconsent|csrftoken|jsessionid|phpsessid|connect\.sid)$/i;
const STATIC_TRACKING_COOKIE_NAME = /^(?:__utm[a-z]+|_?ga|_?gid|_?gat|_?gac|_?gcl|_?fbp|_?fbc|amp_token)$/i;
const SEMANTIC_IDENTIFIER_HINTS = Object.freeze([
  [/(?:e-?mail|이메일)/i, "email"],
  [/(?:phone|mobile|tel|전화)/i, "phone"],
  [/(?:session|sess|세션)/i, "session"],
  [/(?:auth|login|로그인|인증)/i, "auth"],
  [/(?:consent|cookie|쿠키|동의)/i, "consent"],
  [/(?:analytic|track|metric|telemetry|분석|추적)/i, "analytics"],
  [/(?:advert|marketing|campaign|광고|마케팅)/i, "marketing"],
  [/(?:account|profile|user|member|customer|visitor|tenant|uid|계정|사용자|회원|고객)/i, "user"]
]);
const transientCookieNameIdentities = new WeakMap();
const STATIC_ROUTE_WORDS = new Set([
  "account",
  "ad",
  "ads",
  "advertising",
  "analytics",
  "api",
  "assets",
  "auth",
  "beacon",
  "callback",
  "cdn",
  "checkout",
  "collect",
  "consent",
  "cookie",
  "cookies",
  "event",
  "events",
  "graphql",
  "legal",
  "login",
  "logout",
  "metrics",
  "oauth",
  "payment",
  "payments",
  "pixel",
  "policy",
  "privacy",
  "profile",
  "recaptcha",
  "reset",
  "security",
  "static",
  "telemetry",
  "terms",
  "track",
  "tracking",
  "user",
  "users"
]);
const STATIC_LOCALE_SEGMENTS = new Set([
  "de",
  "en",
  "en-gb",
  "en-us",
  "es",
  "fr",
  "ja",
  "ko",
  "ko-kr",
  "pt",
  "zh",
  "zh-cn",
  "zh-tw"
]);

function isSensitiveQueryKey(key) {
  const text = String(key || "");
  if (SENSITIVE_QUERY_KEY.test(text)) return true;
  const compact = text.toLowerCase().replace(/[^a-z0-9]/g, "");
  return /^(?:access|api|auth|bearer|client|csrf|id|oauth|refresh|session)(?:key|secret|token)$/.test(compact);
}

function clipString(value, maxLength) {
  return typeof value === "string" ? value.slice(0, maxLength) : "";
}

function safeDecodeURIComponent(value) {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function boundedNetworkUrlText(rawUrl) {
  return typeof rawUrl === "string" && rawUrl.length > 0 && rawUrl.length <= MAX_RAW_NETWORK_URL_LENGTH
    ? rawUrl
    : "";
}

function looksLikeDynamicToken(value) {
  const text = String(value || "").replace(/[_-]/g, "");
  if (text.length < 24) return false;
  if (/^eyJ/i.test(text)) return true;
  const hasLetter = /[a-z]/i.test(text);
  const hasDigit = /\d/.test(text);
  const hasMixedCase = /[a-z]/.test(text) && /[A-Z]/.test(text);
  const digitCount = (text.match(/\d/g) || []).length;
  return Boolean(
    hasLetter &&
      ((hasDigit && (hasMixedCase || (text.length >= 32 && digitCount >= 4))) ||
        (!hasDigit && hasMixedCase && text.length >= 24))
  );
}

function minimizeTokenCandidate(candidate) {
  if (!looksLikeDynamicToken(candidate)) return candidate;
  const prefixMatch = /^([a-z]+)([_-])(.+)$/i.exec(candidate);
  if (
    prefixMatch &&
    SEMANTIC_IDENTIFIER_PREFIXES.has(prefixMatch[1].toLowerCase()) &&
    looksLikeDynamicToken(prefixMatch[3])
  ) {
    return `${prefixMatch[1]}${prefixMatch[2]}__token__`;
  }
  return "__token__";
}

function minimizeSemanticIdentifierSuffix(value) {
  const securityPrefix = /^(__(?:host|secure)-)(.+)$/i.exec(value);
  const prefix = securityPrefix?.[1] || "";
  const candidate = securityPrefix?.[2] || value;
  const match = /^([a-z]+)([._-])(.+)$/i.exec(candidate);
  if (!match || !SEMANTIC_IDENTIFIER_PREFIXES.has(match[1].toLowerCase())) return value;

  const suffixWords = match[3]
    .toLowerCase()
    .split(/[_-]+/)
    .filter(Boolean);
  const isKnownSemanticSuffix =
    suffixWords.length > 0 &&
    suffixWords.every((word) => SAFE_SEMANTIC_IDENTIFIER_SUFFIX_WORDS.has(word));
  if (isKnownSemanticSuffix) return value;
  return `${prefix}${match[1]}${match[2]}__identifier__`;
}

function minimizeUnknownIdentifierTokens(value) {
  const securityPrefix = /^(__(?:host|secure)-)(.+)$/i.exec(value);
  const prefix = securityPrefix?.[1] || "";
  const candidate = securityPrefix?.[2] || value;
  if (SAFE_STANDALONE_IDENTIFIER_NAME.test(candidate)) return value;
  if (/__(?:hex|identifier|number|token|uuid)__/.test(candidate)) return value;

  const tokenized = candidate
    .replace(/([a-z\d])([A-Z])/g, "$1_$2")
    .toLowerCase()
    .split(/[^a-z\d]+/)
    .filter(Boolean);
  if (
    tokenized.length > 0 &&
    tokenized.every(
      (token) => SAFE_SEMANTIC_IDENTIFIER_SUFFIX_WORDS.has(token) || SEMANTIC_IDENTIFIER_PREFIXES.has(token)
    )
  ) {
    return value;
  }

  const semanticHints = Array.from(
    new Set(
      SEMANTIC_IDENTIFIER_HINTS
        .filter(([pattern]) => pattern.test(candidate))
        .map(([, category]) => category)
    )
  );
  return `${prefix}${semanticHints.length > 0 ? semanticHints.join("_") : ""}__identifier__`;
}

function minimizeTrackingCookieFamily(value) {
  const name = String(value || "");
  if (STATIC_TRACKING_COOKIE_NAME.test(name)) return name.toLowerCase();

  const googleFamily = /^(_?(?:ga|gat|gac|gcl))_.+$/i.exec(name);
  if (googleFamily) return `${googleFamily[1].toLowerCase()}___identifier__`;

  const namedFamily = /^(ajs|amplitude|mixpanel)_.+$/i.exec(name);
  if (namedFamily) return `${namedFamily[1].toLowerCase()}___identifier__`;

  if (/^mp_.+_mixpanel$/i.test(name)) return "mp___identifier___mixpanel";
  return "";
}

/**
 * Retains semantic identifier words while replacing embedded per-user/per-event
 * material with stable categories. The result is safe to use as a conservative
 * identity: two dynamic names can merge, but the original identifier cannot leak.
 */
export function minimizeDynamicIdentifier(value, maxLength = 256) {
  if (typeof value !== "string") return "";
  let normalized = value.trim();
  if (!normalized) return "";
  const trackingFamily = minimizeTrackingCookieFamily(normalized);
  if (trackingFamily) return trackingFamily.slice(0, maxLength);
  normalized = normalized
    .replace(UUID_IDENTIFIER, "\u0001uuid\u0001")
    .replace(LONG_HEX_IDENTIFIER, (candidate) => {
      const uniqueCharacters = new Set(candidate.toLowerCase()).size;
      return /[a-f]/i.test(candidate) && (/\d/.test(candidate) || uniqueCharacters >= 4)
        ? "\u0001hex\u0001"
        : candidate;
    })
    .replace(LONG_TOKEN_IDENTIFIER, minimizeTokenCandidate)
    .replace(LONG_NUMBER_IDENTIFIER, "__number__")
    .replaceAll("\u0001uuid\u0001", "__uuid__")
    .replaceAll("\u0001hex\u0001", "__hex__");
  normalized = minimizeSemanticIdentifierSuffix(normalized);
  normalized = minimizeUnknownIdentifierTokens(normalized);
  return normalized.slice(0, maxLength);
}

function opaqueFingerprint(value) {
  const text = String(value || "");
  let first = 0xcbf29ce484222325n;
  let second = 0x84222325cbf29ce4n;
  for (let index = 0; index < text.length; index += 1) {
    const code = BigInt(text.charCodeAt(index));
    first ^= code;
    first = BigInt.asUintN(64, first * 0x100000001b3n);
    second ^= code + BigInt(index & 0xff);
    second = BigInt.asUintN(64, second * 0x100000001b3n);
  }
  return `${first.toString(16).padStart(16, "0")}${second.toString(16).padStart(16, "0")}`;
}

export function documentUrlFingerprint(rawUrl) {
  try {
    const boundedUrl = boundedNetworkUrlText(rawUrl);
    if (!boundedUrl) return "";
    const parsed = new URL(boundedUrl);
    if (!["http:", "https:"].includes(parsed.protocol)) return "";
    parsed.username = "";
    parsed.password = "";
    return opaqueFingerprint(parsed.href);
  } catch {
    return "";
  }
}

function sanitizePathSegment(segment) {
  const decoded = safeDecodeURIComponent(segment).trim();
  if (!decoded) return "";
  if (decoded.length > 48 || decoded.includes("@") || TOKEN_LIKE_PATH.test(decoded)) {
    return ":redacted";
  }
  if (/^\d+$/.test(decoded)) return ":id";

  const normalized = decoded.toLowerCase().replace(/[^a-z0-9._~-]/g, "-").slice(0, 48);
  if (/^v\d{1,3}$/.test(normalized) || STATIC_LOCALE_SEGMENTS.has(normalized)) {
    return normalized;
  }

  const extensionMatch = /\.([a-z0-9]{1,8})$/.exec(normalized);
  const withoutExtension = extensionMatch ? normalized.slice(0, -extensionMatch[0].length) : normalized;
  const words = withoutExtension.split(/[-_.]+/).filter(Boolean);
  if (words.length > 0 && words.every((word) => STATIC_ROUTE_WORDS.has(word))) {
    return encodeURIComponent(normalized);
  }
  if (extensionMatch && /^(?:css|gif|html?|ico|jpe?g|js|json|png|svg|txt|webp)$/.test(extensionMatch[1])) {
    return `:file.${extensionMatch[1]}`;
  }
  return ":segment";
}

export function minimizePathname(pathname, options = {}) {
  const maxSegments = options.maxSegments || DEFAULT_MAX_PATH_SEGMENTS;
  const maxLength = options.maxLength || DEFAULT_MAX_PATH_LENGTH;
  const segments = String(pathname || "/")
    .slice(0, Math.max(4_096, maxLength * 8))
    .split("/")
    .filter(Boolean)
    .slice(0, maxSegments)
    .map(sanitizePathSegment)
    .filter(Boolean);
  const minimized = segments.length > 0 ? `/${segments.join("/")}` : "/";
  return minimized.slice(0, maxLength);
}

export function sanitizeFieldKeys(keys, options = {}) {
  const maxKeys = options.maxKeys || DEFAULT_MAX_FIELD_KEYS;
  const maxLength = options.maxLength || DEFAULT_MAX_FIELD_KEY_LENGTH;
  const sanitized = [];
  const seen = new Set();

  const source =
    Array.isArray(keys) || (keys && typeof keys !== "string" && typeof keys[Symbol.iterator] === "function")
      ? keys
      : [];
  for (const key of source) {
    if (sanitized.length >= maxKeys) break;
    if (typeof key !== "string") continue;
    const raw = key.trim();
    if (raw.length > Math.max(4_096, maxLength * 8)) continue;
    const normalized = minimizeDynamicIdentifier(raw, Math.max(4_096, maxLength * 8));
    if (normalized === "__identifier__") continue;
    if (normalized.length > maxLength) continue;
    if (!normalized || !/^[\p{L}\p{N}_.\[\]-]+$/u.test(normalized) || seen.has(normalized)) continue;
    seen.add(normalized);
    sanitized.push(normalized);
  }

  return sanitized;
}

export function sanitizeNetworkUrl(rawUrl, options = {}) {
  try {
    const boundedUrl = boundedNetworkUrlText(rawUrl);
    if (!boundedUrl) return null;
    const parsed = new URL(boundedUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) return null;

    const path = minimizePathname(parsed.pathname, options);
    const queryKeys = sanitizeFieldKeys(parsed.searchParams.keys(), options);
    return {
      url: `${parsed.protocol}//${parsed.host}${path}`,
      origin: parsed.origin,
      host: parsed.hostname.toLowerCase(),
      path,
      scheme: parsed.protocol.slice(0, -1),
      queryKeys
    };
  } catch {
    return null;
  }
}

export function sameDocumentUrl(left, right) {
  function identity(value) {
    try {
      const boundedUrl = boundedNetworkUrlText(value);
      if (!boundedUrl) return "";
      const parsed = new URL(boundedUrl);
      if (!["http:", "https:"].includes(parsed.protocol)) return "";
      parsed.username = "";
      parsed.password = "";
      parsed.hash = "";
      return parsed.href;
    } catch {
      return "";
    }
  }

  const leftIdentity = identity(left);
  return Boolean(leftIdentity && leftIdentity === identity(right));
}

export function sanitizeRequestDetails(details = {}) {
  const normalizedUrl = sanitizeNetworkUrl(details.url);
  if (!normalizedUrl || !Number.isInteger(details.tabId) || details.tabId < 0) return null;

  // The listener deliberately does not request Chrome's request-body view, so
  // form values and raw upload bytes never cross that API boundary.
  return {
    url: normalizedUrl.url,
    host: normalizedUrl.host,
    path: normalizedUrl.path,
    scheme: normalizedUrl.scheme,
    method: clipString(details.method, 16).toUpperCase(),
    type: clipString(details.type, 32),
    timeStamp: Number.isFinite(details.timeStamp) ? details.timeStamp : Date.now(),
    queryKeys: normalizedUrl.queryKeys,
    bodyKeys: []
  };
}

export function hostMatchesCookieDomain(host, cookieDomain) {
  const normalizedHost = String(host || "").toLowerCase().replace(/^\./, "");
  const normalizedDomain = String(cookieDomain || "").toLowerCase().replace(/^\./, "");
  return Boolean(
    normalizedHost &&
      normalizedDomain &&
      (normalizedHost === normalizedDomain || normalizedHost.endsWith(`.${normalizedDomain}`))
  );
}

function normalizedPartitionKey(partitionKey) {
  const value = typeof partitionKey === "string" ? partitionKey : partitionKey?.topLevelSite;
  const normalized = sanitizeNetworkUrl(value);
  return normalized
    ? {
        topLevelSite: normalized.origin,
        hasCrossSiteAncestor: Boolean(
          typeof partitionKey === "object" && partitionKey?.hasCrossSiteAncestor
        )
      }
    : null;
}

function normalizedPartitionSite(partitionKey) {
  return normalizedPartitionKey(partitionKey)?.topLevelSite || "";
}

export function cookieIdentity(cookie = {}) {
  const partitionKey = normalizedPartitionKey(cookie.partitionKey);
  const rawPath = clipString(cookie.path, 512) || "/";
  const pathFingerprint = /^[a-f0-9]{32}$/i.test(cookie.pathFingerprint || "")
    ? String(cookie.pathFingerprint).toLowerCase()
    : opaqueFingerprint(rawPath);
  const minimizedName = minimizeDynamicIdentifier(cookie.name, 256);
  const nameIdentity =
    cookie && typeof cookie === "object" && transientCookieNameIdentities.has(cookie)
      ? transientCookieNameIdentities.get(cookie)
      : minimizedName;
  return [
    clipString(cookie.storeId, 80),
    partitionKey?.topLevelSite || "",
    partitionKey ? String(partitionKey.hasCrossSiteAncestor) : "",
    clipString(cookie.domain, 255).toLowerCase().replace(/^\./, ""),
    pathFingerprint,
    nameIdentity
  ].join("\u0000");
}

export function sanitizeCookieRecord(cookie = {}, metadata = {}) {
  const partitionKey = normalizedPartitionKey(cookie.partitionKey);
  const rawPath = clipString(cookie.path, 512) || "/";
  const minimizedPath = minimizePathname(rawPath, { maxSegments: 4, maxLength: 180 });
  const pathFingerprint = /^[a-f0-9]{32}$/i.test(cookie.pathFingerprint || "")
    ? String(cookie.pathFingerprint).toLowerCase()
    : opaqueFingerprint(rawPath);
  const removed = Boolean(
    Object.hasOwn(metadata, "removed") ? metadata.removed : cookie.removed
  );
  const deletedAt = [metadata.deletedAt, cookie.deletedAt]
    .find((value) => Number.isFinite(value) && value > 0);
  const explicitFirstSetObservedAt = [
    metadata.firstSetObservedAt,
    cookie.firstSetObservedAt
  ].find((value) => Number.isFinite(value) && value > 0);
  const legacyFirstObservedAt = [
    metadata.firstObservedAt,
    metadata.timeStamp,
    cookie.firstObservedAt,
    cookie.timeStamp
  ].find((value) => Number.isFinite(value) && value > 0);
  // A short-lived V4 writer could persist a delete-only tombstone with the
  // deletion copied into every legacy observation field. Without an explicit
  // set field, prefer losing a same-millisecond set/delete over inventing
  // post-choice tracking from a deletion.
  const safeLegacyFirstObservedAt =
    Number.isFinite(legacyFirstObservedAt) &&
    !(
      !Number.isFinite(explicitFirstSetObservedAt) &&
      removed &&
      Number.isFinite(deletedAt) &&
      legacyFirstObservedAt === deletedAt
    )
      ? legacyFirstObservedAt
      : undefined;
  const firstSetObservedAt = [explicitFirstSetObservedAt, safeLegacyFirstObservedAt]
    .find((value) => Number.isFinite(value) && value > 0);
  const explicitLastSetObservedAt = [
    metadata.lastSetObservedAt,
    cookie.lastSetObservedAt
  ].find((value) => Number.isFinite(value) && value > 0);
  const legacyLastObservedAt = [metadata.lastObservedAt, cookie.lastObservedAt]
    .find((value) => Number.isFinite(value) && value > 0);
  // V4 records written before set/delete evidence was split could have used a
  // deletion time as lastObservedAt. Do not migrate that deletion into a set.
  const safeLegacyLastObservedAt =
    Number.isFinite(legacyLastObservedAt) &&
    !(Number.isFinite(deletedAt) && legacyLastObservedAt === deletedAt)
      ? legacyLastObservedAt
      : undefined;
  const lastSetObservedAt = [
    explicitLastSetObservedAt,
    safeLegacyLastObservedAt,
    firstSetObservedAt
  ].find((value) => Number.isFinite(value) && value > 0);
  const hasObservedTime =
    Boolean(partitionKey) &&
    metadata.timingConfidence === "observed" &&
    Number.isFinite(firstSetObservedAt);
  const rawName = clipString(cookie.name, 256);
  const minimizedName = minimizeDynamicIdentifier(rawName, 256);
  const inheritedNameIdentity =
    cookie && typeof cookie === "object" ? transientCookieNameIdentities.get(cookie) : "";
  // A persisted record can be reconciled by identity only when neither its
  // display name nor path had to be minimized. This coarse boolean is safe to
  // persist; the raw-name/path fingerprints remain memory-only.
  const identityStable =
    typeof metadata.identityStable === "boolean"
      ? metadata.identityStable
      : typeof cookie.identityStable === "boolean"
      ? cookie.identityStable
      : rawName === minimizedName && rawPath === minimizedPath;
  const record = {
    name: minimizedName,
    domain: clipString(cookie.domain, 255).toLowerCase(),
    hostOnly: Boolean(cookie.hostOnly),
    path: minimizedPath,
    pathFingerprint,
    identityStable,
    secure: Boolean(cookie.secure),
    httpOnly: Boolean(cookie.httpOnly),
    sameSite: clipString(cookie.sameSite, 32),
    session: Boolean(cookie.session),
    expirationDate: Number.isFinite(cookie.expirationDate) ? cookie.expirationDate : undefined,
    storeId: clipString(cookie.storeId, 80),
    partitionKey: partitionKey || undefined,
    removed,
    cause: clipString(metadata.cause, 40),
    timingConfidence: hasObservedTime ? "observed" : "unknown"
  };
  transientCookieNameIdentities.set(
    record,
    inheritedNameIdentity || (rawName === minimizedName ? minimizedName : opaqueFingerprint(rawName))
  );
  if (hasObservedTime) {
    record.firstSetObservedAt = firstSetObservedAt;
    record.lastSetObservedAt = Math.max(
      firstSetObservedAt,
      lastSetObservedAt || firstSetObservedAt
    );
    // These aliases remain for existing report and extension consumers. Both
    // now mean non-removal set/update evidence only.
    record.firstObservedAt = record.firstSetObservedAt;
    record.lastObservedAt = record.lastSetObservedAt;
    // Keep the legacy field as an alias for consumers written before the
    // bounded first/last evidence model. It always means first observation.
    record.timeStamp = record.firstSetObservedAt;
  }
  if (Boolean(partitionKey) && Number.isFinite(deletedAt)) record.deletedAt = deletedAt;
  return record;
}

export function reconcileCookieRecords(records, changeInfo, options = {}) {
  const maxRecords = options.maxRecords || 120;
  const cookie = changeInfo?.cookie;
  if (!cookie?.domain || !cookie?.name) return Array.isArray(records) ? records.slice(-maxRecords) : [];

  const active = new Map();
  for (const record of Array.isArray(records) ? records : []) {
    if (!record) continue;
    const sanitizedRecord = sanitizeCookieRecord(record, record);
    if (
      sanitizedRecord.removed &&
      !(sanitizedRecord.timingConfidence === "observed" &&
        Number.isFinite(sanitizedRecord.firstSetObservedAt))
    ) {
      continue;
    }
    active.set(cookieIdentity(sanitizedRecord), sanitizedRecord);
  }

  const identity = cookieIdentity(sanitizeCookieRecord(cookie, cookie));
  const previous = active.get(identity);
  const fallbackEventAt = [options.observedAt, options.now]
    .find((value) => Number.isFinite(value) && value > 0);
  const eventFirstSetObservedAt = [
    options.firstSetObservedAt,
    changeInfo.removed ? undefined : options.firstObservedAt,
    changeInfo.removed ? undefined : fallbackEventAt
  ].find((value) => Number.isFinite(value) && value > 0);
  const eventLastSetObservedAt = [
    options.lastSetObservedAt,
    changeInfo.removed ? undefined : options.lastObservedAt,
    changeInfo.removed ? undefined : fallbackEventAt,
    eventFirstSetObservedAt
  ].find((value) => Number.isFinite(value) && value > 0);
  const eventDeletedAt = [
    options.deletedAt,
    changeInfo.removed ? fallbackEventAt : undefined
  ].find((value) => Number.isFinite(value) && value > 0);
  const previousFirstSetObservedAt =
    previous?.timingConfidence === "observed"
      ? [previous.firstSetObservedAt, previous.firstObservedAt, previous.timeStamp].find(
          (value) => Number.isFinite(value) && value > 0
        )
      : undefined;
  const previousLastSetObservedAt =
    previous?.timingConfidence === "observed"
      ? [
          previous.lastSetObservedAt,
          previous.lastObservedAt === previous.deletedAt
            ? undefined
            : previous.lastObservedAt,
          previousFirstSetObservedAt
        ].find((value) => Number.isFinite(value) && value > 0)
      : undefined;
  const firstSetObservedAt = [previousFirstSetObservedAt, eventFirstSetObservedAt]
    .filter((value) => Number.isFinite(value))
    .reduce((earliest, value) => Math.min(earliest, value), Number.POSITIVE_INFINITY);
  const lastSetObservedAt = [
    previousLastSetObservedAt,
    previousFirstSetObservedAt,
    eventLastSetObservedAt
  ]
    .filter((value) => Number.isFinite(value))
    .reduce((latest, value) => Math.max(latest, value), Number.NEGATIVE_INFINITY);
  const hasObservedEvidence =
    Boolean(normalizedPartitionKey(cookie.partitionKey)) && Number.isFinite(firstSetObservedAt);

  // A deletion alone is not evidence that the site set or updated a cookie in
  // this observation session. A tombstone survives only when it already has
  // safely attributed non-removal evidence.
  if (changeInfo.removed && !hasObservedEvidence) {
    active.delete(identity);
  } else {
    const deletedAt = [previous?.deletedAt, eventDeletedAt]
      .filter((value) => Number.isFinite(value))
      .reduce((latest, value) => Math.max(latest, value), Number.NEGATIVE_INFINITY);
    active.set(
      identity,
      sanitizeCookieRecord(cookie, {
        cause: changeInfo.cause,
        removed: Boolean(changeInfo.removed),
        identityStable:
          typeof previous?.identityStable === "boolean"
            ? previous.identityStable && cookie.identityStable !== false
            : cookie.identityStable,
        timingConfidence: hasObservedEvidence ? "observed" : "unknown",
        firstSetObservedAt: hasObservedEvidence ? firstSetObservedAt : undefined,
        lastSetObservedAt: hasObservedEvidence ? lastSetObservedAt : undefined,
        deletedAt: Number.isFinite(deletedAt) ? deletedAt : undefined
      })
    );
  }

  return Array.from(active.values())
    .sort((left, right) => {
      // Current browser inventory wins bounded capacity over historical
      // tombstones; otherwise a burst of deletions could hide live cookies.
      const stateDifference = Number(!left.removed) - Number(!right.removed);
      if (stateDifference !== 0) return stateDifference;
      return (
        (left.lastSetObservedAt || left.lastObservedAt || left.timeStamp || 0) -
        (right.lastSetObservedAt || right.lastObservedAt || right.timeStamp || 0)
      );
    })
    .slice(-maxRecords);
}

function samePartitionSite(tabUrl, partitionSite) {
  const tab = sanitizeNetworkUrl(tabUrl);
  const partition = sanitizeNetworkUrl(partitionSite);
  if (!tab || !partition || tab.scheme !== partition.scheme) return false;
  return hostMatchesCookieDomain(tab.host, partition.host) || hostMatchesCookieDomain(partition.host, tab.host);
}

export function getCookieAttributionTabIds(changeInfo, tabs = []) {
  const cookie = changeInfo?.cookie;
  if (!cookie?.domain) return [];

  const partitionSite = normalizedPartitionSite(cookie.partitionKey);
  const matching = (Array.isArray(tabs) ? tabs : []).filter(
    (tab) => Number.isInteger(tab?.id) && tab.id >= 0 && sanitizeNetworkUrl(tab.url)
  );

  if (partitionSite) {
    const attributed = matching.filter((tab) => samePartitionSite(tab.url, partitionSite));
    if (!changeInfo.removed && attributed.length !== 1) return [];
    return attributed.map((tab) => tab.id);
  }

  // An unpartitioned third-party cookie has no reliable top-level-tab attribution.
  // It is associated only with tabs where it is a first-party cookie.
  const attributed = matching.filter((tab) =>
    cookie.hostOnly
      ? sanitizeNetworkUrl(tab.url).host === String(cookie.domain || "").toLowerCase().replace(/^\./, "")
      : hostMatchesCookieDomain(sanitizeNetworkUrl(tab.url).host, cookie.domain)
  );
  if (!changeInfo.removed && attributed.length !== 1) return [];
  return attributed.map((tab) => tab.id);
}

export function isObservationSessionCurrent(expected, current) {
  return Boolean(
    expected &&
      current &&
      Number.isFinite(expected.generation) &&
      expected.generation === current.generation &&
      expected.navigationKey === current.navigationKey &&
      expected.origin === current.origin &&
      expected.documentFingerprint === current.documentFingerprint
  );
}

export function isRequestEventInSession(event, session) {
  if (!event || !session) {
    return false;
  }
  if (Number.isFinite(event.sequence) && Number.isFinite(session.startedSequence)) {
    if (event.sequence < session.startedSequence) return false;
  } else if (
    Number.isFinite(event.timeStamp) &&
    Number.isFinite(session.startedAt) &&
    event.timeStamp < session.startedAt
  ) {
    return false;
  }
  if (
    event.type !== "main_frame" &&
    event.frameId === 0 &&
    session.documentId &&
    event.documentId &&
    session.documentId !== event.documentId
  ) {
    return false;
  }
  return true;
}

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function hasExactKeys(value, keys) {
  if (!isPlainObject(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

export function validateRuntimeMessage(message, sender, runtimeId) {
  if (!isPlainObject(message) || !ALLOWED_MESSAGE_TYPES.has(message.type)) {
    return { ok: false, error: "Unsupported message type" };
  }
  if (!sender || sender.id !== runtimeId) {
    return { ok: false, error: "Untrusted message sender" };
  }

  const isContent = Number.isInteger(sender.tab?.id) && sender.tab.id >= 0;
  if (CONTENT_MESSAGE_TYPES.has(message.type)) {
    if (!isContent || (sender.frameId !== undefined && sender.frameId !== 0)) {
      return { ok: false, error: "Message requires a top-level content sender" };
    }
    if (message.type === "GET_COMPANION_OVERLAY_STATE") {
      let senderUrl;
      try {
        senderUrl = new URL(sender.url);
      } catch {
        // Rejected below with the same bounded validation response.
      }
      const validDocumentId =
        typeof sender.documentId === "string" &&
        sender.documentId.length > 0 &&
        sender.documentId.length <= 128;
      const validLifecycle = sender.documentLifecycle === "active";
      const validUrl =
        ["http:", "https:"].includes(senderUrl?.protocol) &&
        sameDocumentUrl(sender.url, sender.tab?.url || "");
      if (!hasExactKeys(message, ["type"]) || !validDocumentId || !validLifecycle || !validUrl) {
        return { ok: false, error: "Invalid companion overlay sender" };
      }
    }
    if (message.type === "PAGE_RISK_SCAN") {
      const hasValidAssessment =
        typeof message.policyLike === "boolean" &&
        Number.isFinite(message.policyConfidence) &&
        message.policyConfidence >= 0 &&
        message.policyConfidence <= 1 &&
        Number.isFinite(message.textLength) &&
        message.textLength >= 0 &&
        message.textLength <= 120_000;
      const hasValidText = message.policyLike
        ? typeof message.text === "string" && message.text.length <= 120_000
        : message.text === undefined || message.text === "";
      if (!hasValidAssessment || !hasValidText) {
        return { ok: false, error: "Invalid page scan payload" };
      }
    }
    return { ok: true, type: message.type, source: "content", tabId: sender.tab.id };
  }

  if (POPUP_MESSAGE_TYPES.has(message.type)) {
    if (isContent) return { ok: false, error: "Message requires an extension-page sender" };
    const tablessMessage = [
      "CHECK_SAVED_POLICIES_NOW",
      "GET_COMPANION_OVERLAY_PREFERENCE",
      "SET_COMPANION_OVERLAY_PREFERENCE"
    ].includes(message.type);
    if (!tablessMessage && (!Number.isInteger(message.tabId) || message.tabId < 0)) {
      return { ok: false, error: "Invalid tab id" };
    }
    if (
      message.type === "GET_COMPANION_OVERLAY_PREFERENCE" &&
      !hasExactKeys(message, ["type"])
    ) {
      return { ok: false, error: "Invalid companion overlay preference request" };
    }
    if (
      message.type === "SET_COMPANION_OVERLAY_PREFERENCE" &&
      (!hasExactKeys(message, ["type", "enabled"]) || typeof message.enabled !== "boolean")
    ) {
      return { ok: false, error: "Invalid companion overlay preference request" };
    }
    if (["CLEAR_NETWORK_ACTIVITY", "SAVE_OBSERVATION_SNAPSHOT"].includes(message.type)) {
      const validDocumentId =
        typeof message.documentId === "string" &&
        message.documentId.length > 0 &&
        message.documentId.length <= 128;
      const validDocumentFingerprint =
        typeof message.documentFingerprint === "string" &&
        /^[a-f0-9]{32}$/.test(message.documentFingerprint);
      if (!validDocumentId || !validDocumentFingerprint) {
        return { ok: false, error: "Invalid observation page context" };
      }
    }
    if (
      message.type === "SAVE_OBSERVATION_SNAPSHOT" &&
      message.label !== undefined &&
      (typeof message.label !== "string" || message.label.length > 120)
    ) {
      return { ok: false, error: "Invalid snapshot label" };
    }
    if (message.type === "SAVE_MONITORED_POLICY_SNAPSHOT") {
      let policyUrl = null;
      try {
        policyUrl = new URL(message.policyUrl);
      } catch {
        // Rejected below with the same bounded validation response.
      }
      const validPolicyUrl =
        typeof message.policyUrl === "string" &&
        message.policyUrl.length > 0 &&
        message.policyUrl.length <= 2_048 &&
        policyUrl?.protocol === "https:" &&
        !policyUrl.username &&
        !policyUrl.password &&
        !policyUrl.hash;
      const validTitle =
        typeof message.title === "string" && message.title.length <= 512;
      const validDocumentId =
        typeof message.documentId === "string" &&
        message.documentId.length > 0 &&
        message.documentId.length <= 128;
      const hasNoPageText = !Object.prototype.hasOwnProperty.call(message, "text");
      if (!validPolicyUrl || !validTitle || !validDocumentId || !hasNoPageText) {
        return { ok: false, error: "Invalid monitored policy snapshot request" };
      }
    }
    if (message.type === "SET_RISK_INDICATOR") {
      const indicator = message.indicator;
      const validIndicator =
        isPlainObject(indicator) &&
        (indicator.level === undefined || (typeof indicator.level === "string" && indicator.level.length <= 40)) &&
        (indicator.score === undefined || indicator.score === null || Number.isFinite(indicator.score)) &&
        (indicator.label === undefined || (typeof indicator.label === "string" && indicator.label.length <= 240)) &&
        (indicator.source === undefined || (typeof indicator.source === "string" && indicator.source.length <= 40)) &&
        (indicator.title === undefined || (typeof indicator.title === "string" && indicator.title.length <= 512)) &&
        typeof indicator.documentFingerprint === "string" &&
        /^[a-f0-9]{32}$/.test(indicator.documentFingerprint) &&
        typeof indicator.documentId === "string" &&
        indicator.documentId.length > 0 &&
        indicator.documentId.length <= 128 &&
        typeof indicator.url === "string" &&
        indicator.url.length > 0 &&
        indicator.url.length <= 2048;
      if (!validIndicator) return { ok: false, error: "Invalid risk indicator" };
    }
    return { ok: true, type: message.type, source: "extension-page", tabId: message.tabId };
  }

  return { ok: false, error: "Invalid message" };
}

function parseIpv4Address(hostname) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(hostname);
  if (!match) return null;
  const octets = match.slice(1).map(Number);
  return octets.some((octet) => octet > 255) ? null : octets;
}

function isNonGlobalIpv4(octets) {
  if (!Array.isArray(octets) || octets.length !== 4) return true;
  return (
    octets[0] === 10 ||
    octets[0] === 127 ||
    octets[0] === 0 ||
    (octets[0] === 100 && octets[1] >= 64 && octets[1] <= 127) ||
    (octets[0] === 169 && octets[1] === 254) ||
    (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
    (octets[0] === 192 && octets[1] === 168) ||
    (octets[0] === 192 && octets[1] === 0 && [0, 2].includes(octets[2])) ||
    (octets[0] === 198 && [18, 19].includes(octets[1])) ||
    (octets[0] === 198 && octets[1] === 51 && octets[2] === 100) ||
    (octets[0] === 203 && octets[1] === 0 && octets[2] === 113) ||
    octets[0] >= 224
  );
}

function parseIpv6Address(hostname) {
  if (!hostname || hostname.includes("%") || (hostname.match(/::/g) || []).length > 1) return null;

  let source = hostname;
  const dottedSuffix = /(?:^|:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(source);
  if (dottedSuffix) {
    const octets = parseIpv4Address(dottedSuffix[1]);
    if (!octets) return null;
    const ipv4Hextets = [
      ((octets[0] << 8) | octets[1]).toString(16),
      ((octets[2] << 8) | octets[3]).toString(16)
    ];
    source = `${source.slice(0, dottedSuffix.index)}:${ipv4Hextets.join(":")}`;
  }

  const hasCompression = source.includes("::");
  const [leftSource, rightSource = ""] = source.split("::");
  const left = leftSource ? leftSource.split(":") : [];
  const right = rightSource ? rightSource.split(":") : [];
  if (
    [...left, ...right].some((part) => !/^[\da-f]{1,4}$/i.test(part)) ||
    (!hasCompression && left.length !== 8) ||
    (hasCompression && left.length + right.length >= 8)
  ) {
    return null;
  }

  const missing = hasCompression ? 8 - left.length - right.length : 0;
  const parts = [...left, ...Array.from({ length: missing }, () => "0"), ...right];
  return parts.length === 8 ? parts.map((part) => Number.parseInt(part, 16)) : null;
}

function embeddedIpv4(segments, firstSegment) {
  return [
    segments[firstSegment] >> 8,
    segments[firstSegment] & 0xff,
    segments[firstSegment + 1] >> 8,
    segments[firstSegment + 1] & 0xff
  ];
}

function isNonGlobalIpv6(hostname) {
  const segments = parseIpv6Address(hostname);
  if (!segments) return true;

  const allZeroThrough = (end) => segments.slice(0, end).every((part) => part === 0);
  const unspecified = segments.every((part) => part === 0);
  const loopback = allZeroThrough(7) && segments[7] === 1;
  const uniqueLocal = (segments[0] & 0xfe00) === 0xfc00;
  const linkLocal = (segments[0] & 0xffc0) === 0xfe80;
  const deprecatedSiteLocal = (segments[0] & 0xffc0) === 0xfec0;
  const multicast = (segments[0] & 0xff00) === 0xff00;
  const documentation2001 = segments[0] === 0x2001 && segments[1] === 0x0db8;
  const documentation3fff = segments[0] === 0x3fff && (segments[1] & 0xf000) === 0;
  const discardOnly =
    segments[0] === 0x0100 && segments[1] === 0 && segments[2] === 0 && segments[3] === 0;
  const benchmarking =
    segments[0] === 0x2001 && segments[1] === 0x0002 && segments[2] === 0;
  const orchid =
    segments[0] === 0x2001 &&
    ((segments[1] & 0xfff0) === 0x0010 || (segments[1] & 0xfff0) === 0x0020);
  const localTranslation =
    segments[0] === 0x0064 && segments[1] === 0xff9b && segments[2] === 1;
  const segmentRoutingSids = segments[0] === 0x5f00;

  if (
    unspecified ||
    loopback ||
    uniqueLocal ||
    linkLocal ||
    deprecatedSiteLocal ||
    multicast ||
    documentation2001 ||
    documentation3fff ||
    discardOnly ||
    benchmarking ||
    orchid ||
    localTranslation ||
    segmentRoutingSids
  ) {
    return true;
  }

  // URL parsers render dotted IPv4 suffixes as hextets, so inspect known
  // IPv4-embedding layouts after parsing instead of relying on source text.
  const ipv4Compatible = allZeroThrough(6);
  const ipv4Mapped = allZeroThrough(5) && segments[5] === 0xffff;
  const ipv4Translated = allZeroThrough(4) && segments[4] === 0xffff && segments[5] === 0;
  const wellKnownTranslation =
    segments[0] === 0x0064 &&
    segments[1] === 0xff9b &&
    segments.slice(2, 6).every((part) => part === 0);
  const sixToFour = segments[0] === 0x2002;
  const isatap =
    [0, 0x0200].includes(segments[4]) && segments[5] === 0x5efe;
  if (ipv4Compatible || ipv4Mapped || ipv4Translated || wellKnownTranslation || isatap) {
    return isNonGlobalIpv4(embeddedIpv4(segments, 6));
  }
  if (sixToFour) return isNonGlobalIpv4(embeddedIpv4(segments, 1));

  // Teredo embeds IPv4 addresses and is not a trustworthy route to a fetched
  // policy host. Reject the entire special-purpose prefix fail-closed.
  if (segments[0] === 0x2001 && segments[1] === 0) return true;
  return false;
}

function isPrivateHostname(hostname) {
  const host = String(hostname || "")
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
  if (
    !host ||
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "localdomain" ||
    host.endsWith(".localdomain") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".lan") ||
    host.endsWith(".home.arpa") ||
    host.endsWith(".invalid") ||
    host.endsWith(".test") ||
    host.endsWith(".onion")
  ) {
    return true;
  }
  if (!host.includes(".") && !host.includes(":")) return true;
  if (host.includes(":")) return isNonGlobalIpv6(host);
  const octets = parseIpv4Address(host);
  return octets ? isNonGlobalIpv4(octets) : false;
}

export function validatePolicyFetchUrl(rawUrl, options = {}) {
  let parsed;
  try {
    if (typeof rawUrl !== "string" || rawUrl.length > 2_048) throw new Error("Invalid policy URL");
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("Invalid policy URL");
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error("Unsupported policy URL scheme");
  if (parsed.username || parsed.password) throw new Error("Policy URL credentials are not allowed");
  if (isPrivateHostname(parsed.hostname) && !options.allowPrivateHosts) {
    throw new Error("Private policy hosts are not allowed");
  }
  if (parsed.protocol !== "https:") throw new Error("HTTPS policy URLs are required");
  if (Array.from(parsed.searchParams.keys()).some(isSensitiveQueryKey)) {
    throw new Error("Sensitive policy URL parameters are not allowed");
  }

  parsed.hash = "";
  return parsed;
}

export function isAllowedPolicyContentType(contentType) {
  const mimeType = String(contentType || "").split(";", 1)[0].trim().toLowerCase();
  return ["text/html", "application/xhtml+xml", "text/plain"].includes(mimeType);
}

export async function readResponseTextLimited(response, maxBytes = DEFAULT_POLICY_MAX_BYTES) {
  const declaredLength = Number(response.headers?.get?.("content-length"));
  if (Number.isFinite(declaredLength) && declaredLength > maxBytes) {
    throw new Error("Policy response exceeds the size limit");
  }

  if (!response.body?.getReader) {
    const buffer = await response.arrayBuffer();
    if (buffer.byteLength > maxBytes) throw new Error("Policy response exceeds the size limit");
    return new TextDecoder("utf-8", { fatal: false }).decode(buffer);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: false });
  let received = 0;
  let text = "";

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      await reader.cancel().catch(() => {});
      throw new Error("Policy response exceeds the size limit");
    }
    text += decoder.decode(value, { stream: true });
  }

  return text + decoder.decode();
}

export async function mapPolicyChecksWithConcurrency(entries, mapper, requestedConcurrency = 4) {
  const items = Array.isArray(entries) ? entries : Array.from(entries || []);
  if (typeof mapper !== "function") throw new TypeError("A policy check function is required");
  if (items.length === 0) return [];

  const parsedConcurrency = Number(requestedConcurrency);
  const concurrency = Math.min(
    4,
    Math.max(1, Number.isFinite(parsedConcurrency) ? Math.floor(parsedConcurrency) : 4)
  );
  const results = new Array(items.length);
  let nextIndex = 0;

  async function worker() {
    while (nextIndex < items.length) {
      const index = nextIndex;
      nextIndex += 1;
      results[index] = await mapper(items[index], index);
    }
  }

  await Promise.all(Array.from({ length: Math.min(concurrency, items.length) }, () => worker()));
  return results;
}

export async function fetchPolicyDocument(rawUrl, options = {}) {
  const fetchImpl = options.fetchImpl || fetch;
  const timeoutMs = options.timeoutMs || DEFAULT_POLICY_TIMEOUT_MS;
  const maxBytes = options.maxBytes || DEFAULT_POLICY_MAX_BYTES;
  const requestUrl = validatePolicyFetchUrl(rawUrl, options);
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetchImpl(requestUrl.href, {
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      signal: controller.signal,
      headers: { Accept: "text/html,application/xhtml+xml,text/plain;q=0.9" }
    });

    if (response.status >= 300 && response.status < 400) {
      await response.body?.cancel?.().catch?.(() => {});
      throw new Error("Policy redirects are not allowed");
    }
    if (!response.ok) {
      await response.body?.cancel?.().catch?.(() => {});
      throw new Error(`Policy fetch failed: ${response.status}`);
    }

    const finalUrl = validatePolicyFetchUrl(response.url || requestUrl.href, options);
    if (finalUrl.href !== requestUrl.href) {
      await response.body?.cancel?.().catch?.(() => {});
      throw new Error("Unexpected policy redirect");
    }
    if (!isAllowedPolicyContentType(response.headers?.get?.("content-type"))) {
      await response.body?.cancel?.().catch?.(() => {});
      throw new Error("Unsupported policy content type");
    }

    return {
      url: finalUrl.href,
      text: await readResponseTextLimited(response, maxBytes),
      contentType: response.headers.get("content-type")
    };
  } catch (error) {
    if (error?.name === "AbortError") throw new Error("Policy fetch timed out");
    throw error;
  } finally {
    clearTimeout(timeoutId);
  }
}
