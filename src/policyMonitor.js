import { t } from "./i18n.js";
import { hashText, normalizePolicyText } from "./policySnapshots.js";

const IMPORTANT_SECTION_IDS = new Set([
  "collected_data",
  "purpose",
  "third_party",
  "cookies_tracking",
  "overseas_transfer",
  "retention",
  "legal_basis",
  "automated_decision",
  "user_rights",
  "security",
  "processors",
  "children",
  "dispute_liability"
]);
const COMMON_HTML_ENTITIES = Object.freeze({
  amp: "&",
  apos: "'",
  bull: "•",
  copy: "©",
  emsp: " ",
  ensp: " ",
  gt: ">",
  hellip: "…",
  ldquo: "“",
  lsquo: "‘",
  lt: "<",
  mdash: "—",
  middot: "·",
  nbsp: " ",
  ndash: "–",
  quot: '"',
  rdquo: "”",
  reg: "®",
  rsquo: "’",
  thinsp: " ",
  trade: "™"
});
const MAX_POLICY_HTML_CHARS = 1024 * 1024;
const MAX_EXTRACTED_TEXT_CHARS = 256 * 1024;
const MAX_HTML_STACK_DEPTH = 256;
const SKIPPED_HTML_TAGS = new Set(["script", "style", "noscript", "template", "svg"]);
const VOID_HTML_TAGS = new Set([
  "area",
  "base",
  "br",
  "col",
  "embed",
  "hr",
  "img",
  "input",
  "link",
  "meta",
  "param",
  "source",
  "track",
  "wbr"
]);

export function extractPolicyTextFromHtml(html) {
  const regions = scanPolicyHtml(String(html || "").slice(0, MAX_POLICY_HTML_CHARS));
  const mainText = finalizeExtractedText(regions.main);
  const articleText = finalizeExtractedText(regions.article);
  const semanticText = mainText.length >= articleText.length ? mainText : articleText;

  if (semanticText) return semanticText;
  return finalizeExtractedText(regions.body) || finalizeExtractedText(regions.document);
}

export function shouldNotifyPolicyChange(changeAnalysis) {
  if (!changeAnalysis?.hasPrevious || !changeAnalysis.changed) return false;

  const hasImportantSectionChange = (changeAnalysis.sectionChanges || []).some((change) =>
    IMPORTANT_SECTION_IDS.has(change.id)
  );
  const hasNewRisk = (changeAnalysis.riskChanges?.added || []).length > 0;

  return hasImportantSectionChange || hasNewRisk;
}

export function buildPolicyChangeNotification(snapshot, changeAnalysis) {
  const changedSections = (changeAnalysis.sectionChanges || [])
    .filter((change) => IMPORTANT_SECTION_IDS.has(change.id))
    .map((change) => change.label)
    .slice(0, 4);
  const newRisks = (changeAnalysis.riskChanges?.added || []).slice(0, 3);
  const parts = [];

  if (changedSections.length > 0) {
    parts.push(`${t("policyNotificationChangedSection")}: ${changedSections.join(", ")}`);
  }

  if (newRisks.length > 0) {
    parts.push(`${t("policyNotificationNewRisk")}: ${newRisks.join(", ")}`);
  }

  return {
    title: t("policyChangeTitle"),
    message: `${hostFromUrl(snapshot.url) || snapshot.origin} - ${parts.join(" / ") || t("policyNotificationDefault")}`
  };
}

export function buildPolicyChangeDedupeKey(origin, changeAnalysis, currentSnapshot) {
  const sectionPart = (changeAnalysis.sectionChanges || [])
    .map((change) => `${change.id}:${change.changeType}`)
    .sort()
    .join("|");
  const riskPart = [...(changeAnalysis.riskChanges?.added || [])].sort().join("|");
  return hashText(`${origin}:${currentSnapshot.textHash}:${sectionPart}:${riskPart}`);
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function decodeNumericEntity(original, value, radix) {
  const codePoint = Number.parseInt(value, radix);
  if (!Number.isFinite(codePoint) || codePoint < 0 || codePoint > 0x10ffff) return original;
  return String.fromCodePoint(codePoint);
}

function scanPolicyHtml(source) {
  const regions = {
    main: createTextAccumulator(),
    article: createTextAccumulator(),
    body: createTextAccumulator(),
    document: createTextAccumulator()
  };
  const stack = [];
  const context = {
    articleDepth: 0,
    bodyDepth: 0,
    hiddenOverflow: false,
    mainDepth: 0,
    skippedDepth: 0
  };
  let cursor = 0;

  while (cursor < source.length) {
    const tagStart = source.indexOf("<", cursor);
    if (tagStart < 0) {
      appendVisibleText(regions, context, source.slice(cursor));
      break;
    }

    if (tagStart > cursor) appendVisibleText(regions, context, source.slice(cursor, tagStart));

    if (source.startsWith("<!--", tagStart)) {
      const commentEnd = source.indexOf("-->", tagStart + 4);
      appendVisibleText(regions, context, " ");
      cursor = commentEnd < 0 ? source.length : commentEnd + 3;
      continue;
    }

    const tagEnd = findTagEnd(source, tagStart + 1);
    if (tagEnd < 0) {
      appendVisibleText(regions, context, source.slice(tagStart));
      break;
    }

    const tag = parseHtmlTag(source, tagStart + 1, tagEnd);
    appendVisibleText(regions, context, " ");
    if (tag?.closing) {
      closeHtmlTag(tag.name, stack, context);
    } else if (tag && !VOID_HTML_TAGS.has(tag.name)) {
      // In text/html a trailing slash does not self-close non-void elements.
      // Treat it as an opening tag so `<script/>` and `<div hidden/>` cannot
      // expose their following subtree as visible policy text.
      openHtmlTag(tag, stack, context);
    }
    cursor = tagEnd + 1;
  }

  return regions;
}

function createTextAccumulator() {
  return { length: 0, parts: [] };
}

function appendVisibleText(regions, context, text) {
  if (!text || context.skippedDepth > 0 || context.hiddenOverflow) return;
  appendBounded(regions.document, text);
  if (context.bodyDepth > 0) appendBounded(regions.body, text);
  if (context.mainDepth > 0) appendBounded(regions.main, text);
  if (context.articleDepth > 0) appendBounded(regions.article, text);
}

function appendBounded(accumulator, text) {
  const remaining = MAX_EXTRACTED_TEXT_CHARS - accumulator.length;
  if (remaining <= 0) return;
  const part = text.length > remaining ? text.slice(0, remaining) : text;
  accumulator.parts.push(part);
  accumulator.length += part.length;
}

function openHtmlTag(tag, stack, context) {
  const skipped = SKIPPED_HTML_TAGS.has(tag.name) || tag.staticallyHidden;
  if (stack.length >= MAX_HTML_STACK_DEPTH) {
    // Once a skipped subtree begins beyond the bounded parser stack, fail closed
    // for the remainder instead of accidentally exposing its hidden text.
    if (context.skippedDepth > 0 || skipped) context.hiddenOverflow = true;
    return;
  }
  const visible = context.skippedDepth === 0 && !skipped;
  const frame = {
    article: visible && tag.name === "article",
    body: visible && tag.name === "body",
    main: visible && tag.name === "main",
    name: tag.name,
    skipped
  };
  stack.push(frame);
  if (frame.skipped) context.skippedDepth += 1;
  if (frame.article) context.articleDepth += 1;
  if (frame.body) context.bodyDepth += 1;
  if (frame.main) context.mainDepth += 1;
}

function closeHtmlTag(name, stack, context) {
  let matchingIndex = -1;
  for (let index = stack.length - 1; index >= 0; index -= 1) {
    if (stack[index].name === name) {
      matchingIndex = index;
      break;
    }
  }
  if (matchingIndex < 0) return;

  while (stack.length > matchingIndex) {
    const frame = stack.pop();
    if (frame.skipped) context.skippedDepth -= 1;
    if (frame.article) context.articleDepth -= 1;
    if (frame.body) context.bodyDepth -= 1;
    if (frame.main) context.mainDepth -= 1;
  }
}

function findTagEnd(source, start) {
  let quote = "";
  for (let index = start; index < source.length; index += 1) {
    const character = source[index];
    if (quote) {
      if (character === quote) quote = "";
    } else if (character === '"' || character === "'") {
      quote = character;
    } else if (character === ">") {
      return index;
    }
  }
  return -1;
}

function parseHtmlTag(source, start, end) {
  let cursor = skipHtmlWhitespace(source, start, end);
  let closing = false;
  if (source[cursor] === "/") {
    closing = true;
    cursor = skipHtmlWhitespace(source, cursor + 1, end);
  }

  const nameStart = cursor;
  while (cursor < end && isHtmlNameCharacter(source.charCodeAt(cursor))) cursor += 1;
  if (cursor === nameStart) return null;
  const name = source.slice(nameStart, cursor).toLowerCase();
  if (closing) return { closing: true, name, selfClosing: false, staticallyHidden: false };

  let staticallyHidden = false;
  while (cursor < end) {
    cursor = skipHtmlWhitespace(source, cursor, end);
    if (cursor >= end || source[cursor] === "/") break;
    const attributeStart = cursor;
    while (cursor < end && isHtmlAttributeNameCharacter(source.charCodeAt(cursor))) cursor += 1;
    if (cursor === attributeStart) {
      cursor += 1;
      continue;
    }

    const attributeName = source.slice(attributeStart, cursor).toLowerCase();
    cursor = skipHtmlWhitespace(source, cursor, end);
    let attributeValue = "";
    if (source[cursor] === "=") {
      cursor = skipHtmlWhitespace(source, cursor + 1, end);
      const quote = source[cursor] === '"' || source[cursor] === "'" ? source[cursor] : "";
      if (quote) {
        const valueStart = ++cursor;
        while (cursor < end && source[cursor] !== quote) cursor += 1;
        attributeValue = source.slice(valueStart, cursor);
        if (cursor < end) cursor += 1;
      } else {
        const valueStart = cursor;
        while (cursor < end && !isHtmlWhitespace(source.charCodeAt(cursor))) cursor += 1;
        attributeValue = source.slice(valueStart, cursor);
      }
    }

    if (attributeName === "hidden") {
      staticallyHidden = true;
    } else if (attributeName === "aria-hidden" && attributeValue.trim().toLowerCase() === "true") {
      staticallyHidden = true;
    } else if (attributeName === "style" && hasHiddenInlineStyle(attributeValue)) {
      staticallyHidden = true;
    }
  }

  let tail = end - 1;
  while (tail >= start && isHtmlWhitespace(source.charCodeAt(tail))) tail -= 1;
  return { closing: false, name, selfClosing: source[tail] === "/", staticallyHidden };
}

function skipHtmlWhitespace(source, start, end) {
  let cursor = start;
  while (cursor < end && isHtmlWhitespace(source.charCodeAt(cursor))) cursor += 1;
  return cursor;
}

function isHtmlWhitespace(code) {
  return code === 9 || code === 10 || code === 12 || code === 13 || code === 32;
}

function isHtmlNameCharacter(code) {
  return (
    (code >= 48 && code <= 57) ||
    (code >= 65 && code <= 90) ||
    (code >= 97 && code <= 122) ||
    code === 45 ||
    code === 58 ||
    code === 95
  );
}

function isHtmlAttributeNameCharacter(code) {
  return isHtmlNameCharacter(code) || code === 46;
}

function hasHiddenInlineStyle(value) {
  const compactStyle = String(value || "").toLowerCase().replace(/[\t\n\f\r ]+/g, "");
  return compactStyle.includes("display:none") || compactStyle.includes("visibility:hidden");
}

function finalizeExtractedText(accumulator) {
  const extractedText = accumulator.parts
    .join("")
    .replace(/&#(\d{1,8});/g, (match, codePoint) => decodeNumericEntity(match, codePoint, 10))
    .replace(/&#x([\da-f]{1,6});/gi, (match, codePoint) => decodeNumericEntity(match, codePoint, 16))
    .replace(/&([a-z][a-z\d]{1,31});/gi, (match, name) => COMMON_HTML_ENTITIES[name.toLowerCase()] ?? match);
  return normalizePolicyText(extractedText);
}
