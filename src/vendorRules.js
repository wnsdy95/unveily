export const VENDOR_RULES = [
  {
    vendor: "Google Analytics",
    patterns: ["google-analytics.com", "analytics.google.com", "googletagmanager.com"],
    category: "analytics",
    risk: "tracking",
    expectedPolicySections: ["cookies_tracking", "third_party", "processors"]
  },
  {
    vendor: "Google Ads / DoubleClick",
    patterns: ["doubleclick.net", "googleadservices.com", "googlesyndication.com"],
    category: "advertising",
    risk: "tracking",
    expectedPolicySections: ["cookies_tracking", "third_party"]
  },
  {
    vendor: "Meta Pixel",
    patterns: ["connect.facebook.net", "facebook.com", "facebook.net"],
    category: "advertising",
    risk: "tracking",
    expectedPolicySections: ["cookies_tracking", "third_party"]
  },
  {
    vendor: "Hotjar",
    patterns: ["hotjar.com", "hotjar.io"],
    category: "analytics",
    risk: "tracking",
    expectedPolicySections: ["cookies_tracking", "processors"]
  },
  {
    vendor: "Segment",
    patterns: ["segment.com", "segment.io"],
    category: "analytics",
    risk: "tracking",
    expectedPolicySections: ["cookies_tracking", "processors"]
  },
  {
    vendor: "Amplitude",
    patterns: ["amplitude.com"],
    category: "analytics",
    risk: "tracking",
    expectedPolicySections: ["cookies_tracking", "processors"]
  },
  {
    vendor: "Stripe",
    patterns: ["stripe.com", "stripe.network"],
    category: "payment",
    risk: "processor",
    expectedPolicySections: ["processors", "purpose", "security"]
  },
  {
    vendor: "PayPal",
    patterns: ["paypal.com", "paypalobjects.com"],
    category: "payment",
    risk: "processor",
    expectedPolicySections: ["processors", "purpose", "security"]
  },
  {
    vendor: "Intercom",
    patterns: ["intercom.io", "intercomcdn.com"],
    category: "support",
    risk: "processor",
    expectedPolicySections: ["processors", "purpose"]
  },
  {
    vendor: "Zendesk",
    patterns: ["zendesk.com", "zdassets.com"],
    category: "support",
    risk: "processor",
    expectedPolicySections: ["processors", "purpose"]
  },
  {
    vendor: "Sentry",
    patterns: ["sentry.io", "ingest.sentry.io"],
    category: "error_monitoring",
    risk: "processor",
    expectedPolicySections: ["processors", "security"]
  },
  {
    vendor: "Cloudflare",
    patterns: ["cloudflare.com", "cloudflareinsights.com"],
    category: "cdn_security",
    risk: "infrastructure",
    expectedPolicySections: ["security"]
  },
  {
    vendor: "Amazon Web Services",
    patterns: ["amazonaws.com", "cloudfront.net"],
    category: "hosting",
    risk: "processor",
    expectedPolicySections: ["processors", "security"]
  },
  {
    vendor: "Auth0",
    patterns: ["auth0.com"],
    category: "authentication",
    risk: "processor",
    expectedPolicySections: ["processors", "security", "purpose"]
  },
  {
    vendor: "reCAPTCHA",
    patterns: ["recaptcha.net", "www.google.com/recaptcha", "gstatic.com/recaptcha"],
    category: "security",
    risk: "processor",
    expectedPolicySections: ["processors", "security"]
  }
];

export function classifyVendorHost(hostOrUrl, customRules = []) {
  const value = String(hostOrUrl || "").toLowerCase();
  const rules = [...customRules, ...VENDOR_RULES];
  const match = rules.find((rule) => rule.patterns.some((pattern) => value.includes(pattern.toLowerCase())));

  if (!match) {
    return {
      vendor: "Unknown",
      category: "unknown",
      risk: "unknown",
      expectedPolicySections: ["third_party", "processors"]
    };
  }

  return {
    vendor: match.vendor,
    category: match.category,
    risk: match.risk,
    expectedPolicySections: match.expectedPolicySections
  };
}
