import assert from "node:assert/strict";
import test from "node:test";
import {
  analyzeClientStorage,
  analyzeBehaviorPolicyAlignment,
  analyzeConsentCompliance,
  extractPolicySections,
  analyzeFormFields,
  analyzeJurisdictionCompliance,
  analyzeNetworkActivity,
  analyzeObservationDelta,
  analyzePolicy,
  detectJurisdiction,
  MAX_POLICY_ANALYSIS_CHARS
} from "../src/analyzer.js";
import { classifyVendorHost } from "../src/vendorRules.js";
import { setLocalePreference } from "../src/i18n.js";

test("detects data categories and high-risk clauses", () => {
  const result = analyzePolicy(`
    We collect your name, email, phone number, IP address, cookie identifiers, location, and payment information.
    We may share or transfer this information to third parties and partners for advertising and analytics.
    Any dispute is subject to binding arbitration and class action waiver.
  `);

  assert.equal(result.ok, true);
  assert.equal(result.level, "high");
  assert.ok(result.dataCategories.some((category) => category.id === "contact"));
  assert.ok(result.dataCategories.some((category) => category.id === "payment"));
  assert.ok(result.risks.some((risk) => risk.id === "broad_data_sharing"));
  assert.ok(result.risks.some((risk) => risk.id === "arbitration"));
  assert.ok(result.policySections.some((section) => section.id === "third_party" && section.found));
});

test("handles Korean policy language", () => {
  const result = analyzePolicy(`
    회사는 회원가입 시 이름, 이메일, 전화번호, 쿠키, 접속 로그, 위치 정보를 수집합니다.
    개인정보는 목적 달성 후 파기하나 관계 법령에 따라 필요한 기간 보관할 수 있습니다.
    회원은 동의 철회 및 회원탈퇴를 요청할 수 있으며, 회사는 암호화와 접근통제를 적용합니다.
  `);

  assert.equal(result.ok, true);
  assert.ok(result.dataCategories.some((category) => category.id === "identity"));
  assert.ok(result.dataCategories.some((category) => category.id === "device"));
  assert.ok(result.positives.some((item) => /삭제|탈퇴|delete|deletion/i.test(item)));
  assert.ok(result.positives.some((item) => /보안|security/i.test(item)));
});

test("rejects empty text", () => {
  const result = analyzePolicy("   ");

  assert.equal(result.ok, false);
  assert.equal(result.message, "No text available to analyze.");
});

test("flags network behavior not clearly disclosed by policy", () => {
  const result = analyzeNetworkActivity(
    "We collect your name and email to provide the service.",
    [
      {
        url: "https://www.google-analytics.com/g/collect?email=user@example.com",
        host: "www.google-analytics.com",
        method: "GET",
        type: "xmlhttprequest",
        queryKeys: ["email"],
        bodyKeys: []
      },
      {
        url: "http://api.example-cdn.com/signup",
        host: "api.example-cdn.com",
        method: "POST",
        type: "xmlhttprequest",
        queryKeys: [],
        bodyKeys: ["card_number"]
      }
    ],
    "https://service.example.com/signup"
  );

  assert.equal(result.requestCount, 2);
  assert.ok(result.findings.some((finding) => finding.id === "tracker_without_disclosure"));
  assert.ok(result.findings.some((finding) => finding.id === "insecure_http"));
  assert.ok(result.findings.some((finding) => finding.id === "sensitive_fields_without_category"));
  assert.ok(result.vendorSummary.some((vendor) => vendor.vendor === "Google Analytics" && vendor.category === "analytics"));
});

test("flags signup form fields not disclosed in policy categories", () => {
  const result = analyzeFormFields("We collect your name and email to create your account.", [
    {
      type: "email",
      name: "email",
      label: "Email",
      required: true
    },
    {
      type: "text",
      name: "card_number",
      label: "Card number",
      required: true
    },
    {
      type: "text",
      name: "birthdate",
      label: "Date of birth",
      required: true
    }
  ]);

  assert.equal(result.fieldCount, 3);
  assert.equal(result.sensitiveFieldCount, 3);
  assert.ok(result.categories.some((category) => category.id === "payment"));
  assert.ok(result.findings.some((finding) => finding.id === "form_fields_without_policy_category"));
});

test("flags tracking cookies and sensitive storage without disclosure", () => {
  const result = analyzeClientStorage(
    "We collect your name and email to create your account.",
    {
      localStorageKeys: ["auth_token", "user_email"],
      sessionStorageKeys: []
    },
    [
      {
        name: "_fbp",
        domain: ".facebook.com",
        secure: true,
        httpOnly: false,
        sameSite: "lax",
        removed: false
      },
      {
        name: "session_id",
        domain: ".example.com",
        secure: false,
        httpOnly: true,
        sameSite: "unspecified",
        removed: false
      }
    ],
    "https://service.example.com/signup"
  );

  assert.equal(result.cookieCount, 2);
  assert.ok(result.findings.some((finding) => finding.id === "tracking_cookie_without_disclosure"));
  assert.ok(result.findings.some((finding) => finding.id === "storage_without_disclosure"));
  assert.ok(result.findings.some((finding) => finding.id === "weak_cookie_security"));
});

test("recognizes privacy-minimized tracking-cookie family placeholders", () => {
  const names = [
    "_ga___identifier__",
    "_gac___identifier__",
    "_gcl___identifier__",
    "ajs___identifier__",
    "amplitude___identifier__",
    "mixpanel___identifier__",
    "mp___identifier___mixpanel",
    "__utma"
  ];
  const cookies = names.map((name) => ({
    name,
    domain: ".example.com",
    removed: false
  }));

  const result = analyzeConsentCompliance({}, [], cookies);
  assert.equal(result.trackingCookieCount, names.length);
});

test("flags tracking when consent controls are missing or disabled", () => {
  const result = analyzeConsentCompliance(
    {
      detected: true,
      containers: [
        {
          text: "Cookie notice",
          buttons: ["Accept all"],
          toggles: [
            {
              label: "Analytics cookies",
              checked: false,
              name: "analytics"
            }
          ]
        }
      ]
    },
    [
      {
        url: "https://www.google-analytics.com/g/collect",
        host: "www.google-analytics.com"
      }
    ],
    [
      {
        name: "_ga",
        domain: ".example.com",
        removed: false
      }
    ]
  );

  assert.equal(result.detected, true);
  assert.equal(result.disabledTrackingToggleCount, 1);
  assert.ok(result.findings.some((finding) => finding.id === "consent_no_reject_option"));
  assert.ok(result.findings.some((finding) => finding.id === "tracking_before_clear_choice"));
  assert.ok(result.findings.some((finding) => finding.id === "tracking_despite_disabled_toggle"));
  assert.ok(result.choiceAnalyses.some((choice) => choice.type === "accept_all" && choice.riskLevel === "high"));
  assert.ok(result.consentCategories.some((category) => category.id === "analytics"));
});

test("flags tracking without visible consent ui", () => {
  const result = analyzeConsentCompliance(
    { detected: false, containers: [] },
    [
      {
        url: "https://connect.facebook.net/en_US/fbevents.js",
        host: "connect.facebook.net"
      }
    ],
    []
  );

  assert.ok(result.findings.some((finding) => finding.id === "tracking_without_visible_consent"));
});

test("explains cookie choices and their risk levels", () => {
  const result = analyzeConsentCompliance(
    {
      detected: true,
      containers: [
        {
          text: "We use strictly necessary cookies, analytics cookies, and advertising cookies.",
          buttons: ["Accept all", "Reject all", "Cookie settings"],
          toggles: [
            {
              label: "Analytics cookies",
              checked: false,
              name: "analytics"
            },
            {
              label: "Advertising cookies",
              checked: false,
              name: "ads"
            }
          ]
        }
      ]
    },
    [],
    []
  );

  const acceptAll = result.choiceAnalyses.find((choice) => choice.type === "accept_all");
  const necessaryOnly = result.choiceAnalyses.find((choice) => choice.type === "necessary_only");
  const preferences = result.choiceAnalyses.find((choice) => choice.type === "preferences");

  assert.equal(acceptAll.riskLevel, "high");
  assert.ok(acceptAll.allowedCategories.some((category) => category.id === "advertising"));
  assert.equal(necessaryOnly.riskLevel, "low");
  assert.deepEqual(necessaryOnly.allowedCategories.map((category) => category.id), ["necessary"]);
  assert.equal(preferences.riskLevel, "medium");
  assert.ok(preferences.allowedCategories.some((category) => category.id === "analytics"));
});

test("flags rejection hidden behind preferences", () => {
  const result = analyzeConsentCompliance({
    detected: true,
    containers: [
      {
        text: "Cookie consent for analytics and marketing.",
        buttons: ["Accept all", "Manage settings"],
        toggles: []
      }
    ]
  });

  assert.ok(result.findings.some((finding) => finding.id === "reject_hidden_in_preferences"));
});

test("compares tracking activity after a saved snapshot", () => {
  const snapshot = {
    label: "after reject",
    createdAt: 1000,
    requestCount: 1,
    cookieCount: 0
  };
  const result = analyzeObservationDelta(
    snapshot,
    [
      {
        timeStamp: 800,
        url: "https://service.example.com/app",
        host: "service.example.com",
        method: "GET"
      },
      {
        timeStamp: 1200,
        url: "https://www.google-analytics.com/g/collect",
        host: "www.google-analytics.com",
        method: "GET"
      },
      {
        timeStamp: 1300,
        url: "https://api.example.com/profile",
        host: "api.example.com",
        method: "POST"
      }
    ],
    [
      {
        timeStamp: 1400,
        name: "_ga",
        domain: ".example.com",
        timingConfidence: "observed",
        partitionKey: { topLevelSite: "https://service.example.com" },
        removed: false
      }
    ]
  );

  assert.equal(result.hasSnapshot, true);
  assert.equal(result.trackingRequestDelta, 1);
  assert.equal(result.trackingCookieDelta, 1);
  assert.ok(result.findings.some((finding) => finding.id === "tracking_after_snapshot"));
  assert.ok(result.findings.some((finding) => finding.id === "write_request_after_snapshot"));
});

test("extracts structured policy sections", () => {
  const sections = extractPolicySections(`
    수집하는 개인정보 항목
    회사는 이름, 이메일, 전화번호, 쿠키 및 접속 로그를 수집합니다.

    개인정보의 보유 및 파기
    회원 탈퇴 시 지체 없이 파기하나 관계 법령에 따라 3년간 보관할 수 있습니다.

    제3자 제공 및 처리위탁
    회사는 결제 처리를 위해 결제대행사에 개인정보 처리를 위탁할 수 있습니다.

    쿠키와 맞춤형 광고
    회사는 쿠키와 행태정보를 이용하여 맞춤형 광고를 제공할 수 있으며 사용자는 거부할 수 있습니다.
  `);

  assert.ok(sections.some((section) => section.id === "collected_data" && section.found));
  assert.ok(sections.some((section) => section.id === "retention" && section.found));
  assert.ok(sections.some((section) => section.id === "third_party" && section.found));
  assert.ok(sections.some((section) => section.id === "cookies_tracking" && section.found));
});

test("detects Korean jurisdiction and flags missing local policy disclosures", () => {
  const result = analyzeJurisdictionCompliance(
    "회사는 이름과 이메일을 수집합니다.",
    {
      signals: {
        language: "ko-KR",
        timeZone: "Asia/Seoul",
        host: "service.kr"
      },
      observed: {
        hasThirdParty: true,
        hasTracking: true,
        hasOverseasTransfer: true
      }
    }
  );

  assert.equal(result.jurisdiction.code, "KR");
  assert.ok(result.findings.some((finding) => finding.id === "kr_missing_core_policy_sections"));
  assert.ok(result.findings.some((finding) => finding.id === "kr_third_party_without_disclosure"));
  assert.ok(result.findings.some((finding) => finding.id === "kr_overseas_transfer_without_disclosure"));
});

test("detects US jurisdiction and flags tracking opt-out gaps", () => {
  const result = analyzeJurisdictionCompliance(
    "We collect your email to provide the service.",
    {
      signals: {
        language: "en-US",
        timeZone: "America/Los_Angeles",
        host: "service.us"
      },
      observed: {
        hasTracking: true,
        hasSensitiveData: true
      }
    }
  );

  assert.equal(result.jurisdiction.code, "US");
  assert.ok(result.findings.some((finding) => finding.id === "us_tracking_without_optout_notice"));
  assert.ok(result.findings.some((finding) => finding.id === "us_sensitive_data_without_notice"));
});

test("detects GDPR jurisdiction and flags missing GDPR disclosures", () => {
  const result = analyzeJurisdictionCompliance(
    "We collect your email to provide the service.",
    {
      signals: {
        countryCode: "DE",
        language: "de-DE",
        timeZone: "Europe/Berlin"
      },
      observed: {
        hasTracking: true,
        hasOverseasTransfer: true,
        hasSensitiveData: true,
        hasProfiling: true
      }
    }
  );

  assert.equal(result.jurisdiction.code, "GDPR");
  assert.ok(result.findings.some((finding) => finding.id === "gdpr_missing_core_information"));
  assert.ok(result.findings.some((finding) => finding.id === "gdpr_tracking_without_specific_consent_notice"));
  assert.ok(result.findings.some((finding) => finding.id === "gdpr_transfer_without_safeguards_notice"));
  assert.ok(result.findings.some((finding) => finding.id === "gdpr_profiling_without_notice"));
});

test("scores behavior-policy alignment from observed activity", () => {
  const result = analyzeBehaviorPolicyAlignment(
    `
      Information we collect
      We collect your name and email.

      Cookies
      We use analytics cookies and provide opt-out choices.
    `,
    {
      hasFormData: true,
      hasTracking: true,
      hasThirdParty: true,
      hasStorage: true,
      hasSensitiveData: true,
      hasAuthStorage: true,
      hasOverseasTransfer: true
    }
  );

  assert.ok(result.score < 100);
  assert.ok(result.findings.some((finding) => finding.id === "alignment_missing_third_party"));
  assert.ok(result.findings.some((finding) => finding.id === "alignment_missing_retention"));
  assert.ok(result.findings.some((finding) => finding.id === "alignment_missing_security"));
});

test("classifies local vendor rules and surfaces purpose-specific gaps", () => {
  const result = analyzeNetworkActivity(
    `
      Information we collect
      We collect name and email.

      Security
      We use safeguards to protect data.
    `,
    [
      {
        url: "https://js.stripe.com/v3",
        host: "js.stripe.com",
        method: "GET",
        queryKeys: [],
        bodyKeys: []
      },
      {
        url: "https://www.google-analytics.com/g/collect",
        host: "www.google-analytics.com",
        method: "GET",
        queryKeys: [],
        bodyKeys: []
      }
    ],
    "https://shop.example.com"
  );

  assert.ok(result.vendorSummary.some((vendor) => vendor.vendor === "Stripe" && vendor.category === "payment"));
  assert.ok(result.vendorSummary.some((vendor) => vendor.vendor === "Google Analytics" && vendor.category === "analytics"));
  assert.ok(result.findings.some((finding) => finding.id === "vendor_policy_section_gap"));
});

test("custom vendor rules override built-in and unknown classifications", () => {
  const result = analyzeNetworkActivity(
    "We use authentication providers and security safeguards.",
    [
      {
        url: "https://niceid.co.kr/cert",
        host: "niceid.co.kr",
        method: "GET",
        queryKeys: [],
        bodyKeys: []
      }
    ],
    "https://service.example.com",
    [
      {
        vendor: "NICE 본인인증",
        patterns: ["niceid.co.kr"],
        category: "authentication",
        risk: "processor",
        expectedPolicySections: ["processors", "purpose", "security"]
      }
    ]
  );

  assert.equal(result.vendorSummary[0].vendor, "NICE 본인인증");
  assert.equal(result.vendorSummary[0].category, "authentication");
});

test("prefers IP country code when provided for jurisdiction", () => {
  const result = analyzeJurisdictionCompliance("We collect email.", {
    signals: {
      countryCode: "KR",
      language: "en-US",
      timeZone: "America/New_York"
    },
    observed: {}
  });

  assert.equal(result.jurisdiction.code, "KR");
  assert.equal(result.jurisdiction.basis, "IP country code");
  assert.equal(result.jurisdiction.confidence, "medium");
});

test("requires sharing target and action in the same non-negated context", () => {
  const servicePurpose = analyzePolicy("We collect your email to provide the service.");
  const separatedSignals = analyzePolicy(
    "We collect your email. We work with third parties. We provide a reliable service to customers."
  );
  const negativeDisclosure = analyzePolicy(
    "We do not sell or share personal information with third parties."
  );
  const positiveDisclosure = analyzePolicy(
    "We may share personal information with third parties for advertising."
  );

  assert.equal(servicePurpose.ok, true);
  assert.equal(servicePurpose.risks.some((risk) => risk.id === "broad_data_sharing"), false);
  assert.equal(separatedSignals.risks.some((risk) => risk.id === "broad_data_sharing"), false);
  assert.equal(negativeDisclosure.risks.some((risk) => risk.id === "broad_data_sharing"), false);
  assert.equal(positiveDisclosure.risks.some((risk) => risk.id === "broad_data_sharing"), true);
});

test("preserves a positive sharing action after a separately negated action", () => {
  const english = analyzePolicy(
    "We collect email. We do not sell and may share personal information with third parties for advertising."
  );
  const korean = analyzePolicy(
    "회사는 이메일을 수집합니다. 개인정보를 판매하지 않으며 제3자와 공유합니다."
  );

  assert.equal(english.risks.some((risk) => risk.id === "broad_data_sharing"), true);
  assert.equal(korean.risks.some((risk) => risk.id === "broad_data_sharing"), true);
});

test("keeps a wrapped sharing sentence in one risk context", () => {
  const result = analyzePolicy(
    "We collect email.\nWe may share personal information\nwith third parties for advertising."
  );

  assert.equal(result.risks.some((risk) => risk.id === "broad_data_sharing"), true);
});

test("does not treat child-protection negations as high-risk child collection", () => {
  const english = analyzePolicy(
    "We do not knowingly collect personal information from children under 13."
  );
  const korean = analyzePolicy(
    "회사는 만 14세 미만 아동의 개인정보를 수집하지 않습니다."
  );
  const actualCollection = analyzePolicy(
    "We knowingly collect personal information from children under 13."
  );

  assert.equal(english.risks.some((risk) => risk.id === "children"), false);
  assert.equal(korean.risks.some((risk) => risk.id === "children"), false);
  assert.equal(actualCollection.risks.some((risk) => risk.id === "children"), true);
});

test("keeps a high-severity finding from producing an overall low level", () => {
  const result = analyzePolicy(
    "We may share personal information with third parties."
  );

  assert.equal(result.risks[0].severity, "high");
  assert.equal(result.overallSeverity, "high");
  assert.notEqual(result.level, "low");
  assert.match(result.summary, /Caution|High|주의|높음/);
});

test("returns an explicit unknown state for ordinary non-policy page text", () => {
  const result = analyzePolicy(
    "Welcome to our workspace. Build projects with your team and ship faster today."
  );

  assert.equal(result.ok, false);
  assert.equal(result.status, "not_policy");
  assert.equal(result.level, "unknown");
  assert.equal(result.score, null);
});

test("does not accept a policy footer link or bare title as policy body", () => {
  const footer = analyzePolicy(
    "Welcome to our shop. Browse products and contact support. About Careers Privacy Policy Terms of Service Copyright 2026."
  );
  const bareTitle = analyzePolicy("Privacy Policy");

  assert.equal(footer.status, "not_policy");
  assert.equal(bareTitle.status, "not_policy");
});

test("recognizes inflected data-practice verbs in policy text", () => {
  const result = analyzePolicy(
    "The company collects personal information including email and phone."
  );

  assert.equal(result.ok, true);
  assert.ok(result.dataCategories.some((category) => category.id === "contact"));
});

test("matches data categories on token boundaries", () => {
  const interfacePolicy = analyzePolicy(
    "Privacy Policy. We process interface configuration data to provide the service."
  );
  const ipPolicy = analyzePolicy(
    "Privacy Policy. We collect personal information such as an IP address for account security."
  );
  const cookiePolicy = analyzePolicy(
    "Privacy Policy. We collect personal information through cookies."
  );

  assert.equal(interfacePolicy.dataCategories.some((category) => category.id === "biometric"), false);
  assert.equal(ipPolicy.dataCategories.some((category) => category.id === "contact"), false);
  assert.equal(ipPolicy.dataCategories.some((category) => category.id === "device"), true);
  assert.equal(cookiePolicy.dataCategories.some((category) => category.id === "device"), true);
});

test("matches sensitive field names by identifier tokens instead of substrings", () => {
  const policy = "Privacy Policy. We process information to provide the service.";
  const benignKeys = ["page", "shipping_option", "platform", "hotel"];
  const benignNetwork = analyzeNetworkActivity(
    policy,
    [{ host: "service.example.com", url: "https://service.example.com/api", method: "POST", bodyKeys: benignKeys }],
    "https://service.example.com"
  );
  const benignForm = analyzeFormFields(policy, benignKeys.map((name) => ({ name, type: "text" })));
  const benignStorage = analyzeClientStorage(policy, { localStorageKeys: benignKeys }, [], "https://service.example.com");
  const realNetwork = analyzeNetworkActivity(
    policy,
    [
      {
        host: "service.example.com",
        url: "https://service.example.com/api",
        method: "POST",
        bodyKeys: ["contact_email", "clientIp", "card_number", "geo_location"]
      }
    ],
    "https://service.example.com"
  );
  const detectedCategories = new Set(realNetwork.sensitiveFields.map((field) => field.category));

  assert.deepEqual(benignNetwork.sensitiveFields, []);
  assert.deepEqual(benignForm.categories, []);
  assert.deepEqual(benignStorage.classifiedStorage, []);
  assert.deepEqual(detectedCategories, new Set(["contact", "payment", "location", "device"]));
});

test("uses registrable domains for common multi-label public suffixes", () => {
  const ukResult = analyzeNetworkActivity(
    "We collect email.",
    [
      { host: "api.example.co.uk", url: "https://api.example.co.uk/a", method: "GET" },
      { host: "api.other.co.uk", url: "https://api.other.co.uk/a", method: "GET" }
    ],
    "https://shop.example.co.uk"
  );
  const krResult = analyzeNetworkActivity(
    "회사는 이메일을 수집합니다.",
    [
      { host: "api.example.co.kr", url: "https://api.example.co.kr/a", method: "GET" },
      { host: "api.other.co.kr", url: "https://api.other.co.kr/a", method: "GET" }
    ],
    "https://shop.example.co.kr"
  );
  const indiaResult = analyzeNetworkActivity(
    "We collect email.",
    [{ host: "api.other.co.in", url: "https://api.other.co.in/a", method: "GET" }],
    "https://shop.example.co.in"
  );
  const githubResult = analyzeNetworkActivity(
    "We collect email.",
    [{ host: "bob.github.io", url: "https://bob.github.io/a", method: "GET" }],
    "https://alice.github.io"
  );

  assert.deepEqual(ukResult.thirdPartyHosts, ["api.other.co.uk"]);
  assert.deepEqual(krResult.thirdPartyHosts, ["api.other.co.kr"]);
  assert.deepEqual(indiaResult.thirdPartyHosts, ["api.other.co.in"]);
  assert.deepEqual(githubResult.thirdPartyHosts, ["bob.github.io"]);
});

test("uses the pinned private PSL section for sibling hosting tenants", () => {
  for (const suffix of [
    "appspot.com",
    "blogspot.com",
    "vercel.app",
    "pages.dev",
    "netlify.app",
    "web.app",
    "firebaseapp.com",
    "herokuapp.com",
    "cloudfront.net"
  ]) {
    const result = analyzeNetworkActivity(
      "We process account data to provide this service.",
      [{ host: `bob.${suffix}`, url: `https://bob.${suffix}/api`, method: "POST" }],
      `https://alice.${suffix}`
    );
    assert.deepEqual(result.thirdPartyHosts, [`bob.${suffix}`], suffix);
    assert.ok(result.findings.some((finding) => finding.id === "third_party_post"), suffix);
  }
});

test("matches vendor rules on hostname boundaries instead of substrings", () => {
  assert.equal(classifyVendorHost("https://js.stripe.com/v3").vendor, "Stripe");
  assert.equal(classifyVendorHost("https://evilstripe.com.attacker.test/v3").vendor, "Unknown");
  assert.equal(classifyVendorHost("https://stripe.com.attacker.test/v3").vendor, "Unknown");
});

test("does not treat a generic vendor word as disclosure of every host", () => {
  const result = analyzeNetworkActivity(
    "We collect email and use a vendor to provide the service.",
    [
      {
        host: "metrics.external.example",
        url: "https://metrics.external.example/collect",
        method: "GET"
      }
    ],
    "https://service.example.com"
  );

  assert.ok(result.findings.some((finding) => finding.id === "undisclosed_third_parties"));
});

test("matches disclosed vendor aliases on word boundaries", () => {
  const request = [{ host: "js.stripe.com", url: "https://js.stripe.com/v3", method: "GET" }];
  const substringOnly = analyzeNetworkActivity(
    "We collect email and use a pinstripe design across the service.",
    request,
    "https://service.example.com"
  );
  const exactAlias = analyzeNetworkActivity(
    "We collect email and use Stripe for payment processing.",
    request,
    "https://service.example.com"
  );

  assert.equal(substringOnly.findings.some((finding) => finding.id === "undisclosed_third_parties"), true);
  assert.equal(exactAlias.findings.some((finding) => finding.id === "undisclosed_third_parties"), false);
});

test("weighs host jurisdiction over conflicting timezone and avoids high confidence from hints", () => {
  const germanSiteFromSeoul = detectJurisdiction({
    host: "service.de",
    language: "de-DE",
    timeZone: "Asia/Seoul"
  });
  const conflictingHints = detectJurisdiction({
    host: "service.example.com",
    language: "de-DE",
    timeZone: "Asia/Seoul"
  });
  const koreanHints = detectJurisdiction({
    host: "service.kr",
    language: "ko-KR",
    timeZone: "Asia/Seoul"
  });

  assert.equal(germanSiteFromSeoul.code, "GDPR");
  assert.equal(germanSiteFromSeoul.confidence, "medium");
  assert.equal(conflictingHints.code, "GENERAL");
  assert.equal(koreanHints.code, "KR");
  assert.equal(koreanHints.confidence, "medium");
});

test("does not equate every America or Europe timezone with US or EU jurisdiction", () => {
  assert.equal(detectJurisdiction({ timeZone: "America/Toronto" }).code, "GENERAL");
  assert.equal(detectJurisdiction({ timeZone: "America/Mexico_City" }).code, "GENERAL");
  assert.equal(detectJurisdiction({ timeZone: "America/Sao_Paulo" }).code, "GENERAL");
  assert.equal(detectJurisdiction({ timeZone: "Europe/Zurich" }).code, "GENERAL");
  assert.equal(detectJurisdiction({ timeZone: "America/New_York" }).code, "US");
  assert.equal(detectJurisdiction({ timeZone: "Europe/Paris" }).code, "GDPR");
});

test("distinguishes user account closure from provider termination discretion", () => {
  const userClosure = analyzePolicy(
    "Terms of Service. You may terminate your account at any time."
  );
  const providerTermination = analyzePolicy(
    "Terms of Service. We may suspend or terminate your account at our discretion."
  );
  const conditionalProviderTermination = analyzePolicy(
    "Terms of Service. If you violate these terms, we may terminate your account."
  );
  const negatedProviderTermination = analyzePolicy(
    "Terms of Service. We will not terminate your account without cause."
  );
  const noTargetedAds = analyzePolicy(
    "Privacy Policy. We collect email. We do not use personalized ads or targeted advertising."
  );
  const targetedAds = analyzePolicy(
    "Privacy Policy. We collect email. We use personalized ads for marketing."
  );
  const koreanUserClosure = analyzePolicy(
    "서비스 약관. 회원은 서비스 계정을 언제든지 해지할 수 있습니다."
  );
  const koreanProviderTermination = analyzePolicy(
    "서비스 약관. 회사는 위반 시 회원 계정을 해지할 수 있습니다."
  );
  const koreanNegatedTermination = analyzePolicy(
    "서비스 약관. 회사는 정당한 사유 없이 회원 계정을 해지하지 않습니다."
  );

  assert.equal(userClosure.risks.some((risk) => risk.id === "account_termination"), false);
  assert.equal(providerTermination.risks.some((risk) => risk.id === "account_termination"), true);
  assert.equal(conditionalProviderTermination.risks.some((risk) => risk.id === "account_termination"), true);
  assert.equal(negatedProviderTermination.risks.some((risk) => risk.id === "account_termination"), false);
  assert.equal(noTargetedAds.risks.some((risk) => risk.id === "behavioral_ads"), false);
  assert.equal(targetedAds.risks.some((risk) => risk.id === "behavioral_ads"), true);
  assert.equal(koreanUserClosure.risks.some((risk) => risk.id === "account_termination"), false);
  assert.equal(koreanProviderTermination.risks.some((risk) => risk.id === "account_termination"), true);
  assert.equal(koreanNegatedTermination.risks.some((risk) => risk.id === "account_termination"), false);
});

test("separates consent tracking before and after a known choice time", () => {
  const result = analyzeConsentCompliance(
    {
      detected: true,
      observationStartedAt: 1000,
      choiceAt: 3000,
      containers: [
        {
          text: "Analytics cookies",
          buttons: ["Accept all", "Reject all"],
          toggles: [{ label: "Analytics", name: "analytics", checked: false }]
        }
      ]
    },
    [
      { host: "www.google-analytics.com", timeStamp: 500 },
      { host: "www.google-analytics.com", timeStamp: 1500 },
      { host: "www.google-analytics.com", timeStamp: 4500 }
    ],
    []
  );

  assert.equal(result.preChoiceTrackingRequestCount, 1);
  assert.equal(result.postChoiceTrackingRequestCount, 1);
  assert.equal(result.ignoredPreObservationTrackingRequestCount, 1);
  assert.equal(result.timing.boundaryType, "choice");
  assert.ok(result.findings.some((finding) => finding.id === "tracking_before_clear_choice" && finding.severity === "high"));
  assert.ok(result.findings.some((finding) => finding.id === "tracking_despite_disabled_toggle" && finding.severity === "high"));
});

test("unpartitioned cookie event times cannot prove pre-consent or post-rejection activity", () => {
  const consent = {
    detected: true,
    choice: { kind: "reject_all", at: 3000 },
    containers: [{ text: "Analytics cookies", buttons: ["Reject all"], toggles: [] }]
  };
  const unpartitioned = analyzeConsentCompliance(consent, [], [
    { name: "_ga", domain: ".example.com", timingConfidence: "observed", timeStamp: 1000 },
    { name: "_fbp", domain: ".example.com", timingConfidence: "observed", timeStamp: 5000 }
  ]);

  assert.equal(unpartitioned.preChoiceTrackingCookieCount, 0);
  assert.equal(unpartitioned.postChoiceTrackingCookieCount, 0);
  assert.equal(unpartitioned.unclassifiedTrackingCookieCount, 2);
  assert.equal(
    unpartitioned.findings.find((finding) => finding.id === "tracking_after_rejection")?.confidence,
    "low"
  );

  const partitioned = analyzeConsentCompliance(consent, [], [
    {
      name: "_ga",
      domain: ".analytics.test",
      timingConfidence: "observed",
      timeStamp: 1000,
      partitionKey: { topLevelSite: "https://service.example.com" }
    },
    {
      name: "_fbp",
      domain: ".analytics.test",
      timingConfidence: "observed",
      timeStamp: 5000,
      partitionKey: { topLevelSite: "https://service.example.com" }
    }
  ]);

  assert.equal(partitioned.preChoiceTrackingCookieCount, 1);
  assert.equal(partitioned.postChoiceTrackingCookieCount, 1);
  assert.equal(partitioned.unclassifiedTrackingCookieCount, 0);
  assert.equal(
    partitioned.findings.find((finding) => finding.id === "tracking_after_rejection")?.confidence,
    "high"
  );
});

test("one active cookie identity can provide both pre- and post-choice set evidence", () => {
  const result = analyzeConsentCompliance(
    {
      detected: true,
      observationStartedAt: 500,
      choice: { kind: "reject_all", at: 3_000 },
      containers: [{ text: "Analytics cookies", buttons: ["Reject all"], toggles: [] }]
    },
    [],
    [
      {
        name: "_ga",
        domain: ".analytics.test",
        removed: false,
        timingConfidence: "observed",
        firstSetObservedAt: 1_000,
        lastSetObservedAt: 5_000,
        firstObservedAt: 1_000,
        lastObservedAt: 5_000,
        timeStamp: 1_000,
        partitionKey: { topLevelSite: "https://service.example.com" }
      }
    ]
  );

  assert.equal(result.trackingCookieCount, 1);
  assert.equal(result.preChoiceTrackingCookieCount, 1);
  assert.equal(result.postChoiceTrackingCookieCount, 1);
  assert.equal(result.unclassifiedTrackingCookieCount, 0);
  assert.ok(
    result.findings.some(
      (finding) => finding.id === "tracking_before_clear_choice" && finding.severity === "high"
    )
  );
  assert.ok(
    result.findings.some(
      (finding) => finding.id === "tracking_after_rejection" && finding.severity === "high"
    )
  );
});

test("removed cookies count real set updates but never treat deletion time as tracking", () => {
  const consent = {
    detected: true,
    observationStartedAt: 500,
    choice: { kind: "reject_all", at: 3_000 },
    containers: [{ text: "Analytics cookies", buttons: ["Reject all"], toggles: [] }]
  };
  const updatedThenDeleted = analyzeConsentCompliance(consent, [], [
    {
      name: "_ga",
      domain: ".analytics.test",
      removed: true,
      timingConfidence: "observed",
      firstSetObservedAt: 1_000,
      lastSetObservedAt: 5_000,
      deletedAt: 6_000,
      partitionKey: { topLevelSite: "https://service.example.com" }
    }
  ]);
  const setThenDeleted = analyzeConsentCompliance(consent, [], [
    {
      name: "_ga",
      domain: ".analytics.test",
      removed: true,
      timingConfidence: "observed",
      firstSetObservedAt: 1_000,
      lastSetObservedAt: 1_000,
      deletedAt: 5_000,
      partitionKey: { topLevelSite: "https://service.example.com" }
    }
  ]);
  const legacyDeletionContaminatedLast = analyzeConsentCompliance(consent, [], [
    {
      name: "_ga",
      domain: ".analytics.test",
      removed: true,
      timingConfidence: "observed",
      firstObservedAt: 1_000,
      lastObservedAt: 5_000,
      deletedAt: 5_000,
      timeStamp: 1_000,
      partitionKey: { topLevelSite: "https://service.example.com" }
    }
  ]);
  const legacyDeleteOnly = analyzeConsentCompliance(consent, [], [
    {
      name: "_ga",
      domain: ".analytics.test",
      removed: true,
      timingConfidence: "observed",
      firstObservedAt: 5_000,
      lastObservedAt: 5_000,
      timeStamp: 5_000,
      deletedAt: 5_000,
      partitionKey: { topLevelSite: "https://service.example.com" }
    }
  ]);

  assert.equal(updatedThenDeleted.trackingCookieCount, 1);
  assert.equal(updatedThenDeleted.preChoiceTrackingCookieCount, 1);
  assert.equal(updatedThenDeleted.postChoiceTrackingCookieCount, 1);
  assert.equal(setThenDeleted.trackingCookieCount, 1);
  assert.equal(setThenDeleted.preChoiceTrackingCookieCount, 1);
  assert.equal(setThenDeleted.postChoiceTrackingCookieCount, 0);
  assert.equal(legacyDeletionContaminatedLast.preChoiceTrackingCookieCount, 1);
  assert.equal(legacyDeletionContaminatedLast.postChoiceTrackingCookieCount, 0);
  assert.equal(legacyDeleteOnly.trackingCookieCount, 0);
  assert.equal(legacyDeleteOnly.preChoiceTrackingCookieCount, 0);
  assert.equal(legacyDeleteOnly.postChoiceTrackingCookieCount, 0);
  assert.equal(legacyDeleteOnly.unclassifiedTrackingCookieCount, 0);
});

test("cookie identity counts stay unique when its latest set is boundary-ambiguous", () => {
  const result = analyzeConsentCompliance(
    {
      detected: true,
      observationStartedAt: 500,
      choice: { kind: "reject_all", at: 3_000 },
      containers: [{ text: "Analytics cookies", buttons: ["Reject all"], toggles: [] }]
    },
    [],
    [
      {
        name: "_ga",
        domain: ".analytics.test",
        removed: false,
        timingConfidence: "observed",
        firstSetObservedAt: 1_000,
        lastSetObservedAt: 3_500,
        partitionKey: { topLevelSite: "https://service.example.com" }
      }
    ]
  );

  assert.equal(result.trackingCookieCount, 1);
  assert.equal(result.preChoiceTrackingCookieCount, 1);
  assert.equal(result.postChoiceTrackingCookieCount, 0);
  assert.equal(result.unclassifiedTrackingCookieCount, 1);
});

test("does not label known post-choice-only activity as pre-choice tracking", () => {
  const result = analyzeConsentCompliance(
    {
      detected: true,
      choiceAt: 2000,
      containers: [
        {
          text: "Analytics cookies",
          buttons: ["Accept all", "Reject all"],
          toggles: []
        }
      ]
    },
    [{ host: "www.google-analytics.com", timeStamp: 3500 }],
    []
  );

  assert.equal(result.preChoiceTrackingRequestCount, 0);
  assert.equal(result.postChoiceTrackingRequestCount, 1);
  assert.equal(result.findings.some((finding) => finding.id === "tracking_before_clear_choice"), false);
});

test("distinguishes rejection, acceptance, and saved preferences when evaluating post-choice tracking", () => {
  const trackingRequest = { host: "www.google-analytics.com", timeStamp: 3501 };
  const rejectResult = analyzeConsentCompliance(
    {
      detected: true,
      choice: { kind: "reject_all", at: 2000 },
      containers: [{ text: "Cookie choices", buttons: ["Reject all"], toggles: [] }]
    },
    [trackingRequest],
    []
  );
  const acceptResult = analyzeConsentCompliance(
    {
      detected: true,
      choice: { kind: "accept_all", at: 2000 },
      containers: [
        {
          text: "Analytics cookies",
          buttons: ["Accept all"],
          toggles: [{ label: "Analytics", checked: false }]
        }
      ]
    },
    [trackingRequest],
    []
  );
  const savedPreferencesResult = analyzeConsentCompliance(
    {
      detected: true,
      choice: {
        kind: "save_preferences",
        at: 2000,
        toggles: [{ label: "Analytics", name: "analytics", checked: false }]
      },
      containers: []
    },
    [trackingRequest],
    []
  );

  assert.equal(rejectResult.choiceKind, "reject_all");
  assert.ok(rejectResult.findings.some((finding) => finding.id === "tracking_after_rejection" && finding.severity === "high"));
  assert.equal(rejectResult.findings.some((finding) => finding.id === "tracking_despite_disabled_toggle"), false);
  assert.equal(acceptResult.choiceKind, "accept_all");
  assert.equal(acceptResult.findings.some((finding) => finding.id === "tracking_after_rejection"), false);
  assert.equal(acceptResult.findings.some((finding) => finding.id === "tracking_despite_disabled_toggle"), false);
  assert.equal(savedPreferencesResult.choiceKind, "save_preferences");
  assert.ok(
    savedPreferencesResult.findings.some(
      (finding) => finding.id === "tracking_despite_disabled_toggle" && finding.severity === "high"
    )
  );
});

test("does not treat Continue or consent prose as an accept choice", () => {
  const continueOnly = analyzeConsentCompliance({
    detected: true,
    containers: [
      {
        text: "By continuing, you acknowledge this cookie consent notice.",
        buttons: ["Continue"],
        toggles: []
      }
    ]
  });
  const savedPreferences = analyzeConsentCompliance({
    detected: true,
    containers: [{ text: "Cookie settings", buttons: ["Save preferences"], toggles: [] }]
  });

  assert.equal(continueOnly.acceptAvailable, false);
  assert.equal(continueOnly.choiceAnalyses.length, 0);
  assert.equal(savedPreferences.acceptAvailable, false);
  assert.equal(savedPreferences.preferenceAvailable, true);
  assert.ok(savedPreferences.choiceAnalyses.some((choice) => choice.type === "save_choices"));
});

test("matches tracker indicators on domain and path-token boundaries", () => {
  const policy = "Privacy Policy. We collect email to provide the service.";
  const benignRequests = [
    { host: "collective.example", url: "https://collective.example/api", method: "GET" },
    { host: "pixelcraft.example", url: "https://pixelcraft.example/gallery", method: "GET" },
    { host: "api.example", url: "https://api.example/analyticsreport", method: "GET" }
  ];
  const realRequests = [
    { host: "analytics.example", url: "https://analytics.example/v1/events", method: "GET" },
    { host: "api.metrics.example", url: "https://api.metrics.example/v1/collect", method: "GET" }
  ];

  assert.deepEqual(
    analyzeNetworkActivity(policy, benignRequests, "https://service.example").trackerHosts,
    []
  );
  assert.deepEqual(
    analyzeNetworkActivity(policy, realRequests, "https://service.example").trackerHosts.sort(),
    ["analytics.example", "api.metrics.example"]
  );

  const benignConsent = analyzeConsentCompliance(
    { detected: false, containers: [] },
    benignRequests,
    [{ name: "legal_notice", removed: false }, { name: "contract_id", removed: false }]
  );
  assert.equal(benignConsent.trackingRequestCount, 0);
  assert.equal(benignConsent.trackingCookieCount, 0);
});

test("does not let an earlier same-host request hide later tracker, HTTP, or vendor evidence", () => {
  const result = analyzeNetworkActivity(
    "Privacy Policy. We collect email to provide the service.",
    [
      { host: "api.metrics.example", url: "https://api.metrics.example/api", method: "GET" },
      { host: "api.metrics.example", url: "https://api.metrics.example/v1/collect", method: "GET" },
      { host: "mixed.example", url: "https://mixed.example/api", method: "GET" },
      { host: "mixed.example", url: "http://mixed.example/api", method: "GET" },
      { host: "www.google.com", url: "https://www.google.com/maps", method: "GET" },
      { host: "www.google.com", url: "https://www.google.com/recaptcha/api.js", method: "GET" }
    ],
    "https://service.example"
  );

  assert.ok(result.trackerHosts.includes("api.metrics.example"));
  assert.ok(result.findings.some((finding) => finding.id === "insecure_http"));
  assert.ok(result.vendorSummary.some((vendor) => vendor.vendor === "reCAPTCHA"));
});

test("does not turn negated or concrete policy safeguards into risks", () => {
  const result = analyzePolicy(`
    Privacy Policy. We collect email to provide the service.
    We do not transfer personal information outside your country.
    We do not require binding arbitration or a class action waiver.
    We delete personal information after the purpose is fulfilled.
    We use appropriate safeguards including encryption and access control.
  `);
  const korean = analyzePolicy(`
    개인정보 처리방침. 회사는 서비스 제공을 위해 이메일을 수집합니다.
    개인정보는 목적 달성 후 지체 없이 파기하며 국외로 이전하지 않습니다.
    회사는 강제 중재를 요구하지 않습니다.
  `);

  for (const riskId of ["overseas_transfer", "arbitration", "retention_unclear", "security_vague"]) {
    assert.equal(result.risks.some((risk) => risk.id === riskId), false, riskId);
  }
  for (const riskId of ["overseas_transfer", "arbitration", "retention_unclear"]) {
    assert.equal(korean.risks.some((risk) => risk.id === riskId), false, riskId);
  }
});

test("keeps genuine unclear retention, vague security, transfer, and arbitration risks", () => {
  const result = analyzePolicy(`
    Privacy Policy. We collect email and retain it as long as necessary.
    We use reasonable security measures.
    We may transfer personal information outside your country.
    Disputes are subject to binding arbitration and a class action waiver.
  `);

  for (const riskId of ["retention_unclear", "security_vague", "overseas_transfer", "arbitration"]) {
    assert.equal(result.risks.some((risk) => risk.id === riskId), true, riskId);
  }
});

test("leaves events within one second of a consent choice unclassified", () => {
  const result = analyzeConsentCompliance(
    {
      detected: true,
      choiceAt: 2000,
      containers: [{ text: "Analytics cookies", buttons: ["Accept all", "Reject all"], toggles: [] }]
    },
    [
      { host: "www.google-analytics.com", timeStamp: 999 },
      { host: "www.google-analytics.com", timeStamp: 1500 },
      { host: "www.google-analytics.com", timeStamp: 2000 },
      { host: "www.google-analytics.com", timeStamp: 2500 },
      { host: "www.google-analytics.com", timeStamp: 3001 }
    ],
    []
  );

  assert.equal(result.preChoiceTrackingRequestCount, 1);
  assert.equal(result.postChoiceTrackingRequestCount, 1);
  assert.equal(result.unclassifiedTrackingRequestCount, 3);
  assert.equal(result.timing.ambiguityWindowMs, 1000);
});

test("does not treat an observation snapshot as a consent choice boundary", () => {
  const result = analyzeConsentCompliance(
    {
      detected: true,
      snapshotAt: 2000,
      containers: [
        {
          text: "Analytics cookies",
          buttons: ["Reject all"],
          toggles: [{ label: "Analytics", checked: false }]
        }
      ]
    },
    [{ host: "www.google-analytics.com", timeStamp: 2500 }],
    []
  );
  const finding = result.findings.find((item) => item.id === "tracking_despite_disabled_toggle");

  assert.equal(result.timing.snapshotAt, 2000);
  assert.equal(result.timing.boundaryAt, null);
  assert.equal(result.timing.boundaryType, "none");
  assert.equal(result.postChoiceTrackingRequestCount, 0);
  assert.equal(result.unclassifiedTrackingRequestCount, 1);
  assert.equal(finding.severity, "medium");
  assert.equal(finding.confidence, "low");
});

test("marks consent timing claims as low-confidence when timestamps are unavailable", () => {
  const result = analyzeConsentCompliance(
    {
      detected: true,
      containers: [
        {
          text: "Analytics cookies",
          buttons: ["Accept all"],
          toggles: [{ label: "Analytics", checked: false }]
        }
      ]
    },
    [{ host: "www.google-analytics.com" }],
    []
  );
  const beforeFinding = result.findings.find((finding) => finding.id === "tracking_before_clear_choice");
  const disabledFinding = result.findings.find((finding) => finding.id === "tracking_despite_disabled_toggle");

  assert.equal(beforeFinding.severity, "medium");
  assert.equal(beforeFinding.confidence, "low");
  assert.equal(disabledFinding.severity, "medium");
  assert.equal(disabledFinding.confidence, "low");
  assert.doesNotMatch(beforeFinding.detail, /^finding\./);
});

test("does not leak translation keys or unresolved placeholders in findings", () => {
  const network = analyzeNetworkActivity(
    "We collect email.",
    [{ host: "api.external.test", url: "https://api.external.test/write", method: "POST" }],
    "https://service.example.com"
  );
  const alignment = analyzeBehaviorPolicyAlignment("We collect email.", {
    vendorSummary: [
      {
        host: "js.stripe.com",
        vendor: "Stripe",
        category: "payment",
        expectedPolicySections: ["processors"],
        missingPolicySections: ["processors"]
      }
    ]
  });
  const jurisdiction = analyzeJurisdictionCompliance("We collect email.", {
    signals: { countryCode: "KR" },
    observed: { hasThirdParty: true }
  });
  const renderedStrings = [
    ...network.findings.flatMap((finding) => [finding.title, finding.detail, finding.advice]),
    ...alignment.findings.flatMap((finding) => [finding.title, finding.detail, finding.advice]),
    ...jurisdiction.findings.flatMap((finding) => [finding.title, finding.detail, finding.advice])
  ].filter(Boolean);

  assert.ok(renderedStrings.every((value) => !value.includes("$2")));
  assert.ok(renderedStrings.every((value) => !value.startsWith("finding.")));
  assert.ok(renderedStrings.every((value) => !value.includes("consentCategoryLabels.payment")));
});

test("localizes analyzer-generated field and synthetic choice labels", async () => {
  await setLocalePreference("en");
  try {
    const network = analyzeNetworkActivity(
      "Privacy Policy. We collect email.",
      [{ host: "service.example.com", url: "https://service.example.com/api", method: "GET", queryKeys: ["email"] }],
      "https://service.example.com"
    );
    const consent = analyzeConsentCompliance({
      detected: true,
      containers: [{ text: "Analytics cookies", buttons: [], toggles: [{ label: "Analytics", checked: false }] }]
    });

    assert.equal(network.sensitiveFields[0].label, "Contact");
    assert.equal(consent.choiceAnalyses[0].label, "Preferences");
  } finally {
    await setLocalePreference("auto");
  }
});

test("accepts bounded legacy network records without a URL", () => {
  const result = analyzeNetworkActivity(
    "Privacy Policy. We collect email.",
    [{ host: "api.external.test", method: "GET", queryKeys: [], bodyKeys: [] }],
    "https://service.example.com"
  );

  assert.equal(result.requestCount, 1);
  assert.deepEqual(result.thirdPartyHosts, ["api.external.test"]);
});

test("bounds attacker-controlled policy text and avoids repeated-token regex denial of service", { timeout: 6_000 }, () => {
  const adversarialInputs = [
    `Privacy Policy. We collect personal data. ${"change ".repeat(150_000)}`,
    `Privacy Policy. We collect personal data. ${"delete ".repeat(35_000)}`,
    `개인정보 처리방침. 회사는 개인정보를 수집합니다. ${"계정 ".repeat(80_000)}`
  ];
  const startedAt = performance.now();

  for (const input of adversarialInputs) {
    const result = analyzePolicy(input);
    assert.ok(input.length >= 200_000);
    assert.equal(result.ok, true);
    assert.ok(result.wordCount <= MAX_POLICY_ANALYSIS_CHARS);
  }

  assert.ok(performance.now() - startedAt < 3_500, "adversarial policy analysis exceeded the bounded runtime budget");
});

test("keeps policy-change matching local while preserving normal clause detection", () => {
  const localClause = analyzePolicy(
    "Privacy Policy. We collect personal data. We may change these terms after giving notice."
  );
  const distantTokens = analyzePolicy(
    `Privacy Policy. We collect personal data. change ${"unrelated filler ".repeat(30)} terms.`
  );

  assert.equal(localClause.risks.some((risk) => risk.id === "policy_change"), true);
  assert.equal(distantTokens.risks.some((risk) => risk.id === "policy_change"), false);
});
