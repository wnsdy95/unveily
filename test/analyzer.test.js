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
  analyzePolicy
} from "../src/analyzer.js";

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
});
