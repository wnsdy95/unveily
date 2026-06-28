const LOCALE_PREFERENCE_KEY = "uiLocaleOverride";
const LEGACY_LOCALE_PREFERENCE_KEYS = ["localePreference", "locale", "language", "uiLocale"];
const AUTO_LOCALE = "auto";
const SUPPORTED_LOCALES = new Set(["ko", "en"]);
let loadedLocalePreference = false;
let localeOverride = AUTO_LOCALE;
let effectiveLocale = null;

const FALLBACK_MESSAGES = {
  ko: {
    appName: "unveily",
    appDescription: "약관과 개인정보처리방침을 요약하고 위험 조항과 수집 데이터를 표시합니다.",
    actionTitle: "unveily",
    languageLabel: "언어",
    languageAuto: "자동",
    languageKorean: "한국어",
    languageEnglish: "English",
    popupTitle: "unveily",
    popupSourceDefault: "현재 페이지 또는 붙여넣은 텍스트를 분석합니다.",
    menuCollapse: "메뉴 접기",
    menuExpand: "메뉴 열기",
    analysisMenuLabel: "분석 방식",
    analyzePage: "현재 페이지 분석",
    analyzeCookies: "쿠키 분석",
    analyzePaste: "붙여넣기 분석",
    saveSnapshot: "기준 저장",
    resetObservation: "관찰 초기화",
    exportMarkdown: "Markdown 저장",
    exportJson: "JSON 저장",
    savePolicy: "정책 저장",
    deletePolicy: "저장본 삭제",
    checkPolicies: "변경 확인",
    pasteLabel: "약관 또는 개인정보처리방침 원문",
    pastePlaceholder: "분석할 약관이나 개인정보처리방침을 붙여넣으세요.",
    disclaimer: "규칙 기반 1차 점검입니다. 법률 자문이나 보안 진단을 대체하지 않습니다.",
    severityHigh: "높음",
    severityMedium: "주의",
    severityLow: "낮음",
    statusAnalysisComplete: "분석 완료: 약 $1개 단어",
    statusAnalyzingPage: "현재 페이지 텍스트와 네트워크 요청을 읽는 중입니다.",
    statusNoActiveTab: "활성화된 탭을 찾을 수 없습니다.",
    statusUnsupportedPageScheme: "현재 탭은 분석 대상이 아닙니다. 웹사이트(http/https) 탭에서 실행하세요.",
    statusPageScriptUnavailable: "현재 페이지에서 분석 스크립트를 찾지 못했습니다. 페이지 이동 직후거나 보안 제한 페이지일 수 있습니다. 새로고침 후 잠시 후 다시 시도하세요.",
    statusNoPagePayload: "현재 탭이 응답하지 않습니다. 페이지를 새로고침 후 다시 시도하세요.",
    statusPageReadFailed: "현재 페이지를 읽지 못했습니다. 페이지를 새로고침한 뒤 다시 시도하거나 붙여넣기 분석을 사용하세요.",
    statusCookieAnalyzing: "쿠키 배너, 허용 선택지, 저장소 동작을 읽는 중입니다.",
    statusCookieComplete: "쿠키 분석 완료: 동의 UI $1, 쿠키 $2개",
    statusCookieFailed: "쿠키 분석을 실행하지 못했습니다. 페이지를 새로고침한 뒤 다시 시도하세요.",
    statusPolicySaved: "현재 정책 스냅샷을 로컬에 저장했습니다.",
    statusNeedPageAnalysis: "먼저 현재 페이지 분석을 실행하세요.",
    statusPolicyDeleted: "이 사이트의 로컬 정책 저장본을 삭제했습니다.",
    statusPolicyDeleteFailed: "삭제할 저장본의 사이트를 찾지 못했습니다.",
    statusCheckingPolicies: "저장된 정책 URL을 확인하는 중입니다.",
    statusPoliciesChecked: "정책 확인 완료: $1개 확인, $2개 변경, $3개 알림",
    statusPoliciesCheckFailed: "저장된 정책 확인에 실패했습니다.",
    statusJsonSaved: "JSON 리포트를 저장했습니다.",
    statusMarkdownSaved: "Markdown 리포트를 저장했습니다.",
    statusObservationSaved: "현재 관찰 상태를 기준으로 저장했습니다. 동의 선택 후 다시 분석하세요.",
    statusObservationSaveFailed: "기준 저장에 실패했습니다.",
    statusObservationReset: "관찰 데이터를 초기화했습니다. 페이지를 새로고침하거나 동의 선택 후 다시 분석하세요.",
    statusObservationResetFailed: "관찰 초기화에 실패했습니다.",
    statusLanguageUpdated: "언어가 변경되어 즉시 적용됩니다. 보고서는 새로 분석하면 반영된 언어로 다시 표시됩니다.",
    pastedTextSource: "붙여넣은 텍스트",
    currentPageSource: "현재 페이지",
    cookieAnalysisSource: "쿠키 분석",
    detected: "감지",
    notDetected: "없음",
    notAvailable: "사용 불가",
    exists: "있음",
    unclear: "불명확",
    noClearSignal: "명확한 위험 신호가 감지되지 않았습니다.",
    riskLevelTitle: "위험도",
    cookieRiskTitle: "쿠키 위험도",
    dataCategoriesTitle: "수집 가능 데이터",
    riskClausesTitle: "주의할 조항",
    protectionsTitle: "확인된 보호 장치",
    policyEvidenceTitle: "정책 근거 구조화",
    missingEvidenceTitle: "명확히 찾지 못한 항목",
    policyChangeTitle: "정책 변경 감지",
    previousSavedAt: "이전 저장",
    changeStatus: "변경 상태",
    changed: "변경됨",
    unchanged: "동일",
    sectionDiffsTitle: "섹션 변경 내용",
    before: "이전",
    after: "현재",
    behaviorAlignmentTitle: "실제 동작 정합도",
    alignmentScore: "정합도",
    level: "수준",
    jurisdictionTitle: "적용 기준",
    jurisdiction: "관할권",
    confidence: "판정 신뢰도",
    snapshotComparisonTitle: "스냅샷 비교",
    snapshotBaseline: "기준",
    snapshotUserBaseline: "사용자 기준",
    additionalRequests: "추가 요청",
    additionalCookies: "추가 쿠키",
    policyNotificationChangedSection: "변경 섹션",
    policyNotificationNewRisk: "새 위험",
    policyNotificationDefault: "중요 변경이 감지되었습니다.",
    changeTypeAdded: "추가됨",
    changeTypeRemoved: "제거됨",
    changeTypeModified: "수정됨",
    policyTextChangedTitle: "정책 원문 변경 감지",
    policyTextChangedAdvice: "변경된 섹션과 위험 조항을 확인하세요.",
    policySectionChangedTitle: "정책 주요 섹션 변경 감지",
    policySectionChangedAdvice: "제3자 제공, 쿠키/행태정보, 국외 이전, 보유 기간 변경은 우선 확인하세요.",
    policyNewRiskTitle: "새 위험 조항 감지",
    policyNewRiskAdvice: "이전 저장본에는 없던 위험 패턴이 새로 감지됐습니다.",
    consentComparisonTitle: "동의 선택 비교",
    consentUi: "동의 UI",
    rejectOption: "거부 선택지",
    trackingActions: "추적성 동작",
    cookieDefaultEnabledSuffix: " 기본 켜짐.",
    cookieInferredSuffix: " 추정.",
    cookieChoicesTitle: "쿠키 허용 선택지",
    warningSignalsTitle: "주의 신호",
    allowedItemsTitle: "허용되는 항목",
    checkPointsTitle: "확인할 점",
    cookieStorageTitle: "쿠키/저장소 비교",
    cookieChanges: "쿠키 변경",
    storageKeys: "저장소 키",
    signupFormTitle: "회원가입 폼 비교",
    allFields: "전체 입력 필드",
    sensitiveFields: "개인정보성 필드",
    detectedFieldsTitle: "감지된 입력 항목",
    networkTitle: "네트워크 동작 비교",
    observedRequests: "관찰 요청",
    thirdPartyDomains: "제3자 도메인",
    vendorClassificationTitle: "벤더 분류",
    detectedThirdPartyDomainsTitle: "감지된 제3자 도메인",
    targetTitle: "분석 대상",
    page: "페이지",
    cookieChoicesCount: "동의 선택지",
    cookieBeforeChoiceSummaryHigh: "광고/분석 쿠키, 동의 전 추적, 또는 정책과 실제 동작 불일치 가능성이 있습니다. 모두 허용 전에 선택지별 허용 항목을 확인하세요.",
    cookieBeforeChoiceSummaryMedium: "일부 선택 쿠키나 설정 숨김 가능성이 있습니다. 필수 쿠키만 허용할 수 있는지 확인하는 것이 안전합니다.",
    cookieBeforeChoiceSummaryLowEmpty: "현재 관찰된 쿠키와 추적성 요청이 적어 위험 신호가 낮습니다.",
    cookieBeforeChoiceSummaryLow: "현재 관찰된 쿠키 선택지와 저장소 동작에서 큰 위험 신호는 감지되지 않았습니다.",
    noDetectedDataCategories: "명확히 감지된 항목이 없습니다. 수집 항목 표가 별도로 있는지 확인하세요.",
    noPolicyRisks: "주요 위험 패턴은 감지되지 않았습니다.",
    noPositiveSignals: "삭제권, 보안 조치, 보유 기간 같은 긍정 신호가 명확히 감지되지 않았습니다.",
    noSavedPolicySnapshot: "이 사이트의 저장된 정책 스냅샷이 없습니다. 현재 정책을 저장하면 다음 분석부터 변경을 감지합니다.",
    noPolicyChanges: "저장된 정책과 현재 정책의 주요 변경은 감지되지 않았습니다.",
    noAlignmentFindings: "관찰된 동작과 정책 근거의 정합성이 높습니다.",
    noJurisdictionFindings: "자동 적용된 기준에서 추가 경고는 감지되지 않았습니다.",
    noPolicyEvidence: "구조화 가능한 정책 근거를 찾지 못했습니다.",
    noSnapshot: "기준 저장 후 다시 분석하면 이후 발생한 추적 요청과 쿠키를 따로 비교합니다.",
    noDeltaTracking: "기준 저장 이후 새 추적 동작은 감지되지 않았습니다.",
    noConsentConflict: "동의 UI와 추적 동작 사이의 명확한 충돌은 감지되지 않았습니다.",
    noCookieChoiceClassified: "감지된 쿠키 선택지를 분류하지 못했습니다. 설정 버튼 안의 항목을 직접 확인하세요.",
    noAllowedItems: "명확히 분류된 허용 항목이 없습니다.",
    noExtraConcerns: "추가 위험 신호가 명확히 감지되지 않았습니다.",
    noStorageConflict: "쿠키와 브라우저 저장소에서 큰 충돌 신호는 감지되지 않았습니다.",
    noFormConflict: "폼 입력 항목은 정책의 수집 항목과 크게 충돌하지 않습니다.",
    noSensitiveFormFields: "민감한 폼 입력 항목이 감지되지 않았습니다.",
    noNetworkConflict: "현재까지 감지된 네트워크 동작은 정책과 크게 충돌하지 않습니다.",
    noThirdPartyDomain: "제3자 도메인이 감지되지 않았습니다.",
    noVendors: "분류된 벤더가 없습니다.",
    optionTitle: "unveily 설정",
    optionsHeading: "로컬 벤더 룰",
    optionsDescription: "사용자 정의 도메인 분류는 이 브라우저의 로컬 저장소에만 저장됩니다.",
    vendorName: "벤더명",
    vendorPlaceholder: "예: NICE 본인인증",
    domainPatterns: "도메인 패턴",
    domainPatternsPlaceholder: "예: niceid.co.kr, nice.co.kr",
    category: "카테고리",
    riskRole: "위험/역할",
    requiredPolicySections: "필요 정책 섹션",
    processors: "처리위탁",
    purpose: "수집 목적",
    security: "보안 조치",
    cookiesTracking: "쿠키/행태정보",
    thirdParty: "제3자 제공",
    overseasTransfer: "국외 이전",
    save: "저장",
    cancel: "취소",
    savedRules: "저장된 룰",
    savedSnapshots: "저장된 정책 스냅샷",
    noSavedRules: "저장된 사용자 룰이 없습니다.",
    noSavedSnapshots: "저장된 정책 스냅샷이 없습니다.",
    edit: "수정",
    delete: "삭제",
    statusRuleInvalid: "벤더명, 도메인 패턴, 필요 정책 섹션을 확인하세요.",
    statusRuleSaved: "로컬 사용자 룰을 저장했습니다.",
    statusRuleDeleted: "로컬 사용자 룰을 삭제했습니다.",
    statusRuleLoaded: "수정할 룰을 불러왔습니다.",
    statusSnapshotDeleted: "정책 스냅샷을 삭제했습니다."
  },
  en: {
    appName: "unveily",
    appDescription: "Summarize terms and privacy policies, highlighting risky clauses and collected data.",
    actionTitle: "unveily",
    languageLabel: "Language",
    languageAuto: "Auto",
    languageKorean: "Korean",
    languageEnglish: "English",
    popupTitle: "unveily",
    popupSourceDefault: "Analyze the current page or pasted text.",
    menuCollapse: "Hide menu",
    menuExpand: "Show menu",
    analysisMenuLabel: "Analysis section",
    analyzePage: "Analyze page",
    analyzeCookies: "Cookie analysis",
    analyzePaste: "Paste analysis",
    saveSnapshot: "Save baseline",
    resetObservation: "Reset observation",
    exportMarkdown: "Save Markdown",
    exportJson: "Save JSON",
    savePolicy: "Save policy",
    deletePolicy: "Delete saved",
    checkPolicies: "Check changes",
    pasteLabel: "Terms or privacy policy text",
    pastePlaceholder: "Paste the terms or privacy policy text to analyze.",
    disclaimer: "This is a rule-based first-pass review. It is not legal advice or a security audit.",
    severityHigh: "High",
    severityMedium: "Caution",
    severityLow: "Low",
    statusAnalysisComplete: "Analysis complete: about $1 words",
    statusAnalyzingPage: "Reading page text and network activity.",
    statusNoActiveTab: "Could not find the active tab.",
    statusUnsupportedPageScheme: "Current tab is not supported for analysis. Open an http/https page.",
    statusPageScriptUnavailable: "Could not locate analysis script in the current page. The page may be newly loaded or restricted. Refresh and retry after a moment.",
    statusNoPagePayload: "The current tab did not return page data. Refresh and retry.",
    statusPageReadFailed: "Could not read the current page. Refresh and retry, or use paste analysis.",
    statusCookieAnalyzing: "Reading cookie banner, consent choices, and storage activity.",
    statusCookieComplete: "Cookie analysis complete: consent UI $1, cookies $2",
    statusCookieFailed: "Could not run cookie analysis. Refresh the page and try again.",
    statusPolicySaved: "Saved the current policy snapshot locally.",
    statusNeedPageAnalysis: "Run current page analysis first.",
    statusPolicyDeleted: "Deleted the local policy snapshot for this site.",
    statusPolicyDeleteFailed: "Could not find a saved snapshot for this site.",
    statusCheckingPolicies: "Checking saved policy URLs.",
    statusPoliciesChecked: "Policy check complete: $1 checked, $2 changed, $3 notified",
    statusPoliciesCheckFailed: "Failed to check saved policies.",
    statusJsonSaved: "Saved the JSON report.",
    statusMarkdownSaved: "Saved the Markdown report.",
    statusObservationSaved: "Saved the current observation as a baseline. Choose consent options, then analyze again.",
    statusObservationSaveFailed: "Failed to save the baseline.",
    statusObservationReset: "Cleared observation data. Refresh the page or choose consent options, then analyze again.",
    statusObservationResetFailed: "Failed to reset observation data.",
    statusLanguageUpdated: "Language setting has been applied. Re-run analysis to refresh report text in the selected language.",
    pastedTextSource: "Pasted text",
    currentPageSource: "Current page",
    cookieAnalysisSource: "Cookie analysis",
    detected: "Detected",
    notDetected: "None",
    notAvailable: "Not available",
    exists: "Available",
    unclear: "Unclear",
    noClearSignal: "No clear risk signals detected.",
    riskLevelTitle: "Risk level",
    cookieRiskTitle: "Cookie risk",
    dataCategoriesTitle: "Possible collected data",
    riskClausesTitle: "Clauses to review",
    protectionsTitle: "Detected safeguards",
    policyEvidenceTitle: "Structured policy evidence",
    missingEvidenceTitle: "Not clearly found",
    policyChangeTitle: "Policy change detection",
    previousSavedAt: "Previous save",
    changeStatus: "Change status",
    changed: "Changed",
    unchanged: "Unchanged",
    sectionDiffsTitle: "Section diffs",
    before: "Before",
    after: "Current",
    behaviorAlignmentTitle: "Behavior-policy alignment",
    alignmentScore: "Alignment",
    level: "Level",
    jurisdictionTitle: "Applied standard",
    jurisdiction: "Jurisdiction",
    confidence: "Confidence",
    snapshotComparisonTitle: "Snapshot comparison",
    snapshotBaseline: "Baseline",
    snapshotUserBaseline: "User baseline",
    policyNotificationChangedSection: "Changed section",
    policyNotificationNewRisk: "New risk",
    policyNotificationDefault: "Important changes detected.",
    changeTypeAdded: "Added",
    changeTypeRemoved: "Removed",
    changeTypeModified: "Modified",
    policyTextChangedTitle: "Policy text changed",
    policyTextChangedAdvice: "Review changed sections and newly added risk clauses.",
    policySectionChangedTitle: "Major policy section changes detected",
    policySectionChangedAdvice: "Prioritize checking changes in third-party sharing, cookies/analytics, overseas transfer, and retention period.",
    policyNewRiskTitle: "New risk clause detected",
    policyNewRiskAdvice: "A new risk pattern not present in the previously saved snapshot was detected.",
    additionalRequests: "Additional requests",
    additionalCookies: "Additional cookies",
    cookieDefaultEnabledSuffix: " default-on.",
    cookieInferredSuffix: " inferred.",
    consentComparisonTitle: "Consent choice comparison",
    consentUi: "Consent UI",
    rejectOption: "Reject option",
    trackingActions: "Tracking activity",
    cookieChoicesTitle: "Cookie consent choices",
    warningSignalsTitle: "Warning signals",
    allowedItemsTitle: "Allowed items",
    checkPointsTitle: "Checkpoints",
    cookieStorageTitle: "Cookie/storage comparison",
    cookieChanges: "Cookie changes",
    storageKeys: "Storage keys",
    signupFormTitle: "Signup form comparison",
    allFields: "All input fields",
    sensitiveFields: "Personal-data fields",
    detectedFieldsTitle: "Detected fields",
    networkTitle: "Network behavior comparison",
    observedRequests: "Observed requests",
    thirdPartyDomains: "Third-party domains",
    vendorClassificationTitle: "Vendor classification",
    detectedThirdPartyDomainsTitle: "Detected third-party domains",
    targetTitle: "Analysis target",
    page: "Page",
    cookieChoicesCount: "Consent choices",
    cookieBeforeChoiceSummaryHigh: "Advertising/analytics cookies, pre-choice tracking, or policy-behavior mismatch may exist. Review each choice before accepting all.",
    cookieBeforeChoiceSummaryMedium: "Some optional cookies or hidden settings may exist. Check whether strictly necessary cookies only is available.",
    cookieBeforeChoiceSummaryLowEmpty: "Few cookies and tracking requests were observed, so risk signals are low.",
    cookieBeforeChoiceSummaryLow: "No major risk signals were detected in the observed cookie choices and storage behavior.",
    noDetectedDataCategories: "No clear data category was detected. Check whether there is a separate collected-data table.",
    noPolicyRisks: "No major risky policy patterns detected.",
    noPositiveSignals: "No clear signals for deletion rights, security controls, or retention periods were detected.",
    noSavedPolicySnapshot: "No saved policy snapshot exists for this site. Save the current policy to detect changes next time.",
    noPolicyChanges: "No major change was detected compared with the saved policy.",
    noAlignmentFindings: "Observed behavior appears well aligned with policy evidence.",
    noJurisdictionFindings: "No additional warning was detected under the applied standard.",
    noPolicyEvidence: "Could not find structured policy evidence.",
    noSnapshot: "Save a baseline, then analyze again to compare tracking requests and cookies after that point.",
    noDeltaTracking: "No new tracking activity was detected after the saved baseline.",
    noConsentConflict: "No clear conflict between consent UI and tracking behavior was detected.",
    noCookieChoiceClassified: "Could not classify detected cookie choices. Check the items inside settings manually.",
    noAllowedItems: "No clearly classified allowed items.",
    noExtraConcerns: "No additional clear risk signal detected.",
    noStorageConflict: "No major conflict was detected in cookies or browser storage.",
    noFormConflict: "Form fields do not strongly conflict with policy data categories.",
    noSensitiveFormFields: "No sensitive form fields detected.",
    noNetworkConflict: "Observed network behavior does not strongly conflict with the policy.",
    noThirdPartyDomain: "No third-party domain detected.",
    noVendors: "No classified vendors.",
    optionTitle: "unveily Settings",
    optionsHeading: "Local vendor rules",
    optionsDescription: "Custom domain classifications are stored only in this browser's local storage.",
    vendorName: "Vendor name",
    vendorPlaceholder: "e.g. NICE identity verification",
    domainPatterns: "Domain patterns",
    domainPatternsPlaceholder: "e.g. niceid.co.kr, nice.co.kr",
    category: "Category",
    riskRole: "Risk/role",
    requiredPolicySections: "Required policy sections",
    processors: "Processors",
    purpose: "Purpose",
    security: "Security controls",
    cookiesTracking: "Cookies/tracking",
    thirdParty: "Third-party sharing",
    overseasTransfer: "International transfer",
    save: "Save",
    cancel: "Cancel",
    savedRules: "Saved rules",
    savedSnapshots: "Saved policy snapshots",
    noSavedRules: "No custom rules saved.",
    noSavedSnapshots: "No policy snapshots saved.",
    edit: "Edit",
    delete: "Delete",
    statusRuleInvalid: "Check vendor name, domain patterns, and required policy sections.",
    statusRuleSaved: "Saved the local custom rule.",
    statusRuleDeleted: "Deleted the local custom rule.",
    statusRuleLoaded: "Loaded the rule for editing.",
    statusSnapshotDeleted: "Deleted the policy snapshot."
  }
};

function browserLocale() {
  const localeHints = [
    globalThis.chrome?.i18n?.getUILanguage?.(),
    globalThis.navigator?.language,
    ...(globalThis.navigator?.languages || [])
  ].filter(Boolean);

  const hasKoreanSignal = localeHints.some((value) => String(value).toLowerCase().startsWith("ko"));
  if (hasKoreanSignal) return "ko";

  const hasEnglishSignal = localeHints.some((value) => String(value).toLowerCase().startsWith("en"));
  if (hasEnglishSignal) return "en";

  return "en";
}

function normalizeLocale(value) {
  if (typeof value !== "string") return AUTO_LOCALE;
  const normalized = value.toLowerCase().trim();
  if (normalized === "ko" || normalized === "ko-kr" || normalized === "korean" || normalized === "kr") return "ko";
  if (
    normalized === "en" ||
    normalized === "en-us" ||
    normalized === "en-gb" ||
    normalized === "english"
  ) {
    return "en";
  }
  if (normalized === AUTO_LOCALE || normalized === "auto") return AUTO_LOCALE;
  return AUTO_LOCALE;
}

function setLocaleState(overrideLocale) {
  localeOverride = normalizeLocale(overrideLocale);
  effectiveLocale = localeOverride === AUTO_LOCALE ? browserLocale() : localeOverride;
}

function resolveLocaleInternal() {
  if (!effectiveLocale) {
    setLocaleState(localeOverride);
  }
  return effectiveLocale;
}

async function loadLocalePreference() {
  if (loadedLocalePreference) return;
  loadedLocalePreference = true;

  try {
    const storage = globalThis.chrome?.storage?.local;
    if (!storage?.get) {
      setLocaleState(AUTO_LOCALE);
      return;
    }

    const result = await storage.get([LOCALE_PREFERENCE_KEY, ...LEGACY_LOCALE_PREFERENCE_KEYS]);
    const hasNewValue = Object.prototype.hasOwnProperty.call(result || {}, LOCALE_PREFERENCE_KEY);
    const legacyValue =
      result?.[LOCALE_PREFERENCE_KEY] ??
      LEGACY_LOCALE_PREFERENCE_KEYS.map((key) => result?.[key]).find((value) => value !== undefined);
    const nextLocale = normalizeLocale(legacyValue ?? AUTO_LOCALE);
    setLocaleState(nextLocale);
    if (!hasNewValue && nextLocale !== AUTO_LOCALE) {
      try {
        await storage.set({ [LOCALE_PREFERENCE_KEY]: nextLocale });
      } catch {
        // Best-effort migration to the latest key.
      }
    }
  } catch {
    setLocaleState(AUTO_LOCALE);
  }
}

export async function getLocalePreference() {
  await loadLocalePreference();
  return localeOverride;
}

export async function setLocalePreference(value) {
  const nextLocale = normalizeLocale(value);
  setLocaleState(nextLocale);
  try {
    await globalThis.chrome?.storage?.local?.set?.({ [LOCALE_PREFERENCE_KEY]: nextLocale });
  } catch {
    // Storage is optional in test and some runtime contexts.
  }
}

export async function initI18n(root = document) {
  await loadLocalePreference();
  await applyI18n(root);
}

export function localeCode() {
  const locale = resolveLocaleInternal();
  return SUPPORTED_LOCALES.has(locale) ? locale : "en";
}

function fallbackMessage(locale, key) {
  return FALLBACK_MESSAGES[locale]?.[key] || FALLBACK_MESSAGES.ko[key] || key;
}

function applySubstitutions(message, substitutions) {
  return substitutions.reduce((text, value, index) => text.replaceAll(`$${index + 1}`, String(value)), message);
}

export function t(key, substitutions = []) {
  const locale = localeCode();

  if (localeOverride !== AUTO_LOCALE) {
    return applySubstitutions(fallbackMessage(locale, key), substitutions);
  }

  const chromeMessage = globalThis.chrome?.i18n?.getMessage?.(key, substitutions);
  if (chromeMessage) return chromeMessage;

  return applySubstitutions(fallbackMessage(locale, key), substitutions);
}

export async function applyI18n(root = document) {
  await loadLocalePreference();
  root.documentElement?.setAttribute("lang", localeCode());
  root.title = t(root.querySelector("title")?.dataset.i18n || "appName");

  root.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = t(element.dataset.i18n);
  });
  root.querySelectorAll("[data-i18n-aria-label]").forEach((element) => {
    element.setAttribute("aria-label", t(element.dataset.i18nAriaLabel));
  });

  root.querySelectorAll("[data-i18n-placeholder]").forEach((element) => {
    element.setAttribute("placeholder", t(element.dataset.i18nPlaceholder));
  });
}
