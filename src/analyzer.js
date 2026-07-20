import { classifyVendorHost } from "./vendorRules.js";
import { localeCode } from "./i18n.js";
import { registrableDomain } from "./publicSuffixRules.js";

// Treat every policy body as attacker-controlled input. Keeping the analyzer's
// own ceiling means callers cannot accidentally re-introduce an expensive
// whole-document scan even if their UI or message validation changes later.
export const MAX_POLICY_ANALYSIS_CHARS = 120_000;
const MAX_ANALYSIS_SENTENCE_CHARS = 2_000;
const ANALYSIS_SENTENCE_OVERLAP_CHARS = 160;

const ANALYZER_TEXT = {
  ko: {
    riskLevels: {
      high: "높음",
      medium: "주의",
      low: "낮음",
      moderate: "보통",
      unknown: "판단 불가"
    },
    dataCategoryLabels: {
      identity: "신원 정보",
      contact: "연락처",
      account: "계정 정보",
      payment: "결제 정보",
      device: "기기 및 접속 정보",
      location: "위치 정보",
      usage: "이용 행태",
      biometric: "민감/생체 정보"
    },
    positiveRuleTitles: {
      delete_right: "삭제/탈퇴 권리 안내",
      security_controls: "보안 조치 언급",
      retention_policy: "데이터 보유 기간 안내"
    },
    riskRuleTexts: {
      broad_data_sharing: {
        title: "광범위한 제3자 제공 가능성",
        advice: "제공 대상, 목적, 보유 기간이 구체적인지 확인하세요. '업무상 필요한 경우'처럼 넓은 표현은 주의가 필요합니다."
      },
      behavioral_ads: {
        title: "맞춤형 광고 및 추적",
        advice: "광고 목적의 추적을 끌 수 있는 설정이나 옵트아웃 링크가 있는지 확인하세요."
      },
      policy_change: {
        title: "약관 변경 통지 범위가 넓음",
        advice: "중요 변경 시 별도 동의 또는 명확한 사전 통지를 제공하는지 확인하세요."
      },
      account_termination: {
        title: "계정 제한/해지 재량",
        advice: "해지 사유, 이의제기 절차, 데이터 백업 가능 여부가 명시되어야 합니다."
      },
      liability_limit: {
        title: "책임 제한 조항",
        advice: "서비스 장애, 데이터 손실, 보안 사고에 대한 책임을 과도하게 배제하는지 살펴보세요."
      },
      retention_unclear: {
        title: "보유 기간이 불명확할 수 있음",
        advice: "각 데이터 항목별 보유 기간과 삭제 시점이 분리되어 있는지 확인하세요."
      },
      overseas_transfer: {
        title: "국외 이전 가능성",
        advice: "이전 국가, 수탁자, 이전 항목, 보유 기간, 거부권 안내가 있는지 확인하세요."
      },
      arbitration: {
        title: "분쟁 해결 권리 제한 가능성",
        advice: "소송권, 집단구제, 관할지가 사용자에게 불리하게 제한되는지 확인하세요."
      },
      security_vague: {
        title: "보안 조치 설명이 추상적",
        advice: "암호화, 접근통제, 침해 통지, 로그 관리 등 구체적인 조치가 있는지 보세요."
      },
      children: {
        title: "아동/청소년 데이터 관련 조항",
        advice: "연령 제한, 법정대리인 동의, 삭제 요청 절차가 명확한지 확인하세요."
      }
    },
    consentCategoryLabels: {
      necessary: "필수/보안 쿠키",
      functional: "기능/환경설정 쿠키",
      personalization: "개인화 쿠키",
      analytics: "분석/성능 쿠키",
      advertising: "광고/마케팅 쿠키",
      social: "소셜/외부 연동 쿠키",
      third_party: "제3자 제공/외부 파트너",
      payment: "결제 처리",
      support: "고객 지원",
      error_monitoring: "오류 모니터링",
      hosting: "호스팅/인프라",
      authentication: "인증",
      security: "보안",
      cdn_security: "CDN/보안",
      unknown: "분류되지 않은 외부 서비스"
    },
    consentCategoryReasons: {
      necessary: "로그인, 보안, 세션 유지처럼 서비스 제공에 필요한 범위입니다.",
      functional: "언어, 지역, 화면 설정 같은 편의 기능을 저장할 수 있습니다.",
      personalization: "사용자 행동을 기반으로 콘텐츠나 추천을 조정할 수 있습니다.",
      analytics: "방문, 클릭, 체류 시간 같은 이용 행태를 측정할 수 있습니다.",
      advertising: "광고 식별, 맞춤형 광고, 외부 광고 네트워크 추적에 쓰일 수 있습니다.",
      social: "소셜 로그인, 공유 버튼, 외부 위젯이 사용자를 식별할 수 있습니다.",
      third_party: "외부 사업자에게 쿠키나 식별자가 전달될 수 있습니다.",
      payment: "결제 승인과 부정 결제 방지를 위해 결제 사업자에게 정보가 전달될 수 있습니다.",
      support: "고객 문의 처리 과정에서 지원 사업자가 일부 정보를 처리할 수 있습니다.",
      error_monitoring: "장애 진단을 위해 오류와 기기 정보가 처리될 수 있습니다.",
      hosting: "서비스 운영을 위해 호스팅 사업자가 데이터를 처리할 수 있습니다.",
      authentication: "로그인과 본인 확인을 위해 인증 사업자가 정보를 처리할 수 있습니다.",
      security: "보안 검증과 공격 방지를 위해 식별 정보가 처리될 수 있습니다.",
      cdn_security: "콘텐츠 전송과 보안 방어를 위해 접속 정보가 처리될 수 있습니다.",
      unknown: "외부 서비스의 실제 처리 목적을 직접 확인해야 합니다."
    },
    sensitiveFieldLabels: {
      contact: "연락처",
      identity: "신원 정보",
      account: "계정 정보",
      payment: "결제 정보",
      location: "위치 정보",
      device: "기기 및 접속 정보"
    },
    policySectionLabels: {
      collected_data: "수집 항목",
      purpose: "수집 목적",
      legal_basis: "처리 법적 근거",
      retention: "보유 기간",
      third_party: "제3자 제공",
      processors: "처리위탁",
      overseas_transfer: "국외 이전",
      automated_decision: "자동화 의사결정/프로파일링",
      cookies_tracking: "쿠키/행태정보",
      user_rights: "이용자 권리",
      security: "보안 조치",
      children: "아동/청소년",
      dispute_liability: "분쟁/책임 제한"
    },
    jurisdictionLabels: {
      KR: "한국",
      US: "미국",
      GDPR: "GDPR/EU",
      GENERAL: "일반"
    },
    jurisdictionBasis: {
      ip: "IP 국가 코드",
      krSignal: "브라우저 언어/타임존 또는 .kr 도메인",
      euSignal: "브라우저 언어/타임존 또는 EU/EEA 도메인",
      usSignal: "브라우저 언어/타임존 또는 .us 도메인",
      uncertain: "관할권 신호 부족"
    },
    finding: {
      noPolicyText: "분석할 텍스트가 없습니다.",
      notPolicyText: "현재 텍스트를 약관 또는 개인정보처리방침으로 신뢰하기 어렵습니다.",
      jurisdiction_uncertain_title: "관할권 자동 판정이 불확실함",
      jurisdiction_uncertain_detail: "브라우저 언어, 타임존, 사이트 도메인만으로 한국/미국/GDPR 기준을 확정하지 못했습니다.",
      jurisdiction_uncertain_advice: "설정 화면에서 적용 기준을 사용자가 직접 선택할 수 있게 하는 것이 안전합니다.",
      undisclosed_third_parties_title: "정책에 명확히 보이지 않는 제3자 요청",
      undisclosed_third_parties_advice: "개인정보처리방침의 제3자 제공, 처리위탁, 국외 이전 목록에 이 도메인들이 포함되어 있는지 확인하세요.",
      vendor_policy_section_gap_title: "벤더 목적별 정책 근거 부족",
      vendor_policy_section_gap_advice: "감지된 벤더의 실제 목적에 맞는 처리위탁, 쿠키/광고, 보안, 결제 목적 고지가 있는지 확인하세요.",
      tracker_without_disclosure_title: "광고/분석 요청 대비 고지 부족 가능성",
      tracker_without_disclosure_advice: "정책에 쿠키, 행태정보, 맞춤형 광고, 분석 도구 사용 목적과 거부 방법이 있는지 확인하세요.",
      sensitive_fields_without_category_title: "요청 필드와 수집 항목 고지 불일치 가능성",
      sensitive_fields_without_category_advice: "실제로 전송되는 필드가 정책의 수집 항목에 포함되는지 확인하세요. 이 확장은 값이 아니라 필드명만 봅니다.",
      third_party_post_title: "제3자 도메인으로 데이터 전송 요청",
      third_party_post_advice: "회원가입, 결제, 분석 SDK 요청인지 구분하고 정책의 처리위탁/제3자 제공 근거와 맞는지 확인하세요.",
      insecure_http_title: "암호화되지 않은 HTTP 요청",
      insecure_http_advice: "개인정보나 식별자가 HTTP로 전송되면 중간자 공격에 취약합니다. HTTPS 적용 여부를 확인하세요.",
      form_fields_without_policy_category_title: "회원가입 폼 수집 항목 고지 누락 가능성",
      form_fields_without_policy_category_advice: "페이지에서 요구하는 입력 항목이 개인정보처리방침의 수집 항목에 포함되는지 확인하세요.",
      many_required_sensitive_fields_title: "필수 개인정보 입력 항목이 많음",
      many_required_sensitive_fields_advice: "서비스 제공에 꼭 필요한 항목인지, 선택 동의 항목과 분리되어 있는지 확인하세요.",
      storage_without_disclosure_title: "브라우저 저장소 사용 고지 부족 가능성",
      storage_without_disclosure_advice: "정책에 localStorage/sessionStorage, 쿠키, 식별자 저장 목적과 보관 기간이 설명되어 있는지 확인하세요.",
      tracking_cookie_without_disclosure_title: "추적성 쿠키 고지 부족 가능성",
      tracking_cookie_without_disclosure_advice: "쿠키/행태정보/맞춤형 광고 고지와 거부 방법이 제공되는지 확인하세요.",
      third_party_cookie_without_disclosure_title: "제3자 쿠키 고지 부족 가능성",
      third_party_cookie_without_disclosure_advice: "정책의 제3자 제공, 처리위탁, 쿠키 제공 업체 목록과 일치하는지 확인하세요.",
      weak_cookie_security_title: "쿠키 보안 속성 확인 필요",
      weak_cookie_security_advice: "인증/식별 쿠키는 Secure, HttpOnly, 적절한 SameSite 설정이 필요합니다.",
      tracking_without_visible_consent_title: "동의 UI 감지 전 추적 동작",
      tracking_without_visible_consent_advice: "광고/분석 추적이 동의 전 실행되는지 확인하세요. 페이지 로드 직후 발생한 요청은 특히 주의가 필요합니다.",
      tracking_before_clear_choice_title: "동의 선택 전 추적 가능성",
      tracking_before_clear_choice_advice: "사용자가 허용/거부를 누르기 전 이미 분석·광고 SDK나 쿠키가 실행되는지 새 세션에서 재현 확인하세요.",
      consent_no_reject_option_title: "거부 또는 설정 선택지가 불명확함",
      consent_no_reject_option_advice: "선택 동의는 거부하거나 세부 설정할 수 있어야 합니다. UI가 수락만 유도하는지 확인하세요.",
      reject_hidden_in_preferences_title: "거부 선택지가 설정 안에 숨겨졌을 수 있음",
      reject_hidden_in_preferences_advice: "필수 쿠키만 허용하거나 선택 동의를 거부하는 경로가 설정 화면 안에만 있는지 확인하세요.",
      tracking_despite_disabled_toggle_title: "추적 항목 비활성 상태에서 추적 동작 감지",
      tracking_despite_disabled_toggle_advice: "사용자가 거부한 뒤에도 SDK가 로드되거나 쿠키가 생성되는지 재현 테스트가 필요합니다.",
      tracking_after_rejection_title: "거부 선택 이후 추적 동작 감지",
      tracking_after_rejection_advice: "거부 이후 발생한 요청·쿠키가 필수 기능인지 확인하고, 광고·분석 추적기는 선택 동의 전까지 차단해야 합니다.",
      tracking_after_snapshot_title: "기준 저장 이후 추적 동작 발생",
      tracking_after_snapshot_advice: "동의 거부 직후 저장한 기준이라면, 거부 이후에도 추적이 시작되는지 재현 확인이 필요합니다.",
      write_request_after_snapshot_title: "기준 저장 이후 데이터 전송 요청",
      write_request_after_snapshot_advice: "동의 선택 후 새로 전송되는 데이터가 정책과 동의 범위에 맞는지 확인하세요.",
      gdpr_missing_core_information_title: "GDPR 투명성 고지 핵심 항목 누락 가능성",
      gdpr_missing_core_information_advice: "GDPR 고지는 처리 목적, 개인정보 범주, 법적 근거, 보유 기간, 수령자, 권리, 철회권 등을 명확하고 쉬운 언어로 제공해야 합니다.",
      gdpr_tracking_without_specific_consent_notice_title: "추적/광고 동의 고지 부족 가능성",
      gdpr_tracking_without_specific_consent_notice_advice: "동의가 필요한 추적은 자유롭고, 구체적이며, 정보에 근거한 명확한 긍정 행위여야 하고 철회 방법이 설명되어야 합니다.",
      gdpr_transfer_without_safeguards_notice_title: "EEA 외 이전 보호조치 고지 부족 가능성",
      gdpr_transfer_without_safeguards_notice_advice: "적정성 결정, 표준계약조항, 기타 적절한 보호조치 또는 예외 근거가 설명되어 있는지 확인하세요.",
      gdpr_special_category_without_notice_title: "특별범주 개인정보 고지 부족 가능성",
      gdpr_special_category_without_notice_advice: "특별범주 데이터는 명시적 동의 등 별도 근거와 강화된 보호조치가 필요할 수 있습니다.",
      gdpr_profiling_without_notice_title: "프로파일링/자동화 의사결정 고지 부족 가능성",
      gdpr_profiling_without_notice_advice: "관련 로직, 의미, 예상 결과와 거부권 또는 인간 개입 요청권을 확인하세요.",
      kr_missing_core_policy_sections_title: "한국 기준 핵심 처리방침 항목 누락 가능성",
      kr_missing_core_policy_sections_advice: "수집 항목, 처리 목적, 보유 기간, 정보주체 권리, 안전성 확보조치가 명확히 구분되어 있는지 확인하세요.",
      kr_third_party_without_disclosure_title: "제3자/처리위탁 고지 부족 가능성",
      kr_third_party_without_disclosure_advice: "제공받는 자, 제공 목적, 제공 항목, 보유 및 이용 기간 또는 위탁업무와 수탁자를 확인하세요.",
      kr_tracking_without_cookie_section_title: "쿠키/행태정보 고지 부족 가능성",
      kr_tracking_without_cookie_section_advice: "맞춤형 광고, 행태정보 수집, 거부 방법이 처리방침이나 동의 UI에 설명되어 있는지 확인하세요.",
      kr_overseas_transfer_without_disclosure_title: "국외 이전 고지 부족 가능성",
      kr_overseas_transfer_without_disclosure_advice: "이전 국가, 이전받는 자, 이전 항목, 이전 목적, 보유 기간, 이전 근거가 공개되어 있는지 확인하세요.",
      us_missing_transparency_sections_title: "미국 기준 개인정보 고지 투명성 부족 가능성",
      us_missing_transparency_sections_advice: "수집 정보, 이용 목적, 공유 대상, 이용자 권리 설명이 명확한지 확인하세요.",
      us_tracking_without_optout_notice_title: "추적/공유 opt-out 고지 부족 가능성",
      us_tracking_without_optout_notice_advice: "미국 주 프라이버시 법 적용 가능성이 있는 경우 판매/공유 거부, 타겟 광고 거부, 민감정보 제한 권리가 제공되는지 확인하세요.",
      us_sensitive_data_without_notice_title: "민감정보 고지 부족 가능성",
      us_sensitive_data_without_notice_advice: "민감 개인정보의 수집 목적, 제한/거부권, 보안 조치가 별도로 설명되는지 확인하세요.",
      us_children_without_parental_consent_title: "아동 개인정보 보호 고지 부족 가능성",
      us_children_without_parental_consent_advice: "13세 미만 아동 대상 서비스라면 부모 통제와 검증 가능한 부모 동의 절차를 확인하세요.",
      alignment_missing_collect_title: "실제 수집 항목 정책 근거 부족",
      alignment_missing_tracking_title: "추적/광고 동작 정책 근거 부족",
      alignment_missing_third_party_title: "제3자/수탁자 통신 정책 근거 부족",
      alignment_missing_retention_title: "보유 기간 정책 근거 부족",
      alignment_missing_security_title: "보안 조치 정책 근거 부족",
      alignment_missing_overseas_transfer_title: "국외 이전 정책 근거 부족",
      alignment_generic_advice: "실제 관찰된 동작과 정책 근거 섹션이 일치하도록 정책 또는 구현을 확인하세요."
    },
    findingTemplates: {
      noPolicyText: "분석할 텍스트가 없습니다.",
      undisclosedThirdParties: "$1로 요청이 발생했습니다.",
      trackerWithoutDisclosure: "$1 같은 추적성 도메인이 감지됐습니다.",
      sensitiveFieldsWithoutCategory: "$1 필드명이 감지됐습니다.",
      insecureHttp: "$1 요청이 HTTP로 발생했습니다.",
      storageWithoutDisclosure: "$1 저장 키가 감지됐습니다.",
      trackingCookiesWithoutDisclosure: "$1 쿠키가 감지됐습니다.",
      thirdPartyCookiesWithoutDisclosure: "$1 쿠키가 감지됐습니다.",
      weakCookieSecurity: "$1 쿠키의 Secure 또는 SameSite 설정을 확인해야 합니다.",
      thirdPartyPost: "POST/PUT/PATCH 요청이 $1 도메인으로 전송되었습니다.",
      consentNoRejectOption: "동의 UI에서 수락 버튼은 보이지만 거부/설정 버튼은 감지되지 않았습니다.",
      consentRejectHidden: "동의 UI에서 수락 및 설정 버튼은 보이지만 즉시 거부 옵션은 감지되지 않았습니다.",
      trackingAfterSnapshot: "$1개 추적성 요청, $2개 추적성 쿠키가 기준 이후 관찰됐습니다.",
      writeRequestAfterSnapshot: "$1로 쓰기 요청이 발생했습니다.",
      trackingWithoutVisibleConsent: "$1개 추적성 요청, $2개 추적성 쿠키가 관찰됐지만 보이는 동의 UI는 감지되지 않았습니다.",
      trackingBeforeClearChoice: "동의 UI가 보이는 상태에서 $1개 추적성 요청, $2개 추적성 쿠키가 함께 관찰됐습니다.",
      trackingTimingUnknown: "$1개 추적성 요청, $2개 추적성 쿠키가 같은 관찰 구간에 있지만 선택 시각이 없어 동의 전 발생으로 단정할 수 없습니다.",
      trackingDespiteDisabledToggle: "$1개 광고/분석 토글이 꺼져 있지만 추적성 요청 또는 쿠키가 관찰됐습니다.",
      trackingDisabledTimingUnknown: "$1개 광고/분석 토글이 꺼진 상태와 추적 동작이 함께 관찰됐지만 선택 시각이 없어 거부 후 발생으로 단정할 수 없습니다.",
      trackingAfterRejection: "거부 선택 이후 $1개 추적성 요청과 $2개 추적성 쿠키가 관찰됐습니다.",
      trackingAfterRejectionTimingUnknown: "거부 선택과 $1개 추적성 요청, $2개 추적성 쿠키가 같은 관찰 구간에 있지만 발생 순서를 확정할 수 없습니다.",
      noDataFound: "명확히 감지된 개인정보 항목은 적지만, 원문에서 수집 항목 표를 직접 확인해야 합니다.",
      summaryIntro: "위험도는 '$1'으로 보입니다.",
      summaryDataFound: "문서에서 $1 수집 가능성이 확인됩니다.",
      summaryFocusRisk: "특히 '$1' 조항을 먼저 확인하세요.",
      summaryPositive: "긍정적으로는 $1가 언급됩니다.",
      cookieDefaultEnabledSuffix: " 기본 켜짐.",
      cookieInferredSuffix: " 추정.",
      syntheticPreferencesLabel: "세부 설정",
      baselineLabel: "기준",
      notDetected: "없음"
    },
    consentChoicePrefixes: {
      accept_all: "모든 선택 쿠키를 허용하는 선택입니다.",
      necessary_only: "필수 쿠키만 허용하거나 선택 쿠키를 거부하는 선택입니다.",
      preferences: "세부 설정으로 들어가 항목별로 켜고 끄는 선택입니다.",
      save_choices: "현재 선택된 항목을 저장하는 선택입니다.",
      unknown: "쿠키 선택지입니다."
    },
    consentChoiceDetails: {
      inferred: "추정 허용 범위: $1",
      explicit: "허용 범위: $1",
      riskSuffix: " 위험도는 $1입니다.",
      concernHighCategory: "$1가 포함됩니다.",
      concernMediumCategory: "$1는 이용 행태 분석이나 개인화에 쓰일 수 있습니다.",
      concernTracking: "동의 선택 전후를 구분하려면 거부 직후 기준 저장 후 다시 분석해야 합니다.",
      concernInferred: "배너에 세부 허용 항목이 명확히 표시되지 않아 일반적인 쿠키 범주로 추정했습니다.",
      concernNecessaryOnlyDefault: "일반적으로 서비스 제공에 필요한 최소 범위라 위험이 낮은 편입니다."
    },
    alignmentLabels: {
      collectedData: "실제 수집 항목",
      tracking: "추적/광고 동작",
      thirdParty: "제3자/수탁자 통신",
      retention: "보유 기간",
      security: "보안 조치",
      overseasTransfer: "국외 이전"
    },
    alignmentReasons: {
      collectedData: "폼/요청/저장소에서 개인정보성 항목이 감지되면 수집 항목 고지가 필요합니다.",
      tracking: "추적성 요청이나 쿠키가 있으면 쿠키, 행태정보, 광고/분석 목적과 거부 방법 고지가 필요합니다.",
      thirdParty: "제3자 도메인이나 제3자 쿠키가 있으면 제공/공유/처리위탁 근거가 필요합니다.",
      retention: "수집 또는 브라우저 저장이 관찰되면 보유 기간이나 삭제 기준이 설명되어야 합니다.",
      security: "민감/결제/인증성 데이터가 관찰되면 보호 조치 설명이 필요합니다.",
      overseasTransfer: "해외 제3자나 비지역 도메인 전송 가능성이 있으면 국외 이전 또는 국제 전송 근거가 필요합니다.",
      vendor: "${vendor} 도메인은 ${category} 용도로 분류되며 ${sections} 근거가 필요합니다."
    },
    alignmentLabelPattern: "${vendor} (${category})"
  },
  en: {
    riskLevels: {
      high: "High",
      medium: "Caution",
      low: "Low",
      moderate: "Moderate",
      unknown: "Unknown"
    },
    dataCategoryLabels: {
      identity: "Identity",
      contact: "Contact",
      account: "Account Info",
      payment: "Payment Information",
      device: "Device/Access Info",
      location: "Location",
      usage: "Usage Behavior",
      biometric: "Sensitive/Biometric"
    },
    positiveRuleTitles: {
      delete_right: "Deletion/withdrawal rights",
      security_controls: "Security controls mentioned",
      retention_policy: "Data retention guidance"
    },
    riskRuleTexts: {
      broad_data_sharing: {
        title: "Possible broad third-party disclosure",
        advice: "Check that recipients, purpose, and retention period are clearly specified; avoid overly broad wording like 'as necessary'."
      },
      behavioral_ads: {
        title: "Personalized advertising and tracking",
        advice: "Check whether opt-in/opt-out controls for ads-related tracking are available."
      },
      policy_change: {
        title: "Wide scope of terms-change notice",
        advice: "Verify that material changes are communicated before enforcement with clear and separate consent where needed."
      },
      account_termination: {
        title: "Account suspension/termination discretion",
        advice: "Cancellation grounds, appeal process, and data backup options should be explicit."
      },
      liability_limit: {
        title: "Liability limitation clause",
        advice: "Check whether service outage, data loss, and security incident liabilities are unreasonably excluded."
      },
      retention_unclear: {
        title: "Retention period may be unclear",
        advice: "Check if retention and deletion timing are separated by each data category."
      },
      overseas_transfer: {
        title: "Possible international transfer",
        advice: "Confirm countries, processors, data types, retention period, and opt-out/withdrawal rights are disclosed."
      },
      arbitration: {
        title: "Potential limitation of dispute rights",
        advice: "Check whether litigation rights, collective remedies, and venue restrictions are unfairly limiting users."
      },
      security_vague: {
        title: "Security controls are described vaguely",
        advice: "Look for concrete controls such as encryption, access control, breach notification, and logging."
      },
      children: {
        title: "Clauses for children / minors",
        advice: "Confirm age limits, guardian consent, and deletion workflows are clear."
      }
    },
    consentCategoryLabels: {
      necessary: "Necessary/security cookies",
      functional: "Functional/preferences cookies",
      personalization: "Personalization cookies",
      analytics: "Analytics/performance cookies",
      advertising: "Advertising/marketing cookies",
      social: "Social/third-party widgets",
      third_party: "Third-party sharing/partners",
      payment: "Payment processing",
      support: "Customer support",
      error_monitoring: "Error monitoring",
      hosting: "Hosting/infrastructure",
      authentication: "Authentication",
      security: "Security",
      cdn_security: "CDN/security",
      unknown: "Unclassified external service"
    },
    consentCategoryReasons: {
      necessary: "Usually limited to service operation needs such as login, security, and session maintenance.",
      functional: "Can store preferences like language, region, and UI settings.",
      personalization: "Can adjust content or recommendations using behavioral signals.",
      analytics: "Can measure visits, clicks, and dwell time.",
      advertising: "May be used for ad identification, personalized ads, and cross-site ad network tracking.",
      social: "Social login, share buttons, and external widgets may identify users.",
      third_party: "Identifiers can be passed to external partners or service providers.",
      payment: "Information may be sent to payment providers for authorization and fraud prevention.",
      support: "A support provider may process limited information while handling customer inquiries.",
      error_monitoring: "Error and device information may be processed for incident diagnosis.",
      hosting: "A hosting provider may process data to operate the service.",
      authentication: "An identity provider may process information for login and identity verification.",
      security: "Identifiers may be processed for security checks and abuse prevention.",
      cdn_security: "Connection information may be processed for content delivery and threat protection.",
      unknown: "Review the external service's actual processing purpose directly."
    },
    sensitiveFieldLabels: {
      contact: "Contact",
      identity: "Identity",
      account: "Account",
      payment: "Payment",
      location: "Location",
      device: "Device/Access"
    },
    policySectionLabels: {
      collected_data: "Collected Data",
      purpose: "Purpose of Use",
      legal_basis: "Legal Basis",
      retention: "Retention",
      third_party: "Third-Party Disclosure",
      processors: "Processors",
      overseas_transfer: "Overseas Transfer",
      automated_decision: "Automated Decision / Profiling",
      cookies_tracking: "Cookies/Tracking",
      user_rights: "User Rights",
      security: "Security Measures",
      children: "Children",
      dispute_liability: "Disputes/Liability"
    },
    jurisdictionLabels: {
      KR: "Korea",
      US: "United States",
      GDPR: "GDPR/EU",
      GENERAL: "General"
    },
    jurisdictionBasis: {
      ip: "IP country code",
      krSignal: "Browser language/timezone or .kr domain",
      euSignal: "Browser language/timezone or EU/EEA domain",
      usSignal: "Browser language/timezone or .us domain",
      uncertain: "Insufficient jurisdiction signals"
    },
    finding: {
      noPolicyText: "No text available to analyze.",
      notPolicyText: "This text cannot be identified reliably as terms or a privacy policy.",
      jurisdiction_uncertain_title: "Jurisdiction could not be determined reliably",
      jurisdiction_uncertain_detail: "Language, timezone, and domain are not sufficient to determine KR/US/GDPR baseline with high confidence.",
      jurisdiction_uncertain_advice: "Allow users to choose the applicable compliance basis manually when needed.",
      undisclosed_third_parties_title: "Third-party request not clearly disclosed in policy",
      undisclosed_third_parties_advice: "Check if this domain is listed under third-party disclosure, processor, or international transfer sections.",
      vendor_policy_section_gap_title: "Missing policy basis for vendor purpose",
      vendor_policy_section_gap_advice: "Check whether vendor purpose-specific policy disclosure exists for the detected vendor category.",
      tracker_without_disclosure_title: "Tracking/analytics request may be insufficiently disclosed",
      tracker_without_disclosure_advice: "Check whether cookie/tracking/analytics purpose and opt-out/deactivation methods are disclosed.",
      sensitive_fields_without_category_title: "Collected fields may not be fully disclosed",
      sensitive_fields_without_category_advice: "Confirm the transmitted fields are included in disclosed collection categories; this check inspects field names only.",
      third_party_post_title: "Data sent to third-party domain",
      third_party_post_advice: "Verify whether POST/PUT/PATCH requests match consent and processor/third-party policy basis.",
      insecure_http_title: "Unencrypted HTTP request detected",
      insecure_http_advice: "If identifiers or personal data are sent over HTTP, this can be intercepted. Confirm HTTPS is enforced.",
      form_fields_without_policy_category_title: "Signup form fields may not be disclosed in policy",
      form_fields_without_policy_category_advice: "Make sure form-required fields are covered by policy collection sections.",
      many_required_sensitive_fields_title: "Many required sensitive inputs detected",
      many_required_sensitive_fields_advice: "Confirm required items are truly necessary and separate optional/consented items.",
      storage_without_disclosure_title: "Storage usage may not be sufficiently disclosed",
      storage_without_disclosure_advice: "Check whether localStorage/sessionStorage, cookies, identifiers, and retention are described clearly.",
      tracking_cookie_without_disclosure_title: "Tracking cookie disclosure may be insufficient",
      tracking_cookie_without_disclosure_advice: "Check for cookie, behavioral data, targeted advertising, and explicit opt-out guidance.",
      third_party_cookie_without_disclosure_title: "Third-party cookie disclosure may be insufficient",
      third_party_cookie_without_disclosure_advice: "Verify third-party provider lists for cookies/analytics/advertising are disclosed.",
      weak_cookie_security_title: "Cookie security attributes should be verified",
      weak_cookie_security_advice: "Auth or identifier cookies should include secure defaults (Secure/HttpOnly/SameSite).",
      tracking_without_visible_consent_title: "Tracking observed before visible consent UI",
      tracking_without_visible_consent_advice: "Check whether tracking starts before consent UI appears. Requests very early after page load need close review.",
      tracking_before_clear_choice_title: "Tracking before consent choice",
      tracking_before_clear_choice_advice: "Verify whether analytics/ads SDK or cookies run before user explicitly accepts/declines.",
      consent_no_reject_option_title: "Reject or settings path is unclear",
      consent_no_reject_option_advice: "Consent should allow refusal and granular settings; confirm this is not accept-only flow.",
      reject_hidden_in_preferences_title: "Reject option may be hidden under settings",
      reject_hidden_in_preferences_advice: "Check whether a clear reject/opt-out path is reachable only through settings.",
      tracking_despite_disabled_toggle_title: "Tracking observed while related toggles are off",
      tracking_despite_disabled_toggle_advice: "Reproduce after rejecting to verify SDK/cookies do not continue loading.",
      tracking_after_rejection_title: "Tracking observed after rejection",
      tracking_after_rejection_advice: "Verify whether post-rejection requests and cookies are strictly necessary; analytics and advertising trackers should remain blocked until opted in.",
      tracking_after_snapshot_title: "Tracking observed after baseline",
      tracking_after_snapshot_advice: "If baseline was captured after opt-out, verify tracking does not restart.",
      write_request_after_snapshot_title: "Data write request after baseline",
      write_request_after_snapshot_advice: "Check whether new writes align with consent scope.",
      gdpr_missing_core_information_title: "Possible GDPR disclosure gaps",
      gdpr_missing_core_information_advice: "GDPR disclosures should include purpose, data categories, legal basis, retention, recipients, rights, and withdrawal.",
      gdpr_tracking_without_specific_consent_notice_title: "Tracking/ad tracking consent disclosure missing",
      gdpr_tracking_without_specific_consent_notice_advice: "Consent for tracking should be explicit, informed, specific, and support easy withdrawal.",
      gdpr_transfer_without_safeguards_notice_title: "Possible cross-border transfer safeguards gap",
      gdpr_transfer_without_safeguards_notice_advice: "Check transfer mechanism: adequacy, SCCs, or other lawful safeguards.",
      gdpr_special_category_without_notice_title: "Special-category data disclosure gap",
      gdpr_special_category_without_notice_advice: "Special-category data usually needs explicit consent and stronger safeguards.",
      gdpr_profiling_without_notice_title: "Profiling/automated decision disclosure gap",
      gdpr_profiling_without_notice_advice: "Confirm logic, meaning, expected effects, and right to human review are disclosed.",
      kr_missing_core_policy_sections_title: "Missing mandatory Korea policy sections",
      kr_missing_core_policy_sections_advice: "Check whether collection, purpose, retention, rights, and security sections are clearly separated.",
      kr_third_party_without_disclosure_title: "Third-party/processor disclosure gap",
      kr_third_party_without_disclosure_advice: "Check recipients, purpose, items, retention, and processor obligations.",
      kr_tracking_without_cookie_section_title: "Cookie/tracking disclosure gap",
      kr_tracking_without_cookie_section_advice: "Check whether ad targeting, behavioral tracking, and opt-out are described in policy/consent UI.",
      kr_overseas_transfer_without_disclosure_title: "International transfer disclosure gap",
      kr_overseas_transfer_without_disclosure_advice: "Check transfer countries, recipients, retained items, purpose, period, and legal basis.",
      us_missing_transparency_sections_title: "Missing transparency disclosures under US baseline",
      us_missing_transparency_sections_advice: "Verify collection, purpose, recipients, and rights disclosures are clear.",
      us_tracking_without_optout_notice_title: "Tracking/opt-out disclosure gap",
      us_tracking_without_optout_notice_advice: "If US state privacy laws may apply, confirm sale/sharing opt-out and targeted ad opt-out guidance.",
      us_sensitive_data_without_notice_title: "Sensitive data disclosure gap",
      us_sensitive_data_without_notice_advice: "Confirm sensitive/financial data collection purpose and revocation options are clearly described.",
      us_children_without_parental_consent_title: "Child privacy gap",
      us_children_without_parental_consent_advice: "If users under 13 are allowed, verify parental controls and verifiable parental consent.",
      alignment_missing_collect_title: "Possible data-collection policy gap",
      alignment_missing_tracking_title: "Possible tracking/advertising policy gap",
      alignment_missing_third_party_title: "Possible third-party processor policy gap",
      alignment_missing_retention_title: "Possible retention policy gap",
      alignment_missing_security_title: "Possible security measure policy gap",
      alignment_missing_overseas_transfer_title: "Possible cross-border transfer policy gap",
      alignment_generic_advice: "Align real behavior with policy sections for actual disclosure and implementation."
    },
    findingTemplates: {
      noPolicyText: "No text available to analyze.",
      undisclosedThirdParties: "$1 was requested.",
      trackerWithoutDisclosure: "Tracker domains were detected: $1.",
      sensitiveFieldsWithoutCategory: "Observed fields: $1.",
      insecureHttp: "Requests observed on HTTP: $1.",
      storageWithoutDisclosure: "Detected storage keys: $1.",
      trackingCookiesWithoutDisclosure: "Tracking cookies detected: $1.",
      thirdPartyCookiesWithoutDisclosure: "Third-party cookies detected: $1.",
      weakCookieSecurity: "Review Secure and SameSite attributes for: $1.",
      thirdPartyPost: "POST/PUT/PATCH requests were sent to: $1.",
      consentNoRejectOption: "An accept action is visible but no reject/settings option was detected in this consent banner.",
      consentRejectHidden: "Accept and settings controls are visible, but a direct reject option is not immediately detected.",
      trackingAfterSnapshot: "After baseline, $1 tracking requests and $2 tracking cookies were observed.",
      writeRequestAfterSnapshot: "Write request observed from: $1.",
      trackingWithoutVisibleConsent: "$1 tracking requests and $2 tracking cookies were observed before consent UI was visible.",
      trackingBeforeClearChoice: "Tracking was observed while consent UI was visible: $1 requests and $2 tracking cookies.",
      trackingTimingUnknown: "$1 tracking requests and $2 tracking cookies were in the same observation window, but no choice time was available to prove they occurred before consent.",
      trackingDespiteDisabledToggle: "Tracking request/cookie was observed even with $1 ad/analytics toggles disabled.",
      trackingDisabledTimingUnknown: "$1 disabled ad/analytics toggles and tracking were observed in the same window, but no choice time was available to prove tracking happened after rejection.",
      trackingAfterRejection: "After rejection, $1 tracking requests and $2 tracking cookies were observed.",
      trackingAfterRejectionTimingUnknown: "Rejection and $1 tracking requests and $2 tracking cookies were observed in the same window, but their order could not be established.",
      noDataFound: "No clear personal data category is detected; check a dedicated data collection table in policy text.",
      summaryIntro: "Risk level appears to be '$1'.",
      summaryDataFound: "The document suggests possible collection of: $1.",
      summaryFocusRisk: "Check '$1' first.",
      summaryPositive: "Positives found: $1.",
      cookieDefaultEnabledSuffix: " default on.",
      cookieInferredSuffix: " inferred.",
      syntheticPreferencesLabel: "Preferences",
      baselineLabel: "Baseline",
      notDetected: "N/A"
    },
    consentChoicePrefixes: {
      accept_all: "This choice allows all cookies.",
      necessary_only: "This choice allows only necessary cookies.",
      preferences: "This choice opens detailed settings and allows per-item control.",
      save_choices: "This choice saves currently selected categories.",
      unknown: "Cookie choice."
    },
    consentChoiceDetails: {
      inferred: "Inferred allowed scope: $1",
      explicit: "Allowed scope: $1",
      riskSuffix: " The risk level is $1.",
      concernHighCategory: "Included: $1.",
      concernMediumCategory: "$1 may be used for behavior analysis or personalization.",
      concernTracking: "Compare before and after consent selection with a fresh observation baseline.",
      concernInferred: "Specific toggles were not fully visible in banner; categories were inferred from common patterns.",
      concernNecessaryOnlyDefault: "This usually looks like a minimum scope for service operation, so risk is generally lower."
    },
    alignmentLabels: {
      collectedData: "Collected Data",
      tracking: "Tracking/Advertising",
      thirdParty: "Third-party / Processor Communications",
      retention: "Retention",
      security: "Security Measures",
      overseasTransfer: "Overseas Transfer"
    },
    alignmentReasons: {
      collectedData: "If personal data is observed in forms/requests/storage, a collection disclosure is required.",
      tracking: "If tracking requests/cookies are present, cookie/tracking/ads purpose and opt-out must be disclosed.",
      thirdParty: "If third-party domains/cookies exist, provider/recipient basis is required.",
      retention: "If collection or storage is observed, retention and deletion criteria should be described.",
      security: "If sensitive/payment/auth data is observed, security protections should be described.",
      overseasTransfer: "If cross-border or non-local transfer is observed, transfer basis is required.",
      vendor: "${vendor} is classified as ${category}; required policy sections: ${sections}."
    },
    alignmentLabelPattern: "${vendor} (${category})"
  }
};

function analyzerLocale() {
  const locale = localeCode();
  return locale === "en" ? "en" : "ko";
}

function formatTemplate(template, params) {
  return params.reduce((text, value, index) => text.replaceAll(`$${index + 1}`, String(value)), template);
}

function tA(path, params = [], locale = analyzerLocale()) {
  const localeData = ANALYZER_TEXT[locale] || ANALYZER_TEXT.ko;
  const fallbackData = ANALYZER_TEXT.ko;
  const lookup = (data) =>
    path
      .split(".")
      .reduce((value, key) => (value && Object.prototype.hasOwnProperty.call(value, key) ? value[key] : undefined), data);

  const found = lookup(localeData);
  const template = (typeof found === "string" ? found : undefined) || lookup(fallbackData) || "";
  return formatTemplate(String(template), params);
}

function riskLevelLabel(level) {
  return tA(`riskLevels.${level}`);
}

function dataCategoryLabel(id) {
  return tA(`dataCategoryLabels.${id}`) || id;
}

function positiveRuleLabel(id) {
  return tA(`positiveRuleTitles.${id}`) || id;
}

function riskRuleLabel(id) {
  return tA(`riskRuleTexts.${id}.title`) || id;
}

function riskRuleAdvice(id) {
  return tA(`riskRuleTexts.${id}.advice`) || "";
}

function consentCategoryLabel(id) {
  return tA(`consentCategoryLabels.${id}`) || id;
}

function consentCategoryReason(id) {
  return tA(`consentCategoryReasons.${id}`) || "";
}

function sensitiveFieldLabel(id) {
  return tA(`sensitiveFieldLabels.${id}`) || id;
}

function policySectionLabel(id) {
  return tA(`policySectionLabels.${id}`) || id;
}

function jurisdictionLabel(code) {
  return tA(`jurisdictionLabels.${code}`) || code;
}

function jurisdictionBasisLabel(key) {
  return tA(`jurisdictionBasis.${key}`) || key;
}

function consentChoicePrefix(type) {
  return tA(`consentChoicePrefixes.${type}`) || "";
}

function consentChoiceDetail(type, inferred, categories) {
  const labels = (categories || []).map((category) => category.label);
  const template = inferred ? tA("consentChoiceDetails.inferred") : tA("consentChoiceDetails.explicit");
  return template.replaceAll("$1", labels.length ? labels.join(", ") : tA("findingTemplates.notDetected"));
}

function sectionFindingsTitle(id) {
  return tA(`finding.${id}`) || id;
}

function sectionFindingTitle(id) {
  return sectionFindingsTitle(id);
}

function sectionFindingAdvice(id) {
  return tA(`finding.${id}_advice`) || "";
}

function sectionFindingDetail(id) {
  return tA(`finding.${id}_detail`) || sectionFindingAdvice(id);
}

function alignmentLabel(pattern) {
  return tA(`alignmentLabels.${pattern}`) || pattern;
}

function alignmentReason(key, params = []) {
  return tA(`alignmentReasons.${key}`, params);
}

const DATA_CATEGORIES = [
  {
    id: "identity",
    label: "신원 정보",
    examples: ["이름", "name", "생년월일", "date of birth", "성별", "gender", "국적", "nationality"]
  },
  {
    id: "contact",
    label: "연락처",
    examples: ["이메일", "email", "전화번호", "phone", "주소", "address", "연락처"]
  },
  {
    id: "account",
    label: "계정 정보",
    examples: ["아이디", "username", "password", "비밀번호", "프로필", "profile", "계정"]
  },
  {
    id: "payment",
    label: "결제 정보",
    examples: ["결제", "payment", "카드", "credit card", "청구", "billing", "계좌", "bank account"]
  },
  {
    id: "device",
    label: "기기 및 접속 정보",
    examples: ["ip address", "ip주소", "쿠키", "cookie", "device", "기기", "browser", "브라우저", "로그", "log"]
  },
  {
    id: "location",
    label: "위치 정보",
    examples: ["location", "위치", "gps", "geolocation", "주소록"]
  },
  {
    id: "usage",
    label: "이용 행태",
    examples: ["usage", "이용기록", "행동", "analytics", "분석", "클릭", "방문", "검색 기록"]
  },
  {
    id: "biometric",
    label: "민감/생체 정보",
    examples: ["biometric", "생체", "얼굴", "face", "지문", "fingerprint", "건강", "health", "민감정보"]
  }
];

const RISK_RULES = [
  {
    id: "broad_data_sharing",
    severity: "high",
    title: "광범위한 제3자 제공 가능성",
    patterns: [
      /third parties?|3rd parties?/i,
      /제3자|제삼자|협력사|제휴사|파트너/,
      /share|sell|transfer|provide/i,
      /공유|판매|이전|제공/
    ],
    advice: "제공 대상, 목적, 보유 기간이 구체적인지 확인하세요. '업무상 필요한 경우'처럼 넓은 표현은 주의가 필요합니다."
  },
  {
    id: "behavioral_ads",
    severity: "medium",
    title: "맞춤형 광고 및 추적",
    patterns: [/targeted ad|personalized ad|interest-based/i, /맞춤형 광고|행태정보|타겟팅|리타겟팅/],
    advice: "광고 목적의 추적을 끌 수 있는 설정이나 옵트아웃 링크가 있는지 확인하세요."
  },
  {
    id: "policy_change",
    severity: "medium",
    title: "약관 변경 통지 범위가 넓음",
    patterns: [
      /change.{0,160}terms|modify.{0,160}terms|update.{0,160}policy/i,
      /약관.{0,120}변경|정책.{0,120}변경|개정/
    ],
    advice: "중요 변경 시 별도 동의 또는 명확한 사전 통지를 제공하는지 확인하세요."
  },
  {
    id: "account_termination",
    severity: "medium",
    title: "계정 제한/해지 재량",
    patterns: [/terminate|suspend|disable.{0,120}account/i, /계정.{0,120}(해지|정지|제한)|서비스.{0,120}중단/],
    advice: "해지 사유, 이의제기 절차, 데이터 백업 가능 여부가 명시되어야 합니다."
  },
  {
    id: "liability_limit",
    severity: "medium",
    title: "책임 제한 조항",
    patterns: [/limitation of liability|not liable|disclaim/i, /책임.{0,120}제한|면책|손해.{0,120}책임.{0,80}없/],
    advice: "서비스 장애, 데이터 손실, 보안 사고에 대한 책임을 과도하게 배제하는지 살펴보세요."
  },
  {
    id: "retention_unclear",
    severity: "medium",
    title: "보유 기간이 불명확할 수 있음",
    patterns: [
      /as long as necessary|retain.{0,160}necessary|indefinitely/i,
      /필요한 기간|필요한 동안|무기한|관계 법령.{0,120}보관/
    ],
    advice: "각 데이터 항목별 보유 기간과 삭제 시점이 분리되어 있는지 확인하세요."
  },
  {
    id: "overseas_transfer",
    severity: "medium",
    title: "국외 이전 가능성",
    patterns: [
      /international transfer|outside your country|cross-border/i,
      /국외 이전|해외 이전|국외.{0,120}보관|해외.{0,120}보관/
    ],
    advice: "이전 국가, 수탁자, 이전 항목, 보유 기간, 거부권 안내가 있는지 확인하세요."
  },
  {
    id: "arbitration",
    severity: "high",
    title: "분쟁 해결 권리 제한 가능성",
    patterns: [
      /binding arbitration|class action waiver|waive.{0,120}jury/i,
      /(?:강제|의무|구속력|전속).{0,20}중재|중재.{0,30}(?:강제|의무|구속력|전속)|집단소송.{0,120}포기|전속.{0,20}관할|관할 법원.{0,30}(?:전속|지정|한정)/
    ],
    advice: "소송권, 집단구제, 관할지가 사용자에게 불리하게 제한되는지 확인하세요."
  },
  {
    id: "security_vague",
    severity: "low",
    title: "보안 조치 설명이 추상적",
    patterns: [
      /reasonable security|appropriate safeguards|industry standard/i,
      /합리적인 보안|적절한 보호|기술적.{0,120}관리적.{0,120}조치/
    ],
    advice: "암호화, 접근통제, 침해 통지, 로그 관리 등 구체적인 조치가 있는지 보세요."
  },
  {
    id: "children",
    severity: "high",
    title: "아동/청소년 데이터 관련 조항",
    patterns: [/children|minor|under 13|under 16/i, /아동|청소년|미성년자|만\s?14세/],
    advice: "연령 제한, 법정대리인 동의, 삭제 요청 절차가 명확한지 확인하세요."
  }
];

const POSITIVE_RULES = [
  {
    id: "delete_right",
    title: "삭제/탈퇴 권리 안내",
    patterns: [/delete.{0,120}account|right to erasure|withdraw consent/i, /회원탈퇴|삭제 요청|동의 철회|처리정지/]
  },
  {
    id: "security_controls",
    title: "보안 조치 언급",
    patterns: [/encrypt|encryption|access control|breach notification/i, /암호화|접근통제|침해.{0,80}통지|보안.{0,80}교육/]
  },
  {
    id: "retention_policy",
    title: "데이터 보유 기간 안내",
    patterns: [/retention period|retain for|stored for/i, /보유 기간|파기|삭제.{0,80}기간/]
  }
];

const KNOWN_TRACKER_DOMAINS = [
  "google-analytics.com",
  "analytics.google.com",
  "googletagmanager.com",
  "doubleclick.net",
  "googleadservices.com",
  "googlesyndication.com",
  "facebook.com",
  "facebook.net",
  "connect.facebook.net",
  "meta.com",
  "hotjar.com",
  "hotjar.io",
  "mixpanel.com",
  "segment.com",
  "segment.io",
  "amplitude.com",
  "fullstory.com"
];
const GENERIC_TRACKER_TOKENS = new Set(["adservice", "analytics", "tracking", "tracker", "pixel", "collect"]);

const CONSENT_BOUNDARY_AMBIGUITY_MS = 1000;

const CONSENT_CATEGORY_RULES = [
  {
    id: "necessary",
    label: "필수/보안 쿠키",
    risk: "low",
    patterns: [/necessary|essential|required|strictly necessary|security|session/i, /필수|보안|세션|로그인|인증/],
    reason: "로그인, 보안, 세션 유지처럼 서비스 제공에 필요한 범위입니다."
  },
  {
    id: "functional",
    label: "기능/환경설정 쿠키",
    risk: "low",
    patterns: [/functional|functionality|preference|preferences|remember/i, /기능|환경설정|선호|편의|저장/],
    reason: "언어, 지역, 화면 설정 같은 편의 기능을 저장할 수 있습니다."
  },
  {
    id: "personalization",
    label: "개인화 쿠키",
    risk: "medium",
    patterns: [/personalization|personalisation|personalized|recommend|profile/i, /개인화|맞춤|추천|프로필/],
    reason: "사용자 행동을 기반으로 콘텐츠나 추천을 조정할 수 있습니다."
  },
  {
    id: "analytics",
    label: "분석/성능 쿠키",
    risk: "medium",
    patterns: [/analytics|performance|statistics|measurement|metrics/i, /분석|통계|성능|측정|지표/],
    reason: "방문, 클릭, 체류 시간 같은 이용 행태를 측정할 수 있습니다."
  },
  {
    id: "advertising",
    label: "광고/마케팅 쿠키",
    risk: "high",
    patterns: [/advertising|ads?|marketing|targeting|retargeting|interest-based/i, /광고|마케팅|타겟|리타겟|행태정보/],
    reason: "광고 식별, 맞춤형 광고, 외부 광고 네트워크 추적에 쓰일 수 있습니다."
  },
  {
    id: "social",
    label: "소셜/외부 연동 쿠키",
    risk: "medium",
    patterns: [/social|facebook|instagram|twitter|x\.com|linkedin|share/i, /소셜|SNS|페이스북|인스타그램|공유/],
    reason: "소셜 로그인, 공유 버튼, 외부 위젯이 사용자를 식별할 수 있습니다."
  },
  {
    id: "third_party",
    label: "제3자 제공/외부 파트너",
    risk: "high",
    patterns: [/third part(y|ies)|partners?|vendors?|service providers?/i, /제3자|제삼자|파트너|제휴사|수탁|위탁|외부/],
    reason: "외부 사업자에게 쿠키나 식별자가 전달될 수 있습니다."
  }
];

const SENSITIVE_FIELD_RULES = [
  {
    category: "contact",
    patterns: [/\b(?:email|emailaddress|e mail|phone|phonenumber|telephone|tel|mobile|address)\b/i, /이메일|전화|주소/]
  },
  {
    category: "identity",
    patterns: [/\b(?:name|fullname|firstname|lastname|birth|dateofbirth|birthday|gender|age)\b/i, /이름|생년|성별|나이/]
  },
  {
    category: "account",
    patterns: [/\b(?:user|username|login|password|passwd|pwd|profile|account)\b(?!\s+number\b)/i, /아이디|비밀번호|계정|프로필/]
  },
  {
    category: "payment",
    patterns: [/\b(?:card|cardnumber|payment|billing|bank|account number|accountnumber)\b/i, /카드|결제|청구|계좌/]
  },
  {
    category: "location",
    patterns: [/\b(?:lat|latitude|lng|lon|longitude|location|geo|gps)\b/i, /위치|좌표/]
  },
  {
    category: "device",
    patterns: [/\b(?:ip|ipaddress|device|cookie|session|token|uuid|gaid|idfa)\b/i, /기기|쿠키|세션|토큰/]
  }
];

const POLICY_SECTION_RULES = [
  {
    id: "collected_data",
    label: "수집 항목",
    headingPatterns: [
      /collect(ed|ion)?|personal information we collect|information you provide/i,
      /수집.{0,100}항목|처리.{0,100}항목|개인정보.{0,100}수집|수집하는.{0,100}정보/
    ],
    contentPatterns: [/name|email|phone|address|payment|cookie|device|location/i, /이름|이메일|전화|주소|결제|쿠키|기기|위치/]
  },
  {
    id: "purpose",
    label: "수집 목적",
    headingPatterns: [/purpose|use of information|how we use/i, /수집.{0,100}목적|이용.{0,100}목적|처리.{0,100}목적/],
    contentPatterns: [/provide|service|account|support|advertis|analytics|marketing/i, /서비스|회원|본인확인|고객지원|광고|분석|마케팅/]
  },
  {
    id: "legal_basis",
    label: "처리 법적 근거",
    headingPatterns: [
      /legal basis|lawful basis|grounds for processing|basis for processing/i,
      /법적.{0,100}근거|처리.{0,100}근거|적법.{0,100}근거/
    ],
    contentPatterns: [
      /consent|contract|legal obligation|legitimate interest|public interest|vital interest/i,
      /동의|계약|법적 의무|정당한 이익|공익|생명.{0,100}이익/
    ]
  },
  {
    id: "retention",
    label: "보유 기간",
    headingPatterns: [/retention|retain|storage period|delete/i, /보유.{0,100}기간|이용.{0,100}기간|파기|삭제/],
    contentPatterns: [/retain|delete|erase|as long as|period|year|month/i, /보유|파기|삭제|기간|년|개월|목적.{0,100}달성/]
  },
  {
    id: "third_party",
    label: "제3자 제공",
    headingPatterns: [/third part(y|ies)|share|disclosure/i, /제3자|제삼자|제공|공유/],
    contentPatterns: [/third part(y|ies)|partner|affiliate|share|sell|transfer/i, /제3자|제삼자|제휴사|협력사|제공|공유|판매|이전/]
  },
  {
    id: "processors",
    label: "처리위탁",
    headingPatterns: [/processor|service provider|subprocessor|vendor/i, /처리위탁|수탁|위탁|수탁자/],
    contentPatterns: [/processor|provider|vendor|subprocessor|entrust/i, /처리위탁|수탁|위탁|대행|업체/]
  },
  {
    id: "overseas_transfer",
    label: "국외 이전",
    headingPatterns: [
      /international transfer|cross-border|outside/i,
      /국외.{0,100}이전|해외.{0,100}이전|국외.{0,100}보관|해외.{0,100}보관/
    ],
    contentPatterns: [/international|country|outside|cross-border/i, /국외|해외|이전.{0,100}국가|보관.{0,100}국가/]
  },
  {
    id: "automated_decision",
    label: "자동화 의사결정/프로파일링",
    headingPatterns: [/automated decision|profiling|profile/i, /자동화.{0,100}의사결정|프로파일링|프로파일/],
    contentPatterns: [/automated|profiling|logic involved|significant effect/i, /자동화|프로파일링|로직|중대한.{0,100}영향/]
  },
  {
    id: "cookies_tracking",
    label: "쿠키/행태정보",
    headingPatterns: [/cookie|tracking|advertis|analytics/i, /쿠키|행태정보|맞춤형.{0,100}광고|추적|광고|분석/],
    contentPatterns: [/cookie|tracking|pixel|advertis|analytics|opt out/i, /쿠키|행태정보|추적|광고|분석|거부|동의/]
  },
  {
    id: "user_rights",
    label: "이용자 권리",
    headingPatterns: [
      /your rights|access|deletion|withdraw|choice/i,
      /이용자.{0,100}권리|정보주체.{0,100}권리|열람|정정|삭제|동의.{0,100}철회|처리정지/
    ],
    contentPatterns: [/access|delete|correct|withdraw|opt out|request/i, /열람|정정|삭제|동의.{0,100}철회|처리정지|요청/]
  },
  {
    id: "security",
    label: "보안 조치",
    headingPatterns: [/security|safeguard|protect/i, /보안|보호.{0,100}조치|안전성.{0,100}확보|기술적.{0,100}관리적/],
    contentPatterns: [/encrypt|access control|security|breach|safeguard/i, /암호화|접근통제|보안|침해|보호조치/]
  },
  {
    id: "children",
    label: "아동/청소년",
    headingPatterns: [/children|minor|under 13|under 16/i, /아동|청소년|미성년자|만\s?14세/],
    contentPatterns: [/children|minor|parent|guardian|under/i, /아동|청소년|미성년자|법정대리인|보호자/]
  },
  {
    id: "dispute_liability",
    label: "분쟁/책임 제한",
    headingPatterns: [/dispute|arbitration|liability|disclaimer/i, /분쟁|중재|책임|면책|손해배상|관할/],
    contentPatterns: [/arbitration|liable|liability|dispute|class action/i, /중재|책임|면책|분쟁|손해|관할/]
  }
];

const JURISDICTIONS = {
  KR: {
    label: "한국",
    requiredSections: ["collected_data", "purpose", "retention", "third_party", "processors", "overseas_transfer", "user_rights", "security"]
  },
  US: {
    label: "미국",
    requiredSections: ["collected_data", "purpose", "retention", "third_party", "cookies_tracking", "user_rights", "security"]
  },
  GDPR: {
    label: "GDPR/EU",
    requiredSections: [
      "collected_data",
      "purpose",
      "legal_basis",
      "retention",
      "third_party",
      "overseas_transfer",
      "user_rights",
      "security"
    ]
  }
};

const EU_COUNTRY_CODES = new Set([
  "AT",
  "BE",
  "BG",
  "HR",
  "CY",
  "CZ",
  "DK",
  "EE",
  "FI",
  "FR",
  "DE",
  "GR",
  "HU",
  "IE",
  "IT",
  "LV",
  "LT",
  "LU",
  "MT",
  "NL",
  "PL",
  "PT",
  "RO",
  "SK",
  "SI",
  "ES",
  "SE",
  "IS",
  "LI",
  "NO"
]);

const US_TIME_ZONES = new Set([
  "america/adak",
  "america/anchorage",
  "america/boise",
  "america/chicago",
  "america/denver",
  "america/detroit",
  "america/juneau",
  "america/los_angeles",
  "america/menominee",
  "america/metlakatla",
  "america/new_york",
  "america/nome",
  "america/phoenix",
  "america/sitka",
  "america/yakutat",
  "pacific/honolulu"
]);

const EU_EEA_TIME_ZONES = new Set([
  "asia/nicosia",
  "atlantic/reykjavik",
  "europe/amsterdam",
  "europe/athens",
  "europe/berlin",
  "europe/bratislava",
  "europe/brussels",
  "europe/bucharest",
  "europe/budapest",
  "europe/copenhagen",
  "europe/dublin",
  "europe/helsinki",
  "europe/lisbon",
  "europe/ljubljana",
  "europe/luxembourg",
  "europe/madrid",
  "europe/malta",
  "europe/mariehamn",
  "europe/oslo",
  "europe/paris",
  "europe/prague",
  "europe/riga",
  "europe/rome",
  "europe/sofia",
  "europe/stockholm",
  "europe/tallinn",
  "europe/vaduz",
  "europe/vienna",
  "europe/vilnius",
  "europe/warsaw",
  "europe/zagreb"
]);

function isUsTimeZone(timeZone) {
  return (
    US_TIME_ZONES.has(timeZone) ||
    timeZone.startsWith("america/indiana/") ||
    timeZone.startsWith("america/kentucky/") ||
    timeZone.startsWith("america/north_dakota/")
  );
}

function isEuEeaTimeZone(timeZone) {
  return EU_EEA_TIME_ZONES.has(timeZone);
}

function boundedPolicyText(value) {
  return String(value || "").slice(0, MAX_POLICY_ANALYSIS_CHARS);
}

function chunkAnalysisSentence(sentence) {
  if (sentence.length <= MAX_ANALYSIS_SENTENCE_CHARS) return [sentence];

  const chunks = [];
  const step = MAX_ANALYSIS_SENTENCE_CHARS - ANALYSIS_SENTENCE_OVERLAP_CHARS;
  for (let offset = 0; offset < sentence.length; offset += step) {
    chunks.push(sentence.slice(offset, offset + MAX_ANALYSIS_SENTENCE_CHARS));
    if (offset + MAX_ANALYSIS_SENTENCE_CHARS >= sentence.length) break;
  }
  return chunks;
}

function getSentences(text) {
  return boundedPolicyText(text)
    .replace(/\r/g, "")
    .split(/\n{2,}/)
    .flatMap((paragraph) =>
      paragraph
        .replace(/\n+/g, " ")
        .replace(/[ \t]+/g, " ")
        .split(/(?<=[.!?。！？])\s+|(?<=다\.)\s+|(?<=요\.)\s+/)
    )
    .map((sentence) => sentence.trim())
    .flatMap(chunkAnalysisSentence)
    .filter(Boolean);
}

function includesAny(text, patterns) {
  return patterns.some((pattern) => pattern.test(text));
}

function normalizedRequestHost(request) {
  const explicitHost = String(request?.host || "")
    .trim()
    .toLowerCase()
    .replace(/^\.+|\.+$/g, "");
  if (explicitHost) return explicitHost;

  try {
    return new URL(String(request?.url || "")).hostname.toLowerCase().replace(/\.$/, "");
  } catch {
    return "";
  }
}

function requestPathTokens(request) {
  let path = "";
  try {
    path = new URL(String(request?.url || "")).pathname;
  } catch {
    path = String(request?.url || "");
  }
  return path
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter(Boolean);
}

function isTrackerRequest(request) {
  const host = normalizedRequestHost(request);
  if (KNOWN_TRACKER_DOMAINS.some((domain) => host === domain || host.endsWith(`.${domain}`))) return true;
  if (host.split(".").some((label) => GENERIC_TRACKER_TOKENS.has(label))) return true;
  return requestPathTokens(request).some((token) => GENERIC_TRACKER_TOKENS.has(token));
}

function isTrackingCookieName(value) {
  const name = String(value || "").toLowerCase();
  return /^(?:_?ga(?:_[a-z0-9_-]{1,128})?|_?gid|_?gat(?:_[a-z0-9_-]{1,128})?|_?gac(?:_[a-z0-9_-]{1,128})?|_?fbp|_?fbc|_?gcl(?:_[a-z0-9_-]{1,128})?|__utm[a-z]+|amp_token|ajs(?:_[a-z0-9_-]{1,128})?|amplitude(?:_[a-z0-9_-]{1,128})?|mixpanel(?:_[a-z0-9_-]{1,128})?|mp_[a-z0-9_-]{1,128}_mixpanel|visitor(?:_[a-z0-9_-]{1,128})?|track(?:er|ing)?(?:_[a-z0-9_-]{1,128})?)$/.test(
    name
  );
}

function normalizeMatchTokens(value) {
  return String(value || "")
    .normalize("NFKC")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .replace(/[^a-z0-9가-힣]+/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function includesDataExample(normalizedText, example) {
  const normalizedExample = normalizeMatchTokens(example);
  if (!normalizedExample) return false;
  if (/[가-힣]/.test(normalizedExample)) return normalizedText.includes(normalizedExample);

  const searchableText = normalizedExample === "address"
    ? normalizedText.replace(/\bip address(?:es)?\b/g, "")
    : normalizedText;
  const words = normalizedExample.split(" ");
  const lastWord = words.at(-1);
  const pluralLastWord = /[^aeiou]y$/.test(lastWord)
    ? `${lastWord.slice(0, -1)}ies`
    : /(?:s|x|z|ch|sh)$/.test(lastWord)
      ? `${lastWord}es`
      : `${lastWord}s`;
  const pluralExample = [...words.slice(0, -1), pluralLastWord].join(" ");
  const paddedText = ` ${searchableText} `;
  return paddedText.includes(` ${normalizedExample} `) || paddedText.includes(` ${pluralExample} `);
}

function matchesSensitiveValue(value, patterns) {
  const normalized = normalizeMatchTokens(value);
  return Boolean(normalized && patterns.some((pattern) => pattern.test(normalized)));
}

const BROAD_SHARING_TARGET_PATTERN = /\bthird[- ]part(?:y|ies)\b|\b(?:business )?partners?\b|\baffiliates?\b|제3자|제삼자|협력사|제휴사|외부\s*사업자/i;
const BROAD_SHARING_ACTION_PATTERN = /\b(?:share|sell|transfer|disclos(?:e|es|ed|ing))\b|공유|판매|이전/i;
const DATA_PROVISION_PATTERN = /\bprovid(?:e|es|ed|ing)\b.{0,80}\b(?:personal\s+)?(?:data|information)\b|\b(?:personal\s+)?(?:data|information)\b.{0,80}\bprovid(?:e|es|ed|ing)\b|(?:개인정보|개인\s*정보|데이터|수집\s*정보).{0,80}제공|제공.{0,80}(?:개인정보|개인\s*정보|데이터|수집\s*정보)/i;
const CHILD_REFERENCE_PATTERN = /\bchildren?\b|\bminors?\b|\bunder\s+(?:13|14|16)\b|아동|청소년|미성년자|만\s*(?:13|14|16)세/i;
const CHILD_DATA_ACTION_PATTERN = /\b(?:collect|process|use|share|sell|transfer|store|retain)\b|수집|처리|이용|사용|공유|판매|이전|보유|저장/i;

function splitRiskClauses(sentence) {
  const coordinatedPredicates = sentence
    .replace(
      /\b(?:and|while|whereas)\s+(?=(?:(?:we|you|they|the (?:company|service)|our (?:company|service))\b|(?:may|might|can|could|will|would|shall)\b))/gi,
      "; "
    )
    .replace(/((?:않|아니)(?:으며|지만|으나|고))\s*/g, "$1; ");

  return coordinatedPredicates
    .split(/\s*(?:;|\bbut\b|\bhowever\b|\bexcept that\b|하지만|그러나|다만)\s*/i)
    .map((clause) => clause.trim())
    .filter(Boolean);
}

function hasNegatedDataAction(clause) {
  return (
    /\b(?:do|does|did|will|would|shall|may|might|can|could)\s+not\b[^.;]{0,60}\b(?:collect|process|use|share|sell|transfer|disclose|provide|store|retain)\b/i.test(clause) ||
    /\b(?:don't|doesn't|didn't|won't|wouldn't|can't|cannot|never)\b[^.;]{0,60}\b(?:collect|process|use|share|sell|transfer|disclose|provide|store|retain)\b/i.test(clause) ||
    /\b(?:is|are|be|been|will be)\s+not\s+(?:collected|processed|used|shared|sold|transferred|disclosed|provided|stored|retained)\b/i.test(clause) ||
    /\b(?:collect|process|use|share|sell|transfer|disclose|provide|store|retain)s?\s+no\b/i.test(clause) ||
    /\bno\s+(?:sale|sharing|transfer|disclosure|collection|processing)\b/i.test(clause) ||
    /(?:수집|처리|이용|사용|공유|판매|이전|제공|보유|저장)(?:하|되)?지\s*(?:않|아니)/.test(clause) ||
    /(?:수집|처리|이용|사용|공유|판매|이전|제공|보유|저장)하지\s*(?:않|아니)/.test(clause) ||
    /(?:수집|처리|이용|사용|공유|판매|이전|제공|보유|저장)\s*(?:없|금지)/.test(clause)
  );
}

function matchesBroadSharingSentence(sentence) {
  return splitRiskClauses(sentence).some((clause) => {
    if (!BROAD_SHARING_TARGET_PATTERN.test(clause) || hasNegatedDataAction(clause)) return false;
    return BROAD_SHARING_ACTION_PATTERN.test(clause) || DATA_PROVISION_PATTERN.test(clause);
  });
}

function matchesChildrenRiskSentence(sentence) {
  return splitRiskClauses(sentence).some(
    (clause) => CHILD_REFERENCE_PATTERN.test(clause) && CHILD_DATA_ACTION_PATTERN.test(clause) && !hasNegatedDataAction(clause)
  );
}

function hasNegatedAdvertisingAction(clause) {
  return (
    hasNegatedDataAction(clause) ||
    /\b(?:do|does|did|will|would|shall|may|might|can|could)\s+not\b[^.;]{0,80}\b(?:serve|show|deliver|target|track|profile|advertis)/i.test(
      clause
    ) ||
    /\b(?:don't|doesn't|didn't|won't|wouldn't|can't|cannot|never)\b[^.;]{0,80}\b(?:serve|show|deliver|target|track|profile|advertis)/i.test(
      clause
    ) ||
    /\b(?:never|without)\b[^.;]{0,80}\b(?:targeting|tracking|profiling|advertising)\b/i.test(clause) ||
    /(?:맞춤형\s*광고|타겟팅|리타겟팅|행태정보|추적)(?:을|를)?\s*(?:사용|제공|수행|활용)?(?:하|되)?지\s*(?:않|아니)/.test(
      clause
    )
  );
}

function matchesBehavioralAdsSentence(sentence, rule) {
  return splitRiskClauses(sentence).some(
    (clause) => includesAny(clause, rule.patterns) && !hasNegatedAdvertisingAction(clause)
  );
}

function matchesAccountTerminationSentence(sentence, rule) {
  return splitRiskClauses(sentence).some((clause) => {
    const negatedTermination =
      /\b(?:do|does|did|will|would|shall|may|might|can|could)\s+not\b[^.;]{0,80}\b(?:terminate|suspend|disable|restrict|close)\b/i.test(
        clause
      ) ||
      /\b(?:don't|doesn't|didn't|won't|wouldn't|can't|cannot|never)\b[^.;]{0,80}\b(?:terminate|suspend|disable|restrict|close)\b/i.test(
        clause
      ) ||
      /\b(?:account|access|service)\b[^.;]{0,50}\b(?:will|may|can)?\s*not\s+be\s*(?:terminated|suspended|disabled|restricted|closed)\b/i.test(
        clause
      ) ||
      /(?:해지|정지|제한|중단|종료)(?:하|되)?지\s*(?:않|아니)/.test(clause);
    if (!includesAny(clause, rule.patterns) || hasNegatedDataAction(clause) || negatedTermination) return false;

    const providerInitiated =
      /\b(?:we|the (?:company|service|provider|operator)|our (?:company|service))\b[^.;]{0,80}\b(?:terminate|suspend|disable|restrict|close)\b/i.test(
        clause
      ) ||
      /\b(?:your\s+)?(?:account|access|service)\b[^.;]{0,50}\b(?:may|can|will)?\s*be\s*(?:terminated|suspended|disabled|restricted|closed)\b/i.test(
        clause
      ) ||
      /(?:회사|운영자|사업자)(?:는|가|은|이)?.{0,80}(?:계정|서비스|이용).{0,40}(?:해지|정지|제한|중단)|서비스(?:는|가|에서).{0,80}(?:계정|이용).{0,40}(?:해지|정지|제한|중단)/.test(
        clause
      );
    if (providerInitiated) return true;

    const userInitiated =
      /\b(?:you|users?|customers?|members?)\b(?:(?!\b(?:we|the (?:company|service|provider|operator)|our (?:company|service))\b)[^.;]){0,60}\b(?:may|can|could|are (?:free|entitled) to)?\s*(?:terminate|close|delete|cancel)\b/i.test(
        clause
      ) ||
      /(?:이용자|사용자|회원|고객)(?:(?!(?:회사|운영자|사업자|서비스(?:는|가|에서))).){0,60}(?:계정|서비스|이용)?.{0,30}(?:탈퇴|해지|삭제|종료)(?:할\s*수|가능)/.test(
        clause
      );
    if (userInitiated) return false;
    return false;
  });
}

function matchesPolicyChangeSentence(sentence, rule) {
  return splitRiskClauses(sentence).some((clause) => {
    if (!includesAny(clause, rule.patterns)) return false;
    return !(
      /\b(?:do|does|did|will|would|shall|may|might|can|could)\s+not\b[^.;]{0,80}\b(?:change|modify|update|revise)\b/i.test(
        clause
      ) ||
      /\b(?:never|won't|wouldn't|cannot|can't)\b[^.;]{0,80}\b(?:change|modify|update|revise)\b/i.test(clause) ||
      /(?:약관|정책)(?:을|를)?[^.;]{0,40}(?:변경|개정)(?:하|되)?지\s*(?:않|아니)/.test(clause)
    );
  });
}

function matchesRetentionRiskSentence(sentence, rule) {
  return splitRiskClauses(sentence).some((clause) => {
    if (!includesAny(clause, rule.patterns) || hasNegatedDataAction(clause)) return false;
    const explicitDuration =
      /\b\d+\s*(?:business\s+)?(?:days?|weeks?|months?|years?)\b/i.test(clause) ||
      /\d+\s*(?:일|주|개월|달|년)/.test(clause);
    return !explicitDuration;
  });
}

function matchesOverseasTransferSentence(sentence, rule) {
  return splitRiskClauses(sentence).some(
    (clause) => includesAny(clause, rule.patterns) && !hasNegatedDataAction(clause)
  );
}

function matchesArbitrationSentence(sentence, rule) {
  return splitRiskClauses(sentence).some((clause) => {
    if (!includesAny(clause, rule.patterns)) return false;
    return !(
      /\b(?:do|does|did|will|would|shall|may|might|can|could)\s+not\b[^.;]{0,80}\b(?:require|impose|use|enforce)\b[^.;]{0,40}\barbitration\b/i.test(
        clause
      ) ||
      /\b(?:no|without)\s+(?:mandatory|binding)\s+arbitration\b/i.test(clause) ||
      /\barbitration\b[^.;]{0,50}\b(?:is|will be)\s+not\s+(?:mandatory|required|binding)\b/i.test(clause) ||
      /(?:중재|집단소송\s*포기|전속\s*관할)(?:를|을)?[^.;]{0,50}(?:요구|강제|적용|지정)(?:하|되)?지\s*(?:않|아니)/.test(
        clause
      )
    );
  });
}

const CONCRETE_SECURITY_CONTROL_PATTERN =
  /encrypt|encryption|access control|multi-factor|two-factor|penetration test|security audit|breach notification|암호화|접근통제|다중\s*인증|이중\s*인증|침투\s*테스트|보안\s*감사|침해.{0,12}통지/i;

function contextualRiskSentenceMatcher(rule) {
  if (rule.id === "broad_data_sharing") return matchesBroadSharingSentence;
  if (rule.id === "children") return matchesChildrenRiskSentence;
  if (rule.id === "behavioral_ads") return (sentence) => matchesBehavioralAdsSentence(sentence, rule);
  if (rule.id === "account_termination") return (sentence) => matchesAccountTerminationSentence(sentence, rule);
  if (rule.id === "policy_change") return (sentence) => matchesPolicyChangeSentence(sentence, rule);
  if (rule.id === "retention_unclear") return (sentence) => matchesRetentionRiskSentence(sentence, rule);
  if (rule.id === "overseas_transfer") return (sentence) => matchesOverseasTransferSentence(sentence, rule);
  if (rule.id === "arbitration") return (sentence) => matchesArbitrationSentence(sentence, rule);
  return null;
}

function matchesRiskRule(rule, text, sentences) {
  if (rule.id === "security_vague") {
    return includesAny(text, rule.patterns) && !CONCRETE_SECURITY_CONTROL_PATTERN.test(text);
  }
  const matcher = contextualRiskSentenceMatcher(rule);
  if (matcher) return sentences.some(matcher);
  return includesAny(text, rule.patterns);
}

function getRiskEvidence(rule, sentences) {
  if (rule.id === "security_vague") {
    const hit = sentences.find((sentence) => includesAny(sentence, rule.patterns));
    return hit ? truncateText(hit, 220) : "";
  }
  const matcher = contextualRiskSentenceMatcher(rule);
  const hit = matcher
    ? sentences.find(matcher)
    : sentences.find((sentence) => includesAny(sentence, rule.patterns));
  return hit ? truncateText(hit, 220) : "";
}

function assessPolicyText(text, sentences) {
  const normalized = text.toLowerCase();
  const explicitPolicyMarker = /privacy policy|privacy notice|cookie policy|terms (?:of use|of service|and conditions)|user agreement|data protection notice|개인정보\s*처리방침|개인정보\s*보호정책|이용약관|서비스\s*약관/.test(normalized);
  const dataPractice = sentences.some(
    (sentence) =>
      (/\b(?:collect(?:s|ed|ing)?|process(?:es|ed|ing)?|use[sd]?|using|share[sd]?|sharing|sell(?:s|ing)?|sold|retain(?:s|ed|ing)?|store[sd]?|storing|delete[sd]?|deleting)\b/i.test(sentence) &&
        /\b(?:personal (?:data|information)|information|data|name|email|phone|cookie|location|payment)\b/i.test(sentence)) ||
      (/(?:개인정보|개인\s*정보|아동.{0,12}정보|이름|이메일|전화번호|쿠키|위치|결제\s*정보)/.test(sentence) &&
        /(?:수집|처리|이용|사용|제공|공유|판매|보유|저장|파기|삭제)/.test(sentence))
  );
  const rightsOrRetention = /right to (?:access|delete|erasure)|withdraw consent|retention period|retain for|data subject|정보주체|동의\s*철회|열람|정정|보유\s*기간|파기/.test(
    normalized
  );
  const termsClause = /binding arbitration|class action waiver|limitation of liability|governing law|terminate (?:your )?account|agree to (?:these|the) terms|agree to be bound|acceptable use|intellectual property|중재|집단소송|책임\s*제한|면책|준거법|관할\s*법원|계정.{0,120}(?:해지|정지)|약관에\s*동의|금지\s*행위|지식재산권/.test(
    normalized
  );
  const score = Math.min(
    1,
    // A footer link or title alone is not enough evidence that the supplied
    // body is itself a policy document.
    (explicitPolicyMarker ? 0.35 : 0) + (dataPractice ? 0.5 : 0) + (rightsOrRetention ? 0.25 : 0) + (termsClause ? 0.5 : 0)
  );

  return {
    score,
    likely: score >= 0.5
  };
}

function findDataCategories(text) {
  const normalized = normalizeMatchTokens(text);
  return DATA_CATEGORIES.filter((category) =>
    category.examples.some((example) => includesDataExample(normalized, example))
  ).map((category) => ({
    id: category.id,
    label: dataCategoryLabel(category.id),
    matched: category.examples.filter((example) => includesDataExample(normalized, example)).slice(0, 4)
  }));
}

function scoreRisks(risks, dataCategories) {
  const severityScore = risks.reduce((score, risk) => {
    if (risk.severity === "high") return score + 20;
    if (risk.severity === "medium") return score + 10;
    return score + 4;
  }, 0);
  const dataScore = Math.min(dataCategories.length * 4, 24);
  return Math.min(100, severityScore + dataScore);
}

function riskLevel(score, risks = []) {
  const highRiskCount = risks.filter((risk) => risk.severity === "high").length;
  if (score >= 60) return "high";
  if (highRiskCount >= 2) return "high";
  if (score >= 35) return "medium";
  if (highRiskCount > 0) return "medium";
  return "low";
}

export function analyzePolicy(inputText) {
  const text = boundedPolicyText(inputText).trim();
  if (!text) {
    return {
      ok: false,
      status: "empty",
      level: "unknown",
      message: tA("finding.noPolicyText")
    };
  }

  const sentences = getSentences(text);
  const policyAssessment = assessPolicyText(text, sentences);
  if (!policyAssessment.likely) {
    const message = tA("finding.notPolicyText");
    return {
      ok: false,
      status: "not_policy",
      message,
      wordCount: text.split(/\s+/).filter(Boolean).length,
      score: null,
      level: "unknown",
      levelLabel: riskLevelLabel("unknown"),
      policyConfidence: policyAssessment.score,
      dataCategories: [],
      risks: [],
      positives: [],
      policySections: [],
      summary: message
    };
  }

  const policySections = extractPolicySections(text);
  const dataCategories = findDataCategories(text);
  const risks = RISK_RULES.filter((rule) => matchesRiskRule(rule, text, sentences)).map((rule) => ({
    id: rule.id,
    severity: rule.severity,
    title: riskRuleLabel(rule.id),
    advice: riskRuleAdvice(rule.id),
    evidence: getRiskEvidence(rule, sentences)
  }));
  const positives = POSITIVE_RULES.filter((rule) => includesAny(text, rule.patterns)).map((rule) => positiveRuleLabel(rule.id));
  const score = scoreRisks(risks, dataCategories);
  const level = riskLevel(score, risks);
  const overallSeverity = risks.reduce(
    (highest, risk) => (riskRank(risk.severity) > riskRank(highest) ? risk.severity : highest),
    "low"
  );

  return {
    ok: true,
    status: "analyzed",
    wordCount: text.split(/\s+/).filter(Boolean).length,
    score,
    level,
    levelLabel: riskLevelLabel(level),
    policyConfidence: policyAssessment.score,
    overallSeverity,
    dataCategories,
    risks: risks.sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 };
      return order[a.severity] - order[b.severity];
    }),
    positives,
    policySections,
    summary: buildSummary(level, dataCategories, risks, positives)
  };
}

export function extractPolicySections(inputText) {
  const text = boundedPolicyText(inputText).trim();
  if (!text) return [];

  const blocks = splitPolicyBlocks(text);
  return POLICY_SECTION_RULES.map((rule) => {
    const matches = blocks
      .map((block, index) => ({
        index,
        title: inferBlockTitle(block),
        text: block,
        score: scorePolicyBlock(block, rule)
      }))
      .filter((block) => block.score > 0)
      .sort((a, b) => b.score - a.score)
      .slice(0, 3)
      .map((block) => ({
        title: block.title || policySectionLabel(rule.id),
        excerpt: truncateText(block.text, 260)
      }));

    return {
      id: rule.id,
      label: policySectionLabel(rule.id),
      found: matches.length > 0,
      evidence: matches
    };
  });
}

export function analyzeNetworkActivity(policyText, requests, pageUrl, customVendorRules = []) {
  const normalizedRequests = Array.isArray(requests) ? requests : [];
  const pageHost = hostFromUrl(pageUrl);
  const safePolicyText = boundedPolicyText(policyText);
  const policy = safePolicyText.toLowerCase();
  const policyDomains = extractPolicyDomains(safePolicyText);
  const policySections = extractPolicySections(safePolicyText);
  const disclosedCategories = findDataCategories(sectionText(policySections, ["collected_data"]) || safePolicyText).map((category) => category.id);

  const uniqueHosts = uniqueBy(normalizedRequests.filter((request) => request.host), (request) => request.host);
  const thirdPartyRequests = uniqueHosts.filter((request) => isThirdPartyHost(pageHost, request.host));
  const thirdPartyRequestDetails = normalizedRequests.filter(
    (request) => request.host && isThirdPartyHost(pageHost, request.host)
  );
  const vendorSummary = classifyVendorRequests(
    preferredVendorRequests(thirdPartyRequestDetails, customVendorRules),
    policySections,
    customVendorRules
  );
  const trackerRequests = uniqueBy(
    normalizedRequests.filter((request) => request.host && isTrackerRequest(request)),
    (request) => request.host
  );
  const postedRequests = normalizedRequests.filter((request) => request.method === "POST" || request.method === "PUT" || request.method === "PATCH");
  const insecureRequests = uniqueBy(
    normalizedRequests.filter((request) => request.host && String(request.url || "").startsWith("http://")),
    (request) => request.host
  );
  const sensitiveFields = detectSensitiveFields(normalizedRequests);

  const findings = [];
  const undisclosedThirdParties = thirdPartyRequests
    .filter((request) => !isHostDisclosed(request.host, policyDomains, policy, customVendorRules))
    .slice(0, 8);

  if (undisclosedThirdParties.length > 0) {
    findings.push({
      id: "undisclosed_third_parties",
      severity: "high",
      title: sectionFindingTitle("undisclosed_third_parties_title"),
      detail: tA("findingTemplates.undisclosedThirdParties", [undisclosedThirdParties.map((request) => request.host).join(", ")]),
      advice: sectionFindingAdvice("undisclosed_third_parties")
    });
  }

  const vendorPolicyGaps = vendorSummary.filter((vendor) => vendor.missingPolicySections.length > 0 && vendor.category !== "cdn_security");
  if (vendorPolicyGaps.length > 0) {
    findings.push({
      id: "vendor_policy_section_gap",
      severity: vendorPolicyGaps.some((vendor) => ["advertising", "analytics", "payment"].includes(vendor.category)) ? "high" : "medium",
      title: sectionFindingTitle("vendor_policy_section_gap_title"),
      detail: vendorPolicyGaps
        .slice(0, 6)
        .map((vendor) => `${vendor.vendor}(${consentCategoryLabel(vendor.category)}): ${vendor.missingPolicySections.map(policySectionLabel).join(", ")}`)
        .join(" / "),
      advice: sectionFindingAdvice("vendor_policy_section_gap")
    });
  }

  if (trackerRequests.length > 0 && !hasPolicySection(policySections, "cookies_tracking") && !mentionsAdvertisingOrAnalytics(policy)) {
    findings.push({
      id: "tracker_without_disclosure",
      severity: "high",
      title: sectionFindingTitle("tracker_without_disclosure_title"),
      detail: tA("findingTemplates.trackerWithoutDisclosure", [trackerRequests.slice(0, 8).map((request) => request.host).join(", ")]),
      advice: sectionFindingAdvice("tracker_without_disclosure")
    });
  }

  const undisclosedFields = sensitiveFields.filter((field) => !disclosedCategories.includes(field.category));
  if (undisclosedFields.length > 0) {
    findings.push({
      id: "sensitive_fields_without_category",
      severity: "medium",
      title: sectionFindingTitle("sensitive_fields_without_category_title"),
      detail: tA("findingTemplates.sensitiveFieldsWithoutCategory", [
        `${undisclosedFields.map((field) => `${field.label}: ${field.keys.join(", ")}`).join(" / ")}`
      ]),
      advice: sectionFindingAdvice("sensitive_fields_without_category")
    });
  }

  const thirdPartyPosts = postedRequests.filter((request) => isThirdPartyHost(pageHost, request.host));
  if (thirdPartyPosts.length > 0) {
    findings.push({
      id: "third_party_post",
      severity: "medium",
      title: sectionFindingTitle("third_party_post_title"),
      detail: tA("findingTemplates.thirdPartyPost", [
        uniqueBy(thirdPartyPosts.filter((request) => request.host), (request) => request.host)
          .slice(0, 8)
          .map((request) => request.host)
          .join(", ")
      ]),
      advice: sectionFindingAdvice("third_party_post")
    });
  }

  if (insecureRequests.length > 0) {
    findings.push({
      id: "insecure_http",
      severity: "high",
      title: sectionFindingTitle("insecure_http_title"),
      detail: tA("findingTemplates.insecureHttp", [`${insecureRequests.slice(0, 6).map((request) => request.host).join(", ")}`]),
      advice: sectionFindingAdvice("insecure_http")
    });
  }

  return {
    requestCount: normalizedRequests.length,
    thirdPartyHosts: thirdPartyRequests.map((request) => request.host),
    trackerHosts: trackerRequests.map((request) => request.host),
    vendorSummary,
    sensitiveFields,
    findings: findings.sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 };
      return order[a.severity] - order[b.severity];
    })
  };
}

export function analyzeFormFields(policyText, fields) {
  const normalizedFields = Array.isArray(fields) ? fields : [];
  const safePolicyText = boundedPolicyText(policyText);
  const policySections = extractPolicySections(safePolicyText);
  const disclosedCategories = findDataCategories(sectionText(policySections, ["collected_data"]) || safePolicyText).map((category) => category.id);
  const classifiedFields = normalizedFields
    .map((field) => ({
      ...field,
      descriptor: getFieldDescriptor(field),
      category: classifyField(field)
    }))
    .filter((field) => field.category);
  const categories = SENSITIVE_FIELD_RULES.map((rule) => {
    const matches = classifiedFields.filter((field) => field.category === rule.category);
    return {
      id: rule.category,
      label: sensitiveFieldLabel(rule.category),
      fields: matches.map((field) => ({
        name: field.name || field.id || field.autocomplete || field.placeholder || field.label || field.type,
        descriptor: field.descriptor,
        required: field.required
      }))
    };
  }).filter((category) => category.fields.length > 0);

  const undisclosed = categories.filter((category) => !disclosedCategories.includes(category.id));
  const findings = [];

  if (undisclosed.length > 0) {
    findings.push({
      id: "form_fields_without_policy_category",
      severity: "high",
      title: sectionFindingTitle("form_fields_without_policy_category_title"),
      detail: undisclosed
        .map((category) => `${category.label}: ${category.fields.slice(0, 5).map((field) => field.name).join(", ")}`)
        .join(" / "),
      advice: sectionFindingAdvice("form_fields_without_policy_category")
    });
  }

  const sensitiveRequired = categories
    .flatMap((category) => category.fields.map((field) => ({ ...field, label: category.label })))
    .filter((field) => field.required);
  if (sensitiveRequired.length >= 4) {
    findings.push({
      id: "many_required_sensitive_fields",
      severity: "medium",
      title: sectionFindingTitle("many_required_sensitive_fields_title"),
      detail: tA("findingTemplates.sensitiveFieldsWithoutCategory", [
        `${sensitiveRequired.slice(0, 8).map((field) => `${field.label}: ${field.name}`).join(", ")}`
      ]),
      advice: sectionFindingAdvice("many_required_sensitive_fields")
    });
  }

  return {
    fieldCount: normalizedFields.length,
    sensitiveFieldCount: classifiedFields.length,
    categories,
    findings
  };
}

export function analyzeClientStorage(policyText, storage = {}, cookies = [], pageUrl = "") {
  const safePolicyText = boundedPolicyText(policyText);
  const policy = safePolicyText.toLowerCase();
  const policySections = extractPolicySections(safePolicyText);
  const pageHost = hostFromUrl(pageUrl);
  const storageKeys = [...(storage.localStorageKeys || []), ...(storage.sessionStorageKeys || [])];
  const classifiedStorage = classifyKeys(storageKeys);
  const activeCookies = (Array.isArray(cookies) ? cookies : []).filter((cookie) => !cookie.removed);
  const thirdPartyCookies = activeCookies.filter((cookie) => {
    const domain = (cookie.domain || "").replace(/^\./, "");
    return pageHost && domain && isThirdPartyHost(pageHost, domain);
  });
  const trackingCookies = activeCookies.filter((cookie) => isTrackingCookieName(cookie.name));
  const weakCookies = activeCookies.filter((cookie) => !cookie.secure || cookie.sameSite === "no_restriction");
  const findings = [];

  if (classifiedStorage.length > 0 && !hasPolicySection(policySections, "cookies_tracking") && !mentionsClientStorage(policy)) {
    findings.push({
      id: "storage_without_disclosure",
      severity: "medium",
      title: sectionFindingTitle("storage_without_disclosure_title"),
      detail: tA("findingTemplates.storageWithoutDisclosure", [
        `${classifiedStorage.map((item) => `${item.label}: ${item.keys.join(", ")}`).join(" / ")}`
      ]),
      advice: sectionFindingAdvice("storage_without_disclosure")
    });
  }

  if (trackingCookies.length > 0 && !hasPolicySection(policySections, "cookies_tracking") && !mentionsAdvertisingOrAnalytics(policy)) {
    findings.push({
      id: "tracking_cookie_without_disclosure",
      severity: "high",
      title: sectionFindingTitle("tracking_cookie_without_disclosure_title"),
      detail: tA("findingTemplates.trackingCookiesWithoutDisclosure", [
        `${trackingCookies.slice(0, 8).map((cookie) => `${cookie.name} (${cookie.domain})`).join(", ")}`
      ]),
      advice: sectionFindingAdvice("tracking_cookie_without_disclosure")
    });
  }

  if (thirdPartyCookies.length > 0 && !/third parties?|제3자|처리위탁|수탁|광고|분석/.test(policy)) {
    findings.push({
      id: "third_party_cookie_without_disclosure",
      severity: "medium",
      title: sectionFindingTitle("third_party_cookie_without_disclosure_title"),
      detail: tA("findingTemplates.thirdPartyCookiesWithoutDisclosure", [
        `${thirdPartyCookies.slice(0, 8).map((cookie) => `${cookie.name} (${cookie.domain})`).join(", ")}`
      ]),
      advice: sectionFindingAdvice("third_party_cookie_without_disclosure")
    });
  }

  if (weakCookies.length > 0) {
    findings.push({
      id: "weak_cookie_security",
      severity: "medium",
      title: sectionFindingTitle("weak_cookie_security_title"),
      detail: tA("findingTemplates.weakCookieSecurity", [`${weakCookies.slice(0, 8).map((cookie) => cookie.name).join(", ")}`]),
      advice: sectionFindingAdvice("weak_cookie_security")
    });
  }

  return {
    localStorageKeyCount: storage.localStorageKeys?.length || 0,
    sessionStorageKeyCount: storage.sessionStorageKeys?.length || 0,
    cookieCount: activeCookies.length,
    thirdPartyCookieCount: thirdPartyCookies.length,
    classifiedStorage,
    findings: findings.sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 };
      return order[a.severity] - order[b.severity];
    })
  };
}

export function analyzeConsentCompliance(consent = {}, requests = [], cookies = []) {
  const containers = Array.isArray(consent.containers)
    ? consent.containers.slice(0, 8).filter((container) => container && typeof container === "object")
    : [];
  const consentDetected = Boolean(consent.detected || containers.length > 0 || consent.detectedAt);
  const visibleChoiceKinds = containers
    .flatMap((container) => (Array.isArray(container.buttons) ? container.buttons.slice(0, 32) : []))
    .map(classifyConsentChoice);
  const rejectAvailable = visibleChoiceKinds.includes("necessary_only");
  const acceptAvailable = visibleChoiceKinds.includes("accept_all");
  const preferenceAvailable = visibleChoiceKinds.some((kind) => ["preferences", "save_choices"].includes(kind));
  const trackingRequests = (Array.isArray(requests) ? requests : []).filter(isTrackerRequest);
  const trackingCookies = (Array.isArray(cookies) ? cookies : []).filter(
    (cookie) =>
      isTrackingCookieName(cookie.name) &&
      (!cookie.removed || Boolean(causallyTrustedCookieSetTimestamps(cookie)))
  );
  const timeline = resolveConsentTimeline(consent);
  const requestTiming = classifyEventsAroundBoundary(trackingRequests, timeline);
  const cookieTiming = classifyCookieEvidenceAroundBoundary(trackingCookies, timeline);
  const observedTrackingRequests = [...requestTiming.before, ...requestTiming.after, ...requestTiming.unknown];
  const observedTrackingCookies = cookieTiming.observed;
  const potentiallyPreChoiceRequests = timeline.boundaryAt
    ? requestTiming.before
    : observedTrackingRequests;
  const potentiallyPreChoiceCookies = timeline.boundaryAt
    ? cookieTiming.before
    : observedTrackingCookies;
  const consentCategories = detectConsentCategories(containers);
  const choiceAnalyses = buildConsentChoiceAnalyses(
    containers,
    consentCategories,
    potentiallyPreChoiceRequests,
    potentiallyPreChoiceCookies
  );
  const choiceToggles = Array.isArray(consent.choice?.toggles) ? consent.choice.toggles.slice(0, 40) : [];
  const disabledTrackingToggles = uniqueBy(
    [...containers.flatMap((container) => (Array.isArray(container.toggles) ? container.toggles.slice(0, 40) : [])), ...choiceToggles].filter((toggle) => {
      if (!toggle || typeof toggle !== "object") return false;
      const descriptor = `${toggle.label || ""} ${toggle.name || ""} ${toggle.id || ""}`.toLowerCase();
      return !toggle.checked && /analytics|advertising|ads|marketing|tracking|광고|분석|마케팅|추적/.test(descriptor);
    }),
    (toggle) => `${toggle.label || ""}:${toggle.name || ""}:${toggle.id || ""}`.toLowerCase()
  );
  const findings = [];

  if ((observedTrackingRequests.length > 0 || observedTrackingCookies.length > 0) && !consentDetected) {
    findings.push({
      id: "tracking_without_visible_consent",
      severity: timeline.observationStartedAt ? "high" : "medium",
      confidence: timeline.observationStartedAt ? "medium" : "low",
      title: sectionFindingTitle("tracking_without_visible_consent_title"),
      detail: tA("findingTemplates.trackingWithoutVisibleConsent", [observedTrackingRequests.length, observedTrackingCookies.length]),
      advice: sectionFindingAdvice("tracking_without_visible_consent")
    });
  }

  const definitePreChoiceCount = requestTiming.before.length + cookieTiming.before.length;
  const unknownTimingCount = requestTiming.unknown.length + cookieTiming.unknown.length;
  const trackingObserved = observedTrackingRequests.length > 0 || observedTrackingCookies.length > 0;

  if (consentDetected && timeline.boundaryAt && definitePreChoiceCount > 0) {
    findings.push({
      id: "tracking_before_clear_choice",
      severity: "high",
      title: sectionFindingTitle("tracking_before_clear_choice_title"),
      detail: tA("findingTemplates.trackingBeforeClearChoice", [requestTiming.before.length, cookieTiming.before.length]),
      advice: sectionFindingAdvice("tracking_before_clear_choice")
    });
  } else if (consentDetected && trackingObserved && (!timeline.boundaryAt || unknownTimingCount > 0)) {
    findings.push({
      id: "tracking_before_clear_choice",
      severity: "medium",
      confidence: "low",
      title: sectionFindingTitle("tracking_before_clear_choice_title"),
      detail: tA("findingTemplates.trackingTimingUnknown", [observedTrackingRequests.length, observedTrackingCookies.length]),
      advice: sectionFindingAdvice("tracking_before_clear_choice")
    });
  }

  if (consentDetected && acceptAvailable && !rejectAvailable && !preferenceAvailable) {
    findings.push({
      id: "consent_no_reject_option",
      severity: "medium",
      title: sectionFindingTitle("consent_no_reject_option_title"),
      detail: tA("findingTemplates.consentNoRejectOption"),
      advice: sectionFindingAdvice("consent_no_reject_option")
    });
  }

  if (consentDetected && acceptAvailable && !rejectAvailable && preferenceAvailable) {
    findings.push({
      id: "reject_hidden_in_preferences",
      severity: "medium",
      title: sectionFindingTitle("reject_hidden_in_preferences_title"),
      detail: tA("findingTemplates.consentRejectHidden"),
      advice: sectionFindingAdvice("reject_hidden_in_preferences")
    });
  }

  const definitePostChoiceCount = requestTiming.after.length + cookieTiming.after.length;
  const rejectedTracking = ["reject_all", "necessary_only"].includes(timeline.choiceKind);
  const acceptedAllTracking = timeline.choiceKind === "accept_all";
  if (rejectedTracking && timeline.boundaryAt && definitePostChoiceCount > 0) {
    findings.push({
      id: "tracking_after_rejection",
      severity: "high",
      confidence: "high",
      title: sectionFindingTitle("tracking_after_rejection_title"),
      detail: tA("findingTemplates.trackingAfterRejection", [requestTiming.after.length, cookieTiming.after.length]),
      advice: sectionFindingAdvice("tracking_after_rejection")
    });
  } else if (rejectedTracking && trackingObserved && unknownTimingCount > 0) {
    findings.push({
      id: "tracking_after_rejection",
      severity: "medium",
      confidence: "low",
      title: sectionFindingTitle("tracking_after_rejection_title"),
      detail: tA("findingTemplates.trackingAfterRejectionTimingUnknown", [requestTiming.unknown.length, cookieTiming.unknown.length]),
      advice: sectionFindingAdvice("tracking_after_rejection")
    });
  }

  if (!rejectedTracking && !acceptedAllTracking && disabledTrackingToggles.length > 0 && timeline.boundaryAt && definitePostChoiceCount > 0) {
    findings.push({
      id: "tracking_despite_disabled_toggle",
      severity: "high",
      title: sectionFindingTitle("tracking_despite_disabled_toggle_title"),
      detail: tA("findingTemplates.trackingDespiteDisabledToggle", [disabledTrackingToggles.length]),
      advice: sectionFindingAdvice("tracking_despite_disabled_toggle")
    });
  } else if (
    !rejectedTracking &&
    !acceptedAllTracking &&
    disabledTrackingToggles.length > 0 &&
    trackingObserved &&
    (!timeline.boundaryAt || unknownTimingCount > 0)
  ) {
    findings.push({
      id: "tracking_despite_disabled_toggle",
      severity: "medium",
      confidence: "low",
      title: sectionFindingTitle("tracking_despite_disabled_toggle_title"),
      detail: tA("findingTemplates.trackingDisabledTimingUnknown", [disabledTrackingToggles.length]),
      advice: sectionFindingAdvice("tracking_despite_disabled_toggle")
    });
  }

  return {
    detected: consentDetected,
    bannerCount: containers.length,
    rejectAvailable,
    acceptAvailable,
    preferenceAvailable,
    consentCategories,
    choiceAnalyses,
    trackingRequestCount: observedTrackingRequests.length,
    trackingCookieCount: observedTrackingCookies.length,
    preChoiceTrackingRequestCount: requestTiming.before.length,
    preChoiceTrackingCookieCount: cookieTiming.before.length,
    postChoiceTrackingRequestCount: requestTiming.after.length,
    postChoiceTrackingCookieCount: cookieTiming.after.length,
    unclassifiedTrackingRequestCount: requestTiming.unknown.length,
    unclassifiedTrackingCookieCount: cookieTiming.unknown.length,
    ignoredPreObservationTrackingRequestCount: requestTiming.outside.length,
    ignoredPreObservationTrackingCookieCount: cookieTiming.outside.length,
    timing: timeline,
    choiceKind: timeline.choiceKind,
    disabledTrackingToggleCount: disabledTrackingToggles.length,
    findings: findings.sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 };
      return order[a.severity] - order[b.severity];
    })
  };
}

function resolveConsentTimeline(consent) {
  const observationStartedAt = firstTimestamp(
    consent.observationStartedAt,
    consent.startedAt,
    consent.pageLoadedAt,
    consent.observation?.startedAt
  );
  const choiceAt = firstTimestamp(
    consent.choice?.at,
    consent.choice?.timeStamp,
    consent.choiceAt,
    consent.choiceTimestamp,
    consent.lastChoiceAt
  );
  const choiceKind = normalizeConsentChoiceKind(consent.choice?.kind) || normalizeConsentChoiceKind(consent.choiceKind);
  const snapshotAt = firstTimestamp(
    consent.snapshotAt,
    consent.snapshotCreatedAt,
    consent.baselineAt,
    consent.snapshot?.createdAt
  );
  const detectedAt = firstTimestamp(consent.detectedAt, consent.uiDetectedAt, consent.observation?.consentDetectedAt);
  // A user-created observation snapshot is useful for delta analysis, but it
  // does not prove that a consent choice happened at that time.
  const boundaryAt = choiceAt || null;

  return {
    observationStartedAt,
    detectedAt,
    choiceAt,
    choiceKind,
    snapshotAt,
    boundaryAt,
    boundaryType: choiceAt ? "choice" : "none",
    ambiguityWindowMs: CONSENT_BOUNDARY_AMBIGUITY_MS,
    confidence: boundaryAt ? "high" : "low"
  };
}

function normalizeConsentChoiceKind(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (["reject_all", "necessary_only"].includes(normalized)) return normalized;
  if (normalized === "accept_all") return normalized;
  if (["save_preferences", "save_choices"].includes(normalized)) return "save_preferences";
  return null;
}

function firstTimestamp(...values) {
  for (const value of values) {
    if (Number.isFinite(value) && value > 0) return Number(value);
    if (typeof value === "string" && value.trim()) {
      const parsed = Date.parse(value);
      if (Number.isFinite(parsed)) return parsed;
    }
  }
  return null;
}

function classifyEventsAroundBoundary(events, timeline, timestampReader = eventTimestamp) {
  const before = [];
  const after = [];
  const unknown = [];
  const outside = [];

  for (const event of events) {
    const timeStamp = timestampReader(event);
    const bucket = eventTimingBucket(timeStamp, timeline);
    ({ before, after, unknown, outside })[bucket].push(event);
  }

  return { before, after, unknown, outside };
}

function eventTimestamp(event) {
  return firstTimestamp(event?.timeStamp, event?.timestamp, event?.createdAt, event?.observedAt);
}

function eventTimingBucket(timeStamp, timeline) {
  if (!timeStamp) return "unknown";
  if (timeline.observationStartedAt && timeStamp < timeline.observationStartedAt) return "outside";
  if (!timeline.boundaryAt) return "unknown";
  if (Math.abs(timeStamp - timeline.boundaryAt) <= CONSENT_BOUNDARY_AMBIGUITY_MS) {
    return "unknown";
  }
  return timeStamp < timeline.boundaryAt ? "before" : "after";
}

function causallyTrustedCookieSetTimestamps(cookie) {
  if (cookie?.timingConfidence !== "observed") return null;
  const topLevelSite = cookie?.partitionKey?.topLevelSite;
  try {
    const parsed = new URL(String(topLevelSite || ""));
    if (!["http:", "https:"].includes(parsed.protocol) || parsed.origin !== topLevelSite) return null;
  } catch {
    return null;
  }
  const explicitFirst = firstTimestamp(cookie?.firstSetObservedAt);
  const legacyFirst = firstTimestamp(
    cookie?.firstObservedAt,
    cookie?.timeStamp,
    cookie?.observedAt
  );
  const deletedAt = firstTimestamp(cookie?.deletedAt);
  if (!explicitFirst && cookie?.removed && legacyFirst && legacyFirst === deletedAt) {
    return null;
  }
  const first = explicitFirst || legacyFirst;
  if (!first) return null;
  const explicitLast = firstTimestamp(cookie?.lastSetObservedAt);
  const legacyLast = firstTimestamp(cookie?.lastObservedAt);
  // Legacy tombstones could have copied deletedAt into lastObservedAt. Only
  // explicit set/update evidence may prove post-choice tracking.
  const safeLegacyLast =
    !explicitLast &&
    legacyLast &&
    cookie?.removed &&
    deletedAt === legacyLast
      ? null
      : legacyLast;
  return {
    first,
    last: Math.max(first, explicitLast || safeLegacyLast || first)
  };
}

function classifyCookieEvidenceAroundBoundary(cookies, timeline) {
  const bucketIndexes = {
    before: new Set(),
    after: new Set(),
    unknown: new Set(),
    outside: new Set()
  };
  cookies.forEach((cookie, index) => {
    const evidence = causallyTrustedCookieSetTimestamps(cookie);
    const timestamps = evidence
      ? Array.from(new Set([evidence.first, evidence.last]))
      : [null];
    for (const timeStamp of timestamps) {
      bucketIndexes[eventTimingBucket(timeStamp, timeline)].add(index);
    }
  });
  const asCookies = (indexes) => Array.from(indexes, (index) => cookies[index]);
  const before = asCookies(bucketIndexes.before);
  const after = asCookies(bucketIndexes.after);
  const unknown = asCookies(bucketIndexes.unknown);
  const outside = asCookies(bucketIndexes.outside);
  const observedIndexes = new Set([
    ...bucketIndexes.before,
    ...bucketIndexes.after,
    ...bucketIndexes.unknown
  ]);
  return {
    before,
    after,
    unknown,
    outside,
    observed: asCookies(observedIndexes)
  };
}

function causallyTrustedCookieLatestSetTimestamp(cookie) {
  return causallyTrustedCookieSetTimestamps(cookie)?.last || null;
}

export function analyzeObservationDelta(snapshot = null, requests = [], cookies = []) {
  if (!snapshot?.createdAt) {
    return {
      hasSnapshot: false,
      findings: []
    };
  }

  const laterRequests = (Array.isArray(requests) ? requests : []).filter((request) => request.timeStamp > snapshot.createdAt);
  const laterCookies = (Array.isArray(cookies) ? cookies : []).filter(
    (cookie) => causallyTrustedCookieLatestSetTimestamp(cookie) > snapshot.createdAt
  );
  const newTrackingRequests = laterRequests.filter(isTrackerRequest);
  const newTrackingCookies = laterCookies.filter((cookie) => isTrackingCookieName(cookie.name));
  const newPosts = laterRequests.filter((request) => ["POST", "PUT", "PATCH"].includes(request.method) && request.host);
  const findings = [];

  if (newTrackingRequests.length > 0 || newTrackingCookies.length > 0) {
    findings.push({
      id: "tracking_after_snapshot",
      severity: "high",
      title: sectionFindingTitle("tracking_after_snapshot_title"),
      detail: tA("findingTemplates.trackingAfterSnapshot", [newTrackingRequests.length, newTrackingCookies.length]),
      advice: sectionFindingAdvice("tracking_after_snapshot")
    });
  }

  if (newPosts.length > 0) {
    findings.push({
      id: "write_request_after_snapshot",
      severity: "medium",
      title: sectionFindingTitle("write_request_after_snapshot_title"),
      detail: tA("findingTemplates.writeRequestAfterSnapshot", [newPosts.slice(0, 8).map((request) => request.host).join(", ")]),
      advice: sectionFindingAdvice("write_request_after_snapshot")
    });
  }

  return {
    hasSnapshot: true,
    snapshotLabel: snapshot.label,
    snapshotCreatedAt: snapshot.createdAt,
    requestDelta: Math.max(0, (Array.isArray(requests) ? requests.length : 0) - (snapshot.requestCount || 0)),
    cookieDelta: Math.max(
      0,
      (Array.isArray(cookies) ? cookies.filter((cookie) => !cookie.removed).length : 0) -
        (snapshot.cookieCount || 0)
    ),
    trackingRequestDelta: newTrackingRequests.length,
    trackingCookieDelta: newTrackingCookies.length,
    findings
  };
}

export function detectJurisdiction(signals = {}) {
  const countryCode = (signals.countryCode || signals.ipCountryCode || "").toUpperCase();
  const languageSignals = [signals.language, ...(signals.languages || [])].filter(Boolean).map((value) => value.toLowerCase());
  const timeZone = (signals.timeZone || "").toLowerCase();
  const host = (signals.host || hostFromUrl(signals.url || "") || "").toLowerCase();

  if (EU_COUNTRY_CODES.has(countryCode)) {
    return {
      code: "GDPR",
      label: jurisdictionLabel("GDPR"),
      confidence: "medium",
      basis: jurisdictionBasisLabel("ip")
    };
  }

  if (countryCode === "KR") {
    return {
      code: "KR",
      label: jurisdictionLabel("KR"),
      confidence: "medium",
      basis: jurisdictionBasisLabel("ip")
    };
  }

  if (countryCode === "US") {
    return {
      code: "US",
      label: jurisdictionLabel("US"),
      confidence: "medium",
      basis: jurisdictionBasisLabel("ip")
    };
  }

  // A known non-KR/US/EU IP country is stronger than browser locale hints and
  // must not be silently reinterpreted as one of those jurisdictions.
  if (countryCode) return generalJurisdiction();

  const scores = { KR: 0, GDPR: 0, US: 0 };
  const hostSignals = {
    KR: host.endsWith(".kr"),
    GDPR: isEuSignal([], "", host),
    US: host.endsWith(".us")
  };
  const languageMatches = {
    KR: languageSignals.some((language) => language === "ko" || language.startsWith("ko-")),
    GDPR: isEuSignal(languageSignals, "", ""),
    US: languageSignals.some((language) => language === "en-us")
  };
  const timeZoneMatches = {
    KR: timeZone === "asia/seoul",
    GDPR: isEuEeaTimeZone(timeZone),
    US: isUsTimeZone(timeZone)
  };

  for (const code of Object.keys(scores)) {
    if (hostSignals[code]) scores[code] += 3;
    if (languageMatches[code]) scores[code] += 1;
    if (timeZoneMatches[code]) scores[code] += 1;
  }

  const ranked = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const [winner, winnerScore] = ranked[0];
  const runnerUpScore = ranked[1][1];
  if (winnerScore === 0 || winnerScore === runnerUpScore) return generalJurisdiction();

  const basisKey = winner === "KR" ? "krSignal" : winner === "GDPR" ? "euSignal" : "usSignal";
  return {
    code: winner,
    label: jurisdictionLabel(winner),
    confidence: winnerScore >= 3 ? "medium" : "low",
    basis: jurisdictionBasisLabel(basisKey)
  };

  function generalJurisdiction() {
    return {
      code: "GENERAL",
      label: jurisdictionLabel("GENERAL"),
      confidence: "low",
      basis: jurisdictionBasisLabel("uncertain")
    };
  }
}

export function analyzeJurisdictionCompliance(policyText, context = {}) {
  const jurisdiction = context.jurisdiction || detectJurisdiction(context.signals || {});
  const safePolicyText = boundedPolicyText(policyText);
  const policySections = extractPolicySections(safePolicyText);
  const observed = context.observed || {};
  const findings = [];

  if (jurisdiction.code === "KR") {
    findings.push(...analyzeKoreanPolicyRequirements(policySections, observed));
  } else if (jurisdiction.code === "US") {
    findings.push(...analyzeUsPolicyRequirements(policySections, observed, safePolicyText));
  } else if (jurisdiction.code === "GDPR") {
    findings.push(...analyzeGdprPolicyRequirements(policySections, observed, safePolicyText));
  } else {
    findings.push({
      id: "jurisdiction_uncertain",
      severity: "low",
      title: sectionFindingTitle("jurisdiction_uncertain_title"),
      detail: sectionFindingDetail("jurisdiction_uncertain"),
      advice: sectionFindingAdvice("jurisdiction_uncertain")
    });
  }

  return {
    jurisdiction,
    findings: findings.sort((a, b) => {
      const order = { high: 0, medium: 1, low: 2 };
      return order[a.severity] - order[b.severity];
    })
  };
}

export function analyzeBehaviorPolicyAlignment(policyText, observed = {}) {
  const policySections = extractPolicySections(boundedPolicyText(policyText));
  const vendorChecks = (observed.vendorSummary || [])
    .filter((vendor) => vendor.category !== "cdn_security")
    .map((vendor) => {
      const reasonsText = tA("alignmentReasons.vendor")
        .replace("${vendor}", vendor.vendor)
        .replace("${category}", consentCategoryLabel(vendor.category))
        .replace("${sections}", vendor.expectedPolicySections.map(sectionLabel).join(", "));
      return {
        id: `vendor_${vendor.category}_${vendor.host}`,
        label: `${vendor.vendor} (${consentCategoryLabel(vendor.category)})`,
        applicable: true,
        aligned: vendor.missingPolicySections.length === 0,
        reason: reasonsText
      };
    });
  const checks = [
    {
      id: "collected_data",
      label: alignmentLabel("collectedData"),
      applicable: observed.hasFormData || observed.hasSensitiveData,
      aligned: hasPolicySection(policySections, "collected_data"),
      reason: alignmentReason("collectedData")
    },
    {
      id: "tracking",
      label: alignmentLabel("tracking"),
      applicable: observed.hasTracking,
      aligned: hasPolicySection(policySections, "cookies_tracking"),
      reason: alignmentReason("tracking")
    },
    {
      id: "third_party",
      label: alignmentLabel("thirdParty"),
      applicable: observed.hasThirdParty,
      aligned: hasAnyPolicySection(policySections, ["third_party", "processors"]),
      reason: alignmentReason("thirdParty")
    },
    {
      id: "retention",
      label: alignmentLabel("retention"),
      applicable: observed.hasFormData || observed.hasStorage,
      aligned: hasPolicySection(policySections, "retention"),
      reason: alignmentReason("retention")
    },
    {
      id: "security",
      label: alignmentLabel("security"),
      applicable: observed.hasSensitiveData || observed.hasAuthStorage,
      aligned: hasPolicySection(policySections, "security"),
      reason: alignmentReason("security")
    },
    {
      id: "overseas_transfer",
      label: alignmentLabel("overseasTransfer"),
      applicable: observed.hasOverseasTransfer,
      aligned: hasPolicySection(policySections, "overseas_transfer"),
      reason: alignmentReason("overseasTransfer")
    },
    ...vendorChecks
  ];
  const applicableChecks = checks.filter((check) => check.applicable);
  const alignedCount = applicableChecks.filter((check) => check.aligned).length;
  const score = applicableChecks.length === 0 ? 100 : Math.round((alignedCount / applicableChecks.length) * 100);
  const findings = applicableChecks
    .filter((check) => !check.aligned)
    .map((check) => {
      const titleId = check.id.startsWith("vendor_")
        ? "vendor_policy_section_gap_title"
        : check.id === "collected_data"
          ? "alignment_missing_collect_title"
          : `alignment_missing_${check.id}_title`;
      return {
        id: `alignment_missing_${check.id}`,
        severity: check.id === "tracking" || check.id === "collected_data" ? "high" : "medium",
        title: sectionFindingTitle(titleId),
        detail: check.reason,
        advice: sectionFindingAdvice("alignment_generic")
      };
    });

  return {
    score,
    level: score >= 80 ? "high" : score >= 50 ? "medium" : "low",
    levelLabel: riskLevelLabel(score >= 80 ? "high" : score >= 50 ? "medium" : "low"),
    checks: applicableChecks,
    findings
  };
}

function analyzeGdprPolicyRequirements(policySections, observed, policyText) {
  const findings = [];
  const policy = policyText.toLowerCase();
  const missingCore = ["collected_data", "purpose", "legal_basis", "retention", "user_rights", "security"].filter(
    (sectionId) => !hasPolicySection(policySections, sectionId)
  );

  if (missingCore.length > 0) {
    findings.push({
      id: "gdpr_missing_core_information",
      severity: "high",
      title: sectionFindingTitle("gdpr_missing_core_information_title"),
      detail: missingCore.map((sectionId) => sectionLabel(sectionId)).join(", "),
      advice: sectionFindingAdvice("gdpr_missing_core_information")
    });
  }

  if (observed.hasTracking && !hasPolicySection(policySections, "cookies_tracking")) {
    findings.push({
      id: "gdpr_tracking_without_specific_consent_notice",
      severity: "high",
      title: sectionFindingTitle("gdpr_tracking_without_specific_consent_notice_title"),
      detail: sectionFindingDetail("gdpr_tracking_without_specific_consent_notice"),
      advice: sectionFindingAdvice("gdpr_tracking_without_specific_consent_notice")
    });
  }

  if (observed.hasOverseasTransfer && !hasPolicySection(policySections, "overseas_transfer")) {
    findings.push({
      id: "gdpr_transfer_without_safeguards_notice",
      severity: "high",
      title: sectionFindingTitle("gdpr_transfer_without_safeguards_notice_title"),
      detail: sectionFindingDetail("gdpr_transfer_without_safeguards_notice"),
      advice: sectionFindingAdvice("gdpr_transfer_without_safeguards_notice")
    });
  }

  if (observed.hasSensitiveData && !/special categor|sensitive|biometric|genetic|health|racial|ethnic|political|religious|민감|생체|건강/.test(policy)) {
    findings.push({
      id: "gdpr_special_category_without_notice",
      severity: "high",
      title: sectionFindingTitle("gdpr_special_category_without_notice_title"),
      detail: sectionFindingDetail("gdpr_special_category_without_notice"),
      advice: sectionFindingAdvice("gdpr_special_category_without_notice")
    });
  }

  if (observed.hasProfiling && !hasPolicySection(policySections, "automated_decision")) {
    findings.push({
      id: "gdpr_profiling_without_notice",
      severity: "medium",
      title: sectionFindingTitle("gdpr_profiling_without_notice_title"),
      detail: sectionFindingDetail("gdpr_profiling_without_notice"),
      advice: sectionFindingAdvice("gdpr_profiling_without_notice")
    });
  }

  return findings;
}

function analyzeKoreanPolicyRequirements(policySections, observed) {
  const findings = [];
  const missingCore = ["collected_data", "purpose", "retention", "user_rights", "security"].filter(
    (sectionId) => !hasPolicySection(policySections, sectionId)
  );

  if (missingCore.length > 0) {
    findings.push({
      id: "kr_missing_core_policy_sections",
      severity: "high",
      title: sectionFindingTitle("kr_missing_core_policy_sections_title"),
      detail: sectionFindingDetail("kr_missing_core_policy_sections"),
      advice: sectionFindingAdvice("kr_missing_core_policy_sections")
    });
  }

  if (observed.hasThirdParty && !hasAnyPolicySection(policySections, ["third_party", "processors"])) {
    findings.push({
      id: "kr_third_party_without_disclosure",
      severity: "high",
      title: sectionFindingTitle("kr_third_party_without_disclosure_title"),
      detail: sectionFindingDetail("kr_third_party_without_disclosure"),
      advice: sectionFindingAdvice("kr_third_party_without_disclosure")
    });
  }

  if (observed.hasTracking && !hasPolicySection(policySections, "cookies_tracking")) {
    findings.push({
      id: "kr_tracking_without_cookie_section",
      severity: "medium",
      title: sectionFindingTitle("kr_tracking_without_cookie_section_title"),
      detail: sectionFindingDetail("kr_tracking_without_cookie_section"),
      advice: sectionFindingAdvice("kr_tracking_without_cookie_section")
    });
  }

  if (observed.hasOverseasTransfer && !hasPolicySection(policySections, "overseas_transfer")) {
    findings.push({
      id: "kr_overseas_transfer_without_disclosure",
      severity: "medium",
      title: sectionFindingTitle("kr_overseas_transfer_without_disclosure_title"),
      detail: sectionFindingDetail("kr_overseas_transfer_without_disclosure"),
      advice: sectionFindingAdvice("kr_overseas_transfer_without_disclosure")
    });
  }

  return findings;
}

function analyzeUsPolicyRequirements(policySections, observed, policyText) {
  const findings = [];
  const policy = policyText.toLowerCase();
  const missingTransparency = ["collected_data", "purpose", "third_party", "user_rights"].filter(
    (sectionId) => !hasPolicySection(policySections, sectionId)
  );

  if (missingTransparency.length > 0) {
    findings.push({
      id: "us_missing_transparency_sections",
      severity: "medium",
      title: sectionFindingTitle("us_missing_transparency_sections_title"),
      detail: missingTransparency.map((sectionId) => sectionLabel(sectionId)).join(", "),
      advice: sectionFindingAdvice("us_missing_transparency_sections")
    });
  }

  if (observed.hasTracking && !hasPolicySection(policySections, "cookies_tracking")) {
    findings.push({
      id: "us_tracking_without_optout_notice",
      severity: "high",
      title: sectionFindingTitle("us_tracking_without_optout_notice_title"),
      detail: sectionFindingDetail("us_tracking_without_optout_notice"),
      advice: sectionFindingAdvice("us_tracking_without_optout_notice")
    });
  }

  if (observed.hasSensitiveData && !/sensitive|precise geolocation|biometric|health|financial|민감|생체|건강|금융/.test(policy)) {
    findings.push({
      id: "us_sensitive_data_without_notice",
      severity: "high",
      title: sectionFindingTitle("us_sensitive_data_without_notice_title"),
      detail: sectionFindingDetail("us_sensitive_data_without_notice"),
      advice: sectionFindingAdvice("us_sensitive_data_without_notice")
    });
  }

  if (hasPolicySection(policySections, "children") && !/parent|guardian|verifiable parental consent|coppa|보호자|법정대리인/.test(policy)) {
    findings.push({
      id: "us_children_without_parental_consent",
      severity: "high",
      title: sectionFindingTitle("us_children_without_parental_consent_title"),
      detail: sectionFindingDetail("us_children_without_parental_consent"),
      advice: sectionFindingAdvice("us_children_without_parental_consent")
    });
  }

  return findings;
}

function buildSummary(level, dataCategories, risks, positives) {
  const parts = [];
  parts.push(tA("findingTemplates.summaryIntro", [riskLevelLabel(level)]));

  if (dataCategories.length > 0) {
    parts.push(tA("findingTemplates.summaryDataFound", [dataCategories.map((item) => item.label).join(", ")]));
  } else {
    parts.push(tA("findingTemplates.noDataFound"));
  }

  if (risks.length > 0) {
    parts.push(tA("findingTemplates.summaryFocusRisk", [risks[0].title]));
  }

  if (positives.length > 0) {
    parts.push(tA("findingTemplates.summaryPositive", [positives.slice(0, 2).join(", ")]));
  }

  return parts.join(" ");
}

function splitPolicyBlocks(text) {
  const normalized = text
    .replace(/\r/g, "")
    .replace(/[ \t]+/g, " ")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
  const headingSplit = normalized
    .split(/\n(?=(?:\d{1,2}[.)]\s*)?(?:[A-Z][A-Za-z ]{3,80}|[가-힣0-9][가-힣0-9\s·/()]{3,80})(?:\n|$))/)
    .map((block) => block.trim())
    .filter((block) => block.length > 30);

  if (headingSplit.length >= 3) return headingSplit.slice(0, 120);

  return getSentences(normalized)
    .reduce((blocks, sentence) => {
      const current = blocks.at(-1) || "";
      if (!current || current.length > 700) {
        blocks.push(sentence);
      } else {
        blocks[blocks.length - 1] = `${current} ${sentence}`;
      }
      return blocks;
    }, [])
    .filter((block) => block.length > 30)
    .slice(0, 120);
}

function inferBlockTitle(block) {
  const firstLine = block.split("\n").map((line) => line.trim()).find(Boolean) || "";
  if (firstLine.length <= 90) return firstLine.replace(/^\d{1,2}[.)]\s*/, "");
  const sentence = getSentences(block)[0] || "";
  return truncateText(sentence, 72);
}

function scorePolicyBlock(block, rule) {
  const title = inferBlockTitle(block);
  const headingScore = rule.headingPatterns.some((pattern) => pattern.test(title)) ? 6 : 0;
  const contentScore = rule.contentPatterns.reduce((score, pattern) => score + (pattern.test(block) ? 2 : 0), 0);
  const headingInBodyScore = rule.headingPatterns.reduce((score, pattern) => score + (pattern.test(block) ? 1 : 0), 0);
  return headingScore + contentScore + headingInBodyScore;
}

function truncateText(text, maxLength) {
  const normalized = text.replace(/\s+/g, " ").trim();
  return normalized.length > maxLength ? `${normalized.slice(0, maxLength - 3)}...` : normalized;
}

function hostFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function isThirdPartyHost(pageHost, requestHost) {
  if (!pageHost || !requestHost) return false;
  return registrableDomain(pageHost) !== registrableDomain(requestHost);
}

function uniqueBy(items, getKey) {
  const seen = new Set();
  return items.filter((item) => {
    const key = getKey(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function extractPolicyDomains(text) {
  const domains = text.match(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi) || [];
  return Array.from(new Set(domains.map((domain) => domain.toLowerCase().replace(/^www\./, ""))));
}

function escapeRegExp(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function policyMentionsVendorAlias(policy, alias) {
  const normalizedAlias = String(alias || "").trim().toLowerCase();
  const compactAlias = normalizedAlias.replace(/[^\p{L}\p{N}]/gu, "");
  if (compactAlias.length < 4) return false;

  const aliasPattern = escapeRegExp(normalizedAlias).replace(/\s+/g, "\\s+");
  return new RegExp(`(?:^|[^\\p{L}\\p{N}])${aliasPattern}(?=$|[^\\p{L}\\p{N}])`, "iu").test(policy);
}

function isHostDisclosed(host, policyDomains, policy, customVendorRules = []) {
  const lowerHost = host.toLowerCase().replace(/^www\./, "");
  const baseDomain = registrableDomain(lowerHost);
  const explicitlyMentioned = policyDomains.some((domain) => {
    const normalizedDomain = domain.toLowerCase().replace(/^www\./, "");
    return (
      lowerHost === normalizedDomain ||
      lowerHost.endsWith(`.${normalizedDomain}`) ||
      normalizedDomain.endsWith(`.${lowerHost}`) ||
      (baseDomain && baseDomain === registrableDomain(normalizedDomain))
    );
  });
  const vendor = classifyVendorHost(lowerHost, customVendorRules).vendor;
  const vendorMentioned =
    vendor !== "Unknown" &&
    vendor
      .toLowerCase()
      .split(/\s*\/\s*/)
      .some((alias) => policyMentionsVendorAlias(policy, alias));

  return explicitlyMentioned || vendorMentioned;
}

function hasPolicySection(policySections, sectionId) {
  return Boolean(policySections.find((section) => section.id === sectionId && section.found));
}

function hasAnyPolicySection(policySections, sectionIds) {
  return sectionIds.some((sectionId) => hasPolicySection(policySections, sectionId));
}

function sectionText(policySections, sectionIds) {
  return policySections
    .filter((section) => sectionIds.includes(section.id) && section.found)
    .flatMap((section) => section.evidence.map((item) => item.excerpt))
    .join(" ");
}

function sectionLabel(sectionId) {
  return policySectionLabel(sectionId);
}

function mentionsAdvertisingOrAnalytics(policy) {
  return /advertising|analytics|tracking|cookie|personalized ad|interest-based|광고|분석|추적|쿠키|행태정보|맞춤형/.test(policy);
}

function detectSensitiveFields(requests) {
  const keys = Array.from(
    new Set(requests.flatMap((request) => [...(request.queryKeys || []), ...(request.bodyKeys || [])]))
  );

  return SENSITIVE_FIELD_RULES.map((rule) => ({
    category: rule.category,
    label: sensitiveFieldLabel(rule.category),
    keys: keys.filter((key) => matchesSensitiveValue(key, rule.patterns)).slice(0, 8)
  })).filter((item) => item.keys.length > 0);
}

function classifyVendorRequests(requests, policySections, customVendorRules = []) {
  return requests.map((request) => {
    const classification = classifyVendorHost(request.url || request.host, customVendorRules);
    const missingPolicySections = classification.expectedPolicySections.filter(
      (sectionId) => !hasPolicySection(policySections, sectionId)
    );

    return {
      host: request.host,
      vendor: classification.vendor,
      category: classification.category,
      risk: classification.risk,
      expectedPolicySections: classification.expectedPolicySections,
      missingPolicySections
    };
  });
}

function preferredVendorRequests(requests, customVendorRules = []) {
  const byHost = new Map();
  for (const request of requests) {
    const current = byHost.get(request.host);
    if (!current) {
      byHost.set(request.host, request);
      continue;
    }
    const currentVendor = classifyVendorHost(current.url || current.host, customVendorRules).vendor;
    const nextVendor = classifyVendorHost(request.url || request.host, customVendorRules).vendor;
    if (currentVendor === "Unknown" && nextVendor !== "Unknown") byHost.set(request.host, request);
  }
  return Array.from(byHost.values());
}

function classifyKeys(keys) {
  return SENSITIVE_FIELD_RULES.map((rule) => ({
    category: rule.category,
    label: sensitiveFieldLabel(rule.category),
    keys: keys.filter((key) => matchesSensitiveValue(key, rule.patterns)).slice(0, 8)
  })).filter((item) => item.keys.length > 0);
}

function mentionsClientStorage(policy) {
  return /cookie|localstorage|sessionstorage|browser storage|device identifier|쿠키|브라우저 저장|로컬스토리지|세션스토리지|식별자|행태정보/.test(policy);
}

function detectConsentCategories(containers) {
  const categories = new Map();

  for (const container of containers) {
    addConsentCategories(categories, container.text || "", false);

    for (const button of container.buttons || []) {
      addConsentCategories(categories, button, false);
    }

    for (const toggle of container.toggles || []) {
      const descriptor = `${toggle.label || ""} ${toggle.name || ""} ${toggle.id || ""}`;
      addConsentCategories(categories, descriptor, Boolean(toggle.checked));
    }
  }

  return Array.from(categories.values()).sort((a, b) => riskRank(b.risk) - riskRank(a.risk));
}

function addConsentCategories(categories, text, defaultEnabled) {
  for (const rule of CONSENT_CATEGORY_RULES) {
    if (!rule.patterns.some((pattern) => pattern.test(text || ""))) continue;
    const existing = categories.get(rule.id);
    categories.set(rule.id, {
      id: rule.id,
      label: consentCategoryLabel(rule.id),
      risk: rule.risk,
      reason: consentCategoryReason(rule.id),
      defaultEnabled: Boolean(existing?.defaultEnabled || defaultEnabled)
    });
  }
}

function buildConsentChoiceAnalyses(containers, consentCategories, trackingRequests, trackingCookies) {
  const choices = uniqueBy(
    containers.flatMap((container) => (container.buttons || []).map((label) => buildConsentChoice(label, consentCategories, trackingRequests, trackingCookies))),
    (choice) => `${choice.type}:${choice.label.toLowerCase()}`
  ).filter((choice) => choice.type !== "unknown");

  const hasToggleSettings = containers.some((container) => (container.toggles || []).length > 0);
  if (hasToggleSettings && !choices.some((choice) => choice.type === "preferences")) {
    choices.push(
      buildConsentChoice(
        tA("findingTemplates.syntheticPreferencesLabel"),
        consentCategories,
        trackingRequests,
        trackingCookies,
        "preferences"
      )
    );
  }

  return choices;
}

function buildConsentChoice(label, consentCategories, trackingRequests, trackingCookies, forcedType = null) {
  const type = forcedType || classifyConsentChoice(label);
  const hasPreChoiceTracking = trackingRequests.length > 0 || trackingCookies.length > 0;
  const inferredCategories = type === "accept_all" && consentCategories.length === 0;
  const allowedCategories = allowedCategoriesForConsentChoice(type, consentCategories);
  const riskLevel = riskForConsentChoice(type, allowedCategories, hasPreChoiceTracking, inferredCategories);
  const concerns = concernsForConsentChoice(type, allowedCategories, hasPreChoiceTracking, inferredCategories);

  return {
    type,
    label,
    riskLevel,
    safetyLabel: safetyLabelForRisk(riskLevel),
    allowedCategories,
    concerns,
    summary: summaryForConsentChoice(type, riskLevel, allowedCategories, inferredCategories)
  };
}

function classifyConsentChoice(label) {
  const text = (label || "").toLowerCase();
  if (hasRejectSignal(text)) return "necessary_only";
  if (
    /\b(?:save|apply)\s+(?:my\s+)?(?:preferences|settings|choices?|selections?)\b|\bconfirm\s+(?:my\s+)?(?:preferences|settings|choices?|selections?)\b|(?:설정|선택)\s*(?:저장|적용)|선택\s*완료/.test(
      text
    )
  ) {
    return "save_choices";
  }
  if (/preference|settings|manage|customize|options|설정|관리|선택|맞춤|변경/.test(text)) return "preferences";
  if (hasAcceptSignal(text) || /accept all|allow all|agree all|전체 동의|모두 허용|모두 수락|전부 허용/.test(text)) return "accept_all";
  return "unknown";
}

function allowedCategoriesForConsentChoice(type, consentCategories) {
  if (type === "necessary_only") {
    const necessary = consentCategories.filter((category) => category.id === "necessary");
    return necessary.length ? necessary : [fallbackConsentCategory("necessary")];
  }

  if (type === "accept_all") {
    return consentCategories.length
      ? consentCategories
      : [
          fallbackConsentCategory("necessary"),
          fallbackConsentCategory("functional"),
          fallbackConsentCategory("analytics"),
          fallbackConsentCategory("advertising")
        ];
  }

  if (type === "preferences" || type === "save_choices") {
    if (type === "save_choices") {
      const enabled = consentCategories.filter((category) => category.defaultEnabled || category.id === "necessary");
      return enabled.length ? enabled : [fallbackConsentCategory("necessary")];
    }

    return consentCategories.length ? consentCategories : [fallbackConsentCategory("necessary")];
  }

  return [];
}

function fallbackConsentCategory(id) {
  const rule = CONSENT_CATEGORY_RULES.find((item) => item.id === id) || CONSENT_CATEGORY_RULES[0];
  return {
    id: rule.id,
    label: consentCategoryLabel(rule.id),
    risk: rule.risk,
    reason: consentCategoryReason(rule.id),
    defaultEnabled: false,
    inferred: true
  };
}

function riskForConsentChoice(type, allowedCategories, hasPreChoiceTracking, inferredCategories) {
  if (hasPreChoiceTracking && type === "necessary_only") return "medium";
  if (hasPreChoiceTracking && type === "accept_all") return "high";
  if (type === "preferences" || type === "save_choices") {
    const enabledRisk = allowedCategories.filter((category) => category.defaultEnabled).reduce((max, category) => Math.max(max, riskRank(category.risk)), 0);
    if (enabledRisk >= 3) return "high";
    if (enabledRisk >= 2 || inferredCategories) return "medium";
    if (type === "preferences") {
      const configurableRisk = allowedCategories.reduce((max, category) => Math.max(max, riskRank(category.risk)), 0);
      return configurableRisk >= 3 ? "medium" : "low";
    }
  }

  const maxRisk = allowedCategories.reduce((max, category) => Math.max(max, riskRank(category.risk)), 0);
  if (maxRisk >= 3) return "high";
  if (maxRisk >= 2 || inferredCategories) return "medium";
  return "low";
}

function concernsForConsentChoice(type, allowedCategories, hasPreChoiceTracking, inferredCategories) {
  const concerns = [];
  const highRiskCategories = allowedCategories.filter((category) => category.risk === "high");
  const mediumRiskCategories = allowedCategories.filter((category) => category.risk === "medium");

  if (highRiskCategories.length > 0) {
    concerns.push(
      tA("consentChoiceDetails.concernHighCategory", [highRiskCategories.map((category) => category.label).join(", ")])
    );
  }

  if (mediumRiskCategories.length > 0 && type !== "accept_all") {
    concerns.push(
      tA("consentChoiceDetails.concernMediumCategory", [mediumRiskCategories.map((category) => category.label).join(", ")])
    );
  }

  if (hasPreChoiceTracking) {
    concerns.push(tA("consentChoiceDetails.concernTracking"));
  }

  if (inferredCategories) {
    concerns.push(tA("consentChoiceDetails.concernInferred"));
  }

  if (type === "necessary_only" && concerns.length === 0) {
    concerns.push(tA("consentChoiceDetails.concernNecessaryOnlyDefault"));
  }

  return concerns;
}

function summaryForConsentChoice(type, riskLevel, allowedCategories, inferredCategories) {
  const categoryLabels = allowedCategories.map((category) => category.label).join(", ");
  const prefix = consentChoicePrefix(type);
  const detail = inferredCategories
    ? tA("consentChoiceDetails.inferred", [categoryLabels])
    : tA("consentChoiceDetails.explicit", [categoryLabels]);
  return `${prefix} ${detail} ${tA("consentChoiceDetails.riskSuffix", [safetyLabelForRisk(riskLevel)])}`;
}

function safetyLabelForRisk(risk) {
  return riskLevelLabel(risk);
}

function riskRank(risk) {
  return { low: 1, medium: 2, high: 3 }[risk] || 0;
}

function hasRejectSignal(text) {
  return /reject|decline|deny|refuse|do not sell|opt out|necessary only|거부|거절|동의하지 않|필수만|선택 해제|옵트아웃/.test(text);
}

function hasAcceptSignal(text) {
  return /accept|agree|allow|consent|동의|허용|수락/.test(text);
}

function isEuSignal(languageSignals, timeZone, host) {
  const euLanguagePrefixes = [
    "bg",
    "cs",
    "da",
    "de",
    "el",
    "es",
    "et",
    "fi",
    "fr",
    "ga",
    "hr",
    "hu",
    "is",
    "it",
    "lt",
    "lv",
    "mt",
    "nl",
    "no",
    "pl",
    "pt",
    "ro",
    "sk",
    "sl",
    "sv"
  ];
  const euTlds = [
    ".eu",
    ".at",
    ".be",
    ".bg",
    ".hr",
    ".cy",
    ".cz",
    ".dk",
    ".ee",
    ".fi",
    ".fr",
    ".de",
    ".gr",
    ".hu",
    ".ie",
    ".it",
    ".lv",
    ".lt",
    ".lu",
    ".mt",
    ".nl",
    ".pl",
    ".pt",
    ".ro",
    ".sk",
    ".si",
    ".es",
    ".se",
    ".is",
    ".li",
    ".no"
  ];

  return (
    isEuEeaTimeZone(timeZone) ||
    languageSignals.some((language) => euLanguagePrefixes.some((prefix) => language === prefix || language.startsWith(`${prefix}-`))) ||
    euTlds.some((tld) => host.endsWith(tld))
  );
}

function getFieldDescriptor(field) {
  return [
    field.name,
    field.id,
    field.autocomplete,
    field.placeholder,
    field.label,
    field.type
  ]
    .filter(Boolean)
    .join(" ");
}

function classifyField(field) {
  const descriptor = getFieldDescriptor(field);
  if (!descriptor) return "";
  const match = SENSITIVE_FIELD_RULES.find((rule) => matchesSensitiveValue(descriptor, rule.patterns));
  return match?.category || "";
}
