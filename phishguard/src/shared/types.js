/**
 * PhishGuard — Shared Types & Constants
 * All shared enumerations, constants, and type definitions.
 */

/** Risk category labels */
export const RISK_CATEGORY = {
  SAFE:       'safe',
  SUSPICIOUS: 'suspicious',
  PHISHING:   'phishing',
  UNKNOWN:    'unknown',
};

/** Score thresholds → category mapping */
export const SCORE_THRESHOLDS = {
  SAFE_MAX:       20,   // 0–20   → Safe
  SUSPICIOUS_MAX: 60,   // 21–60  → Suspicious
  // 61+            → Phishing
};

/** Badge display config per category */
export const BADGE_CONFIG = {
  [RISK_CATEGORY.SAFE]: {
    text:  'OK',
    color: '#22c55e',   // green-500
    bg:    '#dcfce7',
  },
  [RISK_CATEGORY.SUSPICIOUS]: {
    text:  '!',
    color: '#f59e0b',   // amber-500
    bg:    '#fef3c7',
  },
  [RISK_CATEGORY.PHISHING]: {
    text:  'PH',
    color: '#ef4444',   // red-500
    bg:    '#fee2e2',
  },
  [RISK_CATEGORY.UNKNOWN]: {
    text:  '?',
    color: '#6b7280',   // gray-500
    bg:    '#f3f4f6',
  },
};

/** Cache TTL in milliseconds (5 minutes) */
export const CACHE_TTL_MS = 5 * 60 * 1000;

/** Rule IDs — used as stable keys */
export const RULES = {
  HTTP_SCHEME:          'http_scheme',
  IP_HOST:              'ip_host',
  PUNYCODE:             'punycode',
  AT_IN_URL:            'at_in_url',
  MISLEADING_SUBDOMAIN: 'misleading_subdomain',
  SUBDOMAIN_DEPTH:      'subdomain_depth',
  SUSPICIOUS_TLD:       'suspicious_tld',
  TYPOSQUATTING:        'typosquatting',
  LONG_URL:             'long_url',
  EXCESS_ENCODING:      'excess_encoding',
  HIGH_ENTROPY:         'high_entropy',
  LONG_QUERY:           'long_query',
  URL_SHORTENER:        'url_shortener',
  SUSPICIOUS_KEYWORDS:  'suspicious_keywords',
  DOUBLE_SLASH:         'double_slash',
  NON_STANDARD_PORT:    'non_standard_port',
  BLOCKLIST_HIT:        'blocklist_hit',
  SAFE_BROWSING_HIT:    'safe_browsing_hit',
  HTTPS_BONUS:          'https_bonus',
  PASSWORD_FIELD:       'password_field',
  WHITELISTED:          'whitelisted',
  AI_PHISHING_MODEL:    'ai_phishing_model',
  NLP_TEXT_PHISHING:    'nlp_text_phishing',
  GMAIL_SPAM_DETECTED:  'gmail_spam_detected',
  NRD_HEURISTIC:        'nrd_heuristic',
  AI_TRUST_LINGUISTIC:  'ai_trust_linguistic',
  AI_TRUST_BRAND:       'ai_trust_brand',
  AI_TRUST_BEHAVIOR:    'ai_trust_behavior',
  AI_TRUST_LINK:        'ai_trust_link',
  AI_TRUST_FINAL:       'ai_trust_final',
};

/** Rule metadata: weight (points) + human-readable description */
export const RULE_META = {
  [RULES.HTTP_SCHEME]: {
    weight:      15,
    label:       'Insecure HTTP connection',
    description: 'Site uses HTTP instead of HTTPS, leaving data unencrypted.',
    category:    'connection',
  },
  [RULES.IP_HOST]: {
    weight:      25,
    label:       'IP address used as hostname',
    description: 'Legitimate sites use domain names, not raw IP addresses.',
    category:    'domain',
  },
  [RULES.PUNYCODE]: {
    weight:      20,
    label:       'Punycode / IDN homograph',
    description: 'URL uses international characters that can impersonate Latin letters.',
    category:    'domain',
  },
  [RULES.AT_IN_URL]: {
    weight:      30,
    label:       '@ symbol in URL',
    description: 'The @ symbol tricks browsers into ignoring the real destination.',
    category:    'url',
  },
  [RULES.MISLEADING_SUBDOMAIN]: {
    weight:      20,
    label:       'Brand name in subdomain',
    description: 'A brand name appears in the subdomain while the real domain is different.',
    category:    'domain',
  },
  [RULES.SUBDOMAIN_DEPTH]: {
    weight:      10,
    label:       'Excessive subdomain depth',
    description: 'More than 3 subdomain levels is unusual and suspicious.',
    category:    'domain',
  },
  [RULES.SUSPICIOUS_TLD]: {
    weight:      15,
    label:       'High-risk TLD',
    description: 'This top-level domain is commonly abused in phishing campaigns.',
    category:    'domain',
  },
  [RULES.TYPOSQUATTING]: {
    weight:      30,
    label:       'Typosquatting detected',
    description: 'Domain is very similar to a known brand (1–2 character difference).',
    category:    'domain',
  },
  [RULES.LONG_URL]: {
    weight:      10,
    label:       'Unusually long URL',
    description: 'Very long URLs often hide the real destination or contain encoded payloads.',
    category:    'url',
  },
  [RULES.EXCESS_ENCODING]: {
    weight:      15,
    label:       'Excessive URL encoding',
    description: 'Large number of %-encoded characters may indicate URL obfuscation.',
    category:    'url',
  },
  [RULES.HIGH_ENTROPY]: {
    weight:      15,
    label:       'High-entropy URL segment',
    description: 'Random-looking path segments may indicate encoded or obfuscated payloads.',
    category:    'url',
  },
  [RULES.LONG_QUERY]: {
    weight:      10,
    label:       'Very long query string',
    description: 'Excessively long query strings can hide redirect destinations.',
    category:    'url',
  },
  [RULES.URL_SHORTENER]: {
    weight:      20,
    label:       'Known URL shortener',
    description: 'Shortened URLs conceal the real destination, commonly used in phishing.',
    category:    'url',
  },
  [RULES.SUSPICIOUS_KEYWORDS]: {
    weight:      10,
    label:       'Phishing keywords in URL',
    description: 'URL contains words like login, verify, account, secure commonly used in phishing.',
    category:    'url',
  },
  [RULES.DOUBLE_SLASH]: {
    weight:      10,
    label:       'Double slash in path',
    description: 'Unexpected double slashes may indicate URL manipulation.',
    category:    'url',
  },
  [RULES.NON_STANDARD_PORT]: {
    weight:      10,
    label:       'Non-standard port number',
    description: 'Legitimate sites rarely use non-standard ports; this may indicate phishing.',
    category:    'connection',
  },
  [RULES.BLOCKLIST_HIT]: {
    weight:      100,
    label:       'Local blocklist match',
    description: 'This URL/domain is in the local known-phishing blocklist.',
    category:    'intel',
  },
  [RULES.SAFE_BROWSING_HIT]: {
    weight:      100,
    label:       'Google Safe Browsing alert',
    description: 'Google Safe Browsing flagged this URL as malicious.',
    category:    'intel',
  },
  [RULES.HTTPS_BONUS]: {
    weight:      -5,
    label:       'Secure HTTPS connection',
    description: 'HTTPS is present (minor positive signal; not sufficient alone).',
    category:    'connection',
  },
  [RULES.PASSWORD_FIELD]: {
    weight:      8,
    label:       'Password field on suspicious page',
    description: 'Page contains a password input field while showing other risk signals.',
    category:    'page',
  },
  [RULES.WHITELISTED]: {
    weight:      -200,
    label:       'User-whitelisted domain',
    description: 'You have marked this domain as trusted.',
    category:    'user',
  },
  [RULES.AI_PHISHING_MODEL]: {
    weight:      45,
    label:       'AI Threat Model Flag',
    description: 'Our client-side machine learning model flagged this URL structure as highly suspicious.',
    category:    'intel',
  },
  [RULES.NLP_TEXT_PHISHING]: {
    weight:      100,
    label:       'NLP Phishing Detection',
    description: 'Our natural language engine detected high-risk phishing content within the page text.',
    category:    'page',
  },
  [RULES.GMAIL_SPAM_DETECTED]: {
    weight:      65,
    label:       'Gmail Spam Alert',
    description: 'Gmail has internally flagged this message or folder as suspicious/spam.',
    category:    'page',
  },
  [RULES.NRD_HEURISTIC]: {
    weight:      45,
    label:       'Newly Registered Domain Pattern',
    description: 'Domain exhibits patterns common in newly registered phishing sites (Suspicious TLD + High Entropy).',
    category:    'domain',
  },
  [RULES.AI_TRUST_LINGUISTIC]: {
    weight:      0,
    label:       'AI Linguistic Analysis',
    description: 'AI-based analysis of language patterns, urgency, and tone.',
    category:    'ai_trust',
  },
  [RULES.AI_TRUST_BRAND]: {
    weight:      0,
    label:       'AI Brand Verification',
    description: 'Deep check for brand impersonation and spoofing.',
    category:    'ai_trust',
  },
  [RULES.AI_TRUST_BEHAVIOR]: {
    weight:      0,
    label:       'AI Behavioral Check',
    description: 'Analysis of sender behavior and timing anomalies.',
    category:    'ai_trust',
  },
  [RULES.AI_TRUST_LINK]: {
    weight:      0,
    label:       'AI Link Analysis',
    description: 'Deep inspection of URL redirect chains and shorteners.',
    category:    'ai_trust',
  },
  [RULES.AI_TRUST_FINAL]: {
    weight:      40,
    label:       'AI Trust Layer Alert',
    description: 'The AI Trust Layer has flagged this content as suspicious despite clean heuristics.',
    category:    'ai_trust',
  },
};
