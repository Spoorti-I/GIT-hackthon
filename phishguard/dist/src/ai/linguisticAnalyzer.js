/**
 * PhishGuard — Linguistic Analyzer (AI Trust Layer)
 * Detects high-risk language patterns in email/SMS/draft/clipboard text.
 * Runs entirely locally — no API calls required.
 */

// ── Urgency & Fear Patterns ────────────────────────────────────────────────
const URGENCY_PATTERNS = [
  /\bimmediate(ly)?\b/i, /\burgent(ly)?\b/i, /\bact now\b/i,
  /\bwithin \d+ (hour|minute|day)/i, /\bexpire[sd]?\b/i,
  /\bdeadline\b/i, /\blast chance\b/i, /\btime.sensitive\b/i,
  /\bfinal (notice|warning|reminder)\b/i, /\byour account (will be|has been) (closed|suspended|locked)/i,
  /\bverif(y|ication) (required|needed|pending)\b/i,
  /\byour (access|account) (expire[sd]?|will be terminated)\b/i,
  /\basap\b/i, /\bdo not (delay|ignore|miss)\b/i,
];

// ── Fear & Threat Language ──────────────────────────────────────────────────
const FEAR_PATTERNS = [
  /\bunusual (activity|login|sign.in)\b/i, /\bsuspicious (activity|behavior|access)\b/i,
  /\bsecurity (alert|breach|warning|threat|issue)\b/i,
  /\byour (account|password|data) (has been|was) (compromised|stolen|hacked|breached|exposed)\b/i,
  /\bunauthorized (access|login|attempt)\b/i, /\bfraudulent (activity|transaction|charge)\b/i,
  /\bwe detected\b/i, /\bwe noticed\b/i, /\byour information (is at risk|may be at risk)\b/i,
  /\bidentity (theft|fraud)\b/i,
];

// ── Payment & Financial Request Patterns ───────────────────────────────────
const PAYMENT_PATTERNS = [
  /\bpay(ment)? (required|needed|pending|due|overdue)\b/i,
  /\bbank (transfer|wire|account)\b/i, /\bgift card[s]?\b/i,
  /\bwire transfer\b/i, /\bcryptocurrency\b/i, /\bbitcoin\b/i,
  /\bpay (via|using|through) (zelle|venmo|cashapp|western union|moneygram)\b/i,
  /\binvoice (attached|enclosed|overdue)\b/i,
  /\bpurchase order\b/i, /\brefund (pending|processing)\b/i,
  /\badd (your )?payment (method|information|details)\b/i,
];

// ── Credential Request Patterns ─────────────────────────────────────────────
const CREDENTIAL_PATTERNS = [
  /\b(enter|provide|update|confirm|re-?enter) (your )?(password|credentials|login|username)\b/i,
  /\bclick (here|below|the link) to (verify|confirm|update|login|sign in)\b/i,
  /\bverify your (account|identity|email|information)\b/i,
  /\bupdate your (account|billing|payment|personal) (information|details)\b/i,
  /\bsocial security (number|no\.?)\b/i, /\bssn\b/i,
  /\bdate of birth\b/i, /\bmother'?s maiden name\b/i,
  /\bconfirm your (identity|details|information)\b/i,
  /\bpassword (reset|change|update|expired)\b/i,
];

// ── Executive Impersonation Patterns ────────────────────────────────────────
const EXEC_IMPERSONATION_PATTERNS = [
  /\bthis is (the )?(ceo|cfo|coo|cto|president|director|manager|hr)\b/i,
  /\b(ceo|cfo|coo|cto) (request|instruction|approval|confirmation)\b/i,
  /\bper (my|the) (ceo|cfo|director|boss|manager|president)['s]? (request|instruction)\b/i,
  /\bconfidential (transfer|request|task|assignment)\b/i,
  /\bdo not (mention|discuss|share) this (with|to) anyone\b/i,
  /\bkeep this (between us|private|confidential)\b/i,
  /\bi'm (currently|presently) (in a meeting|traveling|unavailable|on a flight)\b/i,
];

// ── Brand Spoofing Language (display-name tricks) ───────────────────────────
const BRAND_DISPLAY_PATTERNS = [
  /\bamazon\s+(support|security|alert|customer service|prime)\b/i,
  /\bpaypal\s+(team|support|security|alert)\b/i,
  /\bmicrosoft\s+(security|support|account team|team)\b/i,
  /\bgoogle\s+(security|account|team|alert|workspace)\b/i,
  /\bapple\s+(id|support|security|team)\b/i,
  /\bnetflix\s+(billing|account|support|team)\b/i,
  /\btcs\s+(hr|recruitment|team|payroll)\b/i,
  /\binfosys\s+(hr|recruitment|team|payroll)\b/i,
  /\bwipro\s+(hr|recruitment|team)\b/i,
  /\birs\s+(refund|notice|agent|collection)\b/i,
  /\bfbi\s+(warrant|notice|alert)\b/i,
  /\bdhl\s+(delivery|shipment|package|tracking)\b/i,
  /\bfedex\s+(delivery|shipment|notice)\b/i,
  /\bups\s+(delivery|shipment|notice)\b/i,
];

// ── Grammar Anomaly Signals (coarse heuristics) ─────────────────────────────
const GRAMMAR_PATTERNS = [
  /\bDear (valued |esteemed |respected )?customer\b/i,  // overly formal non-personalized
  /\bDear (user|member|account holder|client)\b/i,
  /\bKindly (do|click|provide|update|confirm|download)\b/i,
  /\bPlease to (verify|confirm|click)\b/i,
  /\bwe (is|are) writing to (inform|notify|alert|warn)\b/i,
  /\byour (informations?|datas?)\b/i,  // plural misuse
  /\bdo the needful\b/i,
  /\brevert (back|at the earliest)\b/i,
];

// ── Reward Baiting ──────────────────────────────────────────────────────────
const REWARD_PATTERNS = [
  /\byou (have been|are|were) selected\b/i, /\byou (have |'ve )?(won|win|been awarded)\b/i,
  /\bcongratulations?\b/i, /\blottery\b/i, /\bprize\b/i,
  /\bfree (gift|money|prize|reward|iphone|laptop)\b/i,
  /\bclaim (your|the) (prize|reward|gift|money)\b/i,
  /\b\$\d{3,} (refund|reward|cashback)\b/i,
];

// ── Scoring weights ──────────────────────────────────────────────────────────
const CATEGORY_WEIGHTS = {
  urgency:       30,
  fear:          25,
  payment:       30,
  credential:    35,
  execImperson:  40,
  brandDisplay:  25,
  grammar:       15,
  reward:        20,
};

/**
 * Analyze text for linguistic phishing cues.
 * @param {string} text — email body, SMS text, draft, or clipboard content
 * @returns {{ score: number, flags: string[], details: string[] }}
 */
export function analyzeLinguistics(text) {
  if (!text || typeof text !== 'string') {
    return { score: 0, flags: [], details: [] };
  }

  const flags   = [];
  const details = [];
  let rawScore  = 0;

  function check(patterns, label, weight, categoryKey) {
    const matched = patterns.filter(p => p.test(text));
    if (matched.length > 0) {
      flags.push(label);
      // Scale: first match gives full weight, each additional gives 50% more (capped at 2×)
      const bonus = Math.min(matched.length - 1, 2) * weight * 0.5;
      rawScore += weight + bonus;
      details.push(`${label}: ${matched.length} pattern(s) matched`);
    }
  }

  check(URGENCY_PATTERNS,        'Urgency Language',          CATEGORY_WEIGHTS.urgency,      'urgency');
  check(FEAR_PATTERNS,           'Fear/Threat Language',      CATEGORY_WEIGHTS.fear,         'fear');
  check(PAYMENT_PATTERNS,        'Payment Request',           CATEGORY_WEIGHTS.payment,      'payment');
  check(CREDENTIAL_PATTERNS,     'Credential Request',        CATEGORY_WEIGHTS.credential,   'credential');
  check(EXEC_IMPERSONATION_PATTERNS, 'Executive Impersonation', CATEGORY_WEIGHTS.execImperson, 'execImperson');
  check(BRAND_DISPLAY_PATTERNS,  'Brand Display Spoofing',    CATEGORY_WEIGHTS.brandDisplay, 'brandDisplay');
  check(GRAMMAR_PATTERNS,        'Grammar Anomaly',           CATEGORY_WEIGHTS.grammar,      'grammar');
  check(REWARD_PATTERNS,         'Reward Baiting',            CATEGORY_WEIGHTS.reward,       'reward');

  // Normalize to 0–100
  const maxPossible = Object.values(CATEGORY_WEIGHTS).reduce((a, b) => a + b, 0) * 1.5;
  const score = Math.min(100, Math.round((rawScore / maxPossible) * 100));

  return { score, flags, details };
}
