/**
 * PhishGuard — Linguistic Analyzer
 * Detects urgency, fear, payment requests, and social engineering patterns.
 */

const URGENCY_PATTERNS = [
  /\bimmediate(ly)?\b/i, /\baction required\b/i, /\burgent\b/i, /\bexpire[ds]?\b/i,
  /\bfinal notice\b/i, /\blast chance\b/i, /\bwithin \d+ hours\b/i, /\bdeadline\b/i
];

const FEAR_PATTERNS = [
  /\bsuspended\b/i, /\blocked\b/i, /\bcompromised\b/i, /\bunauthorized\b/i,
  /\bsecurity alert\b/i, /\bviolation\b/i, /\bdeactivate[ds]?\b/i, /\billegal\b/i
];

const FINANCIAL_PATTERNS = [
  /\bpayment\b/i, /\bbank\b/i, /\btransfer\b/i, /\binvoice\b/i, /\bbill\b/i,
  /\bcrystal clear\b/i, /\bcrypto\b/i, /\bwallet\b/i, /\brefund\b/i
];

const CREDENTIAL_PATTERNS = [
  /\blogin\b/i, /\bpassword\b/i, /\bverify account\b/i, /\bcredentials\b/i,
  /\bauithenticate\b/i, /\bsign in\b/i, /\breset\b/i
];

/**
 * Analyzes text for linguistic risk factors.
 * @param {string} text 
 * @returns {number} Score 0-100
 */
export function analyzeLinguisticPatterns(text) {
  if (!text) return 0;
  
  let score = 0;
  const lowerText = text.toLowerCase();

  // Check patterns and add weights
  if (URGENCY_PATTERNS.some(p => p.test(lowerText))) score += 30;
  if (FEAR_PATTERNS.some(p => p.test(lowerText))) score += 30;
  if (FINANCIAL_PATTERNS.some(p => p.test(lowerText))) score += 20;
  if (CREDENTIAL_PATTERNS.some(p => p.test(lowerText))) score += 20;

  // Cap at 100
  return Math.min(100, score);
}
