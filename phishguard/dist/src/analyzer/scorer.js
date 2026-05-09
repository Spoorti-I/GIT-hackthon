/**
 * PhishGuard — Scoring Engine
 * Maps the raw risk score from the analyzer to a category (safe/suspicious/phishing).
 * Provides sorted/ranked rule explanations for the popup UI.
 */

import { RISK_CATEGORY, SCORE_THRESHOLDS, BADGE_CONFIG, RULES } from '../shared/types.js';

/**
 * Classify a score into a risk category.
 * @param {number} score
 * @returns {string} - One of RISK_CATEGORY values
 */
export function scoreToCategory(score) {
  if (score <= SCORE_THRESHOLDS.SAFE_MAX)       return RISK_CATEGORY.SAFE;
  if (score <= SCORE_THRESHOLDS.SUSPICIOUS_MAX)  return RISK_CATEGORY.SUSPICIOUS;
  return RISK_CATEGORY.PHISHING;
}

/**
 * Get badge configuration for a category.
 * @param {string} category
 * @returns {{ text: string, color: string, bg: string }}
 */
export function getBadgeConfig(category) {
  return BADGE_CONFIG[category] || BADGE_CONFIG[RISK_CATEGORY.UNKNOWN];
}

/**
 * Produce a final scored result with category, badge, top reasons, etc.
 * @param {import('./urlAnalyzer').AnalysisResult} analysisResult
 * @returns {ScoredResult}
 */
export function scoreResult(analysisResult) {
  const { score, rules } = analysisResult;

  // Handle whitelisted domains
  const isWhitelisted = rules.some(r => r.rule === RULES.WHITELISTED);
  
  // Rule: If ANY rule with points > 0 triggered, we cannot be SAFE.
  // We floor the score to just above SAFE_MAX if it was negative/too low.
  let effectiveScore = isWhitelisted ? 0 : score;
  const hasThreatSignals = rules.some(r => r.points > 0);
  
  if (hasThreatSignals && effectiveScore <= SCORE_THRESHOLDS.SAFE_MAX) {
    effectiveScore = SCORE_THRESHOLDS.SAFE_MAX + 1; // Force into SUSPICIOUS
  }

  // Ensure no negative scores (floor at 0)
  effectiveScore = Math.max(0, effectiveScore);

  const category    = isWhitelisted ? RISK_CATEGORY.SAFE : scoreToCategory(effectiveScore);
  const badgeConfig = getBadgeConfig(category);

  // Sort rules by impact (highest weight first), negatives last
  const sortedRules = [...rules].sort((a, b) => {
    // Positive contributors first, sorted desc
    if (a.points > 0 && b.points > 0) return b.points - a.points;
    if (a.points < 0 && b.points < 0) return a.points - b.points;
    return b.points - a.points;
  });

  // Top 3 most impactful positive rules for summary display
  const topReasons = sortedRules
    .filter(r => r.points > 0)
    .slice(0, 3);

  // Category-specific advice
  const advice = getAdvice(category);

  // Risk percentage (0–100 display)
  const riskPercent = Math.min(100, Math.round((effectiveScore / 100) * 100));

  return {
    ...analysisResult,
    score:        effectiveScore,
    category,
    badge:        badgeConfig,
    sortedRules,
    topReasons,
    advice,
    riskPercent,
    isWhitelisted,
  };
}

/**
 * @typedef {Object} ScoredResult
 * @property {string}   url
 * @property {string}   hostname
 * @property {string}   domain
 * @property {string}   category
 * @property {number}   score
 * @property {number}   riskPercent
 * @property {Object}   badge
 * @property {Array}    sortedRules
 * @property {Array}    topReasons
 * @property {string[]} advice
 * @property {boolean}  isWhitelisted
 */

/**
 * Get actionable advice based on risk category.
 * @param {string} category
 * @returns {string[]}
 */
function getAdvice(category) {
  switch (category) {
    case RISK_CATEGORY.PHISHING:
      return [
        '🚫 Do NOT enter any passwords, credit card numbers, or personal information.',
        '🔒 Close this tab immediately.',
        '📧 If you arrived via email, mark it as phishing and delete it.',
        '🔑 If you already entered credentials, change your passwords immediately.',
      ];
    case RISK_CATEGORY.SUSPICIOUS:
      return [
        '⚠️ Proceed with caution — this site shows suspicious signals.',
        '🔐 Do not enter sensitive information unless you are certain this is legitimate.',
        '🔍 Verify the URL carefully — look for typos or unusual domain names.',
        '📌 If you were redirected here unexpectedly, close this tab.',
      ];
    case RISK_CATEGORY.SAFE:
      return [
        '✅ This site appears safe based on our analysis.',
        '💡 Always stay alert — phishers constantly create new sites.',
        '🔒 Ensure your browser shows a valid security certificate (padlock icon).',
      ];
    default:
      return ['Analysis unavailable for this URL.'];
  }
}

/**
 * Generate a plain-text risk report for clipboard copy.
 * @param {ScoredResult} result
 * @returns {string}
 */
export function generateRiskReport(result) {
  const lines = [
    '═══════════════════════════════════════',
    '  PhishGuard Risk Report',
    '═══════════════════════════════════════',
    `  URL:       ${result.url}`,
    `  Domain:    ${result.domain}`,
    `  Risk:      ${result.category.toUpperCase()} (Score: ${result.score})`,
    `  Analyzed:  ${new Date(result.timestamp).toLocaleString()}`,
    '───────────────────────────────────────',
    '  Risk Factors:',
  ];

  for (const rule of result.sortedRules.filter(r => r.points > 0)) {
    lines.push(`  [+${rule.points}] ${rule.label}`);
    lines.push(`         ${rule.reason}`);
  }

  if (result.sortedRules.some(r => r.points < 0)) {
    lines.push('  Positive Signals:');
    for (const rule of result.sortedRules.filter(r => r.points < 0)) {
      lines.push(`  [${rule.points}] ${rule.label}`);
    }
  }

  lines.push('───────────────────────────────────────');
  lines.push('  Advice:');
  for (const a of result.advice) {
    lines.push(`  ${a}`);
  }
  lines.push('═══════════════════════════════════════');
  lines.push('  PhishGuard — Privacy-first phishing detection');
  lines.push('  Analysis runs locally. No browsing data stored.');

  return lines.join('\n');
}
