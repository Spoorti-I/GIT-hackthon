/**
 * PhishGuard — NLP Engine
 * Lightweight client-side text classification for detecting phishing intent in chat messages and emails.
 */

const VECTORS = {
  URGENCY: [
    /urgent/i, /immediately/i, /expires\s*in/i, /action\s*required/i,
    /suspended/i, /final\s*warning/i, /within\s*\d+\s*(hours|mins|minutes)/i,
    /shortlisted/i, /congratulations/i
  ],
  AUTHORITY: [
    /\bceo\b/i, /it\s*support/i, /admin(istrator)?/i, /\bhr\b/i, 
    /\bgovernment\b/i, /security\s*team/i, /support\s*desk/i,
    /grid\s*control/i, /hospital\s*admin/i, /electricity\s*board/i
  ],
  ACTION: [
    /login/i, /\botp\b/i, /click\s*here/i, /verify/i, 
    /update\s*(your)?\s*account/i, /password/i,
    /transfer/i, /wire/i, /\bmoney\b/i, /\bhelp\b/i
  ]
};

/**
 * Analyzes a text string for phishing intent.
 * @param {string} text The text to analyze
 * @returns {Object} { isPhishing: boolean, score: number, matches: Object }
 */
export function analyzeTextForPhishing(text) {
  if (!text || text.length < 10) {
    return { isPhishing: false, score: 0, matches: {} };
  }

  const matches = {
    urgency: [],
    authority: [],
    action: []
  };

  let score = 0;

  // Check Urgency
  for (const regex of VECTORS.URGENCY) {
    if (regex.test(text)) {
      matches.urgency.push(regex.toString());
      score += 35;
    }
  }

  // Check Authority
  for (const regex of VECTORS.AUTHORITY) {
    if (regex.test(text)) {
      matches.authority.push(regex.toString());
      score += 25;
    }
  }

  // Check Action
  for (const regex of VECTORS.ACTION) {
    if (regex.test(text)) {
      matches.action.push(regex.toString());
      score += 30;
    }
  }

  // Additional context points: combination of vectors
  let activeVectors = 0;
  if (matches.urgency.length > 0) activeVectors++;
  if (matches.authority.length > 0) activeVectors++;
  if (matches.action.length > 0) activeVectors++;

  // Synergy bonus: If all three vectors are present, it's highly likely to be phishing
  if (activeVectors === 3) score += 50;
  else if (activeVectors === 2) score += 20;

  return {
    isPhishing: score >= 80, // Threshold for text phishing
    score: Math.min(score, 100),
    matches
  };
}
