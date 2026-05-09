/**
 * PhishGuard — Link Chain Analyzer
 * Analyzes links for redirect chains, obfuscation, and suspicious parameters.
 */

import { URL_SHORTENERS } from '../analyzer/shortenerList.js';
import { isPunycode } from '../shared/utils.js';

/**
 * Analyzes a link for suspicious traits.
 * @param {string} urlString 
 * @returns {number} Score 0-100
 */
export function analyzeLinkChain(urlString) {
  if (!urlString) return 0;
  
  let score = 0;
  try {
    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();

    // 1. URL Shorteners
    if (URL_SHORTENERS.has(hostname)) {
      score += 40;
    }

    // 2. Punycode
    if (isPunycode(hostname)) {
      score += 50;
    }

    // 3. Hidden tracking/redirect parameters
    if (url.search.includes('redirect=') || url.search.includes('url=') || url.search.includes('next=')) {
      score += 20;
    }

    // 4. Excessive depth or length (already in heuristics, but added here for AI trust)
    if (url.pathname.split('/').length > 5) {
      score += 10;
    }

  } catch (e) {
    return 0;
  }

  return Math.min(100, score);
}
