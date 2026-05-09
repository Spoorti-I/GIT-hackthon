/**
 * PhishGuard — Brand Impersonation Detector
 * Detects if a brand name is being used in a suspicious context.
 */

import { KNOWN_BRANDS } from '../analyzer/brandList.js';

/**
 * Detects brand impersonation.
 * @param {string} text - Message body or sender name
 * @param {string} domain - The actual domain of the site/email
 * @returns {number} Score 0-100
 */
export function detectBrandImpersonation(text, domain) {
  if (!text) return 0;
  
  const lowerText = text.toLowerCase();
  const lowerDomain = domain ? domain.toLowerCase() : '';

  for (const brand of KNOWN_BRANDS) {
    // If brand is mentioned but it's NOT the actual domain
    if (lowerText.includes(brand) && !lowerDomain.includes(brand)) {
      // High suspicion if brand name is mentioned in a non-brand domain
      return 80;
    }
  }

  return 0;
}
