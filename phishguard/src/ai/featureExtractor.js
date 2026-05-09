import { safeParseURL, shannonEntropy, extractRegisteredDomain, countOccurrences } from '../shared/utils.js';

/**
 * Extracts a numerical feature vector from a URL for the AI model.
 * 
 * Features:
 * 0: URL Length (normalized: length / 100)
 * 1: Number of Subdomains
 * 2: Path Entropy
 * 3: Number of '-' in domain
 * 4: Number of special characters in path (% + @)
 * 
 * @param {string} urlString 
 * @returns {number[]} Array of 5 numerical features
 */
export function extractFeatures(urlString) {
  const features = [0, 0, 0, 0, 0];
  const parsed = safeParseURL(urlString);
  
  if (!parsed) return features;

  const { hostname, pathname, search } = parsed;
  const fullPath = pathname + search;

  // Feature 0: URL Length (normalized slightly)
  features[0] = urlString.length / 100;

  // Feature 1: Number of Subdomains
  const domain = extractRegisteredDomain(hostname);
  const subdomainPart = hostname.replace('.' + domain, '');
  if (subdomainPart && subdomainPart !== hostname) {
    features[1] = subdomainPart.split('.').length;
  }

  // Feature 2: Path Entropy
  features[2] = shannonEntropy(fullPath);

  // Feature 3: Hyphens in domain (common in phishing)
  features[3] = countOccurrences(hostname, '-');

  // Feature 4: Suspicious chars in path
  features[4] = countOccurrences(fullPath, '%') + 
                countOccurrences(fullPath, '@');

  return features;
}
