/**
 * PhishGuard — Utility Functions
 * Pure utility functions used across the analyzer.
 */

/**
 * Compute Levenshtein edit distance between two strings.
 * Uses the classic DP approach — O(m*n) but strings are short.
 * @param {string} a
 * @param {string} b
 * @returns {number}
 */
export function levenshteinDistance(a, b) {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;

  // Create DP table
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] = 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }
  }
  return dp[m][n];
}

/**
 * Compute Shannon entropy of a string.
 * High entropy (>3.5) suggests base64 or random identifiers.
 * @param {string} str
 * @returns {number}
 */
export function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Extract the registered domain (eTLD+1 approximation) from a hostname.
 * Simple heuristic: last two parts of hostname, handling common ccSLDs.
 * @param {string} hostname
 * @returns {string}
 */
export function extractRegisteredDomain(hostname) {
  if (!hostname) return '';
  // Remove port if present
  hostname = hostname.split(':')[0];

  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;

  // Common two-part ccTLDs (simplified)
  const twoPartTLDs = new Set([
    'co.uk', 'co.in', 'co.jp', 'co.nz', 'co.za', 'co.au', 'co.kr',
    'com.au', 'com.br', 'com.cn', 'com.ar', 'com.mx', 'com.sg',
    'net.au', 'org.au', 'gov.au', 'edu.au',
    'gov.uk', 'org.uk', 'me.uk', 'ltd.uk', 'plc.uk',
  ]);

  const lastTwo = parts.slice(-2).join('.');
  if (twoPartTLDs.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join('.');
  }
  return lastTwo;
}

/**
 * Extract the TLD from a hostname.
 * @param {string} hostname
 * @returns {string}
 */
export function extractTLD(hostname) {
  if (!hostname) return '';
  const parts = hostname.split(':')[0].split('.');
  return parts[parts.length - 1].toLowerCase();
}

/**
 * Check if hostname contains Punycode (international domain).
 * @param {string} hostname
 * @returns {boolean}
 */
export function isPunycode(hostname) {
  return hostname.toLowerCase().includes('xn--');
}

/**
 * Check if host is an IP address (v4 or v6).
 * @param {string} host
 * @returns {boolean}
 */
export function isIPAddress(host) {
  // Remove port
  host = host.split(':')[0].replace(/^\[/, '').replace(/\]$/, '');
  // IPv4
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/.test(host);
  // IPv6 (simple check)
  const ipv6 = host.includes(':');
  return ipv4 || ipv6;
}

/**
 * Count occurrences of a substring in a string.
 * @param {string} str
 * @param {string} sub
 * @returns {number}
 */
export function countOccurrences(str, sub) {
  let count = 0;
  let pos = 0;
  while ((pos = str.indexOf(sub, pos)) !== -1) {
    count++;
    pos += sub.length;
  }
  return count;
}

/**
 * Check if a URL is a local/private network URL.
 * @param {string} hostname
 * @returns {boolean}
 */
export function isPrivateNetwork(hostname) {
  hostname = hostname.split(':')[0];
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname.startsWith('192.168.') ||
    hostname.startsWith('10.') ||
    hostname.startsWith('172.') ||
    hostname === '::1'
  );
}

/**
 * Safely parse a URL and return the URL object or null.
 * @param {string} urlString
 * @returns {URL|null}
 */
export function safeParseURL(urlString) {
  try {
    return new URL(urlString);
  } catch {
    return null;
  }
}

/**
 * Compute a simple hash of a string (for display, not cryptography).
 * @param {string} str
 * @returns {string}
 */
export function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = (hash << 5) - hash + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(16);
}

/**
 * Truncate a string to maxLength with ellipsis.
 * @param {string} str
 * @param {number} maxLength
 * @returns {string}
 */
export function truncate(str, maxLength = 60) {
  if (!str || str.length <= maxLength) return str;
  return str.slice(0, maxLength - 3) + '...';
}

/**
 * Format a timestamp as a readable string.
 * @param {number} ts - Unix timestamp ms
 * @returns {string}
 */
export function formatTimestamp(ts) {
  return new Date(ts).toLocaleTimeString(undefined, {
    hour:   '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}
