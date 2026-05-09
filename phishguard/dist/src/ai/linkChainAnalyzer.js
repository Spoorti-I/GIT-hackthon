/**
 * PhishGuard — Link Chain Analyzer (AI Trust Layer)
 * Detects redirect chains, URL shorteners, Punycode, Unicode spoofing,
 * and hidden tracking parameters in extracted links.
 * Runs entirely locally.
 */

import { URL_SHORTENERS } from '../analyzer/shortenerList.js';

// Known tracking parameter keys that may hide real destination
const TRACKING_PARAMS = new Set([
  'redirect', 'redirect_uri', 'redirect_url', 'next', 'return',
  'returnurl', 'return_url', 'redir', 'continue', 'dest', 'destination',
  'target', 'url', 'link', 'goto', 'forward', 'out', 'exit',
]);

// Suspicious TLDs for link context
const SUSPICIOUS_TLD_PATTERN = /\.(xyz|tk|ml|ga|cf|gq|top|click|link|work|party|bid|pw|cc|su|ru|cn|info|biz)$/i;

// Punycode detection
function hasPunycode(url) {
  try {
    return url.includes('xn--') || new URL(url).hostname.includes('xn--');
  } catch { return false; }
}

// Unicode homograph detection (non-ASCII characters in hostname)
function hasUnicodeHomograph(url) {
  try {
    const hostname = new URL(url).hostname;
    return /[^\x00-\x7F]/.test(hostname); // non-ASCII
  } catch { return false; }
}

// Extract all URLs from a block of text
function extractUrlsFromText(text) {
  if (!text) return [];
  const urlRegex = /https?:\/\/[^\s<>"')\]]+/gi;
  return [...text.matchAll(urlRegex)].map(m => m[0]);
}

// Extract domain from URL safely
function getDomain(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return null; }
}

function getTLD(hostname) {
  if (!hostname) return '';
  const parts = hostname.split('.');
  return parts[parts.length - 1];
}

/**
 * Analyze links extracted from message content.
 * @param {Object} params
 * @param {string}   [params.body]        — Full message text to extract URLs from
 * @param {string[]} [params.urls]        — Pre-extracted URLs (optional)
 * @param {string}   [params.displayUrl]  — The URL shown to user (vs actual href)
 * @param {string}   [params.actualUrl]   — The real href (for mismatch detection)
 * @returns {{ score: number, flags: string[], suspiciousLinks: string[] }}
 */
export function analyzeLinkChain({ body, urls = [], displayUrl, actualUrl } = {}) {
  const flags          = [];
  const suspiciousLinks = [];
  let score            = 0;

  // Combine pre-extracted + body-extracted URLs
  const allUrls = [...new Set([...urls, ...extractUrlsFromText(body)])];

  for (const rawUrl of allUrls) {
    let url = rawUrl;
    // Strip trailing punctuation
    url = url.replace(/[.,;:!?)]+$/, '');

    const hostname = getDomain(url);
    if (!hostname) continue;

    const tld     = getTLD(hostname);
    let linkScore = 0;
    const linkFlags = [];

    // 1. Known URL shortener
    if (URL_SHORTENERS.has(hostname)) {
      linkScore += 35;
      linkFlags.push(`URL shortener: "${hostname}"`);
    }

    // 2. Punycode / IDN
    if (hasPunycode(url)) {
      linkScore += 30;
      linkFlags.push(`Punycode/IDN in link: "${hostname}"`);
    }

    // 3. Unicode homograph
    if (hasUnicodeHomograph(url)) {
      linkScore += 30;
      linkFlags.push(`Unicode homograph in link: "${hostname}"`);
    }

    // 4. Suspicious TLD
    if (SUSPICIOUS_TLD_PATTERN.test('.' + tld)) {
      linkScore += 20;
      linkFlags.push(`Suspicious TLD ".${tld}" in link`);
    }

    // 5. Tracking/redirect parameters
    try {
      const parsed = new URL(url);
      for (const [key] of parsed.searchParams) {
        if (TRACKING_PARAMS.has(key.toLowerCase())) {
          linkScore += 15;
          linkFlags.push(`Redirect parameter "?${key}=" in link`);
          break;
        }
      }
    } catch {}

    // 6. Multiple redirects in URL (double HTTP)
    if (/https?:\/\/.*https?:\/\//i.test(url)) {
      linkScore += 25;
      linkFlags.push(`Nested redirect detected in link`);
    }

    // 7. IP address as link host
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      linkScore += 25;
      linkFlags.push(`IP address used as link host: "${hostname}"`);
    }

    if (linkScore > 0) {
      suspiciousLinks.push(url);
      score += linkScore;
      flags.push(...linkFlags);
    }
  }

  // 8. Display URL vs actual URL mismatch (text says amazon.com but links to evil.com)
  if (displayUrl && actualUrl) {
    const displayDomain = getDomain(displayUrl);
    const actualDomain  = getDomain(actualUrl);
    if (displayDomain && actualDomain && displayDomain !== actualDomain) {
      score += 40;
      flags.push(`Link mismatch: shown "${displayDomain}" but points to "${actualDomain}"`);
    }
  }

  return {
    score:          Math.min(100, score),
    flags:          [...new Set(flags)],
    suspiciousLinks,
    linkCount:      allUrls.length,
  };
}
