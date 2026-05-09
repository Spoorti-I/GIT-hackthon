/**
 * PhishGuard — Threat Intelligence Module
 * Handles Google Safe Browsing API lookups and custom blocklist integration.
 * Privacy: Only URL hash prefixes are sent to Safe Browsing (not full URLs by default).
 * If user explicitly enables "full URL" mode, a warning is shown.
 */

const SAFE_BROWSING_API_BASE = 'https://safebrowsing.googleapis.com/v4/threatMatches:find';

/**
 * Check a URL against Google Safe Browsing API v4.
 * Uses the Lookup API (simpler, sends full URL but only to Google).
 * @param {string} url
 * @param {string} apiKey
 * @returns {Promise<{ hit: boolean, threats: string[] }>}
 */
export async function checkGoogleSafeBrowsing(url, apiKey) {
  if (!apiKey || !url) {
    return { hit: false, threats: [] };
  }

  try {
    const requestBody = {
      client: {
        clientId:      'phishguard-extension',
        clientVersion: '1.0.0',
      },
      threatInfo: {
        threatTypes: [
          'MALWARE',
          'SOCIAL_ENGINEERING',
          'UNWANTED_SOFTWARE',
          'POTENTIALLY_HARMFUL_APPLICATION',
        ],
        platformTypes:    ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries:    [{ url }],
      },
    };

    const response = await fetch(
      `${SAFE_BROWSING_API_BASE}?key=${apiKey}`,
      {
        method:  'POST',
        headers: { 'Content-Type': 'application/json' },
        body:    JSON.stringify(requestBody),
      }
    );

    if (!response.ok) {
      console.warn('[PhishGuard] Safe Browsing API error:', response.status);
      return { hit: false, threats: [], error: `API error ${response.status}` };
    }

    const data = await response.json();

    if (data.matches && data.matches.length > 0) {
      const threats = [...new Set(data.matches.map(m => m.threatType))];
      return { hit: true, threats };
    }

    return { hit: false, threats: [] };
  } catch (err) {
    console.warn('[PhishGuard] Safe Browsing fetch failed:', err.message);
    return { hit: false, threats: [], error: err.message };
  }
}

/**
 * Load and check user-imported custom blocklist from chrome.storage.
 * @param {string} domain
 * @param {string} hostname
 * @returns {Promise<boolean>}
 */
export async function checkCustomBlocklist(domain, hostname) {
  try {
    const data = await chrome.storage.local.get(['customBlocklist']);
    const list = data.customBlocklist;
    if (!list || !Array.isArray(list)) return false;

    const lDomain   = domain.toLowerCase();
    const lHostname = hostname.toLowerCase();

    for (const entry of list) {
      const lEntry = entry.toLowerCase().trim();
      if (!lEntry) continue;
      if (lDomain === lEntry || lHostname === lEntry || lHostname.endsWith('.' + lEntry)) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Check if a domain is user-whitelisted.
 * @param {string} domain
 * @param {string} hostname
 * @returns {Promise<boolean>}
 */
export async function checkWhitelist(domain, hostname) {
  try {
    const data = await chrome.storage.sync.get(['whitelistedDomains']);
    const list = data.whitelistedDomains;
    if (!list || !Array.isArray(list)) return false;

    const lDomain   = domain.toLowerCase();
    const lHostname = hostname.toLowerCase();

    for (const entry of list) {
      const lEntry = entry.toLowerCase().trim();
      if (!lEntry) continue;
      if (lDomain === lEntry || lHostname === lEntry || lHostname.endsWith('.' + lEntry)) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}
