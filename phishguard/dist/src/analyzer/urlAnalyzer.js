/**
 * PhishGuard — URL Heuristic Analyzer
 * The core analysis engine. Runs all heuristic checks and returns
 * an array of triggered rules with points and explanations.
 *
 * All checks are synchronous and run in < 1ms typically.
 * Async threat intel checks are handled separately and merged.
 */

import { RULES, RULE_META } from '../shared/types.js';
import {
  levenshteinDistance,
  shannonEntropy,
  extractRegisteredDomain,
  extractTLD,
  isPunycode,
  isIPAddress,
  isPrivateNetwork,
  safeParseURL,
  countOccurrences,
} from '../shared/utils.js';
import { KNOWN_BRANDS, BRAND_SUBDOMAIN_PATTERNS } from './brandList.js';
import { SUSPICIOUS_TLDS } from './suspiciousTlds.js';
import { URL_SHORTENERS } from './shortenerList.js';
import { checkLocalBlocklist } from './localBlocklist.js';
import { analyzeUrlWithAI } from '../ai/modelManager.js';

/** Suspicious keywords commonly found in phishing URLs */
const SUSPICIOUS_KEYWORDS = [
  'login', 'signin', 'sign-in', 'verify', 'verification',
  'account', 'secure', 'security', 'update', 'confirm',
  'banking', 'password', 'credential', 'authenticate',
  'support', 'helpdesk', 'recover', 'recovery',
  'suspend', 'suspended', 'unusual', 'activity',
  'click', 'validate', 'unlock', 'alert',
];

/**
 * @typedef {Object} RuleResult
 * @property {string} rule         - Rule ID from RULES constant
 * @property {number} points       - Score contribution (can be negative)
 * @property {string} label        - Human-readable rule label
 * @property {string} reason       - Specific explanation for this URL
 * @property {string} category     - Rule category (url/domain/connection/intel/page/user)
 * @property {boolean} triggered   - Whether the rule fired
 */

/**
 * @typedef {Object} AnalysisResult
 * @property {string}       url          - Full URL analyzed
 * @property {string}       hostname     - Parsed hostname
 * @property {string}       domain       - Registered domain
 * @property {string}       tld          - Top-level domain
 * @property {RuleResult[]} rules        - All triggered rules
 * @property {number}       score        - Total risk score
 * @property {number}       timestamp    - When analysis ran
 * @property {boolean}      isAsync      - Whether async checks are pending
 */

/**
 * Run synchronous heuristic analysis on a URL.
 * @param {string} urlString - The URL to analyze
 * @returns {AnalysisResult}
 */
export function analyzeURL(urlString) {
  const startTime = performance.now();
  const triggered = [];

  // ── Parse URL ──────────────────────────────────────────────────────────────
  const parsed = safeParseURL(urlString);
  if (!parsed) {
    return {
      url:       urlString,
      hostname:  '',
      domain:    '',
      tld:       '',
      rules:     [],
      score:     0,
      timestamp: Date.now(),
      isAsync:   false,
      parseError: true,
      analysisMs: performance.now() - startTime,
    };
  }

  const { protocol, hostname, pathname, search, port, href } = parsed;
  const domain   = extractRegisteredDomain(hostname);
  const tld      = extractTLD(hostname);
  const fullUrl  = href;
  const urlLower = fullUrl.toLowerCase();

  // Helper to add a triggered rule
  function addRule(ruleId, reasonOverride = null) {
    const meta = RULE_META[ruleId];
    triggered.push({
      rule:      ruleId,
      points:    meta.weight,
      label:     meta.label,
      reason:    reasonOverride || meta.description,
      category:  meta.category,
      triggered: true,
    });
  }

  // ── Rule 1: HTTP Scheme ────────────────────────────────────────────────────
  if (protocol === 'http:' && !isPrivateNetwork(hostname)) {
    addRule(RULES.HTTP_SCHEME, `Connection is unencrypted (HTTP). Data can be intercepted.`);
  }

  // ── Rule 2: IP-based Host ─────────────────────────────────────────────────
  if (isIPAddress(hostname)) {
    addRule(RULES.IP_HOST, `Hostname is an IP address (${hostname}). Legitimate sites use domain names.`);
  }

  // ── Rule 3: Punycode / IDN Homograph ──────────────────────────────────────
  if (isPunycode(hostname)) {
    addRule(RULES.PUNYCODE, `Hostname uses internationalized characters (${hostname}) that can visually impersonate Latin letters.`);
  }

  // ── Rule 4: @ Symbol in URL ───────────────────────────────────────────────
  if (fullUrl.includes('@')) {
    addRule(RULES.AT_IN_URL, `URL contains "@" which tricks browsers — everything before @ is ignored as credentials.`);
  }

  // ── Rule 5: Misleading Subdomain (Brand in Subdomain) ────────────────────
  const hostParts = hostname.split('.');
  if (hostParts.length >= 3) {
    const subdomainPart = hostParts.slice(0, -2).join('.').toLowerCase();
    for (const brand of BRAND_SUBDOMAIN_PATTERNS) {
      if (subdomainPart.includes(brand) && !domain.includes(brand)) {
        addRule(
          RULES.MISLEADING_SUBDOMAIN,
          `"${brand}" appears in subdomain (${subdomainPart}) but the actual domain is "${domain}".`
        );
        break;
      }
    }
  }

  // ── Rule 6: Excessive Subdomain Depth ─────────────────────────────────────
  if (hostParts.length > 4) {
    addRule(
      RULES.SUBDOMAIN_DEPTH,
      `Domain has ${hostParts.length - 2} subdomain levels (${hostname}). More than 3 is unusual.`
    );
  }

  // ── Rule 7: Suspicious TLD ────────────────────────────────────────────────
  if (SUSPICIOUS_TLDS.has(tld)) {
    addRule(RULES.SUSPICIOUS_TLD, `TLD ".${tld}" is frequently abused in phishing campaigns.`);
  }

  // ── Rule 8: Typosquatting ─────────────────────────────────────────────────
  // Extract the primary domain name (without TLD) for comparison
  const domainWithoutTLD = domain.split('.').slice(0, -1).join('').toLowerCase();
  if (domainWithoutTLD.length >= 4) {
    let closestBrand = null;
    let minDistance  = Infinity;

    for (const brand of KNOWN_BRANDS) {
      if (Math.abs(brand.length - domainWithoutTLD.length) > 3) continue; // Skip obviously different lengths
      const dist = levenshteinDistance(domainWithoutTLD, brand);
      if (dist > 0 && dist <= 2 && dist < minDistance) {
        minDistance  = dist;
        closestBrand = brand;
      }
    }

    if (closestBrand) {
      addRule(
        RULES.TYPOSQUATTING,
        `Domain "${domainWithoutTLD}" is only ${minDistance} character(s) away from "${closestBrand}". Possible typosquatting.`
      );
    }
  }

  // ── Rule 9: Excessive URL Length ──────────────────────────────────────────
  if (fullUrl.length > 150) {
    addRule(RULES.LONG_URL, `URL is ${fullUrl.length} characters long. Very long URLs often hide real destinations.`);
  }

  // ── Rule 10: Excessive % Encoding ────────────────────────────────────────
  const percentCount = countOccurrences(fullUrl, '%');
  if (percentCount > 3) {
    addRule(
      RULES.EXCESS_ENCODING,
      `URL contains ${percentCount} %-encoded characters, suggesting possible obfuscation.`
    );
  }

  // ── Rule 11: High-Entropy Segment ─────────────────────────────────────────
  const pathSegments = pathname.split('/').filter(Boolean);
  for (const segment of pathSegments) {
    if (segment.length >= 16) {
      const entropy = shannonEntropy(segment);
      if (entropy > 3.8) {
        addRule(
          RULES.HIGH_ENTROPY,
          `Path segment "${segment.slice(0, 20)}..." has high entropy (${entropy.toFixed(2)}), suggesting encoded or random data.`
        );
        break;
      }
    }
  }

  // ── Rule 12: Very Long Query String ───────────────────────────────────────
  if (search && search.length > 200) {
    addRule(
      RULES.LONG_QUERY,
      `Query string is ${search.length} characters long. May be hiding redirect destination or payloads.`
    );
  }

  // ── Rule 13: Known URL Shortener ─────────────────────────────────────────
  if (URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(domain)) {
    addRule(RULES.URL_SHORTENER, `"${hostname}" is a URL shortener. Real destination is hidden.`);
  }

  // ── Rule 14: Suspicious Keywords ─────────────────────────────────────────
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter(kw => urlLower.includes(kw));
  if (foundKeywords.length >= 2) {
    addRule(
      RULES.SUSPICIOUS_KEYWORDS,
      `URL contains phishing-associated keywords: ${foundKeywords.slice(0, 4).map(k => `"${k}"`).join(', ')}.`
    );
  }

  // ── Rule 15: Double Slash in Path ─────────────────────────────────────────
  if (pathname.includes('//')) {
    addRule(RULES.DOUBLE_SLASH, `URL path contains "//" which can indicate URL manipulation.`);
  }

  // ── Rule 16: Non-Standard Port ────────────────────────────────────────────
  const portNum = port ? parseInt(port, 10) : null;
  if (portNum && portNum !== 80 && portNum !== 443 && !isPrivateNetwork(hostname)) {
    addRule(
      RULES.NON_STANDARD_PORT,
      `Non-standard port ${portNum} is used. Legitimate sites typically use 80 or 443.`
    );
  }

  // ── Rule 17: Local Blocklist ──────────────────────────────────────────────
  if (checkLocalBlocklist(domain, hostname, fullUrl)) {
    addRule(RULES.BLOCKLIST_HIT, `"${domain}" matches the local phishing blocklist.`);
  }

  // ── Rule 18: Newly Registered Domain (NRD) Heuristic ─────────────────────
  // Flags domains with suspicious TLDs and High Entropy/Randomness
  const domainEntropy = shannonEntropy(domainWithoutTLD);
  if (SUSPICIOUS_TLDS.has(tld) && domainEntropy > 3.2 && domainWithoutTLD.length > 8) {
    addRule(RULES.NRD_HEURISTIC, `Domain "${domain}" has high randomness and a suspicious TLD, typical of newly registered phishing domains.`);
  }

  // ── Rule 19: HTTPS Bonus (only if no other risk signals) ─────────────────
  if (protocol === 'https:' && triggered.length === 0) {
    addRule(RULES.HTTPS_BONUS, `Site uses HTTPS. Minor positive signal (HTTPS alone doesn't guarantee safety).`);
  }

  // ── Rule 19: AI Threat Model ──────────────────────────────────────────────
  const aiResult = analyzeUrlWithAI(fullUrl);
  if (aiResult.isPhishing) {
    addRule(RULES.AI_PHISHING_MODEL, `Client-side AI model flagged this URL as highly suspicious with ${aiResult.confidence}% confidence.`);
  }

  const score = triggered.reduce((sum, r) => sum + r.points, 0);
  const analysisMs = performance.now() - startTime;

  return {
    url:        fullUrl,
    hostname,
    domain,
    tld,
    rules:      triggered,
    score:      Math.max(0, score), // Never negative
    timestamp:  Date.now(),
    isAsync:    false,
    analysisMs,
  };
}

/**
 * Merge async threat intel results into an existing AnalysisResult.
 * @param {AnalysisResult} result
 * @param {Object} intel - { safeBrowsing: { hit, threats }, customBlocklist: bool, whitelisted: bool }
 * @returns {AnalysisResult}
 */
export function mergeIntelResults(result, intel) {
  const extraRules = [...result.rules];

  if (intel.whitelisted) {
    const meta = RULE_META[RULES.WHITELISTED];
    extraRules.push({
      rule:      RULES.WHITELISTED,
      points:    meta.weight,
      label:     meta.label,
      reason:    `You have whitelisted "${result.domain}".`,
      category:  meta.category,
      triggered: true,
    });
  }

  if (intel.customBlocklist) {
    const meta = RULE_META[RULES.BLOCKLIST_HIT];
    // Only add if not already in rules
    if (!extraRules.some(r => r.rule === RULES.BLOCKLIST_HIT)) {
      extraRules.push({
        rule:      RULES.BLOCKLIST_HIT,
        points:    meta.weight,
        label:     meta.label,
        reason:    `"${result.domain}" matches your custom imported blocklist.`,
        category:  meta.category,
        triggered: true,
      });
    }
  }

  if (intel.safeBrowsing?.hit) {
    const meta = RULE_META[RULES.SAFE_BROWSING_HIT];
    extraRules.push({
      rule:      RULES.SAFE_BROWSING_HIT,
      points:    meta.weight,
      label:     meta.label,
      reason:    `Google Safe Browsing flagged this as: ${intel.safeBrowsing.threats.join(', ')}.`,
      category:  meta.category,
      triggered: true,
    });
  }

  const newScore = Math.max(0, extraRules.reduce((sum, r) => sum + r.points, 0));

  return {
    ...result,
    rules:   extraRules,
    score:   newScore,
    isAsync: false,
  };
}
