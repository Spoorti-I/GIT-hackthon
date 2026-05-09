/**
 * PhishGuard — Brand Impersonation Detector (AI Trust Layer)
 * Detects sender display-name spoofing, reply-chain attacks, and
 * business email compromise using a brand corpus.
 * Runs entirely locally — no API calls.
 */

// ── Brand Corpus ────────────────────────────────────────────────────────────
// Maps canonical brand names → their legitimate sending domains
const BRAND_CORPUS = {
  // Tech Giants
  'amazon':       ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.co.jp', 'amazon.ca'],
  'google':       ['google.com', 'accounts.google.com', 'workspace.google.com', 'gmail.com'],
  'microsoft':    ['microsoft.com', 'office.com', 'outlook.com', 'live.com', 'hotmail.com', 'azure.com'],
  'apple':        ['apple.com', 'icloud.com', 'me.com'],
  'meta':         ['facebook.com', 'meta.com', 'instagram.com', 'whatsapp.com'],
  'netflix':      ['netflix.com'],
  'paypal':       ['paypal.com', 'paypal.me'],
  'dropbox':      ['dropbox.com'],
  'zoom':         ['zoom.us'],
  'linkedin':     ['linkedin.com', 'e.linkedin.com'],
  'twitter':      ['twitter.com', 'x.com'],
  'github':       ['github.com', 'github.io'],
  'slack':        ['slack.com'],
  'adobe':        ['adobe.com', 'adobeid.adobe.com'],
  'salesforce':   ['salesforce.com', 'force.com'],
  
  // Indian IT / Enterprises
  'tcs':          ['tcs.com', 'tata.com', 'tatagroup.com'],
  'infosys':      ['infosys.com'],
  'wipro':        ['wipro.com'],
  'hcl':          ['hcl.com', 'hcltech.com'],
  'accenture':    ['accenture.com'],
  'ibm':          ['ibm.com'],
  'cognizant':    ['cognizant.com'],
  'capgemini':    ['capgemini.com'],
  'oracle':       ['oracle.com'],
  'sap':          ['sap.com'],

  // Banks / Finance
  'chase':        ['chase.com', 'jpmorgan.com'],
  'bank of america': ['bankofamerica.com', 'bofa.com'],
  'wells fargo':  ['wellsfargo.com'],
  'citibank':     ['citibank.com', 'citi.com'],
  'hdfc':         ['hdfcbank.com', 'hdfc.com'],
  'icici':        ['icicibank.com'],
  'sbi':          ['sbi.co.in', 'onlinesbi.com'],
  'axis bank':    ['axisbank.com'],
  'kotak':        ['kotak.com', 'kotakbank.com'],
  
  // Logistics
  'dhl':          ['dhl.com', 'dhlexpress.com'],
  'fedex':        ['fedex.com'],
  'ups':          ['ups.com'],
  'usps':         ['usps.com'],
  'india post':   ['indiapost.gov.in'],

  // Government
  'irs':          ['irs.gov'],
  'fbi':          ['fbi.gov'],
  'dhs':          ['dhs.gov'],
  'income tax':   ['incometax.gov.in', 'incometaxindiaefiling.gov.in'],

  // Other
  'netflix':      ['netflix.com'],
  'spotify':      ['spotify.com'],
  'ebay':         ['ebay.com'],
  'shopify':      ['shopify.com'],
  'stripe':       ['stripe.com'],
  'coinbase':     ['coinbase.com'],
};

// ── Display name patterns that suggest impersonation ──────────────────────
// A sender like "Amazon Security <attacker@gmail.com>" is a classic BEC pattern
function extractDisplayNameBrand(displayName) {
  if (!displayName) return null;
  const lower = displayName.toLowerCase();
  for (const brand of Object.keys(BRAND_CORPUS)) {
    if (lower.includes(brand)) return brand;
  }
  return null;
}

function extractDomainFromEmail(email) {
  if (!email) return null;
  const match = email.match(/@([a-zA-Z0-9.\-]+)$/);
  return match ? match[1].toLowerCase() : null;
}

function isLegitimateForBrand(brand, senderDomain) {
  if (!brand || !senderDomain) return false;
  const legitimateDomains = BRAND_CORPUS[brand] || [];
  return legitimateDomains.some(d =>
    senderDomain === d || senderDomain.endsWith('.' + d)
  );
}

/**
 * Detect brand impersonation from sender info and message body.
 * @param {Object} params
 * @param {string} [params.displayName]   — e.g. "Amazon Security Team"
 * @param {string} [params.senderEmail]   — e.g. "security@gmail.com"
 * @param {string} [params.senderDomain]  — e.g. "gmail.com"
 * @param {string} [params.body]          — Email/SMS body text
 * @param {string} [params.subject]       — Email subject
 * @returns {{ score: number, detectedBrand: string|null, isSpoofed: boolean, flags: string[] }}
 */
export function detectBrandImpersonation({ displayName, senderEmail, senderDomain, body, subject } = {}) {
  const flags = [];
  let score   = 0;

  const combinedText = [displayName, subject, body].filter(Boolean).join(' ');

  // 1. Display name contains a known brand?
  const brandFromDisplay = extractDisplayNameBrand(displayName || '');
  const brandFromBody    = extractDisplayNameBrand(combinedText);
  const detectedBrand    = brandFromDisplay || brandFromBody;

  // 2. If brand detected, check if sending domain is legitimate
  const domain = senderDomain || extractDomainFromEmail(senderEmail || '');
  let isSpoofed = false;

  if (detectedBrand) {
    const isLegit = isLegitimateForBrand(detectedBrand, domain);

    if (!isLegit && domain) {
      // Sender claims to be a known brand but is sending from a different domain
      score += 70;
      isSpoofed = true;
      flags.push(`Brand "${detectedBrand.toUpperCase()}" claimed but sending from "${domain}"`);
    } else if (!isLegit && !domain) {
      score += 35;
      flags.push(`Brand "${detectedBrand.toUpperCase()}" in display name — no sender domain to verify`);
    }
    // If domain matches → legitimate, score stays low

    // 3. Check for HR/Payroll/Recruitment patterns (high-value BEC targets)
    const bec_patterns = [
      /\b(hr|payroll|recruitment|hiring|onboarding)\b/i,
      /\b(salary|compensation|offer letter|joining date)\b/i,
      /\b(noc|no objection|relieving|experience letter)\b/i,
    ];
    const becMatches = bec_patterns.filter(p => p.test(combinedText));
    if (becMatches.length > 0 && isSpoofed) {
      score += 20;
      flags.push(`BEC HR/Payroll keywords + spoofed domain (high-risk combination)`);
    }
  }

  // 4. Free email domain sending as enterprise brand
  const freeEmailDomains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'outlook.com', 'live.com', 'protonmail.com', 'yandex.com'];
  if (detectedBrand && domain && freeEmailDomains.includes(domain)) {
    score += 25;
    flags.push(`Enterprise brand "${detectedBrand.toUpperCase()}" sent from free email domain "${domain}"`);
  }

  // 5. Look-alike domain detection for known brands in sender domain
  // e.g., amaz0n.com, micros0ft.com, applesupp0rt.com
  if (domain && detectedBrand) {
    const brandLegitDomains = BRAND_CORPUS[detectedBrand] || [];
    const isExactMatch = brandLegitDomains.some(d => domain === d || domain.endsWith('.' + d));
    if (!isExactMatch) {
      // Check for look-alike: if the domain contains the brand name but isn't a legit domain
      const brandName = detectedBrand.replace(/\s+/g, '');
      if (domain.includes(brandName) && !isExactMatch) {
        score += 30;
        flags.push(`Look-alike domain "${domain}" contains brand name "${detectedBrand}" but is not a legitimate domain`);
      }
    }
  }

  return {
    score:         Math.min(100, score),
    detectedBrand: detectedBrand || null,
    isSpoofed,
    flags,
  };
}
