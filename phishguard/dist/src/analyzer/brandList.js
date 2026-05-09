/**
 * PhishGuard — Known Brands List
 * Common brands frequently targeted in phishing attacks.
 * Used for typosquatting detection via Levenshtein distance.
 *
 * Format: "registerable domain" (without TLD) OR full "domain.tld"
 * For typosquatting check we compare against the registered domain.
 */

export const KNOWN_BRANDS = [
  // Financial
  'paypal',
  'chase',
  'bankofamerica',
  'wellsfargo',
  'citibank',
  'americanexpress',
  'capitalone',
  'discover',
  'hsbc',
  'barclays',
  'lloyds',
  'natwest',
  'santander',
  'usbank',
  'tdbank',

  // Big Tech
  'google',
  'microsoft',
  'apple',
  'amazon',
  'facebook',
  'meta',
  'instagram',
  'twitter',
  'linkedin',
  'netflix',
  'spotify',
  'adobe',
  'dropbox',
  'github',
  'gitlab',

  // E-commerce / Shopping
  'ebay',
  'walmart',
  'target',
  'bestbuy',
  'etsy',
  'shopify',
  'aliexpress',
  'alibaba',
  'flipkart',

  // Crypto / Finance
  'coinbase',
  'binance',
  'kraken',
  'blockchain',
  'metamask',
  'robinhood',
  'webull',

  // Communication
  'gmail',
  'outlook',
  'yahoo',
  'hotmail',
  'icloud',
  'protonmail',
  'zoom',
  'slack',
  'discord',
  'whatsapp',
  'telegram',

  // Streaming / Media
  'youtube',
  'twitch',
  'hulu',
  'disneyplus',
  'hbomax',
  'primevideo',

  // Government / Utilities
  'irs',
  'ssa',
  'medicare',
  'usps',
  'fedex',
  'ups',
  'dhl',

  // Insurance / Health
  'aetna',
  'anthem',
  'cigna',
  'unitedhealthcare',
  'humana',

  // Tech / Cloud
  'aws',
  'azure',
  'cloudflare',
  'salesforce',
  'oracle',
  'ibm',
  'vmware',
  'godaddy',
];

/**
 * Brands that should never appear as subdomains of other domains.
 * If we see "paypal.suspicious-site.com", that's a red flag.
 */
export const BRAND_SUBDOMAIN_PATTERNS = new Set(KNOWN_BRANDS.map(b => b.toLowerCase()));
