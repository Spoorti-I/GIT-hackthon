/**
 * PhishGuard — Suspicious TLDs
 * Top-level domains frequently abused in phishing and malware campaigns.
 * Based on threat intelligence reports and Spamhaus data.
 * This list is configurable — users can add custom TLDs in options.
 */

export const SUSPICIOUS_TLDS = new Set([
  // Historically abused generic TLDs
  'tk',  // Tokelau — highest abuse rate
  'ml',  // Mali
  'ga',  // Gabon
  'cf',  // Central African Republic
  'gq',  // Equatorial Guinea
  'pw',  // Palau — commonly free-registered
  'top',
  'club',
  'click',
  'download',
  'loan',
  'racing',
  'review',
  'win',
  'bid',
  'trade',
  'webcam',
  'date',
  'faith',
  'party',
  'science',
  'work',
  'men',
  'stream',
  'gdn',
  'accountant',
  'cricket',
  'ninja',

  // Newer GTLDs with high abuse rates
  'buzz',
  'monster',
  'icu',
  'cyou',
  'cfd',
  'sbs',
  'autos',
  'boats',
  'uno',

  // Country codes with high abuse
  'cc',   // Cocos Islands
  'su',   // Soviet Union — legacy still active
  'biz',  // Not inherently bad but abused

  // Specific patterns
  'xyz',  // Very cheap, high abuse
  'live', // Commonly used in phishing
  'support',
  'help',
  'online',
  'site',
  'website',
  'space',
]);
