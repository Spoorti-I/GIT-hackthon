/**
 * PhishGuard — Local Phishing Blocklist (Demo Dataset)
 * A curated set of known phishing domains for offline detection.
 * Can be supplemented via user import in Options page.
 *
 * Format: lowercase domains and URL prefixes.
 * These are EXAMPLE entries — replace with real threat feeds in production.
 */

export const LOCAL_BLOCKLIST = new Set([
  // Demonstrative phishing domains (example patterns)
  'paypal-secure-login.tk',
  'paypal-account-verify.ml',
  'paypal.com.secure-login.xyz',
  'appleid-locked.com',
  'apple-support-account.online',
  'microsoft-account-verify.top',
  'amazon-security-alert.click',
  'amazon-prime-renewal.club',
  'netflix-account-suspended.pw',
  'netfl1x-billing.com',
  'faceb00k-login.com',
  'facebook-security-check.xyz',
  'google-account-recovery.ml',
  'gmail-security-alert.top',
  'chase-bank-secure.tk',
  'chasebank-alert.com',
  'bankofamerica-verify.xyz',
  'wellsfargo-secure.ml',
  'irs-tax-refund.xyz',
  'irs-stimulus-payment.com',
  'usps-package-delivery.top',
  'fedex-delivery-failed.tk',
  'dhl-shipment-tracking.xyz',
  'coinbase-secure.ml',
  'blockchain-wallet-restore.com',
  'metamask-recovery.xyz',
  'binance-login-verify.tk',
  'instagram-verify.ml',
  'twitter-account-suspended.xyz',
  'linkedin-security-alert.top',
  'dropbox-link.tk',
  'adobe-account-verify.ml',
  'office365-login-secure.xyz',
  'outlook-security-verify.top',
  'icloud-find-my.tk',
  'icloud-account-suspended.ml',
  'ebay-security-center.xyz',
  'walmart-survey-winner.top',
  'steam-free-skins.tk',
  'roblox-free-robux.ml',
  'microsoft365-login.xyz',
  'secure-paypal-login.com',
  'paypal-secure.net',
  'verify-paypal.com',
  'login-paypal-secure.com',
  'secure-amazon.net',
  'amazon-login-update.com',
  'update-apple-id.com',
  'appleid-unlock.net',
  'secure-google-login.com',
]);

/**
 * Check if a domain or URL matches the local blocklist.
 * @param {string} domain - The registered domain to check
 * @param {string} hostname - The full hostname
 * @param {string} url - The full URL
 * @returns {boolean}
 */
export function checkLocalBlocklist(domain, hostname, url) {
  const lDomain   = domain.toLowerCase();
  const lHostname = hostname.toLowerCase();
  const lUrl      = url.toLowerCase();

  if (LOCAL_BLOCKLIST.has(lDomain))   return true;
  if (LOCAL_BLOCKLIST.has(lHostname)) return true;

  // Check if URL starts with any blocklist entry
  for (const entry of LOCAL_BLOCKLIST) {
    if (lUrl.includes(entry)) return true;
  }

  return false;
}
