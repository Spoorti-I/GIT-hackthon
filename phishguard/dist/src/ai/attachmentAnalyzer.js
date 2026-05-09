/**
 * PhishGuard — Attachment Analyzer (AI Trust Layer)
 * Detects suspicious attachment types from metadata strings.
 * Runs entirely locally — no API calls.
 */

// High-risk attachment extensions
const HIGH_RISK_EXTENSIONS = new Set([
  'exe', 'bat', 'cmd', 'com', 'scr', 'pif', 'vbs', 'vbe',
  'js', 'jse', 'wsf', 'wsh', 'ps1', 'ps2', 'reg',
  'msi', 'msp', 'mst', 'jar',
  'docm', 'dotm', 'xlsm', 'xltm', 'pptm', 'potm', 'ppam',
  'iso', 'img', 'dmg', 'bin',
  'hta', 'lnk',
  'appx', 'appxbundle',
]);

// Medium-risk extensions (need context)
const MEDIUM_RISK_EXTENSIONS = new Set([
  'zip', 'rar', '7z', 'tar', 'gz', 'bz2',
  'doc', 'xls', 'ppt',                         // old Office (macros possible)
  'pdf',                                         // can contain JS/malware
  'html', 'htm', 'svg',                          // phishing pages as attachments
  'ods', 'odt', 'odp',                           // OpenDocument with macros
]);

// Double-extension patterns (e.g., invoice.pdf.exe, photo.jpg.bat)
const DOUBLE_EXT_PATTERN = /\.\w{2,4}\.(exe|bat|cmd|vbs|scr|js|ps1|hta|lnk)$/i;

// Password-protected archive keywords
const PASS_PROTECTED_PATTERNS = [
  /password.?(is|:|=|below|protected|attached)/i,
  /the (password|pass|pw) (is|for|to open)/i,
  /open with password/i,
  /protected (archive|zip|file|document)/i,
];

// Suspicious filename patterns
const SUSPICIOUS_FILENAME_PATTERNS = [
  /invoice/i, /payment/i, /remittance/i, /receipt/i,
  /urgent/i, /confidential/i, /agreement/i, /contract/i,
  /refund/i, /offer.?letter/i, /job.?offer/i,
  /bank.?statement/i, /account.?details/i,
  /po_/i, /purchase.?order/i,
];

function getExtension(filename) {
  if (!filename) return '';
  const parts = filename.split('.');
  return parts.length > 1 ? parts[parts.length - 1].toLowerCase() : '';
}

/**
 * Analyze attachment metadata for suspicious signals.
 * @param {Object} params
 * @param {Array<{name: string, size?: number, type?: string}>} [params.attachments]
 * @param {string} [params.body] — Email body to detect password-protection patterns
 * @returns {{ score: number, flags: string[], riskLevel: 'none'|'low'|'medium'|'high' }}
 */
export function analyzeAttachments({ attachments = [], body = '' } = {}) {
  const flags = [];
  let score   = 0;

  if (!attachments || attachments.length === 0) {
    return { score: 0, flags: [], riskLevel: 'none' };
  }

  for (const att of attachments) {
    const name  = (att.name || att.filename || '').trim();
    const ext   = getExtension(name);
    const mime  = (att.type || att.mimeType || '').toLowerCase();

    // 1. High-risk extension
    if (HIGH_RISK_EXTENSIONS.has(ext)) {
      score += 60;
      flags.push(`High-risk attachment: "${name}" (.${ext})`);
      continue; // Already max flagged for this file
    }

    // 2. Medium-risk extension
    if (MEDIUM_RISK_EXTENSIONS.has(ext)) {
      score += 20;
      flags.push(`Medium-risk attachment: "${name}" (.${ext})`);
    }

    // 3. Double extension trick
    if (DOUBLE_EXT_PATTERN.test(name)) {
      score += 45;
      flags.push(`Double extension trick: "${name}"`);
    }

    // 4. MIME-type mismatch (e.g., .pdf but mime says application/zip)
    if (ext && mime) {
      const mimeExt = mime.split('/')[1];
      if (mimeExt && !mime.includes(ext) && !['octet-stream', 'unknown'].includes(mimeExt)) {
        score += 20;
        flags.push(`MIME mismatch: "${name}" claims .${ext} but type is "${mime}"`);
      }
    }

    // 5. Suspicious filename even for common extension
    const filenameMatches = SUSPICIOUS_FILENAME_PATTERNS.filter(p => p.test(name));
    if (filenameMatches.length > 0 && MEDIUM_RISK_EXTENSIONS.has(ext)) {
      score += 15;
      flags.push(`Suspicious filename: "${name}"`);
    }

    // 6. Very small PDF (may be a phishing page stub)
    if (ext === 'pdf' && att.size && att.size < 10000) {
      score += 10;
      flags.push(`Unusually small PDF (${att.size} bytes) — may be a credential harvesting stub`);
    }
  }

  // 7. Password-protected archive in body + attachment
  const passMatches = PASS_PROTECTED_PATTERNS.filter(p => p.test(body));
  if (passMatches.length > 0) {
    score += 25;
    flags.push(`Email provides password for attachment — common malware delivery technique`);
  }

  // 8. Multiple attachments (unusual for legitimate transactional email)
  if (attachments.length > 3) {
    score += 10;
    flags.push(`${attachments.length} attachments — unusual for a legitimate email`);
  }

  const riskLevel =
    score >= 50 ? 'high' :
    score >= 25 ? 'medium' :
    score > 0   ? 'low'    : 'none';

  return { score: Math.min(100, score), flags, riskLevel };
}
