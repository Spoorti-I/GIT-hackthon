/**
 * PhishGuard — Attachment Analyzer
 * Detects suspicious attachment types.
 */

const SUSPICIOUS_EXTENSIONS = [
  '.pdf', '.zip', '.docm', '.exe', '.iso', '.msi', '.rar', '.7z', '.js', '.vbs', '.bat', '.scr'
];

/**
 * Analyzes attachment metadata.
 * @param {Array} attachments - List of filenames or metadata objects
 * @returns {number} Score 0-100
 */
export function analyzeAttachments(attachments) {
  if (!attachments || !Array.isArray(attachments)) return 0;
  
  let score = 0;
  for (const attachment of attachments) {
    const filename = (typeof attachment === 'string' ? attachment : attachment.name || '').toLowerCase();
    
    if (SUSPICIOUS_EXTENSIONS.some(ext => filename.endsWith(ext))) {
      score += 40;
    }
    
    // Double extensions
    if (/\.[a-z0-9]+\.[a-z0-9]+$/i.test(filename)) {
      score += 30;
    }
  }

  return Math.min(100, score);
}
