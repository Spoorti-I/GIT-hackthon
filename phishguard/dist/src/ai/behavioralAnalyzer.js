/**
 * PhishGuard — Behavioral Analyzer (AI Trust Layer)
 * Detects first-time sender, time anomalies, and frequency anomalies
 * using a local sender history in chrome.storage.local.
 */

const STORAGE_KEY = 'phishguard_sender_history';
const MAX_HISTORY  = 500;
const HISTORY_TTL  = 90 * 24 * 60 * 60 * 1000; // 90 days

async function loadHistory() {
  try {
    const data = await chrome.storage.local.get([STORAGE_KEY]);
    return data[STORAGE_KEY] || {};
  } catch { return {}; }
}

async function saveHistory(history) {
  try { await chrome.storage.local.set({ [STORAGE_KEY]: history }); } catch {}
}

function pruneHistory(history) {
  const cutoff = Date.now() - HISTORY_TTL;
  return Object.fromEntries(
    Object.entries(history)
      .filter(([, v]) => v.lastSeen > cutoff)
      .sort(([, a], [, b]) => b.lastSeen - a.lastSeen)
      .slice(0, MAX_HISTORY)
  );
}

export async function recordSenderInteraction(senderEmail, domain) {
  if (!senderEmail) return;
  const key   = senderEmail.toLowerCase().trim();
  const now   = Date.now();
  let history = await loadHistory();
  if (!history[key]) {
    history[key] = { firstSeen: now, lastSeen: now, count: 1, domains: [domain].filter(Boolean) };
  } else {
    history[key].lastSeen = now;
    history[key].count = (history[key].count || 0) + 1;
    if (domain && !history[key].domains.includes(domain)) history[key].domains.push(domain);
  }
  await saveHistory(pruneHistory(history));
}

/**
 * Analyze sender behavior for anomaly signals.
 * @param {{ senderEmail?: string, senderDomain?: string, sendTimestamp?: number }} params
 * @returns {Promise<{ score: number, flags: string[], isFirstTime: boolean }>}
 */
export async function analyzeBehavior({ senderEmail, senderDomain, sendTimestamp } = {}) {
  const flags = [];
  let score   = 0;

  if (!senderEmail) return { score: 0, flags: ['No sender email'], isFirstTime: false };

  const key     = senderEmail.toLowerCase().trim();
  const now     = sendTimestamp || Date.now();
  const history = await loadHistory();
  const record  = history[key];
  let isFirstTime = false;

  if (!record) {
    isFirstTime = true;
    score += 30;
    flags.push(`First-time sender: "${senderEmail}"`);
  } else {
    const daysSinceLast = (now - record.lastSeen) / (1000 * 60 * 60 * 24);
    if (daysSinceLast > 60) { score += 20; flags.push(`Long absence: ${Math.round(daysSinceLast)} days since last contact`); }
    if (record.count === 1)  { score += 15; flags.push(`Only 1 prior contact from this sender`); }
    if (senderDomain && record.domains && !record.domains.includes(senderDomain.toLowerCase())) {
      score += 20;
      flags.push(`Domain change: was ${record.domains.join(', ')}, now "${senderDomain}"`);
    }
  }

  const sendHour = new Date(now).getHours();
  if (sendHour >= 0 && sendHour <= 5) { score += 10; flags.push(`Off-hours sending (${sendHour}:xx AM)`); }

  return { score: Math.min(100, score), flags, isFirstTime };
}
