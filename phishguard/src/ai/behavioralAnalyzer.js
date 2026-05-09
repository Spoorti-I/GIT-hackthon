/**
 * PhishGuard — Behavioral Analyzer
 * Analyzes sender behavior and history.
 */

/**
 * Analyzes behavioral signals.
 * @param {object} context - { sender, timestamp, history }
 * @returns {number} Score 0-100
 */
export async function analyzeBehavior(context) {
  // In a real scenario, this would check chrome.storage.local for historical data.
  // For now, we implement a placeholder that flags "first-time" encounters if no history exists.
  
  const { sender, history = [] } = context;
  
  if (!sender) return 0;

  const isNewSender = !history.includes(sender);
  
  if (isNewSender) {
    // New senders are slightly more suspicious in an AI Trust context
    return 30;
  }

  return 0;
}
