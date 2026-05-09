/**
 * PhishGuard — Storage Manager
 * Centralized state management for extension results using chrome.storage.local.
 */

const STORAGE_KEY_PREFIX = 'tab_state_';

/**
 * Save analysis result for a specific tab.
 * @param {number} tabId
 * @param {object} state
 */
export async function setTabState(tabId, state) {
  if (!tabId) return;
  const key = `${STORAGE_KEY_PREFIX}${tabId}`;
  await chrome.storage.local.set({ [key]: { ...state, lastUpdate: Date.now() } });
}

/**
 * Get analysis result for a specific tab.
 * @param {number} tabId
 * @returns {Promise<object|null>}
 */
export async function getTabState(tabId) {
  if (!tabId) return null;
  const key = `${STORAGE_KEY_PREFIX}${tabId}`;
  const data = await chrome.storage.local.get([key]);
  return data[key] || null;
}

/**
 * Remove state for a specific tab.
 * @param {number} tabId
 */
export async function clearTabState(tabId) {
  if (!tabId) return;
  const key = `${STORAGE_KEY_PREFIX}${tabId}`;
  await chrome.storage.local.remove([key]);
}

/**
 * Clear all tab states from storage.
 */
export async function clearAllStates() {
  const all = await chrome.storage.local.get(null);
  const keysToRemove = Object.keys(all).filter(k => k.startsWith(STORAGE_KEY_PREFIX));
  if (keysToRemove.length > 0) {
    await chrome.storage.local.remove(keysToRemove);
  }
}
