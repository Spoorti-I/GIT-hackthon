/**
 * PhishGuard — MV3 Service Worker (Background)
 * Orchestrates tab monitoring, analysis, and badge updates.
 */

import { analyzeURL, mergeIntelResults } from '../analyzer/urlAnalyzer.js';
import { scoreResult, getBadgeConfig }   from '../analyzer/scorer.js';
import { checkGoogleSafeBrowsing, checkCustomBlocklist, checkWhitelist } from '../analyzer/threatIntel.js';
import { analysisCache }                 from '../shared/cache.js';
import { RISK_CATEGORY, BADGE_CONFIG, RULES, RULE_META, SCORE_THRESHOLDS }   from '../shared/types.js';
import * as Storage                      from '../shared/storage.js';
import { runAITrustVerification }        from '../ai/aiTrustLayer.js';

// 0. Initialize on install/update
chrome.runtime.onInstalled.addListener(async () => {
  await Storage.clearAllStates();
  const tabs = await chrome.tabs.query({ url: ['http://*/*', 'https://*/*'] });
  for (const tab of tabs) {
    if (tab.url) analyzeTab(tab.id, tab.url);
  }
});

// URLs we should skip analyzing
const SKIP_PROTOCOLS = new Set(['chrome:', 'chrome-extension:', 'about:', 'edge:', 'moz-extension:', 'devtools:']);

function shouldSkip(url) {
  if (!url) return true;
  for (const proto of SKIP_PROTOCOLS) {
    if (url.startsWith(proto)) return true;
  }
  return false;
}

/**
 * Set the extension badge for a specific tab.
 */
async function updateBadge(tabId, category) {
  const config = getBadgeConfig(category);
  try {
    await chrome.action.setBadgeText({ text: config.text, tabId });
    await chrome.action.setBadgeBackgroundColor({ color: config.color, tabId });
    await chrome.action.setTitle({
      title: `PhishGuard — ${category.charAt(0).toUpperCase() + category.slice(1)}`,
      tabId,
    });
  } catch (err) {
    console.debug('[PhishGuard] Badge update skipped:', err.message);
  }
}

async function setBadgeScanning(tabId) {
  try {
    await chrome.action.setBadgeText({ text: '…', tabId });
    await chrome.action.setBadgeBackgroundColor({ color: '#6b7280', tabId });
    await chrome.action.setTitle({ title: 'PhishGuard — Analyzing…', tabId });
  } catch {}
}

async function setBadgeUnknown(tabId) {
  const config = BADGE_CONFIG[RISK_CATEGORY.UNKNOWN];
  try {
    await chrome.action.setBadgeText({ text: config.text, tabId });
    await chrome.action.setBadgeBackgroundColor({ color: config.color, tabId });
  } catch {}
}

/**
 * Core analysis pipeline for a URL.
 */
async function analyzeTab(tabId, url) {
  if (shouldSkip(url)) {
    await Storage.clearTabState(tabId);
    await setBadgeUnknown(tabId);
    return;
  }

  // 1. Set Scanning State Immediately
  await setBadgeScanning(tabId);
  await Storage.setTabState(tabId, { category: RISK_CATEGORY.UNKNOWN, url, score: 0 });

  const settings = await chrome.storage.sync.get(['enableSafeBrowsing', 'safeBrowsingApiKey']);

  try {
    const domain = new URL(url).hostname;
    
    // 2. Cache Check
    const cached = analysisCache.get(domain);
    if (cached) {
      await finalizeAnalysis(tabId, cached);
      return;
    }

    // 3. Step 1: Sync Heuristics
    const rawResult = analyzeURL(url);
    const initialScore = scoreResult(rawResult);
    await finalizeAnalysis(tabId, initialScore);

    // 4. Step 2: Async Threat Intel
    const [isWhitelisted, customBlocklistHit, safeBrowsingResult] = await Promise.all([
      checkWhitelist(rawResult.domain, rawResult.hostname),
      checkCustomBlocklist(rawResult.domain, rawResult.hostname),
      settings.enableSafeBrowsing && settings.safeBrowsingApiKey
        ? checkGoogleSafeBrowsing(url, settings.safeBrowsingApiKey)
        : Promise.resolve({ hit: false, threats: [] }),
    ]);

    const mergedRaw = mergeIntelResults(rawResult, {
      whitelisted: isWhitelisted,
      customBlocklist: customBlocklistHit,
      safeBrowsing: safeBrowsingResult,
    });
    const finalResult = scoreResult(mergedRaw);

    // 5. Finalize
    analysisCache.set(domain, finalResult);
    await finalizeAnalysis(tabId, finalResult);

  } catch (err) {
    console.error('[PhishGuard] Analysis error:', err);
    await setBadgeUnknown(tabId);
    await Storage.setTabState(tabId, { 
      category: RISK_CATEGORY.UNKNOWN, 
      error: true, 
      errorMsg: err.message 
    });
    notifyPopup(tabId, { category: RISK_CATEGORY.UNKNOWN, error: true });
  }
}

async function finalizeAnalysis(tabId, newResult) {
  const existing = await Storage.getTabState(tabId);
  
  // Merge rules to ensure we don't lose signals (like NLP) that arrived mid-analysis
  const existingRules = existing?.rules || [];
  const mergedRules   = [...existingRules];
  
  for (const rule of newResult.rules) {
    if (!mergedRules.some(r => r.rule === rule.rule)) {
      mergedRules.push(rule);
    }
  }

  // Re-calculate based on merged rules
  const mergedRaw = { 
    ...newResult, 
    rules: mergedRules, 
    score: mergedRules.reduce((acc, r) => acc + r.points, 0) 
  };
  
  const finalScored = scoreResult(mergedRaw);

  // 6. Step 3: AI Trust Layer (Only if Safe/Trusted)
  if (finalScored.category === RISK_CATEGORY.SAFE && !finalScored.aiTrust?.ran) {
    const settings = await chrome.storage.sync.get(['enableAITrustLayer', 'geminiApiKey']);
    if (settings.enableAITrustLayer) {
      try {
        // Show initial SAFE result first to avoid UI hang
        await Storage.setTabState(tabId, finalScored);
        notifyPopup(tabId, finalScored);

        // Collect basic page text if available
        const pageData = await Storage.getTabState(tabId);
        const aiResult = await runAITrustVerification(finalScored, { bodyText: pageData?.bodyText }, settings);
        
        if (aiResult && aiResult.aiCategory !== 'SAFE') {
          const meta = RULE_META[RULES.AI_TRUST_FINAL];
          finalScored.rules.push({
            rule: RULES.AI_TRUST_FINAL,
            points: aiResult.aiCategory === 'HIGH RISK' ? 50 : 25,
            label: meta.label,
            reason: `AI Trust Layer flagged this as ${aiResult.aiCategory} (Score: ${aiResult.aiScore}/100).`,
            category: meta.category,
            triggered: true
          });
          finalScored.rules.push(...(aiResult.aiRules || []));
        }
        finalScored.aiTrust = aiResult;
        
        const updatedScored = scoreResult({
          ...finalScored,
          score: finalScored.rules.reduce((acc, r) => acc + r.points, 0)
        });

        await Storage.setTabState(tabId, updatedScored);
        await updateBadge(tabId, updatedScored.category);
        notifyPopup(tabId, updatedScored);
        return;
      } catch (aiErr) {
        console.warn('[PhishGuard] AI Trust Layer failed:', aiErr);
        // Fall through to finalize with heuristic result
      }
    }
  }

  await Storage.setTabState(tabId, finalScored);
  await updateBadge(tabId, finalScored.category);
  notifyPopup(tabId, finalScored);
}

function notifyPopup(tabId, result) {
  if (chrome.runtime?.id) {
    chrome.runtime.sendMessage({ type: 'ANALYSIS_RESULT', tabId, result }).catch(() => {});
  }
}

// Event Listeners
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'complete' && tab.url) analyzeTab(tabId, tab.url);
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  if (tab.url) {
    const state = await Storage.getTabState(tabId);
    if (state) await updateBadge(tabId, state.category);
    else analyzeTab(tabId, tab.url);
  }
});

chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId === 0) analyzeTab(details.tabId, details.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  Storage.clearTabState(tabId);
});

// Message Handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'GET_RESULT') {
    Storage.getTabState(message.tabId).then(res => sendResponse({ result: res }));
    return true;
  }

  if (message.type === 'NLP_THREAT_DETECTED') {
    handleNlpThreat(sender.tab?.id, message.threat);
    return false;
  }

  if (message.type === 'GMAIL_SPAM_DETECTED') {
    handleGmailSpam(sender.tab?.id, message.url);
    return false;
  }

  if (message.type === 'PAGE_SIGNALS') {
    handlePageSignals(sender.tab?.id, message.signals);
    return false;
  }

  if (message.type === 'ADD_WHITELIST') {
    addToWhitelist(message.domain).then(() => {
      analysisCache.delete(message.domain);
      if (message.tabId) analyzeTab(message.tabId, message.url);
      sendResponse({ success: true });
    });
    return true;
  }

  if (message.type === 'REANALYZE') {
    chrome.tabs.get(message.tabId).then(tab => {
      if (tab?.url) {
        // Clear cache for this domain first to force fresh analysis
        try {
          const domain = new URL(tab.url).hostname;
          analysisCache.delete(domain);
        } catch {}
        analyzeTab(message.tabId, tab.url);
      }
    });
    return false;
  }

  if (message.type === 'CLEAR_CACHE') {
    analysisCache.clear?.();
    return false;
  }
});

async function handleNlpThreat(tabId, threat) {
  if (!tabId) return;
  
  // 1. Get existing state or create a fallback
  let existing = await Storage.getTabState(tabId);
  
  if (!existing) {
    // If no state exists, we create a basic one from the threat itself
    const url = threat.url || 'http://unknown'; 
    let domain = 'unknown';
    try { domain = new URL(url).hostname; } catch(e) {}

    existing = {
      url,
      domain,
      score: 0,
      rules: [],
      category: RISK_CATEGORY.UNKNOWN,
      timestamp: Date.now()
    };
  }

  // 2. Prevent duplicate NLP rules
  if (existing.rules.some(r => r.rule === RULES.NLP_TEXT_PHISHING)) return;

  const meta = RULE_META[RULES.NLP_TEXT_PHISHING];
  const updatedRules = [...existing.rules, {
    rule: RULES.NLP_TEXT_PHISHING,
    points: meta.weight,
    label: meta.label,
    reason: `Phishing cues detected in page text (Urgency/Authority cues).`,
    category: meta.category,
    triggered: true
  }];

  // 3. Re-calculate entire result using the shared scorer
  const updatedRaw = { 
    ...existing, 
    rules: updatedRules, 
    score: existing.score + meta.weight 
  };
  
  console.log(`[PhishGuard] NLP Detector matched! New score: ${updatedRaw.score}`);
  const updatedResult = scoreResult(updatedRaw);
  await finalizeAnalysis(tabId, updatedResult);
}

async function handleGmailSpam(tabId, url) {
  if (!tabId) return;
  const existing = await Storage.getTabState(tabId);
  if (!existing) return;

  if (existing.rules.some(r => r.rule === RULES.GMAIL_SPAM_DETECTED)) return;

  const meta = RULE_META[RULES.GMAIL_SPAM_DETECTED];
  const updatedRules = [...existing.rules, {
    rule: RULES.GMAIL_SPAM_DETECTED,
    points: meta.weight,
    label: meta.label,
    reason: `Integrated Gmail Spam Signal: Message identified as spam by Gmail.`,
    category: meta.category,
    triggered: true
  }];

  const updatedRaw = { ...existing, rules: updatedRules, score: existing.score + meta.weight };
  console.log(`[PhishGuard] Gmail Spam Detector matched! New score: ${updatedRaw.score}`);
  const updatedResult = scoreResult(updatedRaw);
  await finalizeAnalysis(tabId, updatedResult);
}

async function handlePageSignals(tabId, signals) {
  if (!tabId || !signals) return;
  const existing = await Storage.getTabState(tabId);
  if (!existing) return;

  // Save bodyText for AI Trust layer
  if (signals.bodyText) {
    existing.bodyText = signals.bodyText;
  }

  if (signals.passwordFields === 0 || existing.score < 10) {
    await Storage.setTabState(tabId, existing);
    return;
  }

  if (existing.rules.some(r => r.rule === RULES.PASSWORD_FIELD)) return;

  const meta = RULE_META[RULES.PASSWORD_FIELD];
  const updatedRules = [...existing.rules, {
    rule: RULES.PASSWORD_FIELD,
    points: meta.weight,
    label: meta.label,
    reason: `Page has ${signals.passwordFields} password fields on a suspicious domain.`,
    category: meta.category,
    triggered: true
  }];

  const updatedRaw = { ...existing, rules: updatedRules, score: existing.score + meta.weight };
  const updatedResult = scoreResult(updatedRaw);
  await finalizeAnalysis(tabId, updatedResult);
}

async function addToWhitelist(domain) {
  const data = await chrome.storage.sync.get(['whitelistedDomains']);
  const list = data.whitelistedDomains || [];
  if (!list.includes(domain)) {
    list.push(domain);
    await chrome.storage.sync.set({ whitelistedDomains: list });
  }
}

chrome.alarms.create('cache-cleanup', { periodInMinutes: 10 });
chrome.alarms.onAlarm.addListener(() => analysisCache._prune?.());
