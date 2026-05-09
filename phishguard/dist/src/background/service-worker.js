/**
 * PhishGuard — MV3 Service Worker (Background)
 * Orchestrates tab monitoring, analysis, and badge updates.
 */

import { analyzeURL, mergeIntelResults } from '../analyzer/urlAnalyzer.js';
import { scoreResult, getBadgeConfig }   from '../analyzer/scorer.js';
import { checkGoogleSafeBrowsing, checkCustomBlocklist, checkWhitelist } from '../analyzer/threatIntel.js';
import { analysisCache }                 from '../shared/cache.js';
import { RISK_CATEGORY, BADGE_CONFIG, RULES, RULE_META }   from '../shared/types.js';
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

    // 6. AI Trust Verification Layer (runs on every result for full coverage)
    runAITrustOnResult(tabId, finalResult).catch(err =>
      console.warn('[PhishGuard AI Trust] Error:', err.message)
    );

  } catch (err) {
    console.error('[PhishGuard] Analysis error:', err);
    await setBadgeUnknown(tabId);
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
  if (!tabId || !signals || signals.passwordFields === 0) return;
  const existing = await Storage.getTabState(tabId);
  if (!existing || existing.score < 10) return;

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

/**
 * Run the AI Trust Verification Layer — runs on every URL.
 * Purely additive — merges AI penalty rules back into existing state.
 */
async function runAITrustOnResult(tabId, heuristicResult) {
  const settings = await chrome.storage.sync.get(['enableAITrustLayer', 'geminiApiKey']);
  if (!settings.enableAITrustLayer) return;

  // Build content signals from URL
  const content = {
    senderEmail:  '',
    senderDomain: heuristicResult.domain || '',
    displayName:  '',
    subject:      '',
    body:         '',
    urls:         [heuristicResult.url],
    attachments:  [],
    displayUrl:   '',
    actualUrl:    heuristicResult.url,
  };

  const aiResult = await runAITrustVerification(heuristicResult, content, settings);
  if (!aiResult.ran) return;

  const existing = await Storage.getTabState(tabId);
  if (!existing) return;

  // Prevent duplicate AI Trust rules
  if (existing.rules && existing.rules.some(r => r.rule === RULES.AI_TRUST_FINAL)) return;

  const infoRules = [];

  // Add informational sub-score rules (0 points — display only)
  if (aiResult.languageRisk > 0) {
    infoRules.push({
      rule:      RULES.AI_TRUST_LINGUISTIC,
      points:    0,
      label:     RULE_META[RULES.AI_TRUST_LINGUISTIC].label,
      reason:    `Language risk: ${aiResult.languageRisk}/100.${aiResult.allFlags.length ? ' Flags: ' + aiResult.allFlags.slice(0, 2).join('; ') + '.' : ' No suspicious patterns.'}`,
      category:  'ai-trust',
      triggered: true,
    });
  }

  if (aiResult.brandScore > 0) {
    infoRules.push({
      rule:      RULES.AI_TRUST_BRAND,
      points:    0,
      label:     RULE_META[RULES.AI_TRUST_BRAND].label,
      reason:    `Brand impersonation: ${aiResult.brandScore}/100.${aiResult.detectedBrand ? ' Detected brand: ' + aiResult.detectedBrand.toUpperCase() + '.' : ' No impersonation detected.'}`,
      category:  'ai-trust',
      triggered: true,
    });
  }

  if (aiResult.behaviorScore > 0) {
    infoRules.push({
      rule:      RULES.AI_TRUST_BEHAVIOR,
      points:    0,
      label:     RULE_META[RULES.AI_TRUST_BEHAVIOR].label,
      reason:    `Behavioral score: ${aiResult.behaviorScore}/100. ${aiResult.isFirstTimeSender ? 'First-time sender detected.' : 'No behavioral anomalies.'}`,
      category:  'ai-trust',
      triggered: true,
    });
  }

  if (aiResult.linkRisk > 0) {
    infoRules.push({
      rule:      RULES.AI_TRUST_LINK,
      points:    0,
      label:     RULE_META[RULES.AI_TRUST_LINK].label,
      reason:    `Link risk: ${aiResult.linkRisk}/100. ${aiResult.linkRisk > 30 ? 'Suspicious link patterns detected.' : 'Links appear normal.'}`,
      category:  'ai-trust',
      triggered: true,
    });
  }

  // Always add the final summary rule — even with 0 penalty (for UI display)
  const geminiNote = aiResult.usedGemini ? ` Gemini: ${aiResult.geminiReasoning}` : '';
  const safeNote   = aiResult.heuristicPenalty === 0
    ? 'No elevated risk detected by AI verification.'
    : 'Trusted domain flagged — may be abused for social engineering.';
  infoRules.push({
    rule:      RULES.AI_TRUST_FINAL,
    points:    aiResult.heuristicPenalty,
    label:     aiResult.heuristicPenalty === 0
      ? 'AI Trust Verification: Passed'
      : RULE_META[RULES.AI_TRUST_FINAL].label,
    reason:    `AI Trust score: ${aiResult.aiScore}/100 — ${aiResult.aiCategory}. ${geminiNote || safeNote}`.trim(),
    category:  'ai-trust',
    triggered: true,
  });

  // Always merge and persist — even for SAFE verdict (so popup always shows the panel)
  const updatedRules  = [...(existing.rules || []), ...infoRules];
  const updatedScore  = Math.max(0, updatedRules.reduce((sum, r) => sum + r.points, 0));
  const updatedRaw    = { ...existing, rules: updatedRules, score: updatedScore, aiTrust: aiResult };
  const updatedResult = scoreResult(updatedRaw);
  updatedResult.aiTrust = aiResult;

  await Storage.setTabState(tabId, updatedResult);
  await updateBadge(tabId, updatedResult.category);
  notifyPopup(tabId, updatedResult);

  console.log(`[PhishGuard AI Trust] ${heuristicResult.domain}: ${aiResult.aiCategory} (score: ${aiResult.aiScore}, penalty: +${aiResult.heuristicPenalty})`);
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
