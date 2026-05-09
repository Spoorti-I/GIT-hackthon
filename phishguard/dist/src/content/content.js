/**
 * PhishGuard — Content Script
 * Orchestrates page-level signal collection and Multi-Channel Monitoring.
 */

(async function () {
  'use strict';

  // Skip if already injected
  if (window.__phishGuardInjected) return;
  window.__phishGuardInjected = true;

  // 1. Existing functionality: Collect password fields and report
  function collectAndReport() {
    const passwordFields = document.querySelectorAll('input[type="password"]').length;
    const textFields     = document.querySelectorAll('input[type="text"], input[type="email"]').length;
    const forms          = document.querySelectorAll('form').length;

    if (passwordFields > 0 || forms > 0) {
      chrome.runtime.sendMessage({
        type:    'PAGE_SIGNALS',
        signals: {
          passwordFields,
          textFields,
          forms,
          url: window.location.href,
        },
      }).catch(() => {});
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', collectAndReport, { once: true });
  } else {
    collectAndReport();
  }

  // 2. New functionality: Multi-Channel NLP Monitoring
  try {
    // Skip analysis on highly trusted domains to prevent false positives (e.g., GitHub, Google)
    const TRUSTED_DOMAINS = [
      'github.com', 'google.com', 'microsoft.com', 'apple.com', 'stack overflow.com',
      'chatgpt.com', 'anthropic.com', 'gemini.google.com'
    ];
    const currentDomain = window.location.hostname.replace('www.', '');
    if (TRUSTED_DOMAINS.some(d => currentDomain === d || currentDomain.endsWith('.' + d))) {
      console.log(`[PhishGuard] Trusted domain detected (${currentDomain}). Skipping NLP scan.`);
      return;
    }

    const nlpUrl = chrome.runtime.getURL('src/ai/nlpEngine.js');
    const observerUrl = chrome.runtime.getURL('src/content/domObserver.js');
    const alertUrl = chrome.runtime.getURL('src/content/alertInjector.js');

    const [nlpModule, observerModule, alertModule] = await Promise.all([
      import(nlpUrl),
      import(observerUrl),
      import(alertUrl)
    ]);

    const { analyzeTextForPhishing } = nlpModule;
    const { startObserving } = observerModule;
    const { injectWarningBanner } = alertModule;

    // Callback when new text is added to the DOM
    const onNewTextFound = (textArray) => {
      // 1. Check for Gmail Internal Spam signals
      if (window.location.hostname === 'mail.google.com') {
        const gmailSpamBanner = document.querySelector('.au5, .BltHke[role="main"] .asP');
        const isSpamFolder = window.location.hash.includes('#spam');
        
        if (gmailSpamBanner || isSpamFolder) {
          chrome.runtime.sendMessage({
            type: 'GMAIL_SPAM_DETECTED',
            url: window.location.href
          }).catch(() => {});
        }
      }

      for (const text of textArray) {
        const result = analyzeTextForPhishing(text);
        if (result.isPhishing) {
          injectWarningBanner(text);
          // 3. Notify Background script to update global state/popup
          if (chrome.runtime?.id) {
            chrome.runtime.sendMessage({
              type: 'NLP_THREAT_DETECTED',
              threat: { ...result, url: window.location.href }
            }).catch(() => {});
          }
          // Only trigger once per discovery phase to avoid spamming
          break; 
        }
      }
    };

    // Start observing DOM for changes
    startObserving(onNewTextFound);

  } catch (error) {
    console.warn('[PhishGuard] Failed to load NLP modules:', error);
  }
})();
