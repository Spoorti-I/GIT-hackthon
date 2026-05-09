/**
 * PhishGuard — DOM Observer
 * Safely watches for new text nodes (chat messages/emails) being added to the DOM.
 */

let observer = null;
let analyzeCallback = null;
let debounceTimer = null;
const textBuffer = new Set();

/**
 * Initializes the MutationObserver to monitor the DOM.
 * @param {Function} callback Function to call with new text content
 */
export function startObserving(callback) {
  if (observer) return;
  analyzeCallback = callback;

  observer = new MutationObserver((mutations) => {
    let hasNewText = false;

    mutations.forEach((mutation) => {
      if (mutation.type === 'childList') {
        mutation.addedNodes.forEach((node) => {
          // Only process element nodes
          if (node.nodeType === Node.ELEMENT_NODE) {
            // Ignore script, style, and our own injected alert
            if (['SCRIPT', 'STYLE', 'NOSCRIPT'].includes(node.tagName) || node.id === 'phishguard-inline-alert') {
              return;
            }
            
            const text = node.innerText || node.textContent;
            if (text && text.trim().length > 10) {
              textBuffer.add(text.trim());
              hasNewText = true;
            }
          }
        });
      }
    });

    if (hasNewText) {
      processBufferDebounced();
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true
  });
}

/**
 * Stop observing DOM changes.
 */
export function stopObserving() {
  if (observer) {
    observer.disconnect();
    observer = null;
  }
}

/**
 * Debounce processing of the text buffer to avoid performance issues
 * on highly dynamic pages like Slack or Teams.
 */
function processBufferDebounced() {
  if (debounceTimer) clearTimeout(debounceTimer);
  
  debounceTimer = setTimeout(() => {
    if (textBuffer.size > 0 && analyzeCallback) {
      // Process all buffered text
      const allText = Array.from(textBuffer);
      analyzeCallback(allText);
      textBuffer.clear();
    }
  }, 1000); // 1 second debounce
}
