/**
 * PhishGuard — Alert Injector
 * Injects a visual warning banner into the webpage when a threat is detected in chat/email.
 */

let bannerInjected = false;

export function injectWarningBanner(messageText) {
  if (bannerInjected) return;
  bannerInjected = true;

  const banner = document.createElement('div');
  banner.id = 'phishguard-inline-alert';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    background-color: #ef4444; /* red-500 */
    color: white;
    text-align: center;
    padding: 12px;
    font-family: 'Inter', system-ui, sans-serif;
    font-size: 14px;
    font-weight: 600;
    z-index: 2147483647; /* Max z-index */
    box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 10px;
    transition: transform 0.3s ease-in-out;
    transform: translateY(-100%);
  `;

  banner.innerHTML = `
    <svg viewBox="0 0 24 24" width="20" height="20" stroke="currentColor" stroke-width="2" fill="none" stroke-linecap="round" stroke-linejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
      <line x1="12" y1="9" x2="12" y2="13"></line>
      <line x1="12" y1="17" x2="12.01" y2="17"></line>
    </svg>
    <span>PhishGuard Alert: A suspicious phishing message was detected on this page!</span>
    <button id="phishguard-alert-close" style="
      background: rgba(0,0,0,0.2);
      border: none;
      color: white;
      cursor: pointer;
      border-radius: 4px;
      padding: 4px 8px;
      margin-left: 10px;
    ">Dismiss</button>
  `;

  document.body.appendChild(banner);

  // Animate in
  requestAnimationFrame(() => {
    banner.style.transform = 'translateY(0)';
  });

  // Close button handler
  document.getElementById('phishguard-alert-close').addEventListener('click', () => {
    banner.style.transform = 'translateY(-100%)';
    setTimeout(() => {
      banner.remove();
      bannerInjected = false;
    }, 300);
  });
}
