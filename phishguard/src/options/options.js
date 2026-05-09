/**
 * PhishGuard — Options Page Controller
 * Manages settings persistence via chrome.storage.sync + chrome.storage.local.
 */

// ──────────────────────────────────────────────────────────────────────────────
// DOM References
// ──────────────────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);

// General
const toggleEnabled        = $('toggle-enabled');
const toggleContentScript  = $('toggle-content-script');
const selectThreshold      = $('select-threshold');
const cacheTtl             = $('cache-ttl');
const btnClearCache        = $('btn-clear-cache');

// Threat Intel
const toggleSafeBrowsing   = $('toggle-safe-browsing');
const inputApiKey          = $('input-api-key');
const btnToggleKey         = $('btn-toggle-key');
const apiStatus            = $('api-status');
const apiKeySection        = $('api-key-section');

// Blocklist
const blocklistCount       = $('blocklist-count');
const btnClearBlocklist    = $('btn-clear-blocklist');
const blocklistImport      = $('blocklist-import');
const fileImport           = $('file-import');
const btnImportBlocklist   = $('btn-import-blocklist');

// Whitelist
const whitelistInput       = $('whitelist-input');
const btnAddWhitelist      = $('btn-add-whitelist');
const whitelistList        = $('whitelist-list');
const whitelistEmpty       = $('whitelist-empty');

// AI Trust
const toggleAiTrust        = $('toggle-ai-trust');
const geminiApiKey         = $('gemini-api-key');
const btnToggleGeminiKey   = $('btn-toggle-gemini-key');
const geminiStatus         = $('gemini-status');
const geminiKeySection     = $('gemini-key-section');

// Actions
const btnSave              = $('btn-save');
const optionsToast         = $('options-toast');

// Nav
const navItems             = document.querySelectorAll('.nav-item');

// ──────────────────────────────────────────────────────────────────────────────
// Default Settings
// ──────────────────────────────────────────────────────────────────────────────
const DEFAULTS = {
  enabled:             true,
  enableContentScript: true,
  sensitivity:         'balanced',
  cacheTtlMinutes:     5,
  enableSafeBrowsing:  false,
  safeBrowsingApiKey:  '',
  whitelistedDomains:  [],
  enableAITrustLayer:  true,
  geminiApiKey:        'AIzaSyC-bulMEy9FcwLfJ3FFMkcWJTQVuj0bnPU',
};

// ──────────────────────────────────────────────────────────────────────────────
// Load & Render Settings
// ──────────────────────────────────────────────────────────────────────────────
async function loadSettings() {
  try {
    const syncData  = await chrome.storage.sync.get(DEFAULTS);
    const localData = await chrome.storage.local.get({ customBlocklist: [] });

    // Apply to UI
    toggleEnabled.checked       = syncData.enabled;
    toggleContentScript.checked = syncData.enableContentScript;
    selectThreshold.value       = syncData.sensitivity || 'balanced';
    cacheTtl.value              = syncData.cacheTtlMinutes || 5;

    toggleSafeBrowsing.checked  = syncData.enableSafeBrowsing;
    inputApiKey.value           = syncData.safeBrowsingApiKey || '';
    apiKeySection.style.display = syncData.enableSafeBrowsing ? 'flex' : 'none';
    updateApiStatus(syncData.safeBrowsingApiKey);

    // Whitelist
    renderWhitelist(syncData.whitelistedDomains || []);

    // AI Trust
    toggleAiTrust.checked = syncData.enableAITrustLayer;
    geminiApiKey.value = syncData.geminiApiKey || '';
    geminiKeySection.style.display = syncData.enableAITrustLayer ? 'flex' : 'none';
    updateGeminiStatus(syncData.geminiApiKey);

    // Blocklist count
    const count = (localData.customBlocklist || []).length;
    blocklistCount.textContent = `${count} custom entr${count === 1 ? 'y' : 'ies'} loaded`;

  } catch (err) {
    console.error('[PhishGuard Options] Load error:', err);
    showToast('Failed to load settings.', 'error');
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Save Settings
// ──────────────────────────────────────────────────────────────────────────────
async function saveSettings() {
  try {
    await chrome.storage.sync.set({
      enabled:             toggleEnabled.checked,
      enableContentScript: toggleContentScript.checked,
      sensitivity:         selectThreshold.value,
      cacheTtlMinutes:     parseInt(cacheTtl.value, 10) || 5,
      enableSafeBrowsing:  toggleSafeBrowsing.checked,
      safeBrowsingApiKey:  inputApiKey.value.trim(),
      enableAITrustLayer:  toggleAiTrust.checked,
      geminiApiKey:        geminiApiKey.value.trim(),
    });

    // Notify service worker to clear cache (settings changed)
    await chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' }).catch(() => {});

    showToast('✅ Settings saved!');
    updateApiStatus(inputApiKey.value.trim());
  } catch (err) {
    console.error('[PhishGuard Options] Save error:', err);
    showToast('❌ Failed to save settings.', 'error');
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// API Key
// ──────────────────────────────────────────────────────────────────────────────
toggleSafeBrowsing.addEventListener('change', () => {
  apiKeySection.style.display = toggleSafeBrowsing.checked ? 'flex' : 'none';
});

btnToggleKey.addEventListener('click', () => {
  const isPassword = inputApiKey.type === 'password';
  inputApiKey.type   = isPassword ? 'text' : 'password';
  btnToggleKey.textContent = isPassword ? '🙈' : '👁';
});

function updateApiStatus(key) {
  if (!toggleSafeBrowsing.checked) {
    apiStatus.textContent = '';
    apiStatus.className   = 'api-status';
    return;
  }
  if (!key) {
    apiStatus.textContent = '⚠️ No API key — Safe Browsing disabled.';
    apiStatus.className   = 'api-status';
  } else if (key.startsWith('AIza') && key.length > 30) {
    apiStatus.textContent = '✅ API key looks valid.';
    apiStatus.className   = 'api-status ok';
  } else {
    apiStatus.textContent = '⚠️ API key format looks incorrect.';
    apiStatus.className   = 'api-status error';
  }
}

inputApiKey.addEventListener('input', () => updateApiStatus(inputApiKey.value.trim()));

// AI Trust API Key
toggleAiTrust.addEventListener('change', () => {
  geminiKeySection.style.display = toggleAiTrust.checked ? 'flex' : 'none';
});

btnToggleGeminiKey.addEventListener('click', () => {
  const isPassword = geminiApiKey.type === 'password';
  geminiApiKey.type = isPassword ? 'text' : 'password';
  btnToggleGeminiKey.textContent = isPassword ? '🙈' : '👁';
});

function updateGeminiStatus(key) {
  if (!toggleAiTrust.checked) {
    geminiStatus.textContent = '';
    geminiStatus.className = 'api-status';
    return;
  }
  if (!key) {
    geminiStatus.textContent = '⚠️ No Gemini key — LLM analysis disabled.';
    geminiStatus.className = 'api-status';
  } else if (key.startsWith('AIza') && key.length > 30) {
    geminiStatus.textContent = '✅ Gemini API key looks valid.';
    geminiStatus.className = 'api-status ok';
  } else {
    geminiStatus.textContent = '⚠️ Gemini API key format looks incorrect.';
    geminiStatus.className = 'api-status error';
  }
}

geminiApiKey.addEventListener('input', () => updateGeminiStatus(geminiApiKey.value.trim()));

// ──────────────────────────────────────────────────────────────────────────────
// Cache Clear
// ──────────────────────────────────────────────────────────────────────────────
btnClearCache.addEventListener('click', async () => {
  try {
    await chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' });
    showToast('🗑️ Cache cleared!');
  } catch {
    showToast('Cache clear failed.');
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// Blocklist Management
// ──────────────────────────────────────────────────────────────────────────────
btnImportBlocklist.addEventListener('click', () => importBlocklistText(blocklistImport.value));

fileImport.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (ev) => {
    blocklistImport.value = ev.target.result;
    importBlocklistText(ev.target.result);
  };
  reader.readAsText(file);
});

async function importBlocklistText(text) {
  if (!text || !text.trim()) {
    showToast('No domains to import.');
    return;
  }

  let domains = [];

  // Try JSON array first
  try {
    const parsed = JSON.parse(text.trim());
    if (Array.isArray(parsed)) {
      domains = parsed.filter(d => typeof d === 'string');
    }
  } catch {
    // Fall back to one-per-line
    domains = text.split(/[\n,]/)
      .map(d => d.trim().toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, ''))
      .filter(d => d.length > 0 && d.includes('.'));
  }

  if (domains.length === 0) {
    showToast('No valid domains found in input.');
    return;
  }

  try {
    const existing = (await chrome.storage.local.get({ customBlocklist: [] })).customBlocklist;
    const merged   = [...new Set([...existing, ...domains])];
    await chrome.storage.local.set({ customBlocklist: merged });
    blocklistCount.textContent = `${merged.length} custom entr${merged.length === 1 ? 'y' : 'ies'} loaded`;
    blocklistImport.value      = '';
    showToast(`✅ ${domains.length} domains added to blocklist!`);

    // Clear cache so new entries take effect
    await chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' }).catch(() => {});
  } catch (err) {
    showToast('Import failed: ' + err.message);
  }
}

btnClearBlocklist.addEventListener('click', async () => {
  if (!confirm('Clear all custom blocklist entries?')) return;
  await chrome.storage.local.set({ customBlocklist: [] });
  blocklistCount.textContent = '0 custom entries loaded';
  showToast('🗑️ Custom blocklist cleared.');
});

// ──────────────────────────────────────────────────────────────────────────────
// Whitelist Management
// ──────────────────────────────────────────────────────────────────────────────
function renderWhitelist(domains) {
  if (!domains || domains.length === 0) {
    whitelistList.innerHTML = '';
    whitelistEmpty.classList.remove('hidden');
    return;
  }
  whitelistEmpty.classList.add('hidden');
  whitelistList.innerHTML = domains.map(d => `
    <li class="tbs-domain-item">
      <span style="color:var(--safe);margin-right:6px">⚔️</span>
      <span style="flex:1;font-weight:500">${escapeHtml(d)}</span>
      <button class="tbs-remove-btn" data-domain="${escapeHtml(d)}" title="Remove">✕</button>
    </li>
  `).join('');
}

whitelistList.addEventListener('click', async (e) => {
  const btn = e.target.closest('.btn-remove');
  if (!btn) return;
  const domain = btn.dataset.domain;
  try {
    const data = await chrome.storage.sync.get({ whitelistedDomains: [] });
    const updated = data.whitelistedDomains.filter(d => d !== domain);
    await chrome.storage.sync.set({ whitelistedDomains: updated });
    renderWhitelist(updated);
    await chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' }).catch(() => {});
    showToast(`Removed "${domain}" from trusted list.`);
  } catch {
    showToast('Failed to remove domain.');
  }
});

btnAddWhitelist.addEventListener('click', async () => {
  const raw    = whitelistInput.value.trim().toLowerCase();
  const domain = raw.replace(/^(https?:\/\/)?(www\.)?/, '').split('/')[0];
  if (!domain || !domain.includes('.')) {
    showToast('Please enter a valid domain (e.g., example.com)');
    return;
  }
  try {
    const data    = await chrome.storage.sync.get({ whitelistedDomains: [] });
    const updated = [...new Set([...data.whitelistedDomains, domain])];
    await chrome.storage.sync.set({ whitelistedDomains: updated });
    renderWhitelist(updated);
    whitelistInput.value = '';
    showToast(`✅ "${domain}" added to trusted list.`);
    await chrome.runtime.sendMessage({ type: 'CLEAR_CACHE' }).catch(() => {});
  } catch {
    showToast('Failed to add domain.');
  }
});

whitelistInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') btnAddWhitelist.click();
});

// ──────────────────────────────────────────────────────────────────────────────
// Sidebar Navigation (smooth section scroll)
// ──────────────────────────────────────────────────────────────────────────────
navItems.forEach(item => {
  item.addEventListener('click', (e) => {
    e.preventDefault();
    navItems.forEach(n => n.classList.remove('active'));
    item.classList.add('active');
    const sectionId = item.dataset.section;
    const section   = document.getElementById(sectionId);
    if (section) section.scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
});

// ──────────────────────────────────────────────────────────────────────────────
// Save Button
// ──────────────────────────────────────────────────────────────────────────────
btnSave.addEventListener('click', saveSettings);

// ──────────────────────────────────────────────────────────────────────────────
// Toast
// ──────────────────────────────────────────────────────────────────────────────
let toastTimer = null;
function showToast(msg, type = 'info', duration = 2500) {
  optionsToast.textContent = msg;
  optionsToast.classList.remove('hidden', 'show');
  void optionsToast.offsetWidth; // Force reflow
  optionsToast.classList.add('show');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => optionsToast.classList.remove('show'), duration);
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// ──────────────────────────────────────────────────────────────────────────────
// Init
// ──────────────────────────────────────────────────────────────────────────────
loadSettings();
