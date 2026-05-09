/**
 * Threat Breathing Style — Popup Controller
 * Professional phishing detection popup with real-time state synchronization.
 */

import { generateRiskReport } from '../analyzer/scorer.js';
import { RISK_CATEGORY }      from '../shared/types.js';
import { truncate }           from '../shared/utils.js';

const $ = id => document.getElementById(id);

// DOM refs
const stateLoading   = $('state-loading');
const stateError     = $('state-error');
const stateResult    = $('state-result');
const errorReason    = $('error-reason');

const breathingCard  = $('breathing-card');
const ringFill       = $('ring-fill');
const scoreValue     = $('score-value');

const urlProtocolBadge = $('url-protocol-badge');
const urlDomainText    = $('url-domain-text');
const urlPathText      = $('url-path-text');

const adviceScroll   = $('advice-scroll');
const adviceList     = $('advice-list');

const aiEngineBlock     = $('ai-engine-block');
const aiConfidenceScore = $('ai-confidence-score');

const aiTrustPanel       = $('ai-trust-panel');
const aiTrustBadge       = $('ai-trust-badge');
const aiLangProgress     = $('ai-lang-progress');
const aiLangScore        = $('ai-lang-score');
const aiBrandProgress    = $('ai-brand-progress');
const aiBrandScore       = $('ai-brand-score');
const aiBehaviorProgress = $('ai-behavior-progress');
const aiBehaviorScore    = $('ai-behavior-score');
const aiLinkProgress     = $('ai-link-progress');
const aiLinkScore        = $('ai-link-score');
const aiFinalTrustScore  = $('ai-final-trust-score');

const signalCount    = $('signal-count');
const signalsList    = $('signals-list');
const analysisTbody  = $('analysis-tbody');

const btnSettings    = $('btn-settings');
const btnWhitelist   = $('btn-whitelist');
const btnCopy        = $('btn-copy');
const btnReport      = $('btn-report');
const btnRescan      = $('btn-rescan');
const toast          = $('toast');

// ── Status names per category ───────────────────────────────
const FORMS = {
  [RISK_CATEGORY.SAFE]:       { technique:'Status', name:'SAFE',     icon:'🛡️', sub:'Safe to browse' },
  [RISK_CATEGORY.SUSPICIOUS]: { technique:'Status', name:'CAUTION',  icon:'⚠️', sub:'Proceed with caution' },
  [RISK_CATEGORY.PHISHING]:   { technique:'Status', name:'PHISHING', icon:'🚨', sub:'Threat detected' },
  [RISK_CATEGORY.UNKNOWN]:    { technique:'Status', name:'SCANNING', icon:'🔍', sub:'Analyzing domain' },
};

let currentTabId = null, currentResult = null;

function showLoading() {
  stateLoading.classList.remove('hidden');
  stateError.classList.add('hidden');
  stateResult.classList.add('hidden');
}
function showError(msg) {
  stateLoading.classList.add('hidden');
  stateError.classList.remove('hidden');
  stateResult.classList.add('hidden');
  if (msg) errorReason.textContent = msg;
}
function showResult() {
  stateLoading.classList.add('hidden');
  stateError.classList.add('hidden');
  stateResult.classList.remove('hidden');
}

// ── Main render ───────────────────────────────────────────────────
function renderResult(result) {
  if (!result) return;
  
  if (result.error) {
    showError(result.errorMsg || 'An error occurred during analysis.');
    return;
  }

  if (result.category === RISK_CATEGORY.UNKNOWN) {
    showLoading();
    return;
  }
  
  currentResult = result;
  showResult();

  const cat   = result.category || RISK_CATEGORY.UNKNOWN;
  const form  = FORMS[cat];
  const score = result.score || 0;

  // Visual synchronization
  breathingCard.className = `breathing-card tbs-card st-${cat}`;
  
  const bgLayer = document.querySelector('.tbs-bg');
  if (bgLayer) bgLayer.className = `tbs-bg atm-${cat}`;

  const ringWrap = document.querySelector('.score-ring-wrap');
  if (ringWrap) ringWrap.className = `score-ring-wrap tbs-ring st-${cat}`;

  $('form-icon-wrap').textContent   = form.icon;
  $('form-technique').textContent  = form.technique;
  $('form-name').textContent       = form.name;

  // Score ring
  const pct    = Math.min(100, result.riskPercent || 0);
  const offset = 113 - (113 * pct / 100);
  ringFill.style.strokeDashoffset = offset;
  scoreValue.textContent = score;

  const slashEl = $('slash-text');
  if (slashEl) slashEl.textContent = form.sub;

  // URL display
  try {
    const parsed = new URL(result.url || '');
    urlProtocolBadge.textContent = (parsed.protocol === 'https:') ? 'HTTPS' : 'HTTP';
    urlProtocolBadge.className   = (parsed.protocol === 'https:') ? 'url-badge' : 'url-badge http';
    urlDomainText.textContent    = parsed.hostname;
    urlPathText.textContent      = truncate(parsed.pathname + parsed.search, 28);
  } catch {
    urlDomainText.textContent    = result.domain || 'Unknown';
  }

  // Advice
  if (cat !== RISK_CATEGORY.SAFE) {
    adviceScroll.classList.remove('hidden');
    adviceScroll.className = `advice-scroll cat-${cat}`;
    adviceList.innerHTML   = (result.advice || []).map(a => `<li>${esc(a)}</li>`).join('');
  } else {
    adviceScroll.classList.add('hidden');
  }

  // AI & Signals
  const aiRule = (result.sortedRules || []).find(r => r.rule === 'ai_phishing_model');
  aiEngineBlock.style.display = aiRule ? 'block' : 'none';
  if (aiRule) {
    const match = aiRule.reason.match(/(\d+)%/);
    aiConfidenceScore.textContent = match ? `${match[1]}%` : '99%';
  }

  // AI Trust Layer
  if (result.aiTrust) {
    aiTrustPanel.style.display = 'block';
    const trust = result.aiTrust;
    aiTrustBadge.textContent = trust.aiCategory;
    aiTrustBadge.style.backgroundColor = trust.aiCategory === 'SAFE' ? '#dcfce7' : (trust.aiCategory === 'HIGH RISK' ? '#fee2e2' : '#fef3c7');
    aiTrustBadge.style.color = trust.aiCategory === 'SAFE' ? '#15803d' : (trust.aiCategory === 'HIGH RISK' ? '#b91c1c' : '#b45309');
    
    aiLangScore.textContent = `${trust.subScores.linguistic}/100`;
    aiLangProgress.style.width = `${trust.subScores.linguistic}%`;
    
    aiBrandScore.textContent = `${trust.subScores.brand}/100`;
    aiBrandProgress.style.width = `${trust.subScores.brand}%`;
    
    aiBehaviorScore.textContent = `${trust.subScores.behavior}/100`;
    aiBehaviorProgress.style.width = `${trust.subScores.behavior}%`;
    
    aiLinkScore.textContent = `${trust.subScores.link}/100`;
    aiLinkProgress.style.width = `${trust.subScores.link}%`;
    
    aiFinalTrustScore.textContent = `${trust.aiScore}/100`;
  } else {
    aiTrustPanel.style.display = 'none';
  }

  const positives = (result.sortedRules || []).filter(r => r.points > 0);
  signalCount.textContent = positives.length;
  signalsList.innerHTML = positives.length === 0 
    ? `<p class="no-signals">✅ No suspicious signals detected.</p>`
    : positives.slice(0, 3).map((r, i) => `
      <div class="signal-card" style="animation-delay:${i*70}ms">
        <span class="signal-pts ${r.points >= 30 ? 'high' : 'med'}">+${r.points}</span>
        <div><span class="signal-label">${esc(r.label)}</span><span class="signal-detail">${esc(r.reason)}</span></div>
      </div>`).join('');

  // Analysis Table
  analysisTbody.innerHTML = (result.sortedRules || []).map(r => `
    <tr>
      <td><span class="cat-chip">${esc(r.category)}</span><br/>${esc(r.label)}</td>
      <td class="${r.points > 0 ? 'pts-pos' : 'pts-neg'}">${r.points > 0 ? '+' : ''}${r.points}</td>
      <td>${esc(r.reason)}</td>
    </tr>`).join('') || '<tr><td colspan="3">No data</td></tr>';

  // Whitelist
  btnWhitelist.textContent = result.isWhitelisted ? '✅ Trusted' : '🛡️ Trust Domain';
  btnWhitelist.disabled = !!result.isWhitelisted;
}

function esc(s) {
  return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function showToast(msg) {
  toast.textContent = msg;
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 2200);
}

// ── Real-time storage sync ────────────────────────────────────────
chrome.storage.onChanged.addListener((changes) => {
  const key = `tab_state_${currentTabId}`;
  if (changes[key]) {
    renderResult(changes[key].newValue);
  }
});

// ── Handlers ───────────────────────────────────────────────
btnSettings.addEventListener('click', () => chrome.runtime.openOptionsPage());
btnRescan.addEventListener('click', () => {
  showLoading();
  chrome.runtime.sendMessage({ type:'REANALYZE', tabId:currentTabId });
});
btnWhitelist.addEventListener('click', () => {
  chrome.runtime.sendMessage({ type:'ADD_WHITELIST', domain:currentResult.domain, tabId:currentTabId, url: currentResult.url });
});
btnCopy.addEventListener('click', () => {
  navigator.clipboard.writeText(generateRiskReport(currentResult));
  showToast('📜 Report copied!');
});

// ── Init ──────────────────────────────────────────────────────────
async function init() {
  const [tab] = await chrome.tabs.query({ active:true, currentWindow:true });
  if (!tab) return;
  currentTabId = tab.id;
  
  const key = `tab_state_${currentTabId}`;
  const data = await chrome.storage.local.get([key]);
  if (data[key]) renderResult(data[key]);
  else showLoading();
}

init();
