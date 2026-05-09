/**
 * PhishGuard — AI Trust Verification Layer (Orchestrator)
 * Triggered ONLY when heuristic engine rates a URL/content as SAFE or LOW RISK.
 * Runs linguistic, brand, behavioral, link, and attachment analysis locally,
 * then optionally escalates to Gemini API for LLM-powered deep analysis.
 *
 * This module is ADDITIVE — it never overrides the heuristic engine.
 * It only produces an additional score that gets merged back via the existing scorer.
 */

import { analyzeLinguistics }        from './linguisticAnalyzer.js';
import { detectBrandImpersonation }  from './brandImpersonationDetector.js';
import { analyzeBehavior, recordSenderInteraction } from './behavioralAnalyzer.js';
import { analyzeLinkChain }          from './linkChainAnalyzer.js';
import { analyzeAttachments }        from './attachmentAnalyzer.js';
import { callGeminiAnalysis }        from './geminiClient.js';

/**
 * @typedef {Object} AITrustResult
 * @property {boolean}  ran             — Whether the AI layer ran
 * @property {number}   aiScore         — Combined AI confidence score (0–100)
 * @property {string}   aiCategory      — 'SAFE' | 'SUSPICIOUS' | 'HIGH_RISK'
 * @property {number}   languageRisk    — Linguistic analysis score (0–100)
 * @property {number}   brandScore      — Brand impersonation score (0–100)
 * @property {number}   behaviorScore   — Behavioral anomaly score (0–100)
 * @property {number}   linkRisk        — Link chain analysis score (0–100)
 * @property {number}   attachmentRisk  — Attachment analysis score (0–100)
 * @property {string[]} allFlags        — Combined flags from all sub-analyzers
 * @property {boolean}  usedGemini      — Whether Gemini API was used
 * @property {string}   geminiReasoning — Gemini reasoning text (if used)
 * @property {number}   heuristicPenalty — Points to add to heuristic score
 * @property {number}   timestamp
 */

/**
 * Determine the AI category from a composite score.
 * @param {number} score 0–100
 * @returns {'SAFE'|'SUSPICIOUS'|'HIGH_RISK'}
 */
function scoreToAICategory(score) {
  if (score >= 61) return 'HIGH_RISK';
  if (score >= 31) return 'SUSPICIOUS';
  return 'SAFE';
}

/**
 * Map AI category to a heuristic score penalty.
 * Conservative — respects the existing scoring thresholds.
 */
function categoryToPenalty(category) {
  switch (category) {
    case 'HIGH_RISK':  return 50;
    case 'SUSPICIOUS': return 25;
    default:           return 0;
  }
}

/**
 * Main entry point: Run the AI Trust Verification Layer.
 *
 * @param {Object} heuristicResult — The result from the existing heuristic engine
 * @param {Object} content         — Content signals (body, subject, sender info, URLs, attachments)
 * @param {Object} settings        — { enableAITrustLayer, geminiApiKey }
 * @returns {Promise<AITrustResult>}
 */
export async function runAITrustVerification(heuristicResult, content = {}, settings = {}) {
  if (!settings.enableAITrustLayer) {
    return { ran: false };
  }

  const {
    body          = '',
    subject       = '',
    displayName   = '',
    senderEmail   = '',
    senderDomain  = '',
    urls          = [],
    attachments   = [],
    displayUrl    = '',
    actualUrl     = '',
    sendTimestamp = Date.now(),
  } = content;

  // ── Step 1: Run all local sub-analyzers in parallel ─────────────────────
  const [linguistic, brand, behavior, links, attachment] = await Promise.all([
    Promise.resolve(analyzeLinguistics(body || subject)),
    Promise.resolve(detectBrandImpersonation({ displayName, senderEmail, senderDomain, body, subject })),
    analyzeBehavior({ senderEmail, senderDomain, sendTimestamp }),
    Promise.resolve(analyzeLinkChain({ body, urls, displayUrl, actualUrl })),
    Promise.resolve(analyzeAttachments({ attachments, body })),
  ]);

  // ── Step 2: Record sender interaction for future behavioral analysis ─────
  if (senderEmail) {
    recordSenderInteraction(senderEmail, senderDomain).catch(() => {});
  }

  // ── Step 3: Compute weighted AI composite score ─────────────────────────
  // Weights: linguistic 30%, brand 30%, behavioral 20%, link 20%
  // Attachments are additive bonus (up to +20 pts on top)
  const compositeScore = Math.round(
    linguistic.score  * 0.30 +
    brand.score       * 0.30 +
    behavior.score    * 0.20 +
    links.score       * 0.20
  ) + Math.min(20, Math.round(attachment.score * 0.2));

  const clampedScore   = Math.min(100, compositeScore);
  const localCategory  = scoreToAICategory(clampedScore);

  // ── Step 4: Combine all flags ────────────────────────────────────────────
  const allFlags = [
    ...linguistic.flags,
    ...brand.flags,
    ...behavior.flags,
    ...links.flags,
    ...attachment.flags,
  ];

  // ── Step 5: Optional Gemini deep analysis ────────────────────────────────
  let geminiVerdict   = 'SAFE';
  let geminiConfidence = 0;
  let geminiReasoning = '';
  let geminiFlags     = [];
  let usedGemini      = false;

  if (settings.geminiApiKey && settings.enableAITrustLayer) {
    const geminiResult = await callGeminiAnalysis({
      senderEmail,
      senderDomain,
      displayName,
      subject,
      body,
      url:             heuristicResult?.url,
      domain:          heuristicResult?.domain,
      linguisticFlags: linguistic.flags,
      brandFlags:      brand.flags,
      linkFlags:       links.flags,
      attachmentFlags: attachment.flags,
    }, settings.geminiApiKey);

    usedGemini      = geminiResult.usedGemini;
    geminiVerdict   = geminiResult.verdict || 'SAFE';
    geminiConfidence = geminiResult.confidence || 0;
    geminiReasoning = geminiResult.reasoning  || '';
    geminiFlags     = geminiResult.flags      || [];
  }

  // ── Step 6: Final AI category (Gemini takes precedence if used) ──────────
  const finalCategory = usedGemini
    ? (geminiVerdict === 'HIGH_RISK' || geminiVerdict === 'SUSPICIOUS' ? geminiVerdict : localCategory)
    : localCategory;

  // Reconcile score: if Gemini says high risk but local says safe, blend
  let finalScore = clampedScore;
  if (usedGemini && geminiConfidence > 0) {
    finalScore = Math.round((clampedScore * 0.4) + (geminiConfidence * 0.6));
  }

  const aiCategory      = finalScore >= 61 ? 'HIGH_RISK' : finalScore >= 31 ? 'SUSPICIOUS' : 'SAFE';
  const heuristicPenalty = categoryToPenalty(aiCategory);

  return {
    ran:             true,
    aiScore:         Math.min(100, finalScore),
    aiCategory,
    languageRisk:    linguistic.score,
    brandScore:      brand.score,
    behaviorScore:   behavior.score,
    linkRisk:        links.score,
    attachmentRisk:  attachment.score,
    allFlags:        [...new Set([...allFlags, ...geminiFlags])],
    detectedBrand:   brand.detectedBrand,
    isBrandSpoofed:  brand.isSpoofed,
    isFirstTimeSender: behavior.isFirstTime,
    usedGemini,
    geminiReasoning,
    heuristicPenalty,
    timestamp:       Date.now(),
  };
}
