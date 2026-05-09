/**
 * PhishGuard — AI Trust Verification Layer
 * Orchestrates multiple AI/logic-based checks when heuristics say a site is SAFE.
 */

import { analyzeLinguisticPatterns } from './linguisticAnalyzer.js';
import { detectBrandImpersonation } from './brandImpersonationDetector.js';
import { analyzeBehavior } from './behavioralAnalyzer.js';
import { analyzeLinkChain } from './linkChainAnalyzer.js';
import { analyzeAttachments } from './attachmentAnalyzer.js';
import { analyzeWithGemini } from './geminiClient.js';
import { RULES } from '../shared/types.js';

/**
 * Runs the AI Trust Verification Layer.
 * @param {object} result - Existing heuristic result
 * @param {object} content - { bodyText, sender, attachments, ... }
 * @param {object} settings - { enableAITrustLayer, geminiApiKey, ... }
 * @returns {Promise<object>}
 */
export async function runAITrustVerification(result, content = {}, settings = {}) {
  const { bodyText, sender, attachments, history } = content;
  
  // 1. Local specialized analysis
  const linguisticScore = analyzeLinguisticPatterns(bodyText);
  const brandScore      = detectBrandImpersonation(bodyText || sender, result.domain);
  const behaviorScore   = await analyzeBehavior({ sender, history });
  const linkScore       = analyzeLinkChain(result.url);
  const attachmentScore = analyzeAttachments(attachments);

  // 2. Weighted total (Local)
  // Linguistic: 30%, Brand: 30%, Behavior: 20%, Link: 20%
  const localConfidence = (
    (linguisticScore * 0.3) +
    (brandScore * 0.3) +
    (behaviorScore * 0.2) +
    (linkScore * 0.2)
  );

  let finalAiScore = localConfidence;
  let usedGemini = false;
  let geminiVerdict = null;

  // 3. Optional Gemini upgrade
  if (settings.enableAITrustLayer && settings.geminiApiKey) {
    const geminiResult = await analyzeWithGemini({
      heuristicScore: result.score,
      linguisticScore,
      brandScore,
      behaviorScore,
      linkScore,
      attachmentScore,
      url: result.url,
      textSnippet: bodyText?.substring(0, 500)
    }, settings.geminiApiKey);

    if (geminiResult) {
      finalAiScore = geminiResult.confidence;
      geminiVerdict = geminiResult.verdict;
      usedGemini = true;
    }
  }

  // 4. Map to category
  let aiCategory = 'SAFE';
  if (finalAiScore > 60 || geminiVerdict === 'HIGH RISK') aiCategory = 'HIGH RISK';
  else if (finalAiScore > 30 || geminiVerdict === 'SUSPICIOUS') aiCategory = 'SUSPICIOUS';

  // 5. Build rules for the extension UI
  const aiRules = [
    { rule: RULES.AI_TRUST_LINGUISTIC, points: 0, reason: `Score: ${linguisticScore}/100` },
    { rule: RULES.AI_TRUST_BRAND,      points: 0, reason: `Score: ${brandScore}/100` },
    { rule: RULES.AI_TRUST_BEHAVIOR,   points: 0, reason: `Score: ${behaviorScore}/100` },
    { rule: RULES.AI_TRUST_LINK,       points: 0, reason: `Score: ${linkScore}/100` }
  ];

  return {
    ran: true,
    aiScore: Math.round(finalAiScore),
    aiCategory,
    subScores: {
      linguistic: linguisticScore,
      brand: brandScore,
      behavior: behaviorScore,
      link: linkScore,
      attachment: attachmentScore
    },
    usedGemini,
    aiRules,
    timestamp: Date.now()
  };
}
