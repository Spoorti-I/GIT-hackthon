import { analyzeURL } from '../src/analyzer/urlAnalyzer.js';
import { scoreResult } from '../src/analyzer/scorer.js';
import { RISK_CATEGORY } from '../src/shared/types.js';
import { simulatedTyposquatting, simulatedObfuscation, benignControl } from './mockData/threatSimulation.js';

describe('PhishGuard URL Analyzer Heuristics & AI', () => {

  test('flags simulated typosquatting URLs as suspicious or phishing', () => {
    for (const url of simulatedTyposquatting) {
      const raw = analyzeURL(url);
      const scored = scoreResult(raw);
      
      expect(scored.score).toBeGreaterThan(0);
      expect([RISK_CATEGORY.SUSPICIOUS, RISK_CATEGORY.PHISHING]).toContain(scored.category);
    }
  });

  test('flags simulated obfuscated URLs as suspicious or phishing', () => {
    for (const url of simulatedObfuscation) {
      const raw = analyzeURL(url);
      const scored = scoreResult(raw);
      
      expect(scored.score).toBeGreaterThan(0);
      expect([RISK_CATEGORY.SUSPICIOUS, RISK_CATEGORY.PHISHING]).toContain(scored.category);
    }
  });

  test('marks benign control URLs as safe', () => {
    for (const url of benignControl) {
      const raw = analyzeURL(url);
      const scored = scoreResult(raw);
      if (scored.score > 20) {
        console.log('Failed benign URL:', url, 'Score:', scored.score, 'Rules:', scored.sortedRules);
      }
      expect(scored.score).toBeLessThanOrEqual(20);
      expect(scored.category).toBe(RISK_CATEGORY.SAFE);
    }
  });

});
