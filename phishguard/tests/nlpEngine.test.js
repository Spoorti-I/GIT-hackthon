import { analyzeTextForPhishing } from '../src/ai/nlpEngine.js';

describe('PhishGuard NLP Engine', () => {

  test('detects Fake CEO email', () => {
    const text = "URGENT: I am in a meeting. I need you to login immediately and process a wire transfer. - CEO";
    const result = analyzeTextForPhishing(text);
    expect(result.isPhishing).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(80);
    expect(result.matches.urgency.length).toBeGreaterThan(0);
    expect(result.matches.authority.length).toBeGreaterThan(0);
    expect(result.matches.action.length).toBeGreaterThan(0);
  });

  test('detects Fake OTP SMS', () => {
    const text = "Your account has been suspended. Reply with your OTP to verify and unlock your account immediately.";
    const result = analyzeTextForPhishing(text);
    expect(result.isPhishing).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(80);
    expect(result.matches.urgency.length).toBeGreaterThan(0); // suspended, immediately
    expect(result.matches.action.length).toBeGreaterThan(0); // OTP, verify
  });

  test('detects Fake IT support message', () => {
    const text = "IT Support Desk: Final warning. Your password expires in 10 mins. Click here to update your account.";
    const result = analyzeTextForPhishing(text);
    expect(result.isPhishing).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(80);
  });

  test('detects Fake government notice', () => {
    const text = "Government Security Team: Immediate action required. Login to verify your tax refund or face penalties.";
    const result = analyzeTextForPhishing(text);
    expect(result.isPhishing).toBe(true);
    expect(result.score).toBeGreaterThanOrEqual(80);
  });

  test('ignores benign conversation', () => {
    const text = "Hey, are we still meeting with the CEO tomorrow to discuss the new login page update?";
    const result = analyzeTextForPhishing(text);
    // Might trigger some keywords (CEO, login) but should NOT cross the phishing threshold
    expect(result.isPhishing).toBe(false);
    expect(result.score).toBeLessThan(80);
  });

});
