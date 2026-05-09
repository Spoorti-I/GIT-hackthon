/**
 * PhishGuard — Gemini API Client
 * Optional LLM-powered analysis for the AI Trust Layer.
 */

const GEMINI_API_ENDPOINT = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent';

/**
 * Sends content to Gemini for deep security analysis.
 * @param {object} analysisData - Combined data from all analyzers
 * @param {string} apiKey - Gemini API Key
 * @returns {Promise<object>}
 */
export async function analyzeWithGemini(analysisData, apiKey) {
  if (!apiKey) return null;

  const prompt = `
    Analyze the following content for phishing and social engineering threats. 
    Heuristic results: ${JSON.stringify(analysisData)}
    
    Respond in JSON format only:
    {
      "confidence": 0-100,
      "verdict": "SAFE" | "SUSPICIOUS" | "HIGH RISK",
      "reasoning": "string"
    }
  `;

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 8000); // 8 second timeout

  try {
    const response = await fetch(`${GEMINI_API_ENDPOINT}?key=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }]
      }),
      signal: controller.signal
    });
    clearTimeout(timeoutId);

    if (!response.ok) throw new Error(`Gemini API error: ${response.status}`);

    const data = await response.json();
    const textResult = data.candidates?.[0]?.content?.parts?.[0]?.text;
    
    // Extract JSON from response (sometimes Gemini wraps it in markdown)
    const jsonMatch = textResult.match(/\{[\s\S]*\}/);
    return jsonMatch ? JSON.parse(jsonMatch[0]) : null;

  } catch (err) {
    console.warn('[PhishGuard] Gemini analysis failed:', err.message);
    return null;
  }
}
