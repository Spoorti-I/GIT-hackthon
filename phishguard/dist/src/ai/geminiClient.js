/**
 * PhishGuard — Gemini API Client (AI Trust Layer)
 * Optional LLM-powered deep analysis using Google Gemini.
 * Only called when user has configured a Gemini API key.
 */

const GEMINI_API_BASE = 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent';

const SYSTEM_PROMPT = `You are a cybersecurity expert specializing in phishing and social engineering detection. 
Analyze the provided message content and metadata for phishing indicators.
You MUST respond with ONLY valid JSON in this exact format:
{
  "verdict": "SAFE" | "SUSPICIOUS" | "HIGH_RISK",
  "confidence": <number 0-100>,
  "reasoning": "<one concise sentence>",
  "flags": ["<flag1>", "<flag2>"]
}
Do not include any other text outside the JSON.`;

/**
 * Build a structured prompt from extracted signals.
 */
function buildPrompt(signals) {
  const parts = ['Analyze this content for phishing/social engineering:\n'];

  if (signals.senderEmail)  parts.push(`Sender Email: ${signals.senderEmail}`);
  if (signals.senderDomain) parts.push(`Sender Domain: ${signals.senderDomain}`);
  if (signals.displayName)  parts.push(`Display Name: ${signals.displayName}`);
  if (signals.subject)      parts.push(`Subject: ${signals.subject}`);
  if (signals.url)          parts.push(`URL: ${signals.url}`);
  if (signals.domain)       parts.push(`Domain: ${signals.domain}`);

  if (signals.body) {
    const truncatedBody = signals.body.length > 800
      ? signals.body.slice(0, 800) + '... [truncated]'
      : signals.body;
    parts.push(`\nMessage Body:\n${truncatedBody}`);
  }

  if (signals.linguisticFlags?.length)  parts.push(`\nLinguistic Flags: ${signals.linguisticFlags.join(', ')}`);
  if (signals.brandFlags?.length)       parts.push(`Brand Flags: ${signals.brandFlags.join(', ')}`);
  if (signals.linkFlags?.length)        parts.push(`Link Flags: ${signals.linkFlags.join(', ')}`);
  if (signals.attachmentFlags?.length)  parts.push(`Attachment Flags: ${signals.attachmentFlags.join(', ')}`);

  parts.push('\nRespond with ONLY the JSON object described in your instructions.');
  return parts.join('\n');
}

/**
 * Call Gemini API for deep phishing analysis.
 * @param {Object} signals - Aggregated signals from local analyzers
 * @param {string} apiKey  - Gemini API key
 * @returns {Promise<{ verdict: string, confidence: number, reasoning: string, flags: string[], usedGemini: boolean }>}
 */
export async function callGeminiAnalysis(signals, apiKey) {
  if (!apiKey || !signals) {
    return { verdict: 'SAFE', confidence: 0, reasoning: 'Gemini not configured', flags: [], usedGemini: false };
  }

  try {
    const prompt = buildPrompt(signals);
    const requestBody = {
      contents: [
        {
          role: 'user',
          parts: [{ text: `${SYSTEM_PROMPT}\n\n${prompt}` }],
        },
      ],
      generationConfig: {
        temperature:    0.1,
        maxOutputTokens: 256,
        responseMimeType: 'application/json',
      },
    };

    const response = await fetch(`${GEMINI_API_BASE}?key=${apiKey}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(requestBody),
    });

    if (!response.ok) {
      console.warn('[PhishGuard AI Trust] Gemini API error:', response.status);
      return { verdict: 'SAFE', confidence: 0, reasoning: `Gemini API error ${response.status}`, flags: [], usedGemini: false };
    }

    const data = await response.json();
    const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
    if (!rawText) throw new Error('Empty Gemini response');

    // Parse JSON response
    const parsed = JSON.parse(rawText.trim());

    return {
      verdict:    parsed.verdict    || 'SAFE',
      confidence: Number(parsed.confidence) || 0,
      reasoning:  parsed.reasoning  || '',
      flags:      Array.isArray(parsed.flags) ? parsed.flags : [],
      usedGemini: true,
    };

  } catch (err) {
    console.warn('[PhishGuard AI Trust] Gemini call failed:', err.message);
    return { verdict: 'SAFE', confidence: 0, reasoning: `Gemini error: ${err.message}`, flags: [], usedGemini: false };
  }
}
