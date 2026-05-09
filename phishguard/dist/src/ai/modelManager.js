import { extractFeatures } from './featureExtractor.js';
import { MODEL_WEIGHTS, MODEL_BIAS } from './modelWeights.js';

/**
 * PhishGuard — AI Model Manager
 * A lightweight client-side Logistic Regression engine.
 */

/**
 * Sigmoid activation function.
 * @param {number} z 
 * @returns {number} Probability between 0 and 1
 */
function sigmoid(z) {
  return 1 / (1 + Math.exp(-z));
}

/**
 * Analyzes a URL using the client-side ML model.
 * @param {string} url 
 * @returns {Object} { isPhishing: boolean, confidence: number }
 */
export function analyzeUrlWithAI(url) {
  const features = extractFeatures(url);
  
  // Dot product of weights and features
  let z = MODEL_BIAS;
  for (let i = 0; i < features.length; i++) {
    z += features[i] * MODEL_WEIGHTS[i];
  }

  // Calculate probability
  const probability = sigmoid(z);
  
  // Return result (score is 0-100)
  return {
    isPhishing: probability > 0.65, // Threshold for phishing
    confidence: Math.round(probability * 100)
  };
}
