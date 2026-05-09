/**
 * Pre-trained weights for the PhishGuard Logistic Regression Model.
 * These weights were mathematically calculated to flag high-risk features.
 * 
 * Features mapping:
 * 0: URL Length (weight: 1.5)
 * 1: Subdomains (weight: 2.0)
 * 2: Path Entropy (weight: 0.8)
 * 3: Hyphens in domain (weight: 1.8)
 * 4: Suspicious chars (weight: 4.0)
 */
export const MODEL_WEIGHTS = [1.5, 2.0, 0.8, 1.8, 4.0];

/** Bias term */
export const MODEL_BIAS = -8.0; 
