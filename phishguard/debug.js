import { analyzeURL } from './src/analyzer/urlAnalyzer.js';
import { extractFeatures } from './src/ai/featureExtractor.js';
import { analyzeUrlWithAI } from './src/ai/modelManager.js';

const url = 'https://www.youtube.com/watch?v=sUf2PtEZris&list=RDsUf2PtEZris&start_radio=1';
console.log('Features:', extractFeatures(url));
console.log('AI:', analyzeUrlWithAI(url));
console.log('Rules:', analyzeURL(url).rules);
