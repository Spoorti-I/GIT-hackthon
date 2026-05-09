/**
 * PhishGuard — TTL Cache
 * In-memory cache with time-to-live expiry.
 * Avoids re-analyzing the same domain repeatedly.
 */

import { CACHE_TTL_MS } from './types.js';

class TTLCache {
  constructor(ttlMs = CACHE_TTL_MS) {
    this.ttl   = ttlMs;
    this.store = new Map(); // key → { value, expiry }
  }

  /**
   * Get a cached value if it hasn't expired.
   * @param {string} key
   * @returns {any|null}
   */
  get(key) {
    const entry = this.store.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiry) {
      this.store.delete(key);
      return null;
    }
    return entry.value;
  }

  /**
   * Store a value with TTL expiry.
   * @param {string} key
   * @param {any} value
   */
  set(key, value) {
    this.store.set(key, {
      value,
      expiry: Date.now() + this.ttl,
    });
    // Prune old entries if cache grows large
    if (this.store.size > 200) {
      this._prune();
    }
  }

  /**
   * Check if a key exists and is not expired.
   * @param {string} key
   * @returns {boolean}
   */
  has(key) {
    return this.get(key) !== null;
  }

  /**
   * Invalidate a specific key.
   * @param {string} key
   */
  delete(key) {
    this.store.delete(key);
  }

  /**
   * Clear all cached entries.
   */
  clear() {
    this.store.clear();
  }

  /**
   * Get cache statistics.
   * @returns {{ size: number, keys: string[] }}
   */
  stats() {
    this._prune();
    return {
      size: this.store.size,
      keys: [...this.store.keys()],
    };
  }

  /**
   * Remove all expired entries.
   * @private
   */
  _prune() {
    const now = Date.now();
    for (const [key, entry] of this.store.entries()) {
      if (now > entry.expiry) {
        this.store.delete(key);
      }
    }
  }
}

// Singleton cache instance shared across the service worker session
export const analysisCache = new TTLCache(CACHE_TTL_MS);
