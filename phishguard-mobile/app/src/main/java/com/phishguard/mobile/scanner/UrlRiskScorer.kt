package com.phishguard.mobile.scanner

/**
 * PhishGuard — Lightweight URL Risk Scorer
 *
 * Ports key heuristics from the JS extension to Kotlin for offline,
 * on-device URL analysis within SMS messages.
 */
object UrlRiskScorer {

    private val SUSPICIOUS_TLDS = setOf(
        "tk", "ml", "ga", "cf", "gq", "pw", "top", "xyz",
        "icu", "cyou", "work", "click", "link", "online",
        "site", "space", "fun", "world", "vip", "buzz"
    )

    private val URL_SHORTENERS = setOf(
        "bit.ly", "t.co", "tinyurl.com", "is.gd", "buff.ly",
        "ow.ly", "short.io", "rebrand.ly", "cutt.ly", "tiny.cc",
        "shorturl.at", "rb.gy", "clck.ru"
    )

    private val SUSPICIOUS_KEYWORDS = listOf(
        "login", "signin", "verify", "account", "secure", "update",
        "confirm", "banking", "password", "credential", "authenticate",
        "suspended", "alert", "unlock", "validate", "recover",
        "kyc", "otp", "recharge", "winner", "claim", "reward",
        "free", "prize", "lucky", "offer", "cashback"
    )

    private val BRAND_NAMES = listOf(
        "hdfc", "sbi", "icici", "axis", "kotak", "paytm", "phonepe",
        "amazon", "flipkart", "irctc", "airtel", "jio", "google",
        "facebook", "whatsapp", "microsoft", "apple", "paypal",
        "netflix", "swiggy", "zomato", "ola", "uber"
    )

    private val TRUSTED_DOMAINS = setOf(
        "google.com", "google.co.in", "gmail.com", "facebook.com", "fb.me",
        "whatsapp.com", "microsoft.com", "apple.com", "amazon.in", "amazon.com",
        "flipkart.com", "paytm.com", "phonepe.com", "sbi.co.in", "icicibank.com",
        "hdfcbank.com", "axisbank.com", "kotak.com", "airtel.in", "jio.com",
        "m.jio.com", "myjio.jp", "airtel.jp", "bsnl.co.in", "vi.in",
        "irctc.co.in", "swiggy.com", "zomato.com", "gov.in", "nic.in"
    )

    data class UrlRiskResult(
        val url: String,
        val riskScore: Int,
        val signals: List<String>,
        val isShortened: Boolean,
        val hasSuspiciousTld: Boolean,
        val isWhitelisted: Boolean = false
    )

    fun analyze(url: String): UrlRiskResult {
        val signals = mutableListOf<String>()
        var score = 0
        val urlLower = url.lowercase()

        // 0. Whitelist Check
        val domain = extractDomain(urlLower)
        if (domain in TRUSTED_DOMAINS) {
            return UrlRiskResult(url, 0, emptyList(), false, false, true)
        }

        // 1. HTTP (not HTTPS)
        if (urlLower.startsWith("http://")) {
            score += 20
            signals.add("Unencrypted HTTP connection")
        }

        // 2. URL Shortener
        val isShortened = URL_SHORTENERS.any { urlLower.contains(it) }
        if (isShortened) {
            score += 25 // Layer 4: +25 for shortened
            signals.add("URL shortener hiding real destination")
        }

        // 3. Suspicious TLD
        val tld = extractTld(url)
        val hasSuspiciousTld = tld in SUSPICIOUS_TLDS
        if (hasSuspiciousTld) {
            score += 20 // Layer 4: +20 for suspicious TLD
            signals.add("High-risk TLD: .$tld")
        }

        // 4. IP address as host
        if (url.matches(Regex("https?://\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}.*"))) {
            score += 35
            signals.add("IP address used instead of domain name")
        }

        // 5. @ symbol in URL
        if (url.contains("@")) {
            score += 30
            signals.add("@ symbol in URL — real destination may be hidden")
        }

        // 6. Brand name in subdomain (not in domain)
        val subdomain = extractSubdomain(url)
        for (brand in BRAND_NAMES) {
            if (subdomain.contains(brand) && !domain.contains(brand)) {
                score += 35
                signals.add("Brand \"$brand\" in subdomain — possible impersonation of $domain")
                break
            }
        }

        // 7. Suspicious keywords in URL
        val foundKeywords = SUSPICIOUS_KEYWORDS.filter { urlLower.contains(it) }
        if (foundKeywords.size >= 2) {
            score += 20
            signals.add("Phishing keywords: ${foundKeywords.take(3).joinToString(", ")}")
        }

        // 8. Excessive URL length
        if (url.length > 100) {
            score += 10
            signals.add("Unusually long URL (${url.length} chars)")
        }

        // 9. Multiple subdomains (depth > 3)
        val parts = domain.split(".")
        if (parts.size > 4) {
            score += 15
            signals.add("Excessive subdomain depth — ${parts.size - 2} levels")
        }

        // 10. Punycode / international characters
        if (url.contains("xn--")) {
            score += 30 // Layer 4: +30 for punycode
            signals.add("Internationalized domain — possible visual spoofing")
        }

        return UrlRiskResult(
            url = url,
            riskScore = score.coerceIn(0, 100),
            signals = signals,
            isShortened = isShortened,
            hasSuspiciousTld = hasSuspiciousTld
        )
    }

    private fun extractTld(url: String): String {
        return try {
            val host = url.substringAfter("://").substringBefore("/")
                .substringBefore("?").substringBefore("#")
            host.substringAfterLast(".")
        } catch (e: Exception) { "" }
    }

    private fun extractDomain(url: String): String {
        return try {
            val host = url.substringAfter("://").substringBefore("/")
            val parts = host.split(".")
            if (parts.size >= 2) "${parts[parts.size - 2]}.${parts[parts.size - 1]}" else host
        } catch (e: Exception) { url }
    }

    private fun extractSubdomain(url: String): String {
        return try {
            val host = url.substringAfter("://").substringBefore("/")
            val parts = host.split(".")
            if (parts.size > 2) parts.dropLast(2).joinToString(".") else ""
        } catch (e: Exception) { "" }
    }
}
