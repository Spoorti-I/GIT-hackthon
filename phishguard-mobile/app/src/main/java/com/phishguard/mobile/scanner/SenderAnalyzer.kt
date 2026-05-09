package com.phishguard.mobile.scanner

/**
 * PhishGuard — Sender ID Analyzer
 *
 * Analyzes SMS sender IDs for signs of brand impersonation.
 * DLT registered senders in India use format: VM-HDFCBK, AM-SBIBNK etc.
 * Attackers clone these with minor variations.
 */
object SenderAnalyzer {

    private val KNOWN_BRAND_SENDERS = mapOf(
        "HDFCBK" to "HDFC Bank",
        "SBIUPI" to "SBI UPI",
        "ICICIB" to "ICICI Bank",
        "AXISBK" to "Axis Bank",
        "KOTAKB" to "Kotak Bank",
        "PNBSMS" to "PNB Bank",
        "PAYTM" to "Paytm",
        "PHONPE" to "PhonePe",
        "GPAYTS" to "Google Pay",
        "AMAZON" to "Amazon",
        "FLIPKT" to "Flipkart",
        "ZOMATO" to "Zomato",
        "SWIGGY" to "Swiggy",
        "JIOSMS" to "Jio",
        "AIRTEL" to "Airtel",
        "GOOGLE" to "Google",
        "VIISMS" to "Vi"
    )

    private val SENDER_PREFIXES = setOf("VM", "AM", "TM", "BM", "DM", "CP", "JD")

    /**
     * Analyzes a sender ID for impersonation indicators.
     */
    fun analyze(sender: String): SenderRisk {
        val cleanSender = sender.trim().uppercase()

        // 1. Check for exact known brand match — legitimate
        for ((brandCode, brandName) in KNOWN_BRAND_SENDERS) {
            if (cleanSender == brandCode || cleanSender == brandName.uppercase().replace(" ", "")) {
                return SenderRisk(
                    sender = sender,
                    isImpersonating = false,
                    impersonatedBrand = null,
                    riskScore = -40,
                    detail = "Verified sender: $brandName",
                    isVerified = true
                )
            }
            
            if (cleanSender.contains(brandCode)) {
                // Valid format: prefix + exact brand code (e.g., AD-JIOSMS, JM-JIONET)
                val parts = cleanSender.split("-")
                if (parts.size == 2 && parts[0] in SENDER_PREFIXES && 
                    (parts[1] == brandCode || parts[1].contains(brandCode))) {
                    return SenderRisk(
                        sender = sender,
                        isImpersonating = false,
                        impersonatedBrand = null,
                        riskScore = -40, // Layer 1: -40 for whitelisted
                        detail = "Verified DLT sender for $brandName",
                        isVerified = true
                    )
                }
            }
        }

        // 2. Check for near-match impersonation (typosquatting sender IDs)
        for ((brandCode, brandName) in KNOWN_BRAND_SENDERS) {
            val senderCore = cleanSender.replace(Regex("^(VM|AM|TM|BM|DM|CP|JD)-?"), "")
            if (levenshteinDistance(senderCore, brandCode) in 1..2) {
                return SenderRisk(
                    sender = sender,
                    isImpersonating = true,
                    impersonatedBrand = brandName,
                    riskScore = 40,
                    detail = "Sender \"$sender\" closely resembles $brandName's official ID \"$brandCode\". Possible impersonation."
                )
            }
        }

        // 3. Phone number senders (individual numbers) — elevated risk for financial content
        if (sender.matches(Regex("\\+?[0-9]{10,15}"))) {
            return SenderRisk(
                sender = sender,
                isImpersonating = false,
                impersonatedBrand = null,
                riskScore = 15,
                detail = "Message from phone number, not a registered business ID"
            )
        }

        // 4. Short 5-6 digit codes — potential premium rate or scam
        if (sender.matches(Regex("[0-9]{5,6}"))) {
            return SenderRisk(
                sender = sender,
                isImpersonating = false,
                impersonatedBrand = null,
                riskScore = 20,
                detail = "5-digit short code sender. Verify before clicking any links."
            )
        }

        return SenderRisk(
            sender = sender,
            isImpersonating = false,
            impersonatedBrand = null,
            riskScore = 0,
            detail = "Sender ID not matched to known brand patterns"
        )
    }

    private fun levenshteinDistance(a: String, b: String): Int {
        if (a == b) return 0
        if (a.isEmpty()) return b.length
        if (b.isEmpty()) return a.length
        val dp = Array(a.length + 1) { IntArray(b.length + 1) }
        for (i in 0..a.length) dp[i][0] = i
        for (j in 0..b.length) dp[0][j] = j
        for (i in 1..a.length) {
            for (j in 1..b.length) {
                dp[i][j] = if (a[i - 1] == b[j - 1]) dp[i - 1][j - 1]
                else 1 + minOf(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1])
            }
        }
        return dp[a.length][b.length]
    }
}
