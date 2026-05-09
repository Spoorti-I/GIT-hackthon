package com.phishguard.mobile.scanner

/**
 * PhishGuard — Sender ID Analyzer v3 (Enterprise Edition)
 *
 * Layer 1: Trusted Sender Verification
 * - Comprehensive DLT brand database (Telecoms, Banks, Apps)
 * - Auto-whitelist with -60 score for verified senders
 * - TRUSTED classification after 5+ history appearances
 * - Impersonation detection via Levenshtein distance
 */
object SenderAnalyzer {

    // ── Comprehensive brand code → brand name database ─────────────────────
    private val KNOWN_BRAND_SENDERS = mapOf(
        // Telecom — Jio
        "JIOSMS" to "Jio",
        "JIONET" to "Jio",
        "JIOBIZ" to "Jio",
        "JIOPAY" to "Jio",
        "JIOCIN" to "Jio",
        "JIOADS" to "Jio",
        "JIOMSG" to "Jio",

        // Telecom — Airtel
        "AIRTEL" to "Airtel",
        "AIRTLM" to "Airtel",
        "AIRTLP" to "Airtel",
        "AIRTLB" to "Airtel",
        "AIRBN"  to "Airtel",

        // Telecom — Vi (Vodafone Idea)
        "VIISMS" to "Vi",
        "VILIVE" to "Vi",
        "VISMS"  to "Vi",
        "VODAIN" to "Vi",

        // Telecom — BSNL
        "BSNL"   to "BSNL",
        "BSNLSM" to "BSNL",
        "BSNLPK" to "BSNL",

        // Bank — SBI
        "SBIUPI" to "SBI",
        "SBISMS" to "SBI",
        "SBINBK" to "SBI",
        "SBIALR" to "SBI",
        "SBI"    to "SBI",

        // Bank — HDFC
        "HDFCBK" to "HDFC Bank",
        "HDFCBN" to "HDFC Bank",
        "HDFCCC" to "HDFC Bank",
        "HDFCNL" to "HDFC Bank",

        // Bank — ICICI
        "ICICIB" to "ICICI Bank",
        "ICICIN" to "ICICI Bank",
        "ICICIBANK" to "ICICI Bank",

        // Bank — Axis
        "AXISBK" to "Axis Bank",
        "AXISBN" to "Axis Bank",

        // Bank — Kotak
        "KOTAKB" to "Kotak Bank",
        "KOTKMB" to "Kotak Bank",

        // Bank — Canara
        "CANBNK" to "Canara Bank",
        "CANBKS" to "Canara Bank",
        "CANARA" to "Canara Bank",

        // Bank — PNB
        "PNBSMS" to "PNB",
        "PNBANK" to "PNB",

        // Bank — BOB
        "BOIBNK" to "Bank of India",
        "BOBSMS" to "Bank of Baroda",

        // UPI / Payments
        "PAYTM"  to "Paytm",
        "PTMBNK" to "Paytm Bank",
        "PHONPE" to "PhonePe",
        "PHPE"   to "PhonePe",
        "GPAYTS" to "Google Pay",
        "GPAY"   to "Google Pay",

        // E-commerce
        "AMAZON" to "Amazon",
        "AMZNIN" to "Amazon",
        "FLIPKT" to "Flipkart",
        "FLPKRT" to "Flipkart",
        "ZOMATO" to "Zomato",
        "ZMTO"   to "Zomato",
        "SWIGGY" to "Swiggy",
        "SWGY"   to "Swiggy",

        // Tech
        "GOOGLE" to "Google",
        "NFLX"   to "Netflix",
        "IRCTCB" to "IRCTC",
        "IRCTC"  to "IRCTC",

        // Insurance / Govt
        "LICIND" to "LIC India",
        "GOVTIN" to "Government of India",
        "NSDL"   to "NSDL",
        "CDSL"   to "CDSL"
    )

    // ── All valid DLT-registered sender prefixes used in India ─────────────
    private val SENDER_PREFIXES = setOf(
        "VM", "AM", "TM", "BM", "DM", "CP", "JD",
        "AD", "AX", "JX", "JM", "VK", "VN", "TP",
        "IM", "BK", "HD", "SB", "IC", "KT", "AX",
        "AT", "VI", "BS", "GG", "PY", "PP", "FK",
        "ZO", "SW", "IR"
    )

    // ── Telecom-specific keywords that indicate usage/service messages ──────
    private val TELECOM_BODY_KEYWORDS = listOf(
        "data usage", "recharge", "plan expired", "validity",
        "gb remaining", "pack activated", "balance", "mb left",
        "free sms", "roaming", "network"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    /**
     * Analyzes a sender ID and returns a SenderRisk.
     *
     * @param sender      The raw sender string from the SMS
     * @param historyCount Number of previous messages from this sender stored in DB
     * @param messageBody Optional body text to help correct telecom false positives
     */
    fun analyze(
        sender: String,
        historyCount: Int = 0,
        messageBody: String = ""
    ): SenderRisk {
        val cleanSender = sender.trim().uppercase()

        // ── 0. Auto-TRUSTED: 5+ history appearances ────────────────────────
        if (historyCount >= 5) {
            return SenderRisk(
                sender = sender,
                isImpersonating = false,
                impersonatedBrand = null,
                riskScore = -60,
                detail = "TRUSTED sender — appeared $historyCount times in inbox history",
                isVerified = true,
                trustLevel = TrustLevel.TRUSTED
            )
        }

        // ── 1. Exact brand code match (bare code, e.g. "HDFCBK") ───────────
        for ((brandCode, brandName) in KNOWN_BRAND_SENDERS) {
            if (cleanSender == brandCode) {
                return buildVerified(sender, brandName, historyCount)
            }
        }

        // ── 2. DLT format match: PREFIX-BRANDCODE (e.g. "JX-JIOSMS") ──────
        val parts = cleanSender.split("-")
        if (parts.size == 2 && parts[0] in SENDER_PREFIXES) {
            val brandCode = parts[1]
            val brandName = KNOWN_BRAND_SENDERS[brandCode]
                ?: KNOWN_BRAND_SENDERS.entries.firstOrNull { (code, _) ->
                    brandCode.contains(code) || code.contains(brandCode)
                }?.value

            if (brandName != null) {
                return buildVerified(sender, brandName, historyCount)
            }
        }

        // ── 3. Partial match in full sender (e.g. "AD-JIONET123") ──────────
        for ((brandCode, brandName) in KNOWN_BRAND_SENDERS) {
            if (cleanSender.contains(brandCode)) {
                return buildVerified(sender, brandName, historyCount)
            }
        }

        // ── 4. Near-match impersonation check (typosquatting) ──────────────
        for ((brandCode, brandName) in KNOWN_BRAND_SENDERS) {
            val senderCore = cleanSender.replace(Regex("^(${SENDER_PREFIXES.joinToString("|")})-?"), "")
            if (senderCore.length in 4..10 && levenshteinDistance(senderCore, brandCode) in 1..2) {
                return SenderRisk(
                    sender = sender,
                    isImpersonating = true,
                    impersonatedBrand = brandName,
                    riskScore = 40,
                    detail = "Sender \"$sender\" closely resembles $brandName's official ID \"$brandCode\". Possible impersonation.",
                    trustLevel = TrustLevel.SUSPICIOUS
                )
            }
        }

        // ── 5. Phone number sender — moderate risk ──────────────────────────
        if (sender.matches(Regex("\\+?[0-9]{10,15}"))) {
            // Reduce risk if inbox history exists (known contact)
            val phoneRisk = if (historyCount > 0) 5 else 15
            return SenderRisk(
                sender = sender,
                isImpersonating = false,
                impersonatedBrand = null,
                riskScore = phoneRisk,
                detail = "Message from phone number — not a registered business ID",
                trustLevel = TrustLevel.UNKNOWN
            )
        }

        // ── 6. 5–6 digit short code ─────────────────────────────────────────
        if (sender.matches(Regex("[0-9]{5,6}"))) {
            return SenderRisk(
                sender = sender,
                isImpersonating = false,
                impersonatedBrand = null,
                riskScore = 20,
                detail = "5-digit short code sender. Verify before clicking links.",
                trustLevel = TrustLevel.UNKNOWN
            )
        }

        // ── 7. Default: neutral unrecognized sender ID ──────────────────────
        return SenderRisk(
            sender = sender,
            isImpersonating = false,
            impersonatedBrand = null,
            riskScore = 0,
            detail = "Sender ID not matched to known brand patterns",
            trustLevel = TrustLevel.UNKNOWN
        )
    }

    /** Builds a VERIFIED SenderRisk with -60 score adjustment. */
    private fun buildVerified(sender: String, brandName: String, historyCount: Int): SenderRisk {
        val bonus = if (historyCount > 0) -20 else 0 // history bonus stacks
        return SenderRisk(
            sender = sender,
            isImpersonating = false,
            impersonatedBrand = null,
            riskScore = -60 + bonus,
            detail = "Verified DLT sender for $brandName",
            isVerified = true,
            trustLevel = TrustLevel.VERIFIED
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

/** Trust classification for a sender. */
enum class TrustLevel {
    TRUSTED,    // 5+ history; auto-safe
    VERIFIED,   // DLT-registered brand code match
    UNKNOWN,    // Unrecognized but not suspicious
    SUSPICIOUS  // Possible impersonation
}
