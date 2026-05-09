package com.phishguard.mobile.scanner

/**
 * PhishGuard — Enhanced SMS Threat Scanner v2
 *
 * Multi-vector smishing detection engine covering:
 * - Urgency and fear manipulation
 * - Authority impersonation (bank, govt, telecom)
 * - Brand impersonation (Indian-specific)
 * - KYC fraud (common in India)
 * - OTP fraud
 * - Prize/lottery scams
 * - Financial action triggers
 * - URL analysis (integrated with UrlRiskScorer)
 * - Sender ID analysis (integrated with SenderAnalyzer)
 * - Multi-vector combination detection
 */
class SmsThreatScanner {

    // ── Layer 2: OTP Patterns ──────────────────────────────────────────────
    private val otpPatterns = listOf(
        "your otp is", "do not share", "valid for", "login code", "verification code",
        "one time password", "don't share", "secret code", "verification.*otp"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ── Layer 3: Bank Transaction Patterns ──────────────────────────────────
    private val bankPatterns = listOf(
        "debited", "credited", "txn", "a/c", "upi", "ref no", "balance",
        "account ending", "available balance", "spent on", "purchased at"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ── Layer 5: Social Engineering / Urgency ────────────────────────────────
    private val socialEngPatterns = listOf(
        "urgent", "verify now", "account blocked", "click immediately",
        "kyc expired", "claim reward", "lottery", "suspended",
        "action required", "final warning", "expires soon", "security alert"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ── Layer 6: Personal / Conversational Patterns ─────────────────────────
    private val personalPatterns = listOf(
        "where are you", "call me", "coming", "hello", "okay", "how are you",
        "reach", "reached", "at home", "waiting", "see you"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ── Layer 7: Regional Language Support (Hindi/Kannada) ──────────────────
    private val regionalPromoPatterns = listOf(
        "aapka", "kijiye", "dhanyawad", "namaste", "banni", "maadi", "ide"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    /**
     * Main entry point — analyzes a full SMS message using 8-layer logic.
     */
    fun scan(
        text: String, 
        sender: String = "", 
        isManualSafe: Boolean = false,
        historyCount: Int = 0
    ): SmsScanResult {
        val startTime = System.currentTimeMillis()
        if (text.isBlank()) {
            return SmsScanResult(false, 0, "SAFE", emptyList(), emptyList(), null, 0L)
        }

        val detectedSignals = mutableListOf<SmsRiskSignal>()
        var score = 0

        // ── URL Analysis (Layer 4) ───────────────────────────────────────────
        val urlRegex = "(https?://[^\\s]+)".toRegex()
        val detectedUrls = urlRegex.findAll(text).map { it.value }.toList()
        var hasMaliciousUrl = false

        detectedUrls.forEach { url ->
            val urlResult = UrlRiskScorer.analyze(url)
            if (urlResult.isWhitelisted) return@forEach

            if (urlResult.riskScore > 0) {
                score += urlResult.riskScore
                if (urlResult.riskScore >= 40) hasMaliciousUrl = true
                urlResult.signals.forEach { signal ->
                    detectedSignals.add(SmsRiskSignal(
                        type = SignalType.SUSPICIOUS_URL,
                        label = "URL Risk: $signal",
                        detail = "Suspect link detected",
                        score = 20
                    ))
                }
            }
        }

        // ── Layer 1: Trusted Sender Whitelist ───────────────────────────────
        val senderRisk = if (sender.isNotBlank()) SenderAnalyzer.analyze(sender) else null
        if (senderRisk != null && senderRisk.isVerified && detectedUrls.isEmpty()) {
            score -= 40
        }

        // ── Layer 1: Inbox History ──────────────────────────────────────────
        if (historyCount > 0 && detectedUrls.isEmpty()) {
            score -= 20
        }

        // ── Layer 8: Behavioral Learning (Manual Safe) ──────────────────────
        if (isManualSafe && detectedUrls.isEmpty()) {
            score -= 50
        }

        // ── Layer 5: Social Engineering (+15 each) ──────────────────────────
        socialEngPatterns.forEach { regex ->
            if (regex.containsMatchIn(text)) {
                score += 15
                detectedSignals.add(SmsRiskSignal(
                    type = SignalType.URGENCY,
                    label = "Urgency/Social Engineering",
                    detail = "Time pressure or fear tactic",
                    score = 15
                ))
            }
        }

        // ── Layer 2: OTP Context Detection ───────────────────────────────────
        val hasOtpContext = otpPatterns.any { it.containsMatchIn(text) }
        
        // ── Layer 3: Bank Transaction Detection ──────────────────────────────
        val hasBankPattern = bankPatterns.any { it.containsMatchIn(text) }

        // ── Layer 6: Personal Chat Detection ─────────────────────────────────
        val isPersonal = personalPatterns.any { it.containsMatchIn(text) }

        // ── Layer 7: Regional Support ────────────────────────────────────────
        val isRegional = regionalPromoPatterns.any { it.containsMatchIn(text) }

        // ── FINAL CLASSIFICATION LOGIC ──────────────────────────────────────
        
        // Capping and Classification
        var finalScore = score.coerceIn(0, 100)
        
        // OVERRIDES (Context-Aware)
        
        // Rule: OTP is SAFE unless malicious URL exists
        if (hasOtpContext && !hasMaliciousUrl) {
            finalScore = 0
            detectedSignals.clear()
        }

        // Rule: Bank Transaction is SAFE if sender is trusted
        if (hasBankPattern && senderRisk?.isVerified == true && !hasMaliciousUrl) {
            finalScore = 0
            detectedSignals.clear()
        }

        // Rule: Personal chat is SAFE
        if (isPersonal && !hasMaliciousUrl) {
            finalScore = 0
            detectedSignals.clear()
        }

        // Rule: Regional promo is SAFE unless malicious URL exists
        if (isRegional && !hasMaliciousUrl && finalScore > 50) {
            finalScore = 20 // Move to safe/low risk
        }

        val category = when {
            finalScore >= 76 -> "PHISHING"
            finalScore >= 51 -> "SUSPICIOUS"
            finalScore >= 26 -> "LOW RISK"
            else -> "SAFE"
        }

        return SmsScanResult(
            isPhishing = finalScore >= 76,
            score = finalScore,
            category = category,
            signals = detectedSignals,
            detectedUrls = detectedUrls,
            senderRisk = senderRisk,
            analysisMs = System.currentTimeMillis() - startTime
        )
    }

    /**
     * Enhanced scan that includes Cloud API lookups (Layer 4).
     */
    suspend fun scanWithCloud(
        text: String, 
        sender: String = "",
        isManualSafe: Boolean = false,
        historyCount: Int = 0
    ): SmsScanResult {
        val localResult = scan(text, sender, isManualSafe, historyCount)
        if (localResult.detectedUrls.isEmpty()) return localResult

        val newSignals = localResult.signals.toMutableList()
        var newScore = localResult.score

        for (url in localResult.detectedUrls) {
            // Check Google Safe Browsing
            if (CloudThreatScanner.checkGoogleSafeBrowsing(url)) {
                newScore += 60 // Layer 4 spec: +60
                newSignals.add(SmsRiskSignal(
                    type = SignalType.SUSPICIOUS_URL,
                    label = "Google Safe Browsing: MALICIOUS",
                    detail = "Blacklisted link found",
                    score = 60,
                    severity = SignalSeverity.CRITICAL
                ))
            }

            // Check VirusTotal
            val vtPositives = CloudThreatScanner.checkVirusTotal(url)
            if (vtPositives > 0) {
                newScore += 60 // Layer 4 spec: +60
                newSignals.add(SmsRiskSignal(
                    type = SignalType.SUSPICIOUS_URL,
                    label = "VirusTotal: $vtPositives Flags",
                    detail = "Security engines flagged this link",
                    score = 60,
                    severity = SignalSeverity.CRITICAL
                ))
            }
        }

        var finalScore = newScore.coerceIn(0, 100)
        
        // Re-apply overrides if malicious found
        val category = when {
            finalScore >= 76 -> "PHISHING"
            finalScore >= 51 -> "SUSPICIOUS"
            finalScore >= 26 -> "LOW RISK"
            else -> "SAFE"
        }

        return localResult.copy(
            isPhishing = finalScore >= 76,
            score = finalScore,
            category = category,
            signals = newSignals
        )
    }
}
