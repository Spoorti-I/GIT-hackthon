package com.phishguard.mobile.scanner

/**
 * PhishGuard — Enterprise SMS Threat Scanner v3
 *
 * 10-Layer AI + Threat Intelligence Detection Engine
 *
 * Layer 1  — Trusted Sender Verification        (SenderAnalyzer)
 * Layer 2  — Google Safe Browsing               (CloudThreatScanner)
 * Layer 3  — VirusTotal URL / Domain Lookup     (CloudThreatScanner)
 * Layer 4  — Twilio Phone Number Validation     (CloudThreatScanner)
 * Layer 5  — ML Context Classifier              (MlContextClassifier)
 * Layer 6  — Multilingual NLP                   (this file)
 * Layer 7  — Context Detection (OTP/Bank/Telco) (this file)
 * Layer 8  — Social Engineering Detection       (this file)
 * Layer 9  — User Feedback Score Adjustment     (UserFeedbackManager)
 * Layer 10 — AI Fusion Score (weighted blend)   (this file)
 *
 * Final Thresholds:
 *   0–20   SAFE
 *   21–40  LOW RISK
 *   41–60  PROMOTIONAL
 *   61–80  SUSPICIOUS
 *   81–100 PHISHING
 */
class SmsThreatScanner {

    // ══════════════════════════════════════════════════════════════════════
    //  LAYER 7 — Safe Context Patterns
    // ══════════════════════════════════════════════════════════════════════

    private val OTP_CONTEXT = listOf(
        "your otp", "otp is", "otp:", "one time password",
        "do not share", "don't share", "valid for \\d+ min",
        "verification code", "login code", "auth code",
        "use this code", "enter this code", "security code",
        "is your otp", "is your code", "\\d{4,8} is your"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    private val BANKING_CONTEXT = listOf(
        "debited", "credited", "a/c", "account ending", "account no",
        "upi", "ref no", "imps", "neft", "rtgs",
        "available balance", "avl bal", "closing balance",
        "spent on", "purchase at", "txn", "transaction",
        "emi", "auto-debit", "auto debit", "cheque clearance",
        "minimum due", "payment due", "standing instruction"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    private val TELECOM_CONTEXT = listOf(
        "data usage", "data balance", "gb remaining", "mb left",
        "recharge", "pack activated", "plan expired",
        "plan activated", "plan renewed", "validity",
        "free sms", "roaming activated", "network coverage",
        "data exhausted", "speed reduced", "unlimited calls",
        "jio fiber", "airtel broadband", "vi plan", "bsnl pack"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ══════════════════════════════════════════════════════════════════════
    //  LAYER 6 — Multilingual NLP (Hindi + Kannada safe patterns)
    // ══════════════════════════════════════════════════════════════════════

    private val HINDI_SAFE_PATTERNS = listOf(
        // Common Hindi words in promotional/transactional messages
        "aapka", "aapki", "aapke", "aap ka", "aap ki",
        "kijiye", "kare", "karein",
        "dhanyawad", "dhanyavaad", "shukriya",
        "namaste", "namaskar",
        "saphal", "safal",
        "recharge ho gaya", "recharge hua",
        "jama", "nikal", "prapt",
        "seva", "suvidha",
        "vishesh offer", "offer available",
        "mubarak", "shubhkamnayein",
        "khata", "bakaya", "utpann"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    private val KANNADA_SAFE_PATTERNS = listOf(
        // Common Kannada words in messages
        "banni", "maadi", "ide", "ade",
        "nimma", "nimage", "nim",
        "offer", "recharge maadi",
        "dhanyavadagalu", "dhanyavaadagalu",
        "seva", "balake",
        "hosa", "visheshha",
        "yogya", "upayoga"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // Hindi/Kannada scam-intent escalation (if these appear with regional, treat as phishing)
    private val REGIONAL_SCAM_ESCALATORS = listOf(
        "lottery", "lucky draw", "inam", "inaam",
        "jeeta", "jeet gaye",
        "kyc update", "kyc expire",
        "account band", "band ho jayega",
        "turant", "abhi click", "link par click"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ══════════════════════════════════════════════════════════════════════
    //  LAYER 8 — Social Engineering Patterns (+15 each)
    // ══════════════════════════════════════════════════════════════════════

    private val SOCIAL_ENG_PATTERNS = listOf(
        Pair("verify now",        "Verification urgency"),
        Pair("verify immediately","Verification urgency"),
        Pair("account blocked",   "Account threat"),
        Pair("account suspended", "Account threat"),
        Pair("account frozen",    "Account threat"),
        Pair("kyc expired",       "KYC fraud"),
        Pair("kyc update",        "KYC fraud"),
        Pair("kyc pending",       "KYC fraud"),
        Pair("click immediately", "Urgency click bait"),
        Pair("click now",         "Urgency click bait"),
        Pair("claim reward",      "Prize scam"),
        Pair("claim prize",       "Prize scam"),
        Pair("claim now",         "Prize scam"),
        Pair("lottery",           "Lottery fraud"),
        Pair("lucky draw",        "Prize scam"),
        Pair("you have won",      "Prize scam"),
        Pair("you are selected",  "Prize scam"),
        Pair("urgent",            "Urgency manipulation"),
        Pair("action required",   "Urgency manipulation"),
        Pair("final warning",     "Threat manipulation"),
        Pair("expires soon",      "Urgency manipulation"),
        Pair("security alert",    "Fear trigger"),
        Pair("demat frozen",      "Financial threat"),
        Pair("pancard suspended", "Authority impersonation"),
        Pair("aadhaar deactivation","Authority impersonation"),
        Pair("income tax refund", "Tax scam"),
        Pair("it refund",         "Tax scam"),
        Pair("insurance lapsed",  "Threat manipulation")
    ).map { (pattern, label) ->
        Pair(pattern.toRegex(RegexOption.IGNORE_CASE), label)
    }

    // ══════════════════════════════════════════════════════════════════════
    //  LAYER 10 — Weighted Fusion Weights
    // ══════════════════════════════════════════════════════════════════════

    private val W_SENDER    = 0.30
    private val W_URL       = 0.25
    private val W_ML        = 0.20
    private val W_BEHAVIORAL = 0.15
    private val W_LINGUISTIC = 0.10

    // ══════════════════════════════════════════════════════════════════════
    //  PUBLIC API — Local Scan (no network)
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Full local scan with 10-layer logic (no cloud calls).
     *
     * @param text         SMS body text
     * @param sender       Sender ID or phone number
     * @param historyCount Number of prior messages from this sender in DB
     * @param isManualSafe Whether user explicitly whitelisted this sender
     * @param feedbackAdj  Score delta from Layer 9 (getScoreAdjustment)
     */
    fun scan(
        text: String,
        sender: String = "",
        historyCount: Int = 0,
        isManualSafe: Boolean = false,
        feedbackAdj: Int = 0
    ): SmsScanResult {
        val startTime = System.currentTimeMillis()
        if (text.isBlank()) {
            return SmsScanResult(false, 0, "SAFE", emptyList(), emptyList(), null, 0L)
        }

        val detectedSignals = mutableListOf<SmsRiskSignal>()

        // ── Extract URLs ─────────────────────────────────────────────────
        val urlRegex    = "(https?://[^\\s]+)".toRegex()
        val detectedUrls = urlRegex.findAll(text).map { it.value }.toList()

        // ══ COMPONENT SCORES (each normalised 0–100 before weighting) ═══

        // ── Component A: Sender Score (Layer 1) ─────────────────────────
        val senderRisk = if (sender.isNotBlank())
            SenderAnalyzer.analyze(sender, historyCount, text)
        else null

        // senderRisk.riskScore is already [-80, +40]; shift to 0–100 range
        //  -80 → 0 (excellent) | 0 → 50 (neutral) | +40 → 100 (bad)
        val senderRaw    = senderRisk?.riskScore ?: 0
        val senderNorm   = ((senderRaw + 80).toFloat() / 120f * 100f).toInt().coerceIn(0, 100)

        // ── Component B: URL heuristic score (Layer 2 local part) ────────
        var urlHeuristic = 0
        var hasSuspiciousUrl = false
        detectedUrls.forEach { url ->
            val urlResult = UrlRiskScorer.analyze(url)
            if (urlResult.isWhitelisted) return@forEach
            if (urlResult.riskScore > 0) {
                urlHeuristic = maxOf(urlHeuristic, urlResult.riskScore)
                if (urlResult.riskScore >= 40) hasSuspiciousUrl = true
                urlResult.signals.forEach { signal ->
                    detectedSignals.add(SmsRiskSignal(
                        type   = SignalType.SUSPICIOUS_URL,
                        label  = "URL Risk: $signal",
                        detail = "Suspicious link pattern",
                        score  = urlResult.riskScore
                    ))
                }
            }
        }
        val urlNorm = urlHeuristic.coerceIn(0, 100)

        // ── Context detection (Layer 7) ───────────────────────────────────
        val hasOtpContext     = OTP_CONTEXT.any     { it.containsMatchIn(text) }
        val hasBankContext    = BANKING_CONTEXT.any { it.containsMatchIn(text) }
        val hasTelecomContext = TELECOM_CONTEXT.any { it.containsMatchIn(text) }

        // ── Component C: ML classification score (Layer 5) ───────────────
        val mlCategory = MlContextClassifier.classify(text, hasSuspiciousUrl)
        val mlRaw      = MlContextClassifier.mlScoreFor(mlCategory)
        // mlRaw is [-50, +60]; shift to 0–100
        val mlNorm     = ((mlRaw + 50).toFloat() / 110f * 100f).toInt().coerceIn(0, 100)

        // ── Component D: Behavioral score (Layer 9 + history) ────────────
        var behavioralRaw = 0
        if (isManualSafe)    behavioralRaw -= 30
        if (historyCount > 0) behavioralRaw -= 10
        behavioralRaw += feedbackAdj   // from UserFeedbackManager
        val behavioralNorm = ((behavioralRaw + 50).toFloat() / 100f * 100f).toInt().coerceIn(0, 100)

        // ── Component E: Linguistic / Social Engineering (Layers 6 & 8) ──
        var socialScore = 0
        SOCIAL_ENG_PATTERNS.forEach { (regex, label) ->
            if (regex.containsMatchIn(text)) {
                socialScore += 15
                detectedSignals.add(SmsRiskSignal(
                    type     = SignalType.URGENCY,
                    label    = "Social Engineering: $label",
                    detail   = "\"${regex.pattern}\" detected",
                    score    = 15,
                    severity = SignalSeverity.HIGH
                ))
            }
        }

        // Regional language safe override (Layer 6)
        val isHindiPromo    = HINDI_SAFE_PATTERNS.any  { it.containsMatchIn(text) }
        val isKannadaPromo  = KANNADA_SAFE_PATTERNS.any { it.containsMatchIn(text) }
        val hasRegionalScam = REGIONAL_SCAM_ESCALATORS.any { it.containsMatchIn(text) }
        val isRegionalSafe  = (isHindiPromo || isKannadaPromo) && !hasRegionalScam

        if (isRegionalSafe) socialScore = (socialScore - 20).coerceAtLeast(0)

        val linguisticNorm = socialScore.coerceIn(0, 100)

        // ══ LAYER 10 — FUSION SCORE ════════════════════════════════════════
        val fusedRaw = (
            senderNorm    * W_SENDER    +
            urlNorm       * W_URL       +
            mlNorm        * W_ML        +
            behavioralNorm * W_BEHAVIORAL +
            linguisticNorm * W_LINGUISTIC
        ).toInt()

        var finalScore = fusedRaw.coerceIn(0, 100)

        // ══ HARD OVERRIDES (highest priority context rules) ═══════════════

        // OTP messages are ALWAYS safe unless malicious URL confirmed
        if (hasOtpContext && !hasSuspiciousUrl) {
            finalScore = 0
            detectedSignals.clear()
        }

        // Bank alerts are safe when sender is verified AND no malicious URL
        if (hasBankContext && senderRisk?.isVerified == true && !hasSuspiciousUrl) {
            finalScore = minOf(finalScore, 15)
            detectedSignals.removeAll { it.type == SignalType.URGENCY }
        }

        // Telecom service messages are safe unless malicious URL
        if (hasTelecomContext && !hasSuspiciousUrl) {
            finalScore = minOf(finalScore, 15)
            detectedSignals.removeAll { it.type == SignalType.URGENCY }
        }

        // Regional promo without scam → cap at PROMOTIONAL max
        if (isRegionalSafe && finalScore > 60) {
            finalScore = 35
        }

        // TRUSTED sender (5+ history) → hard cap at LOW RISK unless URL
        if (senderRisk?.trustLevel == TrustLevel.TRUSTED && !hasSuspiciousUrl) {
            finalScore = minOf(finalScore, 20)
        }

        // Verified DLT sender with no URL → max LOW RISK
        if (senderRisk?.trustLevel == TrustLevel.VERIFIED && !hasSuspiciousUrl) {
            finalScore = minOf(finalScore, 30)
        }

        // ── Classify ────────────────────────────────────────────────────
        val category = classifyScore(finalScore)

        return SmsScanResult(
            isPhishing   = finalScore >= 81,
            score        = finalScore,
            category     = category,
            signals      = detectedSignals,
            detectedUrls = detectedUrls,
            senderRisk   = senderRisk,
            analysisMs   = System.currentTimeMillis() - startTime,
            mlCategory   = mlCategory
        )
    }

    // ══════════════════════════════════════════════════════════════════════
    //  PUBLIC API — Full Cloud Scan (Layers 2, 3, 4 network calls)
    // ══════════════════════════════════════════════════════════════════════

    /**
     * Full scan including cloud threat API lookups.
     * Calls Google Safe Browsing (L2), VirusTotal (L3), Twilio (L4).
     *
     * @param feedbackAdj Pre-looked-up score delta from UserFeedbackManager
     */
    suspend fun scanWithCloud(
        text: String,
        sender: String = "",
        historyCount: Int = 0,
        isManualSafe: Boolean = false,
        feedbackAdj: Int = 0
    ): SmsScanResult {
        // Start with local analysis
        val local = scan(text, sender, historyCount, isManualSafe, feedbackAdj)

        var newScore   = local.score
        val newSignals = local.signals.toMutableList()
        var hasMaliciousUrlCloud = false

        // ── Layer 2: Google Safe Browsing ─────────────────────────────────
        for (url in local.detectedUrls) {
            when (CloudThreatScanner.checkGoogleSafeBrowsing(url)) {
                is CloudThreatScanner.GsbResult.MaliciousUrl -> {
                    newScore += 80
                    hasMaliciousUrlCloud = true
                    newSignals.add(SmsRiskSignal(
                        type     = SignalType.SUSPICIOUS_URL,
                        label    = "Google Safe Browsing: MALICIOUS",
                        detail   = "Blacklisted by Google threat database",
                        score    = 80,
                        severity = SignalSeverity.CRITICAL
                    ))
                }
                is CloudThreatScanner.GsbResult.CleanUrl -> {
                    newScore -= 30
                    newSignals.add(SmsRiskSignal(
                        type     = SignalType.SUSPICIOUS_URL,
                        label    = "Google Safe Browsing: CLEAN",
                        detail   = "URL verified safe by Google",
                        score    = -30,
                        severity = SignalSeverity.LOW
                    ))
                }
                is CloudThreatScanner.GsbResult.NotScanned -> Unit
            }

            // ── Layer 3: VirusTotal ──────────────────────────────────────
            when (val vtResult = CloudThreatScanner.checkVirusTotal(url)) {
                is CloudThreatScanner.VtResult.Flagged -> {
                    newScore += 70
                    hasMaliciousUrlCloud = true
                    newSignals.add(SmsRiskSignal(
                        type     = SignalType.SUSPICIOUS_URL,
                        label    = "VirusTotal: ${vtResult.count} Flags",
                        detail   = "${vtResult.count} security engines flagged this link",
                        score    = 70,
                        severity = SignalSeverity.CRITICAL
                    ))
                }
                is CloudThreatScanner.VtResult.CleanUrl -> {
                    newScore -= 25
                    newSignals.add(SmsRiskSignal(
                        type     = SignalType.SUSPICIOUS_URL,
                        label    = "VirusTotal: CLEAN",
                        detail   = "URL verified clean by VirusTotal",
                        score    = -25,
                        severity = SignalSeverity.LOW
                    ))
                }
                is CloudThreatScanner.VtResult.NotScanned -> Unit
            }
        }

        // ── Layer 4: Twilio (only for phone number senders) ───────────────
        val isPhoneSender = sender.matches(Regex("\\+?[0-9]{10,15}"))
        if (isPhoneSender) {
            when (CloudThreatScanner.checkTwilioLookup(sender)) {
                is CloudThreatScanner.TwilioResult.Legitimate -> {
                    newScore -= 20
                    newSignals.add(SmsRiskSignal(
                        type     = SignalType.SENDER_SUSPICIOUS,
                        label    = "Twilio: Legitimate Number",
                        detail   = "Phone number verified by Twilio carrier lookup",
                        score    = -20,
                        severity = SignalSeverity.LOW
                    ))
                }
                is CloudThreatScanner.TwilioResult.Spoofed -> {
                    newScore += 50
                    newSignals.add(SmsRiskSignal(
                        type     = SignalType.TWILIO_SPOOFED,
                        label    = "Twilio: SPOOFED NUMBER",
                        detail   = "Sender phone number appears spoofed or uses VOIP",
                        score    = 50,
                        severity = SignalSeverity.CRITICAL
                    ))
                }
                is CloudThreatScanner.TwilioResult.NotScanned -> Unit
            }
        }

        var finalScore = newScore.coerceIn(0, 100)

        // Re-apply safe overrides even after cloud checks
        // OTP: hard safe unless cloud confirmed malicious URL
        val hasOtp     = OTP_CONTEXT.any      { it.containsMatchIn(text) }
        val hasBanking = BANKING_CONTEXT.any  { it.containsMatchIn(text) }
        val hasTelecom = TELECOM_CONTEXT.any  { it.containsMatchIn(text) }

        if (hasOtp && !hasMaliciousUrlCloud)                                        finalScore = 0
        if (hasBanking && local.senderRisk?.isVerified == true && !hasMaliciousUrlCloud) finalScore = minOf(finalScore, 15)
        if (hasTelecom && !hasMaliciousUrlCloud)                                    finalScore = minOf(finalScore, 15)

        val category = classifyScore(finalScore)

        return local.copy(
            isPhishing   = finalScore >= 81,
            score        = finalScore,
            category     = category,
            signals      = newSignals
        )
    }

    // ─── Score → Category mapping (Layer 10 thresholds) ──────────────────

    private fun classifyScore(score: Int): String = when {
        score >= 81 -> "PHISHING"
        score >= 61 -> "SUSPICIOUS"
        score >= 41 -> "PROMOTIONAL"
        score >= 21 -> "LOW RISK"
        else        -> "SAFE"
    }
}
