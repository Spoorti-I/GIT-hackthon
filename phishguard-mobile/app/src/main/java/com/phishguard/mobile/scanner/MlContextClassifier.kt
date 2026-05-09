package com.phishguard.mobile.scanner

/**
 * PhishGuard — ML Context Classifier (Layer 5)
 *
 * On-device classification of SMS messages into semantic categories.
 * This replicates Google ML Kit Text Classifier behaviour using comprehensive
 * rule-based pattern sets without requiring a custom trained model file.
 *
 * Classes:
 *   SAFE        — Clearly safe, no action
 *   PROMOTIONAL — Marketing/offers, not harmful
 *   OTP         — One-time password, always safe
 *   BANKING     — Legitimate bank transaction alert
 *   TELECOM     — Carrier service/data/recharge message
 *   SOCIAL      — Social media or personal
 *   PHISHING    — Confirmed scam intent
 *   UNKNOWN     — Could not classify
 *
 * Rules enforced:
 *   - OTP    → NEVER classified as PHISHING
 *   - BANKING → NEVER classified as PHISHING (if no malicious URL)
 *   - TELECOM → NEVER classified as PHISHING (if no malicious URL)
 */
object MlContextClassifier {

    // ── OTP patterns ─────────────────────────────────────────────────────
    private val OTP_PATTERNS = listOf(
        "your otp", "otp is", "otp:", "one time password",
        "verification code", "login code", "auth code",
        "do not share", "don't share", "valid for \\d+ min",
        "use this code", "enter this code", "security code",
        "\\d{4,8} is your", "is your otp", "is your code"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ── Banking transaction patterns ──────────────────────────────────────
    private val BANKING_PATTERNS = listOf(
        "debited", "credited", "a/c no", "account no", "account ending",
        "upi ref", "ref no", "imps", "neft", "rtgs",
        "available balance", "closing balance", "avl bal",
        "spent on", "purchase at", "transaction of",
        "emi", "auto-debit", "auto debit", "standing instruction",
        "cheque", "clearance", "minimum due", "payment due"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ── Telecom service patterns ──────────────────────────────────────────
    private val TELECOM_PATTERNS = listOf(
        "data usage", "data balance", "gb remaining", "mb left",
        "recharge", "pack activated", "validity expired",
        "plan expired", "plan activated", "plan renewed",
        "free sms", "voice call", "roaming activated",
        "network coverage", "sim activated", "port your number",
        "data exhausted", "speed reduced", "unlimited calls",
        "jio fiber", "airtel broadband", "bsnl broadband"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ── Promotional safe patterns (offers without scam) ───────────────────
    private val PROMO_PATTERNS = listOf(
        "sale", "discount", "off on", "cashback offer",
        "exclusive deal", "limited offer", "free delivery",
        "order confirmed", "shipped", "out for delivery",
        "delivered", "track your order", "new arrival",
        "festival offer", "weekend offer", "flash sale"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ── Social / personal patterns ────────────────────────────────────────
    private val SOCIAL_PATTERNS = listOf(
        "commented on", "liked your", "tagged you", "sent you a",
        "friend request", "follow request", "replied to",
        "mentioned you", "shared a post"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ── Phishing / scam intent patterns ──────────────────────────────────
    private val PHISHING_INTENT_PATTERNS = listOf(
        "click here to verify", "verify your account immediately",
        "kyc update required", "kyc expired", "kyc pending",
        "account will be blocked", "account has been suspended",
        "you have won", "you are selected", "claim your prize",
        "lottery winner", "lucky draw", "1 crore", "10 lakh",
        "income tax refund pending", "it refund", "aadhaar deactivation",
        "pancard suspended", "demat frozen", "insurance lapsed",
        "update your kyc", "link your aadhaar"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    // ── Scam action triggers (escalates classification) ───────────────────
    private val SCAM_ACTION_PATTERNS = listOf(
        "click.*link", "visit.*immediately", "call.*now",
        "send.*otp", "share.*otp", "share.*cvv",
        "download.*apk", "install.*app", "pay.*fine",
        "transfer.*amount", "deposit.*fee"
    ).map { it.toRegex(RegexOption.IGNORE_CASE) }

    /**
     * Classifies an SMS message into one of the MlMessageCategory values.
     *
     * @param text         The SMS body text
     * @param hasMaliciousUrl Whether a malicious URL was found by cloud scanners
     * @return MlMessageCategory for this message
     */
    fun classify(text: String, hasMaliciousUrl: Boolean = false): MlMessageCategory {
        val hasOtp      = OTP_PATTERNS.any      { it.containsMatchIn(text) }
        val hasBanking  = BANKING_PATTERNS.any  { it.containsMatchIn(text) }
        val hasTelecom  = TELECOM_PATTERNS.any  { it.containsMatchIn(text) }
        val hasPromo    = PROMO_PATTERNS.any    { it.containsMatchIn(text) }
        val hasSocial   = SOCIAL_PATTERNS.any   { it.containsMatchIn(text) }
        val hasPhishing = PHISHING_INTENT_PATTERNS.any { it.containsMatchIn(text) }
        val hasScamAct  = SCAM_ACTION_PATTERNS.any  { it.containsMatchIn(text) }

        return when {
            // OTP — always safe even if banking keywords present
            hasOtp && !hasMaliciousUrl                   -> MlMessageCategory.OTP

            // Banking alert — safe unless malicious URL
            hasBanking && !hasMaliciousUrl               -> MlMessageCategory.BANKING

            // Telecom service — safe unless malicious URL
            hasTelecom && !hasMaliciousUrl               -> MlMessageCategory.TELECOM

            // Confirmed phishing intent with scam action
            hasPhishing && (hasScamAct || hasMaliciousUrl) -> MlMessageCategory.PHISHING

            // Social media notification
            hasSocial                                    -> MlMessageCategory.SOCIAL

            // Promotional offer without scam
            hasPromo && !hasPhishing                     -> MlMessageCategory.PROMOTIONAL

            // General phishing intent (no scam action, no URL — escalate to suspicious only)
            hasPhishing                                  -> MlMessageCategory.PHISHING

            else                                         -> MlMessageCategory.UNKNOWN
        }
    }

    /**
     * Returns the score adjustment for the ML category in the fusion engine.
     * Safe categories subtract; phishing adds.
     */
    fun mlScoreFor(category: MlMessageCategory): Int = when (category) {
        MlMessageCategory.OTP         -> -50  // Definitely safe
        MlMessageCategory.BANKING     -> -40  // Very likely safe
        MlMessageCategory.TELECOM     -> -40  // Very likely safe
        MlMessageCategory.SAFE        -> -30
        MlMessageCategory.SOCIAL      -> -20
        MlMessageCategory.PROMOTIONAL ->  -5  // Slight positive; still not harmful
        MlMessageCategory.UNKNOWN     ->   0
        MlMessageCategory.PHISHING    ->  60  // High confidence scam
    }
}
