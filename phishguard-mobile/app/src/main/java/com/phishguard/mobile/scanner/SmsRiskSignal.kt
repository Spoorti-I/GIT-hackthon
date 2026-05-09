package com.phishguard.mobile.scanner

/**
 * Represents a single detected risk signal in an SMS message.
 */
data class SmsRiskSignal(
    val type: SignalType,
    val label: String,
    val detail: String,
    val score: Int,
    val severity: SignalSeverity = SignalSeverity.MEDIUM
)

enum class SignalType {
    URGENCY,
    AUTHORITY_IMPERSONATION,
    BRAND_IMPERSONATION,
    DANGEROUS_ACTION,
    FINANCIAL_FRAUD,
    PRIZE_LOTTERY,
    KYC_FRAUD,
    OTP_FRAUD,
    SUSPICIOUS_URL,
    SHORTENED_URL,
    SUSPICIOUS_TLD,
    SENDER_SUSPICIOUS,
    COMBINATION_ATTACK,
    ML_CLASSIFICATION,
    USER_FEEDBACK,
    TWILIO_SPOOFED
}

enum class SignalSeverity {
    LOW, MEDIUM, HIGH, CRITICAL
}

/**
 * The full result of scanning a single SMS message.
 */
data class SmsScanResult(
    val isPhishing: Boolean,
    val score: Int,
    val category: String,           // SAFE | LOW RISK | PROMOTIONAL | SUSPICIOUS | PHISHING
    val signals: List<SmsRiskSignal>,
    val detectedUrls: List<String>,
    val senderRisk: SenderRisk?,
    val analysisMs: Long,
    val mlCategory: MlMessageCategory = MlMessageCategory.UNKNOWN
) {
    val signals_summary: String
        get() = signals.joinToString(", ") { it.label }
}

data class SenderRisk(
    val sender: String,
    val isImpersonating: Boolean,
    val impersonatedBrand: String?,
    val riskScore: Int,
    val detail: String,
    val isVerified: Boolean = false,
    val trustLevel: TrustLevel = TrustLevel.UNKNOWN
)

/**
 * ML classification category for a message.
 */
enum class MlMessageCategory {
    SAFE,
    PROMOTIONAL,
    OTP,
    BANKING,
    TELECOM,
    SOCIAL,
    PHISHING,
    UNKNOWN
}
