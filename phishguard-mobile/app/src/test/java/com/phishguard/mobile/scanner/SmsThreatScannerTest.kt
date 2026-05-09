package com.phishguard.mobile.scanner

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * PhishGuard — Unit Tests for the 10-Layer Detection Engine
 *
 * Tests validate the critical false-positive reduction requirements:
 *   - Jio/Airtel telecom messages → SAFE
 *   - Bank alerts → SAFE
 *   - OTP messages → SAFE
 *   - Hindi promotional → not PHISHING
 *   - Kannada messages → not PHISHING
 *   - Known phishing SMS → SUSPICIOUS or PHISHING
 */
class SmsThreatScannerTest {

    private lateinit var scanner: SmsThreatScanner

    @Before
    fun setup() {
        scanner = SmsThreatScanner()
    }

    // ── Test Group 1: Telecom Messages ────────────────────────────────────

    @Test
    fun `Jio data usage alert should be SAFE`() {
        val result = scanner.scan(
            text   = "Dear Customer, your Jio data balance is 2.5 GB. Recharge to enjoy unlimited usage.",
            sender = "JX-JIOSMS"
        )
        assertTrue("Score should be ≤20 for Jio message (was ${result.score})", result.score <= 20)
        assertEquals("Category should be SAFE", "SAFE", result.category)
    }

    @Test
    fun `Airtel plan activated should be SAFE`() {
        val result = scanner.scan(
            text   = "Your Airtel Rs 199 plan has been activated. Validity: 28 days. Unlimited calls + 1.5GB/day.",
            sender = "VM-AIRTEL"
        )
        assertTrue("Score should be ≤20 for Airtel message (was ${result.score})", result.score <= 20)
        assertEquals("Category should be SAFE", "SAFE", result.category)
    }

    @Test
    fun `BSNL data exhausted message should be SAFE`() {
        val result = scanner.scan(
            text   = "Dear customer, your BSNL data pack is exhausted. Speed reduced to 64 kbps.",
            sender = "BK-BSNLSM"
        )
        assertTrue("Score should be ≤20 for BSNL alert (was ${result.score})", result.score <= 20)
    }

    // ── Test Group 2: Bank Transaction Alerts ─────────────────────────────

    @Test
    fun `SBI debit alert should be SAFE`() {
        val result = scanner.scan(
            text   = "Rs.5000.00 debited from A/C XX1234 on 09-May. Available Bal: Rs.12,500. -SBI",
            sender = "VM-SBIUPI"
        )
        assertTrue("Score should be ≤20 for SBI debit (was ${result.score})", result.score <= 20)
        assertEquals("Category should be SAFE", "SAFE", result.category)
    }

    @Test
    fun `HDFC credit alert should be SAFE`() {
        val result = scanner.scan(
            text   = "Rs.15,000 credited to your HDFC Bank A/C XX5678 by NEFT. Ref No: 12345678.",
            sender = "AD-HDFCBK"
        )
        assertTrue("Score should be ≤20 for HDFC credit (was ${result.score})", result.score <= 20)
    }

    @Test
    fun `UPI transaction from PhonePe should be SAFE`() {
        val result = scanner.scan(
            text   = "You have received Rs. 200 via UPI from 98765XXXXX. UPI Ref: 123456789012. -PhonePe",
            sender = "VM-PHONPE"
        )
        assertTrue("Score should be ≤30 for PhonePe UPI (was ${result.score})", result.score <= 30)
    }

    // ── Test Group 3: OTP Messages ────────────────────────────────────────

    @Test
    fun `Standard OTP message should score 0 and be SAFE`() {
        val result = scanner.scan(
            text   = "Your OTP is 456789. Valid for 10 minutes. Do not share this OTP with anyone.",
            sender = "VM-SBIUPI"
        )
        assertEquals("OTP message should score exactly 0", 0, result.score)
        assertEquals("Category should be SAFE", "SAFE", result.category)
    }

    @Test
    fun `Amazon OTP should be SAFE`() {
        val result = scanner.scan(
            text   = "123456 is your Amazon verification code. Do not share it with anyone.",
            sender = "AD-AMAZON"
        )
        assertEquals("Amazon OTP should score 0", 0, result.score)
        assertEquals("Category should be SAFE", "SAFE", result.category)
    }

    @Test
    fun `OTP with urgency word should still be SAFE due to OTP override`() {
        val result = scanner.scan(
            text   = "Your OTP is 887766. Valid for 5 minutes. Do not share. Urgent: expires soon.",
            sender = "VM-HDFCBK"
        )
        // OTP override should clear signals and set score to 0
        assertEquals("OTP override should set score to 0", 0, result.score)
    }

    // ── Test Group 4: Regional Language Messages ──────────────────────────

    @Test
    fun `Hindi recharge success message should not be PHISHING`() {
        val result = scanner.scan(
            text   = "Aapka recharge Rs.199 safal raha. Dhanyawad! Validity: 28 din.",
            sender = "JX-JIOSMS"
        )
        assertNotEquals("Hindi success message should not be PHISHING", "PHISHING", result.category)
        assertTrue("Hindi promo score should be ≤40 (was ${result.score})", result.score <= 40)
    }

    @Test
    fun `Kannada offer message should not be PHISHING`() {
        val result = scanner.scan(
            text   = "Nimma Airtel recharge successful. Offer activate maadi. Dhanyavadagalu.",
            sender = "VM-AIRTEL"
        )
        assertNotEquals("Kannada message should not be PHISHING", "PHISHING", result.category)
        assertTrue("Kannada promo score should be ≤40 (was ${result.score})", result.score <= 40)
    }

    // ── Test Group 5: Known Phishing / Scam Messages ──────────────────────

    @Test
    fun `Classic lottery scam should be SUSPICIOUS or PHISHING`() {
        val result = scanner.scan(
            text   = "Congratulations! You have won a lottery of Rs.10 Lakh. Claim your prize now by clicking: http://bit.ly/claim-fake123",
            sender = "+918765432100"
        )
        assertTrue("Lottery scam score should be ≥61 (was ${result.score})", result.score >= 61)
        assertTrue(
            "Category should be SUSPICIOUS or PHISHING (was ${result.category})",
            result.category == "SUSPICIOUS" || result.category == "PHISHING"
        )
    }

    @Test
    fun `KYC fraud message should be SUSPICIOUS or PHISHING`() {
        val result = scanner.scan(
            text   = "Your SBI account will be blocked. KYC expired. Verify now: http://bit.ly/sbionline-kyc",
            sender = "+917654321098"
        )
        assertTrue("KYC scam score should be ≥61 (was ${result.score})", result.score >= 61)
    }

    @Test
    fun `Account blocked threat should be high risk`() {
        val result = scanner.scan(
            text   = "URGENT: Your account has been suspended due to suspicious activity. Verify immediately to unlock.",
            sender = "+919876543210"
        )
        assertTrue("Account threat score should be ≥41 (was ${result.score})", result.score >= 41)
    }

    // ── Test Group 6: Sender Analyzer ─────────────────────────────────────

    @Test
    fun `Verified DLT sender should give -60 contribution`() {
        val risk = SenderAnalyzer.analyze("JX-JIOSMS")
        assertTrue("Verified sender should have negative riskScore (was ${risk.riskScore})", risk.riskScore <= -60)
        assertTrue("Verified sender should be isVerified=true", risk.isVerified)
    }

    @Test
    fun `TRUSTED sender with 5+ history should be marked TRUSTED`() {
        val risk = SenderAnalyzer.analyze("VM-HDFCBK", historyCount = 7)
        assertEquals("5+ history should give TrustLevel.TRUSTED", TrustLevel.TRUSTED, risk.trustLevel)
    }

    @Test
    fun `Impersonating sender should be flagged`() {
        val risk = SenderAnalyzer.analyze("VM-HDFQBK") // one char off from HDFCBK
        assertTrue("Impersonating sender should flag isImpersonating", risk.isImpersonating)
        assertTrue("Impersonation risk score should be positive (was ${risk.riskScore})", risk.riskScore > 0)
    }

    // ── Test Group 7: ML Context Classifier ──────────────────────────────

    @Test
    fun `MlContextClassifier classifies OTP correctly`() {
        val cat = MlContextClassifier.classify("Your OTP is 123456. Do not share.")
        assertEquals("Should classify OTP correctly", MlMessageCategory.OTP, cat)
    }

    @Test
    fun `MlContextClassifier classifies banking correctly`() {
        val cat = MlContextClassifier.classify("Rs.5000 debited from A/C XX1234. Available bal: Rs.12000.")
        assertEquals("Should classify BANKING correctly", MlMessageCategory.BANKING, cat)
    }

    @Test
    fun `MlContextClassifier classifies telecom correctly`() {
        val cat = MlContextClassifier.classify("Your data balance is 1.2 GB remaining. Recharge now.")
        assertEquals("Should classify TELECOM correctly", MlMessageCategory.TELECOM, cat)
    }

    @Test
    fun `MlContextClassifier classifies phishing correctly`() {
        val cat = MlContextClassifier.classify(
            "Your account will be blocked. KYC expired. Click here to verify now.",
            hasMaliciousUrl = true
        )
        assertEquals("Should classify PHISHING correctly", MlMessageCategory.PHISHING, cat)
    }
}
