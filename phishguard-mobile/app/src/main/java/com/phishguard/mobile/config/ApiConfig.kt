package com.phishguard.mobile.config

object ApiConfig {

    // ── Google Safe Browsing ───────────────────────────────────────────────
    const val GOOGLE_SAFE_BROWSING_KEY = "AIzaSyDC-y6clXZ3JfMAZ55mOQu24a-6XXYpC3Y"
    const val GOOGLE_SAFE_BROWSING_URL =
        "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="

    // ── VirusTotal ─────────────────────────────────────────────────────────
    // Replace with your real VirusTotal API key from https://www.virustotal.com/gui/my-portal
    const val VIRUS_TOTAL_KEY = "084bdf8e32e660528095b6f4feb478da066181bb321fcaae2b4eacb21a8eafbc"
    const val VIRUS_TOTAL_URL = "https://www.virustotal.com/api/v3/urls"

    // ── Twilio Lookup v2 ───────────────────────────────────────────────────
    // Create a free trial account at https://www.twilio.com and get your SID + Auth Token
    // The Lookup API is used to validate phone sender IDs and detect spoofed numbers
    const val TWILIO_ACCOUNT_SID  = "OR95006da3657945f32edfcefbb9a37cc8"
    const val TWILIO_AUTH_TOKEN   = "9CAGKF1V95XHMF337Y1Q5YVM"
    const val TWILIO_LOOKUP_URL   = "https://lookups.twilio.com/v2/PhoneNumbers/"

    // ── Feature flags ───────────────────────────────────────────────────────
    val GOOGLE_SAFE_BROWSING_ENABLED: Boolean
        get() = GOOGLE_SAFE_BROWSING_KEY.isNotEmpty()

    val VIRUS_TOTAL_ENABLED: Boolean
        get() = VIRUS_TOTAL_KEY != "YOUR_VIRUS_TOTAL_KEY_HERE"

    val TWILIO_ENABLED: Boolean
        get() = TWILIO_ACCOUNT_SID != "YOUR_TWILIO_ACCOUNT_SID_HERE" &&
                TWILIO_AUTH_TOKEN  != "YOUR_TWILIO_AUTH_TOKEN_HERE"
}
