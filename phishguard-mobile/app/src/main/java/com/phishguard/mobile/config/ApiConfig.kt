package com.phishguard.mobile.config

object ApiConfig {
    // Google Safe Browsing API Key
    // NOTE: In a production app, you should use local encryption or fetch this from a secure backend.
    const val GOOGLE_SAFE_BROWSING_KEY = "AIzaSyDC-y6clXZ3JfMAZ55mOQu24a-6XXYpC3Y"

    // VirusTotal API Key
    // Replace with your real VirusTotal API key from https://www.virustotal.com/gui/my-portal
    const val VIRUS_TOTAL_KEY = "YOUR_VIRUS_TOTAL_KEY_HERE"

    // Endpoint for Google Safe Browsing Lookup
    const val GOOGLE_SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="
    
    // Endpoint for VirusTotal URL Report
    const val VIRUS_TOTAL_URL = "https://www.virustotal.com/api/v3/urls"
}
