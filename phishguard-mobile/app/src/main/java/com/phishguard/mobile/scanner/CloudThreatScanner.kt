package com.phishguard.mobile.scanner

import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import com.phishguard.mobile.config.ApiConfig
import okhttp3.Credentials
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * PhishGuard — Cloud Threat Scanner v3 (Enterprise Edition)
 *
 * Layer 2: Google Safe Browsing API
 *   - Malicious URL  → +80
 *   - Scanned, clean → -30
 *   - API disabled   →  0
 *
 * Layer 3: VirusTotal API v3
 *   - Malicious/suspicious flags → +70
 *   - Scanned, clean            → -25
 *   - API disabled              →  0
 *
 * Layer 4: Twilio Lookup v2
 *   - Legitimate carrier        → -20
 *   - Spoofed / invalid         → +50
 *   - API disabled              →  0
 */
object CloudThreatScanner {

    private val client = OkHttpClient()
    private val gson   = Gson()
    private val TAG    = "CloudThreatScanner"
    private val JSON   = "application/json; charset=utf-8".toMediaType()

    // ─── Sealed result types ───────────────────────────────────────────────

    sealed class GsbResult {
        object NotScanned  : GsbResult()
        object CleanUrl    : GsbResult()
        object MaliciousUrl: GsbResult()
    }

    sealed class VtResult {
        object NotScanned  : VtResult()
        object CleanUrl    : VtResult()
        data class Flagged(val count: Int) : VtResult()
    }

    sealed class TwilioResult {
        object NotScanned  : TwilioResult()
        object Legitimate  : TwilioResult()
        object Spoofed     : TwilioResult()
    }

    // ─── Layer 2: Google Safe Browsing ────────────────────────────────────

    /**
     * Checks a URL against Google Safe Browsing API
     * Returns GsbResult with the outcome.
     *
     * Score impact (applied by caller):
     *   MaliciousUrl → +80
     *   CleanUrl     → -30
     */
    suspend fun checkGoogleSafeBrowsing(url: String): GsbResult =
        withContext(Dispatchers.IO) {
            if (!ApiConfig.GOOGLE_SAFE_BROWSING_ENABLED) return@withContext GsbResult.NotScanned

            val bodyMap = mapOf(
                "client" to mapOf(
                    "clientId"      to "phish-guard-mobile",
                    "clientVersion" to "3.0.0"
                ),
                "threatInfo" to mapOf(
                    "threatTypes"      to listOf(
                        "MALWARE",
                        "SOCIAL_ENGINEERING",
                        "UNWANTED_SOFTWARE",
                        "POTENTIALLY_HARMFUL_APPLICATION"
                    ),
                    "platformTypes"    to listOf("ANY_PLATFORM"),
                    "threatEntryTypes" to listOf("URL"),
                    "threatEntries"    to listOf(mapOf("url" to url))
                )
            )

            val request = Request.Builder()
                .url(ApiConfig.GOOGLE_SAFE_BROWSING_URL + ApiConfig.GOOGLE_SAFE_BROWSING_KEY)
                .post(gson.toJson(bodyMap).toRequestBody(JSON))
                .build()

            try {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) return@withContext GsbResult.NotScanned
                    val body = response.body?.string() ?: ""
                    Log.d(TAG, "GSB response: $body")
                    return@withContext if (body.contains("matches"))
                        GsbResult.MaliciousUrl
                    else
                        GsbResult.CleanUrl
                }
            } catch (e: Exception) {
                Log.e(TAG, "GSB error: ${e.message}")
                GsbResult.NotScanned
            }
        }

    // ─── Layer 3: VirusTotal ───────────────────────────────────────────────

    /**
     * Checks a URL against VirusTotal API v3.
     * Returns VtResult with the outcome.
     *
     * Score impact (applied by caller):
     *   Flagged → +70
     *   Clean   → -25
     */
    suspend fun checkVirusTotal(url: String): VtResult =
        withContext(Dispatchers.IO) {
            if (!ApiConfig.VIRUS_TOTAL_ENABLED) return@withContext VtResult.NotScanned

            val urlBase64 = Base64.encodeToString(
                url.toByteArray(),
                Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING
            )

            val request = Request.Builder()
                .url("${ApiConfig.VIRUS_TOTAL_URL}/$urlBase64")
                .addHeader("x-apikey", ApiConfig.VIRUS_TOTAL_KEY)
                .get()
                .build()

            try {
                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) return@withContext VtResult.NotScanned
                    val body = response.body?.string() ?: ""
                    Log.d(TAG, "VT response: $body")

                    val json       = gson.fromJson(body, Map::class.java)
                    val data       = json["data"]       as? Map<*, *>
                    val attributes = data?.get("attributes") as? Map<*, *>
                    val stats      = attributes?.get("last_analysis_stats") as? Map<*, *>

                    val malicious  = (stats?.get("malicious")  as? Double)?.toInt() ?: 0
                    val suspicious = (stats?.get("suspicious") as? Double)?.toInt() ?: 0
                    val total      = malicious + suspicious

                    return@withContext if (total > 0)
                        VtResult.Flagged(total)
                    else
                        VtResult.CleanUrl
                }
            } catch (e: Exception) {
                Log.e(TAG, "VirusTotal error: ${e.message}")
                VtResult.NotScanned
            }
        }

    // ─── Layer 4: Twilio Lookup v2 ────────────────────────────────────────

    /**
     * Validates a phone-number sender using Twilio Lookup API v2.
     * Only called when sender looks like a phone number.
     *
     * Score impact (applied by caller):
     *   Legitimate → -20
     *   Spoofed    → +50
     */
    suspend fun checkTwilioLookup(sender: String): TwilioResult =
        withContext(Dispatchers.IO) {
            if (!ApiConfig.TWILIO_ENABLED) return@withContext TwilioResult.NotScanned

            // Twilio requires E.164 format; prepend +91 for Indian numbers if needed
            val e164 = if (sender.startsWith("+")) sender
                       else if (sender.length == 10) "+91$sender"
                       else return@withContext TwilioResult.NotScanned

            val url = "${ApiConfig.TWILIO_LOOKUP_URL}${e164}?Fields=line_type_intelligence"

            val request = Request.Builder()
                .url(url)
                .addHeader(
                    "Authorization",
                    Credentials.basic(ApiConfig.TWILIO_ACCOUNT_SID, ApiConfig.TWILIO_AUTH_TOKEN)
                )
                .get()
                .build()

            try {
                client.newCall(request).execute().use { response ->
                    if (response.code == 404) return@withContext TwilioResult.Spoofed
                    if (!response.isSuccessful) return@withContext TwilioResult.NotScanned

                    val body = response.body?.string() ?: ""
                    Log.d(TAG, "Twilio response: $body")

                    val json  = gson.fromJson(body, Map::class.java)
                    val valid = json["valid"] as? Boolean ?: false

                    if (!valid) return@withContext TwilioResult.Spoofed

                    // Check line_type_intelligence for VOIP / spoofed indicators
                    val lineType = json["line_type_intelligence"] as? Map<*, *>
                    val type     = lineType?.get("type") as? String ?: ""

                    return@withContext when {
                        type in listOf("voip", "nonFixedVoip") -> TwilioResult.Spoofed
                        else -> TwilioResult.Legitimate
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Twilio error: ${e.message}")
                TwilioResult.NotScanned
            }
        }
}
