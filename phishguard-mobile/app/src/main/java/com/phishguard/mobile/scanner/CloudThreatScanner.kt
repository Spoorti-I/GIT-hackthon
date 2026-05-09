package com.phishguard.mobile.scanner

import com.google.gson.Gson
import com.phishguard.mobile.config.ApiConfig
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object CloudThreatScanner {

    private val client = OkHttpClient()
    private val gson = Gson()
    private val TAG = "CloudThreatScanner"
    private val JSON = "application/json; charset=utf-8".toMediaType()

    /**
     * Checks a URL against Google Safe Browsing API
     * Returns true if the URL is flagged as malicious
     */
    suspend fun checkGoogleSafeBrowsing(url: String): Boolean = withContext(Dispatchers.IO) {
        if (ApiConfig.GOOGLE_SAFE_BROWSING_KEY.isEmpty()) return@withContext false

        val requestBodyJson = mapOf(
            "client" to mapOf(
                "clientId" to "phish-guard-mobile",
                "clientVersion" to "1.0.0"
            ),
            "threatInfo" to mapOf(
                "threatTypes" to listOf("MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"),
                "platformTypes" to listOf("ANY_PLATFORM"),
                "threatEntryTypes" to listOf("URL"),
                "threatEntries" to listOf(mapOf("url" to url))
            )
        )

        val request = Request.Builder()
            .url(ApiConfig.GOOGLE_SAFE_BROWSING_URL + ApiConfig.GOOGLE_SAFE_BROWSING_KEY)
            .post(gson.toJson(requestBodyJson).toRequestBody(JSON))
            .build()

        try {
            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                Log.d(TAG, "Google response: $body")
                // If the response contains "matches", it means the URL was found in a threat list
                return@withContext body.contains("matches")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Google API Error: ${e.message}")
            false
        }
    }

    /**
     * Checks a URL against VirusTotal API (v3)
     * Returns a simple score (number of positive flags)
     */
    suspend fun checkVirusTotal(url: String): Int = withContext(Dispatchers.IO) {
        if (ApiConfig.VIRUS_TOTAL_KEY == "YOUR_VIRUS_TOTAL_KEY_HERE") return@withContext 0

        // VirusTotal v3 requires encoding the URL to base64 (no padding)
        val urlBase64 = android.util.Base64.encodeToString(url.toByteArray(), 
            android.util.Base64.URL_SAFE or android.util.Base64.NO_WRAP or android.util.Base64.NO_PADDING)

        val request = Request.Builder()
            .url("${ApiConfig.VIRUS_TOTAL_URL}/$urlBase64")
            .addHeader("x-apikey", ApiConfig.VIRUS_TOTAL_KEY)
            .get()
            .build()

        try {
            client.newCall(request).execute().use { response ->
                val body = response.body?.string() ?: ""
                Log.d(TAG, "VirusTotal response: $body")
                
                val json = gson.fromJson(body, Map::class.java)
                val data = json["data"] as? Map<*, *>
                val attributes = data?.get("attributes") as? Map<*, *>
                val lastStats = attributes?.get("last_analysis_stats") as? Map<*, *>
                
                val malicious = (lastStats?.get("malicious") as? Double)?.toInt() ?: 0
                val suspicious = (lastStats?.get("suspicious") as? Double)?.toInt() ?: 0
                
                return@withContext malicious + suspicious
            }
        } catch (e: Exception) {
            Log.e(TAG, "VirusTotal API Error: ${e.message}")
            0
        }
    }
}
