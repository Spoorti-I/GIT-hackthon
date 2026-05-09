package com.phishguard.mobile.receiver

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.provider.Telephony
import android.util.Log
import com.phishguard.mobile.data.ScanRecord
import com.phishguard.mobile.data.ThreatDatabase
import com.phishguard.mobile.data.ThreatRepository
import com.phishguard.mobile.scanner.SmsThreatScanner
import com.phishguard.mobile.scanner.UserFeedbackManager
import com.phishguard.mobile.utils.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

/**
 * PhishGuard SMS Receiver v3
 *
 * Intercepts incoming SMS messages and routes them through the
 * 10-layer AI + threat intelligence detection engine.
 *
 * Changes from v2:
 * - Passes feedback score adjustment (Layer 9) into scanner
 * - Uses new 5-tier classification in notification gating
 * - Passes historyCount to SenderAnalyzer for TRUSTED classification
 */
class SmsReceiver : BroadcastReceiver() {

    private val scanner = SmsThreatScanner()
    private val TAG     = "PhishGuard"

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        val prefs = context.getSharedPreferences("phishguard_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("protection_enabled", true)) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)

        for (sms in messages) {
            val sender = sms.displayOriginatingAddress ?: "Unknown"
            val body   = sms.messageBody ?: ""

            Log.d(TAG, "Intercepted SMS from $sender")

            CoroutineScope(Dispatchers.IO).launch {
                val db           = ThreatDatabase.getInstance(context)
                val repository   = ThreatRepository(db.scanDao())
                val feedbackMgr  = UserFeedbackManager(db.feedbackDao())

                // Layer 1: sender history count for TRUSTED classification
                val historyCount = repository.getSenderHistoryCount(sender)

                // Layer 8: check user whitelist (manual safe-mark)
                val isManualSafe = repository.isUserWhitelisted(sender, db)

                // Layer 9: score adjustment from stored user feedback
                val feedbackAdj  = feedbackMgr.getScoreAdjustment(sender)

                // Run full 10-layer scan with cloud APIs
                val result = scanner.scanWithCloud(
                    text         = body,
                    sender       = sender,
                    historyCount = historyCount,
                    isManualSafe = isManualSafe,
                    feedbackAdj  = feedbackAdj
                )

                Log.d(TAG, "Scan: ${result.category} (score=${result.score}, ML=${result.mlCategory})")

                // Persist result to Room database
                val record = ScanRecord.fromScanResult(sender, body, result)
                repository.insert(record)

                // Only alert the user for non-SAFE results
                val notifEnabled = prefs.getBoolean("notifications_enabled", true)
                if (result.category != "SAFE" && notifEnabled) {
                    Log.w(TAG, "THREAT from $sender: ${result.category} (${result.score})")
                    NotificationHelper(context).showThreatNotification(sender, result)
                }
            }
        }
    }
}
