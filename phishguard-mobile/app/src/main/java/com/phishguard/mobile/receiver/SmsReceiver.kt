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
import com.phishguard.mobile.utils.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class SmsReceiver : BroadcastReceiver() {

    private val scanner = SmsThreatScanner()
    private val TAG = "PhishGuard"

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Telephony.Sms.Intents.SMS_RECEIVED_ACTION) return

        // Check if protection is enabled
        val prefs = context.getSharedPreferences("phishguard_prefs", Context.MODE_PRIVATE)
        if (!prefs.getBoolean("protection_enabled", true)) return

        val messages = Telephony.Sms.Intents.getMessagesFromIntent(intent)

        for (sms in messages) {
            val sender = sms.displayOriginatingAddress ?: "Unknown"
            val body = sms.messageBody ?: ""

            Log.d(TAG, "Intercepted SMS from $sender")

            // Run scanner on IO thread
            CoroutineScope(Dispatchers.IO).launch {
                val db = ThreatDatabase.getInstance(context)
                val repository = ThreatRepository(db.scanDao())
                
                // Fetch context for Layer 1 & 8
                val historyCount = repository.getSenderHistoryCount(sender)
                val isManualSafe = repository.isUserWhitelisted(sender, db)

                // 1. Scan with full engine including sender analysis + Cloud APIs
                val result = scanner.scanWithCloud(body, sender, isManualSafe, historyCount)

                Log.d(TAG, "Scan result: ${result.category} (score: ${result.score})")

                // 2. Persist to Room database
                val record = ScanRecord.fromScanResult(sender, body, result)
                repository.insert(record)

                // 3. Alert if not safe (and notifications are enabled)
                if (result.category != "SAFE" &&
                    prefs.getBoolean("notifications_enabled", true)) {
                    Log.w(TAG, "THREAT DETECTED from $sender: ${result.category} (${result.score})")
                    NotificationHelper(context).showThreatNotification(sender, result)
                }
            }
        }
    }
}
