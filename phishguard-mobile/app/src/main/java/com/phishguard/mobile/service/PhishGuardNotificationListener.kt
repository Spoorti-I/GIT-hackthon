package com.phishguard.mobile.service

import android.service.notification.NotificationListenerService
import android.service.notification.StatusBarNotification
import android.util.Log
import com.phishguard.mobile.data.ScanRecord
import com.phishguard.mobile.data.ThreatDatabase
import com.phishguard.mobile.data.ThreatRepository
import com.phishguard.mobile.scanner.SmsThreatScanner
import com.phishguard.mobile.utils.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class PhishGuardNotificationListener : NotificationListenerService() {

    private val scanner = SmsThreatScanner()
    private val TAG = "PhishGuardNotif"
    private val serviceScope = CoroutineScope(Dispatchers.IO)

    override fun onNotificationPosted(sbn: StatusBarNotification) {
        val packageName = sbn.packageName
        
        // Target messaging apps
        val targetPackages = listOf(
            "com.whatsapp",
            "com.whatsapp.w4b",
            "org.telegram.messenger",
            "com.facebook.orca", // Messenger
            "com.instagram.android",
            "com.google.android.apps.messaging" // Google Messages (duplicate check with SmsReceiver but fine)
        )

        if (packageName !in targetPackages) return

        val extras = sbn.notification.extras
        val title = extras.getString("android.title") ?: "Unknown"
        val text = extras.getCharSequence("android.text")?.toString() ?: ""

        if (text.isNotBlank()) {
            Log.d(TAG, "Notification detected from $packageName: ${text.take(20)}...")
            scanText(title, text, packageName)
        }
    }

    private fun scanText(sender: String, text: String, packageName: String) {
        serviceScope.launch {
            val result = scanner.scanWithCloud(text, sender)
            if (result.category != "SAFE") {
                Log.w(TAG, "THREAT DETECTED in $packageName notification: ${result.category}")
                
                // Save to database
                val repository = ThreatRepository(ThreatDatabase.getInstance(applicationContext).scanDao())
                val sourceLabel = when {
                    packageName.contains("whatsapp") -> "WhatsApp"
                    packageName.contains("telegram") -> "Telegram"
                    packageName.contains("facebook") -> "Messenger"
                    else -> "Messaging App"
                }
                
                val record = ScanRecord.fromScanResult("$sourceLabel: $sender", text, result)
                repository.insert(record)

                // Show notification
                NotificationHelper(applicationContext).showThreatNotification(sourceLabel, result)
            }
        }
    }
}
