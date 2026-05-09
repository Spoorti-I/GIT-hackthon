package com.phishguard.mobile.service

import android.app.Service
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.util.Log
import com.phishguard.mobile.data.ScanRecord
import com.phishguard.mobile.data.ThreatDatabase
import com.phishguard.mobile.data.ThreatRepository
import com.phishguard.mobile.scanner.SmsThreatScanner
import com.phishguard.mobile.utils.NotificationHelper
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class ClipboardMonitorService : Service() {

    private lateinit var clipboardManager: ClipboardManager
    private val scanner = SmsThreatScanner()
    private val TAG = "PhishGuardClipboard"
    private val serviceScope = CoroutineScope(Dispatchers.IO)

    private val clipboardListener = ClipboardManager.OnPrimaryClipChangedListener {
        val clip = clipboardManager.primaryClip
        if (clip != null && clip.itemCount > 0) {
            val text = clip.getItemAt(0).text?.toString() ?: ""
            if (text.isNotBlank()) {
                Log.d(TAG, "Clipboard change detected: ${text.take(20)}...")
                scanText(text)
            }
        }
    }

    override fun onCreate() {
        super.onCreate()
        clipboardManager = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        clipboardManager.addPrimaryClipChangedListener(clipboardListener)
        Log.d(TAG, "ClipboardMonitorService created")
    }

    override fun onDestroy() {
        super.onDestroy()
        clipboardManager.removePrimaryClipChangedListener(clipboardListener)
        Log.d(TAG, "ClipboardMonitorService destroyed")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun scanText(text: String) {
        serviceScope.launch {
            val result = scanner.scanWithCloud(text, "Clipboard")
            if (result.category != "SAFE") {
                Log.w(TAG, "THREAT DETECTED in clipboard: ${result.category}")
                
                // Save to database
                val repository = ThreatRepository(ThreatDatabase.getInstance(applicationContext).scanDao())
                val record = ScanRecord.fromScanResult("Clipboard", text, result)
                repository.insert(record)

                // Show notification
                NotificationHelper(applicationContext).showThreatNotification("Clipboard", result)
            }
        }
    }
}
