package com.phishguard.mobile

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.LiveData
import androidx.lifecycle.MutableLiveData
import androidx.lifecycle.viewModelScope
import com.phishguard.mobile.data.ScanRecord
import com.phishguard.mobile.data.ThreatDatabase
import com.phishguard.mobile.data.ThreatRepository
import kotlinx.coroutines.launch

import android.content.Context
import android.provider.Telephony
import com.phishguard.mobile.scanner.SmsThreatScanner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class DashboardStats(
    val total: Int,
    val threats: Int,
    val safe: Int
)

class MainViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = ThreatRepository(
        ThreatDatabase.getInstance(application).scanDao()
    )
    private val scanner = SmsThreatScanner()

    val recentRecords: LiveData<List<ScanRecord>> = repository.recentRecords
    val unreadThreatCount: LiveData<Int> = repository.unreadThreatCount

    private val _stats = MutableLiveData<DashboardStats>()
    val stats: LiveData<DashboardStats> = _stats

    private val _isScanning = MutableLiveData<Boolean>(false)
    val isScanning: LiveData<Boolean> = _isScanning

    init {
        refreshStats()
    }

    fun refreshStats() {
        viewModelScope.launch {
            val (total, threats, safe) = repository.getStats()
            _stats.postValue(DashboardStats(total, threats, safe))
        }
    }

    fun analyzeExistingInbox(context: Context) {
        val prefs = context.getSharedPreferences("phishguard_prefs", Context.MODE_PRIVATE)
        if (prefs.getBoolean("has_scanned_inbox", false)) return

        viewModelScope.launch {
            _isScanning.postValue(true)
            withContext(Dispatchers.IO) {
                val cursor = context.contentResolver.query(
                    Telephony.Sms.Inbox.CONTENT_URI,
                    arrayOf(Telephony.Sms.Inbox.ADDRESS, Telephony.Sms.Inbox.BODY, Telephony.Sms.Inbox.DATE),
                    null,
                    null,
                    "${Telephony.Sms.Inbox.DATE} DESC LIMIT 100"
                )

                cursor?.use {
                    val addressIdx = it.getColumnIndex(Telephony.Sms.Inbox.ADDRESS)
                    val bodyIdx = it.getColumnIndex(Telephony.Sms.Inbox.BODY)
                    val dateIdx = it.getColumnIndex(Telephony.Sms.Inbox.DATE)

                    while (it.moveToNext()) {
                        val sender = it.getString(addressIdx) ?: "Unknown"
                        val body = it.getString(bodyIdx) ?: ""
                        val timestamp = it.getLong(dateIdx)

                        val db = ThreatDatabase.getInstance(getApplication())
                        val isManualSafe = repository.isUserWhitelisted(sender, db)
                        val historyCount = repository.getSenderHistoryCount(sender)

                        val result = scanner.scanWithCloud(body, sender, isManualSafe, historyCount)
                        // We only save if it's NOT safe, or if we want full stats.
                        // User wants "detect threats", so saving everything helps the dashboard stats.
                        val record = ScanRecord.fromScanResult(sender, body, result).copy(
                            timestamp = timestamp,
                            isRead = true // Historical messages are likely already read
                        )
                        repository.insert(record)
                    }
                }
            }
            prefs.edit().putBoolean("has_scanned_inbox", true).apply()
            _isScanning.postValue(false)
            refreshStats()
        }
    }
}
