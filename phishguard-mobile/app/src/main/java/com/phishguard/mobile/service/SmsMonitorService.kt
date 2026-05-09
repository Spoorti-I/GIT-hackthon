package com.phishguard.mobile.service

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.phishguard.mobile.R

/**
 * PhishGuard SMS Monitor Foreground Service.
 *
 * Required on Android 8+ to keep the app alive in the background
 * so that the SmsReceiver can intercept SMS messages reliably.
 *
 * On Android 14+, apps must declare FOREGROUND_SERVICE_TYPE.
 * The BroadcastReceiver (SmsReceiver) is the actual SMS listener
 * and will continue to work as long as this service is running.
 */
class SmsMonitorService : Service() {

    private val SERVICE_NOTIF_ID = 9001
    private val CHANNEL_ID = "PhishGuardService"

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        startForeground(SERVICE_NOTIF_ID, buildServiceNotification())
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // Return START_STICKY so Android restarts the service if killed
        return START_STICKY
    }

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onDestroy() {
        super.onDestroy()
        // Restart self on destroy to maintain continuous protection
        val restartIntent = Intent(applicationContext, SmsMonitorService::class.java)
        restartIntent.setPackage(packageName)
        startService(restartIntent)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "PhishGuard Active Protection",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows when PhishGuard is actively monitoring SMS"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    private fun buildServiceNotification() = NotificationCompat.Builder(this, CHANNEL_ID)
        .setSmallIcon(android.R.drawable.ic_dialog_info)
        .setContentTitle(getString(R.string.notif_service_title))
        .setContentText("PhishGuard is protecting your SMS in real-time")
        .setPriority(NotificationCompat.PRIORITY_LOW)
        .setOngoing(true)
        .setShowWhen(false)
        .build()
}
