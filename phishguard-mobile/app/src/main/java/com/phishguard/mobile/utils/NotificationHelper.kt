package com.phishguard.mobile.utils

import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import com.phishguard.mobile.MainActivity
import com.phishguard.mobile.R
import com.phishguard.mobile.scanner.SmsScanResult

class NotificationHelper(private val context: Context) {

    private val CHANNEL_ID = "PhishGuardThreats"
    private val CHANNEL_NAME = "PhishGuard SMS Alerts"

    init {
        createNotificationChannel()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val importance = NotificationManager.IMPORTANCE_HIGH
            val channel = NotificationChannel(CHANNEL_ID, CHANNEL_NAME, importance).apply {
                description = "Alerts for suspicious or phishing SMS messages"
                enableVibration(true)
            }
            val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }

    fun showThreatNotification(sender: String, result: SmsScanResult) {
        if (result.category == "SAFE") return

        val icon = if (result.category == "PHISHING") "🚨" else "⚠️"
        val title = "$icon PhishGuard: ${result.category} SMS Detected"
        val signalsSummary = result.signals.take(3).joinToString(" · ") { it.label }
        val content = "From: $sender\nScore: ${result.score}/100\n$signalsSummary"

        // Open MainActivity on tap
        val tapIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            context, 0, tapIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val builder = NotificationCompat.Builder(context, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.ic_dialog_alert)
            .setContentTitle(title)
            .setContentText("From: $sender — Score: ${result.score}/100")
            .setStyle(NotificationCompat.BigTextStyle().bigText(content))
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setAutoCancel(true)
            .setContentIntent(pendingIntent)

        val notificationManager = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        notificationManager.notify(System.currentTimeMillis().toInt(), builder.build())
    }
}
