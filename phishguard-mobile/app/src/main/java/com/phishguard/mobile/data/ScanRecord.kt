package com.phishguard.mobile.data

import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.TypeConverter
import androidx.room.TypeConverters

/**
 * Room Entity representing a single SMS scan record persisted to the database.
 */
@Entity(tableName = "scan_records")
@TypeConverters(Converters::class)
data class ScanRecord(
    @PrimaryKey(autoGenerate = true)
    val id: Long = 0,
    val sender: String,
    val messageSnippet: String,     // First 200 chars
    val fullMessage: String,        // Full message body
    val score: Int,
    val category: String,           // SAFE | SUSPICIOUS | PHISHING
    val signals: List<String>,      // Signal labels
    val detectedUrls: List<String>,
    val timestamp: Long = System.currentTimeMillis(),
    val isRead: Boolean = false
) {
    val isPhishing: Boolean get() = category == "PHISHING"
    val isSuspicious: Boolean get() = category == "SUSPICIOUS"
    val isSafe: Boolean get() = category == "SAFE"

    companion object {
        fun fromScanResult(
            sender: String,
            body: String,
            result: com.phishguard.mobile.scanner.SmsScanResult
        ): ScanRecord = ScanRecord(
            sender = sender,
            messageSnippet = body.take(200),
            fullMessage = body,
            score = result.score,
            category = result.category,
            signals = result.signals.map { it.label },
            detectedUrls = result.detectedUrls
        )
    }
}

class Converters {
    @TypeConverter
    fun fromStringList(value: List<String>): String = value.joinToString("|||")

    @TypeConverter
    fun toStringList(value: String): List<String> =
        if (value.isBlank()) emptyList() else value.split("|||")
}
