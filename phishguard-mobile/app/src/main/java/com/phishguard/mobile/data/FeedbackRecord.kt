package com.phishguard.mobile.data

import androidx.room.Entity
import androidx.room.PrimaryKey
import androidx.room.Index

/**
 * Room entity that stores user feedback (Mark as Safe / Mark as Phishing).
 *
 * Layer 9: User Feedback Learning
 * - When user marks a sender as safe   → future messages from same sender get -20 score
 * - When user marks a sender as phishing → future messages from same sender get +20 score
 */
@Entity(
    tableName = "feedback_records",
    indices = [Index(value = ["sender"])]
)
data class FeedbackRecord(
    @PrimaryKey
    val sender: String,
    val isSafe: Boolean,        // true = user marked safe, false = user marked phishing
    val timestamp: Long = System.currentTimeMillis(),
    val messageSnippet: String = ""  // Optional: stores first 80 chars of the flagged message
)
