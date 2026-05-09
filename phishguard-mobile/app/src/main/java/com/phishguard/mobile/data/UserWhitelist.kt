package com.phishguard.mobile.data

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * Entity for senders manually marked as safe by the user.
 */
@Entity(tableName = "user_whitelist")
data class UserWhitelist(
    @PrimaryKey
    val sender: String,
    val timestamp: Long = System.currentTimeMillis()
)
