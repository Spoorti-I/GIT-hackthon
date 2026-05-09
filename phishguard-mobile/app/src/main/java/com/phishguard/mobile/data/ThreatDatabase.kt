package com.phishguard.mobile.data

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.TypeConverters

/**
 * PhishGuard Room Database — single source of truth for scan history.
 * Uses singleton pattern to prevent multiple instances.
 */
@Database(
    entities = [ScanRecord::class, UserWhitelist::class],
    version = 2,
    exportSchema = false
)
@TypeConverters(Converters::class)
abstract class ThreatDatabase : RoomDatabase() {

    abstract fun scanDao(): ScanDao
    abstract fun whitelistDao(): WhitelistDao

    companion object {
        @Volatile
        private var INSTANCE: ThreatDatabase? = null

        fun getInstance(context: Context): ThreatDatabase {
            return INSTANCE ?: synchronized(this) {
                val instance = Room.databaseBuilder(
                    context.applicationContext,
                    ThreatDatabase::class.java,
                    "phishguard_threats.db"
                )
                    .fallbackToDestructiveMigration()
                    .build()
                INSTANCE = instance
                instance
            }
        }
    }
}
