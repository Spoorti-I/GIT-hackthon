package com.phishguard.mobile.data

import androidx.lifecycle.LiveData
import androidx.room.*

/**
 * Room DAO for scan record CRUD operations.
 */
@Dao
interface ScanDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(record: ScanRecord): Long

    @Query("SELECT * FROM scan_records ORDER BY timestamp DESC")
    fun getAllRecords(): LiveData<List<ScanRecord>>

    @Query("SELECT * FROM scan_records ORDER BY timestamp DESC LIMIT :limit")
    fun getRecentRecords(limit: Int = 20): LiveData<List<ScanRecord>>

    @Query("SELECT * FROM scan_records WHERE category = :category ORDER BY timestamp DESC")
    fun getByCategory(category: String): LiveData<List<ScanRecord>>

    @Query("SELECT * FROM scan_records WHERE id = :id")
    suspend fun getById(id: Long): ScanRecord?

    @Query("SELECT COUNT(*) FROM scan_records")
    suspend fun getTotalCount(): Int

    @Query("SELECT COUNT(*) FROM scan_records WHERE category = 'PHISHING' OR category = 'SUSPICIOUS'")
    suspend fun getThreatCount(): Int

    @Query("SELECT COUNT(*) FROM scan_records WHERE category = 'SAFE'")
    suspend fun getSafeCount(): Int

    @Query("DELETE FROM scan_records WHERE id = :id")
    suspend fun deleteById(id: Long)

    @Query("DELETE FROM scan_records")
    suspend fun deleteAll()

    @Query("DELETE FROM scan_records WHERE timestamp < :beforeTimestamp")
    suspend fun deleteOlderThan(beforeTimestamp: Long)

    @Query("UPDATE scan_records SET isRead = 1 WHERE id = :id")
    suspend fun markAsRead(id: Long)

    @Query("SELECT COUNT(*) FROM scan_records WHERE isRead = 0 AND category != 'SAFE'")
    fun getUnreadThreatCount(): LiveData<Int>

    @Query("SELECT COUNT(*) FROM scan_records WHERE sender = :sender")
    suspend fun getSenderHistoryCount(sender: String): Int
}

@Dao
interface WhitelistDao {
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun addToWhitelist(sender: UserWhitelist)

    @Query("SELECT COUNT(*) FROM user_whitelist WHERE sender = :sender")
    suspend fun isWhitelisted(sender: String): Int

    @Query("DELETE FROM user_whitelist WHERE sender = :sender")
    suspend fun removeFromWhitelist(sender: String)

    @Query("SELECT * FROM user_whitelist")
    fun getAllWhitelisted(): LiveData<List<UserWhitelist>>
}
