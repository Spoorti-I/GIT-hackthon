package com.phishguard.mobile.data

import androidx.lifecycle.LiveData

/**
 * Repository abstracting Room database access from ViewModels.
 */
class ThreatRepository(private val dao: ScanDao) {

    val allRecords: LiveData<List<ScanRecord>> = dao.getAllRecords()
    val recentRecords: LiveData<List<ScanRecord>> = dao.getRecentRecords(10)
    val unreadThreatCount: LiveData<Int> = dao.getUnreadThreatCount()

    fun getByCategory(category: String): LiveData<List<ScanRecord>> =
        dao.getByCategory(category)

    suspend fun insert(record: ScanRecord): Long = dao.insert(record)

    suspend fun getById(id: Long): ScanRecord? = dao.getById(id)

    suspend fun markAsRead(id: Long) = dao.markAsRead(id)

    suspend fun deleteById(id: Long) = dao.deleteById(id)

    suspend fun deleteAll() = dao.deleteAll()

    suspend fun getStats(): Triple<Int, Int, Int> {
        val total = dao.getTotalCount()
        val threats = dao.getThreatCount()
        val safe = dao.getSafeCount()
        return Triple(total, threats, safe)
    }

    suspend fun getSenderHistoryCount(sender: String): Int = dao.getSenderHistoryCount(sender)

    suspend fun isUserWhitelisted(sender: String, database: ThreatDatabase): Boolean {
        return database.whitelistDao().isWhitelisted(sender) > 0
    }

    suspend fun addToWhitelist(sender: String, database: ThreatDatabase) {
        database.whitelistDao().addToWhitelist(UserWhitelist(sender))
    }
}
