package com.phishguard.mobile.data

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query

/**
 * Room DAO for user feedback storage and retrieval.
 */
@Dao
interface FeedbackDao {

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveFeedback(record: FeedbackRecord)

    @Query("SELECT * FROM feedback_records WHERE sender = :sender LIMIT 1")
    suspend fun getFeedbackForSender(sender: String): FeedbackRecord?

    @Query("SELECT COUNT(*) FROM feedback_records WHERE isSafe = 1")
    suspend fun getSafeCount(): Int

    @Query("SELECT COUNT(*) FROM feedback_records WHERE isSafe = 0")
    suspend fun getPhishingCount(): Int

    @Query("DELETE FROM feedback_records WHERE sender = :sender")
    suspend fun deleteFeedbackForSender(sender: String)

    @Query("DELETE FROM feedback_records")
    suspend fun deleteAll()
}
