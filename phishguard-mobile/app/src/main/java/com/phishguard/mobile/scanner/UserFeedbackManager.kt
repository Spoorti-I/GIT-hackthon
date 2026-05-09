package com.phishguard.mobile.scanner

import com.phishguard.mobile.data.FeedbackDao
import com.phishguard.mobile.data.FeedbackRecord

/**
 * PhishGuard — User Feedback Manager (Layer 9)
 *
 * Reads stored user feedback and adjusts scan scores accordingly.
 *
 *   Sender marked as SAFE    → -20 score adjustment
 *   Sender marked as PHISHING → +20 score adjustment
 *   No feedback stored        →   0 (neutral)
 */
class UserFeedbackManager(private val feedbackDao: FeedbackDao) {

    /**
     * Returns the score delta for a sender based on stored user feedback.
     * Negative = reduce threat score (safer), Positive = increase score.
     */
    suspend fun getScoreAdjustment(sender: String): Int {
        val feedback = feedbackDao.getFeedbackForSender(sender) ?: return 0
        return if (feedback.isSafe) -20 else +20
    }

    /**
     * Records that the user has marked this sender as SAFE.
     */
    suspend fun markSenderSafe(sender: String, messageSnippet: String = "") {
        feedbackDao.saveFeedback(
            FeedbackRecord(
                sender          = sender,
                isSafe          = true,
                messageSnippet  = messageSnippet.take(80)
            )
        )
    }

    /**
     * Records that the user has marked this sender as PHISHING.
     */
    suspend fun markSenderPhishing(sender: String, messageSnippet: String = "") {
        feedbackDao.saveFeedback(
            FeedbackRecord(
                sender          = sender,
                isSafe          = false,
                messageSnippet  = messageSnippet.take(80)
            )
        )
    }

    /**
     * Clears all feedback for a sender (let the AI decide fresh).
     */
    suspend fun clearFeedback(sender: String) {
        feedbackDao.deleteFeedbackForSender(sender)
    }
}
