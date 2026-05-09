package com.phishguard.mobile

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import com.phishguard.mobile.data.ThreatDatabase
import com.phishguard.mobile.data.ThreatRepository
import kotlinx.coroutines.launch
import java.text.SimpleDateFormat
import java.util.*

class ThreatDetailActivity : AppCompatActivity() {

    private lateinit var repository: ThreatRepository

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_threat_detail)

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        repository = ThreatRepository(ThreatDatabase.getInstance(this).scanDao())

        val recordId = intent.getLongExtra("record_id", -1L)
        if (recordId == -1L) { finish(); return }

        lifecycleScope.launch {
            val record = repository.getById(recordId) ?: run { finish(); return@launch }
            repository.markAsRead(recordId)

            val scoreTxt = findViewById<TextView>(R.id.txt_score_big)
            val categoryTxt = findViewById<TextView>(R.id.txt_category_detail)
            val senderTxt = findViewById<TextView>(R.id.txt_sender_detail)
            val timeTxt = findViewById<TextView>(R.id.txt_time_detail)
            val bodyTxt = findViewById<TextView>(R.id.txt_message_body)
            val signalsLayout = findViewById<LinearLayout>(R.id.layout_signals_detail)
            val noSignalsTxt = findViewById<TextView>(R.id.txt_no_signals_detail)

            scoreTxt.text = record.score.toString()
            categoryTxt.text = record.category
            senderTxt.text = "From: ${record.sender.ifBlank { "Unknown" }}"
            timeTxt.text = SimpleDateFormat("MMM d, yyyy h:mm a", Locale.getDefault())
                .format(Date(record.timestamp))
            bodyTxt.text = record.fullMessage

            val scoreColor = when (record.category) {
                "PHISHING"   -> "#EF4444"
                "SUSPICIOUS" -> "#F59E0B"
                else         -> "#10B981"
            }
            categoryTxt.setTextColor(Color.parseColor(scoreColor))
            scoreTxt.setTextColor(Color.parseColor(scoreColor))

            if (record.signals.isEmpty()) {
                noSignalsTxt.visibility = View.VISIBLE
            } else {
                record.signals.forEach { signal ->
                    val chip = TextView(this@ThreatDetailActivity).apply {
                        text = "• $signal"
                        textSize = 13f
                        setTextColor(Color.parseColor("#1E293B"))
                        setPadding(0, 6, 0, 6)
                    }
                    signalsLayout.addView(chip)
                }
            }
            val btnReport = findViewById<android.view.View>(R.id.btn_report_phishing)
            val btnMarkSafe = findViewById<android.view.View>(R.id.btn_mark_safe)

            btnReport.setOnClickListener {
                android.widget.Toast.makeText(this@ThreatDetailActivity, "Threat reported to PhishGuard community", android.widget.Toast.LENGTH_SHORT).show()
                finish()
            }

            btnMarkSafe.setOnClickListener {
                lifecycleScope.launch {
                    repository.deleteById(recordId)
                    android.widget.Toast.makeText(this@ThreatDetailActivity, "Marked as safe and removed from logs", android.widget.Toast.LENGTH_SHORT).show()
                    finish()
                }
            }
        }
    }
}
