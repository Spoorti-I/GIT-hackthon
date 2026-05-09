package com.phishguard.mobile

import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.textfield.TextInputEditText
import com.phishguard.mobile.scanner.SmsThreatScanner
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch

class ManualScanActivity : AppCompatActivity() {

    private val scanner = SmsThreatScanner()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_manual_scan)

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        val editText = findViewById<TextInputEditText>(R.id.edit_sms_text)
        val btnAnalyze = findViewById<View>(R.id.btn_analyze)
        val btnClear = findViewById<View>(R.id.btn_clear)
        val cardResult = findViewById<View>(R.id.card_result)
        val txtScore = findViewById<TextView>(R.id.txt_result_score)
        val txtCategory = findViewById<TextView>(R.id.txt_result_category)
        val txtDesc = findViewById<TextView>(R.id.txt_result_desc)
        val signalsLayout = findViewById<LinearLayout>(R.id.layout_signals)
        val noSignalsTxt = findViewById<TextView>(R.id.txt_no_signals)

        btnClear.setOnClickListener {
            editText.text?.clear()
            cardResult.visibility = View.GONE
        }

        btnAnalyze.setOnClickListener {
            val inputText = editText.text?.toString()?.trim() ?: ""
            if (inputText.isBlank()) {
                editText.error = "Please enter some text to analyze"
                return@setOnClickListener
            }

            // Show a "Scanning..." state if needed, but for now just launch
            lifecycleScope.launch {
                val result = scanner.scanWithCloud(inputText)

                txtScore.text = result.score.toString()
                txtCategory.text = result.category

                val (color, desc) = when (result.category) {
                    "PHISHING" -> "#EF4444" to "🚨 High likelihood of smishing. Do NOT click any links."
                    "SUSPICIOUS" -> "#F59E0B" to "⚠️ Suspicious patterns detected. Proceed with caution."
                    else -> "#10B981" to "✅ This message appears safe based on our analysis."
                }

                txtScore.setTextColor(Color.parseColor(color))
                txtCategory.setTextColor(Color.parseColor(color))
                txtDesc.text = desc

                signalsLayout.removeAllViews()
                noSignalsTxt.visibility = View.GONE

                if (result.signals.isEmpty()) {
                    noSignalsTxt.visibility = View.VISIBLE
                } else {
                    result.signals.forEach { signal ->
                        val severityColor = when (signal.severity.name) {
                            "CRITICAL" -> "#EF4444"
                            "HIGH" -> "#F59E0B"
                            "MEDIUM" -> "#3B82F6"
                            else -> "#64748B"
                        }
                        val row = LinearLayout(this@ManualScanActivity).apply {
                            orientation = LinearLayout.VERTICAL
                            setPadding(0, 8, 0, 8)
                        }
                        val label = TextView(this@ManualScanActivity).apply {
                            text = "• ${signal.label}"
                            textSize = 13f
                            setTextColor(Color.parseColor(severityColor))
                            setTypeface(android.graphics.Typeface.DEFAULT_BOLD)
                        }
                        val detail = TextView(this@ManualScanActivity).apply {
                            text = "  ${signal.detail}"
                            textSize = 12f
                            setTextColor(Color.parseColor("#475569"))
                        }
                        row.addView(label)
                        row.addView(detail)
                        signalsLayout.addView(row)
                    }
                }

                cardResult.visibility = View.VISIBLE
            }
        }
    }
}
