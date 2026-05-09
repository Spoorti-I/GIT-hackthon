package com.phishguard.mobile

import android.graphics.Color
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.recyclerview.widget.DiffUtil
import androidx.recyclerview.widget.ListAdapter
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.phishguard.mobile.data.ScanRecord
import java.text.SimpleDateFormat
import java.util.*

class ThreatAdapter(
    private val onItemClick: (ScanRecord) -> Unit
) : ListAdapter<ScanRecord, ThreatAdapter.ThreatViewHolder>(DiffCallback) {

    companion object DiffCallback : DiffUtil.ItemCallback<ScanRecord>() {
        override fun areItemsTheSame(a: ScanRecord, b: ScanRecord) = a.id == b.id
        override fun areContentsTheSame(a: ScanRecord, b: ScanRecord) = a == b
    }

    override fun onCreateViewHolder(parent: ViewGroup, viewType: Int): ThreatViewHolder {
        val view = LayoutInflater.from(parent.context).inflate(R.layout.item_threat, parent, false)
        return ThreatViewHolder(view)
    }

    override fun onBindViewHolder(holder: ThreatViewHolder, position: Int) {
        holder.bind(getItem(position))
    }

    inner class ThreatViewHolder(itemView: View) : RecyclerView.ViewHolder(itemView) {
        private val severityBar: View = itemView.findViewById(R.id.severity_bar)
        private val threatIcon: TextView = itemView.findViewById(R.id.threat_icon)
        private val txtSender: TextView = itemView.findViewById(R.id.txt_sender)
        private val txtCategory: TextView = itemView.findViewById(R.id.txt_category)
        private val txtSnippet: TextView = itemView.findViewById(R.id.txt_snippet)
        private val txtScore: TextView = itemView.findViewById(R.id.txt_score)
        private val txtTimestamp: TextView = itemView.findViewById(R.id.txt_timestamp)
        private val cardRoot: MaterialCardView = itemView.findViewById(R.id.card_root)

        private val dateFormat = SimpleDateFormat("MMM d, h:mm a", Locale.getDefault())

        fun bind(record: ScanRecord) {
            txtSender.text = record.sender.ifBlank { "Unknown" }
            txtSnippet.text = record.messageSnippet
            txtScore.text = "Score: ${record.score}/100"
            txtTimestamp.text = dateFormat.format(Date(record.timestamp))
            txtCategory.text = record.category

            when (record.category) {
                "PHISHING" -> {
                    threatIcon.text = "🚨"
                    val red = Color.parseColor("#EF4444")
                    severityBar.setBackgroundColor(red)
                    txtCategory.setTextColor(red)
                    txtCategory.setBackgroundColor(Color.parseColor("#FEF2F2"))
                    txtScore.setTextColor(red)
                }
                "SUSPICIOUS" -> {
                    threatIcon.text = "⚠️"
                    val orange = Color.parseColor("#F59E0B")
                    severityBar.setBackgroundColor(orange)
                    txtCategory.setTextColor(orange)
                    txtCategory.setBackgroundColor(Color.parseColor("#FFFBEB"))
                    txtScore.setTextColor(orange)
                }
                else -> {
                    threatIcon.text = "✅"
                    val green = Color.parseColor("#10B981")
                    severityBar.setBackgroundColor(green)
                    txtCategory.setTextColor(green)
                    txtCategory.setBackgroundColor(Color.parseColor("#ECFDF5"))
                    txtScore.setTextColor(green)
                }
            }

            cardRoot.setOnClickListener { onItemClick(record) }
        }
    }
}
