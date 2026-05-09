package com.phishguard.mobile

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.tabs.TabLayout
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.phishguard.mobile.data.ThreatDatabase
import com.phishguard.mobile.data.ThreatRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class SmsHistoryActivity : AppCompatActivity() {

    private lateinit var repository: ThreatRepository
    private lateinit var adapter: ThreatAdapter
    private lateinit var recycler: RecyclerView
    private lateinit var tabLayout: TabLayout
    private lateinit var layoutEmpty: LinearLayout

    private val tabs = listOf("ALL", "PHISHING", "SUSPICIOUS", "SAFE")
    private var currentTab = "ALL"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_sms_history)

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        repository = ThreatRepository(ThreatDatabase.getInstance(this).scanDao())
        recycler = findViewById(R.id.recycler_history)
        tabLayout = findViewById(R.id.tab_layout)
        layoutEmpty = findViewById(R.id.layout_empty)

        adapter = ThreatAdapter { record ->
            val intent = Intent(this, ThreatDetailActivity::class.java)
            intent.putExtra("record_id", record.id)
            startActivity(intent)
        }
        recycler.adapter = adapter
        recycler.layoutManager = LinearLayoutManager(this)

        tabs.forEach { tabLayout.addTab(tabLayout.newTab().setText(it)) }

        tabLayout.addOnTabSelectedListener(object : TabLayout.OnTabSelectedListener {
            override fun onTabSelected(tab: TabLayout.Tab?) {
                currentTab = tabs[tab?.position ?: 0]
                observeRecords()
            }
            override fun onTabUnselected(tab: TabLayout.Tab?) {}
            override fun onTabReselected(tab: TabLayout.Tab?) {}
        })

        observeRecords()
    }

    private fun observeRecords() {
        val liveData = if (currentTab == "ALL") repository.allRecords
                       else repository.getByCategory(currentTab)
        liveData.observe(this) { records ->
            adapter.submitList(records)
            layoutEmpty.visibility = if (records.isEmpty()) View.VISIBLE else View.GONE
            recycler.visibility = if (records.isEmpty()) View.GONE else View.VISIBLE
        }
    }
}
