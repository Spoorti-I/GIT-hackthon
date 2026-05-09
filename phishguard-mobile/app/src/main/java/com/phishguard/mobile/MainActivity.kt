package com.phishguard.mobile

import android.Manifest
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.ViewModelProvider
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.phishguard.mobile.service.SmsMonitorService

class MainActivity : AppCompatActivity() {

    private lateinit var viewModel: MainViewModel
    private lateinit var adapter: ThreatAdapter

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { results ->
        val smsGranted = results[Manifest.permission.RECEIVE_SMS] == true ||
                         results[Manifest.permission.READ_SMS] == true
        if (smsGranted) {
            onPermissionsGranted()
        } else {
            showPermissionRationale()
        }
    }

    private fun onPermissionsGranted() {
        startSmsMonitorService()
        startClipboardMonitorService()
        viewModel.analyzeExistingInbox(this)
        checkNotificationAccess()
    }

    private fun checkNotificationAccess() {
        val enabledListeners = android.provider.Settings.Secure.getString(contentResolver, "enabled_notification_listeners")
        val isEnabled = enabledListeners?.contains(packageName) == true
        
        if (!isEnabled) {
            AlertDialog.Builder(this)
                .setTitle("WhatsApp Protection")
                .setMessage("To detect phishing in WhatsApp and other messaging apps, PhishGuard needs Notification Access. Would you like to enable it now?")
                .setPositiveButton("Enable") { _, _ ->
                    startActivity(Intent("android.settings.ACTION_NOTIFICATION_LISTENER_SETTINGS"))
                }
                .setNegativeButton("Later", null)
                .show()
        }
    }

    private fun startClipboardMonitorService() {
        val intent = Intent(this, com.phishguard.mobile.service.ClipboardMonitorService::class.java)
        startService(intent)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        viewModel = ViewModelProvider(this)[MainViewModel::class.java]

        setupRecyclerView()
        setupNavigation()
        observeViewModel()
        checkAndRequestPermissions()
    }

    private fun setupRecyclerView() {
        adapter = ThreatAdapter { record ->
            val intent = Intent(this, ThreatDetailActivity::class.java)
            intent.putExtra("record_id", record.id)
            startActivity(intent)
        }
        val recycler = findViewById<RecyclerView>(R.id.recycler_recent_threats)
        recycler.adapter = adapter
        recycler.layoutManager = LinearLayoutManager(this)
        recycler.isNestedScrollingEnabled = false
    }

    private fun setupNavigation() {
        val bottomNav = findViewById<BottomNavigationView>(R.id.bottom_nav)
        bottomNav.selectedItemId = R.id.nav_dashboard

        bottomNav.setOnItemSelectedListener { item ->
            when (item.itemId) {
                R.id.nav_history -> {
                    startActivity(Intent(this, SmsHistoryActivity::class.java))
                    false
                }
                R.id.nav_scan -> {
                    startActivity(Intent(this, ManualScanActivity::class.java))
                    false
                }
                R.id.nav_settings -> {
                    startActivity(Intent(this, SettingsActivity::class.java))
                    false
                }
                else -> true
            }
        }

        findViewById<View>(R.id.card_manual_scan).setOnClickListener {
            startActivity(Intent(this, ManualScanActivity::class.java))
        }

        val btnViewAll = findViewById<TextView>(R.id.btn_view_all)
        btnViewAll.setOnClickListener {
            startActivity(Intent(this, SmsHistoryActivity::class.java))
        }

        val cardHistory = findViewById<View>(R.id.card_history)
        cardHistory.setOnClickListener {
            startActivity(Intent(this, SmsHistoryActivity::class.java))
        }
    }

    private fun observeViewModel() {
        val statTotal = findViewById<TextView>(R.id.stat_total)
        val statThreats = findViewById<TextView>(R.id.stat_threats)
        val statSafe = findViewById<TextView>(R.id.stat_safe)
        val txtEmpty = findViewById<TextView>(R.id.txt_empty_threats)
        val recycler = findViewById<RecyclerView>(R.id.recycler_recent_threats)

        viewModel.stats.observe(this) { stats ->
            statTotal.text = stats.total.toString()
            statThreats.text = stats.threats.toString()
            statSafe.text = stats.safe.toString()
        }

        viewModel.recentRecords.observe(this) { records ->
            adapter.submitList(records)
            txtEmpty.visibility = if (records.isEmpty()) View.VISIBLE else View.GONE
            recycler.visibility = if (records.isEmpty()) View.GONE else View.VISIBLE
            viewModel.refreshStats()
        }
    }

    private fun checkAndRequestPermissions() {
        val permsNeeded = buildList {
            if (!hasPermission(Manifest.permission.RECEIVE_SMS)) add(Manifest.permission.RECEIVE_SMS)
            if (!hasPermission(Manifest.permission.READ_SMS)) add(Manifest.permission.READ_SMS)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                if (!hasPermission(Manifest.permission.POST_NOTIFICATIONS))
                    add(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        if (permsNeeded.isEmpty()) {
            onPermissionsGranted()
        } else {
            permissionLauncher.launch(permsNeeded.toTypedArray())
        }
    }

    private fun showPermissionRationale() {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.perm_sms_title))
            .setMessage(getString(R.string.perm_sms_message))
            .setPositiveButton(getString(R.string.btn_grant)) { _, _ ->
                permissionLauncher.launch(arrayOf(
                    Manifest.permission.RECEIVE_SMS,
                    Manifest.permission.READ_SMS
                ))
            }
            .setNegativeButton(getString(R.string.btn_cancel), null)
            .show()
    }

    private fun startSmsMonitorService() {
        val intent = Intent(this, SmsMonitorService::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            startForegroundService(intent)
        } else {
            startService(intent)
        }
    }

    private fun hasPermission(permission: String): Boolean =
        checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
}
