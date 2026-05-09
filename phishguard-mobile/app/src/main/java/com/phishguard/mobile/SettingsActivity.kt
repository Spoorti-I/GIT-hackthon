package com.phishguard.mobile

import android.app.role.RoleManager
import android.content.Intent
import android.os.Build
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.switchmaterial.SwitchMaterial

class SettingsActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val toolbar = findViewById<androidx.appcompat.widget.Toolbar>(R.id.toolbar)
        setSupportActionBar(toolbar)
        toolbar.setNavigationOnClickListener { finish() }

        val switchProtection = findViewById<SwitchMaterial>(R.id.switch_protection)
        val switchNotifications = findViewById<SwitchMaterial>(R.id.switch_notifications)
        val cardDefaultSms = findViewById<androidx.cardview.widget.CardView>(R.id.card_default_sms)

        val prefs = getSharedPreferences("phishguard_prefs", MODE_PRIVATE)
        switchProtection.isChecked = prefs.getBoolean("protection_enabled", true)
        switchNotifications.isChecked = prefs.getBoolean("notifications_enabled", true)

        switchProtection.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("protection_enabled", isChecked).apply()
        }

        switchNotifications.setOnCheckedChangeListener { _, isChecked ->
            prefs.edit().putBoolean("notifications_enabled", isChecked).apply()
        }

        cardDefaultSms.setOnClickListener {
            requestDefaultSmsApp()
        }
    }

    private fun requestDefaultSmsApp() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            val roleManager = getSystemService(RoleManager::class.java)
            if (roleManager.isRoleAvailable(RoleManager.ROLE_SMS)) {
                if (!roleManager.isRoleHeld(RoleManager.ROLE_SMS)) {
                    val intent = roleManager.createRequestRoleIntent(RoleManager.ROLE_SMS)
                    startActivityForResult(intent, REQUEST_DEFAULT_SMS)
                }
            }
        } else {
            val intent = Intent("android.provider.Telephony.ACTION_CHANGE_DEFAULT")
            intent.putExtra("package", packageName)
            startActivity(intent)
        }
    }

    companion object {
        private const val REQUEST_DEFAULT_SMS = 1001
    }
}
