package com.yuzx.app.ui.aegis

import android.Manifest
import android.app.AppOpsManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.app.usage.UsageEvents
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.hardware.display.DisplayManager
import android.media.AudioManager
import android.net.Uri
import android.os.Build
import android.os.Handler
import android.os.IBinder
import android.os.Looper
import android.os.Process
import android.view.Display
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.yuzx.app.MainActivity
import com.yuzx.app.R
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * Play-Store-compliant, non-root Digital Arrest & Screen-Share Scam Interrupter.
 *
 * Detects the exact behavioral signature of remote-access / Digital Arrest scams:
 *  - Active cellular or VoIP call (AudioManager MODE_IN_CALL / MODE_IN_COMMUNICATION)
 *  - Active non-default / virtual / presentation display (DisplayManager)
 *  - Optional foreground UPI / Banking app detection (UsageStatsManager)
 *
 * Fires an immediate high-priority warning with 1-tap 1930 Cyber Helpline dial
 * and 1-tap Family WhatsApp SOS alert.
 */
class ScamShieldMonitorService : Service() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var pollJob: Job? = null

    private lateinit var displayManager: DisplayManager
    private lateinit var audioManager: AudioManager
    private var modeChangedListener: AudioManager.OnModeChangedListener? = null
    private var lastReportedPackage: String? = null
    private var lastAlertAtMillis: Long = 0L

    private val displayListener = object : DisplayManager.DisplayListener {
        override fun onDisplayAdded(displayId: Int) = evaluateRiskState()
        override fun onDisplayRemoved(displayId: Int) = evaluateRiskState()
        override fun onDisplayChanged(displayId: Int) = evaluateRiskState()
    }

    override fun onCreate() {
        super.onCreate()
        ensureChannels()
        displayManager = getSystemService(Context.DISPLAY_SERVICE) as DisplayManager
        audioManager = getSystemService(Context.AUDIO_SERVICE) as AudioManager
        displayManager.registerDisplayListener(displayListener, Handler(Looper.getMainLooper()))

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val listener = AudioManager.OnModeChangedListener { _ -> evaluateRiskState() }
            modeChangedListener = listener
            audioManager.addOnModeChangedListener(mainExecutor, listener)
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_TEST_ALERT -> {
                fireScamWarning(
                    reason = "Test Alert: Active Call + Screen Share detected",
                    upiApp = "PhonePe / UPI",
                    force = true,
                )
            }
        }

        val notification = buildOngoingNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIF_ONGOING_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIF_ONGOING_ID, notification)
        }

        AegisGuard.setScamShieldEnabled(this, true)
        _status.update {
            it.copy(
                isMonitorRunning = true,
                hasUsageStatsAccess = hasUsageStatsPermission(this),
            )
        }
        startPollingLoop()
        evaluateRiskState()
        return START_STICKY
    }

    override fun onDestroy() {
        pollJob?.cancel()
        try {
            displayManager.unregisterDisplayListener(displayListener)
        } catch (_: Exception) {}
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            modeChangedListener?.let {
                try {
                    audioManager.removeOnModeChangedListener(it)
                } catch (_: Exception) {}
            }
        }
        serviceScope.cancel()
        AegisGuard.setScamShieldEnabled(this, false)
        _status.update {
            it.copy(
                isMonitorRunning = false,
                isInCallOrVoip = false,
                isScreenShareActive = false,
                activeScreenShareReason = null,
                foregroundUpiApp = null,
            )
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun startPollingLoop() {
        pollJob?.cancel()
        pollJob = serviceScope.launch {
            while (isActive) {
                evaluateRiskState()
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    private fun evaluateRiskState() {
        val mode = try {
            audioManager.mode
        } catch (_: Exception) {
            AudioManager.MODE_NORMAL
        }
        val inCall = mode == AudioManager.MODE_IN_COMMUNICATION || mode == AudioManager.MODE_IN_CALL

        val screenShareReason = detectActiveScreenShare()
        val isScreenSharing = screenShareReason != null
        val usageGranted = hasUsageStatsPermission(this)
        val foregroundPkg = if (usageGranted) queryForegroundPackage() else null
        val upiAppLabel = foregroundPkg?.let { INDIAN_UPI_BANKING_APPS[it] }

        _status.update {
            it.copy(
                isMonitorRunning = true,
                isInCallOrVoip = inCall,
                isScreenShareActive = isScreenSharing,
                activeScreenShareReason = screenShareReason,
                foregroundUpiApp = upiAppLabel,
                hasUsageStatsAccess = usageGranted,
            )
        }

        if (inCall && isScreenSharing) {
            val reason = buildString {
                append("Active Call + Screen Sharing ($screenShareReason)")
                if (upiAppLabel != null) append(" while $upiAppLabel is open")
            }
            fireScamWarning(reason = reason, upiApp = upiAppLabel, force = false)
        }
    }

    private fun detectActiveScreenShare(): String? {
        val displays = try {
            displayManager.displays
        } catch (_: Exception) {
            emptyArray()
        }
        for (display in displays) {
            if (display.displayId == Display.DEFAULT_DISPLAY) continue
            val isPresentation = (display.flags and Display.FLAG_PRESENTATION) != 0
            val isPrivate = (display.flags and Display.FLAG_PRIVATE) != 0
            val name = display.name?.trim().orEmpty()
            return when {
                name.isNotEmpty() && (isPrivate || isPresentation) -> name
                isPresentation -> "External / Wireless Cast"
                isPrivate -> "Virtual / Screen-Share Display"
                else -> name.ifEmpty { "Secondary Display" }
            }
        }
        return null
    }

    private fun queryForegroundPackage(): String? {
        val usageStats = getSystemService(Context.USAGE_STATS_SERVICE) as? UsageStatsManager ?: return lastReportedPackage
        val now = System.currentTimeMillis()
        val events = try {
            usageStats.queryEvents(now - USAGE_LOOKBACK_MS, now)
        } catch (_: Exception) {
            return lastReportedPackage
        }
        val event = UsageEvents.Event()
        var latestPkg: String? = null
        while (events.hasNextEvent()) {
            events.getNextEvent(event)
            val isForegroundEvent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                event.eventType == UsageEvents.Event.ACTIVITY_RESUMED
            } else {
                @Suppress("DEPRECATION")
                event.eventType == UsageEvents.Event.MOVE_TO_FOREGROUND
            }
            if (isForegroundEvent && event.packageName != null) {
                val pkg = event.packageName
                if (pkg != packageName && pkg !in IGNORED_LAUNCHERS) {
                    latestPkg = pkg
                }
            }
        }
        if (latestPkg != null) {
            lastReportedPackage = latestPkg
        }
        return lastReportedPackage
    }

    private fun fireScamWarning(reason: String, upiApp: String?, force: Boolean) {
        val now = System.currentTimeMillis()
        if (!force && now - lastAlertAtMillis < ALERT_COOLDOWN_MS) return
        lastAlertAtMillis = now

        _status.update {
            it.copy(
                lastWarningAtMillis = now,
                lastWarningReason = reason,
            )
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
                PackageManager.PERMISSION_GRANTED
            if (!granted) return
        }

        val openAppIntent = PendingIntent.getActivity(
            this,
            901,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val dial1930Intent = PendingIntent.getActivity(
            this,
            902,
            Intent(Intent.ACTION_DIAL, Uri.parse("tel:1930")).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val sosIntent = PendingIntent.getActivity(
            this,
            903,
            AegisGuard.buildFamilySosIntent(this, reason),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )

        val title = if (upiApp != null) {
            "STOP! $upiApp open during Screen Share & Call"
        } else {
            "STOP! Possible Digital Arrest / Screen-Share Scam"
        }
        val body = "Do NOT transfer money or share OTPs. Hang up, stop screen sharing, and verify with family or call 1930."

        val notification = NotificationCompat.Builder(this, CHANNEL_ALERT_ID)
            .setSmallIcon(R.drawable.ic_app_yuzx_aegis)
            .setContentTitle(title)
            .setContentText(body)
            .setStyle(NotificationCompat.BigTextStyle().bigText("$body\n\nTrigger: $reason"))
            .setPriority(NotificationCompat.PRIORITY_MAX)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setDefaults(Notification.DEFAULT_ALL)
            .setAutoCancel(true)
            .setContentIntent(openAppIntent)
            .setFullScreenIntent(openAppIntent, true)
            .addAction(0, "Call 1930 Helpline", dial1930Intent)
            .addAction(0, "SOS Family", sosIntent)
            .build()

        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIF_ALERT_ID, notification)
    }

    private fun buildOngoingNotification(): Notification {
        val openIntent = PendingIntent.getActivity(
            this,
            900,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
        )
        return NotificationCompat.Builder(this, CHANNEL_ONGOING_ID)
            .setSmallIcon(R.drawable.ic_app_yuzx_aegis)
            .setContentTitle("YUZx Scam Shield Active")
            .setContentText("Watching for risky Call + Screen-Share + UPI combinations on-device.")
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .build()
    }

    private fun ensureChannels() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val ongoing = NotificationChannel(
            CHANNEL_ONGOING_ID,
            "YUZx Scam Shield Monitor",
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = "Keeps on-device Digital Arrest and screen-share scam protection active."
        }
        val alert = NotificationChannel(
            CHANNEL_ALERT_ID,
            "YUZx Scam & Digital Arrest Alerts",
            NotificationManager.IMPORTANCE_HIGH,
        ).apply {
            description = "Urgent warnings when a call and screen-share occur together."
            enableVibration(true)
        }
        nm.createNotificationChannel(ongoing)
        nm.createNotificationChannel(alert)
    }

    companion object {
        const val ACTION_START = "com.yuzx.app.SCAM_SHIELD_START"
        const val ACTION_STOP = "com.yuzx.app.SCAM_SHIELD_STOP"
        const val ACTION_TEST_ALERT = "com.yuzx.app.SCAM_SHIELD_TEST_ALERT"

        private const val CHANNEL_ONGOING_ID = "yuzx_scam_shield_ongoing"
        private const val CHANNEL_ALERT_ID = "yuzx_scam_shield_alert"
        private const val NOTIF_ONGOING_ID = 8810
        private const val NOTIF_ALERT_ID = 8811

        private const val POLL_INTERVAL_MS = 2_000L
        private const val USAGE_LOOKBACK_MS = 5_000L
        private const val ALERT_COOLDOWN_MS = 20_000L

        private val _status = MutableStateFlow(ScamShieldStatus())
        val status: StateFlow<ScamShieldStatus> = _status.asStateFlow()

        private val IGNORED_LAUNCHERS = setOf(
            "com.android.launcher",
            "com.google.android.apps.nexuslauncher",
            "com.miui.home",
            "com.sec.android.app.launcher",
            "com.oppo.launcher",
            "com.coloros.launcher",
            "com.vivo.launcher",
        )

        private val INDIAN_UPI_BANKING_APPS = mapOf(
            "com.phonepe.app" to "PhonePe",
            "com.google.android.apps.nbu.paisa.user" to "Google Pay",
            "net.one97.paytm" to "Paytm",
            "in.org.npci.upiapp" to "BHIM UPI",
            "com.dreamplug.androidapp" to "CRED",
            "com.sbi.lotusintouch" to "SBI YONO",
            "com.csam.icici.bank.imobile" to "ICICI iMobile",
            "com.snapwork.hdfc" to "HDFC Bank",
            "com.axis.mobile" to "Axis Mobile",
            "com.msf.kbank.mobile" to "Kotak811",
        )

        fun start(context: Context) {
            val intent = Intent(context, ScamShieldMonitorService::class.java).setAction(ACTION_START)
            ContextCompat.startForegroundService(context, intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, ScamShieldMonitorService::class.java).setAction(ACTION_STOP)
            context.startService(intent)
        }

        fun triggerTestAlert(context: Context) {
            val intent = Intent(context, ScamShieldMonitorService::class.java).setAction(ACTION_TEST_ALERT)
            ContextCompat.startForegroundService(context, intent)
        }

        fun hasUsageStatsPermission(context: Context): Boolean {
            val appOps = context.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager ?: return false
            val mode = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                appOps.unsafeCheckOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.packageName,
                )
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    context.packageName,
                )
            }
            return mode == AppOpsManager.MODE_ALLOWED
        }
    }
}

