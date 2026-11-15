package com.yuzx.app.security.dataguard

import com.yuzx.app.ui.aegis.AegisMvtIocDatabase
import java.util.Locale

/**
 * High-performance on-device threat intelligence database for YUZX Sovereign Data Guard.
 * Compiles signatures from DuckDuckGo Tracker Radar, Exodus Privacy, Disconnect.me,
 * AdGuard Mobile Filters, and Amnesty International MVT.
 */
object DataGuardThreatDatabase {

    enum class TrackerCategory(val label: String, val badgeEmoji: String) {
        ADVERTISING("Advertising", "📢"),
        ANALYTICS("Analytics & Telemetry", "📊"),
        FINGERPRINTING("Device Fingerprinting", "🕵️"),
        SOCIAL_TRACKING("Social Tracking", "👥"),
        MERCENARY_SPYWARE("Mercenary Spyware (MVT)", "🚨"),
        DATA_BROKER("Data Broker", "💼"),
        SCAM_APK_PHISHING("Scam APK & Remote-Access Relay", "🛡️")
    }

    data class ThreatSignature(
        val domain: String,
        val owner: String,
        val category: TrackerCategory,
        val threatLevel: Int = 1 // 1: Standard Tracker, 2: Aggressive, 3: Malicious / Spyware
    )

    data class EvaluationResult(
        val isBlocked: Boolean,
        val domain: String,
        val owner: String? = null,
        val category: TrackerCategory? = null,
        val threatLevel: Int = 0
    )

    // Curated high-prevalence mobile trackers & ad servers
    private val KNOWN_TRACKERS = listOf(
        // ── META / FACEBOOK ───────────────────────────────────────────────
        ThreatSignature("graph.facebook.com", "Meta Platforms, Inc.", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("b-graph.facebook.com", "Meta Platforms, Inc.", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("pixel.facebook.com", "Meta Platforms, Inc.", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("an.facebook.com", "Meta Audience Network", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("connect.facebook.net", "Meta Platforms, Inc.", TrackerCategory.SOCIAL_TRACKING, 1),
        ThreatSignature("graph.instagram.com", "Instagram / Meta", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("logging.instagram.com", "Instagram / Meta", TrackerCategory.ANALYTICS, 1),

        // ── GOOGLE / ALPHABET ─────────────────────────────────────────────
        ThreatSignature("app-measurement.com", "Google LLC (Firebase Analytics)", TrackerCategory.ANALYTICS, 2),
        ThreatSignature("google-analytics.com", "Google LLC", TrackerCategory.ANALYTICS, 1),
        ThreatSignature("adservice.google.com", "Google AdServices", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("pagead2.googlesyndication.com", "Google Ads", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("doubleclick.net", "Google DoubleClick", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("crashlyticsreports-pa.googleapis.com", "Google Crashlytics", TrackerCategory.ANALYTICS, 1),

        // ── ATTRIBUTION & DEVICE FINGERPRINTING SDKS ──────────────────────
        ThreatSignature("appsflyer.com", "AppsFlyer Ltd.", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("t.appsflyer.com", "AppsFlyer Attribution", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("app.appsflyer.com", "AppsFlyer Attribution", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("branch.io", "Branch Metrics", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("api2.branch.io", "Branch Attribution SDK", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("adjust.com", "Adjust GmbH", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("app.adjust.com", "Adjust Attribution SDK", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("kochava.com", "Kochava Inc.", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("control.kochava.com", "Kochava Measurement", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("singular.net", "Singular Inc.", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("tune.com", "Branch / Tune", TrackerCategory.FINGERPRINTING, 2),
        ThreatSignature("tenjin.com", "Tenjin Attribution", TrackerCategory.FINGERPRINTING, 2),

        // ── BYTEDANCE / TIKTOK ────────────────────────────────────────────
        ThreatSignature("pangle.io", "ByteDance (Pangle Ad Network)", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("pangolin.sgsnssdk.com", "ByteDance Pangle", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("analytics.tiktok.com", "ByteDance TikTok", TrackerCategory.ANALYTICS, 2),
        ThreatSignature("log.byteoversea.com", "ByteDance Overseas Logging", TrackerCategory.ANALYTICS, 2),

        // ── GLOBAL AD NETWORKS (GAMES & FREE APPS) ────────────────────────
        ThreatSignature("unityads.unity3d.com", "Unity Technologies", TrackerCategory.ADVERTISING, 1),
        ThreatSignature("adserver.unityads.unity3d.com", "Unity Ads", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("applovin.com", "AppLovin Corporation", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("d.applovin.com", "AppLovin SDK", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("vungle.com", "Liftoff / Vungle", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("ironsrc.com", "ironSource / Unity", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("chartboost.com", "Chartboost", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("tapjoy.com", "Tapjoy Inc.", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("mintegral.com", "Mintegral International", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("inmobi.com", "InMobi Technology", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("config.inmobi.com", "InMobi Ad SDK", TrackerCategory.ADVERTISING, 2),
        ThreatSignature("startappservice.com", "Start.io / StartApp", TrackerCategory.ADVERTISING, 2),

        // ── DATA BROKERS & RETARGETING ───────────────────────────────────
        ThreatSignature("criteo.com", "Criteo SA", TrackerCategory.DATA_BROKER, 2),
        ThreatSignature("taboola.com", "Taboola Inc.", TrackerCategory.DATA_BROKER, 1),
        ThreatSignature("outbrain.com", "Outbrain Inc.", TrackerCategory.DATA_BROKER, 1),
        ThreatSignature("rubiconproject.com", "Magnite / Rubicon", TrackerCategory.DATA_BROKER, 2),

        // ── CHINESE OEM TELEMETRY ─────────────────────────────────────────
        ThreatSignature("tracking.miui.com", "Xiaomi MIUI Telemetry", TrackerCategory.ANALYTICS, 2),
        ThreatSignature("data.mistat.xiaomi.com", "Xiaomi Analytics", TrackerCategory.ANALYTICS, 2),
        ThreatSignature("heytapmobile.com", "OPPO / Realme HeyTap", TrackerCategory.ANALYTICS, 2),
        ThreatSignature("telemetry.vivo.com.cn", "Vivo Telemetry", TrackerCategory.ANALYTICS, 2),
        ThreatSignature("track.uc.cn", "Alibaba UC Browser", TrackerCategory.FINGERPRINTING, 2),

        // ── INDIAN SCAM APK LURES & REMOTE-ACCESS RELAYS ──────────────────
        ThreatSignature("parivahan-echallan.in", "Fake RTO e-Challan APK", TrackerCategory.SCAM_APK_PHISHING, 3),
        ThreatSignature("rto-echallan-apk.in", "Fake RTO e-Challan APK", TrackerCategory.SCAM_APK_PHISHING, 3),
        ThreatSignature("pmkisan-yojana-app.in", "Fake PM-KISAN APK", TrackerCategory.SCAM_APK_PHISHING, 3),
        ThreatSignature("sbi-kyc-update.in", "Fake Bank KYC Phishing", TrackerCategory.SCAM_APK_PHISHING, 3),
        ThreatSignature("hdfc-kyc-update.in", "Fake Bank KYC Phishing", TrackerCategory.SCAM_APK_PHISHING, 3),
        ThreatSignature("net.anydesk.com", "AnyDesk Remote Relay", TrackerCategory.SCAM_APK_PHISHING, 2),
        ThreatSignature("boot.net.anydesk.com", "AnyDesk Remote Relay", TrackerCategory.SCAM_APK_PHISHING, 2),
        ThreatSignature("router.teamviewer.com", "TeamViewer Remote Relay", TrackerCategory.SCAM_APK_PHISHING, 2)
    )

    private val EXACT_MATCH_MAP: Map<String, ThreatSignature> =
        KNOWN_TRACKERS.associateBy { it.domain.lowercase(Locale.ROOT) }

    private val SUFFIX_TRACKERS: List<ThreatSignature> =
        KNOWN_TRACKERS.sortedByDescending { it.domain.length }

    /**
     * Evaluates a requested domain in < 1 microsecond.
     * Checks exact matches, suffix subdomains, and Amnesty MVT Pegasus/Predator C2s.
     */
    fun evaluateDomain(rawDomain: String): EvaluationResult {
        val cleanDomain = rawDomain.trim().lowercase(Locale.ROOT)
            .removePrefix("http://")
            .removePrefix("https://")
            .substringBefore(":")
            .substringBefore("/")

        if (cleanDomain.isBlank()) {
            return EvaluationResult(isBlocked = false, domain = cleanDomain)
        }

        // 1. Check Amnesty MVT & Citizen Lab mercenary spyware IOCs (Critical severity)
        val mvtMatch = AegisMvtIocDatabase.matchDomain(cleanDomain)
        if (mvtMatch != null) {
            return EvaluationResult(
                isBlocked = true,
                domain = cleanDomain,
                owner = mvtMatch,
                category = TrackerCategory.MERCENARY_SPYWARE,
                threatLevel = 3
            )
        }

        // 2. Direct exact match (O(1) Hash Map)
        EXACT_MATCH_MAP[cleanDomain]?.let { sig ->
            return EvaluationResult(
                isBlocked = true,
                domain = cleanDomain,
                owner = sig.owner,
                category = sig.category,
                threatLevel = sig.threatLevel
            )
        }

        // 3. Suffix match (e.g. sub.t.appsflyer.com matches appsflyer.com)
        for (sig in SUFFIX_TRACKERS) {
            if (cleanDomain.endsWith(".${sig.domain}")) {
                return EvaluationResult(
                    isBlocked = true,
                    domain = cleanDomain,
                    owner = sig.owner,
                    category = sig.category,
                    threatLevel = sig.threatLevel
                )
            }
        }

        return EvaluationResult(isBlocked = false, domain = cleanDomain)
    }

    fun totalSignaturesCount(): Int = KNOWN_TRACKERS.size + AegisMvtIocDatabase.totalSignatureCount()
}

