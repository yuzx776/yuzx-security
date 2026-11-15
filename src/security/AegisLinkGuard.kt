package com.yuzx.app.security

import android.net.Uri
import com.yuzx.app.ui.aegis.AegisMvtIocDatabase
import java.util.Locale

/**
 * Real-time Phishing, IP Logger, and Malicious Link Interceptor.
 * Analyzes URLs clicked inside messages or clipboard before launching the browser.
 */
object AegisLinkGuard {

    enum class ThreatLevel {
        SAFE,
        SUSPICIOUS,
        DANGEROUS
    }

    data class EvaluationResult(
        val threatLevel: ThreatLevel,
        val reason: String,
        val detectedThreat: String? = null
    )

    private val IP_LOGGER_DOMAINS = setOf(
        "grabify.link", "iplogger.org", "iplogger.com", "iplogger.ru",
        "2no.co", "yip.su", "blasze.tk", "cursecode.me", "ps3cfw.com",
        "star-app.net", "partpicker.shop", "sportshighlights.club",
        "locationtracker.net", "track-ip.net", "leancoding.co"
    )

    private val DANGEROUS_EXTENSIONS = setOf(
        ".apk", ".xapk", ".apks", ".dex", ".exe", ".msi", ".bat", ".cmd", ".vbs", ".sh"
    )

    private val SUSPICIOUS_TLDS = setOf(
        ".xyz", ".top", ".click", ".buzz", ".tk", ".ml", ".ga", ".cf", ".gq", ".work", ".fit", ".rest", ".monster"
    )

    private val SCAM_KEYWORDS = listOf(
        "subhadra-bonus", "sarkari-form-download", "kyc-update", "pan-link",
        "cbi-police", "digital-arrest", "free-recharge", "lottery-prize",
        "whatsapp-gift", "bank-verification", "apk-download", "mod-apk",
        "bijli-bill", "electricity-cut", "power-disconnect", "challan-pay",
        "echallan", "vahan-fine", "wedding-invitation", "shadi-card",
        "pmkisan", "ladli-behna", "yojana-apply", "fedex-customs",
        "parcel-seized", "reward-points-redeem", "credit-limit-increase"
    )

    fun evaluateUrl(url: String): EvaluationResult {
        val trimmed = url.trim().lowercase(Locale.ROOT)
        val uri = try {
            Uri.parse(trimmed)
        } catch (_: Exception) {
            return EvaluationResult(ThreatLevel.SUSPICIOUS, "Invalid URL structure")
        }

        val host = uri.host?.lowercase(Locale.ROOT) ?: ""
        val path = uri.path?.lowercase(Locale.ROOT) ?: ""

        // 0. Check against Amnesty MVT & Citizen Lab Mercenary Spyware C2 database
        val mvtMatch = AegisMvtIocDatabase.matchDomain(host)
        if (mvtMatch != null) {
            return EvaluationResult(
                ThreatLevel.DANGEROUS,
                "CRITICAL WARNING: This link connects to verified mercenary spyware / stalkerware command & control infrastructure ($mvtMatch). Opening it may lead to remote device compromise.",
                "Mercenary Spyware C2 ($mvtMatch)"
            )
        }

        // 1. Check for IP loggers & tracking redirectors
        if (IP_LOGGER_DOMAINS.any { host.contains(it) }) {
            return EvaluationResult(
                ThreatLevel.DANGEROUS,
                "This link uses a known IP Logger domain designed to secretly track your exact GPS location and IP address.",
                "IP Logger / Spyware Tracker"
            )
        }

        // 2. Check for direct APK / Executable download payload
        if (DANGEROUS_EXTENSIONS.any { path.endsWith(it) || trimmed.contains(it) }) {
            return EvaluationResult(
                ThreatLevel.DANGEROUS,
                "This link triggers a direct APK/executable package download. Installing unverified APKs may infect your device with trojans or stalkerware.",
                "Unverified Package / Trojan Risk"
            )
        }

        // 3. Check for Punycode homograph attack (e.g. xn--...)
        if (host.startsWith("xn--") || host.contains(".xn--")) {
            return EvaluationResult(
                ThreatLevel.SUSPICIOUS,
                "This domain uses internationalized punycode characters to visually impersonate legitimate websites (Homograph phishing attack).",
                "Lookalike Domain (Homograph Phishing)"
            )
        }

        // 4. Check for Scam keywords combined with untrusted TLDs
        val hasScamKeyword = SCAM_KEYWORDS.any { trimmed.contains(it) }
        val hasSuspiciousTld = SUSPICIOUS_TLDS.any { host.endsWith(it) }

        if (hasScamKeyword) {
            val isOfficialGov = host.endsWith(".gov.in") || host.endsWith(".nic.in")
            if (!isOfficialGov) {
                return EvaluationResult(
                    ThreatLevel.DANGEROUS,
                    "This link mimics government welfare, KYC, or police verification schemes, but is not on an official government or verified domain.",
                    "Phishing / Welfare Scam Pattern"
                )
            }
        }

        if (hasSuspiciousTld) {
            return EvaluationResult(
                ThreatLevel.SUSPICIOUS,
                "This website uses an untrusted top-level domain frequently associated with throwaway phishing campaigns and malicious ads.",
                "High-Risk TLD"
            )
        }

        return EvaluationResult(ThreatLevel.SAFE, "No immediate threat indicators found")
    }
}

