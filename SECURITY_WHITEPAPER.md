# YUZx Security Architecture & On-Device Scam Shield Whitepaper (v1.5.6)

- **Application ID:** `com.xchat.android`
- **Version:** `1.5.6` (`versionCode = 56`)
- **Developer:** Amit Mallick / Shinra Labs (RakshaPlus Technologies)
- **Public Verification Repo:** `https://github.com/yuzx776/yuzx-security`
- **PDF Edition:** [YUZx_Security_Whitepaper_v1.5.6.pdf](./YUZx_Security_Whitepaper_v1.5.6.pdf)

---

## 1. Executive Summary & Design Philosophy

YUZx is an Android privacy-first communication platform engineered around two core threat models:
1. **Cryptographic confidentiality and device-level duress resistance** for private messaging.
2. **Real-time on-device fraud and spyware defense** tailored for high-risk mobile environments (screen-sharing scams, "Digital Arrest" impersonation calls, malicious APK sideloading, and UPI/banking phishing).

Unlike legacy security tools that require root access, invasive accessibility services, or privileged `BIND_VPN_SERVICE` tunnels, YUZx implements its defense stack using standard, Play-Store-compliant Android platform APIs so that all security inspections execute locally on-device with zero telemetry upload.

## 2. Cryptographic & Identity Architecture

- **Zero-Knowledge Vault Identity (`ZeroKnowledgeVaultManager.kt`):**
  Generates phone-number-free identities (`YUZX-XXXX-XXXX-XXXX`) using `SecureRandom.getInstanceStrong()` with a 256-bit (32-byte) `vault_secret`, 32-byte public key digest, and SHA-256 integrity checksum (`YUZX_ZERO_KNOWLEDGE_VAULT_V1`). Secret byte arrays are zeroed in memory after serialization.
- **Hardware-Backed App Lock (`AppLockManager.kt`):**
  Generates a non-exportable 256-bit AES-GCM key (`yuzx_app_lock_key`) inside `AndroidKeyStore` with 128-bit GCM authentication tags and 12-byte IVs. User PINs are hashed with `PBKDF2WithHmacSHA256` (256-bit output) with salt and in-memory char-array wiping.
- **Plausible Deniability (`CipherMaskTransformer.kt`):**
  Entering a secondary Cipher/Duress PIN deterministically transforms contacts, room titles, and message previews into natural, everyday decoy conversations without revealing error banners or scrambled ciphertext markers.
- **Emergency Nuke Protocol (`NukeScope.kt`):**
  Entering a dedicated Nuke PIN triggers granular local sanitization across `local_data`, `messages`, `vault`, `calls`, and optionally full account deletion.
- **Room & Fingerprint Proof (`ChatCryptoProofSheet.kt`):**
  Derives deterministic SHA-256 room hashes, Merkle tree roots, hardware TEE device/peer fingerprints, and 24-digit Safety Numbers for out-of-band verification.
- **Clipboard Hygiene (`ClipboardSecurityHelper.kt`):**
  Marks sensitive copies with `ClipDescription.EXTRA_IS_SENSITIVE` (Android 13+) to hide OS preview popups and automatically scrubs the clipboard after 60 seconds.

## 3. YUZx Scam Shield (Non-Root, Zero-VPN Fraud Defense)

`ScamShieldMonitorService.kt` runs as an Android `foregroundServiceType="specialUse"` component with explicit user consent:
- **Live Screen-Share + Call Detection:** Uses `DisplayManager.DisplayListener` to detect active virtual/presentation displays while `AudioManager.getMode()` reports `MODE_IN_CALL` or `MODE_IN_COMMUNICATION`.
- **Banking & UPI App Correlation:** When optional Usage Access (`PACKAGE_USAGE_STATS`) is granted, `UsageStatsManager.queryEvents()` checks whether an Indian UPI/banking app (PhonePe, Google Pay, Paytm, BHIM, YONO SBI, HDFC, ICICI iMobile, Kotak) is in the foreground during active screen-sharing.
- **High-Priority Fraud Intervention:** Fires a local high-priority notification with one-tap actions to dial `tel:1930` (National Cybercrime Helpline) or alert a trusted family contact via SOS.
- **Malicious Link & Spyware C2 Interception (`AegisLinkGuard.kt`):** Evaluates URLs before browser launch against IP loggers, direct `.apk`/`.xapk`/`.dex` payloads, Punycode homographs (`xn--`), scam lure keywords, and Amnesty MVT / Citizen Lab mercenary spyware C2 indicators (`AegisMvtIocDatabase`).
- **Zero-VPN Private DNS Hardening:** Guides users to Android's native Private DNS (DNS-over-TLS) settings without declaring `BIND_VPN_SERVICE`.

## 4. Transport Security, Data Safety & Account Deletion

- **Encryption in Transit:** All client-server communications use HTTPS/TLS.
- **No Undocumented OTA Code Execution:** Updates are delivered exclusively via Google Play Store review channels.
- **Account & Data Deletion:** Publicly accessible at `https://xchat-backend.xchat-amitmallik.workers.dev/delete-account`.
