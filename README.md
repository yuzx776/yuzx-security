# YUZx Security Architecture & Open-Source Verification

[![License: MIT](https://img.shields.io/badge/License-MIT-emerald.svg)](LICENSE)
[![Platform: Android](https://img.shields.io/badge/Platform-Android%20(com.xchat.android)-blue.svg)](https://play.google.com/store/apps/details?id=com.xchat.android)
[![Whitepaper: v1.5.6](https://img.shields.io/badge/Whitepaper-v1.5.6%20PDF-brightgreen.svg)](./YUZx_Security_Whitepaper_v1.5.6.pdf)

This repository publishes the **public security specification, technical whitepaper (PDF & Markdown), and verifiable security source modules** for **YUZx (`com.xchat.android`, v1.5.6)** by Amit Mallick / Shinra Labs (RakshaPlus Technologies).

## What Is Verifiable Here

| Component | Source File | Security Guarantee |
| :--- | :--- | :--- |
| **Zero-Knowledge Vault Identity** | [`ZeroKnowledgeVaultManager.kt`](./src/security/ZeroKnowledgeVaultManager.kt) | Phone-number-free `YUZX-XXXX-XXXX-XXXX` identity, 256-bit `SecureRandom` secret token, SHA-256 checksum, and in-memory byte zeroing |
| **Hardware-Backed App Lock** | [`AppLockManager.kt`](./src/security/AppLockManager.kt) | `AndroidKeyStore` 256-bit AES-GCM (`yuzx_app_lock_key`) + `PBKDF2WithHmacSHA256` PIN hashing |
| **Plausible Deniability (Cipher Mode)** | [`CipherMaskTransformer.kt`](./src/security/CipherMaskTransformer.kt) | Deterministic decoy conversation/contact rendering under a secondary Duress PIN |
| **Emergency Nuke Protocol** | [`NukeScope.kt`](./src/security/NukeScope.kt) | Granular local wipe scope (`local_data`, `messages`, `vault`, `calls`, `account`) |
| **On-Device Scam Shield** | [`ScamShieldMonitorService.kt`](./src/security/ScamShieldMonitorService.kt) | Non-root, **zero-VPN** (`specialUse` foreground service) detecting active screen-sharing during calls + optional UPI/banking foreground correlation |
| **Phishing & Spyware C2 Guard** | [`AegisLinkGuard.kt`](./src/security/AegisLinkGuard.kt) | Intercepts IP loggers, APK/executable payloads, Punycode homographs (`xn--`), and Amnesty MVT / Citizen Lab mercenary spyware C2 domains |
| **Threat Indicator Database** | [`DataGuardThreatDatabase.kt`](./src/security/DataGuardThreatDatabase.kt) | Local offline indicator database including `SCAM_APK_PHISHING` signatures |
| **Clipboard Leak Protection** | [`ClipboardSecurityHelper.kt`](./src/security/ClipboardSecurityHelper.kt) | `ClipDescription.EXTRA_IS_SENSITIVE` (Android 13+) and automatic 60-second clipboard scrub |
| **Crypto Proof & Safety Numbers** | [`ChatCryptoProofSheet.kt`](./src/security/ChatCryptoProofSheet.kt) | SHA-256 room hash, Merkle root, TEE fingerprints, and 24-digit out-of-band Safety Numbers |

## Technical Whitepaper

- **PDF:** [YUZx_Security_Whitepaper_v1.5.6.pdf](./YUZx_Security_Whitepaper_v1.5.6.pdf)
- **Markdown:** [SECURITY_WHITEPAPER.md](./SECURITY_WHITEPAPER.md)

## Transport, Privacy & Play Store Compliance

- **Encryption in Transit:** All client-server traffic is encrypted via HTTPS/TLS.
- **Zero-VPN Architecture:** YUZx does **not** declare `BIND_VPN_SERVICE` and never routes user traffic through third-party VPN servers; DNS-level protection uses Android's native Private DNS (DNS-over-TLS).
- **No Undocumented OTA Code Execution:** App updates are distributed strictly through Google Play Store review channels.
- **Account & Data Deletion:** Public deletion portal at `https://xchat-backend.xchat-amitmallik.workers.dev/delete-account`.

## Responsible Disclosure

See [SECURITY.md](./SECURITY.md) for vulnerability reporting guidelines.
