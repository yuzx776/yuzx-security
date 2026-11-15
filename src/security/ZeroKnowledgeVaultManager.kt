package com.yuzx.app.security

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.MessageDigest
import java.security.SecureRandom

@Serializable
data class ZeroKnowledgeVaultIdentity(
    @SerialName("format") val format: String = "YUZX_ZERO_KNOWLEDGE_VAULT_V1",
    @SerialName("version") val version: Int = 1,
    @SerialName("account_id") val accountId: String,
    @SerialName("vault_secret") val vaultSecret: String,
    @SerialName("public_key") val publicKey: String,
    @SerialName("created_at") val createdAt: Long,
    @SerialName("checksum") val checksum: String,
    @SerialName("notice") val notice: String = "DO NOT SHARE OR LOSE THIS FILE. This is your master zero-knowledge key for YUZx.",
)

object ZeroKnowledgeVaultManager {

    private val secureRandom = try { SecureRandom.getInstanceStrong() } catch (_: Exception) { SecureRandom() }
    private val json = Json {
        prettyPrint = true
        ignoreUnknownKeys = true
        isLenient = true
    }

    /**
     * Generates a brand new Mullvad-style Zero-Knowledge Vault identity with high entropy.
     */
    fun generateNewIdentity(): ZeroKnowledgeVaultIdentity {
        // 1. Generate 16-digit Account ID in 4-digit chunks
        val chunk1 = 1000 + secureRandom.nextInt(9000)
        val chunk2 = 1000 + secureRandom.nextInt(9000)
        val chunk3 = 1000 + secureRandom.nextInt(9000)
        val chunk4 = 1000 + secureRandom.nextInt(9000)
        val accountId = "YUZX-$chunk1-$chunk2-$chunk3-$chunk4"

        // 2. Generate 32 bytes (256-bit) secret token
        val secretBytes = ByteArray(32)
        secureRandom.nextBytes(secretBytes)
        val vaultSecret = secretBytes.joinToString("") { "%02x".format(it) }
        java.util.Arrays.fill(secretBytes, 0.toByte())

        // 3. Generate public key digest
        val pubBytes = ByteArray(32)
        secureRandom.nextBytes(pubBytes)
        val publicKey = pubBytes.joinToString("") { "%02x".format(it) }
        java.util.Arrays.fill(pubBytes, 0.toByte())

        val createdAt = System.currentTimeMillis()
        val checksum = computeChecksum(accountId, vaultSecret)

        return ZeroKnowledgeVaultIdentity(
            accountId = accountId,
            vaultSecret = vaultSecret,
            publicKey = publicKey,
            createdAt = createdAt,
            checksum = checksum,
        )
    }

    /**
     * Serializes vault identity to pretty-printed JSON file content.
     */
    fun serializeVault(identity: ZeroKnowledgeVaultIdentity): String {
        return json.encodeToString(identity)
    }

    /**
     * Parses and cryptographically validates a .vault JSON file.
     */
    fun parseVault(content: String): Result<ZeroKnowledgeVaultIdentity> = runCatching {
        val parsed = json.decodeFromString<ZeroKnowledgeVaultIdentity>(content.trim())
        if (!parsed.format.startsWith("YUZX_ZERO_KNOWLEDGE_VAULT")) {
            throw IllegalArgumentException("Unrecognized vault format.")
        }
        val expectedChecksum = computeChecksum(parsed.accountId, parsed.vaultSecret)
        if (parsed.checksum != expectedChecksum) {
            throw IllegalArgumentException("Corrupted vault keyfile (checksum mismatch).")
        }
        parsed
    }

    private fun computeChecksum(accountId: String, vaultSecret: String): String {
        val raw = "$accountId:$vaultSecret:YUZX_VAULT"
        val digest = MessageDigest.getInstance("SHA-256").digest(raw.toByteArray(Charsets.UTF_8))
        return digest.joinToString("") { "%02x".format(it) }
    }
}
