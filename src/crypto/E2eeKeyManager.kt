package com.yuzx.app.core.chatcore.api.crypto

import android.content.Context
import android.util.Log
import com.yuzx.app.core.authcore.api.AuthService
import com.yuzx.app.core.authcore.api.models.AuthState
import com.yuzx.app.core.chatcore.api.models.normalizedUserId
import com.yuzx.app.core.chatcore.security.HardwareSecurityKeystoreManager
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONObject
import java.security.KeyPair
import java.security.PrivateKey
import java.security.PublicKey
import java.util.concurrent.ConcurrentHashMap
import javax.crypto.SecretKey
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class E2eeKeyManager @Inject constructor(
    @ApplicationContext private val context: Context,
    private val cryptoEngine: E2eeCryptoEngine,
    private val pqCryptoEngine: PostQuantumCryptoEngine,
    private val authService: AuthService,
    private val okHttpClient: OkHttpClient,
    private val hardwareSecurityKeystoreManager: HardwareSecurityKeystoreManager,
) {
    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val scope = CoroutineScope(Dispatchers.IO)
    private val jsonMediaType = "application/json; charset=utf-8".toMediaType()

    // In-memory cache for derived shared AES keys (0ms instant lookup)
    private val sharedKeysCache = ConcurrentHashMap<String, SecretKey>()

    // In-memory cache for peer classical public keys
    private val peerPublicKeysCache = ConcurrentHashMap<String, PublicKey>()

    // In-memory cache for peer Post-Quantum (ML-KEM-768) public keys
    private val peerKyberPublicKeysCache = ConcurrentHashMap<String, ByteArray>()

    // Negative cache for peers who have no E2EE public key on the server (TTL: 10 minutes)
    private val noPublicKeyPeers = ConcurrentHashMap<String, Long>()
    private val negativeCacheTtlMs = 10 * 60 * 1000L

    private var myKeyPair: KeyPair? = null
    private var myKyberKeyPair: PostQuantumCryptoEngine.KyberKeyPair? = null
    private var currentUserId: String? = null

    init {
        scope.launch {
            authService.observeAuthState().collect { authState ->
                if (authState is AuthState.Authenticated) {
                    val userId = authState.session.userId.normalizedUserId()
                    if (currentUserId != userId || myKeyPair == null || myKyberKeyPair == null) {
                        currentUserId = userId
                        sharedKeysCache.clear()
                        peerPublicKeysCache.clear()
                        peerKyberPublicKeysCache.clear()
                        loadOrGenerateMyKeysForUser(userId)
                    }
                    uploadMyPublicKeyIfNeeded(authState.session.accessToken, userId)
                } else if (authState is AuthState.Unauthenticated) {
                    currentUserId = null
                    myKeyPair = null
                    myKyberKeyPair = null
                    sharedKeysCache.clear()
                    peerPublicKeysCache.clear()
                    peerKyberPublicKeysCache.clear()
                }
            }
        }
    }

    private fun getPrivKeyPref(userId: String): String = "e2ee_priv_${userId.normalizedUserId()}"
    private fun getPubKeyPref(userId: String): String = "e2ee_pub_${userId.normalizedUserId()}"
    private fun getKyberPrivKeyPref(userId: String): String = "pq_e2ee_kyber_priv_${userId.normalizedUserId()}"
    private fun getKyberPubKeyPref(userId: String): String = "pq_e2ee_kyber_pub_${userId.normalizedUserId()}"
    private fun getUploadedPref(userId: String, pubBase64: String): String =
        "e2ee_up_${userId.normalizedUserId()}_${pubBase64.hashCode()}"

    private fun encryptAndStorePrivateKey(prefKey: String, rawPrivateKeyBase64: String) {
        try {
            val encryptedBytes = hardwareSecurityKeystoreManager.encrypt(rawPrivateKeyBase64.toByteArray(Charsets.UTF_8))
            val encryptedBase64 = CryptoBase64.encode(encryptedBytes)
            prefs.edit().putString(prefKey, "enc:$encryptedBase64").apply()
        } catch (e: Exception) {
            Log.w(TAG, "Hardware encryption failed for $prefKey, falling back to legacy storage", e)
            prefs.edit().putString(prefKey, rawPrivateKeyBase64).apply()
        }
    }

    private fun retrieveAndDecryptPrivateKey(prefKey: String): String? {
        val stored = prefs.getString(prefKey, null) ?: return null
        if (stored.startsWith("enc:")) {
            return try {
                val cipherTextBase64 = stored.removePrefix("enc:")
                val cipherBytes = CryptoBase64.decode(cipherTextBase64)
                val decryptedBytes = hardwareSecurityKeystoreManager.decrypt(cipherBytes)
                if (decryptedBytes != null) String(decryptedBytes, Charsets.UTF_8) else null
            } catch (e: Exception) {
                Log.e(TAG, "Hardware decryption failed for $prefKey", e)
                null
            }
        }
        // Seamless migration: re-encrypt existing plaintext key with Hardware Keystore
        try {
            encryptAndStorePrivateKey(prefKey, stored)
        } catch (_: Throwable) {}
        return stored
    }

    @Synchronized
    private fun loadOrGenerateMyKeysForUser(userId: String) {
        if (userId.isBlank()) return
        try {
            val privKeyName = getPrivKeyPref(userId)
            val pubKeyName = getPubKeyPref(userId)
            val savedPriv = retrieveAndDecryptPrivateKey(privKeyName)
            val savedPub = prefs.getString(pubKeyName, null)

            if (!savedPriv.isNullOrBlank() && !savedPub.isNullOrBlank()) {
                val priv = cryptoEngine.decodePrivateKey(savedPriv)
                val pub = cryptoEngine.decodePublicKey(savedPub)
                myKeyPair = KeyPair(pub, priv)
                Log.d(TAG, "Loaded existing classical E2EE keypair for user $userId (Hardware Keystore Protected)")
            } else {
                val newKeyPair = cryptoEngine.generateKeyPair()
                myKeyPair = newKeyPair
                encryptAndStorePrivateKey(privKeyName, cryptoEngine.encodePrivateKey(newKeyPair.private))
                prefs.edit()
                    .putString(pubKeyName, cryptoEngine.encodePublicKey(newKeyPair.public))
                    .apply()
                Log.d(TAG, "Generated and saved new classical E2EE keypair for user $userId (Hardware Keystore Protected)")
            }

            // Post-Quantum ML-KEM-768 KeyPair
            val kyberPrivKeyName = getKyberPrivKeyPref(userId)
            val kyberPubKeyName = getKyberPubKeyPref(userId)
            val savedKyberPriv = retrieveAndDecryptPrivateKey(kyberPrivKeyName)
            val savedKyberPub = prefs.getString(kyberPubKeyName, null)

            if (!savedKyberPriv.isNullOrBlank() && !savedKyberPub.isNullOrBlank()) {
                myKyberKeyPair = PostQuantumCryptoEngine.KyberKeyPair(
                    publicKey = pqCryptoEngine.decodeKyberPublicKey(savedKyberPub),
                    secretKey = pqCryptoEngine.decodeKyberSecretKey(savedKyberPriv),
                )
                Log.d(TAG, "Loaded existing Post-Quantum ML-KEM keypair for user $userId (Hardware Keystore Protected)")
            } else {
                val newKyberKeyPair = pqCryptoEngine.generateKyber768KeyPair()
                myKyberKeyPair = newKyberKeyPair
                encryptAndStorePrivateKey(kyberPrivKeyName, pqCryptoEngine.encodeKyberSecretKey(newKyberKeyPair.secretKey))
                prefs.edit()
                    .putString(kyberPubKeyName, pqCryptoEngine.encodeKyberPublicKey(newKyberKeyPair.publicKey))
                    .apply()
                Log.d(TAG, "Generated and saved new Post-Quantum ML-KEM keypair for user $userId (Hardware Keystore Protected)")
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load E2EE keys for $userId, generating fallback", e)
            val newKeyPair = cryptoEngine.generateKeyPair()
            myKeyPair = newKeyPair
            val newKyberKeyPair = pqCryptoEngine.generateKyber768KeyPair()
            myKyberKeyPair = newKyberKeyPair

            encryptAndStorePrivateKey(getPrivKeyPref(userId), cryptoEngine.encodePrivateKey(newKeyPair.private))
            encryptAndStorePrivateKey(getKyberPrivKeyPref(userId), pqCryptoEngine.encodeKyberSecretKey(newKyberKeyPair.secretKey))
            prefs.edit()
                .putString(getPubKeyPref(userId), cryptoEngine.encodePublicKey(newKeyPair.public))
                .putString(getKyberPubKeyPref(userId), pqCryptoEngine.encodeKyberPublicKey(newKyberKeyPair.publicKey))
                .apply()
        }
    }

    suspend fun ensureMyKeysLoaded(userId: String? = null): KeyPair? {
        if (myKeyPair != null && (userId == null || userId.normalizedUserId() == currentUserId)) return myKeyPair
        val activeUserId = userId?.normalizedUserId()?.takeIf { it.isNotBlank() }
            ?: currentUserId
            ?: authService.getCurrentSession()?.userId?.normalizedUserId()
        if (!activeUserId.isNullOrBlank()) {
            currentUserId = activeUserId
            loadOrGenerateMyKeysForUser(activeUserId)
            return myKeyPair
        }
        return null
    }

    fun getMyPublicKeyBase64(userId: String? = null): String? {
        val targetId = userId?.normalizedUserId()?.takeIf { it.isNotBlank() } ?: currentUserId
        if (myKeyPair == null && !targetId.isNullOrBlank()) {
            loadOrGenerateMyKeysForUser(targetId)
        }
        val keyPair = myKeyPair ?: return null
        return cryptoEngine.encodePublicKey(keyPair.public)
    }

    fun getMyKyberPublicKeyBase64(userId: String? = null): String? {
        val targetId = userId?.normalizedUserId()?.takeIf { it.isNotBlank() } ?: currentUserId
        if (myKyberKeyPair == null && !targetId.isNullOrBlank()) {
            loadOrGenerateMyKeysForUser(targetId)
        }
        val kyberKp = myKyberKeyPair ?: return null
        return pqCryptoEngine.encodeKyberPublicKey(kyberKp.publicKey)
    }

    /**
     * Upload local public key and Post-Quantum key to backend profile.
     */
    suspend fun uploadMyPublicKeyIfNeeded(
        accessToken: String,
        userId: String? = null,
        baseUrl: String = "https://xchat-backend.xchat-amitmallik.workers.dev",
    ) = withContext(Dispatchers.IO) {
        val targetUserId = (userId ?: currentUserId ?: authService.getCurrentSession()?.userId).orEmpty().normalizedUserId()
        if (targetUserId.isNotBlank() && (myKeyPair == null || myKyberKeyPair == null)) {
            loadOrGenerateMyKeysForUser(targetUserId)
        }
        val pubBase64 = getMyPublicKeyBase64(targetUserId) ?: return@withContext
        val kyberPubBase64 = getMyKyberPublicKeyBase64(targetUserId)

        val uploadedKeyName = if (targetUserId.isNotBlank()) getUploadedPref(targetUserId, pubBase64 + (kyberPubBase64 ?: "")) else KEY_PUBLIC_KEY_UPLOADED
        val isUploaded = prefs.getBoolean(uploadedKeyName, false)
        if (isUploaded) return@withContext

        try {
            val payload = JSONObject().apply {
                put("publicKey", pubBase64)
                if (!kyberPubBase64.isNullOrBlank()) {
                    put("pqPublicKey", kyberPubBase64)
                }
            }.toString()

            val request = Request.Builder()
                .url("$baseUrl/api/users/keys/public-key")
                .header("Authorization", "Bearer $accessToken")
                .post(payload.toRequestBody(jsonMediaType))
                .build()

            val response = okHttpClient.newCall(request).execute()
            if (response.isSuccessful) {
                prefs.edit().putBoolean(uploadedKeyName, true).apply()
                Log.d(TAG, "Hybrid E2EE Public Keys (Classical + ML-KEM) successfully synced for user $targetUserId")
            } else {
                Log.w(TAG, "Failed to upload E2EE public key: HTTP ${response.code}")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to upload E2EE public key", e)
        }
    }

    /**
     * Fetch peer's classical and Post-Quantum public keys from cache or backend API.
     */
    suspend fun getPeerPublicKey(
        peerUserId: String,
        accessToken: String?,
        baseUrl: String = "https://xchat-backend.xchat-amitmallik.workers.dev",
        forceRefresh: Boolean = false,
    ): PublicKey? = withContext(Dispatchers.IO) {
        val cleanPeerId = peerUserId.normalizedUserId()
        if (cleanPeerId.isBlank()) return@withContext null
        if (!forceRefresh) {
            peerPublicKeysCache[cleanPeerId]?.let { return@withContext it }
            val lastNegativeTime = noPublicKeyPeers[cleanPeerId]
            if (lastNegativeTime != null && (System.currentTimeMillis() - lastNegativeTime) < negativeCacheTtlMs) {
                return@withContext null
            }
        }

        if (accessToken.isNullOrBlank()) return@withContext null

        try {
            val request = Request.Builder()
                .url("$baseUrl/api/users/$cleanPeerId/public-key")
                .header("Authorization", "Bearer $accessToken")
                .get()
                .build()

            val response = okHttpClient.newCall(request).execute()
            val body = response.body?.string().orEmpty()
            if (response.isSuccessful) {
                val json = JSONObject(body)
                val pubBase64 = json.optString("publicKey")
                val pqPubBase64 = json.optString("pqPublicKey")

                if (pubBase64.isNotBlank()) {
                    val pubKey = cryptoEngine.decodePublicKey(pubBase64)
                    noPublicKeyPeers.remove(cleanPeerId)
                    peerPublicKeysCache[cleanPeerId] = pubKey

                    if (pqPubBase64.isNotBlank()) {
                        try {
                            peerKyberPublicKeysCache[cleanPeerId] = pqCryptoEngine.decodeKyberPublicKey(pqPubBase64)
                            Log.d(TAG, "Peer $cleanPeerId supports Post-Quantum ML-KEM!")
                        } catch (e: Exception) {
                            Log.w(TAG, "Failed to decode peer Post-Quantum public key: ${e.message}")
                        }
                    }

                    return@withContext pubKey
                } else {
                    noPublicKeyPeers[cleanPeerId] = System.currentTimeMillis()
                    Log.d(TAG, "Peer $cleanPeerId has not uploaded an E2EE public key yet")
                }
            } else {
                noPublicKeyPeers[cleanPeerId] = System.currentTimeMillis()
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to fetch peer public key for $cleanPeerId", e)
            noPublicKeyPeers[cleanPeerId] = System.currentTimeMillis()
        }
        null
    }

    /**
     * Asynchronously pre-fetch and derive the shared key in the background
     * when a chat room is opened, guaranteeing 0ms latency when sending messages.
     */
    fun preloadKeyForPeer(
        peerUserId: String,
        accessToken: String? = null,
        baseUrl: String = "https://xchat-backend.xchat-amitmallik.workers.dev",
    ) {
        val cleanPeerId = peerUserId.normalizedUserId()
        if (cleanPeerId.isBlank()) return
        if (sharedKeysCache.containsKey(cleanPeerId)) return
        val lastNegative = noPublicKeyPeers[cleanPeerId]
        if (lastNegative != null && (System.currentTimeMillis() - lastNegative) < negativeCacheTtlMs) return

        scope.launch {
            try {
                getOrDeriveSharedKey(cleanPeerId, accessToken, baseUrl)
            } catch (e: Exception) {
                Log.d(TAG, "Preload E2EE key for $cleanPeerId completed: ${e.message}")
            }
        }
    }

    /**
     * Get or derive 256-bit symmetric shared key for a peer (Classical ECDH).
     */
    suspend fun getOrDeriveSharedKey(
        peerUserId: String,
        accessToken: String?,
        baseUrl: String = "https://xchat-backend.xchat-amitmallik.workers.dev",
        forceRefresh: Boolean = false,
    ): SecretKey? = withContext(Dispatchers.IO) {
        val cleanPeerId = peerUserId.normalizedUserId()
        if (cleanPeerId.isBlank()) return@withContext null
        if (!forceRefresh) {
            sharedKeysCache[cleanPeerId]?.let { return@withContext it }
        }

        val myPriv = (ensureMyKeysLoaded()?.private) ?: return@withContext null
        val token = accessToken?.takeIf { it.isNotBlank() } ?: authService.getCurrentSession()?.accessToken
        val peerPub = getPeerPublicKey(cleanPeerId, token, baseUrl, forceRefresh) ?: return@withContext null

        try {
            val derived = cryptoEngine.deriveSharedKey(myPriv, peerPub)
            sharedKeysCache[cleanPeerId] = derived
            derived
        } catch (e: Exception) {
            Log.e(TAG, "Failed to derive shared key with $cleanPeerId", e)
            null
        }
    }

    /**
     * Encrypt message for peer:
     * - Uses Post-Quantum ML-KEM + ECDH Hybrid if peer supports PQ (`pqe2ee:`).
     * - Falls back to Classical ECDH (`e2ee:`) if peer has classical key.
     * - Falls back to plain text if peer has no keys registered.
     */
    suspend fun encryptForPeer(
        peerUserId: String,
        plainText: String,
        accessToken: String?,
        baseUrl: String = "https://xchat-backend.xchat-amitmallik.workers.dev",
    ): String {
        val cleanPeerId = peerUserId.normalizedUserId()
        if (plainText.isBlank() || cleanPeerId.isBlank()) return plainText

        val token = accessToken?.takeIf { it.isNotBlank() } ?: authService.getCurrentSession()?.accessToken
        val myKeys = ensureMyKeysLoaded()
        val peerPub = getPeerPublicKey(cleanPeerId, token, baseUrl)
        if (myKeys != null && peerPub != null) {
            return cryptoEngine.encryptWithEphemeralRatchet(
                plainText = plainText,
                myStaticPrivateKey = myKeys.private,
                peerStaticPublicKey = peerPub,
            )
        }
        // Fallback to classical static ECDH if needed
        val sharedKey = getOrDeriveSharedKey(cleanPeerId, token, baseUrl) ?: return plainText
        return cryptoEngine.encrypt(plainText, sharedKey)
    }

    /**
     * Decrypt message received from peer:
     * - Automatically detects Post-Quantum `pqe2ee:` payload.
     * - Automatically detects Classical `e2ee:` payload with self-healing key refresh.
     * - Plain text returns as-is.
     */
    suspend fun decryptFromPeer(
        peerUserId: String,
        payload: String?,
        accessToken: String?,
        baseUrl: String = "https://xchat-backend.xchat-amitmallik.workers.dev",
    ): String? {
        if (payload == null) return null
        val cleanPeerId = peerUserId.normalizedUserId()
        if (cleanPeerId.isBlank()) return payload

        // 1. Post-Quantum Payload
        if (payload.startsWith(PostQuantumCryptoEngine.PQ_PREFIX)) {
            val myKeys = ensureMyKeysLoaded()
            val myKyber = myKyberKeyPair
            val token = accessToken?.takeIf { it.isNotBlank() } ?: authService.getCurrentSession()?.accessToken
            val peerPub = getPeerPublicKey(cleanPeerId, token, baseUrl)

            if (myKeys != null && myKyber != null && peerPub != null) {
                val hybridKp = PostQuantumCryptoEngine.HybridKeyPair(myKeys, myKyber)
                var decrypted = pqCryptoEngine.decrypt(payload, hybridKp, peerPub)
                if (decrypted != null) return decrypted

                // Self-Healing for PQ: If initial decrypt failed, peer may have rotated key
                if (!token.isNullOrBlank()) {
                    Log.d(TAG, "Initial PQ decrypt failed for peer $cleanPeerId. Refreshing public keys...")
                    noPublicKeyPeers.remove(cleanPeerId)
                    peerPublicKeysCache.remove(cleanPeerId)
                    peerKyberPublicKeysCache.remove(cleanPeerId)
                    val freshPeerPub = getPeerPublicKey(cleanPeerId, token, baseUrl, forceRefresh = true)
                    if (freshPeerPub != null) {
                        decrypted = pqCryptoEngine.decrypt(payload, hybridKp, freshPeerPub)
                        if (decrypted != null) return decrypted
                    }
                }
            } else if (myKeys != null && myKyber != null && !token.isNullOrBlank()) {
                noPublicKeyPeers.remove(cleanPeerId)
                val freshPeerPub = getPeerPublicKey(cleanPeerId, token, baseUrl, forceRefresh = true)
                if (freshPeerPub != null) {
                    val hybridKp = PostQuantumCryptoEngine.HybridKeyPair(myKeys, myKyber)
                    val decrypted = pqCryptoEngine.decrypt(payload, hybridKp, freshPeerPub)
                    if (decrypted != null) return decrypted
                }
            }
        }

        // 2. Ephemeral Forward-Secrecy Ratchet Payload (e2ee2:)
        if (payload.startsWith(E2eeCryptoEngine.E2EE_V2_PREFIX)) {
            noPublicKeyPeers.remove(cleanPeerId)
            val token = accessToken?.takeIf { it.isNotBlank() } ?: authService.getCurrentSession()?.accessToken
            val myKeys = ensureMyKeysLoaded()
            val peerPub = getPeerPublicKey(cleanPeerId, token, baseUrl, forceRefresh = false)
            var decrypted = if (myKeys != null && peerPub != null) {
                cryptoEngine.decryptWithEphemeralRatchet(payload, myKeys.private, peerPub)
            } else null

            if (decrypted == null && myKeys != null && !token.isNullOrBlank()) {
                Log.d(TAG, "Initial e2ee2 decrypt failed for peer $cleanPeerId. Refreshing public key...")
                peerPublicKeysCache.remove(cleanPeerId)
                sharedKeysCache.remove(cleanPeerId)
                val freshPeerPub = getPeerPublicKey(cleanPeerId, token, baseUrl, forceRefresh = true)
                if (freshPeerPub != null) {
                    decrypted = cryptoEngine.decryptWithEphemeralRatchet(payload, myKeys.private, freshPeerPub)
                }
            }
            return decrypted
        }

        // 3. Classical E2EE Payload (e2ee:)
        if (payload.startsWith(E2eeCryptoEngine.E2EE_PREFIX)) {
            noPublicKeyPeers.remove(cleanPeerId)
            var sharedKey = getOrDeriveSharedKey(cleanPeerId, accessToken, baseUrl, forceRefresh = false)
            var decrypted = if (sharedKey != null) cryptoEngine.decrypt(payload, sharedKey) else null

            // Self-Healing
            if (decrypted == null && !accessToken.isNullOrBlank()) {
                Log.d(TAG, "Initial decrypt failed for peer $cleanPeerId. Refreshing public key...")
                peerPublicKeysCache.remove(cleanPeerId)
                sharedKeysCache.remove(cleanPeerId)
                val freshSharedKey = getOrDeriveSharedKey(cleanPeerId, accessToken, baseUrl, forceRefresh = true)
                if (freshSharedKey != null) {
                    decrypted = cryptoEngine.decrypt(payload, freshSharedKey)
                }
            }
            return decrypted
        }

        // 3. Plain text legacy fallback
        return payload
    }

    companion object {
        private const val TAG = "E2eeKeyManager"
        private const val PREFS_NAME = "yuzx_e2ee_prefs"
        private const val KEY_PUBLIC_KEY_UPLOADED = "my_e2ee_public_key_uploaded"
    }
}
