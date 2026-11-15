package com.yuzx.app.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricManager
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.security.KeyStore
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Arrays
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppLockManager @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val prefs by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    private val _isAppLockEnabled = MutableStateFlow(hasPin())
    val isAppLockEnabled: StateFlow<Boolean> = _isAppLockEnabled.asStateFlow()

    private val _isLocked = MutableStateFlow(hasPin())
    val isLocked: StateFlow<Boolean> = _isLocked.asStateFlow()

    private val _isBiometricEnabled = MutableStateFlow(isBiometricEnabledInternal())
    val isBiometricEnabled: StateFlow<Boolean> = _isBiometricEnabled.asStateFlow()

    private val _activeLockMode = MutableStateFlow(LockMode.NORMAL)
    val activeLockMode: StateFlow<LockMode> = _activeLockMode.asStateFlow()

    private val _failedAttempts = MutableStateFlow(prefs.getInt(KEY_FAILED_ATTEMPTS, 0))
    val failedAttempts: StateFlow<Int> = _failedAttempts.asStateFlow()

    private val _lockoutUntil = MutableStateFlow(prefs.getLong(KEY_LOCKOUT_UNTIL, 0L))
    val lockoutUntil: StateFlow<Long> = _lockoutUntil.asStateFlow()

    var onNukeTriggered: ((NukeScope) -> Unit)? = null

    fun isLockedOut(): Boolean {
        return _lockoutUntil.value > System.currentTimeMillis()
    }

    fun getRemainingLockoutSeconds(): Long {
        val diff = _lockoutUntil.value - System.currentTimeMillis()
        return if (diff > 0) (diff / 1000) + 1 else 0L
    }

    fun registerFailedAttempt() {
        val newAttempts = _failedAttempts.value + 1
        _failedAttempts.value = newAttempts
        prefs.edit().putInt(KEY_FAILED_ATTEMPTS, newAttempts).apply()

        val lockoutDurationMs = when {
            newAttempts >= 10 -> 5 * 60 * 1000L
            newAttempts >= 8 -> 2 * 60 * 1000L
            newAttempts >= 5 -> 30 * 1000L
            else -> 0L
        }

        if (lockoutDurationMs > 0) {
            val lockoutEnd = System.currentTimeMillis() + lockoutDurationMs
            _lockoutUntil.value = lockoutEnd
            prefs.edit().putLong(KEY_LOCKOUT_UNTIL, lockoutEnd).apply()
        }
    }

    fun resetFailedAttempts() {
        _failedAttempts.value = 0
        _lockoutUntil.value = 0L
        prefs.edit()
            .putInt(KEY_FAILED_ATTEMPTS, 0)
            .putLong(KEY_LOCKOUT_UNTIL, 0L)
            .apply()
    }

    fun hasPin(): Boolean {
        return prefs.getString(KEY_PIN_ENCRYPTED_DATA, null) != null ||
            prefs.getString(KEY_PIN_HASH, null) != null
    }

    fun hasNukePin(): Boolean {
        return prefs.getString(KEY_NUKE_PIN_DATA, null) != null
    }

    fun hasCipherPin(): Boolean {
        return prefs.getString(KEY_CIPHER_PIN_DATA, null) != null
    }

    fun canUseBiometrics(): Boolean {
        val pm = context.packageManager
        val hasFingerprintFeature = pm.hasSystemFeature(android.content.pm.PackageManager.FEATURE_FINGERPRINT)
        if (hasFingerprintFeature) return true

        val biometricManager = BiometricManager.from(context)
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.BIOMETRIC_WEAK or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        val result = biometricManager.canAuthenticate(authenticators)
        return result != BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE &&
            result != BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE
    }

    private fun isBiometricEnabledInternal(): Boolean {
        return prefs.getBoolean(KEY_BIOMETRIC_ENABLED, true)
    }

    fun isBiometricUnlockActive(): Boolean {
        return hasPin() && canUseBiometrics() && isBiometricEnabled.value
    }

    fun setBiometricEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_BIOMETRIC_ENABLED, enabled).apply()
        _isBiometricEnabled.value = enabled
    }

    /**
     * Store 4-to-6 digit PIN with PBKDF2 (100,000 rounds) + Android KeyStore AES-256-GCM
     */
    private fun storeEncryptedPin(prefKey: String, pin: String): Boolean {
        if (pin.length !in 4..6 || !pin.all { it.isDigit() }) return false
        return try {
            val salt = ByteArray(16)
            val strongRandom = try { SecureRandom.getInstanceStrong() } catch (_: Exception) { SecureRandom() }
            strongRandom.nextBytes(salt)
            val pbkdf2Hash = computePbkdf2Hash(pin, salt)

            val payload = ByteArray(salt.size + pbkdf2Hash.size)
            System.arraycopy(salt, 0, payload, 0, salt.size)
            System.arraycopy(pbkdf2Hash, 0, payload, salt.size, pbkdf2Hash.size)

            val encryptedPayload = encryptWithKeyStore(payload)
            prefs.edit().putString(prefKey, encryptedPayload).apply()

            // Zeroize sensitive buffers
            Arrays.fill(payload, 0.toByte())
            Arrays.fill(pbkdf2Hash, 0.toByte())
            Arrays.fill(salt, 0.toByte())
            true
        } catch (e: Exception) {
            false
        }
    }

    private fun verifyEncryptedPin(prefKey: String, pin: String): Boolean {
        if (pin.length !in 4..6 || !pin.all { it.isDigit() }) return false
        val encryptedData = prefs.getString(prefKey, null) ?: return false

        return try {
            val decryptedPayload = decryptWithKeyStore(encryptedData) ?: return false
            if (decryptedPayload.size < 48) return false

            val salt = decryptedPayload.copyOfRange(0, 16)
            val storedHash = decryptedPayload.copyOfRange(16, 48)
            val computedHash = computePbkdf2Hash(pin, salt)

            val matched = MessageDigest.isEqual(computedHash, storedHash)

            // Zeroize sensitive buffers immediately after comparison
            Arrays.fill(decryptedPayload, 0.toByte())
            Arrays.fill(salt, 0.toByte())
            Arrays.fill(storedHash, 0.toByte())
            Arrays.fill(computedHash, 0.toByte())
            matched
        } catch (e: Exception) {
            false
        }
    }

    // 1. MASTER PIN
    fun setPin(pin: String): Boolean {
        val success = storeEncryptedPin(KEY_PIN_ENCRYPTED_DATA, pin)
        if (success) {
            prefs.edit()
                .remove(KEY_PIN_HASH)
                .remove(KEY_PIN_SALT)
                .putBoolean(KEY_BIOMETRIC_ENABLED, true)
                .apply()
            _isAppLockEnabled.value = true
            _isLocked.value = false
            _isBiometricEnabled.value = true
            _activeLockMode.value = LockMode.NORMAL
        }
        return success
    }

    fun verifyPin(pin: String): Boolean {
        if (verifyEncryptedPin(KEY_PIN_ENCRYPTED_DATA, pin)) return true

        // Legacy SHA-256 fallback & auto-migration
        val storedLegacyHash = prefs.getString(KEY_PIN_HASH, null) ?: return false
        val storedLegacySaltBase64 = prefs.getString(KEY_PIN_SALT, null) ?: return false

        return try {
            val salt = Base64.getDecoder().decode(storedLegacySaltBase64)
            val digest = MessageDigest.getInstance("SHA-256")
            digest.update(salt)
            val hashBytes = digest.digest(pin.toByteArray(Charsets.UTF_8))
            val computedHashBase64 = Base64.getEncoder().encodeToString(hashBytes)

            if (computedHashBase64 == storedLegacyHash) {
                setPin(pin)
                true
            } else {
                false
            }
        } catch (e: Exception) {
            false
        }
    }

    fun disablePin(currentPin: String): Boolean {
        if (verifyPin(currentPin)) {
            prefs.edit()
                .remove(KEY_PIN_ENCRYPTED_DATA)
                .remove(KEY_PIN_HASH)
                .remove(KEY_PIN_SALT)
                .remove(KEY_NUKE_PIN_DATA)
                .remove(KEY_CIPHER_PIN_DATA)
                .remove(KEY_DECOY_ROOM_IDS)
                .remove(KEY_BIOMETRIC_ENABLED)
                .apply()
            _decoyRoomIds.value = emptySet()
            _isAppLockEnabled.value = false
            _isLocked.value = false
            _isBiometricEnabled.value = false
            _activeLockMode.value = LockMode.NORMAL
            return true
        }
        return false
    }

    // 2. NUKE PIN & SCOPE
    fun setNukePin(pin: String, scope: NukeScope = NukeScope()): Boolean {
        val success = storeEncryptedPin(KEY_NUKE_PIN_DATA, pin)
        if (success) {
            setNukeScope(scope)
        }
        return success
    }

    fun disableNukePin(): Boolean {
        prefs.edit().remove(KEY_NUKE_PIN_DATA).apply()
        return true
    }

    fun verifyNukePin(pin: String): Boolean {
        return verifyEncryptedPin(KEY_NUKE_PIN_DATA, pin)
    }

    fun getNukeScope(): NukeScope {
        val set = prefs.getStringSet(KEY_NUKE_SCOPE, null)
        return if (set != null) NukeScope.fromList(set.toList()) else NukeScope()
    }

    fun setNukeScope(scope: NukeScope) {
        prefs.edit().putStringSet(KEY_NUKE_SCOPE, scope.toList().toSet()).apply()
    }

    // 3. CIPHER / DECOY PIN & ROOMS
    private val _decoyRoomIds = MutableStateFlow(getDecoyRoomIdsInternal())
    val decoyRoomIds: StateFlow<Set<String>> = _decoyRoomIds.asStateFlow()

    private fun getDecoyRoomIdsInternal(): Set<String> {
        return prefs.getStringSet(KEY_DECOY_ROOM_IDS, null) ?: emptySet()
    }

    fun getDecoyRoomIds(): Set<String> {
        return _decoyRoomIds.value
    }

    fun setDecoyRoomIds(roomIds: Set<String>) {
        prefs.edit().putStringSet(KEY_DECOY_ROOM_IDS, roomIds).apply()
        _decoyRoomIds.value = roomIds
    }

    fun setCipherPin(pin: String): Boolean {
        return storeEncryptedPin(KEY_CIPHER_PIN_DATA, pin)
    }

    fun disableCipherPin(): Boolean {
        prefs.edit()
            .remove(KEY_CIPHER_PIN_DATA)
            .remove(KEY_DECOY_ROOM_IDS)
            .apply()
        _decoyRoomIds.value = emptySet()
        return true
    }

    fun verifyCipherPin(pin: String): Boolean {
        return verifyEncryptedPin(KEY_CIPHER_PIN_DATA, pin)
    }

    // UNLOCK ROUTER
    fun unlock(pin: String): UnlockResult {
        if (isLockedOut()) {
            return UnlockResult.Failed
        }

        if (verifyPin(pin)) {
            resetFailedAttempts()
            _activeLockMode.value = LockMode.NORMAL
            _isLocked.value = false
            return UnlockResult.NormalSuccess
        }
        if (hasCipherPin() && verifyCipherPin(pin)) {
            resetFailedAttempts()
            _activeLockMode.value = LockMode.CIPHER
            _isLocked.value = false
            return UnlockResult.CipherSuccess
        }
        if (hasNukePin() && verifyNukePin(pin)) {
            resetFailedAttempts()
            _isLocked.value = false
            val scope = getNukeScope()
            executeLocalNuke(scope)
            return UnlockResult.NukeTriggered(scope)
        }

        registerFailedAttempt()
        return UnlockResult.Failed
    }

    fun unlockWithBiometrics(mode: LockMode = LockMode.NORMAL) {
        if (!isLockedOut()) {
            resetFailedAttempts()
            _activeLockMode.value = mode
            _isLocked.value = false
        }
    }

    fun triggerNuke(scope: NukeScope = getNukeScope()) {
        resetFailedAttempts()
        executeLocalNuke(scope)
    }

    fun lock() {
        if (hasPin()) {
            _isLocked.value = true
            _activeLockMode.value = LockMode.NORMAL
        }
    }

    fun resetToNormalMode() {
        _activeLockMode.value = LockMode.NORMAL
    }

    private fun executeLocalNuke(scope: NukeScope) {
        try {
            if (scope.wipeLocalData) {
                // Clear app-lock preferences & credentials
                prefs.edit().clear().apply()
                _isAppLockEnabled.value = false
                _isLocked.value = false
                _isBiometricEnabled.value = false
                _failedAttempts.value = 0
                _lockoutUntil.value = 0L
            }
            onNukeTriggered?.invoke(scope)
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    private fun computePbkdf2Hash(pin: String, salt: ByteArray): ByteArray {
        val pinChars = pin.toCharArray()
        val spec = PBEKeySpec(pinChars, salt, PBKDF2_ITERATIONS, 256)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val hash = factory.generateSecret(spec).encoded
        spec.clearPassword()
        Arrays.fill(pinChars, '\u0000')
        return hash
    }

    private fun getOrCreateKeyStoreKey(): SecretKey {
        val keyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = (keyStore.getEntry(KEYSTORE_ALIAS, null) as? KeyStore.SecretKeyEntry)?.secretKey
        if (existing != null) return existing

        val keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        val spec = KeyGenParameterSpec.Builder(
            KEYSTORE_ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        keyGenerator.init(spec)
        return keyGenerator.generateKey()
    }

    private fun encryptWithKeyStore(data: ByteArray): String {
        val key = getOrCreateKeyStoreKey()
        val cipher = Cipher.getInstance(GCM_TRANSFORMATION).apply {
            init(Cipher.ENCRYPT_MODE, key)
        }
        val iv = cipher.iv
        val cipherText = cipher.doFinal(data)
        val combined = ByteArray(iv.size + cipherText.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(cipherText, 0, combined, iv.size, cipherText.size)
        return Base64.getEncoder().encodeToString(combined)
    }

    private fun decryptWithKeyStore(encryptedBase64: String): ByteArray? {
        return try {
            val combined = Base64.getDecoder().decode(encryptedBase64)
            if (combined.size <= 12) return null
            val iv = combined.copyOfRange(0, 12)
            val cipherText = combined.copyOfRange(12, combined.size)
            val key = getOrCreateKeyStoreKey()
            val spec = GCMParameterSpec(128, iv)
            val cipher = Cipher.getInstance(GCM_TRANSFORMATION).apply {
                init(Cipher.DECRYPT_MODE, key, spec)
            }
            cipher.doFinal(cipherText)
        } catch (e: Exception) {
            null
        }
    }

    companion object {
        private const val PREFS_NAME = "yuzx_app_lock_prefs"
        private const val KEY_PIN_ENCRYPTED_DATA = "pin_encrypted_data_v2"
        private const val KEY_PIN_HASH = "pin_hash"
        private const val KEY_PIN_SALT = "pin_salt"
        private const val KEY_NUKE_PIN_DATA = "nuke_pin_encrypted_data"
        private const val KEY_CIPHER_PIN_DATA = "cipher_pin_encrypted_data"
        private const val KEY_DECOY_ROOM_IDS = "decoy_visible_room_ids"
        private const val KEY_NUKE_SCOPE = "nuke_scope_v1"
        private const val KEY_BIOMETRIC_ENABLED = "biometric_enabled"
        private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
        private const val KEY_LOCKOUT_UNTIL = "lockout_until"

        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val KEYSTORE_ALIAS = "yuzx_app_lock_key"
        private const val GCM_TRANSFORMATION = "AES/GCM/NoPadding"
        private const val PBKDF2_ITERATIONS = 100_000
    }
}
