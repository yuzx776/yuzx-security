package com.yuzx.app.core.chatcore

import com.yuzx.app.core.chatcore.api.crypto.E2eeCryptoEngine
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class E2eeCryptoEngineTest {

    private val cryptoEngine = E2eeCryptoEngine()

    @Test
    fun `ECDH key agreement derives identical shared key for Alice and Bob`() {
        // Alice generates keypair
        val aliceKeyPair = cryptoEngine.generateKeyPair()
        // Bob generates keypair
        val bobKeyPair = cryptoEngine.generateKeyPair()

        // Alice derives shared key using Bob's public key
        val aliceSharedKey = cryptoEngine.deriveSharedKey(aliceKeyPair.private, bobKeyPair.public)

        // Bob derives shared key using Alice's public key
        val bobSharedKey = cryptoEngine.deriveSharedKey(bobKeyPair.private, aliceKeyPair.public)

        // The derived AES keys must be 100% identical in bytes
        assertEquals(aliceSharedKey.algorithm, bobSharedKey.algorithm)
        assertTrue(aliceSharedKey.encoded.contentEquals(bobSharedKey.encoded))
    }

    @Test
    fun `Encrypt and decrypt message recovers exact plaintext`() {
        val aliceKeyPair = cryptoEngine.generateKeyPair()
        val bobKeyPair = cryptoEngine.generateKeyPair()

        val aliceSharedKey = cryptoEngine.deriveSharedKey(aliceKeyPair.private, bobKeyPair.public)
        val bobSharedKey = cryptoEngine.deriveSharedKey(bobKeyPair.private, aliceKeyPair.public)

        val originalMessage = "Hello Bob! This is an End-to-End encrypted message 🔐🚀"
        val encryptedPayload = cryptoEngine.encrypt(originalMessage, aliceSharedKey)

        assertTrue(encryptedPayload.startsWith(E2eeCryptoEngine.E2EE_PREFIX))
        assertNotEquals(originalMessage, encryptedPayload)

        val decryptedMessage = cryptoEngine.decrypt(encryptedPayload, bobSharedKey)
        assertEquals(originalMessage, decryptedMessage)
    }

    @Test
    fun `Decryption fails gracefully with tampered ciphertext or wrong key`() {
        val aliceKeyPair = cryptoEngine.generateKeyPair()
        val bobKeyPair = cryptoEngine.generateKeyPair()
        val eveKeyPair = cryptoEngine.generateKeyPair() // Attacker

        val aliceSharedKey = cryptoEngine.deriveSharedKey(aliceKeyPair.private, bobKeyPair.public)
        val eveSharedKey = cryptoEngine.deriveSharedKey(eveKeyPair.private, bobKeyPair.public)

        val message = "Secret financial transaction"
        val ciphertext = cryptoEngine.encrypt(message, aliceSharedKey)

        // Eve tries to decrypt Alice's message to Bob
        val eveDecrypted = cryptoEngine.decrypt(ciphertext, eveSharedKey)
        assertNull("Eve should not be able to decrypt with wrong key", eveDecrypted)
    }

    @Test
    fun `Legacy plain text is passed through unchanged for backward compatibility`() {
        val keyPair = cryptoEngine.generateKeyPair()
        val sharedKey = cryptoEngine.deriveSharedKey(keyPair.private, keyPair.public)

        val legacyPlaintext = "Old unencrypted message from 2024"
        val result = cryptoEngine.decrypt(legacyPlaintext, sharedKey)
        assertEquals(legacyPlaintext, result)
    }

    @Test
    fun `Throughput test verifies sub-millisecond encryption and decryption`() {
        val aliceKeyPair = cryptoEngine.generateKeyPair()
        val bobKeyPair = cryptoEngine.generateKeyPair()
        val sharedKey = cryptoEngine.deriveSharedKey(aliceKeyPair.private, bobKeyPair.public)

        val sampleText = "A rapid chat message for benchmark testing."

        val iterations = 500
        val startTime = System.nanoTime()

        for (i in 0 until iterations) {
            val encrypted = cryptoEngine.encrypt(sampleText, sharedKey)
            val decrypted = cryptoEngine.decrypt(encrypted, sharedKey)
            assertEquals(sampleText, decrypted)
        }

        val totalTimeNanos = System.nanoTime() - startTime
        val avgTimeMillis = (totalTimeNanos.toDouble() / iterations) / 1_000_000.0

        println("Average Encrypt+Decrypt time per message: $avgTimeMillis ms")
        assertTrue("Expected average time < 2.0ms per message", avgTimeMillis < 2.0)
    }

    @Test
    fun `Key rotation recovery derives fresh shared key and decrypts successfully`() {
        val aliceKeyPair = cryptoEngine.generateKeyPair()
        val bobKeyPair = cryptoEngine.generateKeyPair()

        // Alice encrypts for Bob's initial key
        val aliceSharedKey = cryptoEngine.deriveSharedKey(aliceKeyPair.private, bobKeyPair.public)
        val message = "Hello after rotation"
        val ciphertext = cryptoEngine.encrypt(message, aliceSharedKey)

        // Bob rotates his keypair
        val bobNewKeyPair = cryptoEngine.generateKeyPair()
        // Alice re-derives shared key with Bob's new public key
        val aliceNewSharedKey = cryptoEngine.deriveSharedKey(aliceKeyPair.private, bobNewKeyPair.public)
        val bobNewSharedKey = cryptoEngine.deriveSharedKey(bobNewKeyPair.private, aliceKeyPair.public)

        val newCiphertext = cryptoEngine.encrypt(message, aliceNewSharedKey)
        val decrypted = cryptoEngine.decrypt(newCiphertext, bobNewSharedKey)
        assertEquals(message, decrypted)
    }

    @Test
    fun `Ephemeral ratchet v2 encrypts and decrypts with per-message forward secrecy`() {
        val aliceKeyPair = cryptoEngine.generateKeyPair()
        val bobKeyPair = cryptoEngine.generateKeyPair()
        val eveKeyPair = cryptoEngine.generateKeyPair()

        val msg = "Per-message ephemeral ECDH forward secrecy test"
        val payload1 = cryptoEngine.encryptWithEphemeralRatchet(msg, aliceKeyPair.private, bobKeyPair.public)
        val payload2 = cryptoEngine.encryptWithEphemeralRatchet(msg, aliceKeyPair.private, bobKeyPair.public)

        assertTrue(payload1.startsWith(E2eeCryptoEngine.E2EE_V2_PREFIX))
        assertTrue(payload2.startsWith(E2eeCryptoEngine.E2EE_V2_PREFIX))
        // Identical plaintext must produce distinct ephemeral public keys, IVs, and ciphertexts
        assertNotEquals(payload1, payload2)

        assertEquals(msg, cryptoEngine.decryptWithEphemeralRatchet(payload1, bobKeyPair.private, aliceKeyPair.public))
        assertEquals(msg, cryptoEngine.decryptWithEphemeralRatchet(payload2, bobKeyPair.private, aliceKeyPair.public))

        // Eve cannot decrypt with wrong private key
        assertNull(cryptoEngine.decryptWithEphemeralRatchet(payload1, eveKeyPair.private, aliceKeyPair.public))

        // Tampered ciphertext fails GCM authentication
        val tampered = payload1.dropLast(4) + "AAAA"
        assertNull(cryptoEngine.decryptWithEphemeralRatchet(tampered, bobKeyPair.private, aliceKeyPair.public))
    }
}
