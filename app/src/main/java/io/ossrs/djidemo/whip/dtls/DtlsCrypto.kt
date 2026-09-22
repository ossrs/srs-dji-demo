package io.ossrs.djidemo.whip.dtls

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The cryptography behind the handshake: the TLS pseudo-random function, the key schedule it
 * drives, and the AEAD that protects records once it has run.
 *
 * All the primitives come from the Android platform's own providers. Nothing here implements a
 * cipher or a hash -- it implements the *construction* TLS builds out of them, which is where all
 * the version-specific detail lives.
 *
 * The one cipher suite supported is `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`. That is not a
 * limitation worth apologising for: it is what WebRTC endpoints negotiate in practice, and an
 * AEAD suite means the record layer has no separate MAC key, no padding and no ordering subtleties
 * between encryption and authentication.
 */
internal object DtlsCrypto {

    const val CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256 = 0xC02B

    /** AES-128-GCM: 16-byte key, 4-byte implicit salt, 8-byte explicit nonce, 16-byte tag. */
    const val KEY_SIZE = 16
    const val FIXED_IV_SIZE = 4
    const val EXPLICIT_NONCE_SIZE = 8
    const val TAG_SIZE = 16

    const val VERIFY_DATA_SIZE = 12

    /**
     * `P_SHA256` from RFC 5246 section 5: HMAC iterated until enough bytes exist.
     *
     * `A(0)` is the seed and `A(i) = HMAC(secret, A(i-1))`; the output is the concatenation of
     * `HMAC(secret, A(i) + seed)`. TLS 1.2 fixed the hash to whatever the cipher suite names, which
     * for this suite is SHA-256, so there is no hash agility to carry here.
     */
    fun prf(secret: ByteArray, label: String, seed: ByteArray, length: Int): ByteArray {
        val labelledSeed = label.toByteArray(Charsets.US_ASCII) + seed
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }

        val out = ByteArray(length)
        var a = labelledSeed
        var written = 0
        while (written < length) {
            a = mac.doFinal(a)
            val block = mac.doFinal(a + labelledSeed)
            val take = minOf(block.size, length - written)
            System.arraycopy(block, 0, out, written, take)
            written += take
        }
        return out
    }

    /**
     * The extended master secret of RFC 7627.
     *
     * The original construction derived the master secret from the two random values alone, which
     * let an attacker who could man-in-the-middle two handshakes make them agree on the same master
     * secret. Binding it to a hash of the whole handshake instead closes that, and WebRTC endpoints
     * require the extension -- so this client offers it and does not implement the legacy form.
     */
    fun extendedMasterSecret(preMasterSecret: ByteArray, handshakeHash: ByteArray): ByteArray =
        prf(preMasterSecret, "extended master secret", handshakeHash, 48)

    /**
     * Splits the key block into the four values an AEAD suite needs.
     *
     * The order within the block is fixed by the specification: client key, server key, client
     * salt, server salt. There are no MAC keys, because GCM authenticates as it encrypts.
     */
    fun keyBlock(masterSecret: ByteArray, clientRandom: ByteArray, serverRandom: ByteArray): Keys {
        val block = prf(
            masterSecret,
            "key expansion",
            // Note the order: the key block's seed is server random first, which is the reverse of
            // the master secret's. Swapping them produces keys that fail only at the first
            // decryption, with no clue as to why.
            serverRandom + clientRandom,
            2 * KEY_SIZE + 2 * FIXED_IV_SIZE,
        )
        var offset = 0
        fun take(size: Int) = block.copyOfRange(offset, offset + size).also { offset += size }
        return Keys(
            clientWriteKey = take(KEY_SIZE),
            serverWriteKey = take(KEY_SIZE),
            clientWriteIv = take(FIXED_IV_SIZE),
            serverWriteIv = take(FIXED_IV_SIZE),
        )
    }

    class Keys(
        val clientWriteKey: ByteArray,
        val serverWriteKey: ByteArray,
        val clientWriteIv: ByteArray,
        val serverWriteIv: ByteArray,
    )

    /** `verify_data` for a Finished message: 12 bytes over a hash of every handshake message. */
    fun verifyData(masterSecret: ByteArray, label: String, handshakeHash: ByteArray): ByteArray =
        prf(masterSecret, label, handshakeHash, VERIFY_DATA_SIZE)

    /**
     * The RFC 5705 exporter, which is how DTLS-SRTP produces its keys.
     *
     * The point of the exporter is that SRTP's keys are derived from the same master secret as the
     * record layer's but can never be confused with them, because the label is different. This is
     * the entire connection between the handshake and the media that follows it.
     */
    fun exportKeyingMaterial(
        masterSecret: ByteArray,
        label: String,
        clientRandom: ByteArray,
        serverRandom: ByteArray,
        length: Int,
    ): ByteArray = prf(masterSecret, label, clientRandom + serverRandom, length)

    fun sha256(data: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(data)

    /**
     * Encrypts one record body.
     *
     * The explicit nonce is the record's own 64-bit sequence number, which guarantees it is never
     * reused under one key -- the single requirement GCM has and the single way it fails
     * catastrophically. It is prepended to the ciphertext because the receiver needs it and has no
     * other way to know it.
     */
    fun sealRecord(
        key: ByteArray,
        fixedIv: ByteArray,
        explicitNonce: ByteArray,
        additionalData: ByteArray,
        plaintext: ByteArray,
    ): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.ENCRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(TAG_SIZE * 8, fixedIv + explicitNonce),
        )
        cipher.updateAAD(additionalData)
        return explicitNonce + cipher.doFinal(plaintext)
    }

    /**
     * Decrypts one record body, or throws if the tag does not verify.
     *
     * A failure here is never recoverable and never worth retrying: it means the record was
     * corrupted, replayed, or encrypted under keys that do not match.
     */
    fun openRecord(
        key: ByteArray,
        fixedIv: ByteArray,
        additionalData: ByteArray,
        body: ByteArray,
    ): ByteArray {
        require(body.size >= EXPLICIT_NONCE_SIZE + TAG_SIZE) { "dtls record too short" }
        val explicitNonce = body.copyOfRange(0, EXPLICIT_NONCE_SIZE)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(
            Cipher.DECRYPT_MODE,
            SecretKeySpec(key, "AES"),
            GCMParameterSpec(TAG_SIZE * 8, fixedIv + explicitNonce),
        )
        cipher.updateAAD(additionalData)
        return cipher.doFinal(body, EXPLICIT_NONCE_SIZE, body.size - EXPLICIT_NONCE_SIZE)
    }

    /**
     * The additional authenticated data for a record: its sequence number and its header.
     *
     * Authenticating the header is what stops an attacker rewriting a record's type or version
     * without invalidating the tag, and including the epoch and sequence number is what stops one
     * record being replayed as another.
     */
    fun additionalData(epoch: Int, sequence: Long, contentType: Int, version: Int, length: Int): ByteArray {
        val out = ByteArray(13)
        val epochAndSequence = (epoch.toLong() shl 48) or (sequence and 0xFFFFFFFFFFFFL)
        for (i in 0 until 8) out[i] = ((epochAndSequence ushr (56 - i * 8)) and 0xFF).toByte()
        out[8] = contentType.toByte()
        out[9] = ((version ushr 8) and 0xFF).toByte()
        out[10] = (version and 0xFF).toByte()
        out[11] = ((length ushr 8) and 0xFF).toByte()
        out[12] = (length and 0xFF).toByte()
        return out
    }

    /** The eight-byte explicit nonce: the record's epoch and sequence number. */
    fun explicitNonce(epoch: Int, sequence: Long): ByteArray {
        val out = ByteArray(8)
        val value = (epoch.toLong() shl 48) or (sequence and 0xFFFFFFFFFFFFL)
        for (i in 0 until 8) out[i] = ((value ushr (56 - i * 8)) and 0xFF).toByte()
        return out
    }
}
