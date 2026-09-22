package io.ossrs.djidemo.whip.srtp

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * SRTP and SRTCP protection for the `AES_CM_128_HMAC_SHA1_80` profile.
 *
 * SRTP does not wrap RTP in anything. It encrypts the payload in place, leaves the header readable
 * so routers and receivers can still do their job, and appends a ten-byte authentication tag. A
 * packet on the wire is therefore the same shape as the RTP packet that went in, ten bytes longer.
 *
 * Two things are worth understanding before reading the code, and both are consequences of running
 * over UDP where packets are lost and reordered:
 *
 * - **Counter mode, not a chained cipher.** The keystream for a packet is a function of its
 *   sequence number, so a receiver can decrypt packet 900 without having seen 899. The price is
 *   that reusing a counter value under one key destroys the encryption completely, which is why the
 *   rollover counter below is not a nicety.
 * - **The rollover counter.** RTP's sequence number is only 16 bits and wraps every 65,536 packets,
 *   which at this bitrate is a couple of minutes. SRTP therefore counts wraps separately and uses a
 *   48-bit index made of the two, so the counter keeps increasing long after the sequence number
 *   has gone round.
 */
internal class SrtpSession(masterKey: ByteArray, masterSalt: ByteArray) {

    /** Session keys, derived once from the master key the DTLS handshake exported. */
    private val rtpEncryptionKey = deriveKey(masterKey, masterSalt, LABEL_RTP_ENCRYPTION, 16)
    private val rtpAuthKey = deriveKey(masterKey, masterSalt, LABEL_RTP_AUTHENTICATION, 20)
    private val rtpSalt = deriveKey(masterKey, masterSalt, LABEL_RTP_SALT, 14)

    private val rtcpEncryptionKey = deriveKey(masterKey, masterSalt, LABEL_RTCP_ENCRYPTION, 16)
    private val rtcpAuthKey = deriveKey(masterKey, masterSalt, LABEL_RTCP_AUTHENTICATION, 20)
    private val rtcpSalt = deriveKey(masterKey, masterSalt, LABEL_RTCP_SALT, 14)

    /** Wraps of the 16-bit RTP sequence number. See the class comment. */
    private var rolloverCounter = 0L
    private var highestSequence = -1

    /** SRTCP has its own 31-bit index, which is simply a packet counter. */
    private var rtcpIndex = 0L

    /**
     * Encrypts and authenticates one RTP packet.
     *
     * The header is left in the clear and authenticated; only the payload is encrypted. The
     * rollover counter is folded into both the keystream counter and the authentication tag, so a
     * receiver that has lost track of it cannot validate the packet -- which is the mechanism that
     * makes replaying an old packet after a wrap fail.
     */
    fun protectRtp(packet: ByteArray): ByteArray {
        val headerLength = rtpHeaderLength(packet)
        val sequence = ((packet[2].toInt() and 0xFF) shl 8) or (packet[3].toInt() and 0xFF)
        val ssrc = readUInt32(packet, 8)

        advanceRollover(sequence)
        val index = (rolloverCounter shl 16) or sequence.toLong()

        val protected = packet.copyOf(packet.size + TAG_SIZE)
        keystreamXor(
            rtpEncryptionKey,
            counterIv(rtpSalt, ssrc, index),
            protected,
            headerLength,
            packet.size - headerLength,
        )

        // The tag covers the whole packet as it now stands, plus the rollover counter, which is not
        // transmitted anywhere: both sides have to agree on it independently.
        val tag = Mac.getInstance("HmacSHA1").run {
            init(SecretKeySpec(rtpAuthKey, "HmacSHA1"))
            update(protected, 0, packet.size)
            update(be32(rolloverCounter))
            doFinal()
        }
        System.arraycopy(tag, 0, protected, packet.size, TAG_SIZE)
        return protected
    }

    /**
     * Encrypts and authenticates one RTCP packet.
     *
     * SRTCP differs from SRTP in two ways that matter here: the first eight bytes stay in the clear
     * because the sender's identity has to be readable, and the packet index is appended to the
     * packet rather than being recovered from a sequence number -- RTCP has none.
     */
    fun protectRtcp(packet: ByteArray): ByteArray {
        require(packet.size >= RTCP_CLEAR_PREFIX) { "rtcp packet too short" }
        val ssrc = readUInt32(packet, 4)
        rtcpIndex = (rtcpIndex + 1) and 0x7FFFFFFF

        val protected = packet.copyOf(packet.size + 4 + TAG_SIZE)
        keystreamXor(
            rtcpEncryptionKey,
            counterIv(rtcpSalt, ssrc, rtcpIndex),
            protected,
            RTCP_CLEAR_PREFIX,
            packet.size - RTCP_CLEAR_PREFIX,
        )

        // The top bit of the appended word is the "encrypted" flag, which is always set here
        // because this implementation never sends RTCP in the clear.
        val indexWord = be32(rtcpIndex or 0x80000000L)
        System.arraycopy(indexWord, 0, protected, packet.size, 4)

        val tag = Mac.getInstance("HmacSHA1").run {
            init(SecretKeySpec(rtcpAuthKey, "HmacSHA1"))
            update(protected, 0, packet.size + 4)
            doFinal()
        }
        System.arraycopy(tag, 0, protected, packet.size + 4, TAG_SIZE)
        return protected
    }

    /**
     * Tracks sequence number wraps.
     *
     * Only forward progress past the halfway point counts as a wrap, so a reordered packet arriving
     * just after the number rolls over does not advance the counter a second time.
     */
    private fun advanceRollover(sequence: Int) {
        if (highestSequence < 0) {
            highestSequence = sequence
            return
        }
        if (sequence < highestSequence && highestSequence - sequence > 0x8000) rolloverCounter++
        if (sequence > highestSequence || highestSequence - sequence > 0x8000) highestSequence = sequence
    }

    /**
     * Encrypts `length` bytes of [buffer] at [offset] in place, with AES in counter mode.
     *
     * Counter mode turns a block cipher into a stream cipher: successive counter blocks are
     * encrypted to make a keystream, and the keystream is XORed with the data. Java's `AES/CTR`
     * increments the counter exactly as SRTP requires, so the IV can be handed over as-is.
     */
    private fun keystreamXor(key: ByteArray, iv: ByteArray, buffer: ByteArray, offset: Int, length: Int) {
        if (length <= 0) return
        val cipher = Cipher.getInstance("AES/CTR/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
        val encrypted = cipher.doFinal(buffer, offset, length)
        System.arraycopy(encrypted, 0, buffer, offset, length)
    }

    /**
     * The counter block for one packet: the session salt, with the stream and the packet mixed in.
     *
     * Laid out as RFC 3711 specifies: the 112-bit salt occupies the top fourteen bytes, the SSRC is
     * exclusive-ORed in at bytes four to seven, and the 48-bit packet index at bytes eight to
     * thirteen. The final two bytes are the block counter within the packet, which the cipher
     * increments itself.
     */
    private fun counterIv(salt: ByteArray, ssrc: Long, index: Long): ByteArray {
        val iv = ByteArray(16)
        System.arraycopy(salt, 0, iv, 0, salt.size)
        for (i in 0 until 4) {
            iv[4 + i] = (iv[4 + i].toInt() xor ((ssrc ushr (24 - i * 8)) and 0xFF).toInt()).toByte()
        }
        for (i in 0 until 6) {
            iv[8 + i] = (iv[8 + i].toInt() xor ((index ushr (40 - i * 8)) and 0xFF).toInt()).toByte()
        }
        return iv
    }

    /**
     * The length of an RTP header, including the CSRC list and any extension.
     *
     * Needed because encryption starts where the header ends, and the header is not a fixed size:
     * the CSRC count and the extension bit both make it longer.
     */
    private fun rtpHeaderLength(packet: ByteArray): Int {
        var length = 12 + 4 * (packet[0].toInt() and 0x0F)
        val hasExtension = (packet[0].toInt() and 0x10) != 0
        if (hasExtension && packet.size >= length + 4) {
            val words = ((packet[length + 2].toInt() and 0xFF) shl 8) or (packet[length + 3].toInt() and 0xFF)
            length += 4 + 4 * words
        }
        return length
    }

    internal companion object {

        /** The 80-bit authentication tag this profile appends. */
        const val TAG_SIZE = 10

        /** Version, type, length and sender SSRC: eight bytes of RTCP that stay readable. */
        const val RTCP_CLEAR_PREFIX = 8

        const val LABEL_RTP_ENCRYPTION = 0x00
        const val LABEL_RTP_AUTHENTICATION = 0x01
        const val LABEL_RTP_SALT = 0x02
        const val LABEL_RTCP_ENCRYPTION = 0x03
        const val LABEL_RTCP_AUTHENTICATION = 0x04
        const val LABEL_RTCP_SALT = 0x05

        /**
         * The SRTP key derivation function of RFC 3711 section 4.3.
         *
         * Six session keys come out of one master key, and what separates them is a single label
         * byte exclusive-ORed into the counter block. That is the whole mechanism: the same cipher,
         * the same key, six different starting counters, so an attacker who recovers one session
         * key learns nothing about the others.
         *
         * The key derivation rate is fixed at zero -- meaning "derive once, never re-derive" --
         * which is what every WebRTC endpoint uses.
         */
        fun deriveKey(masterKey: ByteArray, masterSalt: ByteArray, label: Int, length: Int): ByteArray {
            val iv = ByteArray(16)
            System.arraycopy(masterSalt, 0, iv, 0, masterSalt.size)
            // The label sits in the top byte of the 56-bit key id, which lines up with byte seven
            // of the 112-bit salt. The rest of the key id is the derivation index, always zero.
            iv[7] = (iv[7].toInt() xor label).toByte()

            val cipher = Cipher.getInstance("AES/CTR/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(masterKey, "AES"), IvParameterSpec(iv))
            // Encrypting zeroes in counter mode is how a keystream is extracted from a block cipher.
            return cipher.doFinal(ByteArray(length))
        }

        fun readUInt32(data: ByteArray, offset: Int): Long =
            ((data[offset].toLong() and 0xFF) shl 24) or ((data[offset + 1].toLong() and 0xFF) shl 16) or
                ((data[offset + 2].toLong() and 0xFF) shl 8) or (data[offset + 3].toLong() and 0xFF)

        fun be32(value: Long) = ByteArray(4) { ((value ushr (24 - it * 8)) and 0xFF).toByte() }
    }
}
