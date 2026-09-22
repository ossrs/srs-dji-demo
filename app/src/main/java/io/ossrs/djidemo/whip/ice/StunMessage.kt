package io.ossrs.djidemo.whip.ice

import java.nio.ByteBuffer
import java.security.SecureRandom
import java.util.zip.CRC32
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * STUN binding messages, with the attributes ICE adds to them.
 *
 * ICE's connectivity check is a STUN binding request sent from one candidate address to another; a
 * success response proves the path works *in that direction*, and both sides check both directions.
 * The two attributes that make it ICE rather than plain STUN are `USERNAME`, which carries the
 * credentials exchanged in the SDP, and `MESSAGE-INTEGRITY`, which authenticates the message with
 * the peer's password -- so a check cannot be forged or replayed onto an unrelated session.
 *
 * Two details in here are the usual source of "the server ignores my checks", and both are about
 * the header's length field. It is rewritten twice: once to cover `MESSAGE-INTEGRITY` while the
 * HMAC is computed over everything before it, and again to cover `FINGERPRINT` while the CRC is
 * computed over everything before *that*. Getting either wrong produces a message the peer drops
 * without answering and without logging.
 */
internal object StunMessage {

    const val BINDING_REQUEST = 0x0001
    const val BINDING_SUCCESS = 0x0101
    const val BINDING_ERROR = 0x0111

    const val ATTR_USERNAME = 0x0006
    const val ATTR_MESSAGE_INTEGRITY = 0x0008
    const val ATTR_XOR_MAPPED_ADDRESS = 0x0020
    const val ATTR_PRIORITY = 0x0024
    const val ATTR_USE_CANDIDATE = 0x0025
    const val ATTR_FINGERPRINT = 0x8028
    const val ATTR_ICE_CONTROLLED = 0x8029
    const val ATTR_ICE_CONTROLLING = 0x802A

    const val MAGIC_COOKIE = 0x2112A442
    const val TRANSACTION_ID_SIZE = 12
    const val HEADER_SIZE = 20

    private const val FINGERPRINT_XOR = 0x5354554EL

    private val random = SecureRandom()

    fun newTransactionId(): ByteArray = ByteArray(TRANSACTION_ID_SIZE).also(random::nextBytes)

    /**
     * Whether a datagram is STUN rather than DTLS or RTP.
     *
     * RFC 7983 gives the whole demultiplexing rule for a WebRTC socket in terms of the first byte:
     * 0-3 is STUN, 20-63 is DTLS, 128-191 is RTP or RTCP. The ranges do not overlap, which is why
     * one socket can carry all three without any framing of its own.
     *
     * Note that the test is the byte's **value**, not its top two bits. STUN's leading two bits are
     * zero, but so are a DTLS record's -- a handshake record starts with 22 -- so a two-bit test
     * would route every DTLS record into the ICE layer and the handshake would never see one.
     */
    fun looksLikeStun(data: ByteArray, length: Int): Boolean =
        length >= HEADER_SIZE && (data[0].toInt() and 0xFF) <= 3

    /**
     * Builds a binding request with the ICE attributes, integrity and fingerprint.
     *
     * @param username `remote-ufrag:local-ufrag`, in that order. Reversing it is the other classic
     *   way to produce checks the peer silently ignores.
     * @param password the **peer's** ICE password, from its SDP. Integrity is always keyed with the
     *   credentials of whoever is meant to verify the message.
     * @param useCandidate nominates this path. This client is ICE-controlling and has one candidate
     *   pair to consider, so there is nothing to choose between and the first check can nominate.
     */
    fun bindingRequest(
        transactionId: ByteArray,
        username: String,
        password: String,
        priority: Long,
        tieBreaker: Long,
        useCandidate: Boolean,
    ): ByteArray {
        val attributes = ArrayList<ByteArray>()
        attributes += attribute(ATTR_USERNAME, username.toByteArray(Charsets.UTF_8))
        attributes += attribute(ATTR_PRIORITY, be32(priority))
        attributes += attribute(ATTR_ICE_CONTROLLING, be64(tieBreaker))
        if (useCandidate) attributes += attribute(ATTR_USE_CANDIDATE, ByteArray(0))

        return finish(BINDING_REQUEST, transactionId, attributes, password)
    }

    /** Builds the success response to a peer's check, keyed with **our** password. */
    fun bindingSuccess(
        transactionId: ByteArray,
        password: String,
        mappedAddress: ByteArray,
        mappedPort: Int,
    ): ByteArray {
        val attributes = listOf(attribute(ATTR_XOR_MAPPED_ADDRESS, xorMappedAddress(transactionId, mappedAddress, mappedPort)))
        return finish(BINDING_SUCCESS, transactionId, attributes, password)
    }

    /** Appends integrity and fingerprint, rewriting the length field for each. */
    private fun finish(
        type: Int,
        transactionId: ByteArray,
        attributes: List<ByteArray>,
        password: String,
    ): ByteArray {
        val body = attributes.fold(ByteArray(0)) { acc, attr -> acc + attr }

        // MESSAGE-INTEGRITY is computed over the message as if it already ended with the attribute,
        // so the declared length covers it while the bytes hashed stop short of it.
        val withIntegrityLength = header(type, transactionId, body.size + 24) + body
        val integrity = hmacSha1(password.toByteArray(Charsets.UTF_8), withIntegrityLength)
        val withIntegrity = withIntegrityLength + attribute(ATTR_MESSAGE_INTEGRITY, integrity)

        // FINGERPRINT works the same way one step further out, over the message including the
        // integrity attribute, with the length now also covering the fingerprint itself.
        val withFingerprintLength = withIntegrity.copyOf()
        writeLength(withFingerprintLength, body.size + 24 + 8)
        val crc = CRC32().apply { update(withFingerprintLength) }.value xor FINGERPRINT_XOR
        return withFingerprintLength + attribute(ATTR_FINGERPRINT, be32(crc))
    }

    /** A parsed message. Attributes are kept raw; only a few are ever looked at. */
    class Parsed(
        val type: Int,
        val transactionId: ByteArray,
        val attributes: Map<Int, ByteArray>,
        val raw: ByteArray,
    ) {
        val isRequest get() = type == BINDING_REQUEST
        val isSuccess get() = type == BINDING_SUCCESS
    }

    /** Parses a datagram, or returns null if it is not a well-formed STUN message. */
    fun parse(data: ByteArray, length: Int): Parsed? {
        if (length < HEADER_SIZE) return null
        val buffer = ByteBuffer.wrap(data, 0, length)
        val type = buffer.short.toInt() and 0xFFFF
        val bodyLength = buffer.short.toInt() and 0xFFFF
        if (buffer.int != MAGIC_COOKIE) return null
        if (HEADER_SIZE + bodyLength > length) return null

        val transactionId = ByteArray(TRANSACTION_ID_SIZE).also(buffer::get)

        val attributes = LinkedHashMap<Int, ByteArray>()
        var remaining = bodyLength
        while (remaining >= 4) {
            val attrType = buffer.short.toInt() and 0xFFFF
            val attrLength = buffer.short.toInt() and 0xFFFF
            if (attrLength > buffer.remaining()) return null
            val value = ByteArray(attrLength).also(buffer::get)
            attributes[attrType] = value
            // Attribute values are padded to a four-byte boundary; the padding is not in the length.
            val padding = (4 - (attrLength % 4)) % 4
            if (padding > buffer.remaining()) return null
            buffer.position(buffer.position() + padding)
            remaining -= 4 + attrLength + padding
        }

        return Parsed(type, transactionId, attributes, data.copyOf(length))
    }

    /**
     * Verifies a message's `MESSAGE-INTEGRITY` against [password].
     *
     * The HMAC has to be recomputed over the message truncated at the integrity attribute, with the
     * length field rewritten to what it was when the sender computed it -- which is the position of
     * the attribute, plus its own 24 bytes, minus the header.
     */
    fun verifyIntegrity(parsed: Parsed, password: String): Boolean {
        val integrity = parsed.attributes[ATTR_MESSAGE_INTEGRITY] ?: return false
        if (integrity.size != 20) return false

        val offset = indexOfAttribute(parsed.raw, ATTR_MESSAGE_INTEGRITY) ?: return false
        val truncated = parsed.raw.copyOf(offset)
        writeLength(truncated, offset + 24 - HEADER_SIZE)
        return hmacSha1(password.toByteArray(Charsets.UTF_8), truncated).contentEquals(integrity)
    }

    /** Walks the attribute list for [wanted], returning the offset of its header. */
    private fun indexOfAttribute(raw: ByteArray, wanted: Int): Int? {
        var offset = HEADER_SIZE
        while (offset + 4 <= raw.size) {
            val type = ((raw[offset].toInt() and 0xFF) shl 8) or (raw[offset + 1].toInt() and 0xFF)
            val length = ((raw[offset + 2].toInt() and 0xFF) shl 8) or (raw[offset + 3].toInt() and 0xFF)
            if (type == wanted) return offset
            offset += 4 + length + (4 - (length % 4)) % 4
        }
        return null
    }

    /**
     * `XOR-MAPPED-ADDRESS`: the reflexive address with the magic cookie mixed in.
     *
     * The obfuscation exists because some NATs rewrite anything that looks like an IP address in a
     * payload, which corrupted the plain `MAPPED-ADDRESS` this replaced.
     */
    private fun xorMappedAddress(transactionId: ByteArray, address: ByteArray, port: Int): ByteArray {
        require(address.size == 4) { "ipv4 only" }
        val value = ByteArray(8)
        value[0] = 0
        value[1] = 1 // IPv4
        value[2] = (((port ushr 8) xor ((MAGIC_COOKIE ushr 24) and 0xFF)) and 0xFF).toByte()
        value[3] = (((port and 0xFF) xor ((MAGIC_COOKIE ushr 16) and 0xFF)) and 0xFF).toByte()
        val cookie = be32(MAGIC_COOKIE.toLong() and 0xFFFFFFFFL)
        for (i in 0 until 4) value[4 + i] = (address[i].toInt() xor cookie[i].toInt()).toByte()
        return value
    }

    private fun header(type: Int, transactionId: ByteArray, bodyLength: Int): ByteArray {
        val out = ByteArray(HEADER_SIZE)
        out[0] = ((type ushr 8) and 0xFF).toByte()
        out[1] = (type and 0xFF).toByte()
        writeLength(out, bodyLength)
        val cookie = be32(MAGIC_COOKIE.toLong() and 0xFFFFFFFFL)
        System.arraycopy(cookie, 0, out, 4, 4)
        System.arraycopy(transactionId, 0, out, 8, TRANSACTION_ID_SIZE)
        return out
    }

    private fun writeLength(message: ByteArray, bodyLength: Int) {
        message[2] = ((bodyLength ushr 8) and 0xFF).toByte()
        message[3] = (bodyLength and 0xFF).toByte()
    }

    private fun attribute(type: Int, value: ByteArray): ByteArray {
        val padding = (4 - (value.size % 4)) % 4
        val out = ByteArray(4 + value.size + padding)
        out[0] = ((type ushr 8) and 0xFF).toByte()
        out[1] = (type and 0xFF).toByte()
        out[2] = ((value.size ushr 8) and 0xFF).toByte()
        out[3] = (value.size and 0xFF).toByte()
        System.arraycopy(value, 0, out, 4, value.size)
        return out
    }

    private fun hmacSha1(key: ByteArray, message: ByteArray): ByteArray =
        Mac.getInstance("HmacSHA1").run {
            init(SecretKeySpec(key, "HmacSHA1"))
            doFinal(message)
        }

    private fun be32(value: Long) = byteArrayOf(
        ((value ushr 24) and 0xFF).toByte(), ((value ushr 16) and 0xFF).toByte(),
        ((value ushr 8) and 0xFF).toByte(), (value and 0xFF).toByte(),
    )

    private fun be64(value: Long) = ByteArray(8) { ((value ushr (56 - it * 8)) and 0xFF).toByte() }
}
