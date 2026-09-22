package io.ossrs.djidemo.whip.dtls

import java.io.ByteArrayOutputStream

/**
 * Just enough DER to write one X.509 certificate.
 *
 * DER is a tag-length-value encoding: every value is a type byte, a length, and the bytes. The only
 * part with any subtlety is the length, which is a single byte below 128 and otherwise a byte
 * saying how many length bytes follow. Everything here is a few lines on top of that.
 */
internal object Der {

    const val INTEGER = 0x02
    const val BIT_STRING = 0x03
    const val NULL = 0x05
    const val OBJECT_IDENTIFIER = 0x06
    const val UTF8_STRING = 0x0C
    const val SEQUENCE = 0x30
    const val SET = 0x31
    const val UTC_TIME = 0x17

    /** Wraps [content] in a tag-length-value. */
    fun encode(tag: Int, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(content.size + 8)
        out.write(tag)
        writeLength(out, content.size)
        out.write(content)
        return out.toByteArray()
    }

    fun sequence(vararg parts: ByteArray) = encode(SEQUENCE, concat(*parts))

    fun set(vararg parts: ByteArray) = encode(SET, concat(*parts))

    /** A context-specific constructed tag, as used for the certificate's explicit version field. */
    fun explicit(number: Int, content: ByteArray) = encode(0xA0 or number, content)

    /**
     * A non-negative integer.
     *
     * DER integers are signed two's complement, so a value whose top bit is set needs a leading
     * zero byte or it would read as negative. Serial numbers hit this about half the time.
     */
    fun integer(value: ByteArray): ByteArray {
        var start = 0
        while (start < value.size - 1 && value[start] == 0.toByte() && (value[start + 1].toInt() and 0x80) == 0) start++
        val trimmed = value.copyOfRange(start, value.size)
        val body = if (trimmed.isNotEmpty() && (trimmed[0].toInt() and 0x80) != 0) byteArrayOf(0) + trimmed else trimmed
        return encode(INTEGER, if (body.isEmpty()) byteArrayOf(0) else body)
    }

    fun integer(value: Int) = integer(
        byteArrayOf(
            (value ushr 24).toByte(), (value ushr 16).toByte(),
            (value ushr 8).toByte(), value.toByte(),
        ),
    )

    /** A bit string with no unused trailing bits, which is the only kind a certificate needs. */
    fun bitString(content: ByteArray) = encode(BIT_STRING, byteArrayOf(0) + content)

    fun utf8String(value: String) = encode(UTF8_STRING, value.toByteArray(Charsets.UTF_8))

    fun utcTime(value: String) = encode(UTC_TIME, value.toByteArray(Charsets.US_ASCII))

    fun nullValue() = encode(NULL, ByteArray(0))

    /**
     * An object identifier, from its dotted form.
     *
     * The first two arcs are packed into one byte as `40 * first + second`, and every arc after
     * that is base-128 with the top bit set on all but the final byte.
     */
    fun oid(dotted: String): ByteArray {
        val arcs = dotted.split('.').map { it.toLong() }
        require(arcs.size >= 2) { "oid needs at least two arcs" }
        val body = ByteArrayOutputStream(16)
        body.write((arcs[0] * 40 + arcs[1]).toInt())
        for (arc in arcs.drop(2)) {
            val chunks = ArrayList<Int>(5)
            var remaining = arc
            do {
                chunks.add(0, (remaining and 0x7F).toInt())
                remaining = remaining ushr 7
            } while (remaining > 0)
            for (i in chunks.indices) {
                body.write(if (i == chunks.size - 1) chunks[i] else chunks[i] or 0x80)
            }
        }
        return encode(OBJECT_IDENTIFIER, body.toByteArray())
    }

    private fun writeLength(out: ByteArrayOutputStream, length: Int) {
        if (length < 0x80) {
            out.write(length)
            return
        }
        val bytes = ArrayList<Int>(4)
        var remaining = length
        while (remaining > 0) {
            bytes.add(0, remaining and 0xFF)
            remaining = remaining ushr 8
        }
        out.write(0x80 or bytes.size)
        bytes.forEach(out::write)
    }

    private fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(parts.sumOf { it.size })
        parts.forEach(out::write)
        return out.toByteArray()
    }
}
