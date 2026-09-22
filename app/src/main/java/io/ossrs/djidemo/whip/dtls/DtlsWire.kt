package io.ossrs.djidemo.whip.dtls

import java.io.ByteArrayOutputStream

/** DTLS record content types. */
internal object ContentType {
    const val CHANGE_CIPHER_SPEC = 20
    const val ALERT = 21
    const val HANDSHAKE = 22
    const val APPLICATION_DATA = 23
}

/** Handshake message types, in the order a full handshake uses them. */
internal object HandshakeType {
    const val CLIENT_HELLO = 1
    const val SERVER_HELLO = 2
    const val HELLO_VERIFY_REQUEST = 3
    const val CERTIFICATE = 11
    const val SERVER_KEY_EXCHANGE = 12
    const val CERTIFICATE_REQUEST = 13
    const val SERVER_HELLO_DONE = 14
    const val CERTIFICATE_VERIFY = 15
    const val CLIENT_KEY_EXCHANGE = 16
    const val FINISHED = 20
}

/**
 * DTLS 1.2 on the wire is `{254, 253}` -- the ones-complement of 1.2, chosen so that DTLS versions
 * sort the opposite way round to TLS ones and the two can never be confused by a naive parser.
 */
internal const val DTLS_1_2 = 0xFEFD

/** DTLS 1.0, which is the version a ClientHello's record layer still carries for compatibility. */
internal const val DTLS_1_0 = 0xFEFF

internal const val RECORD_HEADER_SIZE = 13
internal const val HANDSHAKE_HEADER_SIZE = 12

/** One DTLS record, as read off the wire. */
internal class DtlsRecord(
    val contentType: Int,
    val version: Int,
    val epoch: Int,
    val sequence: Long,
    val body: ByteArray,
)

/**
 * One complete handshake message.
 *
 * DTLS adds three fields TLS does not have -- a message sequence number and a fragment offset and
 * length -- because a handshake message can be larger than a datagram and datagrams can be lost or
 * reordered. [encodedForTranscript] deliberately writes the message back as if it had never been
 * fragmented, because that is the form both sides must hash: two peers that fragmented differently
 * would otherwise compute different Finished values from the same conversation.
 */
internal class HandshakeMessage(val type: Int, val messageSeq: Int, val body: ByteArray) {

    fun encodedForTranscript(): ByteArray {
        val out = ByteArrayOutputStream(HANDSHAKE_HEADER_SIZE + body.size)
        out.write(type)
        writeUInt24(out, body.size)
        out.write((messageSeq ushr 8) and 0xFF)
        out.write(messageSeq and 0xFF)
        writeUInt24(out, 0)           // fragment offset
        writeUInt24(out, body.size)   // fragment length equals the whole message
        out.write(body)
        return out.toByteArray()
    }
}

/** A growable big-endian writer, which is most of what building TLS structures consists of. */
internal class TlsWriter(capacity: Int = 256) {

    private val out = ByteArrayOutputStream(capacity)

    val size: Int get() = out.size()

    fun u8(value: Int) = apply { out.write(value and 0xFF) }

    fun u16(value: Int) = apply {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    fun u24(value: Int) = apply { writeUInt24(out, value) }

    fun bytes(value: ByteArray) = apply { out.write(value) }

    /** A vector with an 8-bit length prefix, which TLS uses for anything small. */
    fun vector8(value: ByteArray) = apply {
        u8(value.size)
        bytes(value)
    }

    /** A vector with a 16-bit length prefix. */
    fun vector16(value: ByteArray) = apply {
        u16(value.size)
        bytes(value)
    }

    /** A vector with a 24-bit length prefix, which only certificate structures need. */
    fun vector24(value: ByteArray) = apply {
        u24(value.size)
        bytes(value)
    }

    fun toByteArray(): ByteArray = out.toByteArray()
}

/** A bounds-checked big-endian reader. Every read that would run off the end throws. */
internal class TlsReader(private val data: ByteArray, private var pos: Int = 0, private val end: Int = data.size) {

    val remaining: Int get() = end - pos

    fun u8(): Int = require(1).let { data[pos++].toInt() and 0xFF }

    fun u16(): Int = (u8() shl 8) or u8()

    fun u24(): Int = (u8() shl 16) or (u8() shl 8) or u8()

    fun bytes(count: Int): ByteArray {
        require(count)
        return data.copyOfRange(pos, pos + count).also { pos += count }
    }

    fun vector8(): ByteArray = bytes(u8())

    fun vector16(): ByteArray = bytes(u16())

    fun vector24(): ByteArray = bytes(u24())

    fun skip(count: Int) = require(count).also { pos += count }

    private fun require(count: Int) {
        if (count < 0 || pos + count > end) throw IllegalStateException("dtls message truncated")
    }
}

private fun writeUInt24(out: ByteArrayOutputStream, value: Int) {
    out.write((value ushr 16) and 0xFF)
    out.write((value ushr 8) and 0xFF)
    out.write(value and 0xFF)
}
