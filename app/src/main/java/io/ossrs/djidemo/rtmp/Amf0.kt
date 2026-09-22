package io.ossrs.djidemo.rtmp

import java.io.ByteArrayOutputStream

/**
 * The slice of AMF0 that RTMP command messages actually use.
 *
 * AMF0 is Adobe's serialisation format, and RTMP carries its commands -- `connect`, `createStream`,
 * `publish` and the `_result` / `onStatus` replies -- as a flat sequence of AMF0 values. Only a
 * handful of its types ever appear there, so this encodes and decodes those and no more: numbers
 * are IEEE-754 doubles, strings are UTF-8 with a 16-bit length, and objects are key-value pairs
 * terminated by the three-byte end marker.
 *
 * Everything unsupported is skipped on read rather than treated as an error, because a server is
 * free to put extra properties in its replies and this client only ever looks for three or four of
 * them.
 */
internal object Amf0 {

    const val NUMBER = 0x00
    const val BOOLEAN = 0x01
    const val STRING = 0x02
    const val OBJECT = 0x03
    const val NULL = 0x05
    const val UNDEFINED = 0x06
    const val ECMA_ARRAY = 0x08
    const val OBJECT_END = 0x09
    const val STRICT_ARRAY = 0x0A
    const val DATE = 0x0B
    const val LONG_STRING = 0x0C
}

/** Builds the AMF0 body of one command message. */
internal class Amf0Writer {

    private val out = ByteArrayOutputStream(256)

    fun number(value: Double) = apply {
        out.write(Amf0.NUMBER)
        writeDouble(out, value)
    }

    fun string(value: String) = apply {
        out.write(Amf0.STRING)
        writeShortString(out, value)
    }

    fun nullValue() = apply { out.write(Amf0.NULL) }

    /**
     * Writes an anonymous object. Property order is preserved, which matters only in that it makes
     * a packet capture easy to compare against what ffmpeg or OBS sends.
     */
    fun obj(build: Amf0Properties.() -> Unit) = apply {
        val properties = Amf0Properties().apply(build)
        out.write(Amf0.OBJECT)
        properties.writeBodyTo(out)
        writeObjectEnd(out)
    }

    /**
     * Writes an ECMA array: an object with a leading property count. `onMetaData` is conventionally
     * sent this way. The count is advisory -- the end marker is what actually terminates it -- but
     * some servers log a warning when it disagrees, so it is filled in correctly.
     */
    fun ecmaArray(build: Amf0Properties.() -> Unit) = apply {
        val properties = Amf0Properties().apply(build)
        out.write(Amf0.ECMA_ARRAY)
        writeInt(out, properties.count)
        properties.writeBodyTo(out)
        writeObjectEnd(out)
    }

    fun toByteArray(): ByteArray = out.toByteArray()
}

/**
 * The properties of one AMF0 object, collected before they are written.
 *
 * Buffered rather than streamed straight out because an ECMA array has to declare how many
 * properties follow before the first one, and counting them twice is worse than holding a few
 * hundred bytes.
 */
internal class Amf0Properties {

    private val body = ByteArrayOutputStream(128)

    var count = 0
        private set

    fun put(name: String, value: String) = property(name) {
        body.write(Amf0.STRING)
        writeShortString(body, value)
    }

    fun put(name: String, value: Double) = property(name) {
        body.write(Amf0.NUMBER)
        writeDouble(body, value)
    }

    fun put(name: String, value: Int) = put(name, value.toDouble())

    fun put(name: String, value: Boolean) = property(name) {
        body.write(Amf0.BOOLEAN)
        body.write(if (value) 1 else 0)
    }

    internal fun writeBodyTo(sink: ByteArrayOutputStream) = body.writeTo(sink)

    private fun property(name: String, writeValue: () -> Unit) {
        count++
        writeShortString(body, name)
        writeValue()
    }
}

/** A property name, or a string value: UTF-8 behind a 16-bit length. */
private fun writeShortString(sink: ByteArrayOutputStream, value: String) {
    val bytes = value.toByteArray(Charsets.UTF_8)
    require(bytes.size <= 0xFFFF) { "amf0 string too long" }
    sink.write(bytes.size ushr 8)
    sink.write(bytes.size and 0xFF)
    sink.write(bytes)
}

/** AMF0 numbers are all IEEE-754 doubles, big-endian. There is no integer type. */
private fun writeDouble(sink: ByteArrayOutputStream, value: Double) {
    val bits = java.lang.Double.doubleToLongBits(value)
    for (shift in 56 downTo 0 step 8) sink.write(((bits ushr shift) and 0xFF).toInt())
}

private fun writeInt(sink: ByteArrayOutputStream, value: Int) {
    sink.write(value ushr 24)
    sink.write((value ushr 16) and 0xFF)
    sink.write((value ushr 8) and 0xFF)
    sink.write(value and 0xFF)
}

/** An empty property name followed by the end marker closes an object or an ECMA array. */
private fun writeObjectEnd(sink: ByteArrayOutputStream) {
    sink.write(0)
    sink.write(0)
    sink.write(Amf0.OBJECT_END)
}

/**
 * Reads AMF0 values out of a command message body.
 *
 * Deliberately lenient. This client needs three facts from the server -- which transaction a
 * `_result` answers, the stream id inside it, and the `code` property of an `onStatus` -- so
 * anything else is decoded far enough to be stepped over and then discarded.
 */
internal class Amf0Reader(private val data: ByteArray, private var pos: Int = 0) {

    val hasMore: Boolean get() = pos < data.size

    /**
     * Reads the next value as one of: [Double], [Boolean], [String], `Map<String, Any?>`,
     * `List<Any?>`, or null. Unknown markers throw, because silently returning null for them would
     * desynchronise every value after this one.
     */
    fun readValue(): Any? = when (val marker = readByte()) {
        Amf0.NUMBER -> java.lang.Double.longBitsToDouble(readLong())
        Amf0.BOOLEAN -> readByte() != 0
        Amf0.STRING -> readString(readUShort())
        Amf0.LONG_STRING -> readString(readInt())
        Amf0.OBJECT -> readProperties()
        Amf0.ECMA_ARRAY -> { readInt(); readProperties() }
        Amf0.STRICT_ARRAY -> (0 until readInt()).map { readValue() }
        Amf0.DATE -> java.lang.Double.longBitsToDouble(readLong()).also { readUShort() }
        Amf0.NULL, Amf0.UNDEFINED -> null
        else -> throw IllegalStateException("unsupported amf0 marker $marker")
    }

    private fun readProperties(): Map<String, Any?> {
        val properties = LinkedHashMap<String, Any?>()
        while (true) {
            val name = readString(readUShort())
            if (name.isEmpty() && peekByte() == Amf0.OBJECT_END) {
                pos++
                return properties
            }
            properties[name] = readValue()
        }
    }

    private fun peekByte(): Int = data[pos].toInt() and 0xFF

    private fun readByte(): Int {
        require(pos < data.size) { "amf0 truncated" }
        return data[pos++].toInt() and 0xFF
    }

    private fun readUShort(): Int = (readByte() shl 8) or readByte()

    private fun readInt(): Int =
        (readByte() shl 24) or (readByte() shl 16) or (readByte() shl 8) or readByte()

    private fun readLong(): Long {
        var value = 0L
        repeat(8) { value = (value shl 8) or readByte().toLong() }
        return value
    }

    private fun readString(length: Int): String {
        require(pos + length <= data.size) { "amf0 truncated" }
        val value = String(data, pos, length, Charsets.UTF_8)
        pos += length
        return value
    }
}
