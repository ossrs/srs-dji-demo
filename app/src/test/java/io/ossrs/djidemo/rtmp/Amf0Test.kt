package io.ossrs.djidemo.rtmp

import org.junit.Assert.assertEquals
import org.junit.Test

class Amf0Test {

    @Test
    fun `a connect command round trips through the reader`() {
        val encoded = Amf0Writer()
            .string("connect")
            .number(1.0)
            .obj {
                put("app", "live")
                put("tcUrl", "rtmp://host/live")
                put("fpad", false)
                put("videoCodecs", 128)
            }
            .toByteArray()

        val reader = Amf0Reader(encoded)
        assertEquals("connect", reader.readValue())
        assertEquals(1.0, reader.readValue())

        @Suppress("UNCHECKED_CAST")
        val command = reader.readValue() as Map<String, Any?>
        assertEquals("live", command["app"])
        assertEquals("rtmp://host/live", command["tcUrl"])
        assertEquals(false, command["fpad"])
        assertEquals(128.0, command["videoCodecs"])
    }

    @Test
    fun `an ecma array declares its property count and still terminates`() {
        val encoded = Amf0Writer()
            .string("onMetaData")
            .ecmaArray {
                put("width", 1920)
                put("height", 1080)
                put("videocodecid", 7)
            }
            .toByteArray()

        val reader = Amf0Reader(encoded)
        assertEquals("onMetaData", reader.readValue())

        // "onMetaData" occupies thirteen bytes, then the ECMA array marker, then the count: three
        // properties, declared before the body so a reader knows what is coming.
        assertEquals(3, readInt(encoded, 14))

        @Suppress("UNCHECKED_CAST")
        val metadata = reader.readValue() as Map<String, Any?>
        assertEquals(1920.0, metadata["width"])
        assertEquals(1080.0, metadata["height"])
        assertEquals(7.0, metadata["videocodecid"])
    }

    @Test
    fun `null reads back as null and does not desynchronise what follows`() {
        val encoded = Amf0Writer()
            .string("createStream")
            .number(2.0)
            .nullValue()
            .toByteArray()

        val reader = Amf0Reader(encoded)
        assertEquals("createStream", reader.readValue())
        assertEquals(2.0, reader.readValue())
        assertEquals(null, reader.readValue())
        assertEquals(false, reader.hasMore)
    }

    @Test
    fun `a server result carrying a stream id is decoded the way the client reads it`() {
        // Shaped like SRS's reply to createStream: name, transaction, null, stream id.
        val encoded = Amf0Writer()
            .string("_result")
            .number(2.0)
            .nullValue()
            .number(1.0)
            .toByteArray()

        val reader = Amf0Reader(encoded)
        assertEquals("_result", reader.readValue())
        assertEquals(2.0, reader.readValue())
        reader.readValue()
        assertEquals(1.0, reader.readValue())
    }

    private fun readInt(data: ByteArray, offset: Int) =
        ((data[offset].toInt() and 0xFF) shl 24) or ((data[offset + 1].toInt() and 0xFF) shl 16) or
            ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)
}
