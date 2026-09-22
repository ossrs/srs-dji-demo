package io.ossrs.djidemo.rtmp

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class FlvVideoTest {

    /** A minimal but realistically shaped sequence parameter set: profile 0x42, level 0x1F. */
    private val sps = byteArrayOf(0x67, 0x42, 0x00, 0x1F, 0x11, 0x22)
    private val pps = byteArrayOf(0x68, 0xCE.toByte(), 0x33)

    @Test
    fun `the sequence header copies profile and level out of the sps`() {
        val body = FlvVideo.sequenceHeader(sps, pps)

        assertEquals(0x17, body[0].toInt() and 0xFF) // keyframe, codec AVC
        assertEquals(0x00, body[1].toInt())          // AVC sequence header
        assertEquals(0, body[2].toInt() + body[3].toInt() + body[4].toInt()) // composition time

        assertEquals(1, body[5].toInt())                  // configurationVersion
        assertEquals(0x42, body[6].toInt() and 0xFF)      // AVCProfileIndication, from sps[1]
        assertEquals(0x00, body[7].toInt() and 0xFF)      // profile_compatibility, from sps[2]
        assertEquals(0x1F, body[8].toInt() and 0xFF)      // AVCLevelIndication, from sps[3]
        assertEquals(0xFF, body[9].toInt() and 0xFF)      // four-byte NAL length prefixes
        assertEquals(0xE1, body[10].toInt() and 0xFF)     // exactly one sps
        assertEquals(sps.size, ((body[11].toInt() and 0xFF) shl 8) or (body[12].toInt() and 0xFF))
        assertArrayEquals(sps, body.copyOfRange(13, 13 + sps.size))

        val ppsAt = 13 + sps.size
        assertEquals(1, body[ppsAt].toInt())              // exactly one pps
        assertEquals(pps.size, ((body[ppsAt + 1].toInt() and 0xFF) shl 8) or (body[ppsAt + 2].toInt() and 0xFF))
        assertArrayEquals(pps, body.copyOfRange(ppsAt + 3, ppsAt + 3 + pps.size))
    }

    @Test
    fun `nalu bodies are length prefixed and keep the slice bytes untouched`() {
        val first = byteArrayOf(0x65, 1, 2, 3)
        val second = byteArrayOf(0x41, 4, 5)
        val body = FlvVideo.naluBody(listOf(first, second), keyFrame = true)

        assertEquals(0x17, body[0].toInt() and 0xFF)
        assertEquals(0x01, body[1].toInt())  // NALU rather than sequence header
        assertEquals(5 + 4 + first.size + 4 + second.size, body.size)

        assertEquals(first.size, readInt(body, 5))
        assertArrayEquals(first, body.copyOfRange(9, 9 + first.size))
        val secondAt = 9 + first.size
        assertEquals(second.size, readInt(body, secondAt))
        assertArrayEquals(second, body.copyOfRange(secondAt + 4, secondAt + 4 + second.size))
    }

    @Test
    fun `a non keyframe is marked as an inter frame`() {
        val body = FlvVideo.naluBody(listOf(byteArrayOf(0x41, 9)), keyFrame = false)
        assertEquals(0x27, body[0].toInt() and 0xFF)
    }

    private fun readInt(data: ByteArray, offset: Int) =
        ((data[offset].toInt() and 0xFF) shl 24) or ((data[offset + 1].toInt() and 0xFF) shl 16) or
            ((data[offset + 2].toInt() and 0xFF) shl 8) or (data[offset + 3].toInt() and 0xFF)
}
