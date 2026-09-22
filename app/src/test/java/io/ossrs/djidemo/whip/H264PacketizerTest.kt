package io.ossrs.djidemo.whip

import io.ossrs.djidemo.whip.rtp.H264Packetizer
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class H264PacketizerTest {

    private val ssrc = 0x12345678L
    private val payloadType = 106

    private fun packetizer(maxPayload: Int = 1_160) = H264Packetizer(ssrc, payloadType, maxPayload)

    @Test
    fun `a small nal unit becomes one packet carrying it unchanged`() {
        val unit = byteArrayOf(0x65, 1, 2, 3, 4)
        val packets = packetizer().packetize(listOf(unit), rtpTimestamp = 9000)

        assertEquals(1, packets.size)
        val packet = packets.single()
        assertEquals(12 + unit.size, packet.size)
        assertArrayEquals(unit, packet.copyOfRange(12, packet.size))
        assertEquals(9000L, readUInt32(packet, 4))
        assertEquals(ssrc, readUInt32(packet, 8))
        assertEquals(payloadType, packet[1].toInt() and 0x7F)
        // The last packet of an access unit carries the marker bit.
        assertTrue(markerSet(packet))
    }

    @Test
    fun `a large nal unit is split into fragmentation units`() {
        val slice = ByteArray(300) { (it and 0xFF).toByte() }
        slice[0] = 0x65 // IDR slice, nal_ref_idc 3
        val packets = packetizer(maxPayload = 100).packetize(listOf(slice), rtpTimestamp = 0)

        assertTrue(packets.size > 1)

        packets.forEachIndexed { index, packet ->
            val indicator = packet[12].toInt() and 0xFF
            val header = packet[13].toInt() and 0xFF

            // The indicator keeps the original importance bits and declares type 28.
            assertEquals(H264Packetizer.FU_A_TYPE, indicator and 0x1F)
            assertEquals(0x60, indicator and 0xE0)
            // The fragmentation header carries the original type, here an IDR slice.
            assertEquals(5, header and 0x1F)

            assertEquals(index == 0, (header and 0x80) != 0)
            assertEquals(index == packets.lastIndex, (header and 0x40) != 0)
        }

        // Reassembling the fragments must give back the slice minus its single header byte, which
        // the fragmentation header replaces and which is not retransmitted.
        val reassembled = packets.fold(ByteArray(0)) { acc, packet -> acc + packet.copyOfRange(14, packet.size) }
        assertArrayEquals(slice.copyOfRange(1, slice.size), reassembled)
    }

    @Test
    fun `only the final packet of an access unit is marked`() {
        val units = listOf(
            byteArrayOf(0x67, 0x42, 0, 0x1F),  // sequence parameter set
            byteArrayOf(0x68, 0xCE.toByte()),  // picture parameter set
            byteArrayOf(0x65, 1, 2, 3),        // the slice
        )
        val packets = packetizer().packetize(units, rtpTimestamp = 3000)

        assertEquals(3, packets.size)
        assertFalse(markerSet(packets[0]))
        assertFalse(markerSet(packets[1]))
        assertTrue(markerSet(packets[2]))
    }

    @Test
    fun `parameter sets are sent in band rather than filtered out`() {
        val sps = byteArrayOf(0x67, 0x42, 0, 0x1F)
        val packets = packetizer().packetize(listOf(sps), rtpTimestamp = 0)
        assertArrayEquals(sps, packets.single().copyOfRange(12, packets.single().size))
    }

    @Test
    fun `every packet of one frame shares its timestamp and the sequence number advances`() {
        val slice = ByteArray(500) { 0x33 }
        slice[0] = 0x41
        val packets = packetizer(maxPayload = 100).packetize(listOf(slice), rtpTimestamp = 12345)

        assertTrue(packets.all { readUInt32(it, 4) == 12345L })

        val sequences = packets.map { ((it[2].toInt() and 0xFF) shl 8) or (it[3].toInt() and 0xFF) }
        sequences.zipWithNext { a, b -> assertEquals((a + 1) and 0xFFFF, b) }
    }

    @Test
    fun `counters track what a sender report has to declare`() {
        val packetizer = packetizer(maxPayload = 100)
        val slice = ByteArray(250) { 0x22 }
        slice[0] = 0x65

        val packets = packetizer.packetize(listOf(slice), rtpTimestamp = 0)

        assertEquals(packets.size.toLong(), packetizer.packetCount)
        assertEquals(packets.sumOf { (it.size - 12).toLong() }, packetizer.octetCount)
    }

    private fun markerSet(packet: ByteArray) = (packet[1].toInt() and 0x80) != 0

    private fun readUInt32(data: ByteArray, offset: Int): Long =
        ((data[offset].toLong() and 0xFF) shl 24) or ((data[offset + 1].toLong() and 0xFF) shl 16) or
            ((data[offset + 2].toLong() and 0xFF) shl 8) or (data[offset + 3].toLong() and 0xFF)
}
