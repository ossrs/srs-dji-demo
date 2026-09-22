package io.ossrs.djidemo.camera

import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * The NAL walk both publishers depend on.
 *
 * Worth testing on its own because a mistake here is almost invisible downstream: RTMP and RTP
 * would both still produce plausible packets, just with a byte too many or too few in each NAL
 * unit, and the only symptom would be a decoder that refuses the stream for no stated reason.
 */
class AnnexBTest {

    private fun units(data: ByteArray): List<List<Int>> {
        val found = ArrayList<List<Int>>()
        AnnexB.forEachUnit(data, 0, data.size) { offset, length ->
            found += data.copyOfRange(offset, offset + length).map { it.toInt() and 0xFF }
        }
        return found
    }

    @Test
    fun `splits on three byte start codes`() {
        val data = byteArrayOf(0, 0, 1, 0x67, 0x11, 0, 0, 1, 0x68, 0x22)
        assertEquals(listOf(listOf(0x67, 0x11), listOf(0x68, 0x22)), units(data))
    }

    @Test
    fun `four byte start codes leave no leading zero on the unit`() {
        val data = byteArrayOf(0, 0, 0, 1, 0x67, 0x11, 0, 0, 0, 1, 0x65, 0x22)
        assertEquals(listOf(listOf(0x67, 0x11), listOf(0x65, 0x22)), units(data))
    }

    @Test
    fun `trailing encoder padding is not carried into a unit`() {
        val data = byteArrayOf(0, 0, 1, 0x65, 0x33, 0, 0, 0)
        assertEquals(listOf(listOf(0x65, 0x33)), units(data))
    }

    @Test
    fun `a unit may contain a zero byte that is not a start code`() {
        val data = byteArrayOf(0, 0, 1, 0x65, 0x00, 0x44)
        assertEquals(listOf(listOf(0x65, 0x00, 0x44)), units(data))
    }

    @Test
    fun `reads the nal type and reference importance out of the header byte`() {
        // 0x67: nal_ref_idc 3, type 7, which is how a sequence parameter set arrives.
        assertEquals(AnnexB.SPS, AnnexB.typeOf(0x67.toByte()))
        assertEquals(3, AnnexB.refIdcOf(0x67.toByte()))
        assertEquals(AnnexB.IDR_SLICE, AnnexB.typeOf(0x65.toByte()))
        assertEquals(AnnexB.NON_IDR_SLICE, AnnexB.typeOf(0x41.toByte()))
    }

    @Test
    fun `lists the types of a typical keyframe buffer`() {
        val keyframe = byteArrayOf(
            0, 0, 0, 1, 0x09, 0x10,       // access unit delimiter
            0, 0, 0, 1, 0x67, 0x42, 0, 0, // sequence parameter set
            0, 0, 0, 1, 0x68, 0xCE.toByte(),
            0, 0, 0, 1, 0x65, 0x88.toByte(),
        )
        assertEquals(
            listOf(AnnexB.ACCESS_UNIT_DELIMITER, AnnexB.SPS, AnnexB.PPS, AnnexB.IDR_SLICE),
            AnnexB.typesIn(keyframe, 0, keyframe.size),
        )
    }
}
