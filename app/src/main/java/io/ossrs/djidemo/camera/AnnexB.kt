package io.ossrs.djidemo.camera

/**
 * Annex-B byte stream scanning, shared by everything that consumes the aircraft's elementary
 * stream.
 *
 * The aircraft hands this app H.264 as an Annex-B byte stream: NAL units separated by three- or
 * four-byte start codes. RTMP wants them length-prefixed and RTP wants them one per packet, so both
 * publishers begin by walking the buffer the same way. The rules are subtle enough -- start code
 * aliasing, encoder padding -- that two copies of the walk drifting apart would be a real hazard,
 * and RTMP and RTP disagreeing about where a NAL unit ends is very hard to see from the outside.
 */
object AnnexB {

    /** NAL unit types this app treats specially. Everything else is passed through untouched. */
    const val NON_IDR_SLICE = 1
    const val IDR_SLICE = 5
    const val SEI = 6
    const val SPS = 7
    const val PPS = 8
    const val ACCESS_UNIT_DELIMITER = 9

    /** The five-bit `nal_unit_type` of a NAL unit, given its first byte. */
    fun typeOf(header: Byte): Int = header.toInt() and 0x1F

    /** The two-bit `nal_ref_idc` of a NAL unit, given its first byte. */
    fun refIdcOf(header: Byte): Int = (header.toInt() shr 5) and 0x03

    /**
     * Calls [block] once per NAL unit in `data[offset until offset + length]`, giving the offset and
     * size of the unit itself with its start code already removed.
     *
     * Only the three-byte pattern `00 00 01` is searched for, which finds the four-byte form as
     * well: `00 00 00 01` contains `00 00 01` starting at its second byte, so the match lands in
     * the same place and the extra leading zero simply falls outside the unit that precedes it --
     * where it is removed again as trailing padding.
     *
     * Trailing zero bytes are trimmed from every unit. An encoder is free to pad between units, and
     * a length-prefixed or packetised framing would otherwise carry that padding as if it were
     * part of the slice.
     */
    inline fun forEachUnit(
        data: ByteArray,
        offset: Int,
        length: Int,
        block: (unitOffset: Int, unitLength: Int) -> Unit,
    ) {
        val end = offset + length
        var unitStart = -1
        var i = offset

        while (i + 2 < end) {
            if (data[i] == 0.toByte() && data[i + 1] == 0.toByte() && data[i + 2] == 1.toByte()) {
                if (unitStart >= 0) block(unitStart, withoutTrailingZeros(data, unitStart, i))
                i += 3
                unitStart = i
            } else {
                i++
            }
        }

        if (unitStart in offset until end) {
            block(unitStart, withoutTrailingZeros(data, unitStart, end))
        }
    }

    /** The length of `data[start until end]` once trailing zero bytes are discounted. */
    fun withoutTrailingZeros(data: ByteArray, start: Int, end: Int): Int {
        var last = end
        while (last > start && data[last - 1] == 0.toByte()) last--
        return last - start
    }

    /**
     * The NAL unit types present in one buffer, in order, capped at [limit].
     *
     * Used for the status readout, where it is the evidence that the tap is delivering a real
     * elementary stream rather than an opaque blob. The cap keeps a malformed buffer from turning
     * this into a long loop on the SDK's callback thread.
     */
    fun typesIn(data: ByteArray, offset: Int, length: Int, limit: Int = 6): List<Int> {
        val types = ArrayList<Int>(4)
        forEachUnit(data, offset, length) { unitOffset, unitLength ->
            if (types.size < limit && unitLength > 0) types += typeOf(data[unitOffset])
        }
        return types
    }

    /** A short name for a NAL type, falling back to the number when it is not one we expect. */
    fun name(type: Int): String = when (type) {
        NON_IDR_SLICE -> "slice"
        IDR_SLICE -> "IDR"
        SEI -> "SEI"
        SPS -> "SPS"
        PPS -> "PPS"
        ACCESS_UNIT_DELIMITER -> "AUD"
        else -> type.toString()
    }
}
