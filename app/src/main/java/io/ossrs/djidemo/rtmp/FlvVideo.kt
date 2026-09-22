package io.ossrs.djidemo.rtmp

import java.io.ByteArrayOutputStream

/**
 * FLV video tag bodies for H.264.
 *
 * This is the whole of the remux. The aircraft gives this app an Annex-B byte stream -- NAL units
 * separated by start codes -- and RTMP carries video as FLV tag bodies, in which NAL units are
 * length-prefixed and the parameter sets are hoisted out into a one-off configuration record. No
 * decoding and no re-encoding happens anywhere: the slice bytes that arrive are the slice bytes
 * that go out, and only the framing around them changes.
 *
 * Every body starts with the same two bytes: frame type and codec in the first, AVC packet type in
 * the second, followed by a 24-bit composition time offset.
 */
internal object FlvVideo {

    private const val FRAME_TYPE_KEY = 1
    private const val FRAME_TYPE_INTER = 2
    private const val CODEC_AVC = 7

    private const val PACKET_TYPE_SEQUENCE_HEADER = 0
    private const val PACKET_TYPE_NALU = 1

    /**
     * The AVC decoder configuration record, wrapped as a sequence header tag body.
     *
     * A decoder cannot make sense of a single slice without the sequence and picture parameter
     * sets, and in Annex-B they arrive inline before each keyframe. FLV instead expects them once,
     * up front, in this record -- so this is sent before the first frame and again whenever the
     * parameter sets change, and a player that joins later gets it from the server's cache.
     *
     * The profile, compatibility and level bytes are not chosen here: they are copied straight out
     * of the SPS, where they are the three bytes following its NAL header.
     */
    fun sequenceHeader(sps: ByteArray, pps: ByteArray): ByteArray {
        require(sps.size >= 4) { "sps too short" }
        val out = ByteArrayOutputStream(sps.size + pps.size + 16)

        out.write((FRAME_TYPE_KEY shl 4) or CODEC_AVC)
        out.write(PACKET_TYPE_SEQUENCE_HEADER)
        writeUInt24(out, 0) // composition time is meaningless for a sequence header

        out.write(1)               // configurationVersion
        out.write(sps[1].toInt())  // AVCProfileIndication
        out.write(sps[2].toInt())  // profile_compatibility
        out.write(sps[3].toInt())  // AVCLevelIndication
        // Six reserved bits set, then lengthSizeMinusOne = 3, i.e. four-byte NAL length prefixes.
        out.write(0xFF)
        // Three reserved bits set, then a five-bit count of sequence parameter sets.
        out.write(0xE1)
        writeUInt16(out, sps.size)
        out.write(sps)
        out.write(1) // one picture parameter set
        writeUInt16(out, pps.size)
        out.write(pps)

        return out.toByteArray()
    }

    /**
     * One access unit's slices, length-prefixed, as a NALU tag body.
     *
     * [units] are the NAL units to carry, already stripped of their start codes. Parameter sets and
     * access unit delimiters are expected to have been filtered out by the caller: the former live
     * in the configuration record, and the latter carry no information a player needs.
     *
     * The composition time offset is always zero. It is the gap between decode and presentation
     * order, which only exists when the encoder emits B-frames; this stream has none, and writing a
     * non-zero value that nothing measured would be worse than writing the truth.
     */
    fun naluBody(units: List<ByteArray>, keyFrame: Boolean): ByteArray {
        val payloadSize = units.sumOf { it.size + 4 }
        val out = ByteArrayOutputStream(payloadSize + 5)

        out.write(((if (keyFrame) FRAME_TYPE_KEY else FRAME_TYPE_INTER) shl 4) or CODEC_AVC)
        out.write(PACKET_TYPE_NALU)
        writeUInt24(out, 0)

        for (unit in units) {
            writeUInt32(out, unit.size)
            out.write(unit)
        }
        return out.toByteArray()
    }

    private fun writeUInt16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeUInt24(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeUInt32(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 24) and 0xFF)
        out.write((value ushr 16) and 0xFF)
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }
}
