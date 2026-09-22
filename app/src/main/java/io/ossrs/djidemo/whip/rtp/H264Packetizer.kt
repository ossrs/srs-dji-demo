package io.ossrs.djidemo.whip.rtp

import io.ossrs.djidemo.camera.AnnexB

/**
 * Cuts H.264 NAL units into RTP packets, following RFC 6184.
 *
 * The problem is a mismatch of sizes. A keyframe off the aircraft can be a hundred kilobytes, while
 * a UDP datagram that will cross a network without being fragmented by IP is about 1,200 bytes. RTP
 * solves this with two packet shapes and this packetiser emits both:
 *
 * - a **single NAL unit packet**, where the payload is the NAL unit as-is, used whenever it fits;
 * - a **fragmentation unit**, where one NAL unit is spread over as many packets as it needs, each
 *   carrying a two-byte header that says which part this is.
 *
 * Mode 1 -- what `packetization-mode=1` in the SDP offers -- permits both. There is a third shape,
 * the aggregation packet, which bundles several small NAL units into one; it is not implemented
 * because at 1080p the only small units are the parameter sets, and saving two packets per keyframe
 * is not worth the code.
 */
internal class H264Packetizer(
    private val ssrc: Long,
    private val payloadType: Int,
    private val maxPayloadSize: Int = DEFAULT_MAX_PAYLOAD,
) {

    private var sequenceNumber = (Math.random() * 0xFFFF).toInt()

    /** Packets sent and payload bytes sent, which the sender report has to declare. */
    var packetCount = 0L
        private set
    var octetCount = 0L
        private set

    /**
     * Packetises one access unit.
     *
     * [units] are the NAL units of a single frame, start codes already removed. They are sent in
     * the order given, and the marker bit is set on the very last packet -- which is how a receiver
     * knows the frame is complete without waiting for the next one's timestamp to change.
     *
     * Parameter sets are **not** filtered out here, unlike the RTMP path. RTP has no configuration
     * record: a receiver gets the sequence and picture parameter sets in band, as their own packets
     * before each keyframe, exactly as they arrive from the aircraft.
     */
    fun packetize(units: List<ByteArray>, rtpTimestamp: Long): List<ByteArray> {
        val packets = ArrayList<ByteArray>(units.size + 4)

        for ((unitIndex, unit) in units.withIndex()) {
            if (unit.isEmpty()) continue
            val lastUnit = unitIndex == units.lastIndex

            if (unit.size <= maxPayloadSize) {
                packets += packet(unit, rtpTimestamp, marker = lastUnit)
                continue
            }

            // A fragmentation unit replaces the NAL unit's single header byte with two: the first
            // keeps the original's importance bits but declares type 28, and the second carries the
            // original type plus start and end flags.
            val header = unit[0]
            val indicator = ((AnnexB.refIdcOf(header) shl 5) or FU_A_TYPE).toByte()
            val originalType = AnnexB.typeOf(header)

            // One byte of each fragment's payload budget goes to the fragmentation header.
            val fragmentSize = maxPayloadSize - 2
            var offset = 1 // the original header byte is not resent
            while (offset < unit.size) {
                val size = minOf(fragmentSize, unit.size - offset)
                val first = offset == 1
                val last = offset + size >= unit.size

                val payload = ByteArray(2 + size)
                payload[0] = indicator
                payload[1] = (((if (first) 0x80 else 0) or (if (last) 0x40 else 0)) or originalType).toByte()
                System.arraycopy(unit, offset, payload, 2, size)

                packets += packet(payload, rtpTimestamp, marker = lastUnit && last)
                offset += size
            }
        }
        return packets
    }

    /**
     * Wraps one payload in an RTP header.
     *
     * The header is deliberately the minimum: no padding, no extension, no contributing sources.
     * The three fields that carry meaning are the sequence number, which lets a receiver detect
     * loss and reordering; the timestamp, which is the frame's presentation time in the 90 kHz
     * clock the SDP agreed and is **the same for every packet of one frame**; and the marker bit.
     */
    private fun packet(payload: ByteArray, rtpTimestamp: Long, marker: Boolean): ByteArray {
        val out = ByteArray(RTP_HEADER_SIZE + payload.size)
        out[0] = 0x80.toByte() // version 2, no padding, no extension, no CSRCs
        out[1] = ((if (marker) 0x80 else 0) or payloadType).toByte()

        val sequence = sequenceNumber and 0xFFFF
        sequenceNumber = (sequenceNumber + 1) and 0xFFFF
        out[2] = ((sequence ushr 8) and 0xFF).toByte()
        out[3] = (sequence and 0xFF).toByte()

        writeUInt32(out, 4, rtpTimestamp)
        writeUInt32(out, 8, ssrc)
        System.arraycopy(payload, 0, out, RTP_HEADER_SIZE, payload.size)

        packetCount++
        octetCount += payload.size
        return out
    }

    companion object {

        const val RTP_HEADER_SIZE = 12

        /** RFC 6184's fragmentation unit A. There is a type 29 as well, which mode 1 forbids. */
        const val FU_A_TYPE = 28

        /**
         * Chosen to keep the whole IP datagram under a 1,500-byte path MTU with room to spare for
         * the RTP header, SRTP's authentication tag, UDP and IP. Going over it does not fail
         * outright -- IP fragments instead -- but a single lost fragment then costs the whole
         * packet, which turns a 1% loss rate into something much worse.
         */
        const val DEFAULT_MAX_PAYLOAD = 1_160

        private fun writeUInt32(out: ByteArray, offset: Int, value: Long) {
            for (i in 0 until 4) out[offset + i] = ((value ushr (24 - i * 8)) and 0xFF).toByte()
        }
    }
}
