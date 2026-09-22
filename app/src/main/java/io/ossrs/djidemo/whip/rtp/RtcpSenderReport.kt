package io.ossrs.djidemo.whip.rtp

import java.io.ByteArrayOutputStream

/**
 * The RTCP compound packet a sender is expected to emit periodically.
 *
 * Video plays without any of this, which makes it tempting to leave out, and leaving it out costs
 * something real: the sender report is the only place the RTP timestamp clock is tied to wall time,
 * so without it a receiver cannot relate this stream to any other, cannot compute round-trip time,
 * and has nothing to base a playout delay on. It is a few dozen bytes every five seconds.
 *
 * A compound packet is a sender report followed by a source description carrying the canonical
 * name, which is what RTCP requires of anything sent on an RTCP channel.
 */
internal object RtcpSenderReport {

    private const val VERSION_BYTE = 0x80
    private const val PT_SENDER_REPORT = 200
    private const val PT_SOURCE_DESCRIPTION = 202
    private const val SDES_CNAME = 1

    /**
     * Builds the compound packet.
     *
     * @param rtpTimestamp the RTP timestamp corresponding to [wallClockMs]. Pairing the two is the
     *   entire point of the report: one is the media clock, the other is real time.
     */
    fun build(ssrc: Long, cname: String, rtpTimestamp: Long, wallClockMs: Long, packets: Long, octets: Long): ByteArray {
        val out = ByteArrayOutputStream(128)
        out.write(senderReport(ssrc, rtpTimestamp, wallClockMs, packets, octets))
        out.write(sourceDescription(ssrc, cname))
        return out.toByteArray()
    }

    private fun senderReport(ssrc: Long, rtpTimestamp: Long, wallClockMs: Long, packets: Long, octets: Long): ByteArray {
        val out = ByteArrayOutputStream(32)
        out.write(VERSION_BYTE)         // version 2, no padding, zero reception report blocks
        out.write(PT_SENDER_REPORT)
        // Length is in 32-bit words, minus one, counting the header. Six words of body plus two of
        // header comes to seven.
        writeUInt16(out, 6)
        writeUInt32(out, ssrc)
        writeUInt64(out, ntpTimestamp(wallClockMs))
        writeUInt32(out, rtpTimestamp)
        writeUInt32(out, packets)
        writeUInt32(out, octets)
        return out.toByteArray()
    }

    private fun sourceDescription(ssrc: Long, cname: String): ByteArray {
        val name = cname.toByteArray(Charsets.UTF_8)
        val body = ByteArrayOutputStream(32)
        writeUInt32(body, ssrc)
        body.write(SDES_CNAME)
        body.write(name.size)
        body.write(name)
        // The item list is terminated by a zero byte, then padded to a four-byte boundary. The
        // padding is part of the packet rather than trailing junk, so it counts in the length.
        body.write(0)
        while (body.size() % 4 != 0) body.write(0)

        val out = ByteArrayOutputStream(body.size() + 4)
        out.write(VERSION_BYTE or 1)    // one chunk follows
        out.write(PT_SOURCE_DESCRIPTION)
        writeUInt16(out, body.size() / 4)
        out.write(body.toByteArray())
        return out.toByteArray()
    }

    /**
     * Wall time as a 64-bit NTP timestamp: seconds since 1900 above the point, fraction below.
     *
     * The 1900 epoch is 70 years and 17 leap days before the Unix one, which is where the constant
     * comes from.
     */
    private fun ntpTimestamp(wallClockMs: Long): Long {
        val seconds = wallClockMs / 1000 + NTP_UNIX_EPOCH_OFFSET
        val fraction = ((wallClockMs % 1000) * (1L shl 32)) / 1000
        return (seconds shl 32) or (fraction and 0xFFFFFFFFL)
    }

    private const val NTP_UNIX_EPOCH_OFFSET = 2_208_988_800L

    private fun writeUInt16(out: ByteArrayOutputStream, value: Int) {
        out.write((value ushr 8) and 0xFF)
        out.write(value and 0xFF)
    }

    private fun writeUInt32(out: ByteArrayOutputStream, value: Long) {
        for (i in 0 until 4) out.write(((value ushr (24 - i * 8)) and 0xFF).toInt())
    }

    private fun writeUInt64(out: ByteArrayOutputStream, value: Long) {
        for (i in 0 until 8) out.write(((value ushr (56 - i * 8)) and 0xFF).toInt())
    }
}
