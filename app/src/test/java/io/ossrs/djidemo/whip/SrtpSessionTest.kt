package io.ossrs.djidemo.whip

import io.ossrs.djidemo.whip.srtp.SrtpSession
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

/**
 * The key derivation is checked against the published vectors in RFC 3711 appendix B.3.
 *
 * This is the one part of the media path with a known right answer that can be checked without a
 * server, and it is worth checking: everything downstream is encrypted with these keys, so if they
 * are wrong the only symptom is a receiver that silently discards every packet. Getting agreement
 * with the specification's own numbers is much stronger evidence than any round trip against this
 * same code would be.
 */
class SrtpSessionTest {

    private val masterKey = hex("E1F97A0D3E018BE0D64FA32C06DE4139")
    private val masterSalt = hex("0EC675AD498AFEEBB6960B3AABE6")

    @Test
    fun `derives the session encryption key from RFC 3711 B_3`() {
        val key = SrtpSession.deriveKey(masterKey, masterSalt, label = 0x00, length = 16)
        assertEquals("C61E7A93744F39EE10734AFE3FF7A087", hexOf(key))
    }

    @Test
    fun `derives the session authentication key from RFC 3711 B_3`() {
        val key = SrtpSession.deriveKey(masterKey, masterSalt, label = 0x01, length = 20)
        assertEquals("CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4", hexOf(key))
    }

    @Test
    fun `derives the session salt from RFC 3711 B_3`() {
        val salt = SrtpSession.deriveKey(masterKey, masterSalt, label = 0x02, length = 14)
        assertEquals("30CBBC08863D8C85D49DB34A9AE1", hexOf(salt))
    }

    @Test
    fun `each label produces a different key from the same master key`() {
        val derived = (0..5).map { hexOf(SrtpSession.deriveKey(masterKey, masterSalt, it, 16)) }
        assertEquals(derived.size, derived.distinct().size)
    }

    @Test
    fun `protection leaves the header readable and appends a ten byte tag`() {
        val session = SrtpSession(masterKey, masterSalt)
        val packet = rtpPacket(sequence = 1, payload = ByteArray(100) { it.toByte() })

        val protected = session.protectRtp(packet)

        assertEquals(packet.size + 10, protected.size)
        // The twelve-byte header is authenticated but not encrypted, so it survives verbatim.
        assertEquals(hexOf(packet.copyOf(12)), hexOf(protected.copyOf(12)))
        // The payload must not.
        assertNotEquals(hexOf(packet.copyOfRange(12, packet.size)), hexOf(protected.copyOfRange(12, packet.size)))
    }

    @Test
    fun `two packets with different sequence numbers get different keystreams`() {
        val session = SrtpSession(masterKey, masterSalt)
        val payload = ByteArray(64) { 0x5A }

        val first = session.protectRtp(rtpPacket(sequence = 1, payload = payload))
        val second = session.protectRtp(rtpPacket(sequence = 2, payload = payload))

        // Identical plaintext under the same key with a reused counter would produce identical
        // ciphertext, which is the failure mode counter mode has and must never exhibit.
        assertNotEquals(
            hexOf(first.copyOfRange(12, first.size - 10)),
            hexOf(second.copyOfRange(12, second.size - 10)),
        )
    }

    @Test
    fun `the rollover counter keeps the keystream unique across a sequence number wrap`() {
        val payload = ByteArray(32) { 0x11 }

        // One session walks up to the wrap and over it; the sequence number returns to 1 while the
        // rollover counter has advanced, so packet index 1 and index 65537 must not collide.
        val session = SrtpSession(masterKey, masterSalt)
        val beforeWrap = session.protectRtp(rtpPacket(sequence = 1, payload = payload))
        session.protectRtp(rtpPacket(sequence = 0xFFFF, payload = payload))
        val afterWrap = session.protectRtp(rtpPacket(sequence = 1, payload = payload))

        assertNotEquals(
            hexOf(beforeWrap.copyOfRange(12, beforeWrap.size - 10)),
            hexOf(afterWrap.copyOfRange(12, afterWrap.size - 10)),
        )
    }

    private fun rtpPacket(sequence: Int, payload: ByteArray): ByteArray {
        val packet = ByteArray(12 + payload.size)
        packet[0] = 0x80.toByte()
        packet[1] = 106
        packet[2] = ((sequence ushr 8) and 0xFF).toByte()
        packet[3] = (sequence and 0xFF).toByte()
        // Timestamp and SSRC; the SSRC is mixed into the counter block, so it must be non-zero.
        for (i in 4 until 8) packet[i] = 0
        packet[8] = 0x12; packet[9] = 0x34; packet[10] = 0x56; packet[11] = 0x78
        System.arraycopy(payload, 0, packet, 12, payload.size)
        return packet
    }

    private fun hex(value: String) = ByteArray(value.length / 2) {
        value.substring(it * 2, it * 2 + 2).toInt(16).toByte()
    }

    private fun hexOf(value: ByteArray) = value.joinToString("") { "%02X".format(it) }
}
