package io.ossrs.djidemo.whip

import io.ossrs.djidemo.whip.ice.StunMessage
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.zip.CRC32

/**
 * These are the tests that catch the two mistakes that make ICE fail silently: a `MESSAGE-INTEGRITY`
 * computed over the wrong length, and a `FINGERPRINT` computed over the wrong extent. A peer drops
 * either without answering and without logging, so nothing downstream would report the problem.
 */
class StunMessageTest {

    private val transactionId = StunMessage.newTransactionId()

    private fun request(password: String = "remotepassword") = StunMessage.bindingRequest(
        transactionId = transactionId,
        username = "remoteufrag:localufrag",
        password = password,
        priority = 2113937151L,
        tieBreaker = 0x0123456789ABCDEFL,
        useCandidate = true,
    )

    @Test
    fun `a binding request carries the ice attributes and parses back`() {
        val message = request()
        val parsed = requireNotNull(StunMessage.parse(message, message.size))

        assertTrue(parsed.isRequest)
        assertArrayEquals(transactionId, parsed.transactionId)
        assertEquals(
            "remoteufrag:localufrag",
            String(parsed.attributes.getValue(StunMessage.ATTR_USERNAME), Charsets.UTF_8),
        )
        assertTrue(StunMessage.ATTR_PRIORITY in parsed.attributes)
        assertTrue(StunMessage.ATTR_ICE_CONTROLLING in parsed.attributes)
        // USE-CANDIDATE carries no value; its presence is the whole message.
        assertEquals(0, parsed.attributes.getValue(StunMessage.ATTR_USE_CANDIDATE).size)
    }

    @Test
    fun `integrity verifies with the right password and fails with any other`() {
        val message = request(password = "correcthorse")
        val parsed = requireNotNull(StunMessage.parse(message, message.size))

        assertTrue(StunMessage.verifyIntegrity(parsed, "correcthorse"))
        assertFalse(StunMessage.verifyIntegrity(parsed, "correcthorsf"))
    }

    @Test
    fun `the declared length covers the integrity and fingerprint attributes`() {
        val message = request()
        val declared = ((message[2].toInt() and 0xFF) shl 8) or (message[3].toInt() and 0xFF)
        // The header is not counted in the length, so everything after it must be.
        assertEquals(message.size - StunMessage.HEADER_SIZE, declared)
    }

    @Test
    fun `the fingerprint is the crc of everything before it, xored with the magic value`() {
        val message = request()
        val fingerprintValue = message.copyOfRange(message.size - 4, message.size)
        val overBytes = message.copyOfRange(0, message.size - 8)

        val expected = (CRC32().apply { update(overBytes) }.value xor 0x5354554EL) and 0xFFFFFFFFL
        val actual = ((fingerprintValue[0].toLong() and 0xFF) shl 24) or
            ((fingerprintValue[1].toLong() and 0xFF) shl 16) or
            ((fingerprintValue[2].toLong() and 0xFF) shl 8) or (fingerprintValue[3].toLong() and 0xFF)
        assertEquals(expected, actual)
    }

    @Test
    fun `a success response is authenticated with our own password`() {
        val response = StunMessage.bindingSuccess(
            transactionId = transactionId,
            password = "localpassword",
            mappedAddress = byteArrayOf(192.toByte(), 168.toByte(), 1, 10),
            mappedPort = 8000,
        )
        val parsed = requireNotNull(StunMessage.parse(response, response.size))
        assertTrue(parsed.isSuccess)
        assertTrue(StunMessage.verifyIntegrity(parsed, "localpassword"))
        assertTrue(StunMessage.ATTR_XOR_MAPPED_ADDRESS in parsed.attributes)
    }

    @Test
    fun `stun is told apart from dtls and rtp by its first byte`() {
        val message = request()
        assertTrue(StunMessage.looksLikeStun(message, message.size))
        // 22 is a DTLS handshake record; 128 is the first byte of an RTP packet.
        assertFalse(StunMessage.looksLikeStun(byteArrayOf(22) + ByteArray(40), 41))
        assertFalse(StunMessage.looksLikeStun(byteArrayOf(0x80.toByte()) + ByteArray(40), 41))
    }

    @Test
    fun `a datagram that is not stun is rejected rather than misread`() {
        // Right size, wrong magic cookie.
        assertEquals(null, StunMessage.parse(ByteArray(40), 40))
        assertEquals(null, StunMessage.parse(ByteArray(4), 4))
    }
}
