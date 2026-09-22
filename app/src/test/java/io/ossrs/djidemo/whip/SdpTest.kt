package io.ossrs.djidemo.whip

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class SdpTest {

    private val offer = Sdp.offer(
        iceUfrag = "abcd1234",
        icePwd = "thequickbrownfoxjumpsove",
        fingerprintSha256 = "AA:BB:CC:DD",
        ssrc = 3735928559L,
        cname = "cnametoken",
    )

    @Test
    fun `the offer says send only, bundled, muxed, and commits to a fingerprint`() {
        assertTrue(offer.contains("a=ice-ufrag:abcd1234"))
        assertTrue(offer.contains("a=ice-pwd:thequickbrownfoxjumpsove"))
        assertTrue(offer.contains("a=fingerprint:sha-256 AA:BB:CC:DD"))
        assertTrue(offer.contains("a=sendonly"))
        assertTrue(offer.contains("a=rtcp-mux"))
        assertTrue(offer.contains("a=setup:actpass"))
        assertTrue(offer.contains("a=ssrc:3735928559 cname:cnametoken"))
        // Without packetization-mode=1 a receiver need not accept the fragmentation units the
        // packetiser emits for anything larger than one packet, which is every keyframe.
        assertTrue(offer.contains("packetization-mode=1"))
        assertTrue(offer.contains("a=rtpmap:${Sdp.PAYLOAD_TYPE} H264/${Sdp.CLOCK_RATE}"))
    }

    @Test
    fun `sdp lines are CRLF terminated`() {
        assertTrue(offer.startsWith("v=0\r\n"))
        assertTrue(offer.endsWith("\r\n"))
        assertEquals(0, offer.count { it == '\n' } - offer.split("\r\n").size + 1)
    }

    private fun answer(setup: String = "passive", candidates: String = "a=candidate:1 1 udp 2130706431 192.168.1.10 8000 typ host") = """
        v=0
        o=SRS 0 0 IN IP4 0.0.0.0
        s=SRSPublishSession
        t=0 0
        a=ice-lite
        m=video 9 UDP/TLS/RTP/SAVPF 106
        c=IN IP4 0.0.0.0
        a=ice-ufrag:serverfrag
        a=ice-pwd:serverpasswordvalue
        a=fingerprint:sha-256 11:22:33:44:55
        a=setup:$setup
        a=mid:0
        a=recvonly
        a=rtcp-mux
        $candidates
    """.trimIndent()

    @Test
    fun `parses the credentials, fingerprint and candidate out of an answer`() {
        val parsed = Sdp.parseAnswer(answer())

        assertEquals("serverfrag", parsed.iceUfrag)
        assertEquals("serverpasswordvalue", parsed.icePwd)
        assertEquals("sha-256", parsed.fingerprintAlgorithm)
        assertEquals(listOf(0x11, 0x22, 0x33, 0x44, 0x55), parsed.fingerprint.map { it.toInt() and 0xFF })
        assertEquals(1, parsed.candidates.size)
        assertEquals(Sdp.Candidate("192.168.1.10", 8000), parsed.candidates.single())
    }

    @Test
    fun `a server that wants to be the dtls client is refused before any packet is sent`() {
        // This client implements only the DTLS client side. Finding that out here, rather than as a
        // handshake that never completes, is the whole point of checking.
        assertThrows(IllegalArgumentException::class.java) { Sdp.parseAnswer(answer(setup = "active")) }
        assertThrows(IllegalArgumentException::class.java) { Sdp.parseAnswer(answer(setup = "actpass")) }
    }

    @Test
    fun `tcp and non-rtp candidates are ignored`() {
        val parsed = Sdp.parseAnswer(
            answer(
                candidates = listOf(
                    "a=candidate:1 1 tcp 2130706431 192.168.1.10 9000 typ host",
                    "a=candidate:2 2 udp 2130706431 192.168.1.10 8001 typ host",
                    "a=candidate:3 1 udp 2130706431 192.168.1.11 8002 typ host",
                ).joinToString("\n"),
            ),
        )
        assertEquals(listOf(Sdp.Candidate("192.168.1.11", 8002)), parsed.candidates)
    }

    @Test
    fun `an answer missing what the transport needs is rejected`() {
        assertThrows(IllegalStateException::class.java) { Sdp.parseAnswer(answer(candidates = "")) }
        assertThrows(IllegalArgumentException::class.java) {
            Sdp.parseAnswer(answer().replace("a=fingerprint:sha-256 11:22:33:44:55", ""))
        }
    }
}
