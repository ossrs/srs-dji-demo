package io.ossrs.djidemo.whip

/**
 * The SDP offer this client sends, and the few facts it needs back out of the answer.
 *
 * SDP is a large format and WebRTC uses a lot of it, but a send-only H.264 publisher needs a
 * strikingly small subset: one media section, one codec, the ICE credentials, and the fingerprint
 * of the certificate the peer will present during the DTLS handshake. Everything else in a browser's
 * offer is there for cases this demo does not have -- audio, multiple codecs, simulcast,
 * renegotiation, data channels.
 */
internal object Sdp {

    /** H.264 constrained baseline 3.1: the profile the aircraft encodes and everything decodes. */
    const val H264_PROFILE_LEVEL_ID = "42e01f"

    /** Dynamic payload type for the one codec offered. Any value in 96..127 would do. */
    const val PAYLOAD_TYPE = 106

    /** H.264 RTP streams are clocked at 90 kHz by convention and by RFC 6184. */
    const val CLOCK_RATE = 90_000

    /**
     * Builds the offer.
     *
     * Three lines carry most of the meaning:
     *
     * - `a=setup:actpass` says this client will take whichever DTLS role the server does not. The
     *   answer settles it, and this client can only be the DTLS *client*, so an answer that also
     *   says `actpass` or `active` is rejected rather than half-honoured.
     * - `a=fingerprint` commits to the certificate that will appear in the handshake. It is what
     *   binds the signalling channel to the media channel: the server refuses to talk to anyone
     *   whose certificate hashes to something else.
     * - `a=sendonly` with `a=rtcp-mux` says one direction and one UDP port for everything, which is
     *   what makes the transport below a single socket rather than four.
     */
    fun offer(
        iceUfrag: String,
        icePwd: String,
        fingerprintSha256: String,
        ssrc: Long,
        cname: String,
    ): String {
        val sessionId = ssrc.toString()
        return listOf(
            "v=0",
            "o=- $sessionId 2 IN IP4 127.0.0.1",
            "s=-",
            "t=0 0",
            "a=group:BUNDLE 0",
            "a=msid-semantic: WMS $STREAM_LABEL",
            "m=video 9 UDP/TLS/RTP/SAVPF $PAYLOAD_TYPE",
            // The address is the "no candidate here" placeholder. Candidates arrive from the
            // server's answer, and this client offers none of its own: it is the one dialling out.
            "c=IN IP4 0.0.0.0",
            "a=rtcp:9 IN IP4 0.0.0.0",
            "a=ice-ufrag:$iceUfrag",
            "a=ice-pwd:$icePwd",
            "a=ice-options:trickle",
            "a=fingerprint:sha-256 $fingerprintSha256",
            "a=setup:actpass",
            "a=mid:0",
            "a=sendonly",
            "a=rtcp-mux",
            "a=rtcp-rsize",
            "a=rtpmap:$PAYLOAD_TYPE H264/$CLOCK_RATE",
            // packetization-mode=1 is what permits the fragmentation units the packetiser emits;
            // without it a receiver may only accept NAL units small enough to fit one packet.
            "a=fmtp:$PAYLOAD_TYPE level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=$H264_PROFILE_LEVEL_ID",
            "a=ssrc:$ssrc cname:$cname",
            "a=ssrc:$ssrc msid:$STREAM_LABEL $TRACK_LABEL",
        ).joinToString("\r\n", postfix = "\r\n")
    }

    /** What the answer has to tell this client before any packet can be sent. */
    data class Answer(
        val iceUfrag: String,
        val icePwd: String,
        val fingerprint: ByteArray,
        val fingerprintAlgorithm: String,
        val candidates: List<Candidate>,
    )

    /** One address to try. Only host candidates over UDP are used; see [parseAnswer]. */
    data class Candidate(val host: String, val port: Int)

    /**
     * Pulls the ICE credentials, the certificate fingerprint and the candidate addresses out of the
     * answer.
     *
     * Attribute lines are read wherever they appear rather than per media section, which is correct
     * here only because the offer contains exactly one media section and bundles everything onto it.
     *
     * Only UDP candidates are collected. TCP candidates would need a completely different transport,
     * and a server that offers nothing else is a server this client cannot reach -- which is worth
     * failing on rather than silently timing out.
     */
    fun parseAnswer(sdp: String): Answer {
        var ufrag: String? = null
        var pwd: String? = null
        var fingerprint: ByteArray? = null
        var algorithm = "sha-256"
        var setup: String? = null
        val candidates = ArrayList<Candidate>()

        for (raw in sdp.split('\n')) {
            val line = raw.trim()
            when {
                line.startsWith("a=ice-ufrag:") -> ufrag = line.substringAfter(':')
                line.startsWith("a=ice-pwd:") -> pwd = line.substringAfter(':')
                line.startsWith("a=setup:") -> setup = line.substringAfter(':')
                line.startsWith("a=fingerprint:") -> {
                    val value = line.substringAfter(':')
                    algorithm = value.substringBefore(' ').lowercase()
                    fingerprint = value.substringAfter(' ').split(':')
                        .map { it.trim().toInt(16).toByte() }
                        .toByteArray()
                }
                line.startsWith("a=candidate:") -> parseCandidate(line)?.let(candidates::add)
            }
        }

        // This client implements the DTLS client side only. If the server also wants to be the
        // client there is no handshake to be had, and finding that out here is much better than
        // finding it out as a silent timeout after the ICE checks have already succeeded.
        require(setup == null || setup == "passive") {
            "server asked for dtls role '$setup'; this client can only be the dtls client"
        }

        return Answer(
            iceUfrag = requireNotNull(ufrag) { "answer has no ice-ufrag" },
            icePwd = requireNotNull(pwd) { "answer has no ice-pwd" },
            fingerprint = requireNotNull(fingerprint) { "answer has no fingerprint" },
            fingerprintAlgorithm = algorithm,
            candidates = candidates.ifEmpty { throw IllegalStateException("answer has no candidates") },
        )
    }

    /** `a=candidate:<foundation> <component> <transport> <priority> <ip> <port> typ <type> ...` */
    private fun parseCandidate(line: String): Candidate? {
        val parts = line.substringAfter(':').split(' ').filter { it.isNotEmpty() }
        if (parts.size < 8) return null
        if (!parts[2].equals("udp", ignoreCase = true)) return null
        // Component 1 is RTP. With rtcp-mux there is no component 2, but a server may list one.
        if (parts[1] != "1") return null
        val port = parts[5].toIntOrNull() ?: return null
        return Candidate(parts[4], port)
    }

    /** Labels only, but they have to be consistent between the msid lines and the ssrc lines. */
    const val STREAM_LABEL = "srs-dji-demo"
    const val TRACK_LABEL = "video"
}
