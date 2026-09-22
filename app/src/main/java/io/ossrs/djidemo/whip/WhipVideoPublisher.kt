package io.ossrs.djidemo.whip

import io.ossrs.djidemo.camera.AnnexB
import io.ossrs.djidemo.camera.EncodedFrame
import io.ossrs.djidemo.publish.PendingFrame
import io.ossrs.djidemo.publish.PublishPump
import io.ossrs.djidemo.publish.PublishState
import io.ossrs.djidemo.publish.PublishTransport
import io.ossrs.djidemo.publish.VideoPublisher
import io.ossrs.djidemo.whip.dtls.DtlsClient
import io.ossrs.djidemo.whip.dtls.SelfSignedCertificate
import io.ossrs.djidemo.whip.rtp.H264Packetizer
import io.ossrs.djidemo.whip.rtp.RtcpSenderReport
import io.ossrs.djidemo.whip.srtp.SrtpSession
import java.net.URI
import java.security.SecureRandom
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Publishes the aircraft's H.264 to a WHIP endpoint.
 *
 * The same remux as the RTMP path, ending in a different framing -- but where RTMP is one TCP
 * connection and a handshake, WebRTC is four protocols stacked on one UDP socket, and the order
 * they happen in is the thing to understand:
 *
 * 1. **Signalling.** POST an SDP offer, get an answer. The answer carries the server's address, its
 *    ICE credentials and the fingerprint of the certificate it will present.
 * 2. **ICE.** Authenticated STUN checks prove the UDP path works in both directions.
 * 3. **DTLS.** A handshake over that path proves the server holds the certificate the answer
 *    promised, and produces key material for SRTP. The media never travels inside DTLS.
 * 4. **SRTP.** Each frame is cut into RTP packets, encrypted, and sent.
 *
 * Each step depends on the one before, and each can fail for its own reasons, which is why the
 * status line names the step rather than just saying "connecting".
 */
class WhipVideoPublisher(private val url: WhipUrl) : VideoPublisher {

    override val protocol = "whip"

    private val _state = MutableStateFlow<PublishState>(PublishState.Idle)
    override val state: StateFlow<PublishState> = _state.asStateFlow()

    private val pump = PublishPump("whip-publish", _state, Transport())

    private val random = SecureRandom()
    private val ssrc = (random.nextInt().toLong() and 0xFFFFFFFFL)
    private val cname = randomToken(16)

    private val packetizer = H264Packetizer(ssrc, Sdp.PAYLOAD_TYPE)

    private var transport: WhipTransport? = null
    private var srtp: SrtpSession? = null
    private var resource: URI? = null

    /** The first frame's presentation time, so the RTP clock starts near zero. */
    private var originMs = Long.MIN_VALUE
    private var lastReportMs = 0L

    /** Whether a frame carrying SPS and PPS has gone out; nothing before it is decodable. */
    private var sentKeyFrame = false

    override fun start() = pump.start()

    override fun stop() = pump.stop()

    override fun onEncodedFrame(data: ByteArray, offset: Int, length: Int, frame: EncodedFrame) =
        pump.offer(data, offset, length, frame)

    /**
     * The protocol half, driven entirely by [PublishPump] on its own thread.
     *
     * An inner class rather than something this publisher implements directly, so that `open`,
     * `write` and `close` are not part of its public surface: a caller may start and stop a
     * publish, and only the pump may drive a connection.
     */
    private inner class Transport : PublishTransport {


        override fun open() {
            _state.value = PublishState.Connecting("certificate")
            val certificate = SelfSignedCertificate.generate()
            val localUfrag = randomToken(8)
            val localPwd = randomToken(24)

            _state.value = PublishState.Connecting("signalling")
            val offer = Sdp.offer(
                iceUfrag = localUfrag,
                icePwd = localPwd,
                fingerprintSha256 = certificate.sha256Fingerprint,
                ssrc = ssrc,
                cname = cname,
            )
            val session = WhipSignaling.exchange(url, offer)
            resource = session.resource
            val answer = Sdp.parseAnswer(session.answer)

            require(answer.fingerprintAlgorithm == "sha-256") {
                "server offered a ${answer.fingerprintAlgorithm} fingerprint; only sha-256 is supported"
            }

            _state.value = PublishState.Connecting("ice")
            // Only the first candidate is tried. A server that publishes several is usually listing the
            // same host on multiple interfaces, and a publisher with one path to take gains nothing
            // from walking the list -- but this is the line to change if that stops being true.
            val socket = WhipTransport(
                candidate = answer.candidates.first(),
                localUfrag = localUfrag,
                localPwd = localPwd,
                remoteUfrag = answer.iceUfrag,
                remotePwd = answer.icePwd,
            )
            transport = socket
            socket.connect()

            _state.value = PublishState.Connecting("dtls")
            val keys = DtlsClient(certificate, answer.fingerprint, socket).handshake()

            // This client is the DTLS client, so its own SRTP keys are the "client" half of the
            // exported material. Taking the wrong half produces packets the server drops silently.
            srtp = SrtpSession(keys.clientMasterKey, keys.clientMasterSalt)
            socket.startKeepalive()
        }

        override fun write(pending: PendingFrame): Int {
            val transport = transport ?: return 0
            val srtp = srtp ?: return 0
            val data = pending.data

            // A publish usually starts between keyframes, which on this aircraft are seconds
            // apart. Slices before the first IDR reference a picture the receiver never had, so
            // they are dropped here, as the RTMP path drops them, rather than sent to be discarded
            // or, worse, decoded into garbage. Returning 0 keeps the publish in its waiting state.
            if (!sentKeyFrame) {
                val types = pending.frame.nalTypes
                if (AnnexB.SPS !in types || AnnexB.PPS !in types) return 0
                sentKeyFrame = true
            }

            val units = ArrayList<ByteArray>(4)
            AnnexB.forEachUnit(data, 0, data.size) { unitOffset, unitLength ->
                if (unitLength <= 0) return@forEachUnit
                // Access unit delimiters carry nothing RTP needs: the marker bit already says where a
                // frame ends. Parameter sets, unlike on the RTMP path, are kept and sent in band.
                if (AnnexB.typeOf(data[unitOffset]) == AnnexB.ACCESS_UNIT_DELIMITER) return@forEachUnit
                units += data.copyOfRange(unitOffset, unitOffset + unitLength)
            }
            if (units.isEmpty()) return 0

            if (originMs == Long.MIN_VALUE) originMs = pending.frame.presentationTimeMs
            val elapsedMs = (pending.frame.presentationTimeMs - originMs).coerceAtLeast(0)
            // The 90 kHz clock the SDP agreed. Every packet of one frame carries the same value, which
            // is how a receiver knows they belong together.
            val rtpTimestamp = (elapsedMs * (Sdp.CLOCK_RATE / 1000)) and 0xFFFFFFFFL

            var written = 0
            for (packet in packetizer.packetize(units, rtpTimestamp)) {
                val protected = srtp.protectRtp(packet)
                transport.send(protected)
                written += protected.size
            }

            written += maybeSendReport(transport, srtp, rtpTimestamp)
            return written
        }

        /**
         * Sends a sender report every few seconds.
         *
         * Driven off the frame path rather than a timer, because a report is only meaningful when it
         * can pair an RTP timestamp with a wall-clock time, and the frame just sent is where both of
         * those are known.
         */
        private fun maybeSendReport(transport: WhipTransport, srtp: SrtpSession, rtpTimestamp: Long): Int {
            val now = System.currentTimeMillis()
            if (now - lastReportMs < REPORT_INTERVAL_MS) return 0
            lastReportMs = now

            val report = RtcpSenderReport.build(
                ssrc = ssrc,
                cname = cname,
                rtpTimestamp = rtpTimestamp,
                wallClockMs = now,
                packets = packetizer.packetCount,
                octets = packetizer.octetCount,
            )
            val protected = srtp.protectRtcp(report)
            transport.send(protected)
            return protected.size
        }

        override fun close() {
            transport?.close()
            transport = null
            srtp = null
            originMs = Long.MIN_VALUE
            lastReportMs = 0
            sentKeyFrame = false
            resource?.let(WhipSignaling::delete)
            resource = null
        }
    }

    private fun randomToken(length: Int): String {
        val alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return (0 until length).map { alphabet[random.nextInt(alphabet.length)] }.joinToString("")
    }

    private companion object {

        /** RFC 3550 suggests five seconds as a sensible minimum for a session of this size. */
        const val REPORT_INTERVAL_MS = 5_000L
    }
}
