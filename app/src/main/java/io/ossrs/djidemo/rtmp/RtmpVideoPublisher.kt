package io.ossrs.djidemo.rtmp

import io.ossrs.djidemo.camera.AnnexB
import io.ossrs.djidemo.camera.EncodedFrame
import io.ossrs.djidemo.publish.PendingFrame
import io.ossrs.djidemo.publish.PublishPump
import io.ossrs.djidemo.publish.PublishState
import io.ossrs.djidemo.publish.PublishTransport
import io.ossrs.djidemo.publish.VideoPublisher
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Publishes the aircraft's H.264 to an RTMP server.
 *
 * The job is a remux and nothing more: take the Annex-B access unit the tap delivered, hoist its
 * parameter sets into an AVC configuration record the first time they are seen, length-prefix the
 * remaining NAL units, and write the result as an RTMP video message. The slice bytes are never
 * touched, so what reaches the server is exactly what the aircraft encoded, at the downlink's own
 * resolution, for almost no CPU.
 */
class RtmpVideoPublisher(private val url: RtmpUrl) : VideoPublisher {

    override val protocol = "rtmp"

    private val _state = MutableStateFlow<PublishState>(PublishState.Idle)
    override val state: StateFlow<PublishState> = _state.asStateFlow()

    private val pump = PublishPump("rtmp-publish", _state, Transport())

    private var connection: RtmpConnection? = null

    /** The parameter sets currently announced to the server, so a change can be detected. */
    private var announcedSps: ByteArray? = null
    private var announcedPps: ByteArray? = null

    /**
     * The presentation timestamp of the first frame published.
     *
     * The aircraft's timestamps are absolute epoch-style milliseconds, while RTMP expects a stream
     * starting near zero. Subtracting the first one turns the former into the latter without
     * inventing a clock.
     */
    private var originMs = Long.MIN_VALUE

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
            connection = RtmpConnection(url).also { connection ->
                connection.connectAndPublish { step -> _state.value = PublishState.Connecting(step) }
            }
        }

        override fun write(pending: PendingFrame): Int {
            val connection = connection ?: return 0
            val data = pending.data

            var sps: ByteArray? = null
            var pps: ByteArray? = null
            val slices = ArrayList<ByteArray>(4)

            AnnexB.forEachUnit(data, 0, data.size) { unitOffset, unitLength ->
                if (unitLength > 0) {
                    when (AnnexB.typeOf(data[unitOffset])) {
                        // Parameter sets belong in the configuration record, not in the frame. They
                        // repeat before every keyframe in Annex-B, and forwarding those copies
                        // inline would be harmless but pointless bytes on the wire.
                        AnnexB.SPS -> sps = data.copyOfRange(unitOffset, unitOffset + unitLength)
                        AnnexB.PPS -> pps = data.copyOfRange(unitOffset, unitOffset + unitLength)
                        // An access unit delimiter only marks a boundary the framing already gives.
                        AnnexB.ACCESS_UNIT_DELIMITER -> Unit
                        else -> slices += data.copyOfRange(unitOffset, unitOffset + unitLength)
                    }
                }
            }

            var written = 0
            val currentSps = sps
            val currentPps = pps
            if (currentSps != null && currentPps != null &&
                (!currentSps.contentEquals(announcedSps) || !currentPps.contentEquals(announcedPps))
            ) {
                // The first time through this also carries the dimensions, which are only known
                // now: the tap reports them per frame, and there was nothing to report at connect.
                if (announcedSps == null) {
                    connection.sendMetadata(
                        width = pending.frame.width,
                        height = pending.frame.height,
                        frameRate = pending.frame.frameRate.toDouble(),
                    )
                }
                written += connection.sendVideo(FlvVideo.sequenceHeader(currentSps, currentPps), 0)
                announcedSps = currentSps
                announcedPps = currentPps
            }

            // Nothing can be decoded before the configuration record, so anything arriving ahead of
            // the first parameter sets is dropped rather than sent for the server to discard. In
            // practice that is at most the frames before the first keyframe.
            if (announcedSps == null || slices.isEmpty()) return written

            if (originMs == Long.MIN_VALUE) originMs = pending.frame.presentationTimeMs
            val timestamp = (pending.frame.presentationTimeMs - originMs).coerceAtLeast(0)

            written += connection.sendVideo(FlvVideo.naluBody(slices, pending.frame.keyFrame), timestamp)
            return written
        }

        override fun close() {
            connection?.close()
            connection = null
            announcedSps = null
            announcedPps = null
            originMs = Long.MIN_VALUE
        }
    }
}
