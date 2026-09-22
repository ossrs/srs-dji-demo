package io.ossrs.djidemo.publish

import io.ossrs.djidemo.camera.EncodedVideoSink
import kotlinx.coroutines.flow.StateFlow

/** Where a publish has got to. */
sealed interface PublishState {

    /** Started, but no frame has arrived yet, so there is nothing to connect for. */
    data object Idle : PublishState

    /** Setting up the connection: TCP and handshake for RTMP, signalling and ICE for WHIP. */
    data class Connecting(val step: String) : PublishState

    /**
     * Connected and ready, but no frame has been written yet.
     *
     * Usually that is a wait for the aircraft's next keyframe: a publish can start at any point in
     * a keyframe interval several seconds long, and neither publisher writes anything before a
     * frame carrying SPS and PPS.
     *
     * This is a real and common state, not a transient one: the connection is fully established --
     * for WHIP that means signalling, ICE, DTLS and the SRTP keys are all done -- and the publisher
     * is simply waiting for the aircraft to send something. It exists because without it the status
     * line stayed on the last [Connecting] step until the first frame arrived, which reads as a
     * failure of that step. With the aircraft idle it cost a long WHIP debugging detour: the
     * handshake had in fact succeeded and the screen still said `connecting: dtls`.
     */
    data object Connected : PublishState

    /**
     * Connected, and frames are going out.
     *
     * @param sent frames written to the network.
     * @param dropped frames the queue could not hold. Non-zero means the uplink is slower than the
     *   aircraft's encoder, which is the one failure this design can absorb and keep running.
     * @param bitrateBps measured from what was actually written to the socket, so unlike the tap's
     *   figure this includes the protocol's own framing.
     */
    data class Live(
        val sent: Long,
        val dropped: Long,
        val bytes: Long,
        val bitrateBps: Double,
    ) : PublishState

    /** Shutting down. */
    data object Stopping : PublishState

    /** Stopped cleanly. */
    data object Stopped : PublishState

    /**
     * The publish is not happening. [reason] is short enough for a status line.
     *
     * [retrying] separates two very different things: a connection that failed and will be dialled
     * again in a moment, versus one that can never work -- a URL this app cannot honour, a server
     * that rejected the stream. Both stop the video; only one is worth waiting through.
     */
    data class Failed(val reason: String, val retrying: Boolean = false) : PublishState
}

/**
 * Something that takes the aircraft's encoded frames and puts them on a network.
 *
 * The interface exists so the screen can hold *a* publisher chosen at run time from the URL that
 * was typed, rather than one protocol wired in at build time. Everything above it -- the tap, the
 * status line -- is written against these members and never learns which protocol it is driving.
 *
 * Implementations inherit [EncodedVideoSink]'s contract verbatim: `onEncodedFrame` runs on the
 * SDK's callback thread with a buffer DJI recycles immediately, so an implementation that keeps the
 * bytes must copy them, and one that blocks stalls the decoder feeding the on-screen preview. In
 * practice that means every implementation here hands off to its own sender thread.
 */
interface VideoPublisher : EncodedVideoSink {

    /** The word the status line prints for this protocol: `rtmp`, `whip`. Short, lower case. */
    val protocol: String

    /** Current status. Updated from whatever thread the implementation publishes on. */
    val state: StateFlow<PublishState>

    /** Begins publishing. Idempotent. */
    fun start()

    /** Stops publishing and releases the connection. Idempotent, and safe after a failure. */
    fun stop()
}
