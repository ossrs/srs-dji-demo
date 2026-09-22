package io.ossrs.djidemo.camera

import android.util.Log
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import dji.sdk.keyvalue.value.common.ComponentIndexType
import dji.v5.manager.datacenter.camera.StreamInfo
import dji.v5.manager.interfaces.ICameraStreamManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

private const val TAG = "EncodedVideoTap"

/**
 * One encoded frame, described. Deliberately holds **no reference to the SDK's byte array**.
 *
 * @param sequence this app's own count, 1-based. The elementary stream carries no frame number.
 * @param arrivalMs monotonic arrival time, used only to derive observed frame rate and bitrate.
 *   Not the same clock as [presentationTimeMs].
 * @param presentationTimeMs the encoder's own timestamp, in milliseconds. This is what a muxer
 *   needs; it is an absolute epoch-style value, so publishers subtract their own origin from it.
 * @param nalTypes the Annex-B NAL types found in the payload. The one field not copied from
 *   `StreamInfo`: it is read out of the bytes themselves, and it is the evidence that the tap is
 *   delivering a real elementary stream rather than an opaque blob.
 */
data class EncodedFrame(
    val sequence: Long,
    val arrivalMs: Long,
    val mimeType: String,
    val width: Int,
    val height: Int,
    val frameRate: Int,
    val keyFrame: Boolean,
    val presentationTimeMs: Long,
    val length: Int,
    val nalTypes: List<Int>,
)

/**
 * A consumer of encoded frames, invoked inline on the SDK's callback thread.
 *
 * The contract is the SDK's own, passed straight through and not softened:
 *
 * - `data` is a buffer DJI **recycles for the next callback**. An implementation that keeps the
 *   bytes past the call must copy them.
 * - The call is on the SDK's thread at the full frame rate. An implementation that blocks stalls
 *   the SDK pipeline that also feeds the on-screen preview, so real work belongs on another thread.
 */
fun interface EncodedVideoSink {

    fun onEncodedFrame(data: ByteArray, offset: Int, length: Int, frame: EncodedFrame)
}

/**
 * A rolling measurement of what the tap is producing.
 *
 * Rates are measured across a window rather than counted from the start, so they describe what the
 * stream is doing now instead of averaging away a drop-out from a minute ago.
 *
 * @param bitrateBps payload bits per second. Elementary-stream bytes only, with no container, so
 *   this reads lower than what RTMP or WHIP measurement of the same stream reports.
 * @param hasParameterSets whether SPS **and** PPS have both been seen since this camera's stream
 *   began. A publisher cannot start without them -- RTMP needs them for its AVC sequence header
 *   and WHIP needs them before the first slice means anything to a decoder -- so this is the
 *   difference between frames arriving and frames a stream can actually be built from.
 *   Latched rather than measured over the rolling window, and that is the point: the aircraft
 *   repeats them only with each IDR, about every eight seconds (190-odd frames at 24 fps), while
 *   the window holds 64. A windowed answer was true for a third of every keyframe interval, and
 *   Start blinked on and off in step with it. Having seen one IDR proves the next will come; a
 *   publisher that starts between them waits for it itself.
 */
data class TapStats(
    val frames: Long = 0,
    val keyFrames: Long = 0,
    val bytes: Long = 0,
    val fps: Double = 0.0,
    val bitrateBps: Double = 0.0,
    val latest: EncodedFrame? = null,
    val sinceLastFrameMs: Long = -1,
    val hasParameterSets: Boolean = false,
)

/** Where the encoded tap has got to. */
sealed interface TapState {

    /** [EncodedVideoTap.start] has not run, or [EncodedVideoTap.stop] has. */
    data object Stopped : TapState

    /** Listening, but with no camera index to attach to. Normal with no aircraft attached. */
    data object Waiting : TapState

    /**
     * The listener is registered against [camera]. [stats] stays empty until the first callback,
     * which is itself the interesting distinction: registered-but-silent is a real failure mode,
     * and it looks nothing like not being registered at all.
     */
    data class Receiving(val camera: ComponentIndexType, val stats: TapStats) : TapState
}

/**
 * Whether there is live media a publisher could actually be started from.
 *
 * This, and **not** Eco Mode, is what gates the Start button. The distinction was learned the hard
 * way on the sandbox and is worth stating plainly: Eco Mode can begin *after* a camera session is
 * already established, and the frames already flowing keep flowing and stay publishable. What Eco
 * Mode reliably prevents is a fresh app establishing a *new* camera feed. So the diagnostic is an
 * explanation, not a readiness signal -- gating on it would both block publishes that would have
 * worked and allow publishes that cannot.
 *
 * Three conditions, each for its own reason: two frames because one measures no rate at all; a
 * non-zero rate because [TapStats.fps] is already reported as zero once the stream goes stale, so
 * this covers a stream that has quietly stopped; and one keyframe's parameter sets, ever, because
 * that proves the stream can be described. Not a keyframe *now*: see [TapStats.hasParameterSets].
 */
val TapState.hasLiveMedia: Boolean
    get() = this is TapState.Receiving &&
        stats.frames >= 2 &&
        stats.fps > 0.0 &&
        stats.hasParameterSets

/**
 * Taps the aircraft's compressed video and hands it to a [sink].
 *
 * This is the demo's subject. `addReceiveStreamListener` delivers H.264 that is already encoded, so
 * a publisher only has to **remux** it -- change the framing -- rather than decode and re-encode.
 * That is why publishing from here costs almost no CPU, and why the picture that goes out is the
 * full downlink resolution rather than what a re-encode would settle for.
 *
 * One caveat worth knowing and not worth hiding: on MSDK 5.18 these bytes come from an SDK encoder
 * fed by the SDK's own decoder, not untouched from the aircraft. It is still H.264 and still only
 * needs remuxing, but it is not literally the aircraft's original bitstream.
 */
class EncodedVideoTap {

    /**
     * Where the bytes go, if anywhere. Set before [start].
     *
     * Volatile because it is written from the main thread and read from the SDK's. The tap works
     * with this left null: measuring the stream is its own job and does not depend on a consumer.
     */
    @Volatile
    var sink: EncodedVideoSink? = null

    private val _state = MutableStateFlow<TapState>(TapState.Stopped)

    /** Current tap status including the rolling stats. Emissions are on the main thread. */
    val state: StateFlow<TapState> = _state.asStateFlow()

    private val mainHandler = Handler(Looper.getMainLooper())

    /** Main-thread only. */
    private var running = false
    private var connected = false
    private var attached = false
    private var ticking = false
    private var camera = ComponentIndexType.UNKNOWN
    private var stallReported = false

    /** Guarded by its own monitor: one producer on the SDK thread, one consumer on the main one. */
    private val window = ArrayDeque<EncodedFrame>()
    private var totalFrames = 0L
    private var totalKeyFrames = 0L
    private var totalBytes = 0L
    private var sawSps = false
    private var sawPps = false

    private val cameras = AvailableCameraWatcher { next ->
        if (camera == next) return@AvailableCameraWatcher
        detach()
        camera = next
        // A different camera is a different stream, with parameter sets of its own still to come.
        synchronized(window) {
            sawSps = false
            sawPps = false
        }
        attach()
    }

    private val streamListener = object : ICameraStreamManager.ReceiveStreamListener {
        override fun onReceiveStream(
            data: ByteArray,
            offset: Int,
            length: Int,
            info: StreamInfo,
        ) = onFrame(data, offset, length, info)
    }

    /**
     * Fires once per encoded frame, on an SDK thread, at the stream's full frame rate.
     *
     * The inline work is deliberately bounded: read the primitive `StreamInfo` fields, make one
     * pass over the payload for start codes, push one small record. No I/O, no UI work and no
     * allocation proportional to the payload. The screen is updated by [tick] on its own schedule
     * instead, because a `TextView` cannot usefully be rewritten thirty times a second and posting
     * that many main-thread messages would be the real cost here, not the parsing.
     */
    private fun onFrame(data: ByteArray, offset: Int, length: Int, info: StreamInfo) {
        val mime = info.mimeType?.name ?: "UNKNOWN"
        val described = EncodedFrame(
            sequence = 0, // replaced under the lock, where the counter lives
            arrivalMs = SystemClock.elapsedRealtime(),
            mimeType = mime,
            width = info.width,
            height = info.height,
            frameRate = info.frameRate,
            keyFrame = info.isKeyFrame,
            presentationTimeMs = info.presentationTimeMs,
            length = length,
            nalTypes = AnnexB.typesIn(data, offset, length),
        )

        if (totalFrames == 0L) Log.i(TAG, "first frame $mime ${info.width}x${info.height}")
        val counted: EncodedFrame
        synchronized(window) {
            totalFrames++
            if (described.keyFrame) totalKeyFrames++
            totalBytes += length
            if (AnnexB.SPS in described.nalTypes) sawSps = true
            if (AnnexB.PPS in described.nalTypes) sawPps = true
            counted = described.copy(sequence = totalFrames)
            window.addLast(counted)
            while (window.size > WINDOW) window.removeFirst()
        }

        // Outside the lock, and inside runCatching: the sink is somebody else's code and must not
        // be able to hold the window shut against the main thread, nor take the tap down with it.
        // A publisher that cannot accept this frame is not a reason to stop measuring the stream.
        runCatching { sink?.onEncodedFrame(data, offset, length, counted) }
    }

    /** Begins watching for a camera to tap. Idempotent. Call once registration has succeeded. */
    fun start() {
        if (running) return
        running = true
        _state.value = TapState.Waiting
        cameras.start()
        attach()
    }

    /** Releases the listeners held inside the SDK singleton. Call from `Activity.onDestroy`. */
    fun stop() {
        running = false
        cameras.stop()
        detach()
        _state.value = TapState.Stopped
    }

    /** Whether an aircraft is attached. Nothing is tapped while it is false. */
    fun setConnected(value: Boolean) {
        if (connected == value) return
        connected = value
        if (value) attach() else detach()
    }

    private fun attach() {
        if (!running || !connected || attached) return
        if (camera == ComponentIndexType.UNKNOWN) return

        Log.i(TAG, "addReceiveStreamListener camera=$camera")
        cameraStreamManager.addReceiveStreamListener(camera, streamListener)
        attached = true
        _state.value = TapState.Receiving(camera, snapshot())
        if (!ticking) {
            ticking = true
            mainHandler.post(ticker)
        }
    }

    private fun detach() {
        if (attached) {
            Log.i(TAG, "removeReceiveStreamListener")
            cameraStreamManager.removeReceiveStreamListener(streamListener)
            attached = false
        }
        ticking = false
        mainHandler.removeCallbacks(ticker)
        // Counters and window are left intact. A disconnect should not erase the evidence of what
        // arrived before it, and reattaching simply keeps counting.
        if (running) _state.value = TapState.Waiting
    }

    /**
     * Republishes the measurement on a fixed cadence while attached.
     *
     * A tick rather than a push per frame: the callback fires around thirty times a second and the
     * screen cannot show that, so the UI samples a stream that runs faster than it.
     */
    private val ticker = object : Runnable {
        override fun run() {
            if (!ticking) return
            if (attached) {
                val stats = snapshot()
                _state.value = TapState.Receiving(camera, stats)
                if (stats.frames > 0 && stats.sinceLastFrameMs > STALE_MS && !stallReported) {
                    stallReported = true
                    Log.w(TAG, "frames stopped after ${stats.frames} frames (${stats.sinceLastFrameMs}ms ago)")
                }
                if (stats.sinceLastFrameMs in 0 until STALE_MS) stallReported = false
            }
            mainHandler.postDelayed(this, TICK_MS)
        }
    }

    private fun snapshot(): TapStats {
        val frames: List<EncodedFrame>
        val total: Long
        val keys: Long
        val bytes: Long
        val parameterSets: Boolean
        synchronized(window) {
            frames = window.toList()
            total = totalFrames
            keys = totalKeyFrames
            bytes = totalBytes
            parameterSets = sawSps && sawPps
        }

        val latest = frames.lastOrNull()
        val since = latest?.let { SystemClock.elapsedRealtime() - it.arrivalMs } ?: -1L

        // Rates need two arrivals to have a span between them; one frame measures nothing. A stale
        // window measures nothing useful either -- it would keep reporting the rate the stream had
        // when it stopped -- so a stream that has gone quiet reports zero rather than history.
        var fps = 0.0
        var bitrate = 0.0
        if (frames.size >= 2 && since in 0 until STALE_MS) {
            val spanMs = frames.last().arrivalMs - frames.first().arrivalMs
            if (spanMs > 0) {
                // n frames span n-1 intervals; dividing by n would under-report by 1/n.
                fps = (frames.size - 1) * 1000.0 / spanMs
                // The first frame arrived at the start of the span, so its bytes belong to the
                // period before the window and are excluded from the rate along with it.
                bitrate = frames.drop(1).sumOf { it.length.toLong() } * 8 * 1000.0 / spanMs
            }
        }

        return TapStats(total, keys, bytes, fps, bitrate, latest, since, parameterSets)
    }

    private companion object {

        /** About two seconds at 30 fps: long enough for a stable rate, short enough to react. */
        const val WINDOW = 64

        /** 5 Hz. Fast enough to look live, slow enough that the UI is not the bottleneck. */
        const val TICK_MS = 200L

        /** No frame for this long and the measured rates are history, not measurement. */
        const val STALE_MS = 1_500L
    }
}
