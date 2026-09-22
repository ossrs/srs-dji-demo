package io.ossrs.djidemo.camera

import android.util.Log
import android.view.Surface
import android.view.SurfaceHolder
import android.view.SurfaceView
import dji.sdk.keyvalue.value.common.ComponentIndexType
import dji.v5.manager.interfaces.ICameraStreamManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

private const val TAG = "LivePreview"

/**
 * What the live view is doing.
 *
 * `putCameraStreamSurface` returns void and reports no errors, so "the SDK accepted the surface" is
 * the strongest honest statement this app can make about the picture. That distinction is still
 * worth showing: [Bound] versus [Waiting] separates "the surface was never handed over" from "it
 * was, and there are still no pixels".
 */
sealed interface PreviewState {

    /** [LivePreview.start] has not run, or [LivePreview.stop] has. */
    data object Stopped : PreviewState

    /**
     * Started, but the surface has not been handed to the SDK. Either the aircraft reports no
     * camera yet or the `SurfaceView` has no usable surface. Both are normal for a moment after
     * connecting, and both persist for as long as no aircraft is attached.
     */
    data object Waiting : PreviewState

    /** The surface is bound to [camera]. Not proof that decoded frames are arriving. */
    data class Bound(val camera: ComponentIndexType) : PreviewState
}

/**
 * Puts the aircraft's camera on [surfaceView].
 *
 * This is the whole of the MSDK's rendering path, and the surprise is how little of it there is:
 * `putCameraStreamSurface` *is* the decode-and-render step. No `MediaCodec`, no SPS/PPS parsing, no
 * NAL handling and no render loop, because the SDK owns a hardware decoder per camera index and
 * this call binds its output to a `Surface`.
 *
 * Two things have to be true before that call does anything, and they arrive in **unpredictable
 * order**: a valid sized surface (from the view) and a camera index (from the aircraft, over the
 * radio, some time after connecting). Whichever lands second is what actually starts the video, so
 * [bind] re-checks every precondition rather than trusting a sequence.
 *
 * The stream manager outlives this object, so every attachment has an explicit removal. Omitting
 * one leaks a dead `Surface` into the SDK for the rest of the process.
 *
 * All state here is confined to the main thread: the surface callbacks already arrive there, and
 * [AvailableCameraWatcher] posts the camera index across.
 */
class LivePreview(private val surfaceView: SurfaceView) {

    private val _state = MutableStateFlow<PreviewState>(PreviewState.Stopped)

    /** Current preview status. Emissions are on the main thread. */
    val state: StateFlow<PreviewState> = _state.asStateFlow()

    private var running = false
    private var connected = false
    private var camera = ComponentIndexType.UNKNOWN
    private var surface: Surface? = null
    private var width = 0
    private var height = 0

    /** The surface currently handed to the SDK; removal is keyed by surface, not by index. */
    private var bound: Surface? = null

    private val cameras = AvailableCameraWatcher { next ->
        if (camera == next) return@AvailableCameraWatcher
        // Release the old index before binding the new one: one Surface shows at most one camera.
        unbind()
        camera = next
        bind()
    }

    private val holderCallback = object : SurfaceHolder.Callback {

        override fun surfaceCreated(holder: SurfaceHolder) {
            Log.i(TAG, "surfaceCreated")
            surface = holder.surface
            bind()
        }

        override fun surfaceChanged(holder: SurfaceHolder, format: Int, w: Int, h: Int) {
            // The size lands here and never in surfaceCreated, and putCameraStreamSurface does
            // nothing at all with a zero dimension -- so this, not creation, is usually what
            // starts the video.
            Log.i(TAG, "surfaceChanged ${w}x${h}")
            surface = holder.surface
            width = w
            height = h
            bind()
        }

        override fun surfaceDestroyed(holder: SurfaceHolder) {
            Log.i(TAG, "surfaceDestroyed")
            unbind()
            surface = null
            width = 0
            height = 0
        }
    }

    init {
        // Registered in the constructor rather than in start(), because the two are seconds apart
        // in the wrong direction: the surface is created within milliseconds of the Activity
        // appearing, while registration is a network round-trip to DJI. By the time start() runs,
        // surfaceCreated has almost always already fired -- and addCallback does not replay it.
        surfaceView.holder.addCallback(holderCallback)
    }

    /**
     * Begins looking for a camera to show. Idempotent.
     *
     * Call once registration has succeeded. `MediaDataCenter` is reachable before that, but nothing
     * upstream of `registerApp()` can produce a camera, so starting earlier only widens the window
     * in which the SDK is asked for hardware it is not yet allowed to talk to.
     */
    fun start() {
        if (running) return
        running = true
        _state.value = PreviewState.Waiting
        cameras.start()
        bind()
    }

    /** Releases everything held inside the SDK. Call from `Activity.onDestroy`. */
    fun stop() {
        surfaceView.holder.removeCallback(holderCallback)
        running = false
        cameras.stop()
        unbind()
        _state.value = PreviewState.Stopped
    }

    /** Whether an aircraft is attached. Nothing binds while it is false. */
    fun setConnected(value: Boolean) {
        if (connected == value) return
        connected = value
        if (value) bind() else unbind()
    }

    /**
     * The join point of the race. Reached from every branch above, and safe to call when nothing
     * has changed: binding a surface again updates its camera index, size and scale type rather
     * than stacking a second stream on top.
     */
    private fun bind() {
        val surface = this.surface ?: return
        if (!running || !connected || !surface.isValid) return
        if (camera == ComponentIndexType.UNKNOWN) return
        if (width <= 0 || height <= 0) return

        Log.i(TAG, "putCameraStreamSurface camera=$camera ${width}x${height}")
        cameraStreamManager.putCameraStreamSurface(
            camera,
            surface,
            width,
            height,
            // Letterbox rather than crop. The downlink's aspect ratio is the aircraft's to choose
            // and it is not this screen's shape, so CENTER_CROP would silently hide picture.
            ICameraStreamManager.ScaleType.CENTER_INSIDE,
        )
        bound = surface
        _state.value = PreviewState.Bound(camera)
    }

    private fun unbind() {
        bound?.let {
            Log.i(TAG, "removeCameraStreamSurface")
            cameraStreamManager.removeCameraStreamSurface(it)
        }
        bound = null
        if (running) _state.value = PreviewState.Waiting
    }
}
