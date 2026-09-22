package io.ossrs.djidemo.camera

import android.os.Handler
import android.os.Looper
import dji.sdk.keyvalue.value.common.ComponentIndexType
import dji.v5.manager.datacenter.MediaDataCenter
import dji.v5.manager.interfaces.ICameraStreamManager

/** The stream manager singleton, owned by `MediaDataCenter` and alive for the whole process. */
internal val cameraStreamManager: ICameraStreamManager
    get() = MediaDataCenter.getInstance().cameraStreamManager

/**
 * Reports which camera index this app should be using, on the main thread.
 *
 * Both the preview and the encoded tap need exactly this and nothing more, so it lives in one place
 * instead of twice: the two of them picking different camera indexes would be a confusing bug.
 *
 * The SDK delivers availability on its own thread and can deliver it more than once for the same
 * list, so [onCamera] is posted to the main thread and called only when the chosen index actually
 * changes. [ComponentIndexType.UNKNOWN] means "no camera to use", which is the normal state
 * whenever no aircraft is attached.
 */
internal class AvailableCameraWatcher(private val onCamera: (ComponentIndexType) -> Unit) {

    private val mainHandler = Handler(Looper.getMainLooper())

    /** Main-thread only. */
    private var watching = false
    private var current = ComponentIndexType.UNKNOWN

    private val listener = object : ICameraStreamManager.AvailableCameraUpdatedListener {

        override fun onAvailableCameraUpdated(availableCameraList: List<ComponentIndexType>) {
            // LEFT_OR_MAIN is chosen explicitly rather than taking the first entry: the Mini 4 Pro
            // also exposes VISION_ASSIST, which is the obstacle-sensing view and not the camera
            // anybody wants to watch or publish.
            val next = if (ComponentIndexType.LEFT_OR_MAIN in availableCameraList) {
                ComponentIndexType.LEFT_OR_MAIN
            } else {
                ComponentIndexType.UNKNOWN
            }

            mainHandler.post {
                if (!watching || current == next) return@post
                current = next
                onCamera(next)
            }
        }

        /**
         * Which camera streams are switched on. Unused here -- a stream that is off simply never
         * produces a picture, and the status line already says so -- but this override is
         * **mandatory**.
         *
         * `javap` on `dji-sdk-v5-aircraft-provided-5.18.0.jar` reports this method as `default`,
         * and that is wrong: the stub jar is only what the app compiles against, while the
         * implementation it runs against is decrypted out of the aircraft AAR at startup, and there
         * the method is abstract. Omitting it compiles cleanly and then kills the process on the
         * SDK's first enable-update with
         * `AbstractMethodError: abstract method ... onCameraStreamEnableUpdate(java.util.Map)`.
         * No aircraft is needed to trigger it.
         */
        override fun onCameraStreamEnableUpdate(
            cameraStreamEnableMap: MutableMap<ComponentIndexType, Boolean>,
        ) = Unit
    }

    /** Begins watching. Idempotent. Main thread. */
    fun start() {
        if (watching) return
        watching = true
        cameraStreamManager.addAvailableCameraUpdatedListener(listener)
    }

    /** Stops watching and releases the listener held inside the SDK singleton. Idempotent. */
    fun stop() {
        if (!watching) return
        watching = false
        cameraStreamManager.removeAvailableCameraUpdatedListener(listener)
        if (current != ComponentIndexType.UNKNOWN) {
            current = ComponentIndexType.UNKNOWN
            onCamera(ComponentIndexType.UNKNOWN)
        }
    }
}
