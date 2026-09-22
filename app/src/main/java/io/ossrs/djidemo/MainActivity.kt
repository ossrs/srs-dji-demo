package io.ossrs.djidemo

import android.os.Bundle
import android.view.inputmethod.InputMethodManager
import android.widget.ArrayAdapter
import androidx.appcompat.app.AppCompatActivity
import androidx.appcompat.widget.ListPopupWindow
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import io.ossrs.djidemo.camera.AnnexB
import io.ossrs.djidemo.camera.EncodedVideoTap
import io.ossrs.djidemo.camera.LivePreview
import io.ossrs.djidemo.camera.PreviewState
import io.ossrs.djidemo.camera.TapState
import io.ossrs.djidemo.camera.hasLiveMedia
import io.ossrs.djidemo.databinding.ActivityMainBinding
import io.ossrs.djidemo.publish.PublishState
import io.ossrs.djidemo.publish.PublishTargets
import io.ossrs.djidemo.publish.VideoPublisher
import io.ossrs.djidemo.publish.problemWith
import io.ossrs.djidemo.publish.publisherFor
import io.ossrs.djidemo.sdk.EcoMode
import io.ossrs.djidemo.sdk.EcoModeDiagnostic
import io.ossrs.djidemo.sdk.EcoModeWatcher
import io.ossrs.djidemo.sdk.Registration
import io.ossrs.djidemo.sdk.SdkStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.launch

/**
 * The whole screen: the aircraft's picture, what the SDK and the tap are doing, and one publish.
 *
 * Deliberately one Activity with no architecture around it. The demo has a single job and a single
 * screen, and a reader following the publish path should be able to get from the button to the
 * socket without passing through a ViewModel, a repository and three interfaces on the way.
 */
class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding

    /**
     * Null when the preview has been switched off for a diagnostic run.
     *
     * Debug only, and it exists for one question: the SDK attaches its own encoder-input surface to
     * the same camera index this preview binds to, so "does the tap behave differently with no
     * preview surface attached?" cannot be answered without being able to take the preview away.
     */
    private var preview: LivePreview? = null

    private val tap = EncodedVideoTap()

    /**
     * Why the aircraft may be connected and still sending nothing.
     *
     * Watched only while the screen is visible: it explains the picture, so it is worth nothing
     * when there is no picture to explain.
     */
    private val eco = EcoModeWatcher()

    /** The current publisher, if any. Held as a flow so the status line can follow it. */
    private val publisher = MutableStateFlow<VideoPublisher?>(null)

    private val sdk by lazy { (application as DemoApplication).sdk }

    /** The remembered publish URLs behind the Select button. */
    private val targets by lazy { PublishTargets(this) }

    /** Held so it can be dismissed in [onDestroy]; a popup outliving its Activity leaks it. */
    private var picker: ListPopupWindow? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        applyWindowInsets()

        // adb shell am start -n io.ossrs.djidemo/.MainActivity --ez preview false
        val previewEnabled = intent?.getBooleanExtra(EXTRA_PREVIEW, true) ?: true
        if (previewEnabled) {
            preview = LivePreview(binding.preview)
        } else {
            binding.preview.visibility = android.view.View.GONE
        }

        // Prefilled with the last URL published to, so a relaunch resumes where the previous run
        // pointed -- which is what makes a crash or a redeploy cost nothing to recover from.
        binding.url.setText(targets.last)
        binding.selectUrl.setOnClickListener { showPicker() }
        binding.publishButton.setOnClickListener { onPublishClicked() }

        // Everything the aircraft side does is gated on registration, so it is driven from here
        // rather than from onStart: the SDK's state, not the Activity's, decides when to begin.
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch { sdk.status.collect(::applySdkStatus) }
                launch { renderStatus() }
            }
        }
    }

    /**
     * Keeps the layout clear of the system bars.
     *
     * Landscape is what makes this necessary rather than cosmetic: the navigation bar moves to one
     * of the short edges, so without this the Start button sits underneath it and cannot be
     * reliably tapped. The status bar clips the top of the panel at the same time. Both were
     * observed on the Galaxy S21 before this was added.
     *
     * The cutout is included alongside the bars because a landscape camera hole lands in exactly
     * the gutter this is protecting.
     */
    private fun applyWindowInsets() {
        val gutter = (GUTTER_DP * resources.displayMetrics.density).toInt()
        ViewCompat.setOnApplyWindowInsetsListener(binding.root) { view, insets ->
            val bars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout(),
            )
            view.setPadding(
                bars.left + gutter,
                bars.top + gutter,
                bars.right + gutter,
                bars.bottom + gutter,
            )
            insets
        }
    }

    /**
     * `DeviceHealthManager` is a process-wide singleton, so the listener is added and removed with
     * the screen rather than the process. Registration is not required first -- with no aircraft
     * the health list is simply empty.
     */
    override fun onStart() {
        super.onStart()
        eco.start()
    }

    override fun onStop() {
        eco.stop()
        super.onStop()
    }

    override fun onDestroy() {
        super.onDestroy()
        picker?.dismiss()
        picker = null
        // The SDK's stream manager is process-wide and outlives this Activity, so every listener
        // and surface handed to it has to be handed back or it leaks for the life of the process.
        publisher.value?.stop()
        tap.sink = null
        tap.stop()
        preview?.stop()
    }

    private fun applySdkStatus(status: SdkStatus) {
        if (status.isRegistered) {
            preview?.start()
            tap.start()
        }
        preview?.setConnected(status.aircraftConnected)
        tap.setConnected(status.aircraftConnected)
    }

    private fun onPublishClicked() {
        val existing = publisher.value
        if (existing != null) {
            tap.sink = null
            existing.stop()
            publisher.value = null
            binding.publishButton.setText(R.string.publish_start)
            return
        }

        // Guarded here as well as by the disabled button. A click already in flight when the
        // stream stopped would otherwise open a socket to a server and then send nothing, which
        // looks like a publisher bug from the server's side.
        if (!tap.state.value.hasLiveMedia) return

        val url = binding.url.text.toString().trim()
        problemWith(url)?.let {
            binding.url.error = it
            return
        }
        binding.url.error = null
        // Remembered only once it is known to be publishable, so a typo does not earn a place in
        // the list and then have to be scrolled past every session afterwards.
        targets.remember(url)
        hideKeyboard()

        val started = runCatching { publisherFor(url) }.getOrElse {
            binding.url.error = it.message ?: "cannot publish to this url"
            return
        }
        started.start()
        // Wired only after start(), so no frame can reach a publisher that has not begun.
        tap.sink = started
        publisher.value = started
        binding.publishButton.setText(R.string.publish_stop)
    }

    /**
     * Opens the list of publish URLs, anchored under the Select button.
     *
     * Rebuilt on each tap rather than kept, because the list changes as soon as something is
     * published: the URL just used moves to the top, and a popup created at startup would go on
     * offering yesterday's order.
     *
     * Selecting an entry replaces the field's text and nothing else. It does not start a publish --
     * the choice and the commitment stay separate controls, so a mis-tap on a list of similar
     * addresses cannot begin sending video to the wrong server.
     */
    private fun showPicker() {
        val urls = targets.recent()
        picker?.dismiss()
        picker = ListPopupWindow(this).apply {
            anchorView = binding.selectUrl
            width = binding.controls.width
            isModal = true
            setAdapter(ArrayAdapter(this@MainActivity, R.layout.publish_target_item, urls))
            setOnItemClickListener { _, _, position, _ ->
                binding.url.setText(urls[position])
                binding.url.error = null
                dismiss()
            }
            show()
        }
    }

    private fun hideKeyboard() {
        val service = getSystemService(INPUT_METHOD_SERVICE) as InputMethodManager
        service.hideSoftInputFromWindow(binding.url.windowToken, 0)
    }

    /** What one pass over the combined state decided the screen should show. */
    private data class Screen(val status: String, val startEnabled: Boolean)

    /**
     * Keeps the status column and the Start button in step with every state machine at once.
     *
     * They are combined rather than rendered independently because the interesting information is
     * in how they line up: a tap that is receiving while a publish is idle, or a publish that is
     * live while the tap has gone quiet, each say something that neither line says alone. The
     * button falls out of the same pass, so there is one place where "can this publish start" is
     * decided and no chance of the label and the enablement disagreeing.
     */
    @Suppress("OPT_IN_USAGE")
    private suspend fun renderStatus() {
        val publishState = publisher.flatMapLatest { it?.state ?: MutableStateFlow(null) }
        val previewState = preview?.state ?: MutableStateFlow(PreviewState.Stopped)
        combine(
            sdk.status,
            previewState,
            tap.state,
            publisher,
            publishState,
            eco.state,
        ) { values ->
            val tapState = values[2] as TapState
            val current = values[3] as VideoPublisher?
            Screen(
                status = describe(
                    sdk = values[0] as SdkStatus,
                    preview = values[1] as PreviewState,
                    tap = tapState,
                    publisher = current,
                    publish = values[4] as PublishState?,
                    eco = values[5] as EcoMode,
                ),
                // Once a publisher exists the button is Stop, and Stop must never be unavailable:
                // a stream that has stalled or an aircraft that has just entered Eco Mode is
                // exactly when the user wants to stop it.
                startEnabled = current != null || tapState.hasLiveMedia,
            )
        }.collect {
            binding.status.text = it.status
            binding.publishButton.isEnabled = it.startEnabled
        }
    }

    private fun describe(
        sdk: SdkStatus,
        preview: PreviewState,
        tap: TapState,
        publisher: VideoPublisher?,
        publish: PublishState?,
        eco: EcoMode,
    ): String = buildString {
        // A table: the section name in a fixed-width column and its state beside it, so a healthy
        // screen is one line per section and only the detail a section actually has adds lines.
        fun row(label: String, value: String) = appendLine(label.padEnd(LABEL_WIDTH) + value)
        fun more(value: String) = appendLine(" ".repeat(LABEL_WIDTH) + value)

        // A header rather than a footer, because the question it answers comes before any of the
        // live state: is this the build I just installed? Without it a failed `adb install` and a
        // successful one look identical on screen, and the fix gets applied to the wrong APK.
        //
        // One line for both versions, and versionName alone: versionCode is what the installer
        // compares, but it is not what anyone reads, and the readout is worth more kept short
        // (William, 2026-09-22). The SDK version is null until init completes -- see
        // SdkStatus.sdkVersion -- and is shown as "loading" rather than omitted, so an SDK that
        // never finishes loading is visible here too.
        row("VERSION", "app ${BuildConfig.VERSION_NAME}  msdk ${sdk.sdkVersion ?: "loading"}")

        // First of the live sections, when active, because it is the explanation for everything
        // below it looking broken: registered, connected, a bound surface, and no frames at all.
        if (eco.active) {
            // DJI's own text does not mention the downlink, which is the only part that matters
            // here, so this line is the app's and the rest is the aircraft's.
            row("ECO", "on, no camera feed  ${EcoModeDiagnostic.CODE}")
            if (eco.description.isNotBlank()) more("\"${eco.description}\"")
            more("fix: DJI Fly, or power-cycle")
        }

        row("SDK", when (val registration = sdk.registration) {
            is Registration.Idle -> "idle"
            is Registration.Loading -> "loading ${registration.event.lowercase()}"
            is Registration.Registering -> "registering app key"
            is Registration.Registered -> "registered"
            is Registration.Rejected -> "rejected: ${registration.error.description()}"
        })
        sdk.flySafeDownload?.let { (current, total) ->
            more("fly-safe database ${current * 100 / total.coerceAtLeast(1)}%")
        }
        row("AIRCRAFT", if (sdk.aircraftConnected) (sdk.model?.name ?: "connected") else "not connected")

        row("PREVIEW", when (preview) {
            PreviewState.Stopped -> "stopped"
            PreviewState.Waiting -> "waiting for a camera"
            is PreviewState.Bound -> "on ${preview.camera.name.lowercase()}"
        })

        when (tap) {
            TapState.Stopped -> row("TAP", "stopped")
            TapState.Waiting -> row("TAP", "waiting for a camera")
            is TapState.Receiving -> {
                val stats = tap.stats
                val frame = stats.latest
                if (frame == null) {
                    row("TAP", "listening, no frames yet")
                } else {
                    row("TAP", "${frame.mimeType} ${frame.width}x${frame.height}")
                    more("%.1f fps  %s".format(stats.fps, bitrate(stats.bitrateBps)))
                    more("${stats.frames} frames, ${stats.keyFrames} key")
                    more("last: " + frame.nalTypes.joinToString(" ") { AnnexB.name(it) })
                }
            }
        }

        row("PUBLISH", (publisher?.let { "${it.protocol} " } ?: "") + when (publish) {
            null -> "off"
            PublishState.Idle -> "starting"
            is PublishState.Connecting -> "connecting: ${publish.step}"
            PublishState.Connected -> "waiting for keyframe"
            is PublishState.Live -> "live"
            PublishState.Stopping -> "stopping"
            PublishState.Stopped -> "stopped"
            is PublishState.Failed -> "failed: ${publish.reason}"
        })
        if (publish is PublishState.Live) {
            more("${publish.sent} sent, ${publish.dropped} dropped")
            more(bitrate(publish.bitrateBps))
        }
        // Say why Start is unavailable rather than just greying it out. A disabled button with no
        // reason beside it is the least helpful thing a screen can do, and the reason here is the
        // demo's actual subject: there is no point opening a connection to a server before there
        // is a describable stream to put down it.
        if (publisher == null) {
            waitingFor(tap)?.let { more("start needs $it") }
        }
    }

    /**
     * What [TapState.hasLiveMedia] is still missing, or null when nothing is.
     *
     * Ordered from the most fundamental to the most specific, so the reader is told the earliest
     * unmet condition rather than the last one checked.
     */
    private fun waitingFor(tap: TapState): String? = when {
        tap is TapState.Stopped -> "the sdk to register"
        tap is TapState.Waiting -> "a camera"
        tap !is TapState.Receiving -> "a camera"
        tap.stats.frames < 2 -> "frames from the aircraft"
        tap.stats.fps <= 0.0 -> "frames (stalled)"
        !tap.stats.hasParameterSets -> "a keyframe (SPS/PPS)"
        else -> null
    }

    private fun bitrate(bps: Double) = when {
        bps >= 1_000_000 -> "%.2f Mb/s".format(bps / 1_000_000)
        bps >= 1_000 -> "%.0f kb/s".format(bps / 1_000)
        else -> "%.0f b/s".format(bps)
    }

    private fun dji.v5.common.error.IDJIError.description(): String =
        (description() ?: errorCode() ?: toString()).take(60)

    private companion object {

        /** Breathing room inside whatever the system bars leave. */
        const val GUTTER_DP = 12

        /**
         * The readout's label column: the longest label, AIRCRAFT, plus one space. About 30
         * characters are left beside it on a landscape phone; a longer value wraps back to the
         * left edge and breaks the table.
         */
        const val LABEL_WIDTH = 9

        /** Debug switch for the preview surface; see the [preview] field. */
        const val EXTRA_PREVIEW = "preview"
    }
}
