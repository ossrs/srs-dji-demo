package io.ossrs.djidemo.sdk

import android.util.Log
import dji.v5.manager.diagnostic.DJIDeviceHealthInfo
import dji.v5.manager.diagnostic.DJIDeviceHealthInfoChangeListener
import dji.v5.manager.diagnostic.DeviceHealthManager
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

private const val TAG = "EcoMode"

/**
 * The one aircraft health diagnostic this demo cares about.
 *
 * A grounded Mini 4 Pro that has been sitting idle drops into **Eco Mode** to save battery, and in
 * that state it stops feeding the camera downlink: a newly started app gets a registered SDK, a
 * connected aircraft, a camera index and a bound surface, and then no frames at all. That
 * combination is very easy to misread as a bug in the app, a bad App Key or a cable fault, so the
 * demo names it rather than leaving the reader to guess.
 *
 * MSDK 5.18 exposes no API to turn Eco Mode off, and this app deliberately sends the aircraft no
 * commands, so detection is all that is possible here: the fix is in DJI Fly, or a power cycle.
 */
object EcoModeDiagnostic {

    /** The diagnostic code, as DJI prints it. */
    const val CODE = "0x19000810"

    /**
     * Whether an aircraft-supplied information code is the Eco Mode one.
     *
     * Compared numerically after stripping the prefix rather than by string equality, because the
     * SDK is not consistent about `0x` or about case, and matched on the code rather than on the
     * description because descriptions are localized -- an English-text match would silently stop
     * working on a phone set to another language.
     */
    fun matches(code: String?): Boolean =
        code?.trim()?.removePrefix("0x")?.removePrefix("0X")?.equals("19000810", ignoreCase = true)
            ?: false
}

/**
 * Whether Eco Mode is currently active, and what the aircraft said about it.
 *
 * [description] is the aircraft's own text, shown verbatim instead of a string of this app's own:
 * it is already localized and it is the authority on what the aircraft thinks is wrong.
 */
data class EcoMode(
    val active: Boolean = false,
    val description: String = "",
)

/**
 * Watches `DeviceHealthManager` for [EcoModeDiagnostic].
 *
 * Only that one code is tracked. This is a streaming demo, not an aircraft-health screen, and a
 * general diagnostics panel would be a second subject competing with the first -- the sandbox has
 * one of those, and it is explicitly out of scope here.
 */
class EcoModeWatcher {

    private val _state = MutableStateFlow(EcoMode())

    /**
     * Current Eco Mode status.
     *
     * Written from the SDK's callback thread as well as from [start]; `MutableStateFlow` is
     * thread-safe, and there is no other mutable state here to keep in step with it, so this one
     * needs no handler hop of its own.
     */
    val state: StateFlow<EcoMode> = _state.asStateFlow()

    private var watching = false

    /**
     * Held as a named field, not passed inline: removal is keyed by listener object, so a lambda
     * that cannot be named again could never be removed.
     */
    private val listener = DJIDeviceHealthInfoChangeListener { infos -> publish(infos) }

    /** Begins watching. Idempotent. */
    fun start() {
        if (watching) return
        watching = true
        val health = DeviceHealthManager.getInstance()
        health.addDJIDeviceHealthInfoChangeListener(listener)
        // The listener does not replay, so the state at this moment has to be read directly.
        // Without this, an app started while the aircraft is *already* in Eco Mode shows nothing
        // until the aircraft next changes its mind -- which is the exact case worth reporting.
        publish(health.currentDJIDeviceHealthInfos)
    }

    /** Stops watching and releases the listener held inside the SDK singleton. Idempotent. */
    fun stop() {
        if (!watching) return
        watching = false
        DeviceHealthManager.getInstance().removeDJIDeviceHealthInfoChangeListener(listener)
    }

    /**
     * An empty or Eco-free list means Eco Mode is not active.
     *
     * There is no affirmative "healthy" item to wait for: once Eco Mode is disabled the active
     * list simply goes empty, so absence is the signal rather than a missing notification.
     */
    private fun publish(infos: List<DJIDeviceHealthInfo>?) {
        val eco = infos?.firstOrNull { EcoModeDiagnostic.matches(it.informationCode()) }
        val next = EcoMode(
            active = eco != null,
            description = eco?.description().orEmpty(),
        )
        if (next.active != _state.value.active) Log.i(TAG, "eco mode active=${next.active}")
        _state.value = next
    }
}
