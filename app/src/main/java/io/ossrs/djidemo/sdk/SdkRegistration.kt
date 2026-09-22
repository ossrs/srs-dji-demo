package io.ossrs.djidemo.sdk

import android.content.Context
import android.util.Log
import dji.sdk.keyvalue.key.KeyTools
import dji.sdk.keyvalue.key.ProductKey
import dji.sdk.keyvalue.value.product.ProductType
import dji.v5.common.error.IDJIError
import dji.v5.common.register.DJISDKInitEvent
import dji.v5.manager.KeyManager
import dji.v5.manager.SDKManager
import dji.v5.manager.interfaces.SDKManagerCallback
import dji.v5.network.DJINetworkManager
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

private const val TAG = "SdkRegistration"

/**
 * How far the SDK has got through its two-step `init()` then `registerApp()` sequence.
 *
 * The steps are ordered and cannot be skipped: `registerApp()` is legal only once `init()` has
 * reported [DJISDKInitEvent.INITIALIZE_COMPLETE].
 */
sealed interface Registration {

    /** [SdkRegistration.start] has not run yet. */
    data object Idle : Registration

    /** `init()` is unpacking and loading the SDK. [event] is the last init event reported. */
    data class Loading(val event: String) : Registration

    /** `registerApp()` is in flight. It is a network call to DJI and needs connectivity. */
    data object Registering : Registration

    /** The App Key was accepted. Every other SDK API becomes usable from here on. */
    data object Registered : Registration

    /**
     * Registration was rejected or could not complete. In practice the causes are: no network, a
     * key issued against a different package name, a missing key (the manifest placeholder was
     * never filled in), or a device clock that is badly wrong.
     */
    data class Rejected(val error: IDJIError) : Registration
}

/**
 * One immutable snapshot of everything the screen needs to know about the SDK.
 *
 * @param registration progress through init and App Key registration.
 * @param aircraftConnected whether an aircraft or remote controller is currently attached.
 * @param model the connected model. Separate from [aircraftConnected] because the SDK reports
 *   identity through the key-value system rather than through the connection callback.
 * @param flySafeDownload bytes downloaded to total for the fly-safe database the SDK fetches after
 *   registering, or null when no download is running.
 * @param sdkVersion the MSDK's own version string, or null until the SDK has finished loading. It
 *   cannot be read before then: the version lives in the encrypted payload that `init()` unpacks,
 *   not in the `compileOnly` stub this module is built against.
 */
data class SdkStatus(
    val registration: Registration = Registration.Idle,
    val aircraftConnected: Boolean = false,
    val model: ProductType? = null,
    val flySafeDownload: Pair<Long, Long>? = null,
    val sdkVersion: String? = null,
) {
    val isRegistered: Boolean get() = registration is Registration.Registered
}

/**
 * Drives the MSDK through initialisation and App Key registration and publishes the result.
 *
 * Nothing in this app can talk to an aircraft until [status] reports [Registration.Registered]:
 * `registerApp` is the gate, and a bad key fails in a way that looks like a hardware fault, so the
 * screen shows this state prominently rather than hiding it behind a spinner.
 *
 * Every callback below arrives on an SDK background thread, so all state goes through a
 * [MutableStateFlow] and the re-entry guards are atomics. Nothing here touches a view.
 */
class SdkRegistration {

    private val _status = MutableStateFlow(SdkStatus())

    /** The current SDK status. Safe to collect from any thread. */
    val status: StateFlow<SdkStatus> = _status.asStateFlow()

    /** Guards a second `SDKManager.init()`, which the SDK does not support. */
    private val started = AtomicBoolean(false)

    /** Set once init reports INITIALIZE_COMPLETE, which is what makes `registerApp()` legal. */
    private val loaded = AtomicBoolean(false)

    /** Held while a `registerApp()` call is outstanding so retries cannot overlap it. */
    private val inFlight = AtomicBoolean(false)

    /** Guards attaching the model listener more than once. */
    private val watchingModel = AtomicBoolean(false)

    /** How many times registration has been retried after a failure. */
    private val attempts = AtomicInteger(0)

    /**
     * Retries registration on a delay.
     *
     * A single thread, created lazily and never shut down, because it outlives nothing: this object
     * is process-wide and so is the SDK it drives.
     */
    private val retries: ScheduledExecutorService by lazy {
        Executors.newSingleThreadScheduledExecutor { task ->
            Thread(task, "sdk-registration-retry").apply { isDaemon = true }
        }
    }

    /**
     * Starts initialisation. Call once from `Application.onCreate()`, after `Helper.install()`.
     */
    fun start(context: Context) {
        if (!started.compareAndSet(false, true)) return

        SDKManager.getInstance().init(context.applicationContext, callback)

        // registerApp() fails outright when the device is offline, and the phone is often tethered
        // to a laptop hotspot that comes up after the app does. Retry when connectivity returns.
        DJINetworkManager.getInstance().addNetworkStatusListener { available ->
            if (available) register()
        }
    }

    /**
     * Requests registration if and only if it is both legal and not already happening.
     *
     * Two independent triggers reach here -- init completing and the network returning -- so these
     * checks have to be atomic rather than plain flag reads.
     */
    private fun register() {
        if (!loaded.get()) return
        if (SDKManager.getInstance().isRegistered) return
        if (!inFlight.compareAndSet(false, true)) return

        _status.update { it.copy(registration = Registration.Registering) }
        SDKManager.getInstance().registerApp()
    }

    /**
     * Subscribes to the connected model.
     *
     * The SDK splits this across two channels: [SDKManagerCallback.onProductConnect] says *that*
     * something is attached, while the model name arrives as a key-value update.
     */
    private fun watchModel() {
        if (!watchingModel.compareAndSet(false, true)) return

        KeyManager.getInstance().listen(
            KeyTools.createKey(ProductKey.KeyProductType),
            this,
        ) { _, model ->
            Log.i(TAG, "product type = $model")
            _status.update { it.copy(model = model) }
        }
    }

    /**
     * Tries again after a failure, with a widening delay.
     *
     * The connectivity listener alone is not enough, and the case that proves it is the ordinary
     * one: the app starts while the phone is dozing, or a moment before Wi-Fi finishes associating,
     * and DJI's own error for it is `COULD_NOT_CONNECT_TO_INTERNET`. No connectivity *change*
     * follows -- the network was already there, or came up without the callback firing for this
     * process -- so nothing would ever retry and the app would sit permanently unregistered with
     * an aircraft it refuses to see.
     *
     * Bounded, because the other reason registration fails is a key that will never be accepted:
     * issued for a different package name, or missing because the manifest placeholder was never
     * filled in. Retrying that forever would hide it behind an endlessly hopeful status line.
     */
    private fun scheduleRetry() {
        val attempt = attempts.incrementAndGet()
        if (attempt > MAX_RETRIES) {
            Log.w(TAG, "giving up after $attempt registration attempts")
            return
        }
        val delaySeconds = RETRY_DELAYS_SECONDS[(attempt - 1).coerceAtMost(RETRY_DELAYS_SECONDS.lastIndex)]
        Log.i(TAG, "retrying registration in ${delaySeconds}s (attempt $attempt)")
        retries.schedule(::register, delaySeconds, TimeUnit.SECONDS)
    }

    private val callback = object : SDKManagerCallback {

        override fun onInitProcess(event: DJISDKInitEvent, totalProcess: Int) {
            _status.update { it.copy(registration = Registration.Loading(event.name)) }

            if (event == DJISDKInitEvent.INITIALIZE_COMPLETE) {
                loaded.set(true)
                // Now, and not in start(): before init completes the real SDKManager has not been
                // decrypted and loaded, so this either returns a placeholder or throws. Guarded
                // because a version string is a diagnostic, and no diagnostic is worth taking the
                // app down over.
                val version = runCatching { SDKManager.getInstance().sdkVersion }
                    .onFailure { Log.w(TAG, "could not read the SDK version", it) }
                    .getOrNull()
                _status.update { it.copy(sdkVersion = version) }
                register()
            }
        }

        override fun onRegisterSuccess() {
            Log.i(TAG, "registered")
            inFlight.set(false)
            attempts.set(0)
            _status.update { it.copy(registration = Registration.Registered) }
            watchModel()
        }

        override fun onRegisterFailure(error: IDJIError) {
            Log.w(TAG, "registration failed: $error")
            inFlight.set(false)
            _status.update { it.copy(registration = Registration.Rejected(error)) }
            scheduleRetry()
        }

        override fun onProductConnect(productId: Int) {
            Log.i(TAG, "product connected")
            _status.update { it.copy(aircraftConnected = true) }
        }

        override fun onProductDisconnect(productId: Int) {
            Log.i(TAG, "product disconnected")
            // Drop the cached model with it: the next connection may be a different aircraft.
            _status.update { it.copy(aircraftConnected = false, model = null) }
        }

        override fun onProductChanged(productId: Int) {
            // The new identity arrives through the KeyProductType listener attached above.
        }

        override fun onDatabaseDownloadProgress(current: Long, total: Long) {
            val finished = total > 0 && current >= total
            _status.update { it.copy(flySafeDownload = if (finished) null else current to total) }
        }
    }

    private companion object {

        /**
         * Backoff between attempts. Front-loaded because the overwhelming case is a network that is
         * seconds away from working, and spread out after that so a genuinely bad key is not
         * hammered at DJI's servers.
         */
        val RETRY_DELAYS_SECONDS = longArrayOf(2, 5, 10, 20, 30, 60)

        const val MAX_RETRIES = 6
    }
}
