package io.ossrs.djidemo

import android.app.Application
import android.content.Context
import io.ossrs.djidemo.sdk.SdkRegistration

/**
 * Process entry point.
 *
 * Two things happen here and the order between them is not negotiable: the SDK's class loader is
 * installed before any DJI class is resolved, and registration starts as soon as the process does.
 */
class DemoApplication : Application() {

    /**
     * Process-wide because the SDK it wraps is: `SDKManager.init()` may be called only once and the
     * callback it takes is held until `destroy()`. Owning this from an Activity would re-enter init
     * on every recreation.
     *
     * Lazy is load-bearing, not a style choice. Field initializers run inside the [Application]
     * constructor, which the framework calls *before* [attachBaseContext] -- so building the
     * registrar eagerly would resolve `SDKManagerCallback` before the class loader below exists,
     * and the process would die in its own constructor. Nothing may touch this before [onCreate].
     */
    val sdk: SdkRegistration by lazy { SdkRegistration() }

    /**
     * `dji-sdk-v5-aircraft`'s own `classes.jar` is a few kilobytes and contains nothing but this
     * loader. The real SDK -- `SDKManager` included -- ships encrypted in the AAR's `assets/ac.zip`
     * and is decrypted into the class loader by this call. The `-aircraft-provided` artifact the
     * app compiles against is a stub that is deliberately stripped from the APK.
     *
     * So the call is mandatory, and it has to run before any DJI class is *resolved*, which is why
     * it belongs in `attachBaseContext` rather than `onCreate`. Skip it and the app installs and
     * launches fine, then dies on first contact with the SDK:
     * `NoClassDefFoundError: Failed resolution of: Ldji/v5/manager/SDKManager;`.
     */
    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(base)
        com.cySdkyc.clx.Helper.install(this)
    }

    override fun onCreate() {
        super.onCreate()
        // Registration is a network handshake between the App Key and DJI and needs no aircraft,
        // so there is nothing to wait for: start it here and the app is usable by the time a
        // screen appears, and it survives the Activity being recreated.
        sdk.start(this)
    }
}
