package io.ossrs.djidemo.publish

import android.content.Context
import io.ossrs.djidemo.BuildConfig

/**
 * The publish URLs this phone has used, newest first, kept across launches.
 *
 * This is the whole answer to the fact that typing a server address on a phone is miserable. A
 * server is typed once and picked from a list every time after, which matters most in the field:
 * SRS usually runs on a laptop hotspot whose address changes between sessions, and that is exactly
 * when nobody wants to be tapping out an IP address one digit at a time.
 *
 * Stored as plain text in the app's own preferences. These are LAN addresses, not credentials --
 * RTMP has no separate stream key, and anything genuinely secret in a URL would need somewhere
 * better than this.
 */
class PublishTargets(context: Context) {

    private val prefs = context.getSharedPreferences(FILE, Context.MODE_PRIVATE)

    /** Where to publish unless told otherwise: whatever was used last, or the first built-in. */
    val last: String get() = remembered().firstOrNull() ?: DEFAULTS.first()

    /**
     * What the picker offers: everything used before, then the built-ins not yet used.
     *
     * The built-ins stay at the end rather than being seeded into history, so they are always
     * available to fall back to and never push a real server down the list.
     */
    fun recent(): List<String> = (remembered() + DEFAULTS).distinct().take(LIMIT)

    /** Records a URL as the most recent, moving it up if it was already known. */
    fun remember(url: String) {
        val trimmed = url.trim()
        if (trimmed.isEmpty()) return
        val updated = (listOf(trimmed) + remembered()).distinct().take(LIMIT)
        prefs.edit().putString(KEY_RECENT, updated.joinToString(SEPARATOR)).apply()
    }

    private fun remembered(): List<String> =
        prefs.getString(KEY_RECENT, null)
            ?.split(SEPARATOR)
            ?.filter { it.isNotBlank() }
            ?: emptyList()

    private companion object {

        const val FILE = "publish"
        const val KEY_RECENT = "recent"

        /** A newline cannot occur in a URL, so the list needs no escaping. */
        const val SEPARATOR = "\n"

        /** Enough for a couple of sessions' servers, short enough to scan in one look. */
        const val LIMIT = 8

        /**
         * One endpoint per protocol, so that picking between RTMP and WHIP is a tap rather than an
         * edit -- and so the scheme routing is demonstrable on a phone with no history yet.
         *
         * Only the host is configurable; the rest of each URL is spelled out because its shape is
         * itself the lesson: RTMP carries the application and stream as path segments and has no
         * separate stream key, while SRS's WHIP endpoint takes them as query parameters.
         *
         * The host comes from PUBLISH_HOST in gitignored `local.properties`, so nobody's LAN
         * address is committed. Unset it is loopback, which from the phone is the phone -- these
         * defaults are then a template to edit, not a working server.
         */
        val DEFAULTS = listOf(
            "rtmp://${BuildConfig.PUBLISH_HOST}:1935/live/livestream",
            "http://${BuildConfig.PUBLISH_HOST}:1985/rtc/v1/whip/?app=live&stream=livestream",
        )
    }
}
