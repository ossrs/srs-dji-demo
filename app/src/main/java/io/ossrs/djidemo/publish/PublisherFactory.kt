package io.ossrs.djidemo.publish

import io.ossrs.djidemo.rtmp.RtmpUrl
import io.ossrs.djidemo.rtmp.RtmpVideoPublisher
import io.ossrs.djidemo.whip.WhipUrl
import io.ossrs.djidemo.whip.WhipVideoPublisher

/**
 * Which protocol a publish URL asks for, and the publisher that speaks it.
 *
 * **The scheme is the protocol selector.** There is deliberately no picker control on the screen:
 * `rtmp://host:1935/live/livestream` and `http://host:1985/rtc/v1/whip/?app=live&stream=livestream`
 * already say which protocol they are, and a picker beside the field would store that same fact a
 * second time, with the standing possibility of the two disagreeing. It is also how ffmpeg, OBS and
 * SRS's own documentation address a server, so a URL from any of them pastes in unchanged.
 */
fun publisherFor(url: String): VideoPublisher = when (schemeOf(url)) {
    "rtmp" -> RtmpVideoPublisher(RtmpUrl.parse(url))
    "http", "https" -> WhipVideoPublisher(WhipUrl.parse(url))
    else -> throw IllegalArgumentException("use rtmp:// or http(s):// for whip")
}

/**
 * Why [url] cannot be published to, or null if it can.
 *
 * Runs before [publisherFor] so a typo becomes a message under the field rather than an exception
 * on a background thread a second later. The text appears on screen, so it is short and lower case.
 */
fun problemWith(url: String): String? {
    val trimmed = url.trim()
    if (trimmed.isEmpty()) return "enter a publish url"

    // Parsed rather than pattern-matched: the publisher parses it in a moment anyway, so whatever
    // the parser rejects here is exactly what would have failed there.
    return when (schemeOf(trimmed)) {
        "rtmp" -> runCatching { RtmpUrl.parse(trimmed) }.exceptionOrNull()?.shortMessage("bad rtmp url")
        "http", "https" -> runCatching { WhipUrl.parse(trimmed) }.exceptionOrNull()?.shortMessage("bad whip url")
        else -> "use rtmp:// or http(s):// for whip"
    }
}

private fun Throwable.shortMessage(fallback: String) =
    message?.takeIf { it.isNotBlank() }?.substringBefore(':') ?: fallback

private fun schemeOf(url: String): String =
    url.trim().substringBefore("://", missingDelimiterValue = "").lowercase()
