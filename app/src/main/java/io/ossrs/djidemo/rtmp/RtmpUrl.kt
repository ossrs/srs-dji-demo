package io.ossrs.djidemo.rtmp

/**
 * A publish URL, split the way RTMP's `connect` and `publish` commands need it.
 *
 * RTMP has no separate "stream key" field, which is the thing that surprises people arriving from
 * other services: the app and the stream name are both just path segments, and the split between
 * them is a convention rather than a delimiter. The convention every server and encoder follows is
 * that the **last** segment is the stream name and everything before it is the application, so
 * `rtmp://host:1935/live/livestream` publishes `livestream` into the `live` application.
 *
 * @param tcUrl what `connect` announces as the application's URL, which is the original URL with
 *   the stream name removed.
 */
data class RtmpUrl(
    val host: String,
    val port: Int,
    val app: String,
    val streamName: String,
    val tcUrl: String,
) {

    companion object {

        /** The IANA-assigned RTMP port, used when the URL leaves it out. */
        const val DEFAULT_PORT = 1935

        /**
         * Parses [url], or throws [IllegalArgumentException] with a message short enough to show
         * under the input field.
         */
        fun parse(url: String): RtmpUrl {
            val trimmed = url.trim()
            val afterScheme = trimmed.removePrefix("rtmp://")
            require(afterScheme != trimmed) { "not an rtmp url" }

            val authority = afterScheme.substringBefore('/')
            require(authority.isNotEmpty()) { "missing host" }
            val path = afterScheme.substringAfter('/', missingDelimiterValue = "")

            val host = authority.substringBefore(':')
            require(host.isNotEmpty()) { "missing host" }
            val port = authority.substringAfter(':', missingDelimiterValue = "").let {
                if (it.isEmpty()) DEFAULT_PORT else {
                    it.toIntOrNull()?.takeIf { n -> n in 1..65535 } ?: throw IllegalArgumentException("bad port")
                }
            }

            // A query string belongs to the stream name -- SRS uses it for vhost and tokens -- so
            // it is kept attached rather than stripped, and it is not allowed to confuse the split.
            val query = path.substringAfter('?', missingDelimiterValue = "")
            val segments = path.substringBefore('?').split('/').filter { it.isNotEmpty() }
            require(segments.size >= 2) { "need /app/stream" }

            val app = segments.dropLast(1).joinToString("/")
            val stream = segments.last() + if (query.isEmpty()) "" else "?$query"

            return RtmpUrl(
                host = host,
                port = port,
                app = app,
                streamName = stream,
                tcUrl = "rtmp://$authority/$app",
            )
        }
    }
}
