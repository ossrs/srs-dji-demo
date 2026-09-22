package io.ossrs.djidemo.whip

import java.net.URI

/**
 * A WHIP endpoint.
 *
 * WHIP -- WebRTC-HTTP Ingestion Protocol -- replaces the whole of WebRTC's usual signalling dance
 * with one HTTP POST: the publisher sends an SDP offer as the request body and the server returns
 * its answer. There is no websocket, no signalling server and no application protocol to design,
 * which is the entire reason it exists.
 *
 * The URL is therefore just an HTTP URL. SRS spells it
 * `http://host:1985/rtc/v1/whip/?app=live&stream=livestream`, where the stream to publish is in the
 * query string rather than the path, so nothing here tries to take it apart: the server knows what
 * the URL means, and this client only has to post to it.
 */
data class WhipUrl(val endpoint: URI) {

    override fun toString() = endpoint.toString()

    companion object {

        fun parse(url: String): WhipUrl {
            val uri = runCatching { URI(url.trim()) }.getOrNull() ?: throw IllegalArgumentException("bad url")
            require(uri.scheme?.lowercase() in setOf("http", "https")) { "not an http url" }
            require(!uri.host.isNullOrEmpty()) { "missing host" }
            return WhipUrl(uri)
        }
    }
}
