package io.ossrs.djidemo.whip

import android.util.Log
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

private const val TAG = "WhipSignaling"

/**
 * WHIP's signalling: one HTTP POST out, one SDP answer back.
 *
 * This is the entire protocol, and its whole value. Before WHIP, every WebRTC ingest product
 * invented its own signalling -- a websocket, a JSON envelope, a state machine -- and none of them
 * interoperated. WHIP replaces all of it with a POST whose body is the offer and whose response
 * body is the answer, plus a `Location` header naming a resource to DELETE when finished.
 */
internal object WhipSignaling {

    private const val SDP_CONTENT_TYPE = "application/sdp"

    /** The answer, and the resource to delete when the publish ends. */
    class Session(val answer: String, val resource: URI?)

    /**
     * Posts [offer] and returns the server's answer.
     *
     * A 201 Created is the specified success. Anything else is reported with the server's own
     * response body where there is one, because a WHIP server's error text is usually far more
     * specific than any message this client could invent -- "stream already exists" or "no such
     * application" rather than "signalling failed".
     */
    fun exchange(url: WhipUrl, offer: String): Session {
        val connection = (URL(url.endpoint.toString()).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            connectTimeout = CONNECT_TIMEOUT_MS
            readTimeout = READ_TIMEOUT_MS
            setRequestProperty("Content-Type", SDP_CONTENT_TYPE)
            setRequestProperty("Accept", SDP_CONTENT_TYPE)
        }

        try {
            connection.outputStream.use { it.write(offer.toByteArray(Charsets.UTF_8)) }

            val status = connection.responseCode
            if (status != HttpURLConnection.HTTP_CREATED && status != HttpURLConnection.HTTP_OK) {
                val detail = runCatching {
                    connection.errorStream?.readBytes()?.toString(Charsets.UTF_8)?.trim()
                }.getOrNull()
                throw IOException("whip server returned $status" + if (detail.isNullOrEmpty()) "" else ": ${detail.take(120)}")
            }

            val answer = connection.inputStream.use { it.readBytes().toString(Charsets.UTF_8) }
            require(answer.contains("v=0")) { "whip server did not return an sdp answer" }

            // The Location header may be relative, which is why it is resolved against the request
            // rather than parsed on its own.
            val resource = connection.getHeaderField("Location")
                ?.let { runCatching { url.endpoint.resolve(it) }.getOrNull() }

            return Session(answer, resource)
        } finally {
            connection.disconnect()
        }
    }

    /**
     * Deletes the session resource, which is how a publisher says it has finished.
     *
     * Best effort by design. A server times the session out on its own once the media stops, so
     * failing to delete costs a little tidiness and nothing else -- and the call happens while a
     * publish is already being torn down, often because the network went away in the first place.
     */
    fun delete(resource: URI) {
        runCatching {
            (URL(resource.toString()).openConnection() as HttpURLConnection).apply {
                requestMethod = "DELETE"
                connectTimeout = CONNECT_TIMEOUT_MS
                readTimeout = READ_TIMEOUT_MS
                responseCode
                disconnect()
            }
        }.onFailure { Log.d(TAG, "could not delete the whip resource: ${it.message}") }
    }

    private const val CONNECT_TIMEOUT_MS = 5_000
    private const val READ_TIMEOUT_MS = 10_000
}
