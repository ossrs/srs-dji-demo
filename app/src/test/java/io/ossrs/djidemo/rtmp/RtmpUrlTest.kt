package io.ossrs.djidemo.rtmp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class RtmpUrlTest {

    @Test
    fun `splits the last path segment off as the stream name`() {
        val url = RtmpUrl.parse("rtmp://192.168.1.10:1935/live/livestream")
        assertEquals("192.168.1.10", url.host)
        assertEquals(1935, url.port)
        assertEquals("live", url.app)
        assertEquals("livestream", url.streamName)
        assertEquals("rtmp://192.168.1.10:1935/live", url.tcUrl)
    }

    @Test
    fun `a missing port means the default`() {
        assertEquals(RtmpUrl.DEFAULT_PORT, RtmpUrl.parse("rtmp://host/live/stream").port)
    }

    @Test
    fun `a multi level application keeps everything but the last segment`() {
        val url = RtmpUrl.parse("rtmp://host/live/sub/stream")
        assertEquals("live/sub", url.app)
        assertEquals("stream", url.streamName)
    }

    @Test
    fun `a query string stays with the stream name and out of the tcUrl`() {
        val url = RtmpUrl.parse("rtmp://host:1935/live/stream?vhost=example.com")
        assertEquals("stream?vhost=example.com", url.streamName)
        assertEquals("live", url.app)
        assertEquals("rtmp://host:1935/live", url.tcUrl)
    }

    @Test
    fun `rejects what it cannot publish to`() {
        assertThrows(IllegalArgumentException::class.java) { RtmpUrl.parse("http://host/live/stream") }
        // No application to publish into, which RTMP's connect command requires.
        assertThrows(IllegalArgumentException::class.java) { RtmpUrl.parse("rtmp://host/stream") }
        assertThrows(IllegalArgumentException::class.java) { RtmpUrl.parse("rtmp://host:abc/live/stream") }
        assertThrows(IllegalArgumentException::class.java) { RtmpUrl.parse("rtmp:///live/stream") }
    }
}
