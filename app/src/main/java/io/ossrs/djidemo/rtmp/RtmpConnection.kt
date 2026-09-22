package io.ossrs.djidemo.rtmp

import android.util.Log
import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.EOFException
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.SecureRandom

private const val TAG = "RtmpConnection"

/** One reassembled RTMP message. */
internal class RtmpMessage(
    val typeId: Int,
    val streamId: Int,
    val timestamp: Long,
    val payload: ByteArray,
)

/**
 * An RTMP client connection, carrying exactly enough of the protocol to publish video.
 *
 * RTMP multiplexes messages over a single TCP connection by cutting them into **chunks** on numbered
 * chunk streams, so that a large video message cannot monopolise the link and starve a small control
 * message behind it. That is the whole idea, and it is the only structural thing about RTMP worth
 * understanding before reading this file: everything else is a header layout.
 *
 * What this implements:
 *
 * - the simple handshake (C0/C1/C2 against S0/S1/S2), which is what every server accepts and which
 *   the complex, digest-signed variant was only ever needed for by Flash;
 * - chunk encoding for outgoing messages, and full chunk reassembly for incoming ones;
 * - the `connect` / `createStream` / `publish` command sequence;
 * - the protocol control messages that matter (chunk size, acknowledgements, ping replies).
 *
 * What it does not implement: playback, audio, seeking, the complex handshake, AMF3, and any
 * response the server might send other than the ones this sequence waits for.
 *
 * Not thread-safe. One publisher thread owns it, and the drain thread only reads.
 */
internal class RtmpConnection(private val url: RtmpUrl) {

    private lateinit var socket: Socket
    private lateinit var input: DataInputStream
    private lateinit var output: OutputStream

    /** Chunk size for what this client writes. Announced to the server right after the handshake. */
    private var outgoingChunkSize = PREFERRED_CHUNK_SIZE

    /** Chunk size for what the server writes. 128 until it says otherwise, which it always does. */
    private var incomingChunkSize = DEFAULT_CHUNK_SIZE

    /** Per-chunk-stream state, which is what makes the compressed header formats decodable. */
    private val incoming = HashMap<Int, ChunkStreamState>()

    private var bytesRead = 0L
    private var lastAcknowledged = 0L
    private var ackWindow = DEFAULT_ACK_WINDOW

    private var nextTransactionId = 1.0
    private var streamId = 0

    @Volatile private var closed = false
    private var drainThread: Thread? = null

    /**
     * Serialises writes to the socket.
     *
     * Once [startDraining] is running there are two writers: the publisher thread sending video,
     * and the drain thread answering pings and acknowledgements. Chunks from the two interleaving
     * mid-message would corrupt the stream in a way that looks like a decoder bug at the far end.
     */
    private val writeLock = Any()

    /** Connects, handshakes, and runs the command sequence up to a confirmed publish. */
    fun connectAndPublish(onStep: (String) -> Unit) {
        onStep("tcp")
        socket = Socket().apply {
            tcpNoDelay = true
            soTimeout = READ_TIMEOUT_MS
            connect(InetSocketAddress(url.host, url.port), CONNECT_TIMEOUT_MS)
        }
        input = DataInputStream(BufferedInputStream(socket.getInputStream(), 64 * 1024))
        output = BufferedOutputStream(socket.getOutputStream(), 64 * 1024)

        onStep("handshake")
        handshake()

        // Announce the larger chunk size before anything else. At the 128-byte default a 1080p
        // keyframe is cut into hundreds of chunks, each with its own header, which is pure overhead.
        writeMessage(CSID_CONTROL, 0, TYPE_SET_CHUNK_SIZE, 0, beInt(PREFERRED_CHUNK_SIZE))
        outgoingChunkSize = PREFERRED_CHUNK_SIZE
        flush()

        onStep("connect")
        sendConnect()
        awaitResult("connect")

        onStep("createStream")
        val transaction = sendCreateStream()
        streamId = awaitCreateStreamResult(transaction)

        onStep("publish")
        sendPublish()
        awaitPublishStart()

        // Metadata is deliberately not sent here: the real dimensions are not known until the
        // first frame has been seen, and announcing zeroes now would mean announcing them twice.
        // RtmpVideoPublisher sends it once, together with the AVC sequence header.
        startDraining()
    }

    /**
     * The simple handshake: three 1537- and 1536-byte blobs in each direction.
     *
     * C1 and S1 are a timestamp, four zero bytes and 1528 bytes of filler; C2 and S2 are each an
     * echo of the peer's block. The complex handshake signs that filler with an HMAC, which Flash
     * required and no server insists on -- SRS, nginx-rtmp and ffmpeg all accept this form.
     */
    private fun handshake() {
        val c1 = ByteArray(HANDSHAKE_SIZE)
        SecureRandom().nextBytes(c1)
        // Timestamp zero and the mandatory four zero bytes that mark the simple handshake.
        for (i in 0 until 8) c1[i] = 0

        output.write(RTMP_VERSION)
        output.write(c1)
        flush()

        val s0 = input.readUnsignedByte()
        require(s0 == RTMP_VERSION) { "server speaks rtmp version $s0" }

        val s1 = ByteArray(HANDSHAKE_SIZE).also { input.readFully(it) }
        output.write(s1) // C2 echoes S1
        flush()

        val s2 = ByteArray(HANDSHAKE_SIZE).also { input.readFully(it) }
        // S2 should echo C1. Servers vary in how faithfully they do it, and nothing downstream
        // depends on it, so a mismatch is logged rather than fatal.
        if (!s2.contentEquals(c1)) Log.d(TAG, "S2 did not echo C1; continuing")
    }

    private fun sendConnect() {
        val body = Amf0Writer()
            .string("connect")
            .number(nextTransactionId++)
            .obj {
                put("app", url.app)
                put("type", "nonprivate")
                put("flashVer", FLASH_VERSION)
                put("tcUrl", url.tcUrl)
                // This client publishes and never plays, and saying so lets the server skip
                // setting up a playback path it would never use.
                put("fpad", false)
                put("capabilities", 15)
                put("audioCodecs", 0)
                put("videoCodecs", SUPPORT_VID_H264)
                put("videoFunction", 1)
            }
            .toByteArray()
        writeMessage(CSID_COMMAND, 0, TYPE_AMF0_COMMAND, 0, body)
        flush()
    }

    private fun sendCreateStream(): Double {
        val transaction = nextTransactionId++
        val body = Amf0Writer()
            .string("createStream")
            .number(transaction)
            .nullValue()
            .toByteArray()
        writeMessage(CSID_COMMAND, 0, TYPE_AMF0_COMMAND, 0, body)
        flush()
        return transaction
    }

    private fun sendPublish() {
        val body = Amf0Writer()
            .string("publish")
            // The publish command's transaction id is conventionally 0: it is answered with
            // onStatus rather than _result, so there is no reply to correlate.
            .number(0.0)
            .nullValue()
            .string(url.streamName)
            .string("live")
            .toByteArray()
        writeMessage(CSID_STREAM, streamId, TYPE_AMF0_COMMAND, 0, body)
        flush()
    }

    /**
     * Announces the stream's shape before any media.
     *
     * Players use this to size themselves before the first keyframe arrives, and SRS echoes it to
     * subscribers. The real dimensions are not known until the first frame has been seen, so this
     * is sent with what the tap reported and no more. Audio is absent throughout, and saying so
     * explicitly is better than leaving a player to wait for a track that never comes.
     */
    fun sendMetadata(width: Int = 0, height: Int = 0, frameRate: Double = 0.0) {
        val body = Amf0Writer()
            .string("@setDataFrame")
            .string("onMetaData")
            .ecmaArray {
                if (width > 0) put("width", width)
                if (height > 0) put("height", height)
                if (frameRate > 0) put("framerate", frameRate)
                put("videocodecid", CODEC_ID_AVC)
                put("audiocodecid", 0)
                put("encoder", FLASH_VERSION)
            }
            .toByteArray()
        writeMessage(CSID_STREAM, streamId, TYPE_AMF0_DATA, 0, body)
        flush()
    }

    /** Writes one FLV video payload as an RTMP video message at [timestampMs]. */
    fun sendVideo(payload: ByteArray, timestampMs: Long): Int =
        writeMessage(CSID_VIDEO, streamId, TYPE_VIDEO, timestampMs, payload).also { flush() }

    fun close() {
        closed = true
        drainThread?.interrupt()
        drainThread = null
        runCatching { if (::socket.isInitialized) socket.close() }
    }

    // ---- command replies -------------------------------------------------------------------

    /** Reads until the server answers a command with `_result`, or rejects it with `_error`. */
    private fun awaitResult(what: String) {
        repeat(MAX_REPLY_MESSAGES) {
            val message = readMessage()
            if (message.typeId != TYPE_AMF0_COMMAND) return@repeat
            when (val name = Amf0Reader(message.payload).readValue()) {
                "_result" -> return
                "_error" -> throw IllegalStateException("$what rejected by server")
                else -> Log.d(TAG, "ignoring command $name while awaiting $what")
            }
        }
        throw IllegalStateException("no reply to $what")
    }

    /** Reads until the `_result` for [transaction], whose fourth value is the new stream id. */
    private fun awaitCreateStreamResult(transaction: Double): Int {
        repeat(MAX_REPLY_MESSAGES) {
            val message = readMessage()
            if (message.typeId != TYPE_AMF0_COMMAND) return@repeat
            val reader = Amf0Reader(message.payload)
            val name = reader.readValue()
            val id = reader.readValue() as? Double
            if (name == "_error") throw IllegalStateException("createStream rejected")
            if (name != "_result" || id != transaction) return@repeat
            reader.readValue() // command object, conventionally null here
            val stream = reader.readValue() as? Double
                ?: throw IllegalStateException("createStream returned no stream id")
            return stream.toInt()
        }
        throw IllegalStateException("no reply to createStream")
    }

    /**
     * Reads until the server reports the publish started, or says why it will not.
     *
     * `onStatus` carries the outcome in the `code` property of its information object. The one this
     * client is waiting for is `NetStream.Publish.Start`; anything whose level is `error` is fatal
     * and its own code is the most useful message this app can put on screen.
     */
    private fun awaitPublishStart() {
        repeat(MAX_REPLY_MESSAGES) {
            val message = readMessage()
            if (message.typeId != TYPE_AMF0_COMMAND) return@repeat
            val reader = Amf0Reader(message.payload)
            if (reader.readValue() != "onStatus") return@repeat
            reader.readValue() // transaction id, always 0 for onStatus
            reader.readValue() // command object, null
            val info = reader.readValue() as? Map<*, *> ?: return@repeat
            val code = info["code"] as? String
            when {
                code == "NetStream.Publish.Start" -> return
                info["level"] == "error" -> throw IllegalStateException(code ?: "publish rejected")
                else -> Log.d(TAG, "ignoring status $code")
            }
        }
        throw IllegalStateException("server never confirmed publish")
    }

    /**
     * Drains the connection for the rest of the session.
     *
     * A publisher has almost nothing to read, which makes it tempting to never read at all -- and
     * that is a slow-motion failure: the server's small periodic messages fill this socket's
     * receive buffer, and once it is full the server blocks writing to it and eventually drops the
     * connection. So the messages are read and thrown away, except the two that need an answer.
     */
    private fun startDraining() {
        drainThread = Thread({
            while (!closed) {
                try {
                    handleControl(readMessage())
                } catch (_: java.net.SocketTimeoutException) {
                    // Nothing to read is the normal case for a publisher.
                } catch (t: Throwable) {
                    if (!closed) Log.d(TAG, "drain ended: ${t.message}")
                    return@Thread
                }
            }
        }, "rtmp-drain").apply {
            isDaemon = true
            start()
        }
    }

    // ---- chunk layer -----------------------------------------------------------------------

    /**
     * Writes one message, cut into chunks of at most [outgoingChunkSize] bytes.
     *
     * The first chunk carries a type 0 header, which states the timestamp, length, type and stream
     * id in full; every continuation carries a type 3 header, which states nothing and means "more
     * of the same message". The compressed type 1 and 2 headers would save a handful of bytes per
     * message and are not worth the state they require on the writing side.
     *
     * Returns the total number of bytes written, headers included, so the caller can measure what
     * the protocol really costs rather than what the payload weighs.
     */
    private fun writeMessage(
        csid: Int,
        messageStreamId: Int,
        typeId: Int,
        timestamp: Long,
        payload: ByteArray,
    ): Int = synchronized(writeLock) {
        var written = 0
        val extended = timestamp >= EXTENDED_TIMESTAMP_MARKER

        // Type 0 basic + message header.
        output.write(csid) // fmt 0 occupies the top two bits, which are zero
        writeUInt24(if (extended) EXTENDED_TIMESTAMP_MARKER else timestamp.toInt())
        writeUInt24(payload.size)
        output.write(typeId)
        // The message stream id is the one little-endian field in the whole protocol.
        output.write(messageStreamId and 0xFF)
        output.write((messageStreamId ushr 8) and 0xFF)
        output.write((messageStreamId ushr 16) and 0xFF)
        output.write((messageStreamId ushr 24) and 0xFF)
        if (extended) writeUInt32(timestamp)
        written += 12 + if (extended) 4 else 0

        var offset = 0
        while (offset < payload.size) {
            if (offset > 0) {
                output.write(0xC0 or csid) // fmt 3, same chunk stream
                written += 1
                // A continuation chunk of a message with an extended timestamp repeats it. This is
                // the single most common RTMP interoperability bug in both directions.
                if (extended) {
                    writeUInt32(timestamp)
                    written += 4
                }
            }
            val size = minOf(outgoingChunkSize, payload.size - offset)
            output.write(payload, offset, size)
            written += size
            offset += size
        }
        return written
    }

    private fun flush() = synchronized(writeLock) { output.flush() }

    /** Reads one complete message, reassembling it across as many chunks as it took. */
    private fun readMessage(): RtmpMessage {
        while (true) {
            val basic = input.read()
            if (basic < 0) throw EOFException("server closed the connection")
            val format = (basic ushr 6) and 0x03
            val csid = when (val id = basic and 0x3F) {
                0 -> 64 + input.readUnsignedByte()
                1 -> { val low = input.readUnsignedByte(); val high = input.readUnsignedByte(); 64 + low + (high shl 8) }
                else -> id
            }

            val state = incoming.getOrPut(csid) { ChunkStreamState() }

            when (format) {
                0 -> {
                    state.timestamp = readUInt24().toLong()
                    state.length = readUInt24()
                    state.typeId = input.readUnsignedByte()
                    state.streamId = readLittleEndianInt()
                    state.extended = state.timestamp == EXTENDED_TIMESTAMP_MARKER.toLong()
                    if (state.extended) state.timestamp = readUInt32()
                }
                1 -> {
                    val delta = readUInt24().toLong()
                    state.length = readUInt24()
                    state.typeId = input.readUnsignedByte()
                    state.extended = delta == EXTENDED_TIMESTAMP_MARKER.toLong()
                    state.timestamp += if (state.extended) readUInt32() else delta
                }
                2 -> {
                    val delta = readUInt24().toLong()
                    state.extended = delta == EXTENDED_TIMESTAMP_MARKER.toLong()
                    state.timestamp += if (state.extended) readUInt32() else delta
                }
                else -> {
                    // fmt 3 continues whatever this chunk stream was doing. If it is starting a new
                    // message rather than continuing one, the previous header's values still apply.
                    if (state.extended && state.pending == null) state.timestamp = readUInt32()
                    else if (state.extended) readUInt32()
                }
            }

            val buffer = state.pending ?: ByteArray(state.length).also { state.pending = it; state.filled = 0 }
            val size = minOf(incomingChunkSize, buffer.size - state.filled)
            input.readFully(buffer, state.filled, size)
            state.filled += size
            bytesRead += size

            acknowledgeIfDue()

            if (state.filled == buffer.size) {
                state.pending = null
                val message = RtmpMessage(state.typeId, state.streamId, state.timestamp, buffer)
                if (isControl(message.typeId)) {
                    handleControl(message)
                    continue
                }
                return message
            }
        }
    }

    private fun isControl(typeId: Int) = typeId in intArrayOf(
        TYPE_SET_CHUNK_SIZE, TYPE_ABORT, TYPE_ACKNOWLEDGEMENT,
        TYPE_USER_CONTROL, TYPE_WINDOW_ACK_SIZE, TYPE_SET_PEER_BANDWIDTH,
    )

    /** Applies the protocol control messages that change how the rest of the session is read. */
    private fun handleControl(message: RtmpMessage) {
        when (message.typeId) {
            TYPE_SET_CHUNK_SIZE -> {
                incomingChunkSize = beInt(message.payload).coerceIn(1, MAX_CHUNK_SIZE)
                Log.d(TAG, "server chunk size $incomingChunkSize")
            }
            TYPE_WINDOW_ACK_SIZE -> ackWindow = beInt(message.payload).coerceAtLeast(1)
            TYPE_SET_PEER_BANDWIDTH -> {
                // The server is telling this client how much it may have outstanding. Echoing the
                // window back is what every encoder does and what servers expect to see.
                ackWindow = beInt(message.payload).coerceAtLeast(1)
                writeMessage(CSID_CONTROL, 0, TYPE_WINDOW_ACK_SIZE, 0, beInt(ackWindow))
                flush()
            }
            TYPE_USER_CONTROL -> {
                // Event type 6 is PingRequest; the reply is event type 7 carrying the same payload.
                if (message.payload.size >= 6 && beShort(message.payload) == USER_CONTROL_PING_REQUEST) {
                    val reply = message.payload.copyOf(6)
                    reply[0] = 0
                    reply[1] = USER_CONTROL_PING_RESPONSE.toByte()
                    writeMessage(CSID_CONTROL, 0, TYPE_USER_CONTROL, 0, reply)
                    flush()
                }
            }
        }
    }

    /**
     * Tells the server how much has been received, once a window's worth has gone by.
     *
     * A server that has advertised a window will stop sending after that many unacknowledged bytes,
     * so a client that never acknowledges eventually stalls the conversation.
     */
    private fun acknowledgeIfDue() {
        if (bytesRead - lastAcknowledged < ackWindow) return
        lastAcknowledged = bytesRead
        writeMessage(CSID_CONTROL, 0, TYPE_ACKNOWLEDGEMENT, 0, beInt(bytesRead.toInt()))
        flush()
    }

    // ---- primitives ------------------------------------------------------------------------

    private fun writeUInt24(value: Int) {
        output.write((value ushr 16) and 0xFF)
        output.write((value ushr 8) and 0xFF)
        output.write(value and 0xFF)
    }

    private fun writeUInt32(value: Long) {
        output.write(((value ushr 24) and 0xFF).toInt())
        output.write(((value ushr 16) and 0xFF).toInt())
        output.write(((value ushr 8) and 0xFF).toInt())
        output.write((value and 0xFF).toInt())
    }

    private fun readUInt24(): Int =
        (input.readUnsignedByte() shl 16) or (input.readUnsignedByte() shl 8) or input.readUnsignedByte()

    private fun readUInt32(): Long =
        (readUInt24().toLong() shl 8) or input.readUnsignedByte().toLong()

    private fun readLittleEndianInt(): Int {
        val b0 = input.readUnsignedByte()
        val b1 = input.readUnsignedByte()
        val b2 = input.readUnsignedByte()
        val b3 = input.readUnsignedByte()
        return b0 or (b1 shl 8) or (b2 shl 16) or (b3 shl 24)
    }

    /** Mutable per-chunk-stream state: what the compressed header formats refer back to. */
    private class ChunkStreamState {
        var timestamp = 0L
        var length = 0
        var typeId = 0
        var streamId = 0
        var extended = false
        var pending: ByteArray? = null
        var filled = 0
    }

    companion object {

        const val RTMP_VERSION = 3
        const val HANDSHAKE_SIZE = 1536

        /** Chunk stream ids. Two is reserved for protocol control; the rest are this client's. */
        const val CSID_CONTROL = 2
        const val CSID_COMMAND = 3
        const val CSID_STREAM = 4
        const val CSID_VIDEO = 6

        const val TYPE_SET_CHUNK_SIZE = 1
        const val TYPE_ABORT = 2
        const val TYPE_ACKNOWLEDGEMENT = 3
        const val TYPE_USER_CONTROL = 4
        const val TYPE_WINDOW_ACK_SIZE = 5
        const val TYPE_SET_PEER_BANDWIDTH = 6
        const val TYPE_VIDEO = 9
        const val TYPE_AMF0_DATA = 18
        const val TYPE_AMF0_COMMAND = 20

        const val USER_CONTROL_PING_REQUEST = 6
        const val USER_CONTROL_PING_RESPONSE = 7

        const val DEFAULT_CHUNK_SIZE = 128
        const val MAX_CHUNK_SIZE = 0xFFFFFF

        /**
         * At the 128-byte default every 1080p keyframe is cut into hundreds of chunks. This is the
         * value SRS's own client announces, and it makes the chunk header overhead vanish.
         */
        const val PREFERRED_CHUNK_SIZE = 60_000

        const val DEFAULT_ACK_WINDOW = 5_000_000
        const val EXTENDED_TIMESTAMP_MARKER = 0xFFFFFF

        const val CODEC_ID_AVC = 7
        const val SUPPORT_VID_H264 = 128

        /** Cosmetic, but servers log it, and a recognisable name makes a server log readable. */
        const val FLASH_VERSION = "SRS-DJI-Demo"

        const val CONNECT_TIMEOUT_MS = 5_000
        const val READ_TIMEOUT_MS = 10_000

        /** A bound on how many unrelated messages to step over while waiting for one reply. */
        const val MAX_REPLY_MESSAGES = 32

        fun beInt(value: Int) = byteArrayOf(
            (value ushr 24).toByte(), (value ushr 16).toByte(), (value ushr 8).toByte(), value.toByte(),
        )

        fun beInt(payload: ByteArray): Int =
            ((payload[0].toInt() and 0xFF) shl 24) or ((payload[1].toInt() and 0xFF) shl 16) or
                ((payload[2].toInt() and 0xFF) shl 8) or (payload[3].toInt() and 0xFF)

        fun beShort(payload: ByteArray): Int =
            ((payload[0].toInt() and 0xFF) shl 8) or (payload[1].toInt() and 0xFF)
    }
}
