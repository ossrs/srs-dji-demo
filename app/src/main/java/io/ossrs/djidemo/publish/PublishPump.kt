package io.ossrs.djidemo.publish

import android.os.SystemClock
import android.util.Log
import io.ossrs.djidemo.camera.EncodedFrame
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.flow.MutableStateFlow

private const val TAG = "PublishPump"

/** One frame, with its bytes copied out of the SDK's recycled buffer. */
internal class PendingFrame(val data: ByteArray, val frame: EncodedFrame)

/**
 * The protocol-specific half of publishing: open a connection, write frames, close it.
 *
 * Every method is called on the pump's own worker thread and may block. Throwing from any of them
 * ends the publish and the exception message becomes the reason shown on screen.
 */
internal interface PublishTransport {

    /** Connects and completes whatever handshake the protocol needs. Called once. */
    fun open()

    /**
     * Writes one frame. Returns the number of bytes actually put on the wire, which is what the
     * bitrate readout measures -- a frame the transport chose to skip reports zero rather than its
     * payload size.
     */
    fun write(pending: PendingFrame): Int

    /** Releases the connection. Called exactly once, including after [open] or [write] threw. */
    fun close()
}

/**
 * Moves frames from the SDK's callback thread to a transport's own thread.
 *
 * This exists because of one hard constraint: `onEncodedFrame` runs on an SDK thread that also
 * feeds the on-screen preview, and blocking it stalls the picture. Publishing does network I/O, so
 * it cannot happen there. The pump is the handover -- copy the bytes, hand them over, return.
 *
 * The queue is **bounded and drops rather than blocks**. If the uplink is slower than the aircraft's
 * encoder, something has to give, and the only acceptable answer is to lose frames: blocking would
 * push the stall back into the SDK, and an unbounded queue would grow until the process died while
 * sending video that was already seconds stale. Dropped frames are counted and shown, because a
 * rising drop count is the single most useful diagnostic this screen can offer.
 */
internal class PublishPump(
    private val name: String,
    private val state: MutableStateFlow<PublishState>,
    private val transport: PublishTransport,
) {

    private val queue = ArrayBlockingQueue<PendingFrame>(CAPACITY)
    private val running = AtomicBoolean(false)
    private var worker: Thread? = null

    private var sent = 0L
    private var bytes = 0L

    /**
     * Atomic because it is the one counter incremented on the SDK's thread while the worker thread
     * reads it. `@Volatile` would publish the value but not make `++` atomic, so drops would be
     * undercounted exactly when they matter most -- under load, when both threads are busy.
     */
    private val dropped = java.util.concurrent.atomic.AtomicLong()

    private val meter = BitrateMeter()

    /** Starts the worker. Idempotent. */
    fun start() {
        if (!running.compareAndSet(false, true)) return
        state.value = PublishState.Idle
        worker = Thread(::run, name).apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Stops the worker and closes the transport. Idempotent, and safe to call after a failure.
     *
     * The worker is interrupted rather than waited on indefinitely: it is usually parked in a
     * blocking socket write or a queue poll, and the caller is an Activity being destroyed.
     */
    fun stop() {
        if (!running.compareAndSet(true, false)) return
        state.value = PublishState.Stopping
        worker?.interrupt()
        worker = null
        queue.clear()
    }

    /**
     * Offers one frame. Called on the SDK's thread, and does the minimum that thread can get away
     * with: one array copy and one non-blocking enqueue.
     *
     * The copy is not optional. `data` is a buffer DJI reuses for the next callback, so handing the
     * array itself to another thread would deliver whatever the *next* frame happens to contain.
     */
    fun offer(data: ByteArray, offset: Int, length: Int, frame: EncodedFrame) {
        if (!running.get()) return
        val copy = data.copyOfRange(offset, offset + length)
        if (!queue.offer(PendingFrame(copy, frame))) dropped.incrementAndGet()
    }

    private fun run() {
        try {
            transport.open()
            // Announced before the first frame, so a working connection with an idle source is
            // distinguishable from a connection that never completed.
            state.value = PublishState.Connected
            var lastPublishedAt = 0L
            while (running.get()) {
                val pending = queue.poll(POLL_MS, TimeUnit.MILLISECONDS) ?: continue
                val written = transport.write(pending)
                if (written > 0) {
                    sent++
                    bytes += written
                    meter.record(written)
                }
                // Sampled rather than pushed per frame: frames arrive about thirty times a second
                // and the status column cannot usefully be rewritten that often. The counters stay
                // exact; only how often they are published is throttled.
                // Nothing written yet means the transport is still waiting for a keyframe to begin
                // with, so the state stays Connected. Reporting Live with zero frames sent would
                // claim a stream the server cannot play yet.
                val now = SystemClock.elapsedRealtime()
                if (sent > 0 && now - lastPublishedAt >= PUBLISH_INTERVAL_MS) {
                    lastPublishedAt = now
                    state.value = PublishState.Live(sent, dropped.get(), bytes, meter.bitrateBps())
                }
            }
        } catch (_: InterruptedException) {
            // stop() interrupted a blocking wait. Ordinary shutdown, not a failure.
        } catch (t: Throwable) {
            Log.w(TAG, "$name failed", t)
            if (running.get()) {
                state.value = PublishState.Failed(t.message?.take(80) ?: t.javaClass.simpleName)
            }
        } finally {
            runCatching { transport.close() }
            running.set(false)
            if (state.value is PublishState.Stopping ||
                state.value is PublishState.Live ||
                state.value is PublishState.Connected
            ) {
                state.value = PublishState.Stopped
            }
        }
    }

    private companion object {

        /**
         * About two seconds of video at 30 fps. Long enough to ride out a brief stall in the
         * uplink, short enough that what finally goes out is not uselessly old.
         */
        const val CAPACITY = 60

        /** Short enough that stop() is responsive without interrupt, cheap enough to spin on. */
        const val POLL_MS = 200L

        /** 5 Hz, matching the tap's own cadence so the two halves of the screen agree. */
        const val PUBLISH_INTERVAL_MS = 200L
    }
}

/**
 * Bits per second over a sliding window of what was actually written.
 *
 * Measured over a window rather than averaged from the start, for the same reason the tap's figure
 * is: an average since connect keeps reporting a healthy rate through a stall.
 */
internal class BitrateMeter(private val windowMs: Long = 2_000) {

    private val times = ArrayDeque<Long>()
    private val sizes = ArrayDeque<Int>()
    private var total = 0L

    @Synchronized
    fun record(byteCount: Int) {
        val now = SystemClock.elapsedRealtime()
        times.addLast(now)
        sizes.addLast(byteCount)
        total += byteCount
        evict(now)
    }

    @Synchronized
    fun bitrateBps(): Double {
        val now = SystemClock.elapsedRealtime()
        evict(now)
        val oldest = times.firstOrNull() ?: return 0.0
        val spanMs = now - oldest
        if (spanMs <= 0) return 0.0
        return total * 8 * 1000.0 / spanMs
    }

    private fun evict(now: Long) {
        while (times.isNotEmpty() && now - times.first() > windowMs) {
            times.removeFirst()
            total -= sizes.removeFirst()
        }
    }
}
