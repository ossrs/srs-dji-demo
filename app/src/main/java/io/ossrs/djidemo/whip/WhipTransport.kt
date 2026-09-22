package io.ossrs.djidemo.whip

import android.util.Log
import io.ossrs.djidemo.whip.dtls.DtlsChannel
import io.ossrs.djidemo.whip.ice.StunMessage
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.security.SecureRandom

private const val TAG = "WhipTransport"

/**
 * The single UDP socket that carries everything: ICE checks, the DTLS handshake, and the media.
 *
 * One socket for three protocols is not a shortcut -- it is how WebRTC is specified to work, and it
 * is what makes it able to cross a NAT at all. A NAT will let return traffic back to a port it has
 * seen outbound traffic from, so every additional port would be another hole to punch. Everything
 * therefore goes through one, and the three protocols are told apart by their first byte: RFC 7983
 * assigns 0-3 to STUN, 20-63 to DTLS and 128-191 to RTP and RTCP, with no overlap.
 *
 * ICE is reduced to its simplest useful form. This client offers no candidates of its own and
 * simply dials the server's, which is the right shape for a publisher on a phone talking to a
 * server with a routable address: there is exactly one path to try, so there is nothing to
 * prioritise and nothing to choose between.
 */
internal class WhipTransport(
    private val candidate: Sdp.Candidate,
    private val localUfrag: String,
    private val localPwd: String,
    private val remoteUfrag: String,
    private val remotePwd: String,
) : DtlsChannel {

    private val socket = DatagramSocket()
    private val random = SecureRandom()
    private val tieBreaker = random.nextLong() and Long.MAX_VALUE

    private val buffer = ByteArray(2048)

    /**
     * Non-STUN datagrams that arrived while ICE was still running, held for the DTLS layer.
     *
     * The offer says `a=setup:actpass`, so the server is entitled to choose `active` and open the
     * handshake the instant the path works -- possibly before [connect] has seen its own binding
     * response. Keeping such a record costs nothing and saves a retransmit; dropping it used to be
     * invisible because [connect] never got that far.
     *
     * Only written by [connect], and only read afterwards, so the handover is safe without a lock.
     */
    private val pendingForDtls = ArrayDeque<ByteArray>()

    @Volatile private var closed = false
    private var keepaliveThread: Thread? = null

    /**
     * Connects the socket and runs ICE connectivity checks until the server answers one.
     *
     * A connected UDP socket is used rather than an unconnected one because it makes the kernel
     * drop datagrams from anywhere else, which removes a whole class of off-path injection without
     * a line of code. The answer this waits for has to be authenticated -- an unauthenticated
     * success response proves nothing, since anyone who can see the request can forge one.
     */
    fun connect() {
        socket.soTimeout = SOCKET_TIMEOUT_MS
        socket.connect(InetSocketAddress(InetAddress.getByName(candidate.host), candidate.port))

        val deadline = System.currentTimeMillis() + ICE_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            val transactionId = StunMessage.newTransactionId()
            send(
                StunMessage.bindingRequest(
                    transactionId = transactionId,
                    // The username is the peer's fragment first, then ours. The order is part of
                    // the protocol, not a convention, and reversing it produces checks the server
                    // discards in silence.
                    username = "$remoteUfrag:$localUfrag",
                    // Integrity on an outgoing check is keyed with the password of whoever has to
                    // verify it -- so the server's, from its SDP answer.
                    password = remotePwd,
                    priority = HOST_CANDIDATE_PRIORITY,
                    tieBreaker = tieBreaker,
                    // This client is ICE-controlling with a single candidate pair, so there is
                    // nothing to compare and the first check can nominate the pair outright.
                    useCandidate = true,
                ),
            )

            // Read raw datagrams here, deliberately NOT through receive(). That override exists
            // to hide STUN from the DTLS layer, so it answers requests and swallows everything
            // else STUN-shaped -- including the binding *response* this loop is waiting for. Going
            // through it meant the check could never succeed: receive() returned only non-STUN
            // datagrams, there are none during ICE, so every attempt timed out and the whole
            // connect() failed after ICE_TIMEOUT_MS with the path actually working.
            val checkDeadline = System.currentTimeMillis() + CHECK_INTERVAL_MS
            while (true) {
                val remaining = (checkDeadline - System.currentTimeMillis()).toInt()
                if (remaining <= 0) break
                val datagram = readDatagram(remaining) ?: break

                if (!StunMessage.looksLikeStun(datagram, datagram.size)) {
                    pendingForDtls += datagram
                    continue
                }
                val parsed = StunMessage.parse(datagram, datagram.size) ?: continue

                if (parsed.isRequest) {
                    answerCheck(parsed)
                    continue
                }
                if (!parsed.isSuccess) continue
                if (!parsed.transactionId.contentEquals(transactionId)) continue
                if (!StunMessage.verifyIntegrity(parsed, remotePwd)) {
                    Log.w(TAG, "discarding a binding response that failed integrity")
                    continue
                }
                Log.i(TAG, "ice connectivity check succeeded")
                return
            }
        }
        throw IllegalStateException("ice connectivity check timed out")
    }

    /**
     * Answers the server's own connectivity check.
     *
     * ICE requires both directions to be verified, so the server sends checks too, keyed with the
     * password this client published. Failing to answer them leaves the server believing the path
     * is one-way, and it will eventually stop sending.
     */
    private fun answerCheck(request: StunMessage.Parsed) {
        if (!StunMessage.verifyIntegrity(request, localPwd)) {
            Log.w(TAG, "discarding a binding request that failed integrity")
            return
        }
        send(
            StunMessage.bindingSuccess(
                transactionId = request.transactionId,
                password = localPwd,
                mappedAddress = InetAddress.getByName(candidate.host).address,
                mappedPort = candidate.port,
            ),
        )
    }

    /**
     * Keeps answering the server's checks for the rest of the session.
     *
     * Started once the handshake is done, because until then the handshake loop is reading the
     * socket itself and a second reader would steal its records.
     */
    fun startKeepalive() {
        keepaliveThread = Thread({
            while (!closed) {
                // Pumping receive() is the whole job: it answers the server's checks as a side
                // effect. Testing what it returns for STUN would be dead code -- it never returns
                // STUN. What it does return is inbound media or RTCP, which a send-only publisher
                // has no use for, so it is dropped.
                runCatching { receive(SOCKET_TIMEOUT_MS) }.getOrNull()
            }
        }, "whip-ice-keepalive").apply {
            isDaemon = true
            start()
        }
    }

    // ---- DtlsChannel ---------------------------------------------------------------------------

    override fun send(datagram: ByteArray) {
        if (closed) return
        socket.send(DatagramPacket(datagram, datagram.size))
    }

    /**
     * Returns the next DTLS datagram, answering any ICE check that arrives in the meantime.
     *
     * The handshake must not see STUN traffic and the ICE layer must not see DTLS records, so the
     * demultiplexing happens here where both are visible.
     */
    override fun receive(timeoutMs: Int): ByteArray? {
        pendingForDtls.removeFirstOrNull()?.let { return it }

        val deadline = System.currentTimeMillis() + timeoutMs
        while (!closed) {
            val remaining = (deadline - System.currentTimeMillis()).toInt()
            if (remaining <= 0) return null

            val datagram = readDatagram(remaining) ?: return null
            if (StunMessage.looksLikeStun(datagram, datagram.size)) {
                StunMessage.parse(datagram, datagram.size)
                    ?.takeIf { it.isRequest }
                    ?.let(::answerCheck)
                continue
            }
            return datagram
        }
        return null
    }

    private fun readDatagram(timeoutMs: Int): ByteArray? {
        socket.soTimeout = timeoutMs.coerceIn(1, SOCKET_TIMEOUT_MS)
        val packet = DatagramPacket(buffer, buffer.size)
        return try {
            socket.receive(packet)
            packet.data.copyOf(packet.length)
        } catch (_: SocketTimeoutException) {
            null
        }
    }

    fun close() {
        closed = true
        keepaliveThread?.interrupt()
        keepaliveThread = null
        runCatching { socket.close() }
    }

    private companion object {

        /**
         * The priority a host candidate over UDP would have, per RFC 8445's formula with the
         * recommended type preference of 126 and one component. The server does not act on it here,
         * but the attribute is mandatory in a check.
         */
        const val HOST_CANDIDATE_PRIORITY = 2113937151L

        const val ICE_TIMEOUT_MS = 10_000L
        const val CHECK_INTERVAL_MS = 400
        const val SOCKET_TIMEOUT_MS = 1_000
    }
}
