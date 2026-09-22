package io.ossrs.djidemo.whip.dtls

import android.util.Log
import java.io.ByteArrayOutputStream
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.KeyAgreement

private const val TAG = "DtlsClient"

/** What the handshake exists to produce: SRTP's keys, and which SRTP profile they are for. */
internal class SrtpKeyingMaterial(
    val clientMasterKey: ByteArray,
    val clientMasterSalt: ByteArray,
    val serverMasterKey: ByteArray,
    val serverMasterSalt: ByteArray,
)

/** The datagram channel the handshake runs over. Implemented by the WHIP transport. */
internal interface DtlsChannel {

    fun send(datagram: ByteArray)

    /** Returns the next datagram, or null if [timeoutMs] passed with nothing to read. */
    fun receive(timeoutMs: Int): ByteArray?
}

/**
 * A DTLS 1.2 client, narrowed to exactly what DTLS-SRTP needs.
 *
 * In WebRTC the DTLS handshake is not there to encrypt the media -- SRTP does that. It is there to
 * do two other things: prove that the peer holds the certificate whose fingerprint was in the SDP,
 * and produce shared key material for SRTP that an eavesdropper on the signalling channel cannot
 * derive. The media never travels inside DTLS records at all; only the handshake does.
 *
 * Deliberately narrow, and each of these is a decision rather than an omission:
 *
 * - One cipher suite, `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`.
 * - Client role only. The SDP negotiation refuses any answer that would make this the server.
 * - Extended master secret required; the legacy derivation is not implemented.
 * - No session resumption, no renegotiation, no DTLS 1.0 or 1.3, no application data.
 *
 * It is an implementation of one specific conversation, not a TLS library, and should not be
 * mistaken for one or reused as one.
 */
internal class DtlsClient(
    private val certificate: SelfSignedCertificate,
    private val expectedPeerFingerprint: ByteArray,
    private val channel: DtlsChannel,
) {

    private val random = SecureRandom()

    private val clientRandom = ByteArray(32).also(random::nextBytes)
    private lateinit var serverRandom: ByteArray

    /** Our ephemeral ECDHE key pair. Regenerated per handshake, which is what the E stands for. */
    private val ephemeral: KeyPair = KeyPairGenerator.getInstance("EC").run {
        initialize(ECGenParameterSpec("secp256r1"), random)
        generateKeyPair()
    }

    /**
     * Every handshake message, in order, in its canonical unfragmented form.
     *
     * This is the transcript both sides hash into the Finished messages, so anything appended in
     * the wrong order or the wrong form produces a handshake that fails at the very last step with
     * no indication of which message was wrong.
     */
    private val transcript = ByteArrayOutputStream(4096)

    private var nextMessageSeq = 0
    private var writeEpoch = 0
    private var writeSequence = 0L
    private var readEpoch = 0

    private var keys: DtlsCrypto.Keys? = null
    private lateinit var masterSecret: ByteArray

    private var cookie = ByteArray(0)
    private var certificateRequested = false

    /** Reassembly buffers for the server's fragmented handshake messages, keyed by message_seq. */
    private val reassembly = HashMap<Int, Reassembly>()

    /** Complete server messages waiting to be processed, in arrival order. */
    private val inbound = ArrayDeque<HandshakeMessage>()

    private var serverChangeCipherSpecSeen = false

    /**
     * Runs the whole handshake and returns SRTP's keys.
     *
     * The structure is three flights. This client sends a ClientHello and may be asked to send it
     * again with a cookie; the server answers with its hello, certificate, key exchange and a
     * "done"; this client replies with its own certificate, its half of the key exchange, a
     * signature proving it holds the matching private key, and a Finished; the server answers with
     * a Finished of its own. Both Finished messages are computed over a hash of everything that
     * came before, which is what makes the conversation tamper-evident as a whole rather than
     * message by message.
     */
    fun handshake(): SrtpKeyingMaterial {
        val deadline = System.currentTimeMillis() + HANDSHAKE_TIMEOUT_MS

        sendClientHello()
        var flight = lastFlight

        while (System.currentTimeMillis() < deadline) {
            val message = nextServerMessage(RETRANSMIT_MS)
            if (message == null) {
                // Nothing arrived. DTLS has no retransmission of its own below this layer, so the
                // whole last flight goes again -- the peer either lost ours or we lost theirs, and
                // resending is the only move available to either side.
                flight.forEach(channel::send)
                continue
            }

            when (message.type) {
                HandshakeType.HELLO_VERIFY_REQUEST -> {
                    // A stateless denial-of-service defence: the server refuses to allocate
                    // anything until the client proves it can receive at its claimed address by
                    // echoing a cookie. The exchange is explicitly excluded from the transcript --
                    // the handshake is treated as beginning with the second ClientHello.
                    cookie = TlsReader(message.body).run {
                        skip(2) // server_version
                        vector8()
                    }
                    transcript.reset()
                    sendClientHello()
                    flight = lastFlight
                }

                HandshakeType.SERVER_HELLO -> {
                    appendToTranscript(message)
                    readServerHello(message.body)
                }

                HandshakeType.CERTIFICATE -> {
                    appendToTranscript(message)
                    verifyPeerCertificate(message.body)
                }

                HandshakeType.SERVER_KEY_EXCHANGE -> {
                    appendToTranscript(message)
                    readServerKeyExchange(message.body)
                }

                HandshakeType.CERTIFICATE_REQUEST -> {
                    appendToTranscript(message)
                    certificateRequested = true
                }

                HandshakeType.SERVER_HELLO_DONE -> {
                    appendToTranscript(message)
                    sendClientFlight()
                    flight = lastFlight
                }

                HandshakeType.FINISHED -> {
                    verifyServerFinished(message)
                    return exportSrtpKeys()
                }

                else -> Log.d(TAG, "ignoring handshake type ${message.type}")
            }
        }
        throw IllegalStateException("dtls handshake timed out")
    }

    // ---- flights -----------------------------------------------------------------------------

    private var lastFlight: List<ByteArray> = emptyList()

    private fun sendClientHello() {
        val extensions = TlsWriter(128).apply {
            // Which elliptic curves this client will accept for the key exchange. One entry,
            // because one is what the single supported cipher suite uses.
            extension(EXT_SUPPORTED_GROUPS, TlsWriter().vector16(TlsWriter().u16(NAMED_CURVE_SECP256R1).toByteArray()).toByteArray())
            // Uncompressed points only. Point compression is optional everywhere and supported
            // almost nowhere, and rejecting it up front avoids having to decompress one.
            extension(EXT_EC_POINT_FORMATS, TlsWriter().vector8(byteArrayOf(0)).toByteArray())
            // Which signature algorithms this client will verify, for the ServerKeyExchange.
            extension(EXT_SIGNATURE_ALGORITHMS, TlsWriter().vector16(TlsWriter().u16(SIGNATURE_ECDSA_SHA256).u16(SIGNATURE_RSA_SHA256).toByteArray()).toByteArray())
            // The extension that makes this DTLS-SRTP rather than plain DTLS: it asks for SRTP key
            // material and names the protection profile the media will use.
            extension(
                EXT_USE_SRTP,
                TlsWriter()
                    .vector16(TlsWriter().u16(SRTP_AES128_CM_HMAC_SHA1_80).toByteArray())
                    .vector8(ByteArray(0)) // no master key identifier
                    .toByteArray(),
            )
            extension(EXT_EXTENDED_MASTER_SECRET, ByteArray(0))
        }.toByteArray()

        val body = TlsWriter(256)
            .u16(DTLS_1_2)
            .bytes(clientRandom)
            .vector8(ByteArray(0))  // no session to resume
            .vector8(cookie)
            .vector16(TlsWriter().u16(DtlsCrypto.CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256).toByteArray())
            .vector8(byteArrayOf(0)) // null compression, the only kind TLS 1.2 permits
            .vector16(extensions)
            .toByteArray()

        lastFlight = listOf(sendHandshake(HandshakeType.CLIENT_HELLO, body))
    }

    /**
     * The client's second flight: certificate, key exchange, proof of possession, and Finished.
     *
     * All of it goes in one burst because the server will not answer any of it individually, and
     * the ChangeCipherSpec in the middle means everything after it is already encrypted under keys
     * derived from the exchange two messages earlier.
     */
    private fun sendClientFlight() {
        val datagrams = ArrayList<ByteArray>(5)

        // A certificate is sent whenever the server asked for one -- and in WebRTC it always does,
        // because the client's fingerprint in the SDP is only meaningful if the client proves it.
        if (certificateRequested) {
            val chain = TlsWriter(certificate.encoded.size + 8)
                .vector24(TlsWriter().vector24(certificate.encoded).toByteArray())
                .toByteArray()
            datagrams += sendHandshake(HandshakeType.CERTIFICATE, chain)
        }

        val publicPoint = encodeUncompressedPoint(ephemeral)
        datagrams += sendHandshake(HandshakeType.CLIENT_KEY_EXCHANGE, TlsWriter().vector8(publicPoint).toByteArray())

        // The master secret is fixed once both halves of the exchange are on the transcript. RFC
        // 7627 binds it to a hash of the handshake so far, so it must be computed here -- after
        // ClientKeyExchange and before anything that depends on the keys.
        deriveMasterSecret()

        if (certificateRequested) {
            // Proof that this client holds the private key for the certificate it just sent, made
            // over the entire conversation so far so the signature cannot be lifted into another.
            val signature = certificate.sign(transcript.toByteArray())
            val body = TlsWriter(signature.size + 8)
                .u16(SIGNATURE_ECDSA_SHA256)
                .vector16(signature)
                .toByteArray()
            datagrams += sendHandshake(HandshakeType.CERTIFICATE_VERIFY, body)
        }

        datagrams += writeRecord(ContentType.CHANGE_CIPHER_SPEC, byteArrayOf(1))
        // Everything after the ChangeCipherSpec is protected, so the epoch advances and the record
        // sequence number restarts -- the two together are what keep GCM nonces unique.
        writeEpoch++
        writeSequence = 0

        val verifyData = DtlsCrypto.verifyData(
            masterSecret,
            "client finished",
            DtlsCrypto.sha256(transcript.toByteArray()),
        )
        datagrams += sendHandshake(HandshakeType.FINISHED, verifyData)

        lastFlight = datagrams
    }

    // ---- server messages ---------------------------------------------------------------------

    private fun readServerHello(body: ByteArray) {
        val reader = TlsReader(body)
        val version = reader.u16()
        require(version == DTLS_1_2) { "server chose dtls version $version" }
        serverRandom = reader.bytes(32)
        reader.vector8() // session id, which this client never resumes
        val suite = reader.u16()
        require(suite == DtlsCrypto.CIPHER_SUITE_ECDHE_ECDSA_AES128_GCM_SHA256) {
            "server chose unsupported cipher suite $suite"
        }
        reader.u8() // compression method

        var extendedMasterSecret = false
        var srtpProfile = -1
        if (reader.remaining >= 2) {
            val extensions = TlsReader(reader.vector16())
            while (extensions.remaining >= 4) {
                val type = extensions.u16()
                val value = extensions.vector16()
                when (type) {
                    EXT_EXTENDED_MASTER_SECRET -> extendedMasterSecret = true
                    EXT_USE_SRTP -> srtpProfile = TlsReader(value).run { TlsReader(vector16()).u16() }
                }
            }
        }

        // Both of these are refused rather than worked around. Without the extended master secret
        // the key schedule would have to fall back to a construction with a known weakness, and
        // without use_srtp there would be no agreed profile for the media that follows.
        require(extendedMasterSecret) { "server did not agree extended master secret" }
        require(srtpProfile == SRTP_AES128_CM_HMAC_SHA1_80) { "server chose srtp profile $srtpProfile" }
    }

    /**
     * Checks the server's certificate against the fingerprint from the SDP answer.
     *
     * This is the only identity check in WebRTC, and it is a complete one: the certificate is
     * self-signed and its chain proves nothing, so the fingerprint is what ties this handshake to
     * the server that answered the HTTP request. A mismatch means someone is in the middle.
     */
    private fun verifyPeerCertificate(body: ByteArray) {
        val chain = TlsReader(TlsReader(body).vector24())
        require(chain.remaining > 0) { "server sent an empty certificate chain" }
        val leaf = chain.vector24()

        val actual = MessageDigest.getInstance("SHA-256").digest(leaf)
        require(actual.contentEquals(expectedPeerFingerprint)) {
            "server certificate does not match the fingerprint in the sdp answer"
        }

        peerPublicKey = (CertificateFactory.getInstance("X.509")
            .generateCertificate(leaf.inputStream()) as X509Certificate).publicKey
    }

    private var peerPublicKey: PublicKey? = null
    private lateinit var preMasterSecret: ByteArray

    /**
     * Reads the server's ECDHE parameters and verifies its signature over them.
     *
     * The signature is what makes ephemeral Diffie-Hellman authenticated: the parameters themselves
     * are public and anyone could substitute their own, so the server signs them together with both
     * random values -- which ties them to this handshake and no other.
     */
    private fun readServerKeyExchange(body: ByteArray) {
        val reader = TlsReader(body)
        val curveType = reader.u8()
        require(curveType == CURVE_TYPE_NAMED) { "server used unsupported curve type $curveType" }
        val curve = reader.u16()
        require(curve == NAMED_CURVE_SECP256R1) { "server chose curve $curve" }
        val point = reader.vector8()

        // The signed data is exactly the parameters as they appeared on the wire, so they are
        // rebuilt rather than re-serialised from the parsed values.
        val params = TlsWriter(point.size + 8).u8(curveType).u16(curve).vector8(point).toByteArray()
        val signatureAlgorithm = reader.u16()
        val signature = reader.vector16()

        val algorithm = when (signatureAlgorithm) {
            SIGNATURE_ECDSA_SHA256 -> "SHA256withECDSA"
            SIGNATURE_RSA_SHA256 -> "SHA256withRSA"
            else -> throw IllegalStateException("server signed with algorithm $signatureAlgorithm")
        }
        val verified = Signature.getInstance(algorithm).run {
            initVerify(requireNotNull(peerPublicKey) { "key exchange arrived before the certificate" })
            update(clientRandom)
            update(serverRandom)
            update(params)
            verify(signature)
        }
        require(verified) { "server key exchange signature did not verify" }

        preMasterSecret = KeyAgreement.getInstance("ECDH").run {
            init(ephemeral.private)
            doPhase(decodeUncompressedPoint(point), true)
            generateSecret()
        }
    }

    private fun deriveMasterSecret() {
        masterSecret = DtlsCrypto.extendedMasterSecret(
            preMasterSecret,
            DtlsCrypto.sha256(transcript.toByteArray()),
        )
        keys = DtlsCrypto.keyBlock(masterSecret, clientRandom, serverRandom)
    }

    private fun verifyServerFinished(message: HandshakeMessage) {
        val expected = DtlsCrypto.verifyData(
            masterSecret,
            "server finished",
            DtlsCrypto.sha256(transcript.toByteArray()),
        )
        // Constant-time comparison. The value is an authenticator, and a length-or-prefix leak here
        // is the classic way to turn a MAC check into an oracle.
        require(constantTimeEquals(expected, message.body)) { "server finished did not verify" }
        appendToTranscript(message)
    }

    /**
     * Derives SRTP's keys from the finished handshake.
     *
     * The layout is fixed by RFC 5764: both master keys first, then both salts, all from one
     * exporter output. For this profile that is two 16-byte keys and two 14-byte salts.
     */
    private fun exportSrtpKeys(): SrtpKeyingMaterial {
        val material = DtlsCrypto.exportKeyingMaterial(
            masterSecret,
            "EXTRACTOR-dtls_srtp",
            clientRandom,
            serverRandom,
            2 * SRTP_KEY_SIZE + 2 * SRTP_SALT_SIZE,
        )
        var offset = 0
        fun take(size: Int) = material.copyOfRange(offset, offset + size).also { offset += size }
        val clientKey = take(SRTP_KEY_SIZE)
        val serverKey = take(SRTP_KEY_SIZE)
        val clientSalt = take(SRTP_SALT_SIZE)
        val serverSalt = take(SRTP_SALT_SIZE)
        return SrtpKeyingMaterial(clientKey, clientSalt, serverKey, serverSalt)
    }

    // ---- record and message plumbing -----------------------------------------------------------

    private fun appendToTranscript(message: HandshakeMessage) {
        transcript.write(message.encodedForTranscript())
    }

    /** Frames a handshake message, adds it to the transcript, and sends it as one record. */
    private fun sendHandshake(type: Int, body: ByteArray): ByteArray {
        val message = HandshakeMessage(type, nextMessageSeq++, body)
        val encoded = message.encodedForTranscript()
        transcript.write(encoded)
        // Sent unfragmented. Every message this client sends fits a datagram comfortably -- the
        // largest is its certificate, at a few hundred bytes -- so the fragmentation machinery is
        // implemented only on the receiving side, where the peer's messages can be large.
        return writeRecord(ContentType.HANDSHAKE, encoded)
    }

    /** Builds one record, encrypting it if the handshake has already switched cipher. */
    private fun writeRecord(contentType: Int, payload: ByteArray): ByteArray {
        val sequence = writeSequence++
        val keys = this.keys
        val body = if (writeEpoch == 0 || keys == null) {
            payload
        } else {
            DtlsCrypto.sealRecord(
                keys.clientWriteKey,
                keys.clientWriteIv,
                DtlsCrypto.explicitNonce(writeEpoch, sequence),
                DtlsCrypto.additionalData(writeEpoch, sequence, contentType, DTLS_1_2, payload.size),
                payload,
            )
        }

        val out = TlsWriter(RECORD_HEADER_SIZE + body.size)
            .u8(contentType)
            // A ClientHello's record still claims DTLS 1.0 for the benefit of servers that check
            // the record version before reading the one inside the message.
            .u16(if (writeEpoch == 0 && contentType == ContentType.HANDSHAKE && nextMessageSeq <= 1) DTLS_1_0 else DTLS_1_2)
            .u16(writeEpoch)
            .bytes(sequence48(sequence))
            .vector16(body)
            .toByteArray()

        channel.send(out)
        return out
    }

    /**
     * Returns the next complete handshake message from the server, or null on timeout.
     *
     * Everything below this -- records packed into one datagram, records arriving out of order,
     * messages split across datagrams -- is absorbed here so the handshake above reads as the
     * sequence of messages it logically is.
     */
    private fun nextServerMessage(timeoutMs: Int): HandshakeMessage? {
        inbound.removeFirstOrNull()?.let { return it }

        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            val datagram = channel.receive((deadline - System.currentTimeMillis()).toInt().coerceAtLeast(1))
                ?: continue
            readDatagram(datagram)
            inbound.removeFirstOrNull()?.let { return it }
        }
        return null
    }

    /** A datagram may carry several records back to back; all of them are read. */
    private fun readDatagram(datagram: ByteArray) {
        var offset = 0
        while (offset + RECORD_HEADER_SIZE <= datagram.size) {
            val contentType = datagram[offset].toInt() and 0xFF
            val version = ((datagram[offset + 1].toInt() and 0xFF) shl 8) or (datagram[offset + 2].toInt() and 0xFF)
            val epoch = ((datagram[offset + 3].toInt() and 0xFF) shl 8) or (datagram[offset + 4].toInt() and 0xFF)
            var sequence = 0L
            for (i in 0 until 6) sequence = (sequence shl 8) or (datagram[offset + 5 + i].toLong() and 0xFF)
            val length = ((datagram[offset + 11].toInt() and 0xFF) shl 8) or (datagram[offset + 12].toInt() and 0xFF)
            if (offset + RECORD_HEADER_SIZE + length > datagram.size) return
            val body = datagram.copyOfRange(offset + RECORD_HEADER_SIZE, offset + RECORD_HEADER_SIZE + length)
            offset += RECORD_HEADER_SIZE + length

            handleRecord(DtlsRecord(contentType, version, epoch, sequence, body))
        }
    }

    private fun handleRecord(record: DtlsRecord) {
        val payload = if (record.epoch == 0) {
            record.body
        } else {
            val keys = this.keys ?: return
            // A record that will not authenticate is dropped rather than treated as fatal: on a
            // lossy path a retransmission can legitimately arrive after the keys moved on.
            runCatching {
                DtlsCrypto.openRecord(
                    keys.serverWriteKey,
                    keys.serverWriteIv,
                    DtlsCrypto.additionalData(
                        record.epoch,
                        record.sequence,
                        record.contentType,
                        record.version,
                        record.body.size - DtlsCrypto.EXPLICIT_NONCE_SIZE - DtlsCrypto.TAG_SIZE,
                    ),
                    record.body,
                )
            }.getOrElse {
                Log.d(TAG, "dropping record that failed to authenticate")
                return
            }
        }

        when (record.contentType) {
            ContentType.CHANGE_CIPHER_SPEC -> {
                serverChangeCipherSpecSeen = true
                readEpoch++
            }
            ContentType.ALERT -> {
                // Level 2 is fatal. A close_notify (description 0) at level 1 is a normal shutdown.
                val level = payload.getOrNull(0)?.toInt() ?: 0
                val description = payload.getOrNull(1)?.toInt() ?: 0
                if (level == 2) throw IllegalStateException("server sent fatal dtls alert $description")
            }
            ContentType.HANDSHAKE -> readHandshakeFragments(payload)
        }
    }

    /** Reassembles handshake messages out of the fragments a record carries. */
    private fun readHandshakeFragments(payload: ByteArray) {
        var offset = 0
        while (offset + HANDSHAKE_HEADER_SIZE <= payload.size) {
            val reader = TlsReader(payload, offset)
            val type = reader.u8()
            val length = reader.u24()
            val messageSeq = reader.u16()
            val fragmentOffset = reader.u24()
            val fragmentLength = reader.u24()
            val start = offset + HANDSHAKE_HEADER_SIZE
            if (start + fragmentLength > payload.size) return
            val fragment = payload.copyOfRange(start, start + fragmentLength)
            offset = start + fragmentLength

            val assembly = reassembly.getOrPut(messageSeq) { Reassembly(type, length) }
            if (assembly.accept(fragmentOffset, fragment)) {
                reassembly.remove(messageSeq)
                inbound.addLast(HandshakeMessage(type, messageSeq, assembly.data))
            }
        }
    }

    /**
     * One partially received handshake message.
     *
     * Fragments are tracked by a filled-byte count rather than an interval set, which is correct
     * for the in-order, non-overlapping fragmentation every implementation actually produces, and
     * would mis-handle a peer that deliberately overlapped its fragments. A duplicate fragment --
     * which retransmission produces routinely -- is recognised and ignored.
     */
    private class Reassembly(val type: Int, val length: Int) {

        val data = ByteArray(length)
        private val covered = BooleanArray(length)
        private var filled = 0

        fun accept(offset: Int, fragment: ByteArray): Boolean {
            if (offset < 0 || offset + fragment.size > length) return filled == length
            for (i in fragment.indices) {
                if (covered[offset + i]) continue
                data[offset + i] = fragment[i]
                covered[offset + i] = true
                filled++
            }
            return filled == length
        }
    }

    // ---- elliptic curve helpers ----------------------------------------------------------------

    /** `0x04 || X || Y`, the uncompressed point encoding TLS uses for ECDHE. */
    private fun encodeUncompressedPoint(keyPair: KeyPair): ByteArray {
        val public = keyPair.public as java.security.interfaces.ECPublicKey
        val fieldSize = (public.params.curve.field.fieldSize + 7) / 8
        return byteArrayOf(4) + fixedLength(public.w.affineX.toByteArray(), fieldSize) +
            fixedLength(public.w.affineY.toByteArray(), fieldSize)
    }

    /**
     * Turns the peer's point back into a key.
     *
     * The point is validated by the platform when the key is constructed: a point that is not on
     * the curve is rejected there, which is the check that stops an invalid-curve attack from
     * leaking the private key one bit at a time.
     */
    private fun decodeUncompressedPoint(encoded: ByteArray): PublicKey {
        require(encoded.isNotEmpty() && encoded[0] == 4.toByte()) { "peer sent a compressed ec point" }
        val coordinateSize = (encoded.size - 1) / 2
        val x = java.math.BigInteger(1, encoded.copyOfRange(1, 1 + coordinateSize))
        val y = java.math.BigInteger(1, encoded.copyOfRange(1 + coordinateSize, encoded.size))
        val params = AlgorithmParameters.getInstance("EC").run {
            init(ECGenParameterSpec("secp256r1"))
            getParameterSpec(ECParameterSpec::class.java)
        }
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(ECPoint(x, y), params))
    }

    /** Left-pads or trims a BigInteger's two's-complement bytes to the curve's field size. */
    private fun fixedLength(value: ByteArray, size: Int): ByteArray = when {
        value.size == size -> value
        value.size > size -> value.copyOfRange(value.size - size, value.size)
        else -> ByteArray(size - value.size) + value
    }

    private fun sequence48(value: Long) = ByteArray(6) { ((value ushr (40 - it * 8)) and 0xFF).toByte() }

    private fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
        if (a.size != b.size) return false
        var difference = 0
        for (i in a.indices) difference = difference or (a[i].toInt() xor b[i].toInt())
        return difference == 0
    }

    private fun TlsWriter.extension(type: Int, value: ByteArray) = u16(type).vector16(value)

    private companion object {

        const val EXT_SUPPORTED_GROUPS = 10
        const val EXT_EC_POINT_FORMATS = 11
        const val EXT_SIGNATURE_ALGORITHMS = 13
        const val EXT_USE_SRTP = 14
        const val EXT_EXTENDED_MASTER_SECRET = 23

        const val NAMED_CURVE_SECP256R1 = 23
        const val CURVE_TYPE_NAMED = 3

        const val SIGNATURE_RSA_SHA256 = 0x0401
        const val SIGNATURE_ECDSA_SHA256 = 0x0403

        /** The SRTP protection profile every WebRTC endpoint supports. */
        const val SRTP_AES128_CM_HMAC_SHA1_80 = 0x0001
        const val SRTP_KEY_SIZE = 16
        const val SRTP_SALT_SIZE = 14

        /** Resend the last flight after this long with no reply. */
        const val RETRANSMIT_MS = 1_000

        /** Give up after this long. Long enough for a slow path, short enough to report. */
        const val HANDSHAKE_TIMEOUT_MS = 20_000L
    }
}
