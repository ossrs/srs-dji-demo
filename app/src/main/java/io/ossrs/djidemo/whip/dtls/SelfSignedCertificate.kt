package io.ossrs.djidemo.whip.dtls

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone

/**
 * The certificate this client presents during the DTLS handshake, generated for each session.
 *
 * WebRTC does not use a certificate authority. Identity is established the other way round: the
 * certificate is self-signed and *disposable*, and what makes it trustworthy is that its SHA-256
 * fingerprint was announced in the SDP over a channel the peer already trusts. A peer that sees a
 * certificate hashing to something other than the advertised fingerprint hangs up -- and that is the
 * whole of the authentication story.
 *
 * So there is nothing to store, nothing to renew, and no value in a long validity: the certificate
 * exists for one publish.
 */
internal class SelfSignedCertificate private constructor(
    val keyPair: KeyPair,
    val encoded: ByteArray,
) {

    /** The `a=fingerprint` value for the SDP: uppercase hex bytes separated by colons. */
    val sha256Fingerprint: String by lazy {
        MessageDigest.getInstance("SHA-256").digest(encoded)
            .joinToString(":") { "%02X".format(it) }
    }

    /** Signs [data] with the certificate's private key, as DTLS `CertificateVerify` requires. */
    fun sign(data: ByteArray): ByteArray = Signature.getInstance("SHA256withECDSA").run {
        initSign(keyPair.private)
        update(data)
        sign()
    }

    companion object {

        /** ecdsa-with-SHA256. */
        private const val OID_ECDSA_SHA256 = "1.2.840.10045.4.3.2"

        /** id-at-commonName. */
        private const val OID_COMMON_NAME = "2.5.4.3"

        /**
         * Generates a P-256 key pair and a matching self-signed certificate.
         *
         * P-256 rather than RSA because it is what every WebRTC implementation uses and what makes
         * the handshake cheap enough to be invisible on a phone. The DER is assembled by hand
         * because Android's public API can generate the key but not wrap it in a certificate, and
         * pulling in a full certificate library for one disposable credential is not a trade worth
         * making.
         */
        fun generate(): SelfSignedCertificate {
            val keyPair = KeyPairGenerator.getInstance("EC").run {
                initialize(ECGenParameterSpec("secp256r1"), SecureRandom())
                generateKeyPair()
            }

            val signatureAlgorithm = Der.sequence(Der.oid(OID_ECDSA_SHA256))
            val name = Der.sequence(
                Der.set(Der.sequence(Der.oid(OID_COMMON_NAME), Der.utf8String("WebRTC"))),
            )

            val now = System.currentTimeMillis()
            val validity = Der.sequence(
                Der.utcTime(utcTime(now - ONE_HOUR_MS)),
                Der.utcTime(utcTime(now + THIRTY_DAYS_MS)),
            )

            val serial = ByteArray(16).also { SecureRandom().nextBytes(it) }

            // getEncoded() on a public key already returns a DER SubjectPublicKeyInfo, which is
            // exactly the field the certificate needs, so it is spliced in rather than rebuilt.
            val tbs = Der.sequence(
                Der.explicit(0, Der.integer(2)), // v3
                Der.integer(serial),
                signatureAlgorithm,
                name,                            // issuer -- the same as the subject, being self-signed
                validity,
                name,                            // subject
                keyPair.public.encoded,
            )

            val signature = Signature.getInstance("SHA256withECDSA").run {
                initSign(keyPair.private)
                update(tbs)
                sign()
            }

            val certificate = Der.sequence(tbs, signatureAlgorithm, Der.bitString(signature))
            return SelfSignedCertificate(keyPair, certificate)
        }

        private const val ONE_HOUR_MS = 60 * 60 * 1000L
        private const val THIRTY_DAYS_MS = 30 * 24 * ONE_HOUR_MS

        /** `YYMMDDHHMMSSZ`, which is what UTCTime means in a certificate. */
        private fun utcTime(millis: Long): String =
            SimpleDateFormat("yyMMddHHmmss'Z'", Locale.US)
                .apply { timeZone = TimeZone.getTimeZone("UTC") }
                .format(Date(millis))
    }
}
