package io.ossrs.djidemo.whip

import io.ossrs.djidemo.whip.dtls.Der
import io.ossrs.djidemo.whip.dtls.SelfSignedCertificate
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

class DerTest {

    @Test
    fun `short lengths use one byte and longer ones say how many follow`() {
        val short = Der.encode(0x04, ByteArray(5))
        assertEquals(5, short[1].toInt())

        val long = Der.encode(0x04, ByteArray(300))
        assertEquals(0x82, long[1].toInt() and 0xFF) // two length bytes follow
        assertEquals(300, ((long[2].toInt() and 0xFF) shl 8) or (long[3].toInt() and 0xFF))
    }

    @Test
    fun `object identifiers pack the first two arcs and base 128 the rest`() {
        // ecdsa-with-SHA256, whose published encoding is 2A 86 48 CE 3D 04 03 02.
        assertArrayEquals(
            byteArrayOf(0x06, 0x08, 0x2A, 0x86.toByte(), 0x48, 0xCE.toByte(), 0x3D, 0x04, 0x03, 0x02),
            Der.oid("1.2.840.10045.4.3.2"),
        )
        // id-at-commonName: 55 04 03.
        assertArrayEquals(byteArrayOf(0x06, 0x03, 0x55, 0x04, 0x03), Der.oid("2.5.4.3"))
    }

    @Test
    fun `a value whose top bit is set gets a leading zero so it stays positive`() {
        val encoded = Der.integer(byteArrayOf(0xFF.toByte()))
        assertArrayEquals(byteArrayOf(0x02, 0x02, 0x00, 0xFF.toByte()), encoded)
    }
}

class SelfSignedCertificateTest {

    @Test
    fun `generates a certificate the platform can parse and that verifies against itself`() {
        val certificate = SelfSignedCertificate.generate()

        val parsed = CertificateFactory.getInstance("X.509")
            .generateCertificate(certificate.encoded.inputStream()) as X509Certificate

        assertEquals(3, parsed.version)
        assertEquals("SHA256withECDSA", parsed.sigAlgName)
        // Self-signed means the subject and issuer agree and the certificate verifies with its own
        // public key -- which is exactly the shape WebRTC expects.
        assertEquals(parsed.subjectX500Principal, parsed.issuerX500Principal)
        parsed.verify(parsed.publicKey)
        assertArrayEquals(certificate.keyPair.public.encoded, parsed.publicKey.encoded)
    }

    @Test
    fun `the advertised fingerprint is the sha-256 of the certificate the peer will see`() {
        val certificate = SelfSignedCertificate.generate()

        val expected = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
            .joinToString(":") { "%02X".format(it) }
        assertEquals(expected, certificate.sha256Fingerprint)
        // The value goes straight into an a=fingerprint line, so its shape matters.
        assertTrue(certificate.sha256Fingerprint.matches(Regex("([0-9A-F]{2}:){31}[0-9A-F]{2}")))
    }

    @Test
    fun `signatures verify with the certificate's own public key`() {
        val certificate = SelfSignedCertificate.generate()
        val data = "handshake transcript".toByteArray()

        val verified = Signature.getInstance("SHA256withECDSA").run {
            initVerify(certificate.keyPair.public)
            update(data)
            verify(certificate.sign(data))
        }
        assertTrue(verified)
    }

    @Test
    fun `each session gets its own disposable identity`() {
        assertNotEquals(
            SelfSignedCertificate.generate().sha256Fingerprint,
            SelfSignedCertificate.generate().sha256Fingerprint,
        )
    }
}
