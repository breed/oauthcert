package com.homeofcode.oauth.wg;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.KeyPairGenerator;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

class WGProfileTest {

    @Test
    void testGenerateWireguardKeyPair_ReturnsCorrectLength() {
        byte[] keyPair = WGProfile.generateWireguardKeyPair();
        assertEquals(64, keyPair.length, "Key pair should be 64 bytes (32 private + 32 public)");
    }

    @Test
    void testGenerateWireguardKeyPair_PrivateKeyIsClamped() {
        byte[] keyPair = WGProfile.generateWireguardKeyPair();
        byte[] privateKey = new byte[32];
        System.arraycopy(keyPair, 0, privateKey, 0, 32);

        // Check Curve25519 clamping: first byte has lower 3 bits cleared
        assertEquals(0, privateKey[0] & 0x07, "Private key first byte should have lower 3 bits cleared");
        // Last byte has bit 7 cleared and bit 6 set
        assertEquals(0, privateKey[31] & 0x80, "Private key last byte should have bit 7 cleared");
        assertNotEquals(0, privateKey[31] & 0x40, "Private key last byte should have bit 6 set");
    }

    @Test
    void testGenerateWireguardKeyPair_GeneratesUniqueKeys() {
        byte[] keyPair1 = WGProfile.generateWireguardKeyPair();
        byte[] keyPair2 = WGProfile.generateWireguardKeyPair();

        assertFalse(java.util.Arrays.equals(keyPair1, keyPair2), "Each key pair should be unique");
    }

    @Test
    void testGenerateWireguardKeyPair_PublicKeyIsValidBase64() {
        byte[] keyPair = WGProfile.generateWireguardKeyPair();
        byte[] publicKey = new byte[32];
        System.arraycopy(keyPair, 32, publicKey, 0, 32);

        String base64 = Base64.getEncoder().encodeToString(publicKey);
        assertEquals(44, base64.length(), "Base64 encoded 32-byte key should be 44 characters");
        assertTrue(base64.endsWith("="), "Base64 encoded 32-byte key should end with padding");
    }

    @Test
    void testX25519ScalarMultBase_ProducesConsistentResult() {
        // Test with a known private key
        byte[] privateKey = new byte[32];
        privateKey[0] = (byte) 0x78; // Clamped value
        privateKey[31] = (byte) 0x40; // Clamped value

        byte[] publicKey1 = WGProfile.x25519ScalarMultBase(privateKey);
        byte[] publicKey2 = WGProfile.x25519ScalarMultBase(privateKey);

        assertArrayEquals(publicKey1, publicKey2, "Same private key should produce same public key");
        assertEquals(32, publicKey1.length, "Public key should be 32 bytes");
    }

    @Test
    void testCSRContainsWireguardExtension() throws Exception {
        // Generate wireguard key pair
        byte[] wgKeyPair = WGProfile.generateWireguardKeyPair();
        byte[] wgPublicKey = new byte[32];
        System.arraycopy(wgKeyPair, 32, wgPublicKey, 0, 32);

        // Generate RSA key pair for CSR
        var gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        var pair = gen.generateKeyPair();

        // Create extension
        Extension wgPubKeyExt = new Extension(WGProfile.WG_PUBLIC_KEY_OID, false, new DEROctetString(wgPublicKey));
        Extensions extensions = new Extensions(wgPubKeyExt);

        // Build CSR
        var csrSigner = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        var csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=test@example.com"), pair.getPublic());
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
        var csr = csrBuilder.build(csrSigner);

        // Write to PEM and parse back
        var csrPem = new StringWriter();
        try (var writer = new JcaPEMWriter(csrPem)) {
            writer.writeObject(csr);
        }

        // Parse the CSR
        try (var reader = new PEMParser(new StringReader(csrPem.toString()))) {
            PKCS10CertificationRequest parsedCsr = (PKCS10CertificationRequest) reader.readObject();

            // Verify subject
            assertTrue(parsedCsr.getSubject().toString().contains("test@example.com"),
                    "CSR should contain email in subject");

            // Find and verify extension
            Attribute[] attrs = parsedCsr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
            assertTrue(attrs.length > 0, "CSR should have extension request attribute");

            boolean foundExtension = false;
            for (Attribute attr : attrs) {
                for (ASN1Encodable value : attr.getAttributeValues()) {
                    Extensions exts = Extensions.getInstance(value);
                    Extension ext = exts.getExtension(WGProfile.WG_PUBLIC_KEY_OID);
                    if (ext != null) {
                        foundExtension = true;
                        byte[] extractedKey = ext.getExtnValue().getOctets();
                        assertArrayEquals(wgPublicKey, extractedKey,
                                "Extracted public key should match original");
                    }
                }
            }
            assertTrue(foundExtension, "CSR should contain wireguard public key extension");
        }
    }

    @Test
    void testWGPublicKeyOID() {
        assertEquals("1.3.6.1.4.1.99999.1", WGProfile.WG_PUBLIC_KEY_OID.getId(),
                "OID should match expected value");
    }
}
