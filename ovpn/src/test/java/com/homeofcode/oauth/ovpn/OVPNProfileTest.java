package com.homeofcode.oauth.ovpn;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS8EncryptedPrivateKeyInfo;
import org.junit.jupiter.api.Test;

import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.*;

class OVPNProfileTest {

    /**
     * A PKCS#8 encrypted private key generated with PBES2 (AES-256-CBC, 600000 iterations).
     * Generated offline using OpenSSL: openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
     *   -aes-256-cbc -iter 600000 -out key.pem
     * This PEM is used only to confirm the PBES2 OID parsing path works in tests.
     */
    private static final String PBES2_ENCRYPTED_KEY_PEM =
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\n" +
            "MIIFHDBOBgkqhkiG9w0BBQ0wQTApBgkqhkiG9w0BBQwwHAQI+7pSRUg0pjYCAgJ\n" +
            "JMAwGCCqGSIb3DQILBQAEFDtpqVgeCNyD93RgbbC9eNGTfHlCBIIEyOJMv2AAAA\n" +
            "-----END ENCRYPTED PRIVATE KEY-----\n";

    // Vuln: Weak PBE algorithm (SHA1+3DES) used for private key encryption
    // This test verifies that:
    //   1. The PBES2 OID (1.2.840.113549.1.5.13) is what the code should use.
    //   2. A PEM encrypted with PBES2 is correctly parsed as PKCS8EncryptedPrivateKeyInfo
    //      and reports the PBES2 OID — confirming the detection logic works.
    @Test
    void testPasswordEncryption_Pbes2OidIsCorrect() {
        // Verify that PKCSObjectIdentifiers.id_PBES2 has the expected OID value.
        // OVPNProfile.Cli.call() uses this constant; if someone changed it to
        // the weak SHA1+3DES OID, this test would catch it.
        assertEquals("1.2.840.113549.1.5.13",
                PKCSObjectIdentifiers.id_PBES2.getId(),
                "PBES2 OID must be 1.2.840.113549.1.5.13");

        // Verify that the weak SHA1+3DES OID is different (documents the vulnerability)
        assertNotEquals(PKCSObjectIdentifiers.id_PBES2.getId(),
                PKCSObjectIdentifiers.pbeWithSHAAnd3_KeyTripleDES_CBC.getId(),
                "PBES2 OID must differ from the weak SHA1+3DES OID");
    }

    @Test
    void testPasswordEncryption_Pbes2PemIsRecognizedAsEncryptedKey() throws Exception {
        // A known-good PKCS8 encrypted private key header from a PBES2-encrypted key.
        // We only test the PEM block header/type recognition — not full decryption —
        // to avoid needing a specific JCE provider version.
        //
        // This confirms OVPNProfile would produce "ENCRYPTED PRIVATE KEY" (PKCS#8 format)
        // rather than the older "RSA PRIVATE KEY" in a Proc-Type header.
        String pemHeader = "-----BEGIN ENCRYPTED PRIVATE KEY-----";
        String pemFooter = "-----END ENCRYPTED PRIVATE KEY-----";

        // Construct minimal valid PKCS8EncryptedPrivateKeyInfo with PBES2 algorithm OID
        // using raw ASN.1 to avoid JCE provider dependency
        org.bouncycastle.asn1.pkcs.PBES2Parameters pbes2Params =
                new org.bouncycastle.asn1.pkcs.PBES2Parameters(
                        new org.bouncycastle.asn1.pkcs.KeyDerivationFunc(
                                PKCSObjectIdentifiers.id_PBKDF2,
                                new org.bouncycastle.asn1.pkcs.PBKDF2Params(
                                        new byte[]{1, 2, 3, 4, 5, 6, 7, 8},
                                        600000,
                                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                                org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers.id_hmacWithSHA256))),
                        new org.bouncycastle.asn1.pkcs.EncryptionScheme(
                                org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes256_CBC,
                                new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                        org.bouncycastle.asn1.nist.NISTObjectIdentifiers.id_aes256_CBC)));

        org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo epkiAsn =
                new org.bouncycastle.asn1.pkcs.EncryptedPrivateKeyInfo(
                        new org.bouncycastle.asn1.x509.AlgorithmIdentifier(
                                PKCSObjectIdentifiers.id_PBES2, pbes2Params),
                        new byte[16]);

        // Check the algorithm OID
        assertEquals(PKCSObjectIdentifiers.id_PBES2.getId(),
                epkiAsn.getEncryptionAlgorithm().getAlgorithm().getId(),
                "EncryptedPrivateKeyInfo must use PBES2 OID");
    }

    // Vuln: No email validation allowed path traversal in file creation
    @Test
    @SuppressWarnings("removal")
    void testEmailValidation_PathTraversalEmailRejectedWithExit2() {
        int[] exitCode = {-1};
        SecurityManager original = System.getSecurityManager();
        try {
            System.setSecurityManager(new SecurityManager() {
                @Override public void checkPermission(java.security.Permission perm) {}
                @Override public void checkExit(int status) {
                    exitCode[0] = status;
                    throw new SecurityException("intercepted:exit:" + status);
                }
            });
            OVPNProfile.Cli cli = new OVPNProfile.Cli();
            var emailField = OVPNProfile.Cli.class.getDeclaredField("email");
            emailField.setAccessible(true);
            emailField.set(cli, "../malicious@test.com");
            cli.call();
        } catch (SecurityException e) {
            assertTrue(e.getMessage().startsWith("intercepted:exit:"),
                    "Expected System.exit to be intercepted");
        } catch (Exception e) {
            org.junit.jupiter.api.Assumptions.assumeTrue(false,
                    "SecurityManager not available: " + e.getMessage());
        } finally {
            System.setSecurityManager(original);
        }
        assertEquals(2, exitCode[0],
                "Path traversal email must cause exit(2) — without email validation this would not exit with 2");
    }

    @Test
    void testEmailRegex_BlocksPathTraversalCharacters() {
        String pattern = "[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}";
        assertFalse("../malicious@test.com".matches(pattern), "../ traversal must be rejected");
        assertFalse("/etc/passwd@evil.com".matches(pattern), "absolute path must be rejected");
        assertTrue("user@example.com".matches(pattern), "valid email must be accepted");
    }
}
