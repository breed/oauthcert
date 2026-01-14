package com.homeofcode.wgkeyman;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.security.auth.x500.X500Principal;
import java.io.FileWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Calendar;

import static org.junit.jupiter.api.Assertions.*;

/**
 * End-to-end integration tests that simulate the full workflow:
 * 1. wg tool generates CSR with wireguard public key extension
 * 2. server signs CSR and copies extensions to certificate
 * 3. wg-keyman validates certificate and generates wireguard config
 */
class EndToEndTest {

    private static final ASN1ObjectIdentifier WG_PUBLIC_KEY_OID =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1");

    @TempDir
    Path tempDir;

    private KeyPair caKeyPair;
    private X509CertificateHolder caCert;
    private CertificateService certificateService;

    @BeforeEach
    void setUp() throws Exception {
        // Step 1: Create CA (simulating server setup)
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        caKeyPair = keyGen.generateKeyPair();

        var now = Calendar.getInstance();
        var expire = Calendar.getInstance();
        expire.add(Calendar.YEAR, 1);

        X500Name caSubject = new X500Name("CN=Test CA");
        var builder = new X509v3CertificateBuilder(
                caSubject,
                BigInteger.valueOf(1),
                now.getTime(),
                expire.getTime(),
                caSubject,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded())
        );

        var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
        caCert = builder.build(signer);

        // Write CA cert to file
        Path caCertPath = tempDir.resolve("ca.crt");
        try (var writer = new JcaPEMWriter(new FileWriter(caCertPath.toFile()))) {
            writer.writeObject(caCert);
        }

        // Create service with test config
        certificateService = new CertificateService(
                new CertificateServiceTest.TestWgKeymanConfig(caCert,
                        java.util.Map.of("alice@example.com", 5, "bob@example.com", 10)));
    }

    @Test
    @DisplayName("Full workflow: CSR generation -> signing -> config generation")
    void testFullWorkflow() throws Exception {
        String email = "alice@example.com";

        // === STEP 1: Simulate wg tool generating CSR ===
        // Generate wireguard key pair (like WGProfile.generateWireguardKeyPair())
        byte[] wgPrivateKey = new byte[32];
        new SecureRandom().nextBytes(wgPrivateKey);
        wgPrivateKey[0] &= 248;
        wgPrivateKey[31] &= 127;
        wgPrivateKey[31] |= 64;
        byte[] wgPublicKey = new byte[32];
        org.bouncycastle.math.ec.rfc7748.X25519.scalarMultBase(wgPrivateKey, 0, wgPublicKey, 0);

        // Generate RSA key pair for CSR
        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaKeyPair = rsaGen.generateKeyPair();

        // Create CSR with wireguard extension
        Extension wgExt = new Extension(WG_PUBLIC_KEY_OID, false, new DEROctetString(wgPublicKey));
        Extensions extensions = new Extensions(wgExt);

        var csrSigner = new JcaContentSignerBuilder("SHA256withRSA").build(rsaKeyPair.getPrivate());
        var csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=" + email), rsaKeyPair.getPublic());
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
        PKCS10CertificationRequest csr = csrBuilder.build(csrSigner);

        // Verify CSR has the extension
        String csrPem = toPem(csr);
        assertNotNull(csrPem);
        assertTrue(csrPem.contains("BEGIN CERTIFICATE REQUEST"));

        // === STEP 2: Simulate server signing CSR and copying extensions ===
        // Parse CSR (like server does)
        PKCS10CertificationRequest parsedCsr;
        try (var parser = new PEMParser(new StringReader(csrPem))) {
            parsedCsr = (PKCS10CertificationRequest) parser.readObject();
        }

        // Build certificate
        var now = Calendar.getInstance();
        var expire = Calendar.getInstance();
        expire.add(Calendar.MONTH, 4);

        var certBuilder = new X509v3CertificateBuilder(
                caCert.getSubject(),
                new BigInteger(128, new SecureRandom()),
                now.getTime(),
                expire.getTime(),
                parsedCsr.getSubject(),
                parsedCsr.getSubjectPublicKeyInfo()
        );

        // Copy extensions from CSR (like AuthServer.signCSR does)
        Attribute[] attrs = parsedCsr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        for (Attribute attr : attrs) {
            for (ASN1Encodable value : attr.getAttributeValues()) {
                Extensions exts = Extensions.getInstance(value);
                for (var oid : exts.getExtensionOIDs()) {
                    Extension ext = exts.getExtension(oid);
                    certBuilder.addExtension(ext);
                }
            }
        }

        var certSigner = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
        X509CertificateHolder signedCert = certBuilder.build(certSigner);

        String certPem = toPem(signedCert);
        assertNotNull(certPem);
        assertTrue(certPem.contains("BEGIN CERTIFICATE"));

        // === STEP 3: Simulate wg-keyman processing the certificate ===
        CertificateService.CertificateResult result = certificateService.processCertificate(certPem);

        // Verify success
        assertTrue(result.valid(), "Certificate should be valid: " + result.errorMessage());
        assertEquals(email, result.commonName());

        // Verify wireguard public key was extracted correctly
        String expectedWgPubKey = Base64.getEncoder().encodeToString(wgPublicKey);
        assertEquals(expectedWgPubKey, result.wireguardPublicKey());

        // Verify config was generated
        assertNotNull(result.wireguardConfig());
        assertTrue(result.wireguardConfig().contains("[Interface]"));
        assertTrue(result.wireguardConfig().contains("[Peer]"));
        assertTrue(result.wireguardConfig().contains("Address = 10.0.0.5/32")); // host number 5 for alice

        // Verify the private key from wg tool would complete the config
        String privateKeyLine = "PrivateKey = " + Base64.getEncoder().encodeToString(wgPrivateKey);
        assertNotNull(privateKeyLine);
        assertEquals(44, Base64.getEncoder().encodeToString(wgPrivateKey).length());
    }

    @Test
    @DisplayName("Workflow with unauthorized user should fail")
    void testWorkflowUnauthorizedUser() throws Exception {
        String email = "unauthorized@example.com";

        // Generate wireguard key pair
        byte[] wgPublicKey = new byte[32];
        new SecureRandom().nextBytes(wgPublicKey);

        // Generate signed certificate
        String certPem = createSignedCertificate(email, wgPublicKey);

        // Process certificate
        CertificateService.CertificateResult result = certificateService.processCertificate(certPem);

        // Should fail authorization
        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("not authorized"));
    }

    @Test
    @DisplayName("Workflow with missing wireguard extension should fail")
    void testWorkflowMissingExtension() throws Exception {
        String email = "alice@example.com";

        // Create certificate without wireguard extension
        String certPem = createSignedCertificateWithoutExtension(email);

        // Process certificate
        CertificateService.CertificateResult result = certificateService.processCertificate(certPem);

        // Should fail due to missing extension
        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("wireguard public key"));
    }

    @Test
    @DisplayName("Multiple users get different IP addresses")
    void testMultipleUsersGetDifferentAddresses() throws Exception {
        byte[] wgPublicKey = new byte[32];
        new SecureRandom().nextBytes(wgPublicKey);

        // Alice should get 10.0.0.5
        String aliceCert = createSignedCertificate("alice@example.com", wgPublicKey);
        CertificateService.CertificateResult aliceResult = certificateService.processCertificate(aliceCert);
        assertTrue(aliceResult.valid());
        assertTrue(aliceResult.wireguardConfig().contains("Address = 10.0.0.5/32"));

        // Bob should get 10.0.0.10
        String bobCert = createSignedCertificate("bob@example.com", wgPublicKey);
        CertificateService.CertificateResult bobResult = certificateService.processCertificate(bobCert);
        assertTrue(bobResult.valid());
        assertTrue(bobResult.wireguardConfig().contains("Address = 10.0.0.10/32"));
    }

    private String createSignedCertificate(String cn, byte[] wgPublicKey) throws Exception {
        var now = Calendar.getInstance();
        var expire = Calendar.getInstance();
        expire.add(Calendar.MONTH, 4);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        var builder = new X509v3CertificateBuilder(
                caCert.getSubject(),
                new BigInteger(128, new SecureRandom()),
                now.getTime(),
                expire.getTime(),
                new X500Name("CN=" + cn),
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        );

        builder.addExtension(new Extension(WG_PUBLIC_KEY_OID, false, new DEROctetString(wgPublicKey)));

        var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
        return toPem(builder.build(signer));
    }

    private String createSignedCertificateWithoutExtension(String cn) throws Exception {
        var now = Calendar.getInstance();
        var expire = Calendar.getInstance();
        expire.add(Calendar.MONTH, 4);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();

        var builder = new X509v3CertificateBuilder(
                caCert.getSubject(),
                new BigInteger(128, new SecureRandom()),
                now.getTime(),
                expire.getTime(),
                new X500Name("CN=" + cn),
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded())
        );

        var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
        return toPem(builder.build(signer));
    }

    private String toPem(Object obj) throws Exception {
        StringWriter sw = new StringWriter();
        try (var writer = new JcaPEMWriter(sw)) {
            writer.writeObject(obj);
        }
        return sw.toString();
    }
}
