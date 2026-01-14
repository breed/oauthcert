package com.homeofcode.wgkeyman;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.FileWriter;
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

class CertificateServiceTest {

    private static final ASN1ObjectIdentifier WG_PUBLIC_KEY_OID =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1");

    @TempDir
    Path tempDir;

    private CertificateService certificateService;
    private KeyPair caKeyPair;
    private X509CertificateHolder caCert;
    private byte[] testWgPublicKey;

    @BeforeEach
    void setUp() throws Exception {
        // Generate CA key pair
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        caKeyPair = keyGen.generateKeyPair();

        // Create CA certificate
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

        // Create users file
        Path usersPath = tempDir.resolve("users.lst");
        Files.writeString(usersPath, "5 test@example.com\n10 admin@example.com\n");

        // Create test wireguard public key
        testWgPublicKey = new byte[32];
        new SecureRandom().nextBytes(testWgPublicKey);

        // Create mock config and service
        WgKeymanConfig config = createMockConfig(caCertPath, usersPath);
        certificateService = new CertificateService(config);
    }

    private WgKeymanConfig createMockConfig(Path caCertPath, Path usersPath) throws Exception {
        // We need to create a real config since it loads files in @PostConstruct
        // Using a test-specific approach
        return new TestWgKeymanConfig(caCertPath, usersPath, caCert);
    }

    @Test
    void testParseCertificate_ValidPEM() throws Exception {
        String pem = createSignedCertificatePEM("test@example.com", testWgPublicKey);
        X509CertificateHolder cert = certificateService.parseCertificate(pem);
        assertNotNull(cert);
    }

    @Test
    void testParseCertificate_InvalidPEM() {
        assertThrows(Exception.class, () -> {
            certificateService.parseCertificate("not a valid certificate");
        });
    }

    @Test
    void testExtractCommonName() throws Exception {
        String pem = createSignedCertificatePEM("test@example.com", testWgPublicKey);
        X509CertificateHolder cert = certificateService.parseCertificate(pem);
        String cn = certificateService.extractCommonName(cert);
        assertEquals("test@example.com", cn);
    }

    @Test
    void testExtractWireguardPublicKey() throws Exception {
        String pem = createSignedCertificatePEM("test@example.com", testWgPublicKey);
        X509CertificateHolder cert = certificateService.parseCertificate(pem);
        String extractedKey = certificateService.extractWireguardPublicKey(cert);

        String expectedKey = Base64.getEncoder().encodeToString(testWgPublicKey);
        assertEquals(expectedKey, extractedKey);
    }

    @Test
    void testExtractWireguardPublicKey_NoExtension() throws Exception {
        String pem = createSignedCertificatePEMWithoutExtension("test@example.com");
        X509CertificateHolder cert = certificateService.parseCertificate(pem);
        String extractedKey = certificateService.extractWireguardPublicKey(cert);
        assertNull(extractedKey);
    }

    @Test
    void testValidateCertificate_ValidSignature() throws Exception {
        String pem = createSignedCertificatePEM("test@example.com", testWgPublicKey);
        X509CertificateHolder cert = certificateService.parseCertificate(pem);
        assertTrue(certificateService.validateCertificate(cert));
    }

    @Test
    void testIsAuthorizedUser_AuthorizedUser() {
        assertTrue(certificateService.isAuthorizedUser("test@example.com"));
        assertTrue(certificateService.isAuthorizedUser("admin@example.com"));
    }

    @Test
    void testIsAuthorizedUser_UnauthorizedUser() {
        assertFalse(certificateService.isAuthorizedUser("unknown@example.com"));
    }

    @Test
    void testGetHostNumber() {
        assertEquals(5, certificateService.getHostNumber("test@example.com"));
        assertEquals(10, certificateService.getHostNumber("admin@example.com"));
        assertNull(certificateService.getHostNumber("unknown@example.com"));
    }

    @Test
    void testGenerateWireguardConfig() {
        String config = certificateService.generateWireguardConfig("test@example.com", "testpubkey");
        assertTrue(config.contains("[Interface]"));
        assertTrue(config.contains("[Peer]"));
        assertTrue(config.contains("Address = 10.0.0.5/32"));
        assertTrue(config.contains("PersistentKeepalive = 25"));
    }

    @Test
    void testProcessCertificate_Success() throws Exception {
        String pem = createSignedCertificatePEM("test@example.com", testWgPublicKey);
        CertificateService.CertificateResult result = certificateService.processCertificate(pem);

        assertTrue(result.valid());
        assertNull(result.errorMessage());
        assertEquals("test@example.com", result.commonName());
        assertNotNull(result.wireguardPublicKey());
        assertNotNull(result.wireguardConfig());
    }

    @Test
    void testProcessCertificate_UnauthorizedUser() throws Exception {
        String pem = createSignedCertificatePEM("unknown@example.com", testWgPublicKey);
        CertificateService.CertificateResult result = certificateService.processCertificate(pem);

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("not authorized"));
    }

    @Test
    void testProcessCertificate_NoWireguardKey() throws Exception {
        String pem = createSignedCertificatePEMWithoutExtension("test@example.com");
        CertificateService.CertificateResult result = certificateService.processCertificate(pem);

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("wireguard public key"));
    }

    private String createSignedCertificatePEM(String cn, byte[] wgPublicKey) throws Exception {
        var now = Calendar.getInstance();
        var expire = Calendar.getInstance();
        expire.add(Calendar.MONTH, 4);

        X500Name subject = new X500Name("CN=" + cn);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair clientKeyPair = keyGen.generateKeyPair();

        var builder = new X509v3CertificateBuilder(
                caCert.getSubject(),
                new BigInteger(128, new SecureRandom()),
                now.getTime(),
                expire.getTime(),
                subject,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(clientKeyPair.getPublic().getEncoded())
        );

        // Add wireguard public key extension
        builder.addExtension(new Extension(WG_PUBLIC_KEY_OID, false, new DEROctetString(wgPublicKey)));

        var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
        X509CertificateHolder cert = builder.build(signer);

        StringWriter sw = new StringWriter();
        try (var writer = new JcaPEMWriter(sw)) {
            writer.writeObject(cert);
        }
        return sw.toString();
    }

    private String createSignedCertificatePEMWithoutExtension(String cn) throws Exception {
        var now = Calendar.getInstance();
        var expire = Calendar.getInstance();
        expire.add(Calendar.MONTH, 4);

        X500Name subject = new X500Name("CN=" + cn);

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair clientKeyPair = keyGen.generateKeyPair();

        var builder = new X509v3CertificateBuilder(
                caCert.getSubject(),
                new BigInteger(128, new SecureRandom()),
                now.getTime(),
                expire.getTime(),
                subject,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(clientKeyPair.getPublic().getEncoded())
        );

        var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
        X509CertificateHolder cert = builder.build(signer);

        StringWriter sw = new StringWriter();
        try (var writer = new JcaPEMWriter(sw)) {
            writer.writeObject(cert);
        }
        return sw.toString();
    }

    /**
     * Test-specific config class that allows injecting test data.
     */
    static class TestWgKeymanConfig extends WgKeymanConfig {
        private final X509CertificateHolder caCert;
        private final java.util.Map<String, Integer> users;

        TestWgKeymanConfig(Path caCertPath, Path usersPath, X509CertificateHolder caCert) throws Exception {
            this(caCert, java.util.Map.of("test@example.com", 5, "admin@example.com", 10));
        }

        TestWgKeymanConfig(X509CertificateHolder caCert, java.util.Map<String, Integer> users) {
            this.caCert = caCert;
            this.users = new java.util.HashMap<>(users);
        }

        @Override
        public X509CertificateHolder getCaCert() {
            return caCert;
        }

        @Override
        public java.util.Map<String, Integer> getUserHostNumbers() {
            return users;
        }

        @Override
        public String getServerAddress() {
            return "10.0.0.1";
        }

        @Override
        public String getNetwork() {
            return "10.0.0.0/24";
        }

        @Override
        public String getServerEndpoint() {
            return "vpn.example.com:51820";
        }

        @Override
        public String getServerPublicKey() {
            return "TestServerPublicKey123456789012345678901234=";
        }

        @Override
        public String getClientAddress(int hostNumber) {
            return "10.0.0." + hostNumber + "/32";
        }

        @Override
        public String getAllowedIps() {
            return "10.0.0.0/24";
        }

        @Override
        public String getCertDatesFile() {
            return System.getProperty("java.io.tmpdir") + "/wg-keyman-test-cert-dates.dat";
        }

        @Override
        public String getPeersFile() {
            return System.getProperty("java.io.tmpdir") + "/wg-keyman-test-peers.conf";
        }
    }
}
