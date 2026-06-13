package com.homeofcode.wgkeyman.cli;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayOutputStream;
import java.io.FileWriter;
import java.io.PrintStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Calendar;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for the admin CLI. These build a throwaway configuration (CA cert, users.lst,
 * peers.conf, application.properties) in a temp dir, point {@code spring.config.location} at it,
 * and drive {@link AdminCli#run(String[])} directly.
 */
class AdminCliTest {

    private static final String VALID_WG_KEY = Base64.getEncoder().encodeToString(new byte[32]); // 44 chars, ends '='

    @TempDir
    Path tempDir;

    private PrintStream originalOut;
    private ByteArrayOutputStream captured;
    private String previousConfigLocation;
    private KeyPair caKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        // Build a self-signed CA certificate so config validation/loading succeeds.
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        caKeyPair = keyGen.generateKeyPair();

        Calendar now = Calendar.getInstance();
        Calendar expire = Calendar.getInstance();
        expire.add(Calendar.YEAR, 1);
        X500Name caSubject = new X500Name("CN=Test CA");
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                caSubject, BigInteger.valueOf(1), now.getTime(), expire.getTime(), caSubject,
                SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded()));
        X509CertificateHolder caCert =
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate()));

        Path caCertPath = tempDir.resolve("ca.crt");
        try (JcaPEMWriter writer = new JcaPEMWriter(new FileWriter(caCertPath.toFile()))) {
            writer.writeObject(caCert);
        }

        Files.writeString(tempDir.resolve("users.lst"), "5 test@example.com\n10 admin@example.com\n");
        Files.writeString(tempDir.resolve("peers.conf"), "");

        Path props = tempDir.resolve("application.properties");
        Files.writeString(props, String.join("\n",
                "wgmgr.server=10.0.0.1",
                "wgmgr.network=10.0.0.0/24",
                "wgmgr.server-endpoint=vpn.example.com:51820",
                "wgmgr.server-public-key=" + VALID_WG_KEY,
                "wgmgr.ca-cert=" + caCertPath,
                "wgmgr.users-file=" + tempDir.resolve("users.lst"),
                "wgmgr.peers-file=" + tempDir.resolve("peers.conf"),
                "wgmgr.sync-command=echo synced",
                ""));

        previousConfigLocation = System.getProperty("spring.config.location");
        System.setProperty("spring.config.location", props.toString());

        originalOut = System.out;
        captured = new ByteArrayOutputStream();
        System.setOut(new PrintStream(captured, true, StandardCharsets.UTF_8));
    }

    @AfterEach
    void tearDown() {
        System.setOut(originalOut);
        if (previousConfigLocation == null) {
            System.clearProperty("spring.config.location");
        } else {
            System.setProperty("spring.config.location", previousConfigLocation);
        }
    }

    private String stdout() {
        return captured.toString(StandardCharsets.UTF_8);
    }

    @Test
    void userListShowsConfiguredUsers() {
        assertEquals(0, AdminCli.run(new String[]{"user", "list"}));
        String out = stdout();
        assertTrue(out.contains("test@example.com"), out);
        assertTrue(out.contains("admin@example.com"), out);
    }

    @Test
    void userAddThenListIncludesNewUser() {
        assertEquals(0, AdminCli.run(new String[]{"user", "add", "20", "new@example.com"}));
        captured.reset();
        assertEquals(0, AdminCli.run(new String[]{"user", "list"}));
        assertTrue(stdout().contains("new@example.com"));
    }

    @Test
    void userAddDuplicateFails() {
        assertEquals(1, AdminCli.run(new String[]{"user", "add", "99", "test@example.com"}));
    }

    @Test
    void userRemoveDropsUser() {
        assertEquals(0, AdminCli.run(new String[]{"user", "remove", "admin@example.com"}));
        captured.reset();
        AdminCli.run(new String[]{"user", "list"});
        assertFalse(stdout().contains("admin@example.com"));
    }

    @Test
    void generateProducesConfigForAuthorizedUser() {
        assertEquals(0, AdminCli.run(new String[]{"generate", "--cn", "test@example.com", "--public-key", VALID_WG_KEY}));
        String out = stdout();
        assertTrue(out.contains("[Interface]"), out);
        assertTrue(out.contains("Address = 10.0.0.5/32"), out);
        assertTrue(out.contains("PublicKey = " + VALID_WG_KEY), out);
    }

    @Test
    void generateRejectsUnauthorizedUser() {
        assertEquals(1, AdminCli.run(new String[]{"generate", "--cn", "nobody@example.com", "--public-key", VALID_WG_KEY}));
    }

    @Test
    void generateRequiresKeyOrCert() {
        assertEquals(2, AdminCli.run(new String[]{"generate", "--cn", "test@example.com"}));
    }

    @Test
    void peerListEmptyByDefault() {
        assertEquals(0, AdminCli.run(new String[]{"peer", "list"}));
        assertTrue(stdout().contains("no managed peers"));
    }

    @Test
    void generateFromSignedCertProducesConfig() throws Exception {
        Path certPath = tempDir.resolve("client.crt");
        Files.writeString(certPath, signedClientCertPem("test@example.com", new byte[32]));

        assertEquals(0, AdminCli.run(new String[]{"generate", "--cert", certPath.toString()}));
        String out = stdout();
        assertTrue(out.contains("[Interface]"), out);
        assertTrue(out.contains("Address = 10.0.0.5/32"), out);
        assertTrue(out.contains("PublicKey = " + VALID_WG_KEY), out);
    }

    @Test
    void generateRejectsCertAndKeyTogether() throws Exception {
        Path certPath = tempDir.resolve("client.crt");
        Files.writeString(certPath, signedClientCertPem("test@example.com", new byte[32]));
        assertEquals(2, AdminCli.run(new String[]{
                "generate", "--cert", certPath.toString(), "--cn", "test@example.com", "--public-key", VALID_WG_KEY}));
    }

    @Test
    void unknownSubcommandReturnsUsageError() {
        assertEquals(2, AdminCli.run(new String[]{"bogus"}));
    }

    @Test
    void noArgumentsPrintsHelp() {
        assertEquals(0, AdminCli.run(new String[]{}));
        String out = stdout();
        assertTrue(out.contains("Usage:"), out);
        assertTrue(out.contains("user"), out);
        assertTrue(out.contains("peer"), out);
        assertTrue(out.contains("generate"), out);
    }

    /** Mint a client certificate signed by the test CA, carrying the WireGuard public key extension. */
    private String signedClientCertPem(String cn, byte[] wgKey) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair clientKeyPair = keyGen.generateKeyPair();

        Calendar now = Calendar.getInstance();
        Calendar expire = Calendar.getInstance();
        expire.add(Calendar.YEAR, 1);

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
                new X500Name("CN=Test CA"),
                BigInteger.valueOf(2),
                now.getTime(),
                expire.getTime(),
                new X500Name("CN=" + cn),
                SubjectPublicKeyInfo.getInstance(clientKeyPair.getPublic().getEncoded()));
        builder.addExtension(new org.bouncycastle.asn1.x509.Extension(
                new org.bouncycastle.asn1.ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"),
                false,
                new org.bouncycastle.asn1.DEROctetString(wgKey)));

        X509CertificateHolder cert =
                builder.build(new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate()));

        java.io.StringWriter sw = new java.io.StringWriter();
        try (JcaPEMWriter writer = new JcaPEMWriter(sw)) {
            writer.writeObject(cert);
        }
        return sw.toString();
    }
}
