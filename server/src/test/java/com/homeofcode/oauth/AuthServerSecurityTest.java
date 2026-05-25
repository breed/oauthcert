package com.homeofcode.oauth;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpContext;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpPrincipal;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Calendar;

import static org.junit.jupiter.api.Assertions.*;

class AuthServerSecurityTest {

    private AuthServer server;
    private KeyPair caKeyPair;
    private X509CertificateHolder caCert;
    private Connection connection;

    @BeforeEach
    void setUp() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        caKeyPair = keyGen.generateKeyPair();

        var now = Calendar.getInstance();
        var expire = Calendar.getInstance();
        expire.add(Calendar.YEAR, 1);
        var caSubject = new X500Name("CN=Test CA");
        var builder = new X509v3CertificateBuilder(
                caSubject, BigInteger.valueOf(1), now.getTime(), expire.getTime(), caSubject,
                org.bouncycastle.asn1.x509.SubjectPublicKeyInfo.getInstance(caKeyPair.getPublic().getEncoded()));
        var signer = new JcaContentSignerBuilder("SHA256withECDSA").build(caKeyPair.getPrivate());
        caCert = builder.build(signer);

        connection = DriverManager.getConnection("jdbc:sqlite::memory:");
        server = new AuthServer(connection, caKeyPair.getPrivate(), caCert, "test-client-id", "example.com");
    }

    // Vuln: CRLF injection in Content-Disposition header
    @Test
    void sendFileDownload_CRLFInFilename_IsSanitized() throws Exception {
        var headers = new Headers();
        var exchange = new StubHttpExchange(headers);

        server.sendFileDownload(exchange, "hello".getBytes(), "evil\r\nSet-Cookie: stolen=1");

        String cd = headers.getFirst("Content-Disposition");
        assertNotNull(cd);
        assertFalse(cd.contains("\r"), "CR must be sanitized from Content-Disposition");
        assertFalse(cd.contains("\n"), "LF must be sanitized from Content-Disposition");
        // CRLF replaced with underscore
        assertTrue(cd.contains("evil__Set-Cookie: stolen=1"));
    }

    @Test
    void sendFileDownload_QuoteInFilename_IsSanitized() throws Exception {
        var headers = new Headers();
        var exchange = new StubHttpExchange(headers);

        server.sendFileDownload(exchange, "data".getBytes(), "file\"inject.crt");

        String cd = headers.getFirst("Content-Disposition");
        assertFalse(cd.contains("\"inject"), "Quote injection must be sanitized");
    }

    // Vuln: CSR with tampered (invalid) signature must be rejected
    @Test
    void signCSR_TamperedSignature_ThrowsIOException() throws Exception {
        var gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        var pair = gen.generateKeyPair();
        var csrSigner = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        var csr = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=test@example.com"), pair.getPublic()).build(csrSigner);

        // Tamper the last bytes of the signature
        byte[] csrBytes = csr.getEncoded();
        csrBytes[csrBytes.length - 5] ^= 0xFF;

        var tampered = new PKCS10CertificationRequest(csrBytes);
        StringWriter sw = new StringWriter();
        try (var writer = new JcaPEMWriter(sw)) {
            writer.writeObject(tampered);
        }

        assertThrows(IOException.class, () -> server.signCSR(sw.toString().getBytes()),
                "Tampered CSR signature must be rejected");
    }

    // Vuln: Foreign extensions (e.g. BasicConstraints CA:true) must not be copied to signed cert
    @Test
    void signCSR_BasicConstraintsExtensionNotCopiedToCert() throws Exception {
        var gen = KeyPairGenerator.getInstance("RSA");
        gen.initialize(2048);
        var pair = gen.generateKeyPair();

        // Build CSR with BasicConstraints extension — this would allow cert to act as a CA
        var bcExt = new Extension(
                Extension.basicConstraints, true,
                new DEROctetString(new BasicConstraints(true)));
        var extensions = new Extensions(bcExt);
        var csrSigner = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
        var csrBuilder = new JcaPKCS10CertificationRequestBuilder(
                new X500Principal("CN=test@example.com"), pair.getPublic());
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
        var csr = csrBuilder.build(csrSigner);

        StringWriter sw = new StringWriter();
        try (var writer = new JcaPEMWriter(sw)) {
            writer.writeObject(csr);
        }

        X509CertificateHolder signed = server.signCSR(sw.toString().getBytes());

        assertNull(signed.getExtension(Extension.basicConstraints),
                "BasicConstraints from CSR must not be carried to signed cert (CA escalation)");
    }

    // Vuln: SQL injection in updateCertificateTable revoke query
    @Test
    void updateCertificateTable_InjectionInEmail_DoesNotRevokeBob() throws Exception {
        // Insert alice and bob with revoked=0
        try (var ps = connection.prepareStatement(
                "insert into certificate (serialNumber,email,revoked,expirationDate,signedCertificate) values(?,?,0,'2026-01-01',?)")) {
            ps.setString(1, "alice-sn-1");
            ps.setString(2, "alice@example.com");
            ps.setString(3, "ALICE_CERT");
            ps.execute();

            ps.setString(1, "bob-sn-1");
            ps.setString(2, "bob@example.com");
            ps.setString(3, "BOB_CERT");
            ps.execute();
        }

        // Inject: without PreparedStatement this would revoke ALL rows
        String injectedEmail = "alice@example.com' OR '1'='1";
        server.updateCertificateTable("new-sn-1", injectedEmail, caCert);

        // Bob must NOT be revoked
        try (var check = connection.prepareStatement(
                "select revoked from certificate where email=?")) {
            check.setString(1, "bob@example.com");
            var rs = check.executeQuery();
            assertTrue(rs.next(), "Bob's row should exist");
            assertEquals(0, rs.getInt("revoked"), "Bob must NOT be revoked by SQL injection");
        }
    }

    // Vuln: SQL injection in downloadSigned select query
    @Test
    void downloadSigned_InjectionInEmail_DoesNotLeakCert() throws Exception {
        // Insert alice's cert
        try (var ps = connection.prepareStatement(
                "insert into certificate (serialNumber,email,revoked,expirationDate,signedCertificate) values(?,?,0,'2026-01-01',?)")) {
            ps.setString(1, "alice-sn-1");
            ps.setString(2, "alice@example.com");
            ps.setString(3, "ALICE_SECRET_CERT");
            ps.execute();
        }

        // Without PreparedStatement: "' OR '1'='1" appended to email would return alice's cert
        String injectedEmail = "nobody@attacker.com' OR '1'='1";
        try (var stmt = connection.prepareStatement(
                "select signedCertificate from certificate where revoked = False and email = ?;")) {
            stmt.setString(1, injectedEmail);
            boolean hasResult = stmt.execute();
            if (hasResult) {
                assertFalse(stmt.getResultSet().next(),
                        "SQL injection must not leak alice's certificate");
            }
        }
    }

    // Vuln: java.util.Random used for nonce generation — must be SecureRandom
    @Test
    void rand_FieldIsSecureRandom() throws Exception {
        var field = AuthServer.class.getDeclaredField("rand");
        field.setAccessible(true);
        Object rand = field.get(server);
        assertInstanceOf(SecureRandom.class, rand,
                "rand must be java.security.SecureRandom, not java.util.Random");
    }

    // Minimal HttpExchange stub for sendFileDownload tests
    static class StubHttpExchange extends HttpExchange {
        private final Headers responseHeaders;
        private final ByteArrayOutputStream responseBody = new ByteArrayOutputStream();

        StubHttpExchange(Headers responseHeaders) {
            this.responseHeaders = responseHeaders;
        }

        @Override public Headers getResponseHeaders() { return responseHeaders; }
        @Override public OutputStream getResponseBody() { return responseBody; }
        @Override public void sendResponseHeaders(int rCode, long responseLength) {}
        @Override public URI getRequestURI() { return URI.create("/"); }
        @Override public String getRequestMethod() { return "GET"; }
        @Override public HttpContext getHttpContext() { return null; }
        @Override public void close() {}
        @Override public InputStream getRequestBody() { return InputStream.nullInputStream(); }
        @Override public Headers getRequestHeaders() { return new Headers(); }
        @Override public int getResponseCode() { return 0; }
        @Override public InetSocketAddress getRemoteAddress() { return null; }
        @Override public InetSocketAddress getLocalAddress() { return null; }
        @Override public String getProtocol() { return "HTTP/1.1"; }
        @Override public Object getAttribute(String name) { return null; }
        @Override public void setAttribute(String name, Object value) {}
        @Override public void setStreams(InputStream i, OutputStream o) {}
        @Override public HttpPrincipal getPrincipal() { return null; }
    }
}
