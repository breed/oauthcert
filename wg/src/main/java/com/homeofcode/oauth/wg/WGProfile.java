package com.homeofcode.oauth.wg;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import picocli.CommandLine;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.concurrent.Callable;

public class WGProfile {

    // Custom OID for wireguard public key extension (under private enterprise arc)
    public static final ASN1ObjectIdentifier WG_PUBLIC_KEY_OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1");

    static int screenWidth = 80;
    static String authUrl;

    public static void main(String[] args) {
        try {
            var authUrlStream = WGProfile.class.getResourceAsStream("/authUrl");
            if (authUrlStream == null) {
                throw new IOException("/authUrl missing from jar file.");
            }
            authUrl = new String(authUrlStream.readAllBytes()).trim();
        } catch (IOException e) {
            System.out.println(screenWidth);
            Cli.error("Internal error: " + e.getMessage());
            System.exit(2);
        }
        CommandLine commandLine = new CommandLine(new Cli());
        screenWidth = commandLine.getCommandSpec().usageMessage().autoWidth(true).width();
        if (screenWidth < 20) screenWidth = 80;
        System.exit(commandLine.execute(args));
    }

    /**
     * Generate a wireguard key pair (Curve25519).
     * Returns a byte array where the first 32 bytes are the private key
     * and the last 32 bytes are the public key.
     */
    static byte[] generateWireguardKeyPair() {
        SecureRandom random = new SecureRandom();
        byte[] privateKey = new byte[32];
        random.nextBytes(privateKey);

        // Clamp the private key per Curve25519 spec
        privateKey[0] &= 248;
        privateKey[31] &= 127;
        privateKey[31] |= 64;

        // Generate public key using X25519 base point multiplication
        byte[] publicKey = x25519ScalarMultBase(privateKey);

        byte[] keyPair = new byte[64];
        System.arraycopy(privateKey, 0, keyPair, 0, 32);
        System.arraycopy(publicKey, 0, keyPair, 32, 32);
        return keyPair;
    }

    /**
     * X25519 scalar multiplication with base point.
     * Uses BouncyCastle's X25519 implementation.
     */
    static byte[] x25519ScalarMultBase(byte[] scalar) {
        byte[] publicKey = new byte[32];
        org.bouncycastle.math.ec.rfc7748.X25519.scalarMultBase(scalar, 0, publicKey, 0);
        return publicKey;
    }

    @CommandLine.Command(name = "WGProfile", mixinStandardHelpOptions = true, description = "Generate a CSR with wireguard public key for signing.")
    static class Cli implements Callable<Integer> {

        static {
            // make sure we don't miss any exceptions
            Thread.setDefaultUncaughtExceptionHandler((t, te) -> te.printStackTrace());
            System.setProperty("java.util.logging.SimpleFormatter.format", "%1$tF %1$tT %4$s %5$s%n");
        }

        @CommandLine.Parameters(index = "0", description = "email")
        private String email;

        @CommandLine.Option(names = "-d", description = "working directory for certificates.")
        private final File workingDirectory = new File(".");

        static void wrapOutput(String str) {
            var line = new CommandLine.Help.Column(screenWidth, 0, CommandLine.Help.Column.Overflow.WRAP);
            var txtTable = CommandLine.Help.TextTable.forColumns(
                    CommandLine.Help.defaultColorScheme(CommandLine.Help.Ansi.AUTO), line);
            txtTable.indentWrappedLines = 0;
            txtTable.addRowValues(str);
            System.out.print(txtTable);
            System.out.flush();
        }

        static void error(String message) {
            wrapOutput(CommandLine.Help.Ansi.AUTO.string("@|red " + message + "|@"));
        }

        static void info(String message) {
            wrapOutput(CommandLine.Help.Ansi.AUTO.string("@|blue " + message + "|@"));
        }

        @Override
        public Integer call()
                throws NoSuchAlgorithmException, OperatorCreationException, IOException, InterruptedException {

            /* validate all the parameters first */
            if (!workingDirectory.isDirectory()) {
                error(String.format("%s is not a valid working directory.", workingDirectory.getCanonicalPath()));
                System.exit(2);
            }
            var csrFile = new File(workingDirectory, String.format("%s.csr", email));
            var signedFile = new File(workingDirectory, String.format("%s.crt", email));
            if (signedFile.exists()) {
                if (!signedFile.delete()) {
                    error(String.format("Could not remove %s.", signedFile.getCanonicalPath()));
                    System.exit(2);
                } else {
                    info(String.format("Deleted %s.", signedFile.getCanonicalPath()));
                }
            }

            /* generate wireguard key pair */
            byte[] wgKeyPair = generateWireguardKeyPair();
            byte[] wgPrivateKey = new byte[32];
            byte[] wgPublicKey = new byte[32];
            System.arraycopy(wgKeyPair, 0, wgPrivateKey, 0, 32);
            System.arraycopy(wgKeyPair, 32, wgPublicKey, 0, 32);

            String wgPrivateKeyBase64 = Base64.getEncoder().encodeToString(wgPrivateKey);
            String wgPublicKeyBase64 = Base64.getEncoder().encodeToString(wgPublicKey);

            /* generate RSA key pair for CSR signing */
            var gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);
            KeyPair pair = gen.generateKeyPair();

            /* create extension with wireguard public key */
            Extension wgPubKeyExt = new Extension(WG_PUBLIC_KEY_OID, false, new DEROctetString(wgPublicKey));
            Extensions extensions = new Extensions(wgPubKeyExt);

            /* generate CSR with wireguard public key extension */
            var csrSigner = new JcaContentSignerBuilder("SHA256withRSA").build(pair.getPrivate());
            var csrBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Principal("CN=" + email), pair.getPublic());
            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extensions);
            var csr = csrBuilder.build(csrSigner);

            var csrPem = new StringWriter();
            try (var csrPemWriter = new JcaPEMWriter(csrPem)) {
                csrPemWriter.writeObject(csr);
            }
            Files.writeString(csrFile.toPath(), csrPem.toString());

            info(String.format("Please go to %s to get the file %s signed and put the signed file in %s.", authUrl,
                    csrFile.getCanonicalPath(), signedFile.getCanonicalPath()));

            String waitingString = String.format("Waiting for %s  ", signedFile.getCanonicalPath());
            System.out.print(waitingString);
            var pattern = new char[]{'|', '/', '-', '\\', '|', '/', '-', '\\'};
            var patternIndex = 0;
            while (!signedFile.exists()) {
                System.out.printf("\b%c", pattern[patternIndex]);
                System.out.flush();
                patternIndex = (patternIndex + 1) % pattern.length;
                Thread.sleep(1000);
            }
            System.out.printf("\b\u2705\n");
            System.out.flush();

            /* output wireguard private key */
            System.out.println();
            System.out.println("PrivateKey = " + wgPrivateKeyBase64);
            System.out.println();
            info("Upload the certificate file to a wg-keyman server to get a complete wireguard config.");
            info(String.format("Wireguard public key: %s", wgPublicKeyBase64));

            return 0;
        }
    }
}
