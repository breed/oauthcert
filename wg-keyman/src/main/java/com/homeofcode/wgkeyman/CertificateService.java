package com.homeofcode.wgkeyman;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.springframework.stereotype.Service;

import java.io.StringReader;
import java.security.cert.X509Certificate;
import java.util.Base64;

@Service
public class CertificateService {

    private static final ASN1ObjectIdentifier WG_PUBLIC_KEY_OID =
            new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1");

    private final WgKeymanConfig config;

    public CertificateService(WgKeymanConfig config) {
        this.config = config;
    }

    /**
     * Parse a PEM-encoded certificate.
     */
    public X509CertificateHolder parseCertificate(String pemContent) throws Exception {
        try (var reader = new StringReader(pemContent);
             var pemParser = new PEMParser(reader)) {
            Object obj = pemParser.readObject();
            if (obj instanceof X509CertificateHolder) {
                return (X509CertificateHolder) obj;
            }
            throw new IllegalArgumentException("Invalid certificate format");
        }
    }

    /**
     * Validate that the certificate was signed by our CA.
     */
    public boolean validateCertificate(X509CertificateHolder cert) throws Exception {
        X509CertificateHolder caCert = config.getCaCert();

        // Convert CA cert to X509Certificate for verification
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();
        X509Certificate caCertX509 = converter.getCertificate(caCert);

        // Create content verifier from CA's public key
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                .build(caCertX509.getPublicKey());

        return cert.isSignatureValid(verifierProvider);
    }

    /**
     * Extract the Common Name (CN) from the certificate subject.
     */
    public String extractCommonName(X509CertificateHolder cert) {
        X500Name subject = cert.getSubject();
        RDN[] rdns = subject.getRDNs(BCStyle.CN);
        if (rdns.length > 0) {
            return rdns[0].getFirst().getValue().toString();
        }
        return null;
    }

    /**
     * Extract the wireguard public key from the certificate extension.
     * The extension value is stored as an OCTET STRING containing the raw 32-byte public key.
     */
    public String extractWireguardPublicKey(X509CertificateHolder cert) {
        Extension ext = cert.getExtension(WG_PUBLIC_KEY_OID);
        if (ext == null) {
            return null;
        }
        // Get the raw bytes directly from the extension value (OCTET STRING)
        byte[] wgPublicKey = ext.getExtnValue().getOctets();
        return Base64.getEncoder().encodeToString(wgPublicKey);
    }

    /**
     * Check if the CN is in the authorized users list.
     */
    public boolean isAuthorizedUser(String cn) {
        return config.getUserHostNumbers().containsKey(cn);
    }

    /**
     * Get the host number for a user.
     */
    public Integer getHostNumber(String cn) {
        return config.getUserHostNumbers().get(cn);
    }

    /**
     * Generate the wireguard configuration for a client.
     */
    public String generateWireguardConfig(String cn, String clientPublicKey) {
        Integer hostNumber = getHostNumber(cn);
        if (hostNumber == null) {
            throw new IllegalArgumentException("User not found: " + cn);
        }

        String clientAddress = config.getClientAddress(hostNumber);

        StringBuilder config = new StringBuilder();
        config.append("[Interface]\n");
        config.append("# Add your private key below\n");
        config.append("# PrivateKey = <YOUR_PRIVATE_KEY>\n");
        config.append("Address = ").append(clientAddress).append("\n");
        config.append("\n");
        config.append("[Peer]\n");
        config.append("PublicKey = ").append(this.config.getServerPublicKey()).append("\n");
        config.append("Endpoint = ").append(this.config.getServerEndpoint()).append("\n");
        config.append("AllowedIPs = ").append(this.config.getAllowedIps()).append("\n");
        config.append("PersistentKeepalive = 25\n");

        return config.toString();
    }

    /**
     * Result of processing a certificate upload.
     */
    public record CertificateResult(
            boolean valid,
            String errorMessage,
            String commonName,
            String wireguardPublicKey,
            String wireguardConfig
    ) {
        public static CertificateResult error(String message) {
            return new CertificateResult(false, message, null, null, null);
        }

        public static CertificateResult success(String cn, String wgPublicKey, String wgConfig) {
            return new CertificateResult(true, null, cn, wgPublicKey, wgConfig);
        }
    }

    /**
     * Process an uploaded certificate and return the result.
     */
    public CertificateResult processCertificate(String pemContent) {
        try {
            // Parse the certificate
            X509CertificateHolder cert = parseCertificate(pemContent);

            // Validate signature
            if (!validateCertificate(cert)) {
                return CertificateResult.error("Certificate was not signed by the trusted CA");
            }

            // Extract CN
            String cn = extractCommonName(cert);
            if (cn == null) {
                return CertificateResult.error("Certificate does not contain a Common Name");
            }

            // Check authorization
            if (!isAuthorizedUser(cn)) {
                return CertificateResult.error("User '" + cn + "' is not authorized");
            }

            // Extract wireguard public key
            String wgPublicKey = extractWireguardPublicKey(cert);
            if (wgPublicKey == null) {
                return CertificateResult.error("Certificate does not contain a wireguard public key extension");
            }

            // Generate config
            String wgConfig = generateWireguardConfig(cn, wgPublicKey);

            return CertificateResult.success(cn, wgPublicKey, wgConfig);

        } catch (Exception e) {
            return CertificateResult.error("Error processing certificate: " + e.getMessage());
        }
    }
}
