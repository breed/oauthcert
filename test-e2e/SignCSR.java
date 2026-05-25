import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import java.io.FileReader;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.util.Calendar;
import java.util.Random;

public class SignCSR {
    public static void main(String[] args) throws Exception {
        if (args.length != 4) {
            System.out.println("Usage: java SignCSR <ca.key> <ca.crt> <input.csr> <output.crt>");
            System.exit(1);
        }

        String caKeyFile = args[0];
        String caCertFile = args[1];
        String csrFile = args[2];
        String outputFile = args[3];

        // Load CA private key
        PEMParser keyParser = new PEMParser(new FileReader(caKeyFile));
        Object keyObj = keyParser.readObject();
        PrivateKey caKey;
        if (keyObj instanceof KeyPair) {
            caKey = ((KeyPair) keyObj).getPrivate();
        } else if (keyObj instanceof org.bouncycastle.openssl.PEMKeyPair) {
            caKey = new JcaPEMKeyConverter().getPrivateKey(((org.bouncycastle.openssl.PEMKeyPair) keyObj).getPrivateKeyInfo());
        } else {
            caKey = new JcaPEMKeyConverter().getPrivateKey((org.bouncycastle.asn1.pkcs.PrivateKeyInfo) keyObj);
        }
        keyParser.close();

        // Load CA certificate
        PEMParser certParser = new PEMParser(new FileReader(caCertFile));
        org.bouncycastle.cert.X509CertificateHolder caCert =
            (org.bouncycastle.cert.X509CertificateHolder) certParser.readObject();
        certParser.close();

        // Load CSR
        PEMParser csrParser = new PEMParser(new FileReader(csrFile));
        PKCS10CertificationRequest csr = (PKCS10CertificationRequest) csrParser.readObject();
        csrParser.close();

        // Build certificate
        var now = Calendar.getInstance();
        var expire = Calendar.getInstance();
        expire.add(Calendar.MONTH, 4);

        var builder = new X509v3CertificateBuilder(
            caCert.getSubject(),
            new BigInteger(128, new Random()),
            now.getTime(),
            expire.getTime(),
            csr.getSubject(),
            csr.getSubjectPublicKeyInfo()
        );

        // Copy extensions from CSR
        Attribute[] attributes = csr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        for (Attribute attr : attributes) {
            for (ASN1Encodable value : attr.getAttributeValues()) {
                Extensions extensions = Extensions.getInstance(value);
                for (var oid : extensions.getExtensionOIDs()) {
                    Extension ext = extensions.getExtension(oid);
                    builder.addExtension(ext);
                    System.out.println("Added extension: " + oid);
                }
            }
        }

        // Sign
        String sigAlg = caKey.getAlgorithm().equals("EC") ? "SHA256withECDSA" : "SHA256WithRSA";
        var signer = new JcaContentSignerBuilder(sigAlg).build(caKey);
        var holder = builder.build(signer);

        // Write output
        try (var writer = new JcaPEMWriter(new FileWriter(outputFile))) {
            writer.writeObject(holder);
        }

        System.out.println("Signed certificate written to: " + outputFile);
    }
}
