This SpringBoot server will have a single page that users can upload their signed certificate files to.
If the CN in the certificate matches the list of users, it will return a page with a valid wireguard configuration minus the private key.

# Wireguard Public Key Extraction

The server extracts the client's wireguard public key from an X.509 extension in the uploaded certificate.

| Field | Value |
|-------|-------|
| OID | `1.3.6.1.4.1.99999.1` |
| Critical | No |
| Value | 32-byte Curve25519 public key (DER OCTET STRING) |

To extract using BouncyCastle:

```java
X509CertificateHolder cert = // load certificate
Extension ext = cert.getExtension(new ASN1ObjectIdentifier("1.3.6.1.4.1.99999.1"));
byte[] wgPublicKey = ext.getExtnValue().getOctets();
String base64Key = Base64.getEncoder().encodeToString(wgPublicKey);
```

# SpringBoot variables

- wgmgr.server: the VPN IP address of the wireguard server
- wgmgr.network: the VPN network address
- wgmgr.server-endpoint: the host:port of the internet address of the wireguard server

# Important files

- ca.cert: certificate file for validating uploaded certificates.
- users.lst: List of valid common names mapped to addresses

# users.lst file format

- each line has a HOST_NUMBER followed by whitespace followed by the CN of the user
- lines that start with # are treated as a comment
- blank lines are ignored
