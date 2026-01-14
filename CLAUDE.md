# Project Description

Three executable jar files to generate and use X.509 certificates signed using oauth with openVPN and wireguard.

# Artifacts

There are three maven projects:

- server: receives CSR files and authenticates the client using OAuth and matches the OAuth id to the CSR before signing the certificate.
- ovpn: a cli that generates a CSR for an email address and generates an openVPN profile when the certificate is signed.
- wg: a cli that generates a CSR similar to ovpn but also includes a public key that can be used with wireguard
- wg-keyman: a SpringBoot server that receives a signed certificate with a wireguard public key as an extended attribute and allocates a wireguard address for the client.
