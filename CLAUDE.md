# Project Description

Maven multi-module project for generating and using X.509 certificates signed via OAuth (for
openVPN and WireGuard), plus a WireGuard key manager.

# Artifacts

There are four maven modules:

- server: receives CSR files and authenticates the client using OAuth and matches the OAuth id to the CSR before signing the certificate.
- ovpn: a cli that generates a CSR for an email address and generates an openVPN profile when the certificate is signed.
- wg: a cli that generates a CSR similar to ovpn but also includes a public key that can be used with wireguard
- wg-keyman: a SpringBoot server where users authenticate via OAuth and submit a WireGuard public key; it matches the user's email against the user list and registers a WireGuard peer with an allocated address. The same jar also runs an administrative CLI mode when given a subcommand instead of `serve` (user/peer/generate); see `wg-keyman/README.md`.
