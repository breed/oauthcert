# OAuthCert Server

This server receives CSR files and authenticates the client using OAuth, matching the OAuth identity to the CSR before signing the certificate.

# Configuration

Create a properties file with the following settings:

| Property | Description |
|----------|-------------|
| clientId | Google OAuth client ID |
| clientSecret | Google OAuth client secret |
| redirectURL | OAuth callback URL (must end with `/login/callback`) |
| authDomain | Email domain to authenticate (e.g., `example.com`) |
| authDBFile | SQLite database connection string (e.g., `jdbc:sqlite:auth.db`) |
| CAPrivateKey | Path to CA private key file (PEM format) |
| CACert | Path to CA certificate file (PEM format) |
| serverCert | (Optional) Path to TLS certificate for HTTPS |
| serverKey | (Optional) Path to TLS private key for HTTPS |

# Running as a systemd service

## Build the jar

```bash
mvn package -pl server
```

## Create system user

```bash
sudo useradd -r -s /bin/false oauthcert
```

## Install files

```bash
sudo mkdir -p /opt/oauthcert/server
sudo cp server/target/oauthcert-server-*.jar /opt/oauthcert/server/oauthcert-server.jar
sudo cp /path/to/server.properties /opt/oauthcert/server/
sudo cp /path/to/ca.key /opt/oauthcert/server/
sudo cp /path/to/ca.crt /opt/oauthcert/server/
sudo chown -R oauthcert:oauthcert /opt/oauthcert
sudo chmod 600 /opt/oauthcert/server/server.properties
sudo chmod 600 /opt/oauthcert/server/ca.key
```

Edit `/opt/oauthcert/server/server.properties` with your configuration.

## Install and start the service

```bash
sudo cp server/oauthcert-server.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now oauthcert-server
```

## Check status and logs

```bash
sudo systemctl status oauthcert-server
sudo journalctl -u oauthcert-server -f
```

# CSR Extension Support

The server copies extensions from the CSR to the signed certificate. This allows clients to embed custom data (such as WireGuard public keys) that will be preserved in the signed certificate.

| Field | Value |
|-------|-------|
| OID | `1.3.6.1.4.1.99999.1` |
| Critical | No |
| Value | 32-byte Curve25519 public key (DER OCTET STRING) |
