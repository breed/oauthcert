This SpringBoot server will have a single page that users can upload their signed certificate files to.
If the CN in the certificate matches the list of users, it will return a page with a valid wireguard configuration minus the private key.

# HTTP endpoints

- /x509 endpoints process X.509 certificates with the X.509 extension for the wireguard public key
  - matches the CN from the X.509 certificate with the user list
  - adds the public key to the wireguard config using the address from the user list and the public key from the certificate
- /wg endpoints do the following
  - use oauth to authenticate the client
  - matches the client id with the user list
  - adds the public key to the wireguard config using the address from the user list and the public key that client supplies

# Wireguard configuration

- when a new public key is supplied for a user the wireguard configuration is updated
  - the user's IP address is constructed from the VPN network address and the users HOST_NUMBER
  - the user's IP address and public key is added to the wireguard configuration
  - a comment is added to the configuration indicating
    - the user's name
    - the date it was added
    - the issue date of the certificate if X.509 was used
- if an existing configuration is being changed, the old configuration should be written to the configuration file with a .old extension.
  - the entries of the old configuration should be commented out
  - a comment will be added an entry indicating when it was added to the old configuration

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
- wgmgr.server-public-key: the WireGuard server's public key
- wgmgr.ca-cert: path to CA certificate for validating X.509 certificates
- wgmgr.users-file: path to users list file (reloaded automatically when changed)
- wgmgr.peers-file: path to WireGuard peers config file (default: peers.conf)
- wgmgr.interface: WireGuard interface name (default: wg0)
- wgmgr.sync-command: custom sync command (default: `wg-quick down/up <interface>`)
- wgmgr.x509-enabled: enable X.509 certificate upload endpoint (default: false)

# Important files

- ca.cert: certificate file for validating uploaded certificates.
- users.lst: List of valid common names mapped to addresses

# users.lst file format

- each line has a HOST_NUMBER followed by whitespace followed by the CN of the user
  if the network is an IPv4 network, HOST_NUMBER will be decimal, otherwise it will be hexadecimal
- lines that start with # are treated as a comment
- blank lines are ignored

# Running as a systemd service

## Build the jar

```bash
mvn package -pl wg-keyman
```

## Create system user

```bash
sudo useradd -r -s /bin/false wgkeyman
```

## Install files

```bash
sudo mkdir -p /opt/wg-keyman
sudo cp wg-keyman-*.jar /opt/wg-keyman/wg-keyman.jar
sudo cp application.properties /opt/wg-keyman/
sudo cp ca.crt /opt/wg-keyman/
sudo cp users.lst /opt/wg-keyman/
sudo chown -R wgkeyman:wgkeyman /opt/wg-keyman
```

Edit `/opt/wg-keyman/application.properties` with your configuration.

## Configure WireGuard to include peers.conf

The wg-keyman service writes peer configurations to `peers.conf`. Your main WireGuard configuration file needs to include this file. Edit `/etc/wireguard/wg0.conf` and add a `PostUp` directive:

```ini
[Interface]
PrivateKey = <server-private-key>
Address = 10.0.0.1/24
ListenPort = 51820
PostUp = wg addconf %i /opt/wg-keyman/peers.conf

# Static peers can still be added here
# [Peer]
# ...
```

The `PostUp` directive loads the peers from `peers.conf` when the interface comes up.

## Configure sudo for WireGuard sync

The wg-keyman service uses `wg-quick` to reload the WireGuard interface when peers change. Create a sudoers file to allow this without a password:

```bash
sudo visudo -f /etc/sudoers.d/wgkeyman
```

Add the following lines (adjust interface name as needed):

```
wgkeyman ALL=(ALL) NOPASSWD: /usr/bin/wg-quick down wg0
wgkeyman ALL=(ALL) NOPASSWD: /usr/bin/wg-quick up wg0
```

**Important:** The sudoers rules must match the exact commands that wg-keyman runs. By default, wg-keyman runs:
```
sudo /usr/bin/wg-quick down <interface>
sudo /usr/bin/wg-quick up <interface>
```

To verify the configuration:

```bash
# Test the sudoers rules
sudo -u wgkeyman sudo -n /usr/bin/wg-quick down wg0
sudo -u wgkeyman sudo -n /usr/bin/wg-quick up wg0
```

This should run without prompting for a password.

**Security notes:**
- The sudoers rules are restricted to only the specific `wg-quick` commands with exact arguments
- The wgkeyman user cannot run any other commands as root
- If you change `wgmgr.interface` in application.properties, update the sudoers rules to match
- Use `wgmgr.sync-command` to specify a custom sync command if needed

## Install and start the service

```bash
sudo cp wg-keyman.service /opt/wg-key-man
sudo systemctl enable --now /opt/wg-keyman/wg-keyman
```

## Check status and logs

```bash
sudo systemctl status wg-keyman
sudo journalctl -u wg-keyman -f
```
