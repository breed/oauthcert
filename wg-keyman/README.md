This SpringBoot server authenticates users with OAuth and lets them submit a WireGuard public key.
If the authenticated user's email matches the list of users, it returns a valid wireguard
configuration (minus the private key) and registers the user's public key as a peer.

# Run modes

The `wg-keyman` jar runs in one of two modes, selected by the first argument:

- **Server mode**: `serve` as the first argument starts the Spring Boot web server described below.
  The systemd unit (`wg-keyman.service`) is configured to pass `serve`.
  ```bash
  java -jar wg-keyman.jar serve
  ```
- **CLI mode**: any other first argument is an administrative subcommand, dispatched via PicoCLI
  **without** booting Spring (no Tomcat, no OAuth). It reads the same configuration the server uses
  (see [Administrative CLI](#administrative-cli)).
- With **no arguments**, the CLI usage/help message is printed.
  ```bash
  java -jar wg-keyman.jar
  ```

# Administrative CLI

CLI mode reuses the server's `application.properties` but does not start Spring. Configuration is
resolved in this order: the `spring.config.location` system property, the `SPRING_CONFIG_LOCATION`
environment variable (set by the systemd unit), `application.properties` in the working directory,
then the in-jar defaults. Command output goes to stdout; diagnostics go to stderr (so `generate`
output can be redirected to a file cleanly). Commands exit `0` on success, `1` on an operation
error, and `2` on a usage error.

```bash
# Users (entries in users.lst)
java -jar wg-keyman.jar user list
java -jar wg-keyman.jar user add <HOST_NUMBER> <CN>     # HOST_NUMBER is decimal (IPv4) or hex (IPv6)
java -jar wg-keyman.jar user remove <CN>

# Peers (entries in the peers file)
java -jar wg-keyman.jar peer list
java -jar wg-keyman.jar peer remove <CN>                # removes the managed peer and syncs WireGuard
java -jar wg-keyman.jar peer sync                        # rebuild peers.conf from current state and reload WireGuard

# Print a user's client config using their registered key (stdout, or -o <file>)
java -jar wg-keyman.jar generate <CN>
```

When run on the deployed server, invoke the CLI as the service user so it reads the deployment
config and can write the managed files:

```bash
sudo -u wgkeyman SPRING_CONFIG_LOCATION=/opt/wg-keyman/application.properties \
    java -jar /opt/wg-keyman/wg-keyman.jar user list
```

# HTTP endpoints

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
- if an existing configuration is being changed, the old configuration should be written to the configuration file with a .old extension.
  - the entries of the old configuration should be commented out
  - a comment will be added an entry indicating when it was added to the old configuration

# SpringBoot variables

- wgmgr.server: the VPN IP address of the wireguard server
- wgmgr.network: the VPN network address
- wgmgr.server-endpoint: the host:port of the internet address of the wireguard server
- wgmgr.server-public-key: the WireGuard server's public key
- wgmgr.users-file: path to users list file (reloaded automatically when changed)
- wgmgr.peers-file: path to WireGuard peers config file (default: peers.conf)
- wgmgr.interface: WireGuard interface name (default: wg0)
- wgmgr.sync-command: custom sync command (default: `sudo systemctl reload wg-quick@<interface>`)

# Important files

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
sudo cp users.lst /opt/wg-keyman/
sudo chown -R wgkeyman:wgkeyman /opt/wg-keyman
```

Edit `/opt/wg-keyman/application.properties` with your configuration.

## Configure sudo for WireGuard sync

The wg-keyman service uses systemd to reload the WireGuard configuration when peers change:

```bash
sudo systemctl reload wg-quick@wg0
```

Create a sudoers file to allow this without a password:

```bash
sudo visudo -f /etc/sudoers.d/wgkeyman
```

Add the following line (adjust interface name as needed):

```
wgkeyman ALL=(ALL) NOPASSWD: /usr/bin/systemctl reload wg-quick@wg0
```

To verify the configuration:

```bash
# Test the sudoers rule
sudo -u wgkeyman sudo -n systemctl reload wg-quick@wg0
```

This should run without prompting for a password (assuming the WireGuard interface exists).

**Security notes:**
- The sudoers rule only allows reloading the specific WireGuard interface
- The wgkeyman user cannot run any other commands as root
- If you change `wgmgr.interface` in application.properties, update the sudoers rule to match

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
