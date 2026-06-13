package com.homeofcode.wgkeyman;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileTime;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@Configuration
public class WgKeymanConfig {

    @Value("${wgmgr.server:}")
    private String serverAddress;

    @Value("${wgmgr.network:}")
    private String network;

    @Value("${wgmgr.server-endpoint:}")
    private String serverEndpoint;

    @Value("${wgmgr.server-public-key:}")
    private String serverPublicKey;

    @Value("${wgmgr.users-file:}")
    private String usersFilePath;

    @Value("${wgmgr.peers-file:peers.conf}")
    private String peersFile;

    @Value("${wgmgr.interface:wg0}")
    private String wgInterface;

    @Value("${wgmgr.sync-command:}")
    private String syncCommand;

    private volatile Map<String, Integer> userHostNumbers = new HashMap<>();
    private volatile FileTime usersFileLastModified;

    // Protected constructor for test subclasses
    protected WgKeymanConfig() {}

    /**
     * Build a config instance from a plain {@link Properties} bag instead of Spring's
     * {@code @Value} injection. Used by the administrative CLI, which loads the same
     * {@code application.properties} the server uses but does not boot Spring.
     *
     * <p>Defaults mirror the {@code @Value} defaults declared on the fields above. The same
     * {@link #init()} validation runs, so missing/invalid configuration fails fast.
     */
    public static WgKeymanConfig fromProperties(Properties props) {
        WgKeymanConfig c = new WgKeymanConfig();
        c.serverAddress = props.getProperty("wgmgr.server", "");
        c.network = props.getProperty("wgmgr.network", "");
        c.serverEndpoint = props.getProperty("wgmgr.server-endpoint", "");
        c.serverPublicKey = props.getProperty("wgmgr.server-public-key", "");
        c.usersFilePath = props.getProperty("wgmgr.users-file", "");
        c.peersFile = props.getProperty("wgmgr.peers-file", "peers.conf");
        c.wgInterface = props.getProperty("wgmgr.interface", "wg0");
        c.syncCommand = props.getProperty("wgmgr.sync-command", "");
        c.init();
        return c;
    }

    @PostConstruct
    public void init() {
        validateConfiguration();
        loadUsers();
    }

    /** Whether the configured VPN network is IPv6 (host numbers in users.lst are hex). */
    public boolean isNetworkIPv6() {
        return isIPv6(network.split("/")[0]);
    }

    private void validateConfiguration() {
        if (isBlank(serverAddress)) {
            exitWithError("wgmgr.server is not defined. Set the VPN server IP address.");
        }

        if (isBlank(network)) {
            exitWithError("wgmgr.network is not defined. Set the VPN network (e.g., 10.0.0.0/24 or fd00::/64).");
        } else if (!isValidNetworkFormat(network)) {
            exitWithError("wgmgr.network has invalid format: '" + network + "'. Expected format: IPv4/CIDR (e.g., 10.0.0.0/24) or IPv6/CIDR (e.g., fd00::/64).");
        }

        if (isBlank(serverEndpoint)) {
            exitWithError("wgmgr.server-endpoint is not defined. Set the server endpoint (e.g., vpn.example.com:51820).");
        }

        if (isBlank(serverPublicKey)) {
            exitWithError("wgmgr.server-public-key is not defined. Set the WireGuard server's public key.");
        }

        if (isBlank(usersFilePath)) {
            exitWithError("wgmgr.users-file is not defined. Set the path to the users list file.");
        } else if (!Files.exists(Path.of(usersFilePath))) {
            exitWithError("Users file not found: " + usersFilePath);
        }
    }

    private void exitWithError(String message) {
        System.err.println(message);
        Runtime.getRuntime().halt(1);
    }

    private boolean isBlank(String value) {
        return value == null || value.trim().isEmpty();
    }

    private boolean isValidNetworkFormat(String network) {
        String[] parts = network.split("/");
        if (parts.length != 2) {
            return false;
        }
        String ip = parts[0];
        try {
            int cidr = Integer.parseInt(parts[1]);
            if (isIPv6(ip)) {
                return cidr >= 0 && cidr <= 128;
            } else {
                // IPv4 validation
                String[] octets = ip.split("\\.");
                if (octets.length != 4) {
                    return false;
                }
                for (String octet : octets) {
                    int val = Integer.parseInt(octet);
                    if (val < 0 || val > 255) {
                        return false;
                    }
                }
                return cidr >= 0 && cidr <= 32;
            }
        } catch (NumberFormatException e) {
            return false;
        }
    }

    private boolean isIPv6(String ip) {
        return ip.contains(":");
    }

    private synchronized void loadUsers() {
        boolean ipv6 = isIPv6(network.split("/")[0]);
        Map<String, Integer> newUserHostNumbers = new HashMap<>();
        try {
            var path = Path.of(usersFilePath);
            usersFileLastModified = Files.getLastModifiedTime(path);
            for (String line : Files.readAllLines(path)) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\\s+", 2);
                if (parts.length == 2) {
                    try {
                        // For IPv6, parse host number as hex; for IPv4, parse as decimal
                        int hostNumber = Integer.parseInt(parts[0], ipv6 ? 16 : 10);
                        String cn = parts[1];
                        newUserHostNumbers.put(cn, hostNumber);
                    } catch (NumberFormatException e) {
                        String format = ipv6 ? "hexadecimal" : "decimal";
                        System.err.println("Warning: Invalid host number in users file (expected " + format + "): " + line);
                    }
                } else {
                    System.err.println("Warning: Invalid line format in users file (expected 'HOST_NUMBER EMAIL'): " + line);
                }
            }
        } catch (IOException e) {
            if (userHostNumbers.isEmpty()) {
                exitWithError("Could not read users file: " + e.getMessage());
            } else {
                System.err.println("Warning: Could not reload users file: " + e.getMessage());
                return;
            }
        }

        if (newUserHostNumbers.isEmpty()) {
            if (userHostNumbers.isEmpty()) {
                exitWithError("No users defined in users file: " + usersFilePath);
            } else {
                System.err.println("Warning: Users file is now empty, keeping existing users");
                return;
            }
        }

        userHostNumbers = newUserHostNumbers;
        System.out.println("Loaded " + userHostNumbers.size() + " users from " + usersFilePath);
    }

    /**
     * Check if the users file has been modified and reload if necessary.
     */
    private void reloadUsersIfChanged() {
        if (usersFilePath == null || usersFilePath.isEmpty()) {
            return;
        }
        try {
            Path path = Path.of(usersFilePath);
            FileTime currentModified = Files.getLastModifiedTime(path);
            if (usersFileLastModified == null || currentModified.compareTo(usersFileLastModified) > 0) {
                System.out.println("Users file changed, reloading...");
                loadUsers();
            }
        } catch (IOException e) {
            System.err.println("Warning: Could not check users file modification time: " + e.getMessage());
        }
    }

    public String getServerAddress() {
        return serverAddress;
    }

    public String getNetwork() {
        return network;
    }

    public String getServerEndpoint() {
        return serverEndpoint;
    }

    public String getServerPublicKey() {
        return serverPublicKey;
    }

    public Map<String, Integer> getUserHostNumbers() {
        reloadUsersIfChanged();
        return userHostNumbers;
    }

    public String getUsersFile() {
        return usersFilePath;
    }

    public String getPeersFile() {
        return peersFile;
    }

    public String getWgInterface() {
        return wgInterface;
    }

    public String getSyncCommand() {
        return syncCommand;
    }

    /**
     * Get the client IP address based on the network and host number.
     * For IPv4: replaces the last octet (e.g., 10.0.0.0/24 + host 5 = 10.0.0.5/32)
     * For IPv6: appends host as hex to prefix (e.g., fd00::/64 + host 5 = fd00::5/128)
     */
    public String getClientAddress(int hostNumber) {
        String[] networkParts = network.split("/");
        String baseIp = networkParts[0];

        if (isIPv6(baseIp)) {
            if (hostNumber < 1) {
                throw new IllegalArgumentException("Host number must be positive: " + hostNumber);
            }
            // IPv6: append host number as hex to the prefix
            String prefix = baseIp.endsWith("::") ? baseIp : baseIp.replaceAll("::?$", "::");
            return prefix + Integer.toHexString(hostNumber) + "/128";
        } else {
            // IPv4: this implementation replaces the last octet, so the host must fit a single
            // octet (1-254, excluding the network and broadcast addresses).
            if (hostNumber < 1 || hostNumber > 254) {
                throw new IllegalArgumentException(
                        "Host number out of range for IPv4 network (expected 1-254): " + hostNumber);
            }
            String[] octets = baseIp.split("\\.");
            octets[3] = String.valueOf(hostNumber);
            return String.join(".", octets) + "/32";
        }
    }

    /**
     * Get the allowed IPs for the client (typically the VPN network).
     */
    public String getAllowedIps() {
        return network;
    }
}
