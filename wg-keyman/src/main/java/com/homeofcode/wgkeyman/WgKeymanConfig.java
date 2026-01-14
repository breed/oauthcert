package com.homeofcode.wgkeyman;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.openssl.PEMParser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

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

    @Value("${wgmgr.ca-cert:}")
    private String caCertPath;

    @Value("${wgmgr.users-file:}")
    private String usersFilePath;

    @Value("${wgmgr.cert-dates-file:cert-dates.dat}")
    private String certDatesFile;

    private X509CertificateHolder caCert;
    private Map<String, Integer> userHostNumbers = new HashMap<>();

    // Protected constructor for test subclasses
    protected WgKeymanConfig() {}

    @PostConstruct
    public void init() {
        validateConfiguration();
        loadCaCert();
        loadUsers();
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

        if (isBlank(caCertPath)) {
            exitWithError("wgmgr.ca-cert is not defined. Set the path to the CA certificate file.");
        } else if (!Files.exists(Path.of(caCertPath))) {
            exitWithError("CA certificate file not found: " + caCertPath);
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

    private void loadCaCert() {
        try (var reader = new FileReader(caCertPath);
             var pemParser = new PEMParser(reader)) {
            caCert = (X509CertificateHolder) pemParser.readObject();
            if (caCert == null) {
                exitWithError("Could not parse CA certificate from: " + caCertPath);
            }
        } catch (IOException e) {
            exitWithError("Could not read CA certificate file: " + e.getMessage());
        }
    }

    private void loadUsers() {
        boolean ipv6 = isIPv6(network.split("/")[0]);
        try {
            var path = Path.of(usersFilePath);
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
                        userHostNumbers.put(cn, hostNumber);
                    } catch (NumberFormatException e) {
                        String format = ipv6 ? "hexadecimal" : "decimal";
                        exitWithError("Invalid host number in users file (expected " + format + "): " + line);
                    }
                } else {
                    exitWithError("Invalid line format in users file (expected 'HOST_NUMBER EMAIL'): " + line);
                }
            }
        } catch (IOException e) {
            exitWithError("Could not read users file: " + e.getMessage());
        }

        if (userHostNumbers.isEmpty()) {
            exitWithError("No users defined in users file: " + usersFilePath);
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

    public X509CertificateHolder getCaCert() {
        return caCert;
    }

    public Map<String, Integer> getUserHostNumbers() {
        return userHostNumbers;
    }

    public String getCertDatesFile() {
        return certDatesFile;
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
            // IPv6: append host number as hex to the prefix
            String prefix = baseIp.endsWith("::") ? baseIp : baseIp.replaceAll("::?$", "::");
            return prefix + Integer.toHexString(hostNumber) + "/128";
        } else {
            // IPv4: replace last octet
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
