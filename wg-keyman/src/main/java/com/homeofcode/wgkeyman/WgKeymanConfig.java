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

    @Value("${wgmgr.server}")
    private String serverAddress;

    @Value("${wgmgr.network}")
    private String network;

    @Value("${wgmgr.server-endpoint}")
    private String serverEndpoint;

    @Value("${wgmgr.server-public-key}")
    private String serverPublicKey;

    @Value("${wgmgr.ca-cert:ca.crt}")
    private String caCertPath;

    @Value("${wgmgr.users-file:users.lst}")
    private String usersFilePath;

    private X509CertificateHolder caCert;
    private Map<String, Integer> userHostNumbers = new HashMap<>();

    @PostConstruct
    public void init() throws IOException {
        loadCaCert();
        loadUsers();
    }

    private void loadCaCert() throws IOException {
        try (var reader = new FileReader(caCertPath);
             var pemParser = new PEMParser(reader)) {
            caCert = (X509CertificateHolder) pemParser.readObject();
        }
    }

    private void loadUsers() throws IOException {
        var path = Path.of(usersFilePath);
        if (!Files.exists(path)) {
            return;
        }
        for (String line : Files.readAllLines(path)) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] parts = line.split("\\s+", 2);
            if (parts.length == 2) {
                int hostNumber = Integer.parseInt(parts[0]);
                String cn = parts[1];
                userHostNumbers.put(cn, hostNumber);
            }
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

    /**
     * Get the client IP address based on the network and host number.
     * For example, if network is "10.0.0.0/24" and hostNumber is 5,
     * returns "10.0.0.5/32".
     */
    public String getClientAddress(int hostNumber) {
        String[] networkParts = network.split("/");
        String baseIp = networkParts[0];
        String[] octets = baseIp.split("\\.");
        // Replace last octet with host number
        octets[3] = String.valueOf(hostNumber);
        return String.join(".", octets) + "/32";
    }

    /**
     * Get the allowed IPs for the client (typically the VPN network).
     */
    public String getAllowedIps() {
        return network;
    }
}
