package com.homeofcode.wgkeyman;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class WgKeymanConfigTest {

    @TempDir
    Path tempDir;

    private WgKeymanConfig configForNetwork(String network) throws Exception {
        Path users = tempDir.resolve("users.lst");
        Files.writeString(users, "5 test@example.com\n");
        Properties p = new Properties();
        p.setProperty("wgmgr.server", "10.0.0.1");
        p.setProperty("wgmgr.network", network);
        p.setProperty("wgmgr.server-endpoint", "vpn.example.com:51820");
        p.setProperty("wgmgr.server-public-key", "TestServerPublicKey123456789012345678901234=");
        p.setProperty("wgmgr.users-file", users.toString());
        return WgKeymanConfig.fromProperties(p);
    }

    @Test
    void ipv4ClientAddressValid() throws Exception {
        assertEquals("10.0.0.5/32", configForNetwork("10.0.0.0/24").getClientAddress(5));
    }

    @Test
    void ipv4ClientAddressOutOfRangeThrows() throws Exception {
        WgKeymanConfig c = configForNetwork("10.0.0.0/24");
        assertThrows(IllegalArgumentException.class, () -> c.getClientAddress(255));
        assertThrows(IllegalArgumentException.class, () -> c.getClientAddress(0));
        assertThrows(IllegalArgumentException.class, () -> c.getClientAddress(-1));
    }

    @Test
    void ipv6ClientAddressValid() throws Exception {
        assertEquals("fd00::a/128", configForNetwork("fd00::/64").getClientAddress(10));
    }

    @Test
    void ipv6ClientAddressNonPositiveThrows() throws Exception {
        WgKeymanConfig c = configForNetwork("fd00::/64");
        assertThrows(IllegalArgumentException.class, () -> c.getClientAddress(0));
    }
}
