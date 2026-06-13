package com.homeofcode.wgkeyman;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class WireguardServiceTest {

    private WireguardService service;

    @BeforeEach
    void setUp() {
        service = new WireguardService(
                new TestWgKeymanConfig(Map.of("test@example.com", 5, "admin@example.com", 10)));
    }

    @Test
    void testIsAuthorizedUser_AuthorizedUser() {
        assertTrue(service.isAuthorizedUser("test@example.com"));
        assertTrue(service.isAuthorizedUser("admin@example.com"));
    }

    @Test
    void testIsAuthorizedUser_UnauthorizedUser() {
        assertFalse(service.isAuthorizedUser("unknown@example.com"));
    }

    @Test
    void testGetHostNumber() {
        assertEquals(5, service.getHostNumber("test@example.com"));
        assertEquals(10, service.getHostNumber("admin@example.com"));
        assertNull(service.getHostNumber("unknown@example.com"));
    }

    @Test
    void testGenerateWireguardConfig() {
        String config = service.generateWireguardConfig("test@example.com", "testpubkey");
        assertTrue(config.contains("[Interface]"));
        assertTrue(config.contains("[Peer]"));
        assertTrue(config.contains("Address = 10.0.0.5/32"));
        assertTrue(config.contains("PersistentKeepalive = 25"));
    }

    // Tests for processPublicKey (OAuth flow)

    @Test
    void testProcessPublicKey_Success() {
        String validPublicKey = "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=";
        WireguardService.WireguardResult result = service.processPublicKey("test@example.com", validPublicKey);

        assertTrue(result.valid());
        assertNull(result.errorMessage());
        assertEquals("test@example.com", result.commonName());
        assertEquals(validPublicKey, result.wireguardPublicKey());
        assertNotNull(result.wireguardConfig());
        assertTrue(result.wireguardConfig().contains("[Interface]"));
        assertTrue(result.wireguardConfig().contains("Address = 10.0.0.5/32"));
    }

    @Test
    void testProcessPublicKey_UnauthorizedUser() {
        String validPublicKey = "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=";
        WireguardService.WireguardResult result = service.processPublicKey("unknown@example.com", validPublicKey);

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("not authorized"));
    }

    @Test
    void testProcessPublicKey_UnauthorizedUser_IsNotAddedAsPeer() {
        String validPublicKey = "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=";
        service.processPublicKey("unknown@example.com", validPublicKey);

        // A user that authenticates but is not in the user list must never be persisted as a peer.
        assertFalse(service.listPeers().containsKey("unknown@example.com"));
    }

    @Test
    void testProcessPublicKey_ControlCharInEmail_IsRejected() {
        String validPublicKey = "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=";
        WireguardService.WireguardResult result = service.processPublicKey("test@example.com\nfoo", validPublicKey);
        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("Invalid user identifier"));
    }

    @Test
    void testGetPeerPublicKey() {
        // Note: the test config shares a peers file across tests, so don't assume an empty start;
        // assert the deterministic post-submit state and that an unknown user has no key.
        String validPublicKey = "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=";
        service.processPublicKey("test@example.com", validPublicKey);
        assertEquals(validPublicKey, service.getPeerPublicKey("test@example.com"));
        assertNull(service.getPeerPublicKey("not-a-user@example.com"));
    }

    @Test
    void testListPeersReturnsDefensiveCopy() {
        service.listPeers().put("injected@example.com", "x");
        assertFalse(service.listPeers().containsKey("injected@example.com"));
    }

    // Permanent (manual) peers

    @Test
    void testManualPeerAddListRemove() {
        String key = "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=";
        service.addManualPeer(key, "10.9.9.9/32");
        assertTrue(service.listManualPeers().stream().anyMatch(p -> p.publicKey().equals(key)));

        assertTrue(service.removeManualPeer(key));
        assertFalse(service.listManualPeers().stream().anyMatch(p -> p.publicKey().equals(key)));
        assertFalse(service.removeManualPeer(key)); // already gone
    }

    @Test
    void testAddManualPeerRejectsInvalidKey() {
        assertThrows(IllegalArgumentException.class, () -> service.addManualPeer("tooshort", "10.0.0.9/32"));
    }

    @Test
    void testAddManualPeerRejectsAllowedIpsInjection() {
        String key = "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=";
        assertThrows(IllegalArgumentException.class, () -> service.addManualPeer(key, "10.0.0.9/32\n[Peer]"));
    }

    @Test
    void testProcessPublicKey_EmptyPublicKey() {
        WireguardService.WireguardResult result = service.processPublicKey("test@example.com", "");

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("required"));
    }

    @Test
    void testProcessPublicKey_NullPublicKey() {
        WireguardService.WireguardResult result = service.processPublicKey("test@example.com", null);

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("required"));
    }

    @Test
    void testProcessPublicKey_InvalidPublicKeyFormat_TooShort() {
        WireguardService.WireguardResult result = service.processPublicKey("test@example.com", "shortkey");

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("44 characters"));
    }

    @Test
    void testProcessPublicKey_InvalidPublicKeyFormat_TooLong() {
        // 45 characters - too long
        WireguardService.WireguardResult result =
                service.processPublicKey("test@example.com", "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14==");

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("44 characters"));
    }

    @Test
    void testProcessPublicKey_InvalidPublicKeyFormat_InvalidChars() {
        // 44 characters, ends with =, but has invalid base64 characters (!)
        WireguardService.WireguardResult result =
                service.processPublicKey("test@example.com", "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8!!!!=");

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("not valid base64"));
    }

    @Test
    void testProcessPublicKey_InvalidPublicKeyFormat_NotEndingWithEquals() {
        // 44 characters but doesn't end with =
        WireguardService.WireguardResult result =
                service.processPublicKey("test@example.com", "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14A");

        assertFalse(result.valid());
        assertTrue(result.errorMessage().contains("end with '='"));
    }

    @Test
    void testValidateWireguardPublicKey_Valid() {
        assertNull(service.validateWireguardPublicKey("xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14="));
    }

    @Test
    void testValidateWireguardPublicKey_Null() {
        String error = service.validateWireguardPublicKey(null);
        assertNotNull(error);
        assertTrue(error.contains("required"));
    }

    @Test
    void testValidateWireguardPublicKey_Empty() {
        String error = service.validateWireguardPublicKey("");
        assertNotNull(error);
        assertTrue(error.contains("required"));
    }

    @Test
    void testValidateWireguardPublicKey_WrongLength() {
        String error = service.validateWireguardPublicKey("tooshort=");
        assertNotNull(error);
        assertTrue(error.contains("44 characters"));
    }

    @Test
    void testValidateWireguardPublicKey_NotEndingWithEquals() {
        String error = service.validateWireguardPublicKey("xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14A");
        assertNotNull(error);
        assertTrue(error.contains("end with '='"));
    }

    @Test
    void testValidateWireguardPublicKey_InvalidBase64() {
        String error = service.validateWireguardPublicKey("xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8H!!!=");
        assertNotNull(error);
        assertTrue(error.contains("not valid base64"));
    }

    @Test
    void testProcessPublicKey_WhitespaceIsTrimmed() {
        String validPublicKey = "  xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=  ";
        WireguardService.WireguardResult result = service.processPublicKey("test@example.com", validPublicKey);

        assertTrue(result.valid());
        assertEquals("xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=", result.wireguardPublicKey());
    }

    @Test
    void testProcessPublicKey_MultipleUsersGetDifferentAddresses() {
        String validPublicKey = "xTIBA5rboUvnH4htodjb60Y7YAf21J7YQMlNGC8HQ14=";

        WireguardService.WireguardResult testResult = service.processPublicKey("test@example.com", validPublicKey);
        assertTrue(testResult.valid());
        assertTrue(testResult.wireguardConfig().contains("Address = 10.0.0.5/32"));

        WireguardService.WireguardResult adminResult = service.processPublicKey("admin@example.com", validPublicKey);
        assertTrue(adminResult.valid());
        assertTrue(adminResult.wireguardConfig().contains("Address = 10.0.0.10/32"));
    }

    /**
     * Test config that supplies values directly instead of loading from files, so the service can
     * be exercised without a CA cert or users file on disk.
     */
    static class TestWgKeymanConfig extends WgKeymanConfig {
        private final Map<String, Integer> users;

        TestWgKeymanConfig(Map<String, Integer> users) {
            this.users = new java.util.HashMap<>(users);
        }

        @Override
        public Map<String, Integer> getUserHostNumbers() {
            return users;
        }

        @Override
        public String getServerAddress() {
            return "10.0.0.1";
        }

        @Override
        public String getNetwork() {
            return "10.0.0.0/24";
        }

        @Override
        public String getServerEndpoint() {
            return "vpn.example.com:51820";
        }

        @Override
        public String getServerPublicKey() {
            return "TestServerPublicKey123456789012345678901234=";
        }

        @Override
        public String getClientAddress(int hostNumber) {
            return "10.0.0." + hostNumber + "/32";
        }

        @Override
        public String getAllowedIps() {
            return "10.0.0.0/24";
        }

        @Override
        public String getPeersFile() {
            return System.getProperty("java.io.tmpdir") + "/wg-keyman-test-peers.conf";
        }

        @Override
        public String getWgInterface() {
            return "wg-test";
        }

        @Override
        public String getSyncCommand() {
            // Use echo for testing to avoid actually running wg commands
            return "echo test-sync";
        }
    }
}
