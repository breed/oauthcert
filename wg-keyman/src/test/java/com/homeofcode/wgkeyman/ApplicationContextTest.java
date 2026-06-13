package com.homeofcode.wgkeyman;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * Boots the full Spring application context (server mode). This guards against wiring regressions
 * that the controller slice tests miss because they mock the service bean — in particular, that
 * every {@code @Service}/{@code @Component} has a constructor Spring can autowire.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApplicationContextTest {

    @Autowired
    private WireguardService wireguardService;

    @Test
    void contextLoadsAndServiceIsWired() {
        assertNotNull(wireguardService, "WireguardService bean must be created by Spring");
    }
}
