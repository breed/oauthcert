package com.homeofcode.wgkeyman.cli;

import com.homeofcode.wgkeyman.CertificateService;
import com.homeofcode.wgkeyman.WgKeymanConfig;

/**
 * Shared, lazily-initialised access to configuration and services for the admin CLI. Building the
 * config is deferred until a command actually needs it (and triggers config validation at that
 * point) so that {@code --help} and argument errors don't require a valid deployment.
 */
public class CliContext {

    private WgKeymanConfig config;

    public WgKeymanConfig config() {
        if (config == null) {
            // Config loading prints informational lines (e.g. "Loaded N users") to stdout. In CLI
            // mode stdout is reserved for command output (e.g. the generated config), so redirect
            // those diagnostics to stderr while the config is built.
            java.io.PrintStream realOut = System.out;
            System.setOut(System.err);
            try {
                config = WgKeymanConfig.fromProperties(ConfigLoader.load());
            } finally {
                System.setOut(realOut);
            }
        }
        return config;
    }

    /** A CertificateService that does NOT reload the live interface on construction. */
    public CertificateService service() {
        return new CertificateService(config(), false);
    }

    public UsersFile usersFile() {
        return new UsersFile(config().getUsersFile(), config().isNetworkIPv6());
    }
}
