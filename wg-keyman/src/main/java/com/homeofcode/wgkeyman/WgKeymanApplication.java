package com.homeofcode.wgkeyman;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.util.Arrays;

import com.homeofcode.wgkeyman.cli.AdminCli;

/**
 * Entry point for wg-keyman. Supports two modes:
 *
 * <ul>
 *   <li><b>Server mode</b>: with {@code serve} as the first argument, the full Spring Boot web
 *       server is started.</li>
 *   <li><b>CLI mode</b>: any other first argument is treated as an administrative subcommand
 *       (e.g. {@code user}, {@code peer}, {@code generate}) and is dispatched to PicoCLI
 *       <i>without</i> booting Spring. Configuration is read from the same
 *       {@code application.properties} the server uses (see {@link com.homeofcode.wgkeyman.cli.ConfigLoader}).</li>
 *   <li>With <b>no arguments</b>, the CLI help/usage message is printed.</li>
 * </ul>
 *
 * <p>Note: the server must be requested explicitly with {@code serve}; the systemd unit
 * ({@code wg-keyman.service}) is configured to do this.
 */
@SpringBootApplication
public class WgKeymanApplication {

    public static void main(String[] args) {
        if (isServerMode(args)) {
            // Drop the leading "serve" so it isn't passed on as a Spring argument.
            String[] serverArgs = Arrays.copyOfRange(args, 1, args.length);
            SpringApplication.run(WgKeymanApplication.class, serverArgs);
        } else {
            // No arguments prints the CLI usage; any non-"serve" argument runs an admin command.
            int exitCode = AdminCli.run(args);
            System.exit(exitCode);
        }
    }

    private static boolean isServerMode(String[] args) {
        return args.length > 0 && "serve".equals(args[0]);
    }
}
