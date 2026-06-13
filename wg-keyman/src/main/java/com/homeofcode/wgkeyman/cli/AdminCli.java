package com.homeofcode.wgkeyman.cli;

import com.homeofcode.wgkeyman.WireguardService;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

/**
 * Administrative command-line interface for wg-keyman. Runs without Spring; configuration comes
 * from {@link ConfigLoader}. Assembled and dispatched via {@link #run(String[])}.
 *
 * <pre>
 *   wg-keyman user list
 *   wg-keyman user add &lt;host-number&gt; &lt;cn&gt;
 *   wg-keyman user remove &lt;cn&gt;
 *   wg-keyman peer list
 *   wg-keyman peer remove &lt;cn&gt;
 *   wg-keyman peer sync
 *   wg-keyman generate --cn &lt;cn&gt; --public-key &lt;key&gt;
 * </pre>
 */
@Command(name = "wg-keyman",
        mixinStandardHelpOptions = true,
        description = "Administrative CLI for wg-keyman. Use the 'serve' argument to start the web server instead.")
public class AdminCli implements Runnable {

    @CommandLine.Spec
    CommandLine.Model.CommandSpec spec;

    @Override
    public void run() {
        // No subcommand given: show usage for the fully-assembled command tree.
        spec.commandLine().usage(System.out);
    }

    /** Build the command tree and execute it. Returns a process exit code. */
    public static int run(String[] args) {
        CliContext ctx = new CliContext();

        CommandLine user = new CommandLine(new GroupCommand())
                .addSubcommand("list", new UserListCommand(ctx))
                .addSubcommand("add", new UserAddCommand(ctx))
                .addSubcommand("remove", new UserRemoveCommand(ctx));
        user.getCommandSpec().usageMessage().description("Manage entries in users.lst.");

        CommandLine peer = new CommandLine(new GroupCommand())
                .addSubcommand("list", new PeerListCommand(ctx))
                .addSubcommand("remove", new PeerRemoveCommand(ctx))
                .addSubcommand("sync", new PeerSyncCommand(ctx));
        peer.getCommandSpec().usageMessage().description("Manage WireGuard peers in the peers file.");

        CommandLine root = new CommandLine(new AdminCli())
                .addSubcommand("user", user)
                .addSubcommand("peer", peer)
                .addSubcommand("generate", new GenerateCommand(ctx));

        return root.execute(args);
    }

    /** A no-op parent that prints help when invoked without a subcommand. */
    @Command(mixinStandardHelpOptions = true)
    static class GroupCommand implements Runnable {
        @CommandLine.Spec
        CommandLine.Model.CommandSpec spec;

        @Override
        public void run() {
            spec.commandLine().usage(System.out);
        }
    }

    // ----------------------------------------------------------------------------------- user ---

    @Command(name = "list", description = "List configured users (host number and CN).")
    static class UserListCommand implements Callable<Integer> {
        private final CliContext ctx;

        UserListCommand(CliContext ctx) {
            this.ctx = ctx;
        }

        @Override
        public Integer call() throws Exception {
            List<UsersFile.Entry> entries = ctx.usersFile().list();
            if (entries.isEmpty()) {
                System.out.println("(no users configured)");
                return 0;
            }
            UsersFile uf = ctx.usersFile();
            for (UsersFile.Entry e : entries) {
                System.out.printf("%-8s %s%n", uf.formatHostNumber(e.hostNumber()), e.cn());
            }
            return 0;
        }
    }

    @Command(name = "add", description = "Add a user (host number + CN) to users.lst.")
    static class UserAddCommand implements Callable<Integer> {
        private final CliContext ctx;

        @Parameters(index = "0", paramLabel = "HOST_NUMBER",
                description = "Host number (decimal for IPv4 networks, hexadecimal for IPv6).")
        String hostNumber;

        @Parameters(index = "1", paramLabel = "CN", description = "Common name / email of the user.")
        String cn;

        UserAddCommand(CliContext ctx) {
            this.ctx = ctx;
        }

        @Override
        public Integer call() throws Exception {
            UsersFile uf = ctx.usersFile();
            int host;
            try {
                host = uf.parseHostNumber(hostNumber);
            } catch (NumberFormatException e) {
                String radix = ctx.config().isNetworkIPv6() ? "hexadecimal" : "decimal";
                System.err.println("Invalid host number (expected " + radix + "): " + hostNumber);
                return 2;
            }
            try {
                uf.add(host, cn);
            } catch (IllegalArgumentException e) {
                System.err.println(e.getMessage());
                return 1;
            }
            System.out.println("Added user " + cn + " (host " + uf.formatHostNumber(host) + ").");
            return 0;
        }
    }

    @Command(name = "remove", description = "Remove a user (by CN) from users.lst.")
    static class UserRemoveCommand implements Callable<Integer> {
        private final CliContext ctx;

        @Parameters(index = "0", paramLabel = "CN", description = "Common name / email of the user to remove.")
        String cn;

        UserRemoveCommand(CliContext ctx) {
            this.ctx = ctx;
        }

        @Override
        public Integer call() throws Exception {
            boolean removed = ctx.usersFile().remove(cn);
            if (!removed) {
                System.err.println("No such user: " + cn);
                return 1;
            }
            System.out.println("Removed user " + cn + ".");
            System.out.println("Note: any existing WireGuard peer for this user remains until you run 'peer remove "
                    + cn + "'.");
            return 0;
        }
    }

    // ----------------------------------------------------------------------------------- peer ---

    @Command(name = "list", description = "List wg-keyman managed peers (CN and public key).")
    static class PeerListCommand implements Callable<Integer> {
        private final CliContext ctx;

        PeerListCommand(CliContext ctx) {
            this.ctx = ctx;
        }

        @Override
        public Integer call() {
            Map<String, String> peers = ctx.service().listPeers();
            if (peers.isEmpty()) {
                System.out.println("(no managed peers)");
                return 0;
            }
            for (Map.Entry<String, String> e : peers.entrySet()) {
                System.out.printf("%-40s %s%n", e.getKey(), e.getValue());
            }
            return 0;
        }
    }

    @Command(name = "remove", description = "Remove a managed peer (by CN) and sync WireGuard.")
    static class PeerRemoveCommand implements Callable<Integer> {
        private final CliContext ctx;

        @Parameters(index = "0", paramLabel = "CN", description = "Common name / email of the peer to remove.")
        String cn;

        PeerRemoveCommand(CliContext ctx) {
            this.ctx = ctx;
        }

        @Override
        public Integer call() {
            WireguardService service = ctx.service();
            if (!service.removePeer(cn)) {
                System.err.println("No such managed peer: " + cn);
                return 1;
            }
            String warning = service.save();
            System.out.println("Removed peer " + cn + ".");
            if (warning != null) {
                System.err.println("Warning: " + warning);
                return 1;
            }
            return 0;
        }
    }

    @Command(name = "sync",
            description = "Rebuild the peers file from the current state (backing up the old one) and reload WireGuard.")
    static class PeerSyncCommand implements Callable<Integer> {
        private final CliContext ctx;

        PeerSyncCommand(CliContext ctx) {
            this.ctx = ctx;
        }

        @Override
        public Integer call() {
            String warning = ctx.service().save();
            if (warning != null) {
                System.err.println("Warning: " + warning);
                return 1;
            }
            System.out.println("Rebuilt peers file and synced WireGuard.");
            return 0;
        }
    }

    // ------------------------------------------------------------------------------- generate ---

    @Command(name = "generate",
            description = "Generate a WireGuard client config (printed to stdout) without the web UI. "
                    + "Provide --cn and --public-key.")
    static class GenerateCommand implements Callable<Integer> {
        private final CliContext ctx;

        @Option(names = "--cn", required = true, description = "Common name / email of the user.")
        String cn;

        @Option(names = "--public-key", required = true, description = "WireGuard public key for the user.")
        String publicKey;

        @Option(names = {"-o", "--output"}, description = "Write the config to this file instead of stdout.")
        Path output;

        GenerateCommand(CliContext ctx) {
            this.ctx = ctx;
        }

        @Override
        public Integer call() throws Exception {
            WireguardService service = ctx.service();
            String resolvedCn = cn;
            String resolvedKey = publicKey.trim();

            String keyError = service.validateWireguardPublicKey(resolvedKey);
            if (keyError != null) {
                System.err.println(keyError);
                return 1;
            }
            if (!service.isAuthorizedUser(resolvedCn)) {
                System.err.println("User '" + resolvedCn + "' is not in users.lst.");
                return 1;
            }

            String config = service.generateWireguardConfig(resolvedCn, resolvedKey);
            if (output != null) {
                Files.writeString(output, config);
                System.out.println("Wrote config for " + resolvedCn + " to " + output);
            } else {
                System.out.print(config);
            }
            return 0;
        }
    }
}
