package com.homeofcode.wgkeyman.cli;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Read/edit access to the {@code users.lst} file used by wg-keyman.
 *
 * <p>File format (matching {@code WgKeymanConfig}): each non-blank, non-{@code #} line is a
 * HOST_NUMBER followed by whitespace followed by the user's CN. The host number is decimal for an
 * IPv4 network and hexadecimal for an IPv6 network. Comments and blank lines are preserved across
 * edits, and edits append/remove only the relevant data lines.
 */
public class UsersFile {

    private final Path path;
    private final boolean ipv6;

    public UsersFile(String path, boolean ipv6) {
        this.path = Path.of(path);
        this.ipv6 = ipv6;
    }

    public record Entry(int hostNumber, String cn) {}

    /** Parse the data lines into entries, in file order. Malformed lines are skipped. */
    public List<Entry> list() throws IOException {
        List<Entry> entries = new ArrayList<>();
        if (!Files.exists(path)) {
            return entries;
        }
        for (String line : Files.readAllLines(path)) {
            Entry entry = parse(line);
            if (entry != null) {
                entries.add(entry);
            }
        }
        return entries;
    }

    /**
     * Append a new user. Fails if the CN or the host number is already present.
     *
     * @throws IllegalArgumentException if the CN or host number already exists
     */
    public void add(int hostNumber, String cn) throws IOException {
        String existing = Files.exists(path) ? Files.readString(path) : "";
        if (Files.exists(path)) {
            for (String line : Files.readAllLines(path)) {
                String trimmed = line.trim();
                if (trimmed.isEmpty() || trimmed.startsWith("#")) {
                    continue;
                }
                String[] parts = trimmed.split("\\s+", 2);
                // Host-number collision: check the first token even on otherwise-malformed lines
                // (e.g. a host number with no CN) so they can't be silently duplicated.
                try {
                    if (Integer.parseInt(parts[0], ipv6 ? 16 : 10) == hostNumber) {
                        throw new IllegalArgumentException("host number " + formatHostNumber(hostNumber)
                                + " already in use" + (parts.length == 2 ? " by " + parts[1] : ""));
                    }
                } catch (NumberFormatException ignore) {
                    // first token isn't a host number; not a collision
                }
                if (parts.length == 2 && parts[1].equals(cn)) {
                    throw new IllegalArgumentException("user already exists: " + cn);
                }
            }
        }

        String nl = detectNewline(existing);
        StringBuilder sb = new StringBuilder(existing);
        if (!existing.isEmpty() && !existing.endsWith("\n")) {
            sb.append(nl);
        }
        sb.append(formatHostNumber(hostNumber)).append(" ").append(cn).append(nl);
        Files.writeString(path, sb.toString());
    }

    /**
     * Remove the user with the given CN, preserving all other lines (including comments).
     *
     * @return true if a matching entry was removed
     */
    public boolean remove(String cn) throws IOException {
        if (!Files.exists(path)) {
            return false;
        }
        String nl = detectNewline(Files.readString(path));
        List<String> kept = new ArrayList<>();
        boolean removed = false;
        for (String line : Files.readAllLines(path)) {
            Entry entry = parse(line);
            if (entry != null && entry.cn().equals(cn)) {
                removed = true;
                continue;
            }
            kept.add(line);
        }
        if (removed) {
            Files.writeString(path, kept.isEmpty() ? "" : String.join(nl, kept) + nl);
        }
        return removed;
    }

    /** Preserve the file's existing line-ending style (CRLF vs LF) when rewriting. */
    private static String detectNewline(String content) {
        return content.contains("\r\n") ? "\r\n" : "\n";
    }

    public String formatHostNumber(int hostNumber) {
        return ipv6 ? Integer.toHexString(hostNumber) : Integer.toString(hostNumber);
    }

    /** Parse a host number string using the radix implied by the network family. */
    public int parseHostNumber(String text) {
        return Integer.parseInt(text.trim(), ipv6 ? 16 : 10);
    }

    private Entry parse(String rawLine) {
        String line = rawLine.trim();
        if (line.isEmpty() || line.startsWith("#")) {
            return null;
        }
        String[] parts = line.split("\\s+", 2);
        if (parts.length != 2) {
            return null;
        }
        try {
            int hostNumber = Integer.parseInt(parts[0], ipv6 ? 16 : 10);
            return new Entry(hostNumber, parts[1]);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
