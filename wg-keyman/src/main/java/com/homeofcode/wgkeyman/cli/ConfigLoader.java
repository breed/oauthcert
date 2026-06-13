package com.homeofcode.wgkeyman.cli;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Loads the same {@code application.properties} the Spring Boot server uses, but without booting
 * Spring. Resolution order mirrors how the service is deployed (see {@code wg-keyman.service}):
 *
 * <ol>
 *   <li>{@code spring.config.location} system property, if set</li>
 *   <li>{@code SPRING_CONFIG_LOCATION} environment variable, if set (the systemd unit sets this)</li>
 *   <li>{@code application.properties} in the current working directory (the service's WorkingDirectory)</li>
 *   <li>{@code application.properties} bundled on the classpath (the in-jar defaults)</li>
 * </ol>
 *
 * <p>A location may be a file or a directory; for a directory we look for
 * {@code application.properties} inside it. A leading {@code file:} prefix and {@code optional:}
 * marker (Spring's syntax) are tolerated. Comma-separated locations are tried in order.
 */
public final class ConfigLoader {

    private ConfigLoader() {}

    public static Properties load() {
        Properties props = new Properties();

        for (String location : candidateLocations()) {
            Path path = toPropertiesPath(location);
            if (path != null && Files.isRegularFile(path)) {
                try (InputStream in = Files.newInputStream(path)) {
                    props.load(in);
                    System.err.println("Loaded configuration from " + path);
                    return props;
                } catch (IOException e) {
                    System.err.println("Warning: could not read " + path + ": " + e.getMessage());
                }
            }
        }

        // Fall back to the in-jar defaults on the classpath.
        try (InputStream in = ConfigLoader.class.getResourceAsStream("/application.properties")) {
            if (in != null) {
                props.load(in);
                System.err.println("Loaded configuration from classpath:/application.properties");
                return props;
            }
        } catch (IOException e) {
            System.err.println("Warning: could not read classpath application.properties: " + e.getMessage());
        }

        System.err.println("Warning: no application.properties found; using built-in defaults only.");
        return props;
    }

    private static List<String> candidateLocations() {
        List<String> locations = new ArrayList<>();
        addAll(locations, System.getProperty("spring.config.location"));
        addAll(locations, System.getenv("SPRING_CONFIG_LOCATION"));
        locations.add("application.properties");
        return locations;
    }

    private static void addAll(List<String> out, String commaSeparated) {
        if (commaSeparated == null || commaSeparated.isBlank()) {
            return;
        }
        for (String part : commaSeparated.split(",")) {
            String trimmed = part.trim();
            if (!trimmed.isEmpty()) {
                out.add(trimmed);
            }
        }
    }

    private static Path toPropertiesPath(String location) {
        String loc = location;
        if (loc.startsWith("optional:")) {
            loc = loc.substring("optional:".length());
        }
        if (loc.startsWith("file:")) {
            loc = loc.substring("file:".length());
        }
        if (loc.isEmpty()) {
            return null;
        }
        Path path = Path.of(loc);
        // A directory location means "look for application.properties inside it".
        if (Files.isDirectory(path) || loc.endsWith("/")) {
            return path.resolve("application.properties");
        }
        return path;
    }
}
