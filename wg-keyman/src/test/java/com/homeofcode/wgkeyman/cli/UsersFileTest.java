package com.homeofcode.wgkeyman.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class UsersFileTest {

    @TempDir
    Path tempDir;

    private UsersFile ipv4File(String contents) throws IOException {
        Path p = tempDir.resolve("users.lst");
        Files.writeString(p, contents);
        return new UsersFile(p.toString(), false);
    }

    @Test
    void listParsesEntriesAndSkipsCommentsAndBlanks() throws IOException {
        UsersFile uf = ipv4File("# header comment\n\n70 office\n71 ben@example.com\n");
        List<UsersFile.Entry> entries = uf.list();
        assertEquals(2, entries.size());
        assertEquals(70, entries.get(0).hostNumber());
        assertEquals("office", entries.get(0).cn());
        assertEquals("ben@example.com", entries.get(1).cn());
    }

    @Test
    void addAppendsEntry() throws IOException {
        UsersFile uf = ipv4File("70 office\n");
        uf.add(72, "new@example.com");
        List<UsersFile.Entry> entries = uf.list();
        assertEquals(2, entries.size());
        assertEquals(72, entries.get(1).hostNumber());
        assertEquals("new@example.com", entries.get(1).cn());
    }

    @Test
    void addToFileWithoutTrailingNewlineStillSeparatesLines() throws IOException {
        UsersFile uf = ipv4File("70 office"); // no trailing newline
        uf.add(71, "second@example.com");
        assertEquals(2, uf.list().size());
    }

    @Test
    void addRejectsDuplicateCn() throws IOException {
        UsersFile uf = ipv4File("70 office\n");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> uf.add(99, "office"));
        assertTrue(ex.getMessage().contains("already exists"));
    }

    @Test
    void addRejectsDuplicateHostNumber() throws IOException {
        UsersFile uf = ipv4File("70 office\n");
        IllegalArgumentException ex = assertThrows(IllegalArgumentException.class, () -> uf.add(70, "other@example.com"));
        assertTrue(ex.getMessage().contains("already in use"));
    }

    @Test
    void removeDropsMatchingEntryAndPreservesComments() throws IOException {
        UsersFile uf = ipv4File("# keep me\n70 office\n71 ben@example.com\n");
        assertTrue(uf.remove("office"));
        String remaining = Files.readString(tempDir.resolve("users.lst"));
        assertTrue(remaining.contains("# keep me"));
        assertFalse(remaining.contains("office"));
        assertTrue(remaining.contains("ben@example.com"));
    }

    @Test
    void removeReturnsFalseWhenAbsent() throws IOException {
        UsersFile uf = ipv4File("70 office\n");
        assertFalse(uf.remove("nobody@example.com"));
    }

    @Test
    void ipv6UsesHexHostNumbers() throws IOException {
        Path p = tempDir.resolve("users6.lst");
        Files.writeString(p, "ff alice@example.com\n");
        UsersFile uf = new UsersFile(p.toString(), true);
        assertEquals(255, uf.list().get(0).hostNumber());
        assertEquals("64", uf.formatHostNumber(100));
        assertEquals(256, uf.parseHostNumber("100"));
    }

    @Test
    void ipv4UsesDecimalHostNumbers() throws IOException {
        UsersFile uf = ipv4File("");
        assertEquals("100", uf.formatHostNumber(100));
        assertEquals(100, uf.parseHostNumber("100"));
    }
}
