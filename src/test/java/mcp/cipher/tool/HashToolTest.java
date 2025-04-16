package mcp.cipher.tool;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class HashToolTest {

    HashTool hashTool = new HashTool();

    @Test
    void testGenerateSHA256() throws Exception {
        String input = "test";
        String hash = hashTool.generateSHA256(input);
        assertNotNull(hash);
        assertEquals(64, hash.length());

        // Edge: empty string
        String emptyHash = hashTool.generateSHA256("");
        assertNotNull(emptyHash);
        assertEquals(64, emptyHash.length());

        // Error: null input
        assertThrows(Exception.class, () -> hashTool.generateSHA256(null));
    }

    @Test
    void testGenerateSaltedHash() throws Exception {
        String input = "password";
        String salt = "randomsalt";
        String hash = hashTool.generateSaltedHash(input, salt, "SHA-256");
        assertNotNull(hash);
        assertEquals(64, hash.length());

        // Error: null salt
        assertThrows(Exception.class, () -> hashTool.generateSaltedHash(input, null, "SHA-256"));

        // Error: unsupported algorithm
        assertThrows(Exception.class, () -> hashTool.generateSaltedHash(input, salt, "UNKNOWN"));
    }

    @Test
    void testIsHashMatchWithSalt() throws Exception {
        String input = "value";
        String salt = "mysalt";
        String hash = hashTool.generateSaltedHash(input, salt, "SHA-512");

        assertTrue(hashTool.isHashMatchWithSalt(input, salt, hash, "SHA-512"));

        // Mismatch case
        assertFalse(hashTool.isHashMatchWithSalt("wrong", salt, hash, "SHA-512"));
    }

    @Test
    void testHashBase64() throws Exception {
        String input = "data";
        String hash = hashTool.hashBase64(input, "SHA-256");
        assertNotNull(hash);
        assertTrue(hash.length() > 20);
    }

    @Test
    void testGenerateRandomSalt() {
        String salt = hashTool.generateRandomSalt(16);
        assertNotNull(salt);
        assertEquals(16, salt.length());
    }

    @Test
    void testIsHash() {
        assertTrue(hashTool.isHash("a3f1d9cbb4ee5f9914ad0b06b774c23d"));
        assertFalse(hashTool.isHash("not-a-hash"));
        assertFalse(hashTool.isHash(""));
        assertFalse(hashTool.isHash(null));
    }

    @Test
    void testCompareHash() throws Exception {
        String input = "compare-me";
        String hash = hashTool.generateSHA256(input);

        assertTrue(hashTool.compareHash(input, hash, "SHA-256"));
        assertFalse(hashTool.compareHash("different", hash, "SHA-256"));

        assertThrows(Exception.class, () -> hashTool.compareHash(null, hash, "SHA-256"));
        assertThrows(Exception.class, () -> hashTool.compareHash(input, null, "SHA-256"));
        assertThrows(Exception.class, () -> hashTool.compareHash(input, hash, "UNKNOWN"));
    }

    @Test
    void testGenerateSHA512() throws Exception {
        String input = "test";
        String hash = hashTool.generateSHA512(input);
        assertNotNull(hash);
        assertEquals(128, hash.length());

        assertThrows(Exception.class, () -> hashTool.generateSHA512(null));
    }

    @Test
    void testGenerateMD5() throws Exception {
        String input = "md5";
        String hash = hashTool.generateMD5(input);
        assertNotNull(hash);
        assertEquals(32, hash.length());

        assertThrows(Exception.class, () -> hashTool.generateMD5(null));
    }

    @Test
    void testHashBase64EdgeCases() throws Exception {
        String input = "";
        String base64 = hashTool.hashBase64(input, "SHA-256");
        assertNotNull(base64);
        assertTrue(base64.length() > 0);

        assertThrows(Exception.class, () -> hashTool.hashBase64(null, "SHA-256"));
        assertThrows(Exception.class, () -> hashTool.hashBase64(input, "UNKNOWN"));
    }

    @Test
    void testGenerateRandomSaltEdgeCases() {
        String salt = hashTool.generateRandomSalt(0);
        assertEquals(0, salt.length());

        assertThrows(IllegalArgumentException.class, () -> hashTool.generateRandomSalt(-1));
    }

    @Test
    void testIsHashMatchWithSaltEdgeCases() throws Exception {
        String input = "abc";
        String salt = "xyz";
        String hash = hashTool.generateSaltedHash(input, salt, "SHA-256");

        // salt mismatch
        assertFalse(hashTool.isHashMatchWithSalt(input, "zzz", hash, "SHA-256"));

        // null hash or salt
        assertThrows(Exception.class, () -> hashTool.isHashMatchWithSalt(null, salt, hash, "SHA-256"));
        assertThrows(Exception.class, () -> hashTool.isHashMatchWithSalt(input, null, hash, "SHA-256"));
        assertThrows(Exception.class, () -> hashTool.isHashMatchWithSalt(input, salt, null, "SHA-256"));
    }
}
