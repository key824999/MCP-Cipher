package mcp.cipher.tool;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AESToolTest {

    AESTool aesTool = new AESTool();

    @Test
    void testEncryptAES() throws Exception {
        String key = "securekey123456";
        String plaintext = "Hello World!";

        String encrypted = aesTool.encryptAES(plaintext, key);
        String decrypted = aesTool.decryptAES(encrypted, key);
        assertEquals(plaintext, decrypted);

        encrypted = aesTool.encryptAES("", key);
        decrypted = aesTool.decryptAES(encrypted, key);
        assertEquals("", decrypted);

        String maxKey = "12345678901234567890123456789012";
        encrypted = aesTool.encryptAES("test", maxKey);
        decrypted = aesTool.decryptAES(encrypted, maxKey);
        assertEquals("test", decrypted);

        final String encryptedText = aesTool.encryptAES("secret", key);
        assertThrows(Exception.class, () -> aesTool.decryptAES(encryptedText, "wrongkey654321"));

        assertThrows(Exception.class, () -> aesTool.decryptAES("!!notBase64!!", key));

        assertThrows(Exception.class, () -> aesTool.encryptAES("text", "short"));
    }

    @Test
    void testEncryptAESWithIV() throws Exception {
        String key = "securekey123456";
        String json = "{\"name\":\"test\"}";

        String encrypted = aesTool.encryptJSON(json, key);
        String decrypted = aesTool.decryptJSON(encrypted, key);
        assertEquals(json, decrypted);

        encrypted = aesTool.encryptJSON("", key);
        decrypted = aesTool.decryptJSON(encrypted, key);
        assertEquals("", decrypted);
    }

    @Test
    void testGenerateAESKeyAndValidation() throws Exception {
        String key = aesTool.generateAESKey(128);
        byte[] decoded = java.util.Base64.getDecoder().decode(key);
        assertEquals(16, decoded.length);

        assertTrue(aesTool.validateAESKey("12345678"));
        assertFalse(aesTool.validateAESKey("short"));
        assertFalse(aesTool.validateAESKey(null));
    }

    @Test
    void testAESPerformance() throws Exception {
        String key = "securekey123456";
        String data = "sampleData".repeat(1000);
        String encrypted = aesTool.encryptAES(data, key);

        long start = System.currentTimeMillis();
        for (int i = 0; i < 100; i++) {
            aesTool.encryptAES(data, key);
        }
        long encryptionDuration = System.currentTimeMillis() - start;

        start = System.currentTimeMillis();
        for (int i = 0; i < 100; i++) {
            aesTool.decryptAES(encrypted, key);
        }
        long decryptionDuration = System.currentTimeMillis() - start;

        assertTrue(encryptionDuration < 2000, "Encryption took too long: " + encryptionDuration + "ms");
        assertTrue(decryptionDuration < 2000, "Decryption took too long: " + decryptionDuration + "ms");
    }

    @Test
    void testToHex() {
        byte[] input = "test".getBytes();

        String hex = aesTool.toHex(input);
        assertEquals("74657374", hex);

        String emptyHex = aesTool.toHex(new byte[0]);
        assertEquals("", emptyHex);
    }

    @Test
    void testFromHex() {
        byte[] result = aesTool.fromHex("74657374");
        assertArrayEquals("test".getBytes(), result);

        byte[] empty = aesTool.fromHex("");
        assertArrayEquals(new byte[0], empty);

        assertThrows(Exception.class, () -> aesTool.fromHex("abc"));
        assertThrows(Exception.class, () -> aesTool.fromHex("zzzz"));
    }

    @Test
    void testDecryptJSONWithInvalidFormat() {
        String key = "securekey123456";

        assertThrows(Exception.class, () -> aesTool.decryptJSON("invalid_format_without_colon", key));
        assertThrows(Exception.class, () -> aesTool.decryptJSON("part1:part2:part3", key));
    }

    @Test
    void testGenerateAESKeyWithInvalidSize() {
        assertThrows(Exception.class, () -> aesTool.generateAESKey(100));
        assertThrows(Exception.class, () -> aesTool.generateAESKey(0));
    }

    @Test
    void testEncryptJSONWithNull() {
        String key = "securekey123456";
        assertThrows(Exception.class, () -> aesTool.encryptJSON(null, key));
    }

    @Test
    void testFromHexWithNullInput() {
        assertThrows(Exception.class, () -> aesTool.fromHex(null));
    }
}
