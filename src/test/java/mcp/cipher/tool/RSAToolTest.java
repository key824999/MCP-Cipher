package mcp.cipher.tool;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class RSAToolTest {

    RSATool rsaTool = new RSATool();

    @Test
    void testGenerateRSAKeyPair() throws Exception {
        Map<String, String> keys = rsaTool.generateRSAKeyPair();
        assertNotNull(keys.get("publicKey"));
        assertNotNull(keys.get("privateKey"));
    }

    @Test
    void testEncryptRSA() throws Exception {
        Map<String, String> keys = rsaTool.generateRSAKeyPair();
        String message = "Hello RSA!";
        String encrypted = rsaTool.encryptRSA(message, keys.get("publicKey"));
        String decrypted = rsaTool.decryptRSA(encrypted, keys.get("privateKey"));
        assertEquals(message, decrypted);

        // Edge: empty message
        encrypted = rsaTool.encryptRSA("", keys.get("publicKey"));
        decrypted = rsaTool.decryptRSA(encrypted, keys.get("privateKey"));
        assertEquals("", decrypted);

        // Long message
        String longMessage = "A".repeat(512);
        String longEncrypted = rsaTool.encryptLongRSA(longMessage, keys.get("publicKey"));
        String longDecrypted = rsaTool.decryptLongRSA(longEncrypted, keys.get("privateKey"));
        assertEquals(longMessage, longDecrypted);

        // Error: wrong key decryption
        Map<String, String> wrongKeys = rsaTool.generateRSAKeyPair();
        String finalEncrypted = encrypted;
        assertThrows(Exception.class, () -> rsaTool.decryptRSA(finalEncrypted, wrongKeys.get("privateKey")));
    }

    @Test
    void testSignAndVerify() throws Exception {
        Map<String, String> keys = rsaTool.generateRSAKeyPair();
        String data = "important-data";
        String signature = rsaTool.signData(data, keys.get("privateKey"));
        assertTrue(rsaTool.verifySignature(data, signature, keys.get("publicKey")));

        // Mismatch
        assertFalse(rsaTool.verifySignature("tampered-data", signature, keys.get("publicKey")));

        // Error: verify with wrong public key
        Map<String, String> wrongKeys = rsaTool.generateRSAKeyPair();
        assertFalse(rsaTool.verifySignature(data, signature, wrongKeys.get("publicKey")));
    }

    @Test
    void testPEMConversion() throws Exception {
        Map<String, String> keys = rsaTool.generateRSAKeyPair();
        String publicKeyPEM = rsaTool.formatKeyToPEM(keys.get("publicKey"), true);
        String privateKeyPEM = rsaTool.formatKeyToPEM(keys.get("privateKey"), false);

        String base64Pub = rsaTool.decryptPEMKey(publicKeyPEM, true);
        String base64Priv = rsaTool.decryptPEMKey(privateKeyPEM, false);

        assertEquals(keys.get("publicKey").replaceAll("\\s", ""), base64Pub);
        assertEquals(keys.get("privateKey").replaceAll("\\s", ""), base64Priv);

        // Error: PEM format invalid
        assertThrows(Exception.class, () -> rsaTool.decryptPEMKey("NOT_A_PEM", true));
    }

    @Test
    void testSignJSON() throws Exception {
        Map<String, String> keys = rsaTool.generateRSAKeyPair();
        String json = "{\"user\":\"jungje\"}";
        String signature = rsaTool.signJSON(json, keys.get("privateKey"));
        assertTrue(rsaTool.verifySignature(json, signature, keys.get("publicKey")));

        // Error: tampered JSON
        assertFalse(rsaTool.verifySignature("{\"user\":\"someone\"}", signature, keys.get("publicKey")));
    }

    @Test
    void testValidateRSAKey() throws Exception {
        Map<String, String> keys = rsaTool.generateRSAKeyPair();
        assertTrue(rsaTool.validateRSAKey(keys.get("publicKey")));
        assertFalse(rsaTool.validateRSAKey("shortkey"));
        assertFalse(rsaTool.validateRSAKey(null));
    }

    @Test
    void testDecryptLongRSAWithInvalidBlock() throws Exception {
        Map<String, String> keys = rsaTool.generateRSAKeyPair();
        String invalidBase64 = java.util.Base64.getEncoder().encodeToString("corrupted".getBytes());
        assertThrows(Exception.class, () -> rsaTool.decryptLongRSA(invalidBase64, keys.get("privateKey")));
    }

    @Test
    void testEncryptDecryptWithNullInput() throws Exception {
        Map<String, String> keys = rsaTool.generateRSAKeyPair();

        assertThrows(Exception.class, () -> rsaTool.encryptRSA(null, keys.get("publicKey")));
        assertThrows(Exception.class, () -> rsaTool.decryptRSA(null, keys.get("privateKey")));
    }
}
