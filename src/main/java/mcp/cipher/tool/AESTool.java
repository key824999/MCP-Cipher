
package mcp.cipher.tool;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class AESTool {

    @Tool(description = "Encrypts plaintext using AES in ECB mode (Base64 encoded).")
    public String encryptAES(String plainText, String secretKey) throws Exception {
        if (!this.validateAESKey(secretKey)) {
            throw new IllegalArgumentException("Invalid AES key. Must be 8~32 characters.");
        }

        SecretKeySpec key = this.createKey(secretKey);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
    }

    @Tool(description = "Decrypts AES-encrypted Base64 text using ECB mode.")
    public String decryptAES(String encryptedText, String secretKey) throws Exception {
        if (!this.validateAESKey(secretKey)) {
            throw new IllegalArgumentException("Invalid AES key. Must be 8~32 characters.");
        }

        SecretKeySpec key = this.createKey(secretKey);

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return new String(cipher.doFinal(Base64.getDecoder().decode(encryptedText)));
    }

    @Tool(description = "Encrypts plaintext using AES in CBC mode with random IV. Returns IV:cipherText in Base64.")
    public String encryptAESWithIV(String plainText, String secretKey) throws Exception {
        if (!this.validateAESKey(secretKey)) {
            throw new IllegalArgumentException("Invalid AES key. Must be 8~32 characters.");
        }

        SecretKeySpec key = this.createKey(secretKey);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivSpec = new IvParameterSpec(iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
        byte[] encrypted = cipher.doFinal(plainText.getBytes());

        return Base64.getEncoder().encodeToString(iv) + ":" + Base64.getEncoder().encodeToString(encrypted);
    }

    @Tool(description = "Decrypts AES CBC-encrypted Base64 text formatted as IV:cipherText.")
    public String decryptAESWithIV(String encryptedWithIV, String secretKey) throws Exception {
        if (!this.validateAESKey(secretKey)) {
            throw new IllegalArgumentException("Invalid AES key. Must be 8~32 characters.");
        }

        String[] parts = encryptedWithIV.split(":");

        if (parts.length != 2) {
            throw new IllegalArgumentException("Invalid format. Expected IV:cipherText");
        }

        byte[] iv = Base64.getDecoder().decode(parts[0]);
        byte[] cipherText = Base64.getDecoder().decode(parts[1]);

        SecretKeySpec key = this.createKey(secretKey);
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

        return new String(cipher.doFinal(cipherText));
    }

    @Tool(description = "Generates a random AES key of the given bit size (128, 192, or 256).")
    public String generateAESKey(int bitSize) throws Exception {
        if (bitSize != 128 && bitSize != 192 && bitSize != 256) {
            throw new IllegalArgumentException("Invalid key size. Choose 128, 192, or 256.");
        }

        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(bitSize);

        SecretKey key = keyGen.generateKey();

        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    @Tool(description = "Encodes byte array to hex string.")
    public String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();

        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }

        return sb.toString();
    }

    @Tool(description = "Decodes hex string to Base64 string.")
    public byte[] fromHex(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length.");
        }

        int len = hex.length();
        byte[] output = new byte[len / 2];

        for (int i = 0; i < len; i += 2) {
            int high = Character.digit(hex.charAt(i), 16);
            int low = Character.digit(hex.charAt(i + 1), 16);

            if (high == -1 || low == -1) {
                throw new IllegalArgumentException("Invalid hex character at position " + i);
            }

            output[i / 2] = (byte) ((high << 4) + low);
        }

        return output;
    }

    @Tool(description = "Validates the AES key. Must be non-empty and at least 8 characters.")
    public boolean validateAESKey(String key) {
        return key != null && key.length() >= 8 && key.length() <= 32;
    }

    @Tool(description = "Encrypts a JSON string using AES CBC with IV. Returns Base64 IV:cipherText.")
    public String encryptJSON(String json, String secretKey) throws Exception {
        if (!this.validateAESKey(secretKey)) {
            throw new IllegalArgumentException("Invalid AES key. Must be 8~32 characters.");
        }

        return this.encryptAESWithIV(json, secretKey);
    }

    @Tool(description = "Decrypts a previously encrypted JSON string (AES CBC IV:cipherText format).")
    public String decryptJSON(String encryptedJson, String secretKey) throws Exception {
        if (!this.validateAESKey(secretKey)) {
            throw new IllegalArgumentException("Invalid AES key. Must be 8~32 characters.");
        }

        return this.decryptAESWithIV(encryptedJson, secretKey);
    }

    private SecretKeySpec createKey(String secretKey) {
        byte[] keyBytes = new byte[16];
        byte[] input = secretKey.getBytes();

        System.arraycopy(input, 0, keyBytes, 0, Math.min(input.length, keyBytes.length));

        return new SecretKeySpec(keyBytes, "AES");
    }
}
