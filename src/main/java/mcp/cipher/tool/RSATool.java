package mcp.cipher.tool;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@Component
public class RSATool {

    /**
     * Generates an RSA public/private key pair.
     * The result is returned as a map with keys: "publicKey" and "privateKey", both Base64-encoded.
     */
    @Tool(description = "Generates an RSA public/private key pair and returns them as Base64 strings.")
    public Map<String, String> generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Use 2048-bit RSA keys

        KeyPair keyPair = keyGen.generateKeyPair();

        return new HashMap<>() {{
            put("publicKey", Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
            put("privateKey", Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        }};
    }

    /**
     * Encrypts plaintext using a Base64-encoded RSA public key.
     * Returns the result as a Base64-encoded ciphertext string.
     */
    @Tool(description = "Encrypts a string using a Base64-encoded RSA public key.")
    public String encryptRSA(String plainText, String base64PublicKey) throws Exception {
        PublicKey publicKey = this.loadPublicKey(base64PublicKey);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] encrypted = cipher.doFinal(plainText.getBytes());

        return Base64.getEncoder().encodeToString(encrypted);
    }

    /**
     * Decrypts Base64-encoded RSA ciphertext using a Base64-encoded RSA private key.
     * Returns the original plaintext.
     */
    @Tool(description = "Decrypts RSA-encrypted Base64 text using a Base64-encoded private key.")
    public String decryptRSA(String cipherText, String base64PrivateKey) throws Exception {
        PrivateKey privateKey = this.loadPrivateKey(base64PrivateKey);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(cipherText));

        return new String(decrypted);
    }

    /**
     * Validates whether the provided Base64-encoded RSA key is likely to be valid.
     */
    @Tool(description = "Checks if the given Base64-encoded RSA key string is structurally valid.")
    public boolean validateRSAKey(String base64Key) {
        if (base64Key == null) {
            return false;
        }

        try {
            byte[] decoded = Base64.getDecoder().decode(base64Key);

            return decoded.length > 100; // basic length check for 2048-bit keys
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Encrypts long plaintexts by splitting into blocks that RSA can process.
     */
    @Tool(description = "Encrypts long plaintext using RSA public key with automatic block splitting.")
    public String encryptLongRSA(String plainText, String base64PublicKey) throws Exception {
        PublicKey publicKey = loadPublicKey(base64PublicKey);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);

        byte[] bytes = plainText.getBytes();
        int blockSize = 245; // RSA max input size for 2048-bit key with PKCS1 padding

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        for (int i = 0; i < bytes.length; i += blockSize) {
            int length = Math.min(blockSize, bytes.length - i);
            byte[] block = cipher.doFinal(bytes, i, length);

            outputStream.write(block);
        }

        return Base64.getEncoder().encodeToString(outputStream.toByteArray());
    }

    /**
     * Decrypts a long Base64-encoded ciphertext that was split and encrypted in blocks.
     */
    @Tool(description = "Decrypts long RSA-encrypted text (Base64) using private key and automatic block merging.")
    public String decryptLongRSA(String cipherText, String base64PrivateKey) throws Exception {
        PrivateKey privateKey = loadPrivateKey(base64PrivateKey);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        byte[] encryptedBytes = Base64.getDecoder().decode(cipherText);
        int blockSize = 256; // RSA output block size for 2048-bit key

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        for (int i = 0; i < encryptedBytes.length; i += blockSize) {
            int length = Math.min(blockSize, encryptedBytes.length - i);
            byte[] block = cipher.doFinal(encryptedBytes, i, length);

            outputStream.write(block);
        }

        return outputStream.toString();
    }

    /**
     * Signs data using SHA256withRSA and returns the Base64-encoded signature.
     */
    @Tool(description = "Signs data using a private RSA key and returns the Base64 signature.")
    public String signData(String data, String base64PrivateKey) throws Exception {
        PrivateKey privateKey = loadPrivateKey(base64PrivateKey);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey);
        signature.update(data.getBytes());

        return Base64.getEncoder().encodeToString(signature.sign());
    }

    /**
     * Verifies a signature against the original data using the corresponding public key.
     */
    @Tool(description = "Verifies the RSA signature using the original data and a public key.")
    public boolean verifySignature(String data, String base64Signature, String base64PublicKey) throws Exception {
        PublicKey publicKey = loadPublicKey(base64PublicKey);

        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(publicKey);
        signature.update(data.getBytes());

        return signature.verify(Base64.getDecoder().decode(base64Signature));
    }

    /**
     * Formats a Base64-encoded RSA key into PEM format (for display or export).
     */
    @Tool(description = "Formats a Base64-encoded RSA key string into PEM format.")
    public String formatKeyToPEM(String base64Key, boolean isPublic) {
        StringBuilder sb = new StringBuilder();

        String header = isPublic ? "-----BEGIN PUBLIC KEY-----" : "-----BEGIN PRIVATE KEY-----";
        String footer = isPublic ? "-----END PUBLIC KEY-----" : "-----END PRIVATE KEY-----";

        sb.append(header).append("\n");

        for (int i = 0; i < base64Key.length(); i += 64) {
            int end = Math.min(base64Key.length(), i + 64);

            sb.append(base64Key, i, end).append("\n");
        }

        sb.append(footer);

        return sb.toString();
    }

    /**
     * Parses a PEM-formatted RSA key and returns it as a Base64-encoded string.
     * This can be used to load PEM keys into existing encryption/decryption methods.
     */
    @Tool(description = "Converts a PEM-formatted RSA key into a Base64-encoded string.")
    public String decryptPEMKey(String pem, boolean isPublic) {
        if (pem == null) {
            throw new IllegalArgumentException("PEM input cannot be null");
        }

        if (isPublic) {
            if (!pem.contains("-----BEGIN PUBLIC KEY-----") || !pem.contains("-----END PUBLIC KEY-----")) {
                throw new IllegalArgumentException("Expected a PEM-formatted PUBLIC KEY");
            }
        } else {
            if (!pem.contains("-----BEGIN PRIVATE KEY-----") || !pem.contains("-----END PRIVATE KEY-----")) {
                throw new IllegalArgumentException("Expected a PEM-formatted PRIVATE KEY");
            }
        }

        return pem.replaceAll("-----BEGIN .* KEY-----", "")
                .replaceAll("-----END .* KEY-----", "")
                .replaceAll("\\s", "");
    }

    /**
     * Signs a JSON string using a private RSA key.
     * Returns the Base64-encoded signature.
     */
    @Tool(description = "Signs a JSON string using RSA and returns the Base64 signature.")
    public String signJSON(String json, String base64PrivateKey) throws Exception {
        return this.signData(json, base64PrivateKey);
    }

    /**
     * Converts a Base64-encoded public key string into a PublicKey object.
     */
    private PublicKey loadPublicKey(String base64Key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(base64Key);

        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        return factory.generatePublic(keySpec);
    }

    /**
     * Converts a Base64-encoded private key string into a PrivateKey object.
     */
    private PrivateKey loadPrivateKey(String base64Key) throws Exception {
        byte[] decoded = Base64.getDecoder().decode(base64Key);

        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);

        KeyFactory factory = KeyFactory.getInstance("RSA");

        return factory.generatePrivate(keySpec);
    }
}
