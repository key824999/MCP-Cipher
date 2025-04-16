package mcp.cipher.tool;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.stereotype.Component;

import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

@Component
public class HashTool {

    /**
     * Generates an SHA-256 hash of the input string (hex encoded).
     */
    @Tool(description = "Generates a SHA-256 hash of the input string (hex encoded).")
    public String generateSHA256(String input) throws Exception {
        return this.hash(input, "SHA-256");
    }

    /**
     * Generates an SHA-512 hash of the input string (hex encoded).
     */
    @Tool(description = "Generates a SHA-512 hash of the input string (hex encoded).")
    public String generateSHA512(String input) throws Exception {
        return this.hash(input, "SHA-512");
    }

    /**
     * Generates an MD5 hash of the input string (hex encoded).
     * Note: MD5 is not secure for cryptographic purposes.
     */
    @Tool(description = "Generates an MD5 hash of the input string (hex encoded, insecure).")
    public String generateMD5(String input) throws Exception {
        return this.hash(input, "MD5");
    }

    /**
     * Compares a string against an expected hash using the specified algorithm.
     * Returns true if they match, false otherwise.
     */
    @Tool(description = "Compares input string with expected hash using a given algorithm (SHA-256, SHA-512, or MD5).")
    public boolean compareHash(String input, String expectedHash, String algorithm) throws Exception {
        if (input == null || expectedHash == null || algorithm == null) {
            throw new IllegalArgumentException("Input, expectedHash, and algorithm must not be null.");
        }

        String actualHash = this.hash(input, algorithm);

        return actualHash.equalsIgnoreCase(expectedHash);
    }

    /**
     * Generates a hash of the input and encodes the result as Base64.
     */
    @Tool(description = "Generates a hash of the input and encodes the result as Base64.")
    public String hashBase64(String input, String algorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hash = digest.digest(input.getBytes());

        return Base64.getEncoder().encodeToString(hash);
    }

    /**
     * Generates a hash of the input combined with a salt using the specified algorithm.
     */
    @Tool(description = "Generates a hash of the input combined with a salt using the specified algorithm.")
    public String generateSaltedHash(String input, String salt, String algorithm) throws Exception {
        if (input == null || salt == null || algorithm == null) {
            throw new IllegalArgumentException("Input, salt, and algorithm must not be null.");
        }

        return this.hash(input + salt, algorithm);
    }

    /**
     * Generates a random alphanumeric salt string of the specified length.
     */
    @Tool(description = "Generates a random alphanumeric salt of the specified length.")
    public String generateRandomSalt(int length) {
        if (length < 0) {
            throw new IllegalArgumentException("Salt length must be non-negative.");
        }

        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

        StringBuilder sb = new StringBuilder();
        SecureRandom random = new SecureRandom();

        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }

        return sb.toString();
    }

    /**
     * Compares salted hash with input and salt.
     */
    @Tool(description = "Checks whether the salted hash of input matches the expected hash using the specified algorithm.")
    public boolean isHashMatchWithSalt(String input, String salt, String expectedHash, String algorithm) throws Exception {
        if (input == null || salt == null || expectedHash == null || algorithm == null) {
            throw new IllegalArgumentException("None of the parameters may be null.");
        }

        String actualHash = this.hash(input + salt, algorithm);

        return actualHash.equalsIgnoreCase(expectedHash);
    }

    /**
     * Checks if a given string looks like a valid hexadecimal hash.
     */
    @Tool(description = "Checks if the input string is a valid hexadecimal hash (e.g., SHA or MD5).")
    public boolean isHash(String input) {
        return input != null && input.matches("^[a-fA-F\\d]{32,128}$");
    }

    /**
     * Internal method to hash a string with the given algorithm and return it as a hex string.
     */
    private String hash(String input, String algorithm) throws Exception {
        MessageDigest digest = MessageDigest.getInstance(algorithm);
        byte[] hash = digest.digest(input.getBytes());

        StringBuilder hex = new StringBuilder();

        for (byte b : hash) {
            hex.append(String.format("%02x", b));
        }

        return hex.toString();
    }
}
