# MCP-Cipher

**MCP-Cipher** is a Java-based [Model Context Protocol (MCP)](https://modelcontextprotocol.io) compatible tool that provides cryptographic operations such as AES/RSA encryption, hashing, HMAC, and key generation.

It is designed to be used by any AI agent or tool host that supports the MCP specification.

### ⚡ Secure, Extensible, and Lightweight

MCP-Cipher is designed to be:

- **Secure**, using standard Java crypto libraries (AES, RSA, SHA, HMAC)
- **Extensible**, with modular classes (`AESTool`, `RSATool`, `HashTool`)
- **Lightweight**, using no external cryptography dependencies
  
---

## Installation

### ☕ Java Requirements

MCP-Cipher requires **Java 21 or higher** to run properly.

### 🔹 For Claude Desktop Users

1. Open your `claude_desktop_config.json` file and add the following configuration:

    ```json
    {
      "mcpServers": {
        "mcp-cipher": {
          "command": "java",
          "args": [
            "-jar",
            "https://github.com/key824999/MCP-Cipher/releases/download/v0.1.0/mcp-cipher.jar"
          ]
        }
      }
    }
    ```

2. Restart Claude Desktop or refresh your MCP server list.
3. You can now use cryptographic functions such as `encryptAES`, `generateRSAKeyPair`, `generateSHA256`, and more.

> ⚠️ **Note for multiple MCP servers**
>
> If you're adding more than one MCP server in your `claude_desktop_config.json`,  
> make sure each server block is separated by a comma `,`.
>
> Example:
>
> ```json
> {
>   "mcpServers": {
>     "mcp-cipher": {
>       "command": "java",
>       "args": [
>         "-jar",
>         "https://github.com/key824999/MCP-Cipher/releases/download/v0.1.0/mcp-cipher.jar"
>       ]
>     },
>     "another-mcp-server": {
>       "command": "python",
>       "args": [
>         "another-tool.py"
>       ]
>     }
>   }
> }
> ```
> 
### 🔹 For MCP CLI Users

> If you have [MCP CLI](https://www.npmjs.com/package/mcp) installed, you can register the tool using the following command:

To install this tool using the MCP CLI:

```bash
npx mcp add https://raw.githubusercontent.com/key824999/MCP-Cipher/refs/heads/master/manifest.json
```

## Features by Category

### 🔐 AES (AESTool)
- `encryptAES(plainText, key)` – AES encryption (ECB mode, Base64)
- `decryptAES(cipherText, key)` – AES decryption
- `encryptAESWithIV(plainText, key)` – AES CBC mode with random IV (returns IV:cipherText)
- `decryptAESWithIV(cipherWithIV, key)` – AES CBC decryption
- `generateAESKey(bitSize)` – Generate 128/192/256-bit AES key
- `validateAESKey(key)` – Check key validity (length, non-null)
- `encryptJSON(json, key)` – AES CBC encryption for JSON
- `decryptJSON(cipher, key)` – AES CBC decryption for JSON
- `toHex(byte[])` / `fromHex(hex)` – Hex encoding/decoding

### 🔐 RSA (RSATool)
- `generateRSAKeyPair()` – Generates a Base64 public/private key pair
- `encryptRSA(plainText, publicKey)` – Encrypt using public key
- `decryptRSA(cipherText, privateKey)` – Decrypt using private key
- `encryptLongRSA(plainText, publicKey)` – Encrypt long string (chunked)
- `decryptLongRSA(cipherText, privateKey)` – Decrypt long RSA text
- `signData(data, privateKey)` – Sign data using RSA private key
- `verifySignature(data, signature, publicKey)` – Verify RSA signature
- `formatKeyToPEM(base64Key, isPublic)` – Convert Base64 key to PEM format
- `decryptPEMKey(pem, isPublic)` – Extract Base64 from PEM
- `signJSON(json, privateKey)` – Sign full JSON document
- `validateRSAKey(base64Key)` – Check if Base64 RSA key looks valid

### 🔒 Hashing (HashTool)
- `generateSHA256(input)` – SHA-256 hash (hex)
- `generateSHA512(input)` – SHA-512 hash (hex)
- `generateMD5(input)` – MD5 hash (hex)
- `compareHash(input, expectedHash, algorithm)` – Compare string with hash
- `generateSaltedHash(input, salt, algorithm)` – Salted hash
- `generateRandomSalt(length)` – Generate secure random salt
- `isHash(input)` – Check if string looks like a valid hash
- `isHashMatchWithSalt(input, salt, expectedHash, algorithm)` – Salted hash comparison
- `hashBase64(input, algorithm)` – Generate Base64-encoded hash

> ℹ️ All functions are annotated with `@Tool` and can be auto-discovered by any compliant MCP host at runtime.

## Usage Examples

Once installed in an MCP-compatible host:

- `encryptAES("hello", "mys3cretKey")` → `Base64EncryptedText`
- `decryptAESWithIV("IV:Base64Cipher", "mys3cretKey")` → `hello`
- `generateRSAKeyPair()` → `{ publicKey, privateKey }`
- `signData("important", privateKey)` → `Base64Signature`
- `generateSHA256("secure")` → `HexSHA256Hash`

## Technical Details

- Built with Spring Boot and `spring-ai-mcp-server-spring-boot-starter`
- MCP-compatible methods are annotated with `@Tool`
- `manifest.json` is automatically generated using ClassGraph to scan the tool package
- Executable jar is placed under `./libs` for use by MCP hosts

## Build Instructions

```bash
./gradlew clean build
```

This will:
- Build the executable Spring Boot jar
- Generate `manifest.json`
- Copy the jar to `./libs` for publication

## Output

The following files will be generated and should be committed:

- `libs/MCP-Cipher-0.0.1-SNAPSHOT.jar`
- `manifest.json`

## License

This project is licensed under the **MIT License**.  
See the [`LICENSE`](./LICENSE) file for details.

© 2025 JUNG JE KIM  
Original author and maintainer: [JUNG JE KIM](https://github.com/key824999)

## Author

- Email: wjdwo951219@gmail.com
- GitHub: [@key824999](https://github.com/key824999)
