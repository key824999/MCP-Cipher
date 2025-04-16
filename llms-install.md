# MCP-Cipher: Installation Guide for LLMs

This server provides a lightweight, secure, and MCP-compatible cryptography toolset, including AES, RSA, HMAC, and hash utilities.

---

## ☕ Java Requirements

MCP-Cipher requires **Java 21 or higher** to run properly.

---

## 🔹 For Claude Desktop Users

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

---

## 🔹 For MCP CLI Users

If you have [MCP CLI](https://www.npmjs.com/package/mcp) installed, you can register the tool using:

```bash
npx mcp add https://raw.githubusercontent.com/key824999/MCP-Cipher/refs/heads/master/manifest.json
```

---

## 🔹 Running the Server Locally

To run this server on your own machine:

```bash
git clone https://github.com/key824999/MCP-Cipher.git
cd MCP-Cipher
./gradlew bootRun
```

---

## 📌 Notes

- All tools are exposed via `@Tool` annotations
- The manifest is auto-generated from classpath scanning
- Unit test coverage and input validation are built-in
