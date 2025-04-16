# MCP-Cipher: Installation Guide for LLMs

This server provides a lightweight, secure, and MCP-compatible cryptography toolset, including AES, RSA, and hash utilities.

## 🛠 Installation & Execution

To install and run the server locally:

```bash
npx mcp add https://raw.githubusercontent.com/key824999/MCP-Cipher/refs/heads/master/manifest.json

git clone https://github.com/key824999/MCP-Cipher.git
cd MCP-Cipher
./gradlew bootRun
```

> ☕ Requires Java 21+ and Gradle 8+

## 🧩 Optional: Claude Desktop JSON Config

To run the server via a remote JAR (e.g., for Claude Desktop):

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

## 📌 Notes

- Tools are exposed via `@Tool` annotations
- All inputs are validated
- Fully tested with unit coverage
