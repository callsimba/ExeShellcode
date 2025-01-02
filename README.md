# ExeShellcode
**ExeShellcodeConverter** is a powerful tool for converting `.exe` files to shellcode and vice versa, with optional encryption, compression, and obfuscation. It supports stealthy payload generation for ethical hacking, penetration testing, and secure payload delivery.

## Features

- **Convert EXE to Shellcode**:
  - Optional AES-256 encryption.
  - XOR-based obfuscation for disguise.
  - Data compression for reduced shellcode size.
  - Export shellcode as a PowerShell-compatible byte array.
- **Convert Shellcode to EXE**:
  - Reconstructs the original executable from shellcode.
  - Automatically handles decryption, decompression, and deobfuscation.
- **Stealth and Security**:
  - Embeds metadata to simplify reverse conversion.
  - PowerShell output for in-memory execution.

---

## Requirements

- **Dependencies**:
  - OpenSSL
  - Zlib

Install dependencies on Ubuntu:
```bash
sudo apt install libssl-dev zlib1g-dev
