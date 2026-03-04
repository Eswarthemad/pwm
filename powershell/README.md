# PWM — Personal Password Manager

![License](https://img.shields.io/badge/license-MIT-green)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207.0+-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![Crypto](https://img.shields.io/badge/crypto-Argon2id%20%7C%20AES--256-orange)
![Status](https://img.shields.io/badge/status-Stable-brightgreen)

A single-user, offline password manager built entirely in PowerShell.  
No cloud. No registry changes. No admin rights required.

Two editions available — choose based on your environment.

---

## Editions

| | Standard | Server |
|---|---|---|
| **Cipher** | Twofish-256-EAX | AES-256-CBC + HMAC-SHA256 |
| **KDF** | Argon2id 256MB / 4-iter | PBKDF2-HMAC-SHA256 100k iter |
| **Dependency** | BouncyCastle.Cryptography.dll | None — pure .NET Framework 4.0 |
| **Requires** | PowerShell 7 / .NET 6+ | PowerShell 5.1 / .NET Framework 4.0+ |
| **Use when** | Dev machine, modern Windows | Locked-down server, no internet, PS 5.1 |

> Vault files are **not cross-compatible** between editions. Each edition creates its own `cred-store.etm`.

---

## What It Is

A standalone credential vault for one user on one Windows machine.  
Designed for technically proficient users who understand the security model of local password managers.

- Credentials encrypted with **Twofish-256-EAX** (Standard) or **AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)** (Server)
- Master key derived via **Argon2id** (Standard) or **PBKDF2-HMAC-SHA256** (Server)
- Vault bound to master password + Windows user context (MachineGUID + SID)
- Source code protected by **AES-256-CBC + DPAPI** — plaintext never touches disk after install
- Every encrypted blob includes a fixed associated data value (Standard) or domain-separated MAC input (Server) for format binding

---

## What It Is Not

- Not a Bitwarden or KeePass replacement
- Not multi-user, not multi-device by default (use `-recover` to migrate)
- Not a browser extension or auto-fill tool
- Not audited by a third party
- Not an enterprise password management solution

If you need sync across devices, team sharing, policy enforcement, or browser integration — use a dedicated password manager.

---

### BouncyCastle Dependency (Standard Edition Only)

The Standard Edition requires `BouncyCastle.Cryptography.dll` (BouncyCastle .NET v2.x).

This repository does **not** include the DLL binary.

#### Build-Time Requirement

Place `BouncyCastle.Cryptography.dll` in the same folder as: build\build.ps1


The build script hashes the DLL and embeds the SHA-256 value into the sealed installer.

#### Runtime Requirement

After installation, the DLL will be placed at: %LOCALAPPDATA%\PWM\BouncyCastle.Cryptography.dll


If the DLL is missing or modified, PWM will abort at startup.

To verify integrity:

powershell.\pwm.ps1 -security


The -security command will report DLL hash status.

---

## Features

### Standard Edition (PowerShell 7 / .NET 6+)

| Feature | Detail |
|---|---|
| Encryption | Twofish-256-EAX via BouncyCastle |
| Key derivation | Argon2id — 256MB memory, 4 iterations |
| Vault binding | Master password + MachineGUID + UserSID |
| Session | VMK-only, DPAPI-protected, 30-minute timeout |
| Clipboard | Auto-clears after 30 seconds, crash-safe `finally` block |
| Recovery | Machine-independent recovery key, rotates on every use |
| Source protection | AES-256-CBC encrypted core, DPAPI-bound to Windows user |
| DLL protection | SHA-256 hash of BouncyCastle verified at every startup |

### Server Edition (PowerShell 5.1 / .NET Framework 4.0)

| Feature | Detail |
|---|---|
| Encryption | AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC) |
| Key derivation | PBKDF2-HMAC-SHA256 — 100,000 iterations |
| Vault binding | Master password + MachineGUID + UserSID |
| Session | VMK-only, DPAPI-protected, 30-minute timeout |
| Clipboard | Auto-clears after 30 seconds, crash-safe `finally` block |
| Recovery | Machine-independent recovery key, rotates on every use |
| Source protection | AES-256-CBC encrypted core, DPAPI-bound to Windows user |
| Dependencies | None — zero external dependencies |

---

## Threat Model

### Protected

- **Vault contents** — Authenticated encryption. Any modification results in authentication failure during decryption.
- **Vault key (VMK)** — Never stored in plaintext. Wrapped under a KDF-derived key.
- **Session** — Only the 32-byte VMK cached on disk, DPAPI-protected. Vault remains encrypted between commands.
- **Source code** — `pwm-core.dpapi` is unreadable outside your Windows user context.
- **Master password** — Read as `SecureString`, cleared immediately after use. Never written to disk.
- **Entry passwords** — Byte arrays cleared after encoding. Plaintext lifetime minimized.

### Not Protected

- **File existence** — `cred-store.etm` is visible on disk. Contents are opaque; file path is not hidden.
- **Metadata** — Entity names and notes are visible in search output.
- **Physical access with login** — If an attacker has physical access and your Windows login, DPAPI protection can be defeated. Use BitLocker underneath.
- **Recovery key file** — `pwm-recovery.key` is readable by any process running as your Windows user until deleted. Delete it immediately.
- **Memory forensics** — A live dump during an active command may capture plaintext passwords. Lifetime is minimized, not zero.
- **Same-user malware** — Any process running as your Windows user can access clipboard contents or the session VMK.

---

## Requirements

### Standard Edition
- Windows 10 / 11
- PowerShell 7.0+
- BouncyCastle.Cryptography v2.x
- No admin rights required

### Server Edition
- Windows (any version with PowerShell 5.1)
- PowerShell 5.1 / .NET Framework 4.0+
- No external dependencies
- No admin rights required

---

## License

MIT License

Copyright (c) 2026 Eswar the MAD!!

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
