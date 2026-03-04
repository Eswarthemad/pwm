# SECURITY.md — PWM

## Editions

This document covers both editions. Cryptographic differences are noted per section.

---

## Cryptography Summary

### Key Derivation

**Standard Edition (PowerShell 7 / .NET 6+)**
- Algorithm — Argon2id
- Memory — 256 MB
- Iterations — 4
- Parallelism — 1
- Input — MasterPassword + MachineGUID + UserSID (UTF-8)
- Output — 32-byte key used exclusively to wrap the VMK

Argon2id provides resistance against GPU-accelerated and parallel brute-force attacks.

**Server Edition (PowerShell 5.1 / .NET Framework 4.0)**
- Algorithm — PBKDF2-HMAC-SHA256 (manual implementation)
- Iterations — 100,000
- Salt — 32 bytes, random per vault
- Input — MasterPassword + MachineGUID + UserSID
- Output — 32-byte key used exclusively to wrap the VMK

Trade-off: PBKDF2 is CPU-only and not memory-hard. A sufficiently resourced attacker can test guesses faster than against Argon2id. Use a high-entropy master password.

---

### Vault Encryption

**Standard Edition**
- Cipher — Twofish-256-EAX (AEAD)
- Key — 32-byte random VMK
- Associated Data — Static format-binding value
- Effect — Any modification results in authentication failure during decryption

**Server Edition**
- Cipher — AES-256-CBC
- Integrity — HMAC-SHA256 (Encrypt-then-MAC)
- MAC input — Domain-separated value + ciphertext
- Effect — MAC verified before decryption; any modification results in authentication failure

The VMK is never stored in plaintext.

---

### VMK Wrapping

Two independent wrapped copies of the VMK are stored:

| Path | Wrapped With |
|---|---|
| Primary | KDF(MasterPassword + HostBinding) |
| Recovery | KDF(RecoveryKey) |

Unwrapping one path does not expose the other.

---

### Installer Payload Protection

Both editions use AES-256-CBC:
- Key derived from license key via SHA-256
- Layout — IV(16) + ciphertext
- Payload remains encrypted without the correct key

---

### Session Handling

- Only the 32-byte VMK is written to disk
- DPAPI-protected (CurrentUser scope)
- Expires after 30 minutes
- Filename derived from vault path

DPAPI protects against other users and offline theft, not against same-user processes.

---

### DLL Integrity (Standard Edition Only)

- SHA-256 of BouncyCastle verified on startup
- Mismatch aborts execution

Server edition has no external DLL.

---

## Security Properties

PWM provides protection against:
- Offline vault theft
- Vault tampering
- Accidental corruption
- Unauthorized access from other Windows accounts
- Unauthorized access from other machines

---

## Limitations

### Clipboard Exposure
Passwords remain in the clipboard for up to 30 seconds. Any process running under the same Windows user account can read clipboard contents during that window.

### Same-User Malware
If the user session is compromised, assume vault contents may be accessible.

### Memory Exposure
Plaintext passwords exist in memory during active operations. Exposure window minimized, not eliminated.

### Recovery Key File
Written as plaintext until deleted.

### Physical Access
Full-disk encryption (BitLocker) strongly recommended.

### No Formal Audit
- No third-party audit
- No side-channel resistance analysis
- Constant-time comparison not implemented (not considered exploitable in this local threat model)

---

## Scope

PWM is a personal standalone credential vault. It is not an enterprise platform or cloud-synchronized system.