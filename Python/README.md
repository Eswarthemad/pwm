# PWM — Personal Password Manager (Python Edition)


A single-file, cross-platform, offline password manager written in Python.  
No cloud. No sync. No admin rights. No build step.  
AES-256-GCM encryption with Argon2id key derivation.

PWM is intentionally minimal.

It does one thing: encrypt credentials locally for a single user on a single machine.

There is no network access, no sync service, no browser integration,
and no background processes. Simplicity is the primary security property.

---

## What It Is

A standalone credential vault for one user on one machine.  
Designed for technically proficient users who understand the security model of local password managers.

- Credentials encrypted with **AES-256-GCM** (authenticated encryption)
- Master key derived via **Argon2id** (256MB memory, 4 iterations — GPU-resistant)
- Vault bound to master password + OS + machine identity + username
- Stateless by default — VMK lives in process memory only, dies with the process
- Optional interactive shell mode with idle and TTL timers
- Runs on Windows, WSL, Linux, macOS — one file, no build step

## What It Is Not

- Not a Bitwarden or KeePass replacement
- Not multi-user, not multi-device by default (use `-recover` to migrate)
- Not a browser extension or auto-fill tool
- Not audited by a third party
- Not compatible with the PowerShell editions of PWM (different vault format)

If you need sync across devices, team sharing, or browser integration — use a dedicated password manager.

---

## Editions

This is the Python edition. PWM also has PowerShell editions:

| Edition | Cipher | KDF | Target |
|---|---|---|---|
| **Python** (this) | AES-256-GCM | Argon2id | Windows / WSL / Linux / macOS |
| PS Standard | Twofish-256-EAX | Argon2id | Windows, PowerShell 7 |
| PS Server | AES-256-CBC + HMAC (Encrypt-then-MAC) | PBKDF2 | Windows, PowerShell 5.1 / .NET 4.0 |

> Vault files are **not cross-compatible** between editions. Each edition creates its own `cred-store.etm`.

---

## Features

| Feature | Detail |
|---|---|
| Encryption | AES-256-GCM — authenticated encryption, tamper-proof |
| Key derivation | Argon2id — 256MB memory, 4 iterations, GPU-resistant |
| Vault binding | OS + machine identity + username + master password |
| Header | Magic `b'PWM2ETM\x00'` + version byte — detects corruption and wrong files |
| Session default | Stateless — VMK in process memory only, dies with process |
| Session optional | Shell mode with `--idle-timeout` and `--ttl` watchdog timers |
| Clipboard | Auto-clears after 30 seconds — Windows, macOS, WSL, Linux |
| Recovery | Machine-independent recovery key, single-use, rotates on every use |
| Safe writes | Write to `.tmp` → fsync → atomic rename — power-safe on every vault write |
| Dependencies | Two pip modules only: `cryptography` + `argon2-cffi` |

---

## Threat Model

### Protected

- **Vault contents** — AES-256-GCM. Any modification causes authentication failure during decryption, and no plaintext is released. AAD `b'PWMv2|Eswar the MAD!!'` bound to every GCM operation.
- **Vault key (VMK)** — 32-byte random key, never stored in plaintext. Wrapped under Argon2id-derived key.
- **Session** — Stateless by default. VMK in process memory only. No disk files, no keyring.
- **Master password** — Prompted via `getpass()`. Never echoed, never persisted.
- **Entry passwords** — In memory only during active command. Not persisted outside the vault.
- **Recovery key** — Single-use. Rotates on every `-recover`. Previous key immediately invalid.

### Not Protected

- **File existence** — `cred-store.etm` is visible on disk. Contents are opaque; path is not hidden.
- **Metadata** — Entity names and notes visible in `-search` output.
- **Physical access** — Use full-disk encryption (BitLocker / LUKS / FileVault).
- **Recovery key file** — Readable until deleted. Delete immediately after copying offline.
- **Same-user processes** — Any process running as your user can read clipboard or memory.
- **Memory forensics** — Plaintext in process memory during active commands. Lifetime minimised.
- **Shell history** — Avoid typing passwords as CLI arguments or comments. They appear in shell history.

---

## Requirements

- Python 3.8+
- `pip install cryptography argon2-cffi`
- No admin rights required

### Platform clipboard support

| Platform | Tool used |
|---|---|
| Windows | `clip` (built-in) |
| macOS | `pbcopy` (built-in) |
| WSL | `clip.exe` (Windows binary, always available in WSL) |
| Linux | `xclip` or `xsel` (install one if needed) |

---

## Quickstart

```bash
pip install cryptography argon2-cffi

# Create vault
python pwm.py -init

# Add a credential
python pwm.py -add -entity "github.com" -notes "personal"

# Search
python pwm.py -search "github"

# Copy password to clipboard (auto-clears in 30s)
python pwm.py -copy -id <id> -field password

# Update / remove
python pwm.py -update -id <id>
python pwm.py -remove -id <id>

# Recover vault on new machine
python pwm.py -recover

# View security model
python pwm.py -security
```

### Stateless mode (default)

Password is prompted automatically on every command — no prior unlock needed:

```bash
python pwm.py -search "github"
python pwm.py -copy -id <id> -field password
```

### Explicit unlock prefix

```bash
python pwm.py -unlock -add -entity "github.com"
```

### Shell mode (unlock once, multiple commands)

```bash
python pwm.py -shell
python pwm.py -shell --idle-timeout 3 --ttl 15
```

```
pwm> search github
pwm> copy <id> password
pwm> add github.com personal
pwm> exit
```

Two timers run independently — idle resets on every command, TTL never resets. Whichever fires first locks and exits — even while waiting at the prompt.

---

## Master Password Requirements

Use a strong master password (recommended: 16+ characters or a long passphrase).

---

## Recovery Key

Generated at `-init` and every `-recover`. Single-use — rotates automatically.  
Copy it offline (paper or air-gapped USB). Delete the file immediately after copying.  
Loss of both master password and recovery key means **permanent vault loss**.

---

## Security Notes

**Clipboard** — Password clears after 30 seconds. Any process running as your user can read the clipboard during that window. WSL uses `clip.exe` to reach the Windows clipboard.

**Machine binding** — Vault is cryptographically bound to the machine that created it. Moving to a new machine requires `-recover`. If OS machine identity is unavailable, a fallback ID is generated in `.pwm-host-id` — keep this file safe, it is part of the binding.

**Same-user processes** — No protection against malicious software running under your own account. Use a dedicated OS user account for sensitive credential management.

**BitLocker / LUKS / FileVault** — Run full-disk encryption underneath. Python's `getpass()` and in-memory secrets are only as safe as the OS and hardware underneath them.

**Backup** - Back up cred-store.etm regularly. Without it, credentials are unrecoverable even with the recovery key.

**Shell history** — `python pwm.py -search "github"` is safe. Never type your master password as a command-line argument. The interactive prompts via `getpass()` do not appear in shell history.

---

## File Reference

| File | Purpose |
|---|---|
| `pwm.py` | The entire application. Copy anywhere and run. |
| `cred-store.etm` | Encrypted vault. **Back this up.** |
| `pwm-recovery.key` | Recovery key. Delete after copying offline. |
| `.pwm-host-id` | Fallback machine ID (only created if OS lookup fails). |

---

## License

MIT License

Copyright (c) 2026 Eswar the MAD!!

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.