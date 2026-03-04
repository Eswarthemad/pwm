# SECURITY.md — PWM (Python Edition)

---

## Cryptography Summary

### Key Derivation

- **Algorithm** — Argon2id
- **Memory** — 256 MB
- **Iterations** — 4
- **Parallelism** — 1
- **Input** — `struct.pack('>I', len(password)) + password_bytes + bind_bytes`
- **Output** — 32-byte key used exclusively to wrap the VMK

Length-prefixing the password prevents concatenation ambiguity between password and binding bytes. The derived key is never reused for any other cryptographic purpose.

Argon2id provides resistance against GPU-accelerated and parallel brute-force attacks. Trade-off versus PBKDF2: Argon2id requires significant memory per guess, making large-scale parallel attacks expensive in hardware cost.

---

### Vault Encryption (AEAD)

- **Cipher** — AES-256-GCM
- **Key** — 32-byte random VMK (Vault Master Key)
- **Nonce** — 12 bytes, random per write, embedded in body
- **Tag** — 16 bytes (128-bit GCM authentication tag)
- **AAD** — `b'PWMv2|Eswar the MAD!!'` — bound to every GCM operation
- **Body format** — `nonce(12) + ciphertext(n) + tag(16)` — self-contained

Any modification to `cred-store.etm` results in GCM authentication failure before any plaintext is produced. The AAD acts as a domain separator — a blob encrypted for a different purpose cannot be replayed.

---

### VMK Wrapping

Two independent wrapped copies of the VMK are stored in the vault header:

| Path | Wrapped With |
|---|---|
| Primary | `Argon2id(struct.pack(">I", len(password)) || password || bind_bytes, prim_salt)` |
| Recovery | `Argon2id(recovery_key, rec_salt)` — no host binding |

Both use AES-256-GCM with the same AAD. Unwrapping one path does not expose the other.  
Wrapped VMK layout: `nonce(12) + ciphertext(32) + tag(16) = 60 bytes`.

Recovery has no host binding by design — it must work on any machine.

---

### Host Binding

```
bind_v1 = "pwm:v2|os=<os>|machine=<machine_id>|user=<username>"
```

Normalised: lowercase, stripped, UTF-8 encoded. Added to KDF input as structured suffix.

| OS | Machine identity source |
|---|---|
| Windows | `HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid` |
| Linux | `/etc/machine-id` |
| macOS | `ioreg IOPlatformUUID` |
| Fallback | Random 16-byte hex stored in `.pwm-host-id` |

If OS lookup fails, a stable random fallback is generated and stored in `.pwm-host-id`. A warning is printed. The fallback is weaker than a hardware-rooted ID — keep the file safe.

Stored in vault header as:
- `BindMode` — `0x01` (default) or `0x00` (none)
- `BindHash` — SHA-256 of the full bind string (not the raw IDs)
- `BindHint` — `"os=linux user=eswar"` — human-readable, null-padded to 32 bytes

---

### Vault Header Format (512 bytes)

```
Offset   0 : Magic        8 bytes   b'PWM2ETM\x00' — file type detection
Offset   8 : Version      1 byte    0x01
Offset   9 : PrimSalt    32 bytes   Argon2id salt, primary path
Offset  41 : RecSalt     32 bytes   Argon2id salt, recovery path
Offset  73 : PwWrappedVMK 60 bytes  nonce(12) + ct(32) + tag(16)
Offset 133 : RwWrappedVMK 60 bytes  nonce(12) + ct(32) + tag(16)
Offset 193 : BindMode     1 byte    0x01=default, 0x00=none
Offset 194 : BindHash    32 bytes   SHA-256(bind_v1)
Offset 226 : BindHint    32 bytes   UTF-8 null-padded
Offset 258 : Filler     251 bytes   cryptographically random noise
```

Magic and version are validated on every read. Wrong file or version mismatch produces a clear error before any crypto operation.

---

### Session Handling

**Default (stateless):**  
VMK derived on every command, lives in process memory only, dies with the process. No disk files, no keyring, no OS secret store.

**Shell mode:**  
VMK held in memory for the session duration. A background watchdog thread checks every 5 seconds and calls `os._exit(0)` when idle or TTL limit is exceeded — fires even while blocked at the input prompt.

---

### Safe Writes

Every vault write uses atomic rename:

```python
write to cred-store.etm.tmp
fsync (flush OS buffer to physical disk)
os.replace(.tmp → cred-store.etm)   # atomic on POSIX, best-effort on Windows
```

If power fails before `os.replace()` — original vault untouched, `.tmp` discarded.  
If power fails after — rename completed, new vault in place.  
Applied to every operation: `-init`, `-add`, `-update`, `-remove`, `-recover`.

---

### Vault Body Format

```json
{
  "format":  "pwm-v2",
  "created": "2026-03-04T00:00:00+00:00",
  "entries": [
    {
      "id":       "<hex-32>",
      "entity":   "github.com",
      "username": "eswar",
      "password": "...",
      "notes":    "personal",
      "created":  "...",
      "modified": "..."
    }
  ]
}
```

Format field `pwm-v2` enables future format detection and migration tooling.

---

## Limitations

### Clipboard Exposure
Passwords remain in clipboard for up to 30 seconds. Any process running as your user can read clipboard contents during that window. A `finally` block ensures clearing even on unexpected errors.

WSL clipboard goes through `clip.exe` — it writes to the Windows clipboard, which is shared across all Windows processes.

### Same-User Processes
No protection against malicious software running under your own OS account. If the user session is compromised, assume vault contents may be accessible during an active command.

### Memory Exposure
Plaintext passwords exist in process memory during active operations. Byte references are released immediately after use but Python's garbage collector controls actual zeroing — lifetime is minimised, not zero.

### Recovery Key File
`pwm-recovery.key` is written as plaintext and readable by any process under your user until deleted. Exposure between generation and deletion is real.

### Physical Access
Full-disk encryption (BitLocker / LUKS / FileVault) is required. Python process memory and file handles are not protected against physical access to an unlocked machine.

### Shell History
`getpass()` prompts do not appear in shell history. Arguments do. Never pass sensitive values as CLI arguments.

### No Formal Audit
- No third-party cryptographic audit
- No formal side-channel analysis
- Constant-time comparison not implemented (not exploitable in this local, single-user context)

---

## Recommended Usage

**Dedicated OS account** — Run PWM under an account used only for credential management.

**Restricted folder permissions**

```bash
# Linux / macOS
chmod 700 ~/vault
chmod 600 ~/vault/cred-store.etm

# Windows (PowerShell)
icacls C:\Vault /inheritance:r /grant:r "$env:USERNAME:(OI)(CI)F"
```

**Short clipboard timeout** — Reduce `CLIP_SECS` in `pwm.py` for sensitive environments. 10–15 seconds is practical.

**Full-disk encryption** — BitLocker, LUKS, or FileVault. Non-negotiable on laptops.

**Offline recovery key** — Print or store on air-gapped USB. Do not store in another password manager on the same machine.

**WSL note** — WSL clipboard uses `clip.exe` and writes to the shared Windows clipboard. The 30-second auto-clear fires from the WSL process. Be aware other Windows applications can read the clipboard during that window.

---

## Scope

PWM is a personal, standalone credential vault. It is not an enterprise platform, multi-user system, browser-integrated manager, or cloud solution. Vault format is Python-edition specific — not compatible with the PowerShell editions. Designed for technically proficient users who understand and accept the local threat model.