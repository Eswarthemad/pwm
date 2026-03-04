\# PWM — Personal Password Manager

⚠ This project has not undergone a formal security audit.
Use at your own risk for high-value secrets.

Two editions of PWM are maintained here.



\## Python Edition (Cross-platform)

Location: `./Python`



Single-file CLI vault:

\- AES-256-GCM encryption

\- Argon2id key derivation

\- Stateless default session

\- Linux / macOS / Windows / WSL



\## PowerShell Edition (Windows)



Location: `./PowerShell`



Includes:

\- Standard edition (Twofish-EAX + Argon2id)

\- Server edition (AES-CBC + HMAC + PBKDF2)



Vault formats are \*\*not cross-compatible\*\* between editions.


PWM
 ├─ PowerShell Edition (Windows native)
 │   ├─ DPAPI session protection
 │   └─ Twofish / AES options
 │
 └─ Python Edition (Cross-platform)
     ├─ Argon2id
     ├─ AES-256-GCM
     └─ Stateless default operation