#!/usr/bin/env python3
"""
PWM — Personal Password Manager (Python Edition)
Cipher  : AES-256-GCM
KDF     : Argon2id (256MB, 4-iter, parallelism 1)
AAD     : b'PWMv2|Eswar the MAD!!'
Binding : pwm:v2|os=|machine=|user=
Format  : pwm-v2  —  Python edition only, not compatible with PowerShell edition
"""

# ── Dependency check ──────────────────────────────────────────────────────────
import sys, importlib.util

_REQUIRED = {'cryptography': 'cryptography', 'argon2': 'argon2-cffi'}
_MISSING  = [pip for mod, pip in _REQUIRED.items()
             if importlib.util.find_spec(mod) is None]
if _MISSING:
    print(f"Missing modules. Install with:\n  pip install {' '.join(_MISSING)}")
    sys.exit(1)

# ── Imports ───────────────────────────────────────────────────────────────────
import os, json, struct, secrets, hashlib, platform, subprocess
import argparse, threading, time, textwrap
from datetime import datetime, timezone
from getpass  import getpass
from pathlib  import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from argon2.low_level import hash_secret_raw, Type

# ── Constants ─────────────────────────────────────────────────────────────────
VAULT_FILE    = Path(__file__).parent / 'cred-store.etm'
RECOVERY_FILE = Path(__file__).parent / 'pwm-recovery.key'

AAD           = b'PWMv2|Eswar the MAD!!'
FORMAT        = 'pwm-v2'
VAULT_MAGIC   = b'PWM2ETM' + b'\x00'   # 8 bytes — file type + corruption detection
VAULT_VERSION = 0x01

ARGON_MEM_KB  = 262144   # 256 MB
ARGON_ITER    = 4
ARGON_PAR     = 1
ARGON_LEN     = 32       # VMK size

CLIP_SECS     = 30

# Header layout — 512 bytes fixed, 258 used + 254 filler (random noise)
# Body is self-contained: nonce(12) + ciphertext + tag(16) — no BodyNonce in header
HO_MAGIC      =   0   #  8 bytes  b'PWM2ETM\x00'
HO_VERSION    =   8   #  1 byte   0x01
HO_PRIM_SALT  =   9   # 32 bytes
HO_REC_SALT   =  41   # 32 bytes
HO_PW_VMK     =  73   # 60 bytes  nonce(12) + ct(32) + tag(16)
HO_RW_VMK     = 133   # 60 bytes
HO_BIND_MODE  = 193   #  1 byte   0x01 = default, 0x00 = none
HO_BIND_HASH  = 194   # 32 bytes  SHA-256(bind_v1)
HO_BIND_HINT  = 226   # 32 bytes  UTF-8 null-padded hint
HEADER_SIZE   = 512

VAULT_MIN_SIZE = HEADER_SIZE + 12 + 16   # header + min GCM nonce + tag

HOST_ID_FILE  = Path(__file__).parent / '.pwm-host-id'  # fallback machine-id


# ── Host Binding ──────────────────────────────────────────────────────────────

def _machine_id() -> str:
    """Read OS-native machine identifier."""
    try:
        if platform.system() == 'Windows':
            import winreg
            k = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                               r'SOFTWARE\Microsoft\Cryptography')
            val, _ = winreg.QueryValueEx(k, 'MachineGuid')
            return val.strip().lower()
        elif platform.system() == 'Linux':
            return Path('/etc/machine-id').read_text().strip().lower()
        elif platform.system() == 'Darwin':
            out = subprocess.check_output(
                ['ioreg', '-rd1', '-c', 'IOPlatformExpertDevice'],
                stderr=subprocess.DEVNULL).decode()
            for line in out.splitlines():
                if 'IOPlatformUUID' in line:
                    return line.split('"')[-2].strip().lower()
    except Exception:
        pass
    # OS lookup failed — use or create a stable fallback ID
    if HOST_ID_FILE.exists():
        return HOST_ID_FILE.read_text().strip()
    fallback = secrets.token_hex(16)
    HOST_ID_FILE.write_text(fallback)
    print('WARNING: OS machine-id unavailable. Generated fallback ID.')
    print(f'         Stored in: {HOST_ID_FILE}')
    print('         Vault binding is weaker — keep this file safe.\n')
    return fallback


def _get_user() -> str:
    """Get username. Falls back to env vars if os.getlogin() fails."""
    try:
        return os.getlogin().lower().strip()
    except Exception:
        return (os.environ.get('USERNAME')
                or os.environ.get('USER')
                or 'unknown-user').lower().strip()


def get_binding() -> tuple:
    """Returns (bind_v1_string, bind_bytes). Canonical, lowercase, UTF-8."""
    os_name  = platform.system().lower()
    machine  = _machine_id()
    user     = _get_user()
    bind_str = f"pwm:v2|os={os_name}|machine={machine}|user={user}"
    return bind_str, bind_str.encode('utf-8')


def _bind_hint(bind_str: str) -> bytes:
    """32-byte null-padded hint — e.g. 'os=linux user=eswar'."""
    parts = [p for p in bind_str.split('|')
             if p.startswith('os=') or p.startswith('user=')]
    hint  = ' '.join(parts)[:31]
    return hint.encode('utf-8').ljust(32, b'\x00')


# ── Crypto ────────────────────────────────────────────────────────────────────

def derive_key(password: bytes, salt: bytes, bind_bytes: bytes) -> bytes:
    """Argon2id KDF. Input: length-prefixed password + binding bytes."""
    kdf_input = struct.pack('>I', len(password)) + password + bind_bytes
    return hash_secret_raw(
        secret      = kdf_input,
        salt        = salt,
        time_cost   = ARGON_ITER,
        memory_cost = ARGON_MEM_KB,
        parallelism = ARGON_PAR,
        hash_len    = ARGON_LEN,
        type        = Type.ID,
    )


def gcm_encrypt(key: bytes, plaintext: bytes) -> bytes:
    """Returns nonce(12) + ciphertext + tag(16). AAD bound to every operation."""
    nonce = secrets.token_bytes(12)
    ct    = AESGCM(key).encrypt(nonce, plaintext, AAD)
    return nonce + ct


def gcm_decrypt(key: bytes, data: bytes) -> bytes:
    """data = nonce(12) + ciphertext + tag(16). Raises on auth failure."""
    nonce, ct = data[:12], data[12:]
    try:
        return AESGCM(key).decrypt(nonce, ct, AAD)
    except Exception:
        raise ValueError('Authentication failed — wrong credentials or tampered data.')


# ── Header Pack / Unpack ──────────────────────────────────────────────────────

def pack_header(prim_salt: bytes, rec_salt: bytes,
                pw_vmk: bytes, rw_vmk: bytes,
                bind_str: str) -> bytes:
    raw = bytearray(secrets.token_bytes(HEADER_SIZE))   # filler = random noise
    raw[HO_MAGIC     : HO_MAGIC    +  8] = VAULT_MAGIC
    raw[HO_VERSION]                       = VAULT_VERSION
    raw[HO_PRIM_SALT : HO_PRIM_SALT + 32] = prim_salt
    raw[HO_REC_SALT  : HO_REC_SALT  + 32] = rec_salt
    raw[HO_PW_VMK    : HO_PW_VMK    + 60] = pw_vmk
    raw[HO_RW_VMK    : HO_RW_VMK    + 60] = rw_vmk
    raw[HO_BIND_MODE]                      = 0x01
    raw[HO_BIND_HASH : HO_BIND_HASH + 32] = hashlib.sha256(
                                                bind_str.encode()).digest()
    raw[HO_BIND_HINT : HO_BIND_HINT + 32] = _bind_hint(bind_str)
    return bytes(raw)


def unpack_header(raw: bytes) -> dict:
    magic   = raw[HO_MAGIC : HO_MAGIC + 8]
    version = raw[HO_VERSION]
    if magic != VAULT_MAGIC:
        raise ValueError(
            f'Invalid vault file — bad magic bytes. '
            f'Expected {VAULT_MAGIC!r}, got {magic!r}.')
    if version != VAULT_VERSION:
        raise ValueError(
            f'Unsupported vault version {version:#04x}. '
            f'This build supports version {VAULT_VERSION:#04x}.')
    return {
        'prim_salt' : raw[HO_PRIM_SALT : HO_PRIM_SALT + 32],
        'rec_salt'  : raw[HO_REC_SALT  : HO_REC_SALT  + 32],
        'pw_vmk'    : raw[HO_PW_VMK    : HO_PW_VMK    + 60],
        'rw_vmk'    : raw[HO_RW_VMK    : HO_RW_VMK    + 60],
        'bind_mode' : raw[HO_BIND_MODE],
        'bind_hash' : raw[HO_BIND_HASH : HO_BIND_HASH + 32],
        'bind_hint' : raw[HO_BIND_HINT : HO_BIND_HINT + 32]
                         .rstrip(b'\x00').decode('utf-8', errors='replace'),
    }


# ── Vault File I/O ────────────────────────────────────────────────────────────

def assert_vault():
    if not VAULT_FILE.exists():
        raise SystemExit('Vault not found. Run: python pwm.py -init')
    if VAULT_FILE.stat().st_size < VAULT_MIN_SIZE:
        raise SystemExit('Vault file is corrupt or incomplete.')


def safe_write(path: Path, data: bytes):
    """Write to .tmp → fsync → atomic rename. Every vault write uses this."""
    tmp = path.with_suffix(path.suffix + '.tmp')
    try:
        with open(tmp, 'wb') as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


def read_vault_body(raw: bytes, vmk: bytes) -> dict:
    return json.loads(gcm_decrypt(vmk, raw[HEADER_SIZE:]))


def write_vault(vault: dict, vmk: bytes, header: bytes):
    body = gcm_encrypt(vmk, json.dumps(vault, separators=(',', ':')).encode())
    safe_write(VAULT_FILE, header + body)


def read_header() -> tuple:
    """Returns (raw_header_bytes, hdr_dict)."""
    assert_vault()
    raw = VAULT_FILE.read_bytes()
    return raw[:HEADER_SIZE], unpack_header(raw[:HEADER_SIZE])


# ── Password Helpers ──────────────────────────────────────────────────────────

def prompt_password(prompt: str = 'Master password') -> bytes:
    return getpass(f'{prompt}: ').encode('utf-8')


def check_complexity(pw: bytes):
    s    = pw.decode('utf-8')
    errs = []
    if len(s) < 16:                            errs.append('16+ characters')
    if not any(c.isupper() for c in s):        errs.append('uppercase letter')
    if not any(c.islower() for c in s):        errs.append('lowercase letter')
    if not any(c.isdigit() for c in s):        errs.append('digit')
    if not any(not c.isalnum() for c in s):    errs.append('special character')
    if errs:
        raise ValueError('Password must contain: ' + ', '.join(errs))


def unlock_vault(password: bytes = None) -> tuple:
    """Derive VMK from master password. Returns (vmk, raw_header, hdr_dict).
    Prompts for password if not supplied — used by auto-prompt path."""
    assert_vault()
    if password is None:
        password = prompt_password()
    _, bind_bytes = get_binding()
    raw           = VAULT_FILE.read_bytes()
    hdr           = unpack_header(raw[:HEADER_SIZE])
    print('Deriving key...', flush=True)
    key           = derive_key(password, hdr['prim_salt'], bind_bytes)
    vmk           = gcm_decrypt(key, hdr['pw_vmk'])
    gcm_decrypt(vmk, raw[HEADER_SIZE:])   # verify VMK decrypts body
    return vmk, raw[:HEADER_SIZE], hdr


# ── Recovery Key Helpers ──────────────────────────────────────────────────────

def new_recovery_key() -> tuple:
    """Returns (raw_bytes, formatted_string)."""
    rb  = secrets.token_bytes(32)
    hex = rb.hex().upper()
    fmt = '-'.join(hex[i:i+4] for i in range(0, 64, 4))
    return rb, fmt


def parse_recovery_key(s: str) -> bytes:
    h = s.replace('-', '').replace(' ', '')
    if len(h) != 64:
        raise ValueError('Invalid recovery key — expected 64 hex characters.')
    return bytes.fromhex(h)


def write_recovery_file(fmt: str):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    RECOVERY_FILE.write_text(textwrap.dedent(f"""\
        === PWM VAULT RECOVERY KEY ===
        Generated : {now}
        Machine   : {platform.node()}
        User      : {_get_user()}

        Recovery Key:
        {fmt}

        INSTRUCTIONS:
        1. Copy this file to a SECURE OFFLINE location (USB or printed paper).
        2. DELETE this file from this folder IMMEDIATELY after copying.
        3. Each use of -recover invalidates this key and generates a new one.
        ==============================
    """))


def warn_recovery_file():
    if RECOVERY_FILE.exists():
        print()
        print('  !! WARNING: pwm-recovery.key is still in the vault folder !!')
        print('  !! Copy it to a secure location and DELETE it immediately.  !!')
        print()


# ── Clipboard ─────────────────────────────────────────────────────────────────

def _is_wsl() -> bool:
    try:
        return 'microsoft' in Path('/proc/version').read_text().lower()
    except Exception:
        return False


def _clip_set(text: str):
    os_name = platform.system()
    if os_name == 'Windows':
        proc = subprocess.Popen(['clip'], stdin=subprocess.PIPE)
        proc.communicate(text.encode('utf-16-le'))
    elif os_name == 'Darwin':
        subprocess.run(['pbcopy'], input=text.encode(), check=True)
    elif _is_wsl():
        # WSL: pipe to Windows clip.exe via UTF-16-LE (same encoding Windows clip expects)
        proc = subprocess.Popen(['clip.exe'], stdin=subprocess.PIPE)
        proc.communicate(text.encode('utf-16-le'))
    else:
        for cmd in (['xclip', '-selection', 'clipboard'],
                    ['xsel',  '--clipboard', '--input']):
            try:
                subprocess.run(cmd, input=text.encode(), check=True)
                return
            except FileNotFoundError:
                continue
        raise RuntimeError('No clipboard tool found (install xclip or xsel).')


def copy_to_clipboard(text: str):
    try:
        _clip_set(text)
    except Exception as e:
        print(f'  Clipboard error: {e}')
        return

    def _clear():
        time.sleep(CLIP_SECS)
        try:
            _clip_set('')
        except Exception:
            pass

    threading.Thread(target=_clear, daemon=True).start()


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_init():
    if VAULT_FILE.exists():
        print('WARNING: Vault already exists. All data will be PERMANENTLY lost.')
        if input('Type CONFIRM to proceed: ') != 'CONFIRM':
            print('Aborted.')
            return

    pw1 = prompt_password('Set master password')
    check_complexity(pw1)
    pw2 = prompt_password('Confirm master password')
    if pw1 != pw2:
        raise ValueError('Passwords do not match.')

    bind_str, bind_bytes = get_binding()
    prim_salt = secrets.token_bytes(32)
    rec_salt  = secrets.token_bytes(32)
    vmk       = secrets.token_bytes(32)

    print('Deriving key — this takes a moment...', flush=True)
    prim_key       = derive_key(pw1, prim_salt, bind_bytes)
    rec_raw, rec_fmt = new_recovery_key()
    rec_key        = derive_key(rec_raw, rec_salt, b'')   # recovery: no host binding

    pw_vmk  = gcm_encrypt(prim_key, vmk)
    rw_vmk  = gcm_encrypt(rec_key,  vmk)
    header  = pack_header(prim_salt, rec_salt, pw_vmk, rw_vmk, bind_str)

    vault = {
        'format':  FORMAT,
        'created': datetime.now(timezone.utc).isoformat(),
        'entries': [],
    }
    write_vault(vault, vmk, header)
    write_recovery_file(rec_fmt)

    print('Vault created successfully.')
    warn_recovery_file()


def cmd_add(vmk: bytes, entity: str = '', notes: str = ''):
    warn_recovery_file()
    if not entity:
        entity = input('Entity: ').strip()
    username = input('Username: ').strip()
    pw1 = prompt_password('Password')
    pw2 = prompt_password('Confirm password')
    if pw1 != pw2:
        raise ValueError('Passwords do not match.')

    hdr_bytes, _ = read_header()
    raw           = VAULT_FILE.read_bytes()
    vault         = read_vault_body(raw, vmk)
    now           = datetime.now(timezone.utc).isoformat()
    entry = {
        'id':       secrets.token_hex(16),
        'entity':   entity,
        'username': username,
        'password': pw1.decode('utf-8'),
        'notes':    notes,
        'created':  now,
        'modified': now,
    }
    vault['entries'].append(entry)
    write_vault(vault, vmk, hdr_bytes)
    print(f"Entry added. ID: {entry['id']}")


def cmd_search(vmk: bytes, keyword: str):
    warn_recovery_file()
    raw     = VAULT_FILE.read_bytes()
    vault   = read_vault_body(raw, vmk)
    q       = keyword.lower()
    results = [e for e in vault['entries']
               if q in e.get('entity', '').lower()
               or q in e.get('notes',  '').lower()]
    if not results:
        print(f"No entries found matching '{keyword}'.")
        return

    # Dynamic column widths
    headers = ('ID', 'Entity', 'Username', 'Notes')
    cols    = [
        max(len(headers[0]), max(len(e['id'])                  for e in results)),
        max(len(headers[1]), max(len(e.get('entity',   ''))    for e in results)),
        max(len(headers[2]), max(len(e.get('username', ''))    for e in results)),
        max(len(headers[3]), max(len(e.get('notes',    ''))    for e in results)),
    ]
    fmt = '  '.join(f'{{:<{c}}}' for c in cols)
    print(fmt.format(*headers))
    print(fmt.format(*('-' * c for c in cols)))
    for e in results:
        print(fmt.format(e['id'], e.get('entity', ''),
                         e.get('username', ''), e.get('notes', '')))


def cmd_copy(vmk: bytes, entry_id: str, field: str):
    warn_recovery_file()
    if field not in ('password', 'username'):
        raise ValueError('-field must be password or username')
    raw   = VAULT_FILE.read_bytes()
    vault = read_vault_body(raw, vmk)
    entry = next((e for e in vault['entries'] if e['id'] == entry_id), None)
    if not entry:
        raise ValueError(f'Entry not found: {entry_id}')
    val = entry[field]
    try:
        copy_to_clipboard(val)
        print(f"{field.capitalize()} copied for '{entry['entity']}'. "
              f"Clears in {CLIP_SECS}s.")
    finally:
        val = None


def cmd_list(vmk: bytes):
    """List all entries — equivalent to search with no filter."""
    warn_recovery_file()
    raw     = VAULT_FILE.read_bytes()
    vault   = read_vault_body(raw, vmk)
    entries = vault.get('entries', [])
    if not entries:
        print('Vault is empty.')
        return
    print(f'{len(entries)} entry/entries in vault.')
    # Reuse search display logic with all entries
    headers = ('ID', 'Entity', 'Username', 'Notes')
    cols    = [
        max(len(headers[0]), max(len(e['id'])               for e in entries)),
        max(len(headers[1]), max(len(e.get('entity',   '')) for e in entries)),
        max(len(headers[2]), max(len(e.get('username', '')) for e in entries)),
        max(len(headers[3]), max(len(e.get('notes',    '')) for e in entries)),
    ]
    fmt = '  '.join(f'{{:<{c}}}' for c in cols)
    print(fmt.format(*headers))
    print(fmt.format(*('-' * c for c in cols)))
    for e in entries:
        print(fmt.format(e['id'], e.get('entity', ''),
                         e.get('username', ''), e.get('notes', '')))


def cmd_update(vmk: bytes, entry_id: str):
    warn_recovery_file()
    hdr_bytes, _ = read_header()
    raw   = VAULT_FILE.read_bytes()
    vault = read_vault_body(raw, vmk)
    entry = next((e for e in vault['entries'] if e['id'] == entry_id), None)
    if not entry:
        raise ValueError(f'Entry not found: {entry_id}')

    print('\nCurrent values:')
    print(f"  Entity   : {entry.get('entity',   '')}")
    print(f"  Username : {entry.get('username', '')}")
    print(f"  Notes    : {entry.get('notes',    '')}")
    print('\n(Press Enter to keep current value)\n')

    v = input(f"  New entity   [{entry.get('entity',   '')}]: ").strip()
    if v: entry['entity']   = v
    v = input(f"  New username [{entry.get('username', '')}]: ").strip()
    if v: entry['username'] = v
    v = input(f"  New notes    [{entry.get('notes',    '')}]: ").strip()
    if v: entry['notes']    = v

    if input('  Change password? (y/N): ').strip().lower() == 'y':
        while True:
            pw1 = prompt_password('  New password')
            pw2 = prompt_password('  Confirm new password')
            if pw1 == pw2:
                entry['password'] = pw1.decode('utf-8')
                break
            print('  Passwords do not match. Try again.')

    entry['modified'] = datetime.now(timezone.utc).isoformat()
    write_vault(vault, vmk, hdr_bytes)
    print('Entry updated.')


def cmd_remove(vmk: bytes, entry_id: str):
    warn_recovery_file()
    hdr_bytes, _ = read_header()
    raw   = VAULT_FILE.read_bytes()
    vault = read_vault_body(raw, vmk)
    entry = next((e for e in vault['entries'] if e['id'] == entry_id), None)
    if not entry:
        raise ValueError(f'Entry not found: {entry_id}')

    print('\nAbout to delete:')
    print(f"  Entity   : {entry.get('entity',   '')}")
    print(f"  Username : {entry.get('username', '')}")
    print(f"  Notes    : {entry.get('notes',    '')}\n")
    if input("Type 'yes' to confirm: ") != 'yes':
        print('Aborted.')
        return

    vault['entries'] = [e for e in vault['entries'] if e['id'] != entry_id]
    write_vault(vault, vmk, hdr_bytes)
    print('Entry removed.')


def cmd_recover():
    assert_vault()
    print('Enter your recovery key (format: XXXX-XXXX-...-XXXX)')
    rec_raw  = parse_recovery_key(input('Recovery key: ').strip())
    raw      = VAULT_FILE.read_bytes()
    hdr      = unpack_header(raw[:HEADER_SIZE])

    print('Verifying recovery key...', flush=True)
    rec_key  = derive_key(rec_raw, hdr['rec_salt'], b'')
    vmk      = gcm_decrypt(rec_key, hdr['rw_vmk'])
    body     = raw[HEADER_SIZE:]
    vault    = json.loads(gcm_decrypt(vmk, body))   # verify VMK
    print(f"Verified. Vault has {len(vault['entries'])} entries.")

    pw1 = prompt_password('Set new master password')
    check_complexity(pw1)
    pw2 = prompt_password('Confirm new master password')
    if pw1 != pw2:
        raise ValueError('Passwords do not match.')

    bind_str, bind_bytes = get_binding()
    new_prim_salt        = secrets.token_bytes(32)
    new_rec_salt         = secrets.token_bytes(32)

    print('Deriving new key...', flush=True)
    new_prim_key       = derive_key(pw1, new_prim_salt, bind_bytes)
    new_rec_raw, new_rec_fmt = new_recovery_key()
    new_rec_key        = derive_key(new_rec_raw, new_rec_salt, b'')

    new_pw_vmk = gcm_encrypt(new_prim_key, vmk)
    new_rw_vmk = gcm_encrypt(new_rec_key,  vmk)
    new_header = pack_header(new_prim_salt, new_rec_salt,
                             new_pw_vmk, new_rw_vmk, bind_str)

    safe_write(VAULT_FILE, new_header + body)   # body untouched
    write_recovery_file(new_rec_fmt)

    print('\nVault recovered and re-bound to this machine.')
    print('Previous recovery key is now INVALID.')
    warn_recovery_file()


def cmd_security():
    bind_str, _ = get_binding()
    bind_hash   = hashlib.sha256(bind_str.encode()).hexdigest()
    hdr_hint    = '(no vault)'
    if VAULT_FILE.exists():
        _, hdr   = read_header()
        hdr_hint = hdr['bind_hint'] or '(empty)'

    print(textwrap.dedent(f"""
      PWM Security Model (Python Edition)

      CRYPTOGRAPHICALLY PROTECTED
        Vault contents   AES-256-GCM authenticated encryption.
                         Any modification causes auth failure before decryption.
                         AAD b'PWMv2|Eswar the MAD!!' bound to every GCM operation.

        Vault key (VMK)  32-byte random key, never stored in plaintext.
                         Primary path  : Argon2id(len(pw)+pw+binding, prim_salt)
                         Recovery path : Argon2id(recovery_key, rec_salt) — no binding
                         Both paths use independent GCM-wrapped VMK blobs.

        Master password  Prompted via getpass(). Never echoed, never persisted.
                         Held in memory only for duration of command.

        Session          Stateless by default. VMK in process memory only.
                         Dies with process. No disk files, no keyring.

        Entry passwords  In memory only during active command. Not persisted.

        Recovery key     Single-use. Rotates on every -recover.
                         Previous key immediately invalid after rotation.

      NOT PROTECTED
        File existence   cred-store.etm visible on disk. Contents opaque.
        Metadata         Entity names and notes visible in -search output.
        Physical access  Use full-disk encryption (BitLocker / LUKS / FileVault).
        Recovery key     Readable until deleted. Delete immediately after copying.
        Same-user proc   Any process as your user can read clipboard or memory.
        Memory forensics Plaintext in memory during active command. Lifetime minimised.

      KEY DERIVATION
        Algorithm  : Argon2id
        Memory     : 256 MB
        Iterations : 4
        Parallelism: 1
        Input      : struct.pack('>I', len(pw)) + pw + bind_bytes

      HOST BINDING
        Binding string : {bind_str}
        Binding SHA-256: {bind_hash}
        Vault hint     : {hdr_hint}

      VAULT FORMAT
        Version : {FORMAT}
        Cipher  : AES-256-GCM
        Note    : Python edition only. Not compatible with PowerShell edition.

      HEADER LAYOUT (512 bytes)
        Offset   0 : Magic        8 bytes   file type + version detection
        Offset   8 : Version      1 byte    0x01
        Offset   9 : PrimSalt    32 bytes
        Offset  41 : RecSalt     32 bytes
        Offset  73 : PwWrappedVMK 60 bytes  nonce(12)+ct(32)+tag(16)
        Offset 133 : RwWrappedVMK 60 bytes
        Offset 193 : BindMode     1 byte    0x01=default
        Offset 194 : BindHash    32 bytes   SHA-256(bind_v1)
        Offset 226 : BindHint    32 bytes   UTF-8 null-padded
        Offset 258 : Filler     254 bytes   random noise
        Body: self-contained nonce(12) + ciphertext + tag(16)
    """))


def cmd_shell(idle_timeout: int = 5, ttl: int = 30):
    """Unlock once, run multiple commands. Two timers: idle + TTL."""
    try:
        vmk, _, _ = unlock_vault()
    except Exception as e:
        raise SystemExit(f'Unlock failed: {e}')

    print(f"\nVault unlocked.  idle-timeout={idle_timeout}m  ttl={ttl}m")
    print("Type 'help' for commands, 'exit' to quit.\n")

    start_t      = time.monotonic()
    _last_active = [time.monotonic()]   # list so watchdog thread can mutate it

    def _watchdog():
        """Background thread. Fires even while blocked at input() prompt."""
        while True:
            time.sleep(5)
            now = time.monotonic()
            if (now - _last_active[0]) / 60 >= idle_timeout:
                print(f'\n\nIdle timeout ({idle_timeout}m). Locking.')
                os._exit(0)
            if (now - start_t) / 60 >= ttl:
                print(f'\n\nSession TTL ({ttl}m) expired. Locking.')
                os._exit(0)

    threading.Thread(target=_watchdog, daemon=True).start()

    def _touch():
        _last_active[0] = time.monotonic()


    SHELL_HELP = textwrap.dedent("""\
      Commands available in shell:
        list
      search <keyword>
        copy   <id> <password|username>
        add    [entity] [notes]
        update <id>
        remove <id>
        security
        lock / exit / quit
    """)

    while True:
        try:
            line = input('pwm> ').strip()
        except (EOFError, KeyboardInterrupt):
            print('\nLocking.')
            break

        if not line:
            continue

        parts = line.split(None, 2)
        cmd   = parts[0].lower()
        _touch()

        try:
            if cmd in ('exit', 'lock', 'quit'):
                break
            elif cmd == 'help':
                print(SHELL_HELP)
            elif cmd == 'list':
                cmd_list(vmk)
            elif cmd == 'search':
                kw = parts[1] if len(parts) > 1 else input('Keyword: ').strip()
                cmd_search(vmk, kw)
            elif cmd == 'copy':
                # Accept both: "copy <id> <field>" and "copy -id <id> -field <field>"
                rest  = parts[1:]
                eid   = None
                field = None
                i = 0
                while i < len(rest):
                    if rest[i] == '-id' and i + 1 < len(rest):
                        eid = rest[i+1]; i += 2
                    elif rest[i] == '-field' and i + 1 < len(rest):
                        field = rest[i+1]; i += 2
                    elif eid is None:
                        eid = rest[i]; i += 1
                    elif field is None:
                        field = rest[i]; i += 1
                    else:
                        i += 1
                if not eid or not field:
                    print('Usage: copy <id> <password|username>')
                else:
                    cmd_copy(vmk, eid, field)
            elif cmd == 'add':
                entity = parts[1] if len(parts) > 1 else ''
                notes  = parts[2] if len(parts) > 2 else ''
                cmd_add(vmk, entity, notes)
            elif cmd == 'update':
                eid = parts[1] if len(parts) > 1 else input('ID: ').strip()
                cmd_update(vmk, eid)
            elif cmd == 'remove':
                eid = parts[1] if len(parts) > 1 else input('ID: ').strip()
                cmd_remove(vmk, eid)
            elif cmd == 'security':
                cmd_security()
            else:
                print(f"Unknown: '{cmd}'. Type 'help'.")
        except Exception as e:
            print(f'Error: {e}')


def cmd_help():
    print(textwrap.dedent("""\

      PWM — Personal Password Manager (Python Edition)
      AES-256-GCM | Argon2id 256MB/4-iter | Stateless by default

      USAGE:  python pwm.py <command> [options]

      COMMANDS:
        -init                                  Create new vault
        -unlock                                Explicit unlock prefix (optional)
        -shell [--idle-timeout N] [--ttl N]    Interactive mode (default: 5m idle, 30m ttl)
        -add   [-entity <val>] [-notes <val>]  Add credential
        -list                                  List all entries (auto-prompts password)
        -search <keyword>                      Search by entity or notes (auto-prompts password)
        -copy  -id <id> -field <f>             Copy field to clipboard, clears in 30s
        -update -id <id>                       Edit entry
        -remove -id <id>                       Delete entry
        -recover                               Recover vault, re-bind to this machine
        -security                              Show full security model
        -help                                  Show this help

      STATELESS (default — password prompted automatically):
        python pwm.py -search "github"
        python pwm.py -copy -id <id> -field password

      EXPLICIT UNLOCK PREFIX:
        python pwm.py -unlock -add -entity "github.com"

      SHELL MODE (unlock once, multiple commands):
        python pwm.py -shell
        python pwm.py -shell --idle-timeout 3 --ttl 15

      MASTER PASSWORD: 16+ chars | uppercase | lowercase | digit | special char
      VAULT FORMAT   : pwm-v2 | Python edition only | not compatible with PS edition
      DEPENDENCIES   : pip install cryptography argon2-cffi
    """))


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument('-init',          action='store_true')
    parser.add_argument('-unlock',        action='store_true')
    parser.add_argument('-shell',         action='store_true')
    parser.add_argument('-add',           action='store_true')
    parser.add_argument('-search',        type=str, default=None)
    parser.add_argument('-list',           action='store_true')
    parser.add_argument('-copy',          action='store_true')
    parser.add_argument('-update',        action='store_true')
    parser.add_argument('-remove',        action='store_true')
    parser.add_argument('-recover',       action='store_true')
    parser.add_argument('-security',      action='store_true')
    parser.add_argument('-help',          action='store_true')
    parser.add_argument('-entity',        type=str, default='')
    parser.add_argument('-notes',         type=str, default='')
    parser.add_argument('-id',            type=str, default='')
    parser.add_argument('-field',         type=str, default='')
    parser.add_argument('--idle-timeout', type=int, default=5)
    parser.add_argument('--ttl',          type=int, default=30)
    args = parser.parse_args()

    # If -unlock given alongside a vault command, pre-derive VMK once
    # Determine if -unlock is a prefix (paired with a vault command) or standalone
    _vault_cmds = args.add or args.list or (args.search is not None) or args.copy                   or args.update or args.remove

    _pre_vmk = None
    if args.unlock and _vault_cmds:
        # Pre-unlock once -- shared by the vault command that follows
        try:
            _pre_vmk, _, _ = unlock_vault()
        except Exception as e:
            raise SystemExit(f'Unlock failed: {e}')

    def need_vmk() -> bytes:
        """Return pre-unlocked VMK or auto-prompt."""
        return _pre_vmk if _pre_vmk is not None else unlock_vault()[0]

    try:
        if args.help or len(sys.argv) == 1:
            cmd_help()
        elif args.init:
            cmd_init()
        elif args.shell:
            cmd_shell(args.idle_timeout, args.ttl)
        elif args.recover:
            cmd_recover()
        elif args.security:
            cmd_security()
        elif args.add:
            cmd_add(need_vmk(), args.entity, args.notes)
        elif args.list:
            cmd_list(need_vmk())
        elif args.search is not None:
            cmd_search(need_vmk(), args.search)
        elif args.copy:
            if not args.id:    raise ValueError('Specify -id <id>')
            if not args.field: raise ValueError('Specify -field password|username')
            cmd_copy(need_vmk(), args.id, args.field)
        elif args.update:
            if not args.id: raise ValueError('Specify -id <id>')
            cmd_update(need_vmk(), args.id)
        elif args.remove:
            if not args.id: raise ValueError('Specify -id <id>')
            cmd_remove(need_vmk(), args.id)
        elif args.unlock:
            # Standalone -unlock: verify credentials only, single prompt
            unlock_vault()
            print('Credentials verified.')
        else:
            cmd_help()

    except (KeyboardInterrupt, EOFError):
        print('\nAborted.')
        sys.exit(1)
    except SystemExit:
        raise
    except Exception as e:
        try: _clip_set('')
        except Exception: pass
        print(f'Error: {e}')
        sys.exit(1)


if __name__ == '__main__':
    main()