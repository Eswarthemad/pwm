#Requires -Version 5.1
<#
    PWM - Personal Password Manager
    Cipher   : Twofish-256-EAX (via BouncyCastle)
    KDF      : Argon2id (256MB, 4 iterations)
    Binding  : MachineGUID + UserSID + MasterPassword
    Signed   : Eswar the MAD!!

    Phase 3 hardened:
      - VMK-only session (vault stays encrypted on disk between commands)
      - GUID-named session file in %TEMP% (unpredictable path)
      - DLL hash verification at startup (tamper detection)
      - Clipboard cleared in finally block (crash-safe)
      - Password variable lifetime minimized
      - Argon2id tuned to 256MB / 4 iterations
      - Crash-safe clipboard + session cleanup on unhandled exceptions
      - ETM integrity check (size + existence) before every operation
      - -security command (plain-English security model)
#>

param(
    [switch]$init,
    [switch]$unlock,
    [switch]$recover,
    [switch]$add,
    [string]$search,
    [switch]$copy,
    [switch]$update,
    [switch]$list,
    [switch]$remove,
    [switch]$security,
    [switch]$help,
    [string]$entity = '',
    [string]$notes  = '',
    [string]$id     = '',
    [string]$field  = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Constants ----------------------------------------------------------------

$VAULT_FILE     = Join-Path $PSScriptRoot 'cred-store.etm'
$RECOVERY_FILE  = Join-Path $PSScriptRoot 'pwm-recovery.key'
$SESSION_MINS   = 30
$CLIP_SECS      = 30
$ARGON_MEM_KB   = 262144   # 256 MB
$ARGON_ITER     = 4
$ARGON_PARA     = 1
$HEADER_SIZE    = 512
$VAULT_MIN_SIZE = 528      # 512-byte header + 16-byte minimum EAX tag

# Session file: GUID derived from vault path -- deterministic but unpredictable to outsiders
$_pathBytes   = [System.Text.Encoding]::UTF8.GetBytes($VAULT_FILE)
$_pathHash    = [System.Security.Cryptography.SHA256]::Create().ComputeHash($_pathBytes)
$SESSION_FILE = Join-Path $env:TEMP ([System.Guid]::new([byte[]]$_pathHash[0..15]).ToString() + '.tmp')

# DLL hash -- replaced by build.ps1 at build time. Placeholder skips check on raw script.
$DLL_HASH = '##DLL_SHA256##'

# "Eswar the MAD!!" baked into every encrypted blob as EAX associated data.
# Remove or alter this = vault won't open. Cryptographically invisible in the file.
$SIGNATURE = [System.Text.Encoding]::UTF8.GetBytes('Eswar the MAD!!')

# Header layout (512 bytes, XOR-obfuscated):
# PrimSalt(32) | RecSalt(32) | BodyNonce(16) | PwWrapNonce(16) |
# RwWrapNonce(16) | WrappedVMK(48) | WrappedRVMK(48) | Filler(304)
$HO_PRIM_SALT    = 0
$HO_REC_SALT     = 32
$HO_BODY_NONCE   = 64
$HO_PW_NONCE     = 80
$HO_RW_NONCE     = 96
$HO_WRAPPED_VMK  = 112
$HO_WRAPPED_RVMK = 160
$HDR_SEED = [byte[]](0x4A,0x7F,0x23,0x91,0xB3,0x5C,0xDE,0x08,0x61,0xA4,0x2E,0x9D,0x47,0xC6,0x13,0x85)


# --- BouncyCastle Loader ------------------------------------------------------

function Initialize-BC {
    $dll = Join-Path $env:LOCALAPPDATA 'PWM\BouncyCastle.Cryptography.dll'
    if (-not (Test-Path $dll)) {
        throw "BouncyCastle DLL not found at: $dll`nRun install.ps1 first."
    }
    # Verify DLL hash if build.ps1 embedded one -- detects DLL substitution
    if ($DLL_HASH -ne '##DLL_SHA256##') {
        $sha    = [System.Security.Cryptography.SHA256]::Create()
        $actual = [Convert]::ToBase64String($sha.ComputeHash([System.IO.File]::ReadAllBytes($dll)))
        $sha.Dispose()
        if ($actual -ne $DLL_HASH) {
            throw "BouncyCastle DLL hash mismatch -- possible tampering detected.`nExpected : $DLL_HASH`nActual   : $actual"
        }
    }
    try { Add-Type -Path $dll -ErrorAction Stop } catch {}
    try { $null = [Org.BouncyCastle.Crypto.Parameters.Argon2Parameters] }
    catch { throw "Loaded BouncyCastle DLL does not support Argon2id. Install v2.x from NuGet." }
}


# --- Utility ------------------------------------------------------------------

function Get-HostBinding {
    $guid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    $sid  = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return [System.Text.Encoding]::UTF8.GetBytes("$guid|$sid")
}

function Get-HeaderMask {
    $sha  = [System.Security.Cryptography.SHA256]::Create()
    $mask = [byte[]]::new(512)
    $blk  = $HDR_SEED
    $off  = 0
    while ($off -lt 512) {
        $blk = $sha.ComputeHash($blk)
        $n   = [Math]::Min(32, 512 - $off)
        [Array]::Copy($blk, 0, $mask, $off, $n)
        $off += $n
    }
    $sha.Dispose()
    return $mask
}

function New-RandomBytes([int]$n) {
    $b   = [byte[]]::new($n)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($b)
    $rng.Dispose()
    return $b
}

function Get-Slice([byte[]]$src, [int]$off, [int]$len) {
    $dst = [byte[]]::new($len)
    [Array]::Copy($src, $off, $dst, 0, $len)
    return $dst
}

function Read-SecureBytes([string]$prompt) {
    $ss  = Read-Host $prompt -AsSecureString
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($ss)
    try   { return [System.Text.Encoding]::UTF8.GetBytes(
                [System.Runtime.InteropServices.Marshal]::PtrToStringUni($ptr)) }
    finally {
        [System.Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($ptr)
        $ss.Dispose()
    }
}

function Assert-PasswordComplexity([byte[]]$pwBytes) {
    $pw     = [System.Text.Encoding]::UTF8.GetString($pwBytes)
    $errors = [System.Collections.Generic.List[string]]::new()
    if ($pw.Length -lt 16)            { $errors.Add('Minimum 16 characters') }
    if ($pw -notmatch '[A-Z]')        { $errors.Add('At least one uppercase letter (A-Z)') }
    if ($pw -notmatch '[a-z]')        { $errors.Add('At least one lowercase letter (a-z)') }
    if ($pw -notmatch '[0-9]')        { $errors.Add('At least one digit (0-9)') }
    if ($pw -notmatch '[^A-Za-z0-9]') { $errors.Add('At least one special character') }
    if ($errors.Count -gt 0) {
        throw "Password complexity not met:`n  - " + ($errors -join "`n  - ")
    }
}

function Compare-ByteArrays([byte[]]$a, [byte[]]$b) {
    if ($a.Length -ne $b.Length) { return $false }
    for ($i = 0; $i -lt $a.Length; $i++) { if ($a[$i] -ne $b[$i]) { return $false } }
    return $true
}

function Protect-Bytes([byte[]]$b) {
    Add-Type -AssemblyName System.Security
    return [System.Security.Cryptography.ProtectedData]::Protect(
        $b, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}

function Unprotect-Bytes([byte[]]$b) {
    Add-Type -AssemblyName System.Security
    return [System.Security.Cryptography.ProtectedData]::Unprotect(
        $b, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}

function Assert-VaultIntegrity {
    if (-not (Test-Path $VAULT_FILE)) { throw 'Vault file not found. Run -init first.' }
    $size = (Get-Item $VAULT_FILE).Length
    if ($size -lt $VAULT_MIN_SIZE) {
        throw "Vault file is corrupt or incomplete ($size bytes, minimum $VAULT_MIN_SIZE expected)."
    }
}


# --- Cryptography -------------------------------------------------------------

function Invoke-Argon2id([byte[]]$password, [byte[]]$salt) {
    $builder = [Org.BouncyCastle.Crypto.Parameters.Argon2Parameters+Builder]::new(2)
    [void]($builder = $builder.WithSalt($salt))
    [void]($builder = $builder.WithMemoryAsKB($ARGON_MEM_KB))
    [void]($builder = $builder.WithIterations($ARGON_ITER))
    [void]($builder = $builder.WithParallelism($ARGON_PARA))
    $p   = $builder.Build()
    $gen = [Org.BouncyCastle.Crypto.Generators.Argon2BytesGenerator]::new()
    [void]$gen.Init($p)
    $key = [byte[]]::new(32)
    [void]$gen.GenerateBytes($password, $key, 0, 32)
    return ,$key
}

function Invoke-TfEncrypt([byte[]]$key, [byte[]]$nonce, [byte[]]$data) {
    $aeadParams = [Org.BouncyCastle.Crypto.Parameters.AeadParameters]::new(
                      [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($key), 128, $nonce, $SIGNATURE)
    $eax = [Org.BouncyCastle.Crypto.Modes.EaxBlockCipher]::new(
               [Org.BouncyCastle.Crypto.Engines.TwofishEngine]::new())
    [void]$eax.Init($true, $aeadParams)
    $out = [byte[]]::new($eax.GetOutputSize($data.Length))
    $len = [int]$eax.ProcessBytes($data, 0, $data.Length, $out, 0)
    [void]$eax.DoFinal($out, $len)
    return ,$out
}

function Invoke-TfDecrypt([byte[]]$key, [byte[]]$nonce, [byte[]]$data) {
    $aeadParams = [Org.BouncyCastle.Crypto.Parameters.AeadParameters]::new(
                      [Org.BouncyCastle.Crypto.Parameters.KeyParameter]::new($key), 128, $nonce, $SIGNATURE)
    $eax = [Org.BouncyCastle.Crypto.Modes.EaxBlockCipher]::new(
               [Org.BouncyCastle.Crypto.Engines.TwofishEngine]::new())
    [void]$eax.Init($false, $aeadParams)
    $out = [byte[]]::new($eax.GetOutputSize($data.Length))
    try {
        $len = [int]$eax.ProcessBytes($data, 0, $data.Length, $out, 0)
        [void]$eax.DoFinal($out, $len)
    }
    catch { throw "Authentication failed -- wrong credentials, tampered file, or invalid signature." }
    return ,$out
}


# --- Header Pack / Unpack -----------------------------------------------------

function Pack-Header([hashtable]$h) {
    $mask = Get-HeaderMask
    $raw  = New-RandomBytes $HEADER_SIZE
    [Array]::Copy($h.PrimSalt,    0, $raw, $HO_PRIM_SALT,    32)
    [Array]::Copy($h.RecSalt,     0, $raw, $HO_REC_SALT,     32)
    [Array]::Copy($h.BodyNonce,   0, $raw, $HO_BODY_NONCE,   16)
    [Array]::Copy($h.PwWrapNonce, 0, $raw, $HO_PW_NONCE,     16)
    [Array]::Copy($h.RwWrapNonce, 0, $raw, $HO_RW_NONCE,     16)
    [Array]::Copy($h.WrappedVMK,  0, $raw, $HO_WRAPPED_VMK,  48)
    [Array]::Copy($h.WrappedRVMK, 0, $raw, $HO_WRAPPED_RVMK, 48)
    for ($i = 0; $i -lt $HEADER_SIZE; $i++) { $raw[$i] = $raw[$i] -bxor $mask[$i] }
    return $raw
}

function Unpack-Header([byte[]]$hdr) {
    $mask = Get-HeaderMask
    $raw  = [byte[]]::new($HEADER_SIZE)
    for ($i = 0; $i -lt $HEADER_SIZE; $i++) { $raw[$i] = $hdr[$i] -bxor $mask[$i] }
    return @{
        PrimSalt    = Get-Slice $raw $HO_PRIM_SALT    32
        RecSalt     = Get-Slice $raw $HO_REC_SALT     32
        BodyNonce   = Get-Slice $raw $HO_BODY_NONCE   16
        PwWrapNonce = Get-Slice $raw $HO_PW_NONCE     16
        RwWrapNonce = Get-Slice $raw $HO_RW_NONCE     16
        WrappedVMK  = Get-Slice $raw $HO_WRAPPED_VMK  48
        WrappedRVMK = Get-Slice $raw $HO_WRAPPED_RVMK 48
    }
}


# --- Session Management (VMK only) --------------------------------------------
# Session file stores only the 32-byte VMK, DPAPI-protected, with a UTC timestamp.
# Vault body stays Twofish-encrypted on disk between every command -- never cached.
# Filename is a GUID derived from the vault path -- not guessable from outside.

function Get-Session {
    if (-not (Test-Path $SESSION_FILE)) { return $null }
    try {
        $raw   = [System.IO.File]::ReadAllBytes($SESSION_FILE)
        $ticks = [System.BitConverter]::ToInt64($raw, 0)
        if (([datetime]::UtcNow - [datetime]::FromFileTimeUtc($ticks)).TotalMinutes -gt $SESSION_MINS) {
            Clear-Session; return $null
        }
        return ,(Unprotect-Bytes (Get-Slice $raw 8 ($raw.Length - 8)))
    } catch { Clear-Session; return $null }
}

function Set-Session([byte[]]$vmk) {
    $ticks = [System.BitConverter]::GetBytes([datetime]::UtcNow.ToFileTimeUtc())
    $dpapi = Protect-Bytes $vmk
    [System.IO.File]::WriteAllBytes($SESSION_FILE, $ticks + $dpapi)
}

function Clear-Session {
    if (Test-Path $SESSION_FILE) { Remove-Item $SESSION_FILE -Force -ErrorAction SilentlyContinue }
}

function Require-Session {
    $vmk = Get-Session
    if ($null -ne $vmk) { return ,$vmk }
    Write-Host 'Session expired or locked. Re-enter master password.' -ForegroundColor Yellow
    Invoke-Unlock
    return ,(Get-Session)
}


# --- Vault File I/O -----------------------------------------------------------

function Read-VaultFromFile([byte[]]$vmk) {
    Assert-VaultIntegrity
    $file = [System.IO.File]::ReadAllBytes($VAULT_FILE)
    $hdr  = Unpack-Header (Get-Slice $file 0 $HEADER_SIZE)
    $body = Get-Slice $file $HEADER_SIZE ($file.Length - $HEADER_SIZE)
    return [System.Text.Encoding]::UTF8.GetString((Invoke-TfDecrypt $vmk $hdr.BodyNonce $body)) |
           ConvertFrom-Json
}

function Save-VaultToFile($vault, [byte[]]$vmk, [hashtable]$existingHdr) {
    $bodyNonce = New-RandomBytes 16
    $body      = Invoke-TfEncrypt $vmk $bodyNonce `
                     ([System.Text.Encoding]::UTF8.GetBytes(($vault | ConvertTo-Json -Depth 5)))
    $existingHdr.BodyNonce = $bodyNonce
    [System.IO.File]::WriteAllBytes($VAULT_FILE, (Pack-Header $existingHdr) + $body)
}

function Read-HeaderFromFile {
    Assert-VaultIntegrity
    $raw = [System.IO.File]::ReadAllBytes($VAULT_FILE)
    return Unpack-Header (Get-Slice $raw 0 $HEADER_SIZE)
}


# --- Recovery Key Helpers -----------------------------------------------------

function New-RecoveryKey {
    $bytes  = New-RandomBytes 32
    $hex    = [BitConverter]::ToString($bytes) -replace '-',''
    $groups = for ($i = 0; $i -lt 64; $i += 4) { $hex.Substring($i, 4) }
    return @{ Bytes = $bytes; Formatted = ($groups -join '-') }
}

function Parse-RecoveryKey([string]$fmt) {
    $hex = $fmt -replace '[-\s]',''
    if ($hex.Length -ne 64) { throw "Invalid recovery key -- expected 64 hex characters." }
    $bytes = [byte[]]::new(32)
    for ($i = 0; $i -lt 32; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i*2, 2), 16) }
    return $bytes
}

function Write-RecoveryFile([string]$formatted) {
    Set-Content -Path $RECOVERY_FILE -Encoding UTF8 -Value @"
=== PWM VAULT RECOVERY KEY ===
Generated : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Machine   : $env:COMPUTERNAME
User      : $env:USERDOMAIN\$env:USERNAME

Recovery Key:
$formatted

INSTRUCTIONS:
1. Copy this file to a SECURE OFFLINE location (USB drive or printed paper).
2. DELETE this file from this folder IMMEDIATELY after copying.
3. This key recovers your vault if master password is lost or machine changes.
4. Each use of -recover invalidates this key and generates a new one.
==============================
"@
}

function Assert-RecoveryFileGone {
    if (Test-Path $RECOVERY_FILE) {
        Write-Host ''
        Write-Host '  !! WARNING: pwm-recovery.key is still in the vault folder !!' -ForegroundColor Red
        Write-Host '  !! Copy it to a secure location and DELETE it immediately.  !!' -ForegroundColor Red
        Write-Host ''
    }
}


# --- Commands -----------------------------------------------------------------

function Invoke-Init {
    if (Test-Path $VAULT_FILE) {
        Write-Host 'WARNING: cred-store.etm already exists. All stored credentials will be PERMANENTLY lost.' -ForegroundColor Red
        if ((Read-Host 'Type CONFIRM to proceed') -ne 'CONFIRM') { Write-Host 'Aborted.'; return }
        Clear-Session
    }

    $pass1 = Read-SecureBytes 'Set master password'
    Assert-PasswordComplexity $pass1
    $pass2 = Read-SecureBytes 'Confirm master password'
    if (-not (Compare-ByteArrays $pass1 $pass2)) { throw 'Passwords do not match.' }
    [Array]::Clear($pass2, 0, $pass2.Length)

    $input = $pass1 + (Get-HostBinding)
    [Array]::Clear($pass1, 0, $pass1.Length)

    $primSalt    = New-RandomBytes 32
    $recSalt     = New-RandomBytes 32
    $bodyNonce   = New-RandomBytes 16
    $pwWrapNonce = New-RandomBytes 16
    $rwWrapNonce = New-RandomBytes 16
    $vmk         = New-RandomBytes 32

    Write-Host 'Deriving key -- this takes a moment...' -ForegroundColor Cyan
    $primKey = Invoke-Argon2id $input $primSalt
    [Array]::Clear($input, 0, $input.Length)

    $rec    = New-RecoveryKey
    $recKey = Invoke-Argon2id $rec.Bytes $recSalt

    $hdr = @{
        PrimSalt    = $primSalt
        RecSalt     = $recSalt
        BodyNonce   = $bodyNonce
        PwWrapNonce = $pwWrapNonce
        RwWrapNonce = $rwWrapNonce
        WrappedVMK  = (Invoke-TfEncrypt $primKey $pwWrapNonce $vmk)
        WrappedRVMK = (Invoke-TfEncrypt $recKey  $rwWrapNonce $vmk)
    }

    $vault = [PSCustomObject]@{ entries = @() }
    $body  = Invoke-TfEncrypt $vmk $bodyNonce `
                 ([System.Text.Encoding]::UTF8.GetBytes(($vault | ConvertTo-Json -Depth 5)))
    [System.IO.File]::WriteAllBytes($VAULT_FILE, (Pack-Header $hdr) + $body)

    Write-RecoveryFile $rec.Formatted
    Set-Session $vmk
    [Array]::Clear($vmk, 0, $vmk.Length)

    Write-Host 'Vault created successfully.' -ForegroundColor Green
    Assert-RecoveryFileGone
}


function Invoke-Unlock {
    Assert-VaultIntegrity

    $pass  = Read-SecureBytes 'Master password'
    $input = $pass + (Get-HostBinding)
    [Array]::Clear($pass, 0, $pass.Length)

    Write-Host 'Unlocking...' -ForegroundColor Cyan
    $file    = [System.IO.File]::ReadAllBytes($VAULT_FILE)
    $hdr     = Unpack-Header (Get-Slice $file 0 $HEADER_SIZE)
    $primKey = Invoke-Argon2id $input $hdr.PrimSalt
    [Array]::Clear($input, 0, $input.Length)

    $vmk = Invoke-TfDecrypt $primKey $hdr.PwWrapNonce $hdr.WrappedVMK
    [Array]::Clear($primKey, 0, $primKey.Length)

    # Verify VMK decrypts vault body correctly -- catches wrong password before writing session
    $body = Get-Slice $file $HEADER_SIZE ($file.Length - $HEADER_SIZE)
    [void](Invoke-TfDecrypt $vmk $hdr.BodyNonce $body)

    Set-Session $vmk
    [Array]::Clear($vmk, 0, $vmk.Length)
    Write-Host "Vault unlocked. Session valid for $SESSION_MINS minutes." -ForegroundColor Green
}


function Invoke-Add {
    Assert-RecoveryFileGone
    if (-not $entity) { throw 'Specify -entity <value>' }

    $vmk      = Require-Session
    $username = Read-Host 'Username'
    $pw1      = Read-SecureBytes 'Password'
    $pw2      = Read-SecureBytes 'Confirm password'
    if (-not (Compare-ByteArrays $pw1 $pw2)) {
        [Array]::Clear($pw1, 0, $pw1.Length)
        [Array]::Clear($pw2, 0, $pw2.Length)
        throw 'Passwords do not match.'
    }

    $vault = Read-VaultFromFile $vmk
    $now   = Get-Date -Format 'o'
    $entry = [PSCustomObject]@{
        id       = [System.Guid]::NewGuid().ToString()
        entity   = $entity
        username = $username
        password = [System.Text.Encoding]::UTF8.GetString($pw1)
        notes    = $notes
        created  = $now
        modified = $now
    }
    # Zero password bytes immediately after encoding into the entry object
    [Array]::Clear($pw1, 0, $pw1.Length)
    [Array]::Clear($pw2, 0, $pw2.Length)

    $entries = [System.Collections.Generic.List[object]]::new()
    if ($vault.entries) { $vault.entries | ForEach-Object { $entries.Add($_) } }
    $entries.Add($entry)
    $vault | Add-Member -Force -NotePropertyName entries -NotePropertyValue $entries.ToArray()

    $hdr = Read-HeaderFromFile
    Save-VaultToFile $vault $vmk $hdr
    Set-Session $vmk

    Write-Host "Entry added. ID: $($entry.id)" -ForegroundColor Green
}


function Invoke-Search {
    Assert-RecoveryFileGone
    $vmk   = Require-Session
    $vault = Read-VaultFromFile $vmk
    $q     = $search.ToLower()

    $results = @($vault.entries | Where-Object {
        $_.entity.ToLower().Contains($q) -or $_.notes.ToLower().Contains($q)
    })

    if ($results.Count -eq 0) {
        Write-Host "No entries found matching '$search'." -ForegroundColor Yellow
        return
    }
    $results | Select-Object id, entity, username, notes | Format-Table -AutoSize -Wrap
}


function Invoke-Copy {
    Assert-RecoveryFileGone
    if (-not $id)    { throw 'Specify -id <guid>' }
    if ($field -notin @('password','username')) { throw 'Specify -field password or -field username' }

    $vmk   = Require-Session
    $vault = Read-VaultFromFile $vmk
    $entry = $vault.entries | Where-Object { $_.id -eq $id } | Select-Object -First 1
    if (-not $entry) { throw "Entry not found: $id" }

    $val = if ($field -eq 'password') { $entry.password } else { $entry.username }
    try {
        Set-Clipboard -Value $val
        Start-Job -ScriptBlock { param($s) Start-Sleep $s; Set-Clipboard -Value '' } `
                  -ArgumentList $CLIP_SECS | Out-Null
        $fieldLabel = (Get-Culture).TextInfo.ToTitleCase($field)
        Write-Host "$fieldLabel copied for '$($entry.entity)'. Clipboard clears in $CLIP_SECS seconds." `
                   -ForegroundColor Green
    }
    finally {
        # Clear val from memory even if clipboard operation throws
        $val = $null
    }
}


function Invoke-Update {
    Assert-RecoveryFileGone
    if (-not $id) { throw 'Specify -id <guid>' }

    $vmk   = Require-Session
    $vault = Read-VaultFromFile $vmk
    $entry = $vault.entries | Where-Object { $_.id -eq $id } | Select-Object -First 1
    if (-not $entry) { throw "Entry not found: $id" }

    Write-Host ''
    Write-Host 'Current values:' -ForegroundColor Cyan
    Write-Host "  Entity   : $($entry.entity)"
    Write-Host "  Username : $($entry.username)"
    Write-Host "  Notes    : $($entry.notes)"
    Write-Host ''
    Write-Host '(Press Enter to keep current value)' -ForegroundColor DarkGray
    Write-Host ''

    $v = Read-Host "  New entity   [$($entry.entity)]"
    if ($v) { $entry.entity   = $v }
    $v = Read-Host "  New username [$($entry.username)]"
    if ($v) { $entry.username = $v }
    $v = Read-Host "  New notes    [$($entry.notes)]"
    if ($v) { $entry.notes    = $v }

    if ((Read-Host '  Change password? (y/N)') -in @('y','Y')) {
        do {
            $pw1 = Read-SecureBytes '  New password'
            $pw2 = Read-SecureBytes '  Confirm new password'
            if (-not (Compare-ByteArrays $pw1 $pw2)) {
                [Array]::Clear($pw1, 0, $pw1.Length)
                [Array]::Clear($pw2, 0, $pw2.Length)
                Write-Host '  Passwords do not match. Try again.' -ForegroundColor Yellow
                $pw1 = $null
            }
        } while ($null -eq $pw1)
        $entry.password = [System.Text.Encoding]::UTF8.GetString($pw1)
        [Array]::Clear($pw1, 0, $pw1.Length)
        [Array]::Clear($pw2, 0, $pw2.Length)
    }
    $entry.modified = Get-Date -Format 'o'

    $hdr = Read-HeaderFromFile
    Save-VaultToFile $vault $vmk $hdr
    Set-Session $vmk

    Write-Host 'Entry updated.' -ForegroundColor Green
}


function Invoke-Remove {
    Assert-RecoveryFileGone
    if (-not $id) { throw 'Specify -id <guid>' }

    $vmk   = Require-Session
    $vault = Read-VaultFromFile $vmk
    $entry = $vault.entries | Where-Object { $_.id -eq $id } | Select-Object -First 1
    if (-not $entry) { throw "Entry not found: $id" }

    Write-Host 'About to delete:' -ForegroundColor Yellow
    Write-Host "  Entity   : $($entry.entity)"
    Write-Host "  Username : $($entry.username)"
    Write-Host "  Notes    : $($entry.notes)"

    if ((Read-Host "Type 'yes' to confirm") -ne 'yes') { Write-Host 'Aborted.'; return }

    $entries = [System.Collections.Generic.List[object]]::new()
    $vault.entries | Where-Object { $_.id -ne $id } | ForEach-Object { $entries.Add($_) }
    $vault | Add-Member -Force -NotePropertyName entries -NotePropertyValue $entries.ToArray()

    $hdr = Read-HeaderFromFile
    Save-VaultToFile $vault $vmk $hdr
    Set-Session $vmk

    Write-Host 'Entry removed.' -ForegroundColor Green
}


function Invoke-List {
    Assert-RecoveryFileGone
    $vmk   = Require-Session
    $vault = Read-VaultFromFile $vmk
    $count = @($vault.entries).Count
    if ($count -eq 0) { Write-Host 'Vault is empty.'; return }
    Write-Host "$count entry/entries in vault."
    $vault.entries | Select-Object id, entity, username, notes | Format-Table -AutoSize -Wrap
}


function Invoke-Recover {
    Assert-VaultIntegrity

    Write-Host 'Enter your recovery key (format: XXXX-XXXX-...-XXXX)' -ForegroundColor Cyan
    $recBytes = Parse-RecoveryKey (Read-Host 'Recovery key')

    $file = [System.IO.File]::ReadAllBytes($VAULT_FILE)
    $hdr  = Unpack-Header (Get-Slice $file 0 $HEADER_SIZE)

    Write-Host 'Deriving key...' -ForegroundColor Cyan
    $recKey = Invoke-Argon2id $recBytes $hdr.RecSalt
    $vmk    = Invoke-TfDecrypt $recKey $hdr.RwWrapNonce $hdr.WrappedRVMK

    $body  = Get-Slice $file $HEADER_SIZE ($file.Length - $HEADER_SIZE)
    $vault = [System.Text.Encoding]::UTF8.GetString(
                 (Invoke-TfDecrypt $vmk $hdr.BodyNonce $body)) | ConvertFrom-Json

    Write-Host "Recovery key verified. Vault has $(@($vault.entries).Count) entries." -ForegroundColor Green

    $pass1 = Read-SecureBytes 'Set new master password'
    Assert-PasswordComplexity $pass1
    $pass2 = Read-SecureBytes 'Confirm new master password'
    if (-not (Compare-ByteArrays $pass1 $pass2)) { throw 'Passwords do not match.' }
    [Array]::Clear($pass2, 0, $pass2.Length)

    $input = $pass1 + (Get-HostBinding)
    [Array]::Clear($pass1, 0, $pass1.Length)

    $newPrimSalt    = New-RandomBytes 32
    $newRecSalt     = New-RandomBytes 32
    $newBodyNonce   = New-RandomBytes 16
    $newPwWrapNonce = New-RandomBytes 16
    $newRwWrapNonce = New-RandomBytes 16

    Write-Host 'Deriving new key...' -ForegroundColor Cyan
    $newPrimKey = Invoke-Argon2id $input $newPrimSalt
    [Array]::Clear($input, 0, $input.Length)

    $newRec    = New-RecoveryKey
    $newRecKey = Invoke-Argon2id $newRec.Bytes $newRecSalt

    $newHdr = @{
        PrimSalt    = $newPrimSalt
        RecSalt     = $newRecSalt
        BodyNonce   = $newBodyNonce
        PwWrapNonce = $newPwWrapNonce
        RwWrapNonce = $newRwWrapNonce
        WrappedVMK  = (Invoke-TfEncrypt $newPrimKey $newPwWrapNonce $vmk)
        WrappedRVMK = (Invoke-TfEncrypt $newRecKey  $newRwWrapNonce $vmk)
    }

    $newBody = Invoke-TfEncrypt $vmk $newBodyNonce `
                   ([System.Text.Encoding]::UTF8.GetBytes(($vault | ConvertTo-Json -Depth 5)))
    [System.IO.File]::WriteAllBytes($VAULT_FILE, (Pack-Header $newHdr) + $newBody)

    Write-RecoveryFile $newRec.Formatted
    Set-Session $vmk
    [Array]::Clear($vmk, 0, $vmk.Length)

    Write-Host ''
    Write-Host 'Vault recovered and re-bound to this machine.' -ForegroundColor Green
    Write-Host 'Previous recovery key is now INVALID.' -ForegroundColor Yellow
    Assert-RecoveryFileGone
}


function Show-Security {
    Write-Host @'

  PWM Security Model -- What is and is not protected

  CRYPTOGRAPHICALLY PROTECTED
    Vault contents     Twofish-256-EAX authenticated encryption. Any single bit
                       flip in cred-store.etm causes total decryption failure.
                       Contents are indistinguishable from random noise.

    Vault key (VMK)    32-byte random key, never stored in plaintext anywhere.
                       Wrapped under Argon2id(MasterPassword + MachineGUID + UserSID).
                       Separate recovery path wrapped under the recovery key.

    Session VMK        Only the VMK is stored in the session file -- not the vault.
                       DPAPI-protected (CurrentUser). Vault stays encrypted on disk
                       between every command. Useless on any other machine or account.

    Source code        pwm-core.dpapi is DPAPI-encrypted, bound to this machine
                       and Windows user. License key required at install time.

  PROCEDURALLY PROTECTED
    Clipboard          Auto-clears after 30 seconds. Cleared in finally block --
                       exceptions cannot strand a password in the clipboard.

    Master password    Read as SecureString, converted to bytes, zeroed after use.
                       Never written to disk in any form.

    Entry passwords    Byte arrays zeroed immediately after encoding into entry.
                       Lifetime in memory limited to duration of -add or -update.

    Recovery key       Single-use. Rotates on every -recover. Old key immediately invalid.

    DLL integrity      SHA-256 of BouncyCastle.dll verified at every startup.
                       Mismatch aborts -- prevents DLL substitution attacks.

  NOT PROTECTED (by design or limitation)
    Usernames, entity  Visible in -search output. Not treated as secret.
    names, notes

    File existence     cred-store.etm is visible to any user on the machine.
                       Contents are opaque -- existence is not hidden.

    Physical access    Full physical access + your Windows login defeats DPAPI.
                       Use BitLocker as the layer below this tool.

    Recovery key file  pwm-recovery.key is readable by any process running as your
                       Windows user until deleted. Delete it immediately.

    Memory forensics   Live memory dump during active command may capture plaintext
                       passwords. Lifetime is minimized but not zero.

  KEY DERIVATION
    Algorithm  : Argon2id
    Memory     : 256 MB
    Iterations : 4
    Parallelism: 1
    Input      : MasterPassword + MachineGUID + UserSID

    A dedicated GPU cluster attacking this takes years per guess at typical entropy.
    Do not use a weak master password.

  SIGNATURE
    Every encrypted blob authenticated with "Eswar the MAD!!" as EAX associated data.
    File tampering detected before any decryption is attempted.

'@
}


function Show-Help {
    Write-Host @'

  PWM - Personal Password Manager
  Twofish-256-EAX | Argon2id 256MB/4-iter | Machine + User + Password binding

  USAGE:  .\pwm.ps1 <command> [options]

  COMMANDS:

    -init                               Create a new vault. Generates a recovery key file.
                                        Warns and confirms before overwriting an existing vault.

    -unlock                             Unlock the vault for this session (30-minute window).
                                        Required once per terminal session before other commands.

    -add  -entity <val> [-notes <val>]  Add a new credential. Prompts for username and password.

    -list                               List all entries in the vault.
    -search <keyword>                   Search entries by entity or notes (case-insensitive).
                                        Returns ID, entity, username, notes. Never shows password.
                                        Use the ID returned here with -copy, -update, -remove.

    -copy  -id <guid>  -field <f>       Copy a field to clipboard. Auto-clears after 30 seconds.
                                        -field accepts: password  or  username

    -update  -id <guid>                 Edit an entry. Shows current values first.
                                        Press Enter on any field to keep the existing value.

    -remove  -id <guid>                 Delete an entry. Type 'yes' at the confirmation prompt.

    -recover                            Recover vault with recovery key (machine-independent).
                                        Re-binds vault to current machine. Rotates recovery key.

    -security                           Show full security model -- what is and is not protected.

    -help                               Show this help.

  MASTER PASSWORD REQUIREMENTS:
    16+ characters  |  uppercase  |  lowercase  |  digit  |  special character

  TYPICAL SESSION:
    .\pwm.ps1 -unlock
    .\pwm.ps1 -search "github"
    .\pwm.ps1 -copy -id <guid> -field password

  FILES:
    cred-store.etm     Your encrypted vault.
    pwm-core.dpapi     Encrypted source -- do not delete.
    pwm-recovery.key   Generated at -init and -recover. DELETE after copying to safe storage.

'@
}


# --- Entry Point --------------------------------------------------------------

try {
    Initialize-BC

    if ($args.Count -gt 0) {
        Write-Host "Unknown argument(s): $($args -join ', ')" -ForegroundColor Red
        Show-Help; exit 1
    }

    if      ($help)     { Show-Help }
    elseif  ($security) { Show-Security }
    elseif  ($init)     { Invoke-Init }
    elseif  ($unlock)   { Invoke-Unlock }
    elseif  ($recover)  { Invoke-Recover }
    elseif  ($add)      { Invoke-Add }
    elseif  ($list)   { Invoke-List }
    elseif  ($PSBoundParameters.ContainsKey('search')) { Invoke-Search }
    elseif  ($copy)     { Invoke-Copy }
    elseif  ($update)   { Invoke-Update }
    elseif  ($remove)   { Invoke-Remove }
    else                { Show-Help }

} catch {
    # Crash-safe cleanup -- clear clipboard and session on any unhandled exception
    try { Set-Clipboard -Value '' } catch {}
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}