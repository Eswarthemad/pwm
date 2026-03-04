#Requires -Version 5.1
<#
    PWM - Personal Password Manager (Server Edition)
    Cipher   : AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
    KDF      : PBKDF2-HMAC-SHA256 (100,000 iterations, manual for .NET 4.0 compat)
    Binding  : MachineGUID + UserSID + MasterPassword
    Signed   : Eswar the MAD!!
    Requires : PowerShell 5.1 / .NET Framework 4.0 -- zero external dependencies
#>

param(
    [switch]$init,
    [switch]$unlock,
    [switch]$recover,
    [switch]$add,
    [string]$search,
    [switch]$copy,
    [switch]$update,
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
$PBKDF2_ITER    = 100000
$HEADER_SIZE    = 512
$VAULT_MIN_SIZE = 576      # 512 header + 16 IV + 16 min ciphertext + 32 HMAC

# Session file: GUID derived from vault path -- deterministic but unpredictable
$_hash        = [System.Security.Cryptography.SHA256]::Create().ComputeHash(
                    [System.Text.Encoding]::UTF8.GetBytes($VAULT_FILE))
$SESSION_FILE = Join-Path $env:TEMP ([System.Guid]::new([byte[]]$_hash[0..15]).ToString() + '.tmp')

# "Eswar the MAD!!" prepended to all HMAC inputs as domain separator.
# Any file tampering detected before decryption is attempted.
$SIGNATURE = [System.Text.Encoding]::UTF8.GetBytes('Eswar the MAD!!')

# Header layout (512 bytes, filler is random noise):
# PrimSalt(32) | RecSalt(32) | PwWrappedVMK(96) | RwWrappedVMK(96) | Filler(256)
# WrappedVMK format: IV(16) + AES-CBC(VMK)(48) + HMAC(32) = 96 bytes
$HO_PRIM_SALT  = 0
$HO_REC_SALT   = 32
$HO_PW_WRAPPED = 64
$HO_RW_WRAPPED = 160


# --- Utility ------------------------------------------------------------------

function New-RandomBytes([int]$n) {
    $b   = [byte[]]::new($n)
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $rng.GetBytes($b)
    $rng.Dispose()
    return ,$b
}

function Join-ByteArrays([byte[]]$a, [byte[]]$b) {
    $r = [byte[]]::new($a.Length + $b.Length)
    [System.Buffer]::BlockCopy($a, 0, $r, 0, $a.Length)
    [System.Buffer]::BlockCopy($b, 0, $r, $a.Length, $b.Length)
    return ,$r
}

function Get-Slice([byte[]]$src, [int]$off, [int]$len) {
    $dst = [byte[]]::new($len)
    [Array]::Copy($src, $off, $dst, 0, $len)
    return ,$dst
}

function Get-HostBinding {
    $guid = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Cryptography' -Name MachineGuid).MachineGuid
    $sid  = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return ,[System.Text.Encoding]::UTF8.GetBytes("$guid|$sid")
}

function Read-SecureBytes([string]$prompt) {
    $ss  = Read-Host $prompt -AsSecureString
    $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode($ss)
    try   { return ,[System.Text.Encoding]::UTF8.GetBytes(
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
    return ,[System.Security.Cryptography.ProtectedData]::Protect(
        $b, $null, [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
}

function Unprotect-Bytes([byte[]]$b) {
    Add-Type -AssemblyName System.Security
    return ,[System.Security.Cryptography.ProtectedData]::Unprotect(
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

function Invoke-PBKDF2([byte[]]$password, [byte[]]$salt) {
    # PBKDF2-HMAC-SHA256, manual implementation -- .NET 4.0 Rfc2898DeriveBytes only supports SHA1
    # Single block (block 1), 32-byte output = one full SHA256 block
    $hmac     = New-Object System.Security.Cryptography.HMACSHA256(,$password)
    $blockInt = [byte[]](0, 0, 0, 1)   # block counter big-endian = 1
    $seedData = Join-ByteArrays $salt $blockInt
    $u        = $hmac.ComputeHash($seedData)   # U1
    $t        = [byte[]]$u.Clone()
    for ($i = 1; $i -lt $PBKDF2_ITER; $i++) {
        $u = $hmac.ComputeHash($u)
        for ($j = 0; $j -lt 32; $j++) { $t[$j] = $t[$j] -bxor $u[$j] }
    }
    $hmac.Dispose()
    return ,$t
}

function Invoke-AesEncrypt([byte[]]$key, [byte[]]$plaintext) {
    # Returns IV(16) + ciphertext
    $aes         = [System.Security.Cryptography.Aes]::Create()
    $aes.Key     = $key
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateIV()
    $enc    = $aes.CreateEncryptor()
    $cipher = $enc.TransformFinalBlock($plaintext, 0, $plaintext.Length)
    $result = Join-ByteArrays $aes.IV $cipher
    $aes.Dispose()
    return ,$result
}

function Invoke-AesDecrypt([byte[]]$key, [byte[]]$data) {
    # data = IV(16) + ciphertext
    $iv          = Get-Slice $data 0 16
    $cipher      = Get-Slice $data 16 ($data.Length - 16)
    $aes         = [System.Security.Cryptography.Aes]::Create()
    $aes.Key     = $key
    $aes.IV      = $iv
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $dec    = $aes.CreateDecryptor()
    $result = $dec.TransformFinalBlock($cipher, 0, $cipher.Length)
    $aes.Dispose()
    return ,$result
}

function Get-MAC([byte[]]$key, [byte[]]$data) {
    # HMAC-SHA256 with "Eswar the MAD!!" prepended -- signature is cryptographically bound
    $hmac   = New-Object System.Security.Cryptography.HMACSHA256(,$key)
    $input  = Join-ByteArrays $SIGNATURE $data
    $result = $hmac.ComputeHash($input)
    $hmac.Dispose()
    return ,$result
}

function Invoke-AuthEncrypt([byte[]]$key, [byte[]]$plaintext) {
    # Encrypt-then-MAC: IV(16) + ciphertext(n) + HMAC-SHA256(32)
    $enc    = Invoke-AesEncrypt $key $plaintext
    $mac    = Get-MAC $key $enc
    return ,(Join-ByteArrays $enc $mac)
}

function Invoke-AuthDecrypt([byte[]]$key, [byte[]]$data) {
    # Verify MAC first, then decrypt -- MAC failure = wrong key or tampered file
    $macOff      = $data.Length - 32
    $enc         = Get-Slice $data 0 $macOff
    $storedMac   = Get-Slice $data $macOff 32
    $computedMac = Get-MAC $key $enc
    if (-not (Compare-ByteArrays $storedMac $computedMac)) {
        throw 'Authentication failed -- wrong credentials or tampered file.'
    }
    return ,(Invoke-AesDecrypt $key $enc)
}


# --- Header Pack / Unpack -----------------------------------------------------

function Pack-Header([hashtable]$h) {
    $raw = New-RandomBytes $HEADER_SIZE   # unused bytes are random filler
    [Array]::Copy($h.PrimSalt,     0, $raw, $HO_PRIM_SALT,  32)
    [Array]::Copy($h.RecSalt,      0, $raw, $HO_REC_SALT,   32)
    [Array]::Copy($h.PwWrappedVMK, 0, $raw, $HO_PW_WRAPPED, 96)
    [Array]::Copy($h.RwWrappedVMK, 0, $raw, $HO_RW_WRAPPED, 96)
    return ,$raw
}

function Unpack-Header([byte[]]$raw) {
    return @{
        PrimSalt     = Get-Slice $raw $HO_PRIM_SALT  32
        RecSalt      = Get-Slice $raw $HO_REC_SALT   32
        PwWrappedVMK = Get-Slice $raw $HO_PW_WRAPPED 96
        RwWrappedVMK = Get-Slice $raw $HO_RW_WRAPPED 96
    }
}


# --- Session (VMK only) -------------------------------------------------------
# Stores only the 32-byte VMK, DPAPI-protected -- vault stays encrypted between commands

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
    [System.IO.File]::WriteAllBytes($SESSION_FILE, (Join-ByteArrays $ticks $dpapi))
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
    $body = Get-Slice $file $HEADER_SIZE ($file.Length - $HEADER_SIZE)
    return [System.Text.Encoding]::UTF8.GetString((Invoke-AuthDecrypt $vmk $body)) | ConvertFrom-Json
}

function Save-VaultToFile($vault, [byte[]]$vmk, [hashtable]$existingHdr) {
    $json = $vault | ConvertTo-Json -Depth 5
    $body = Invoke-AuthEncrypt $vmk ([System.Text.Encoding]::UTF8.GetBytes($json))
    [System.IO.File]::WriteAllBytes($VAULT_FILE, (Join-ByteArrays (Pack-Header $existingHdr) $body))
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
    if ($hex.Length -ne 64) { throw 'Invalid recovery key -- expected 64 hex characters.' }
    $bytes = [byte[]]::new(32)
    for ($i = 0; $i -lt 32; $i++) { $bytes[$i] = [Convert]::ToByte($hex.Substring($i*2, 2), 16) }
    return ,$bytes
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

    $inputBytes = Join-ByteArrays $pass1 (Get-HostBinding)
    [Array]::Clear($pass1, 0, $pass1.Length)

    $primSalt = New-RandomBytes 32
    $recSalt  = New-RandomBytes 32
    $vmk      = New-RandomBytes 32

    Write-Host 'Deriving key -- this takes a moment...' -ForegroundColor Cyan
    $primKey = Invoke-PBKDF2 $inputBytes $primSalt
    [Array]::Clear($inputBytes, 0, $inputBytes.Length)

    $rec    = New-RecoveryKey
    $recKey = Invoke-PBKDF2 $rec.Bytes $recSalt

    $hdr = @{
        PrimSalt     = $primSalt
        RecSalt      = $recSalt
        PwWrappedVMK = (Invoke-AuthEncrypt $primKey $vmk)
        RwWrappedVMK = (Invoke-AuthEncrypt $recKey  $vmk)
    }
    [Array]::Clear($primKey, 0, $primKey.Length)
    [Array]::Clear($recKey,  0, $recKey.Length)

    $vault = [PSCustomObject]@{ entries = @() }
    $body  = Invoke-AuthEncrypt $vmk ([System.Text.Encoding]::UTF8.GetBytes(($vault | ConvertTo-Json -Depth 5)))
    [System.IO.File]::WriteAllBytes($VAULT_FILE, (Join-ByteArrays (Pack-Header $hdr) $body))

    Write-RecoveryFile $rec.Formatted
    Set-Session $vmk
    [Array]::Clear($vmk, 0, $vmk.Length)

    Write-Host 'Vault created successfully.' -ForegroundColor Green
    Assert-RecoveryFileGone
}


function Invoke-Unlock {
    Assert-VaultIntegrity

    $pass       = Read-SecureBytes 'Master password'
    $inputBytes = Join-ByteArrays $pass (Get-HostBinding)
    [Array]::Clear($pass, 0, $pass.Length)

    Write-Host 'Unlocking...' -ForegroundColor Cyan
    $file = [System.IO.File]::ReadAllBytes($VAULT_FILE)
    $hdr  = Unpack-Header (Get-Slice $file 0 $HEADER_SIZE)

    $primKey = Invoke-PBKDF2 $inputBytes $hdr.PrimSalt
    [Array]::Clear($inputBytes, 0, $inputBytes.Length)

    $vmk = Invoke-AuthDecrypt $primKey $hdr.PwWrappedVMK
    [Array]::Clear($primKey, 0, $primKey.Length)

    # Verify VMK decrypts vault body -- confirms correct password before writing session
    $body = Get-Slice $file $HEADER_SIZE ($file.Length - $HEADER_SIZE)
    [void](Invoke-AuthDecrypt $vmk $body)

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
        Write-Host "$fieldLabel copied for '$($entry.entity)'. Clipboard clears in $CLIP_SECS seconds." -ForegroundColor Green
    }
    finally { $val = $null }
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


function Invoke-Recover {
    Assert-VaultIntegrity

    Write-Host 'Enter your recovery key (format: XXXX-XXXX-...-XXXX)' -ForegroundColor Cyan
    $recBytes = Parse-RecoveryKey (Read-Host 'Recovery key')

    $file = [System.IO.File]::ReadAllBytes($VAULT_FILE)
    $hdr  = Unpack-Header (Get-Slice $file 0 $HEADER_SIZE)

    Write-Host 'Deriving key...' -ForegroundColor Cyan
    $recKey = Invoke-PBKDF2 $recBytes $hdr.RecSalt
    $vmk    = Invoke-AuthDecrypt $recKey $hdr.RwWrappedVMK

    $body  = Get-Slice $file $HEADER_SIZE ($file.Length - $HEADER_SIZE)
    $vault = [System.Text.Encoding]::UTF8.GetString((Invoke-AuthDecrypt $vmk $body)) | ConvertFrom-Json

    Write-Host "Recovery key verified. Vault has $(@($vault.entries).Count) entries." -ForegroundColor Green

    $pass1 = Read-SecureBytes 'Set new master password'
    Assert-PasswordComplexity $pass1
    $pass2 = Read-SecureBytes 'Confirm new master password'
    if (-not (Compare-ByteArrays $pass1 $pass2)) { throw 'Passwords do not match.' }
    [Array]::Clear($pass2, 0, $pass2.Length)

    $inputBytes = Join-ByteArrays $pass1 (Get-HostBinding)
    [Array]::Clear($pass1, 0, $pass1.Length)

    $newPrimSalt = New-RandomBytes 32
    $newRecSalt  = New-RandomBytes 32

    Write-Host 'Deriving new key...' -ForegroundColor Cyan
    $newPrimKey = Invoke-PBKDF2 $inputBytes $newPrimSalt
    [Array]::Clear($inputBytes, 0, $inputBytes.Length)

    $newRec    = New-RecoveryKey
    $newRecKey = Invoke-PBKDF2 $newRec.Bytes $newRecSalt

    $newHdr = @{
        PrimSalt     = $newPrimSalt
        RecSalt      = $newRecSalt
        PwWrappedVMK = (Invoke-AuthEncrypt $newPrimKey $vmk)
        RwWrappedVMK = (Invoke-AuthEncrypt $newRecKey  $vmk)
    }
    [Array]::Clear($newPrimKey, 0, $newPrimKey.Length)
    [Array]::Clear($newRecKey,  0, $newRecKey.Length)

    $newBody = Invoke-AuthEncrypt $vmk ([System.Text.Encoding]::UTF8.GetBytes(($vault | ConvertTo-Json -Depth 5)))
    [System.IO.File]::WriteAllBytes($VAULT_FILE, (Join-ByteArrays (Pack-Header $newHdr) $newBody))

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

  PWM Security Model (Server Edition) -- What is and is not protected

  CRYPTOGRAPHICALLY PROTECTED
    Vault contents     AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC).
                       HMAC verified before decryption -- any tampered byte = auth failure.
                       "Eswar the MAD!!" prepended to all HMAC inputs as domain separator.
                       Contents indistinguishable from random noise.

    Vault key (VMK)    32-byte random key, never stored in plaintext anywhere.
                       Wrapped under PBKDF2-HMAC-SHA256(MasterPassword + MachineGUID + UserSID).
                       Separate recovery path wrapped under the recovery key.
                       Both wrap operations use independent Encrypt-then-MAC.

    Session VMK        Only the 32-byte VMK stored between commands -- not the vault.
                       DPAPI-protected (CurrentUser). Vault stays encrypted on disk
                       between every command. Useless on any other machine or account.

    Master password    Read as SecureString, converted to bytes, zeroed after use.
                       Never written to disk in any form.

    Entry passwords    Byte arrays zeroed immediately after encoding into entry.
                       Lifetime in memory limited to duration of -add or -update.

    Recovery key       Single-use. Rotates on every -recover. Previous key immediately invalid.

  NOT PROTECTED (by design or limitation)
    Usernames, entity  Visible in -search output. Not treated as secret.
    names, notes

    File existence     cred-store.etm is visible to any user on the machine.
                       Contents are opaque -- existence is not hidden.

    Physical access    Full physical access + Windows login defeats DPAPI.
                       Use BitLocker or equivalent full-disk encryption underneath.

    Recovery key file  pwm-recovery.key readable by any process as your user until deleted.
                       Delete it immediately after copying offline.

    Same-user malware  Any process running as your Windows account can read the session VMK
                       or intercept the clipboard. This tool does not protect against a
                       compromised user session.

    Memory forensics   Live memory dump during active command may capture plaintext passwords.
                       Byte lifetime minimized, not zero.

  KEY DERIVATION
    Algorithm  : PBKDF2-HMAC-SHA256
                 Manual implementation -- .NET Framework 4.0 Rfc2898DeriveBytes only supports SHA1
    Iterations : 100,000
    Salt       : 32 bytes random per vault
    Input      : MasterPassword + MachineGUID + UserSID (concatenated, UTF-8)

    Trade-off vs Argon2id: PBKDF2 is CPU-only, no memory hardness.
    A GPU cluster can attack this faster than Argon2id.
    Compensate with a long, high-entropy master password.

  DEPENDENCIES
    None. Pure .NET Framework 4.0 built-in crypto only.
    AES, HMAC-SHA256, SHA256, PBKDF2, DPAPI -- all in-box on every Windows machine.

  SIGNATURE
    "Eswar the MAD!!" prepended to all HMAC inputs as a domain separator.
    Modification of any encrypted blob detected before decryption.

'@
}


function Show-Help {
    Write-Host @'

  PWM - Personal Password Manager (Server Edition)
  AES-256-CBC + HMAC-SHA256 | PBKDF2-SHA256 100k iter | Machine + User + Password binding
  Zero external dependencies -- pure .NET Framework 4.0 / PowerShell 5.1

  USAGE:  .\pwm.ps1 <command> [options]

  COMMANDS:

    -init                               Create a new vault. Generates a recovery key file.
                                        Warns and confirms before overwriting an existing vault.

    -unlock                             Unlock the vault for this session (30-minute window).
                                        Required once per terminal session before other commands.

    -add  -entity <val> [-notes <val>]  Add a new credential. Prompts for username and password.

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
    cred-store.etm     Your encrypted vault. Back this up.
    pwm-recovery.key   Generated at -init and -recover. DELETE after copying offline.

'@
}


# --- Entry Point --------------------------------------------------------------

try {
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
    elseif  ($PSBoundParameters.ContainsKey('search')) { Invoke-Search }
    elseif  ($copy)     { Invoke-Copy }
    elseif  ($update)   { Invoke-Update }
    elseif  ($remove)   { Invoke-Remove }
    else                { Show-Help }

} catch {
    try { Set-Clipboard -Value '' } catch {}
    Write-Host "Error: $_" -ForegroundColor Red
    exit 1
}