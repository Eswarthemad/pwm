#Requires -Version 5.1
<#
    PWM Build Tool — runs on dev machine only, never distributed
    Produces a single install.ps1 containing:
      - AES-256-GCM encrypted pwm.ps1 source (auth tag inside ciphertext)
      - BouncyCastle DLL copied from script folder at install time
    No separate HMAC file — GCM authentication is tamper-proof by design.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Paths ────────────────────────────────────────────────────────────────────

$SOURCE_SCRIPT  = Join-Path $PSScriptRoot 'pwm.ps1'
$SOURCE_DLL     = Join-Path $PSScriptRoot 'BouncyCastle.Cryptography.dll'
$OUTPUT         = Join-Path $PSScriptRoot 'install.ps1'

# ─── Helpers ──────────────────────────────────────────────────────────────────

function New-LicenseKey {
    # 4 groups of 4 — alphanumeric uppercase, ambiguous chars excluded
    $chars = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
    $rng   = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $groups = 1..4 | ForEach-Object {
        -join (1..4 | ForEach-Object {
            $b = [byte[]]::new(1)
            $rng.GetBytes($b)
            $chars[$b[0] % $chars.Length]
        })
    }
    return $groups -join '-'
}

function Get-KeyBytes([string]$licenseKey) {
    # Derive a 32-byte AES key from the license key via SHA-256
    $raw = [System.Text.Encoding]::UTF8.GetBytes($licenseKey)
    return [System.Security.Cryptography.SHA256]::Create().ComputeHash($raw)
}

function Encrypt-Bytes([byte[]]$data, [byte[]]$keyBytes) {
    # AES-256-GCM: nonce(12) + ciphertext(n) + tag(16) — auth is inside the primitive
    $nonce      = [byte[]]::new(12)
    [System.Security.Cryptography.RandomNumberGenerator]::Fill($nonce)
    $cipher     = [byte[]]::new($data.Length)
    $tag        = [byte[]]::new(16)
    $gcm        = [System.Security.Cryptography.AesGcm]::new($keyBytes)
    $gcm.Encrypt($nonce, $data, $cipher, $tag)
    $gcm.Dispose()
    return $nonce + $cipher + $tag
}

# ─── Main ─────────────────────────────────────────────────────────────────────

# Verify inputs
if (-not (Test-Path $SOURCE_SCRIPT)) { throw "pwm.ps1 not found at: $SOURCE_SCRIPT" }
if (-not (Test-Path $SOURCE_DLL))    { throw "BouncyCastle.Cryptography.dll not found at: $SOURCE_DLL" }

# Generate license key
$licenseKey = New-LicenseKey
$rawKey     = Get-KeyBytes ($licenseKey -replace '-','')

# Compute DLL hash and embed into script source before encrypting
# install.ps1 will verify DLL integrity at startup using this hash
$dllHashBytes   = [System.Security.Cryptography.SHA256]::Create().ComputeHash([System.IO.File]::ReadAllBytes($SOURCE_DLL))
$dllHashB64     = [Convert]::ToBase64String($dllHashBytes)

$scriptContent  = [System.IO.File]::ReadAllText($SOURCE_SCRIPT, [System.Text.Encoding]::UTF8)
$scriptContent  = $scriptContent.Replace("'##DLL_SHA256##'", "'$dllHashB64'")
$scriptBytes    = [System.Text.Encoding]::UTF8.GetBytes($scriptContent)
$encryptedScript= [Convert]::ToBase64String((Encrypt-Bytes $scriptBytes $rawKey))

# Build install.ps1 body
$body = @"
#Requires -Version 5.1
<#
    PWM Installer — run once, self-deletes after installation
    Requires license key generated at build time. No admin rights required.
    Payload is AES-256-GCM encrypted — wrong key or tampering causes auth failure
    inside the crypto primitive itself. Wrong key or tampering will cause cryptographic authentication failure..
#>

Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'

# ─── Embedded Payload ─────────────────────────────────────────────────────────

`$ENCRYPTED_SCRIPT = '$encryptedScript'

# ─── Helpers ──────────────────────────────────────────────────────────────────

function Get-KeyBytes([string]`$licenseKey) {
    `$raw = [System.Text.Encoding]::UTF8.GetBytes(`$licenseKey)
    return [System.Security.Cryptography.SHA256]::Create().ComputeHash(`$raw)
}

function Decrypt-Bytes([byte[]]`$data, [byte[]]`$keyBytes) {
    # AES-256-GCM: nonce(12) + ciphertext(n) + tag(16)
    # Wrong key or tampered payload = GCM auth failure = exception (cannot be bypassed)
    `$nonce  = `$data[0..11]
    `$tag    = `$data[(`$data.Length-16)..(`$data.Length-1)]
    `$cipher = `$data[12..(`$data.Length-17)]
    `$plain  = [byte[]]::new(`$cipher.Length)
    try {
        `$gcm = [System.Security.Cryptography.AesGcm]::new(`$keyBytes)
        `$gcm.Decrypt([byte[]]`$nonce, [byte[]]`$cipher, [byte[]]`$tag, `$plain)
        `$gcm.Dispose()
    } catch {
        throw "Invalid license key or payload has been tampered. Aborting."
    }
    return `$plain
}

# ─── Main ─────────────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  PWM Installer' -ForegroundColor Cyan
Write-Host ''

# Prompt license key
`$input   = Read-Host 'Enter license key (XXXX-XXXX-XXXX-XXXX)'
`$rawKey  = Get-KeyBytes (`$input -replace '-','')

# ─── Copy DLL ────────────────────────────────────────────────────────────────

`$srcDLL = Join-Path `$PSScriptRoot 'BouncyCastle.Cryptography.dll'
if (-not (Test-Path `$srcDLL)) { throw "BouncyCastle.Cryptography.dll not found next to install.ps1" }
`$dllDir = Join-Path `$env:LOCALAPPDATA 'PWM'
if (-not (Test-Path `$dllDir)) { New-Item -ItemType Directory -Path `$dllDir | Out-Null }
`$dllPath = Join-Path `$dllDir 'BouncyCastle.Cryptography.dll'
Copy-Item -Path `$srcDLL -Destination `$dllPath -Force
Write-Host '  BouncyCastle DLL installed.' -ForegroundColor Green

# ─── Decrypt and DPAPI-Protect Source ─────────────────────────────────────────

`$encBytes    = [Convert]::FromBase64String(`$ENCRYPTED_SCRIPT)
`$plainBytes  = Decrypt-Bytes `$encBytes `$rawKey
[Array]::Clear(`$rawKey, 0, `$rawKey.Length)

Add-Type -AssemblyName System.Security
`$dpapi = [System.Security.Cryptography.ProtectedData]::Protect(
              `$plainBytes, `$null,
              [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Array]::Clear(`$plainBytes, 0, `$plainBytes.Length)

`$coreFile = Join-Path `$PSScriptRoot 'pwm-core.dpapi'
[System.IO.File]::WriteAllBytes(`$coreFile, `$dpapi)
Write-Host '  Core encrypted and saved.' -ForegroundColor Green

# ─── Write Launcher ───────────────────────────────────────────────────────────

`$launcher = @'
# PWM Launcher
`$root = `$PSScriptRoot
`$core = Join-Path `$root 'pwm-core.dpapi'
`$dll  = Join-Path `$env:LOCALAPPDATA 'PWM\BouncyCastle.Cryptography.dll'
if (-not (Test-Path `$core)) { Write-Host 'PWM not installed. Run install.ps1 first.'; exit 1 }
if (-not (Test-Path `$dll))  { Write-Host 'BouncyCastle DLL missing from AppData\Local\PWM\'; exit 1 }
Add-Type -AssemblyName System.Security
Add-Type -Path `$dll
`$blob  = [System.IO.File]::ReadAllBytes(`$core)
`$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
              `$blob, `$null,
              [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
`$code  = [System.Text.Encoding]::UTF8.GetString(`$bytes)
[System.Array]::Clear(`$bytes, 0, `$bytes.Length)
# Replace $PSScriptRoot in code with actual path before creating ScriptBlock
`$code = `$code.Replace('`$PSScriptRoot', "'`$root'")
`$sb   = [ScriptBlock]::Create(`$code)
& `$sb @args
'@

`$launcherFile = Join-Path `$PSScriptRoot 'pwm.ps1'
Set-Content -Path `$launcherFile -Value `$launcher -Encoding UTF8
Write-Host '  Launcher written.' -ForegroundColor Green

# ─── Self Delete ──────────────────────────────────────────────────────────────

Write-Host ''
Write-Host '  Installation complete. Use pwm.ps1 for all commands.' -ForegroundColor Green
Write-Host ''

# Zero out then delete — secure wipe, no quoting issues
[System.IO.File]::WriteAllBytes(`$MyInvocation.MyCommand.Path, [byte[]]::new((Get-Item `$MyInvocation.MyCommand.Path).Length))
Remove-Item `$MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue

"@

# Write install.ps1 — no HMAC file needed, GCM auth tag is inside the payload
[System.IO.File]::WriteAllText($OUTPUT, $body, [System.Text.Encoding]::UTF8)

# Clear key from memory
[Array]::Clear($rawKey, 0, $rawKey.Length)

Write-Host ''
Write-Host '╔════════════════════════════════════════════╗' -ForegroundColor Yellow
Write-Host '║           PWM LICENSE KEY                  ║' -ForegroundColor Yellow
Write-Host "║                                            ║" -ForegroundColor Yellow
Write-Host "║     $licenseKey                       ║" -ForegroundColor Yellow
Write-Host '║                                            ║' -ForegroundColor Yellow
Write-Host '║  Write this down. Never shown again.       ║' -ForegroundColor Yellow
Write-Host '╚════════════════════════════════════════════╝' -ForegroundColor Yellow
Write-Host ''
Write-Host "install.ps1 written to: $OUTPUT" -ForegroundColor Green
Write-Host ''
Write-Host 'Carry install.ps1 and BouncyCastle.Cryptography.dll together.' -ForegroundColor Cyan
Write-Host ''