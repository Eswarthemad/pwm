#Requires -Version 5.1
<#
    PWM Build Tool (Server Edition) -- runs on dev machine, never distributed
    Produces a single install.ps1 containing AES-256-CBC encrypted pwm_server.ps1
    No DLL, no DLL hash, no HMAC file -- zero external dependencies on target machine
    Target: PowerShell 5.1 / .NET Framework 4.0
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- Paths --------------------------------------------------------------------

$SOURCE_SCRIPT = Join-Path $PSScriptRoot 'pwm_server.ps1'
$OUTPUT        = Join-Path $PSScriptRoot 'install_server.ps1'

# --- Helpers ------------------------------------------------------------------

function New-LicenseKey {
    $chars  = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'
    $rng    = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $groups = 1..4 | ForEach-Object {
        -join (1..4 | ForEach-Object {
            $b = [byte[]]::new(1)
            $rng.GetBytes($b)
            $chars[$b[0] % $chars.Length]
        })
    }
    $rng.Dispose()
    return $groups -join '-'
}

function Get-KeyBytes([string]$licenseKey) {
    $raw = [System.Text.Encoding]::UTF8.GetBytes($licenseKey)
    return [System.Security.Cryptography.SHA256]::Create().ComputeHash($raw)
}

function Encrypt-Bytes([byte[]]$data, [byte[]]$keyBytes) {
    # AES-256-CBC: IV(16) + ciphertext -- compatible with all .NET versions
    $aes         = [System.Security.Cryptography.Aes]::Create()
    $aes.Key     = $keyBytes
    $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.GenerateIV()
    $enc    = $aes.CreateEncryptor()
    $cipher = $enc.TransformFinalBlock($data, 0, $data.Length)
    $result = $aes.IV + $cipher
    $aes.Dispose()
    return $result
}

# --- Main ---------------------------------------------------------------------

if (-not (Test-Path $SOURCE_SCRIPT)) { throw "pwm_server.ps1 not found at: $SOURCE_SCRIPT" }

$licenseKey     = New-LicenseKey
$rawKey         = Get-KeyBytes ($licenseKey -replace '-','')
$scriptBytes    = [System.IO.File]::ReadAllBytes($SOURCE_SCRIPT)
$encryptedScript= [Convert]::ToBase64String((Encrypt-Bytes $scriptBytes $rawKey))
[Array]::Clear($rawKey, 0, $rawKey.Length)

$body = @"
#Requires -Version 5.1
<#
    PWM Installer (Server Edition) -- run once, self-deletes after installation
    Requires license key generated at build time. No admin rights required.
    Payload is AES-256-CBC encrypted. No plaintext to tamper with.
    Zero external dependencies -- pure .NET Framework 4.0.
#>

Set-StrictMode -Version Latest
`$ErrorActionPreference = 'Stop'

# --- Embedded Payload ---------------------------------------------------------

`$ENCRYPTED_SCRIPT = '$encryptedScript'

# --- Helpers ------------------------------------------------------------------

function Get-KeyBytes([string]`$licenseKey) {
    `$raw = [System.Text.Encoding]::UTF8.GetBytes(`$licenseKey)
    return [System.Security.Cryptography.SHA256]::Create().ComputeHash(`$raw)
}

function Decrypt-Bytes([byte[]]`$data, [byte[]]`$keyBytes) {
    # AES-256-CBC: IV(16) + ciphertext
    `$iv          = `$data[0..15]
    `$cipher      = `$data[16..(`$data.Length-1)]
    `$aes         = [System.Security.Cryptography.Aes]::Create()
    `$aes.Key     = `$keyBytes
    `$aes.IV      = [byte[]]`$iv
    `$aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
    `$aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    try {
        `$dec = `$aes.CreateDecryptor()
        return `$dec.TransformFinalBlock([byte[]]`$cipher, 0, `$cipher.Length)
    } catch {
        throw 'Invalid license key. Aborting.'
    } finally {
        `$aes.Dispose()
    }
}

# --- Main ---------------------------------------------------------------------

Write-Host ''
Write-Host '  PWM Installer (Server Edition)' -ForegroundColor Cyan
Write-Host ''

`$entry  = Read-Host 'Enter license key (XXXX-XXXX-XXXX-XXXX)'
`$rawKey = Get-KeyBytes (`$entry -replace '-','')

# Decrypt payload
`$encBytes   = [Convert]::FromBase64String(`$ENCRYPTED_SCRIPT)
`$plainBytes = Decrypt-Bytes `$encBytes `$rawKey
[Array]::Clear(`$rawKey, 0, `$rawKey.Length)

# DPAPI-protect the decrypted source and write pwm-core.dpapi
Add-Type -AssemblyName System.Security
`$dpapi = [System.Security.Cryptography.ProtectedData]::Protect(
              `$plainBytes, `$null,
              [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
[Array]::Clear(`$plainBytes, 0, `$plainBytes.Length)

`$coreFile = Join-Path `$PSScriptRoot 'pwm-core.dpapi'
[System.IO.File]::WriteAllBytes(`$coreFile, `$dpapi)
Write-Host '  Core encrypted and saved.' -ForegroundColor Green

# Write launcher
`$launcher = @'
# PWM Launcher (Server Edition)
`$root = `$PSScriptRoot
`$core = Join-Path `$root 'pwm-core.dpapi'
if (-not (Test-Path `$core)) { Write-Host 'PWM not installed. Run install_server.ps1 first.'; exit 1 }
Add-Type -AssemblyName System.Security
`$blob  = [System.IO.File]::ReadAllBytes(`$core)
`$bytes = [System.Security.Cryptography.ProtectedData]::Unprotect(
              `$blob, `$null,
              [System.Security.Cryptography.DataProtectionScope]::CurrentUser)
`$code  = [System.Text.Encoding]::UTF8.GetString(`$bytes)
[System.Array]::Clear(`$bytes, 0, `$bytes.Length)
`$code = `$code.Replace('`$PSScriptRoot', "'`$root'")
`$sb   = [ScriptBlock]::Create(`$code)
& `$sb @args
'@

`$launcherFile = Join-Path `$PSScriptRoot 'pwm.ps1'
Set-Content -Path `$launcherFile -Value `$launcher -Encoding UTF8
Write-Host '  Launcher written.' -ForegroundColor Green

# Self-wipe
Write-Host ''
Write-Host '  Installation complete. Use pwm.ps1 for all commands.' -ForegroundColor Green
Write-Host ''

[System.IO.File]::WriteAllBytes(`$MyInvocation.MyCommand.Path, [byte[]]::new((Get-Item `$MyInvocation.MyCommand.Path).Length))
Remove-Item `$MyInvocation.MyCommand.Path -Force -ErrorAction SilentlyContinue
"@

[System.IO.File]::WriteAllText($OUTPUT, $body, [System.Text.Encoding]::UTF8)

# Display license key
Write-Host ''
Write-Host 'o============================================o' -ForegroundColor Yellow
Write-Host '|           PWM LICENSE KEY                  |' -ForegroundColor Yellow
Write-Host '|                                            |' -ForegroundColor Yellow
Write-Host "|     $licenseKey                       |" -ForegroundColor Yellow
Write-Host '|                                            |' -ForegroundColor Yellow
Write-Host '|  Write this down. Never shown again.       |' -ForegroundColor Yellow
Write-Host 'o============================================o' -ForegroundColor Yellow
Write-Host ''
Write-Host "install_server.ps1 written to: $OUTPUT" -ForegroundColor Green
Write-Host ''
Write-Host 'Copy install_server.ps1 to target machine and run it.' -ForegroundColor Cyan
Write-Host ''