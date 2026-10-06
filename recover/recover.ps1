# Get your 1Password Secret Key from your hardware key.            Windows
#
#   Right-click Start > "Terminal (Admin)" or "PowerShell (Admin)", then paste:
#   irm https://lambdasistemi.net/recover/recover.ps1 | iex
#
# Needs the key (and its PIN) and internet. Downloads two public programs, checks
# them against checksums pinned below, runs them once, and deletes them. Your
# Secret Key is copied to the clipboard. UNTESTED ON WINDOWS.
$ErrorActionPreference = 'Stop'
$AgeV = '1.3.2'; $PluginV = '0.5.0'
$Mirror = if ($env:RECOVER_MIRROR) { $env:RECOVER_MIRROR } else { 'https://recovery.plutimus.com' }
$Raw    = if ($env:RECOVER_RAW) { $env:RECOVER_RAW } else { 'https://raw.githubusercontent.com/paolino/paolino/main' }
$Email  = 'paolo.veronelli@gmail.com'
$AgeSum    = 'f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7'
$PluginSum = '8c8038aa3dbe29f4b9aeb1f489876525dc916b2b83fcc3d457d9883f6a962e74'

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Warning 'Windows only lets administrators talk to a security key directly. Reopen PowerShell as Administrator if the key is not found.' }

$tmp = Join-Path $env:TEMP ('recover-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  function Get-Checked($url, $file, $sum) {
    Invoke-WebRequest -Uri $url -OutFile $file -UseBasicParsing
    if ((Get-FileHash -Algorithm SHA256 $file).Hash.ToLower() -ne $sum) { throw "CHECKSUM MISMATCH for $url - refusing to run it" }
  }
  function Get-Bundle($name) {
    foreach ($base in @($Mirror, $Raw)) {
      try { Invoke-WebRequest -Uri "$base/$name" -OutFile (Join-Path $tmp $name) -UseBasicParsing -TimeoutSec 10; if ((Get-Item (Join-Path $tmp $name)).Length -gt 0) { return } } catch {}
    }
    throw "cannot fetch $name from the mirror or GitHub"
  }
  Write-Host '1/3 downloading and checking the two public programs...'
  Get-Checked "https://github.com/FiloSottile/age/releases/download/v$AgeV/age-v$AgeV-windows-amd64.zip" "$tmp\age.zip" $AgeSum
  Get-Checked "https://github.com/olastor/age-plugin-fido2-hmac/releases/download/v$PluginV/age-plugin-fido2-hmac-v$PluginV-windows-amd64.zip" "$tmp\plugin.zip" $PluginSum
  Expand-Archive "$tmp\age.zip" -DestinationPath $tmp; Expand-Archive "$tmp\plugin.zip" -DestinationPath $tmp
  $env:PATH = "$tmp\age;$tmp\age-plugin-fido2-hmac;$env:PATH"

  Write-Host '2/3 fetching your public recovery bundle...'
  Get-Bundle 'recovery.age'; Get-Bundle 'recovery.ids'

  Write-Host '3/3 plug in your key. Enter its PIN when asked, then touch it.'
  $out = & "$tmp\age\age.exe" -d -i "$tmp\recovery.ids" "$tmp\recovery.age"
  $key = ($out | Select-String -Pattern 'A3-[A-Z0-9]{6}(-[A-Z0-9]{5,6}){5}' | Select-Object -First 1).Matches.Value
  if (-not $key) { throw 'could not decrypt (wrong PIN, key not touched, or the key is not enrolled)' }
  Set-Clipboard -Value $key
  Write-Host ''
  Write-Host 'Your Secret Key is on the clipboard (cleared in 60 seconds).'
  Start-Job { Start-Sleep 60; Set-Clipboard -Value ' ' } | Out-Null
  Write-Host ''
  Write-Host 'Now sign in at https://my.1password.com'
  Write-Host "  email:      $Email"
  Write-Host '  Secret Key: paste (Ctrl+V)'
  Write-Host '  password:   yours'
} finally { Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue }
