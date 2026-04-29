# ==============================================================
# setup_target.ps1 – Préparation de la machine cible (TP BadUSB)
# Objectif pédagogique : TP sécurité offensive / défensive
#
# Ce script est exécuté UNE FOIS sur la machine cible avant la
# démonstration. Il remet la machine dans un état « vulnérable »
# en réactivant l'AutoRun Windows, ce qui permet à autorun.inf
# de déclencher launcher.vbs dès l'insertion de la clé USB,
# SANS aucune interaction de l'utilisateur.
#
# Pré-condition exploitée (MITRE ATT&CK T1091) :
#   La fonctionnalité AutoRun de Windows est désactivée par
#   défaut depuis KB971029 (Vista). Sur un parc non durci, il
#   suffit de supprimer ou de réinitialiser la valeur de registre
#   NoDriveTypeAutoRun pour la réactiver.
#
# Utilisation :
#   powershell -ExecutionPolicy Bypass -File setup_target.ps1
# ==============================================================

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

Write-Host "=== Preparation de la machine cible (TP BadUSB) ===" -ForegroundColor Cyan
Write-Host ""

# ──────────────────────────────────────────────────────────────
# 1. Réactivation de l'AutoRun (NoDriveTypeAutoRun = 0x00)
#    0x00 = AutoRun activé pour tous les types de lecteurs
#    (amovibles, réseau, CD-ROM, lecteurs fixes, etc.)
#
#    La valeur par défaut de Windows 10 est 0x91 (lecteurs
#    amovibles et réseau exclus). KB971029 l'a fixée à 0xFF
#    sur les systèmes patchés. Remettre 0x00 restaure le
#    comportement Windows XP/7 d'origine.
# ──────────────────────────────────────────────────────────────

$explorerPolicyHKLM = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$explorerPolicyHKCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"

# Niveau machine (s'applique à tous les utilisateurs)
if (-not (Test-Path $explorerPolicyHKLM)) {
    $null = New-Item -Path $explorerPolicyHKLM -Force
}
Set-ItemProperty -Path $explorerPolicyHKLM -Name "NoDriveTypeAutoRun" -Value 0x00 -Type DWord -Force
Set-ItemProperty -Path $explorerPolicyHKLM -Name "NoAutorun"          -Value 0    -Type DWord -Force
Write-Host "[+] HKLM : NoDriveTypeAutoRun = 0x00 (AutoRun active - tous lecteurs)" -ForegroundColor Green

# Niveau utilisateur courant (prioritaire sur HKLM)
if (-not (Test-Path $explorerPolicyHKCU)) {
    $null = New-Item -Path $explorerPolicyHKCU -Force
}
Set-ItemProperty -Path $explorerPolicyHKCU -Name "NoDriveTypeAutoRun" -Value 0x00 -Type DWord -Force
Write-Host "[+] HKCU : NoDriveTypeAutoRun = 0x00 (AutoRun active - tous lecteurs)" -ForegroundColor Green

# ──────────────────────────────────────────────────────────────
# 2. Suppression du handler AutoPlay par défaut pour les
#    périphériques de stockage (StorageOnArrival).
#    Si Windows a un handler par défaut configuré (ex : « Ouvrir
#    le dossier »), il intercepte l'événement AutoPlay AVANT que
#    autorun.inf puisse s'exécuter. La suppression de ce handler
#    force Windows à lire autorun.inf et à exécuter open=.
# ──────────────────────────────────────────────────────────────

$autoPlayHandlers = @(
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\UserChosenExecuteHandlers\StorageOnArrival",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers\CancelAutoplay\Files"
)

foreach ($key in $autoPlayHandlers) {
    if (Test-Path $key) {
        $null = Remove-Item -Path $key -Recurse -Force 2>&1
        Write-Host "[+] Handler AutoPlay supprime : $key" -ForegroundColor Green
    }
}

# ──────────────────────────────────────────────────────────────
# 3. (Re)démarrage du service ShellHWDetection
#    Ce service est responsable de la détection du matériel
#    et du déclenchement de l'AutoPlay/AutoRun. S'il est arrêté
#    ou désactivé (par defense.ps1 par exemple), AutoRun ne
#    fonctionne pas même avec NoDriveTypeAutoRun = 0x00.
# ──────────────────────────────────────────────────────────────

$svc = Get-Service -Name "ShellHWDetection" -ErrorAction SilentlyContinue
if ($svc) {
    Set-Service  -Name "ShellHWDetection" -StartupType Automatic
    if ($svc.Status -ne "Running") {
        Start-Service -Name "ShellHWDetection"
    }
    Write-Host "[+] Service ShellHWDetection : demarre (StartupType = Automatic)" -ForegroundColor Green
}

# ──────────────────────────────────────────────────────────────
# 4. Désactivation de Windows Defender (protection en temps réel)
#    Permet au payload.ps1 de s'exécuter sans être bloqué
#    par l'antivirus pendant la durée de la démonstration.
#    À réactiver après le TP via Restore-Defender.ps1 ou
#    manuellement dans les Paramètres Windows.
# ──────────────────────────────────────────────────────────────

try {
    Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
    Write-Host "[+] Windows Defender : protection temps reel desactivee" -ForegroundColor Green
} catch {
    Write-Host "[!] Impossible de desactiver Defender (peut etre gere par GPO) : $_" -ForegroundColor Yellow
}

# ──────────────────────────────────────────────────────────────
# 5. Application immédiate sans redémarrage
#    On redémarre le shell Windows (explorer.exe) pour que les
#    modifications de registre soient prises en compte dans la
#    session courante sans nécessiter un reboot complet.
# ──────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "[*] Redemarrage de l'Explorateur Windows pour appliquer les changements..." -ForegroundColor Cyan

$explorerPID = (Get-Process -Name explorer -ErrorAction SilentlyContinue | Select-Object -First 1).Id
if ($explorerPID) {
    Stop-Process -Id $explorerPID -Force
    Start-Sleep -Seconds 2
    # L'Explorateur redémarre automatiquement après avoir été tué
    Write-Host "[+] Explorateur redemarre." -ForegroundColor Green
} else {
    Start-Process "explorer.exe"
    Write-Host "[+] Explorateur lance." -ForegroundColor Green
}

# ──────────────────────────────────────────────────────────────
# 6. Récapitulatif
# ──────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Machine cible prete pour la demonstration ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "  AutoRun           : ACTIVE (NoDriveTypeAutoRun = 0x00)"
Write-Host "  Handler AutoPlay  : supprime (autorun.inf prioritaire)"
Write-Host "  ShellHWDetection  : démarré"
Write-Host "  Windows Defender  : protection temps reel desactivee"
Write-Host ""
Write-Host "  >>> Insérer la clé USB préparée. <<<" -ForegroundColor Yellow
Write-Host "      autorun.inf -> launcher.vbs -> payload.ps1"
Write-Host "      Aucune interaction utilisateur requise."
Write-Host ""
Write-Host "  RAPPEL : Reactiver Defender apres le TP :" -ForegroundColor Red
Write-Host "  Set-MpPreference -DisableRealtimeMonitoring `$false" -ForegroundColor Red
