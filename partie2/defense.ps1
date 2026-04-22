#Requires -RunAsAdministrator
# ==============================================================
# defense.ps1 – Script de défense contre les attaques BadUSB
# Partie 2 – TP BadUSB Attack
#
# Ce script doit être lancé manuellement par le testeur avec
# des droits administrateur :
#   powershell -ExecutionPolicy Bypass -File defense.ps1
#
# Actions réalisées :
#   1. Désactivation d'AutoRun / AutoPlay pour les supports USB
#   2. Journalisation PowerShell activée (ScriptBlock + Transcription)
#   3. Surveillance WMI des insertions USB en temps réel
#   4. Surveillance des créations de comptes locaux
#   5. Surveillance des modifications RDP et WinRM
#   6. Surveillance des processus PowerShell lancés en mode caché
#   7. Alerte + blocage automatique en cas de détection
# ==============================================================

$ErrorActionPreference = "Stop"
$global:DefenseLogFile = "$PSScriptRoot\defense_log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

function global:Write-Log {
    param([string]$Level, [string]$Message)
    $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$ts][$Level] $Message"
    Write-Host $line -ForegroundColor $(
        switch ($Level) {
            "INFO"  { "Cyan"   }
            "WARN"  { "Yellow" }
            "ALERT" { "Red"    }
            default { "White"  }
        }
    )
    Add-Content -Path $global:DefenseLogFile -Value $line
}

# ──────────────────────────────────────────────────────────────
# 1. DÉSACTIVATION DE L'AUTORUN / AUTOPLAY POUR LES CLÉS USB
# ──────────────────────────────────────────────────────────────

function Disable-AutoRunAutoPlay {
    Write-Log "INFO" "Désactivation de l'AutoRun et de l'AutoPlay USB…"

    # Politique machine (tous types de supports amovibles)
    $regBase = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    Set-ItemProperty -Path $regBase -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force
    Set-ItemProperty -Path $regBase -Name "NoAutorun"          -Value 1    -Type DWord -Force

    # Politique utilisateur courant
    $regCU = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer"
    if (-not (Test-Path $regCU)) { New-Item $regCU -Force | Out-Null }
    Set-ItemProperty -Path $regCU -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force
    Set-ItemProperty -Path $regCU -Name "NoAutorun"          -Value 1    -Type DWord -Force

    # Désactivation du service Shell Hardware Detection (AutoPlay)
    $shd = Get-Service -Name ShellHWDetection -EA SilentlyContinue
    if ($shd -and $shd.Status -eq "Running") {
        Stop-Service -Name ShellHWDetection -Force
        Set-Service  -Name ShellHWDetection -StartupType Disabled
        Write-Log "INFO" "Service ShellHWDetection désactivé."
    }

    Write-Log "INFO" "AutoRun/AutoPlay désactivés avec succès."
}

# ──────────────────────────────────────────────────────────────
# 2. ACTIVATION DE LA JOURNALISATION POWERSHELL
# ──────────────────────────────────────────────────────────────

function Enable-PowerShellLogging {
    Write-Log "INFO" "Activation de la journalisation PowerShell…"

    $psBase = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"

    # ScriptBlock Logging : enregistre chaque bloc de code exécuté
    $sbl = "$psBase\ScriptBlockLogging"
    if (-not (Test-Path $sbl)) { New-Item $sbl -Force | Out-Null }
    Set-ItemProperty -Path $sbl -Name "EnableScriptBlockLogging"         -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $sbl -Name "EnableScriptBlockInvocationLogging" -Value 1 -Type DWord -Force

    # Transcription : enregistre les sessions PS dans un fichier texte
    $tr = "$psBase\Transcription"
    if (-not (Test-Path $tr)) { New-Item $tr -Force | Out-Null }
    $transcriptDir = "$env:SystemDrive\PS_Transcripts"
    New-Item -ItemType Directory -Path $transcriptDir -Force | Out-Null
    Set-ItemProperty -Path $tr -Name "EnableTranscripting"     -Value 1            -Type DWord  -Force
    Set-ItemProperty -Path $tr -Name "OutputDirectory"         -Value $transcriptDir -Type String -Force
    Set-ItemProperty -Path $tr -Name "EnableInvocationHeader"  -Value 1            -Type DWord  -Force

    # Module Logging : journalise tous les modules chargés
    $ml = "$psBase\ModuleLogging"
    if (-not (Test-Path $ml)) { New-Item $ml -Force | Out-Null }
    Set-ItemProperty -Path $ml -Name "EnableModuleLogging" -Value 1 -Type DWord -Force

    Write-Log "INFO" "Journalisation PowerShell activée (ScriptBlock + Transcription + Module)."
}

# ──────────────────────────────────────────────────────────────
# 3. SURVEILLANCE DES INSERTIONS DE SUPPORTS USB (WMI)
# ──────────────────────────────────────────────────────────────

function Start-USBMonitor {
    Write-Log "INFO" "Démarrage de la surveillance des insertions USB (WMI)…"

    # Requête WMI : détecte l'ajout d'une instance Win32_DiskDrive
    $query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 " +
             "WHERE TargetInstance ISA 'Win32_DiskDrive'"

    $action = {
        # WMI action blocks run in a separate runspace; use global scope for logging
        $lf   = $global:DefenseLogFile
        $ts   = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        $disk = $event.SourceEventArgs.NewEvent.TargetInstance
        $line = "[$ts][ALERT] Insertion USB détectée : " +
                "DeviceID=$($disk.DeviceID) Model=$($disk.Model) " +
                "InterfaceType=$($disk.InterfaceType) SerialNumber=$($disk.SerialNumber)"
        Write-Host $line -ForegroundColor Red
        if ($lf) { Add-Content -Path $lf -Value $line }

        # Mesure préventive : tente d'identifier et de tuer les processus
        # VBScript ou PowerShell lancés depuis un lecteur amovible
        $removableDrives = Get-WmiObject Win32_LogicalDisk |
                           Where-Object { $_.DriveType -eq 2 } |
                           Select-Object -ExpandProperty DeviceID

        foreach ($drive in $removableDrives) {
            Get-Process -EA 0 | Where-Object {
                $_.Path -like "$drive\*"
            } | ForEach-Object {
                $killLine = "[$ts][ALERT] Processus suspect tué : $($_.Name) (PID=$($_.Id)) depuis $drive"
                Write-Host $killLine -ForegroundColor Red
                if ($lf) { Add-Content -Path $lf -Value $killLine }
                Stop-Process -Id $_.Id -Force -EA 0
            }
        }
    }

    # Enregistrement de l'événement WMI en session
    $null = Register-WmiEvent -Query $query -SourceIdentifier "USBInsert" -Action $action
    Write-Log "INFO" "Surveillance USB active."
}

# ──────────────────────────────────────────────────────────────
# 4. SURVEILLANCE DES CRÉATIONS DE COMPTES LOCAUX
# ──────────────────────────────────────────────────────────────

function Start-UserCreationMonitor {
    Write-Log "INFO" "Démarrage de la surveillance des créations de comptes locaux (WMI)…"

    # Capture les créations de comptes via Win32_UserAccount
    $query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 " +
             "WHERE TargetInstance ISA 'Win32_UserAccount'"

    $action = {
        # WMI action blocks run in a separate runspace; use global scope for logging
        $lf  = $global:DefenseLogFile
        $ts  = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $usr = $event.SourceEventArgs.NewEvent.TargetInstance

        $line = "[$ts][ALERT] Nouveau compte créé : Name=$($usr.Name)  " +
                "Domain=$($usr.Domain)  LocalAccount=$($usr.LocalAccount)  Status=$($usr.Status)"
        Write-Host $line -ForegroundColor Red
        if ($lf) { Add-Content -Path $lf -Value $line }

        # Désactive immédiatement le compte suspect
        try {
            Disable-LocalUser -Name $usr.Name -EA Stop
            $ok = "[$ts][ALERT] Compte '$($usr.Name)' désactivé automatiquement."
            Write-Host $ok -ForegroundColor Red
            if ($lf) { Add-Content -Path $lf -Value $ok }
        } catch {
            $err = "[$ts][WARN] Impossible de désactiver le compte '$($usr.Name)' : $_"
            Write-Host $err -ForegroundColor Yellow
            if ($lf) { Add-Content -Path $lf -Value $err }
        }
    }

    $null = Register-WmiEvent -Query $query -SourceIdentifier "UserCreation" -Action $action
    Write-Log "INFO" "Surveillance des comptes locaux active."
}

# ──────────────────────────────────────────────────────────────
# 5. SURVEILLANCE DES MODIFICATIONS RDP ET WINRM
# ──────────────────────────────────────────────────────────────

function Start-RDPWinRMMonitor {
    Write-Log "INFO" "Démarrage de la surveillance RDP / WinRM…"

    # Valeurs initiales de référence – stockées en scope global pour le timer
    $global:RdpMonitorKey   = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
    $global:RdpMonitorValue = (Get-ItemProperty -Path $global:RdpMonitorKey -EA 0).fDenyTSConnections
    $global:WinRMStartType  = (Get-Service -Name WinRM -EA 0).StartType

    # Boucle de surveillance (toutes les 5 secondes)
    # Register-ObjectEvent s'exécute dans le même runspace ; les variables
    # globales sont accessibles directement.
    $timerAction = {
        # ── Contrôle RDP ──
        $current = (Get-ItemProperty -Path $global:RdpMonitorKey -EA 0).fDenyTSConnections
        if ($null -ne $current -and $current -ne $global:RdpMonitorValue) {
            $msg = "Modification RDP détectée ! fDenyTSConnections : $($global:RdpMonitorValue) -> $current"
            global:Write-Log "ALERT" $msg
            # Rétablissement de la valeur initiale (RDP désactivé)
            Set-ItemProperty -Path $global:RdpMonitorKey -Name "fDenyTSConnections" -Value 1 -Force
            global:Write-Log "INFO" "RDP re-désactivé."
        }

        # ── Contrôle WinRM ──
        $winrmCurrent = (Get-Service -Name WinRM -EA 0).StartType
        if ($winrmCurrent -and $winrmCurrent -ne $global:WinRMStartType -and
            $winrmCurrent -ne "Disabled") {
            global:Write-Log "ALERT" "Modification WinRM détectée ! StartType : $($global:WinRMStartType) -> $winrmCurrent"
            Stop-Service    -Name WinRM -Force -EA 0
            Set-Service     -Name WinRM -StartupType Disabled -EA 0
            global:Write-Log "INFO" "WinRM re-désactivé."
        }
    }

    # Timer PowerShell (intervalle 5 s)
    $timer           = New-Object System.Timers.Timer
    $timer.Interval  = 5000
    $timer.AutoReset = $true
    $null = Register-ObjectEvent -InputObject $timer -EventName Elapsed `
            -SourceIdentifier "RDPWinRMTimer" -Action $timerAction
    $timer.Start()
    Write-Log "INFO" "Surveillance RDP/WinRM active (toutes les 5 s)."
}

# ──────────────────────────────────────────────────────────────
# 6. SURVEILLANCE DES PROCESSUS POWERSHELL EN MODE CACHÉ
# ──────────────────────────────────────────────────────────────

function Start-HiddenPSMonitor {
    Write-Log "INFO" "Démarrage de la surveillance des processus PowerShell cachés…"

    $query  = "SELECT * FROM __InstanceCreationEvent WITHIN 2 " +
              "WHERE TargetInstance ISA 'Win32_Process' AND " +
              "TargetInstance.Name = 'powershell.exe'"

    $action = {
        # WMI action blocks run in a separate runspace; use global scope for logging
        $lf      = $global:DefenseLogFile
        $ts      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $proc    = $event.SourceEventArgs.NewEvent.TargetInstance
        $cmdLine = $proc.CommandLine

        # Indicateurs de comportement malveillant
        $indicators = @(
            "-WindowStyle Hidden",
            "-NonInteractive",
            "-EncodedCommand",
            "-ExecutionPolicy Bypass",
            "-NoProfile.*-File"
        )

        $suspicious = $false
        foreach ($ind in $indicators) {
            if ($cmdLine -match $ind) { $suspicious = $true; break }
        }

        if ($suspicious) {
            $line = "[$ts][ALERT] Processus PowerShell suspect détecté ! " +
                    "PID=$($proc.ProcessId)  CMD=$cmdLine"
            Write-Host $line -ForegroundColor Red
            if ($lf) { Add-Content -Path $lf -Value $line }
            # Tentative de terminaison du processus
            try {
                Stop-Process -Id $proc.ProcessId -Force -EA Stop
                $ok = "[$ts][ALERT] Processus PID=$($proc.ProcessId) terminé."
                Write-Host $ok -ForegroundColor Red
                if ($lf) { Add-Content -Path $lf -Value $ok }
            } catch {
                $err = "[$ts][WARN] Impossible de terminer PID=$($proc.ProcessId) : $_"
                Write-Host $err -ForegroundColor Yellow
                if ($lf) { Add-Content -Path $lf -Value $err }
            }
        }
    }

    $null = Register-WmiEvent -Query $query -SourceIdentifier "HiddenPS" -Action $action
    Write-Log "INFO" "Surveillance des processus PowerShell cachés active."
}

# ──────────────────────────────────────────────────────────────
# 7. VÉRIFICATION DE L'ÉTAT INITIAL + DURCISSEMENT DE BASE
# ──────────────────────────────────────────────────────────────

function Invoke-InitialHardening {
    Write-Log "INFO" "Vérification et durcissement de la configuration initiale…"

    # ── RDP ──
    $rdpVal = (Get-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -EA 0).fDenyTSConnections
    if ($rdpVal -eq 0) {
        Write-Log "WARN" "RDP est actuellement activé. Désactivation…"
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
                         -Name "fDenyTSConnections" -Value 1 -Force
        Disable-NetFirewallRule -DisplayGroup "Remote Desktop" -EA 0
        Write-Log "INFO" "RDP désactivé."
    } else {
        Write-Log "INFO" "RDP déjà désactivé."
    }

    # ── WinRM ──
    $winrm = Get-Service -Name WinRM -EA SilentlyContinue
    if ($winrm -and $winrm.Status -eq "Running") {
        Write-Log "WARN" "WinRM est en cours d'exécution. Arrêt et désactivation…"
        Stop-Service -Name WinRM -Force -EA 0
        Set-Service  -Name WinRM -StartupType Disabled -EA 0
        Write-Log "INFO" "WinRM arrêté et désactivé."
    } else {
        Write-Log "INFO" "WinRM déjà arrêté."
    }

    # ── Règle pare-feu backdoor potentielle ──
    $bkRule = Get-NetFirewallRule -DisplayName "BackdoorRemoteAccess" -EA SilentlyContinue
    if ($bkRule) {
        Remove-NetFirewallRule -DisplayName "BackdoorRemoteAccess" -EA 0
        Write-Log "ALERT" "Règle pare-feu suspecte 'BackdoorRemoteAccess' supprimée."
    }

    # ── Comptes cachés dans SpecialAccounts ──
    $specialKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
    if (Test-Path $specialKey) {
        $hiddenAccounts = Get-ItemProperty -Path $specialKey -EA 0 |
                          Get-Member -MemberType NoteProperty |
                          Where-Object { $_.Name -notmatch "^PS" }
        foreach ($acc in $hiddenAccounts) {
            Write-Log "ALERT" "Compte caché détecté : $($acc.Name)"
            # Désactive le compte caché suspect
            Disable-LocalUser -Name $acc.Name -EA 0
            Write-Log "INFO" "Compte '$($acc.Name)' désactivé."
        }
    }

    Write-Log "INFO" "Durcissement initial terminé."
}

# ──────────────────────────────────────────────────────────────
# POINT D'ENTRÉE PRINCIPAL
# ──────────────────────────────────────────────────────────────

function Main {
    Write-Log "INFO" "======================================================"
    Write-Log "INFO" "   Script de défense BadUSB – Partie 2 – Démarrage"
    Write-Log "INFO" "======================================================"
    Write-Log "INFO" "Fichier de journalisation : $LogFile"

    # Étape 1 : durcissement initial + vérification de l'état existant
    Invoke-InitialHardening

    # Étape 2 : désactivation AutoRun/AutoPlay
    Disable-AutoRunAutoPlay

    # Étape 3 : activation de la journalisation PowerShell
    Enable-PowerShellLogging

    # Étape 4 : démarrage des surveillances WMI et timers
    Start-USBMonitor
    Start-UserCreationMonitor
    Start-RDPWinRMMonitor
    Start-HiddenPSMonitor

    Write-Log "INFO" "Tous les mécanismes de défense sont actifs."
    Write-Log "INFO" "Appuyez sur Ctrl+C pour arrêter la surveillance."
    Write-Log "INFO" "======================================================"

    # Boucle principale : maintient le script en vie
    try {
        while ($true) {
            # Traitement des événements en attente
            $pending = Get-Event -EA 0
            foreach ($ev in $pending) {
                Remove-Event -EventIdentifier $ev.EventIdentifier -EA 0
            }
            Start-Sleep -Seconds 2
        }
    } finally {
        # Nettoyage à l'arrêt (Ctrl+C)
        Unregister-Event -SourceIdentifier "USBInsert"      -EA 0
        Unregister-Event -SourceIdentifier "UserCreation"   -EA 0
        Unregister-Event -SourceIdentifier "RDPWinRMTimer"  -EA 0
        Unregister-Event -SourceIdentifier "HiddenPS"       -EA 0
        Write-Log "INFO" "Surveillance arrêtée proprement."
    }
}

Main
