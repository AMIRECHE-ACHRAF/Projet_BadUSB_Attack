# Projet BadUSB Attack – TP Sécurité

> **Avertissement légal et éthique** : Ce projet est réalisé dans un cadre
> pédagogique strictement encadré. Le code présent dans ce dépôt ne doit être
> utilisé que dans des environnements de test isolés avec l'autorisation
> explicite des propriétaires des machines. Toute utilisation en dehors de ce
> cadre est illégale et engage la responsabilité de l'auteur.

---

## Structure du projet

```
Projet_BadUSB_Attack/
├── partie1/                    # Charge utile (attaque)
│   ├── payload/
│   │   ├── autorun.inf         # AutoRun – déclenche launcher.vbs à l'insertion
│   │   ├── launcher.vbs        # Lanceur silencieux VBScript
│   │   ├── payload.ps1         # Payload principal (version lisible)
│   │   └── payload_obfusque.ps1# Payload obfusqué (évasion AV)
│   └── serveur_c2/
│       ├── server.py           # Serveur C2 Flask (attaquant)
│       └── requirements.txt
└── partie2/
    └── defense.ps1             # Script de défense (testeur)
```

---

## Partie 1 – Charge utile BadUSB

### Vue d'ensemble du scénario

| Étape | Action | Délai |
|-------|--------|-------|
| 1 | Insertion de la clé USB dans le port | T+0 s |
| 2 | Windows lit `autorun.inf` → `launcher.vbs` s'exécute | T+0–1 s |
| 3 | `payload.ps1` s'exécute dans le contexte de l'utilisateur courant | T+1 s |
| 4 | Anti-analyse + élévation silencieuse (UAC bypass fodhelper) | T+1–3 s |
| 5 | Création du compte administrateur caché | T+4 s |
| 6 | Activation RDP + WinRM + règles pare-feu | T+5–8 s |
| 7 | Collecte des informations système | T+9 s |
| 8 | Exfiltration vers le serveur C2 (`10.10.1.13:8080`) | T+10–13 s |
| 9 | Nettoyage des journaux | T+13–15 s |
| 10 | Retrait de la clé USB | ≤ T+15 s |

### Déclenchement depuis un compte utilisateur standard

Le payload est conçu pour s'exécuter **depuis un compte utilisateur standard
(non élevé)**. L'élévation de privilèges est obtenue automatiquement via le
bypass UAC **fodhelper.exe** (MITRE ATT&CK T1548.002) :

1. `launcher.vbs` lance `payload.ps1` dans le contexte de l'utilisateur courant.
2. Le payload détecte qu'il ne tourne pas en mode administrateur.
3. Il inscrit la commande de re-lancement dans
   `HKCU:\Software\Classes\ms-settings\shell\open\command`, puis déclenche
   `fodhelper.exe` (processus auto-élevé de Windows 10/11).
4. Windows relance le payload avec les droits Administrateur, sans afficher
   de prompt UAC.
5. La clé temporaire est supprimée immédiatement.

```
[Compte utilisateur standard]
       │
       ▼
[launcher.vbs → payload.ps1 lancé]
       │
       ├─ Test-Admin → NON
       │
       ▼
[UAC bypass fodhelper]
       │
       ▼
[payload.ps1 relancé avec droits Admin]
       │
       ├─ Création compte backdoor (svc_XXXXXX)
       ├─ Activation RDP + WinRM
       └─ Exfiltration → 10.10.1.13:8080
```

### Fichiers à copier sur la clé USB

```
Racine de la clé USB/
├── autorun.inf             ← déclencheur (open=launcher.vbs)
├── launcher.vbs            ← lanceur silencieux
└── payload.ps1             ← charge utile
```

### Déploiement

**Étape 1 – Démarrer le serveur C2 sur la machine attaquante (10.10.1.13)**

```bash
cd partie1/serveur_c2
pip install -r requirements.txt
python server.py --host 0.0.0.0 --port 8080
```

Interface de suivi : `http://10.10.1.13:8080/status`

**Étape 2 – Préparer la clé USB**

Copier `autorun.inf`, `launcher.vbs` et `payload.ps1` (ou `payload_obfusque.ps1`)
à la racine de la clé USB.

**Étape 3 – Insérer la clé USB dans la machine cible**

L'utilisateur cible n'a pas besoin de droits administrateur. Le payload
s'élève automatiquement.

### Fonctionnalités du payload

#### Anti-analyse et évasion

| Mécanisme | Description |
|-----------|-------------|
| Détection VM | Vérifie les processus `vmtoolsd`, `vboxservice`, etc. |
| Détection sandbox | Contrôle RAM (< 2 Go), cœurs CPU (< 2), espace disque |
| Détection outils | Vérifie `wireshark`, `procmon`, `x64dbg`, `ida`, etc. |
| Clés de registre VM | Vérifie `VMware Tools`, `VirtualBox Guest Additions` |
| Temporisation | Pause initiale de 0,8 s (comportement moins suspect) |

#### Contournement UAC (T1548.002 MITRE ATT&CK)

Le bypass **fodhelper.exe** est utilisé :
- Écrit la commande malveillante dans
  `HKCU:\Software\Classes\ms-settings\shell\open\command`
- Lance `fodhelper.exe` (processus auto-élevé de Windows 10/11)
- Supprime la clé de registre immédiatement après

#### Création du compte administrateur

- Nom généré aléatoirement : `svc_<6 caractères alphanumériques>`
- Mot de passe de 18 caractères (alphanumérique + spéciaux)
- Ajouté aux groupes `Administrators` et `Remote Desktop Users`
- Caché de l'écran de connexion via
  `HKLM:\...\Winlogon\SpecialAccounts\UserList`

#### Activation de l'accès distant

| Protocole | Action |
|-----------|--------|
| RDP | `fDenyTSConnections = 0`, NLA désactivée, règle pare-feu activée |
| WinRM | `Enable-PSRemoting`, service démarré, TrustedHosts = `*` |
| Pare-feu | Règle entrante TCP 3389, 5985, 5986 (tous profils) |

#### Exfiltration des données

Données transmises en JSON via HTTP POST vers `http://10.10.1.13:8080/collect` :

```json
{
  "computer_name": "DESKTOP-XXXX",
  "domain": "WORKGROUP",
  "current_user": "Utilisateur",
  "os_version": "Windows 11 Pro",
  "local_ip": "192.168.1.10",
  "public_ip": "203.0.113.45",
  "backdoor_user": "svc_xKp3mT",
  "backdoor_pass": "P@ssw0rd!Random18",
  "rdp_port": 3389,
  "winrm_port": 5985,
  "timestamp": "2025-04-22 20:01:48"
}
```

Méthode de repli : encodage Base64 dans un paramètre GET (`/b64?d=<base64>`).

#### Nettoyage des traces

- Effacement des journaux d'événements (`System`, `Application`, `Security`,
  `Windows PowerShell`)
- Suppression de l'historique PowerShell (`ConsoleHost_history.txt`)
- Suppression des fichiers Prefetch PowerShell
- Désactivation de la journalisation PowerShell (ScriptBlock + Transcription)

### Version obfusquée (`payload_obfusque.ps1`)

Techniques appliquées :
- **Encodage Base64** des chaînes sensibles (chemins de registre, noms de
  commandes, noms de processus cibles)
- **Concaténation de chaînes** pour briser les signatures AV
  (`g1 "Get-" "Process"` → `Get-Process`)
- **Noms de variables obfusqués** (`$_vp`, `$_u`, `$_pw`, etc.)
- **Décodage dynamique** via la fonction `g0` (`[Convert]::FromBase64String`)
- **Substitution** des cmdlets par des appels via `&(g1 …)`

### Serveur C2 (`server.py`)

Interface de visualisation : `http://10.10.1.13:8080/status`

| Endpoint | Méthode | Rôle |
|----------|---------|------|
| `/collect` | POST | Reçoit le JSON exfiltré |
| `/b64?d=…` | GET | Repli Base64 |
| `/status` | GET | Tableau de bord HTML |
| `/` | GET | Page neutre |

Les données sont persistées dans `partie1/serveur_c2/logs/collected_targets.json`.

---

## Partie 2 – Script de défense (`defense.ps1`)

### Utilisation

```powershell
# Lancer en tant qu'Administrateur
powershell -ExecutionPolicy Bypass -File defense.ps1
```

### Mécanismes de protection

| N° | Mécanisme | Détails |
|----|-----------|---------|
| 1 | **Désactivation AutoRun/AutoPlay** | `NoDriveTypeAutoRun = 0xFF` en machine et utilisateur ; service `ShellHWDetection` désactivé |
| 2 | **Journalisation PowerShell** | ScriptBlock Logging, Module Logging, Transcription activés |
| 3 | **Surveillance USB (WMI)** | Événement WMI `__InstanceCreationEvent` sur `Win32_DiskDrive` ; tue les processus lancés depuis un lecteur amovible |
| 4 | **Surveillance créations de comptes** | WMI sur `Win32_UserAccount` ; désactive immédiatement tout nouveau compte |
| 5 | **Surveillance RDP/WinRM** | Timer toutes les 5 s ; rétablit la désactivation si modification détectée |
| 6 | **Surveillance processus PS cachés** | WMI sur `Win32_Process` ; détecte les indicateurs suspects (`-WindowStyle Hidden`, `-EncodedCommand`, etc.) et tue le processus |
| 7 | **Durcissement initial** | Vérifie et corrige RDP, WinRM, règles pare-feu et comptes cachés au démarrage |

### Indicateurs de compromission (IoC) surveillés

- Processus PowerShell avec `-WindowStyle Hidden`, `-NonInteractive`,
  `-EncodedCommand`, `-ExecutionPolicy Bypass`
- Nouveau compte local ajouté au groupe `Administrators`
- Modification de `fDenyTSConnections` (activation RDP)
- Démarrage ou activation du service WinRM
- Règle pare-feu `BackdoorRemoteAccess`
- Clés de registre `SpecialAccounts\UserList` (comptes cachés)

---

## Connexion à distance après compromission

Une fois les informations reçues sur le serveur C2, l'attaquant peut se
connecter à la machine cible via :

### RDP (Bureau à distance)

```
mstsc /v:<IP_CIBLE>:3389
Utilisateur : svc_<suffix>
Mot de passe : <reçu sur le serveur C2>
```

### PowerShell distant (WinRM)

```powershell
$cred = Get-Credential  # svc_<suffix> / <mot de passe>
Enter-PSSession -ComputerName <IP_CIBLE> -Credential $cred
```

---

## Références

- MITRE ATT&CK T1052.001 – Exfiltration Over USB
- MITRE ATT&CK T1548.002 – Bypass User Account Control (fodhelper)
- MITRE ATT&CK T1078.003 – Valid Accounts: Local Accounts
- MITRE ATT&CK T1021.001 – Remote Services: RDP
- MITRE ATT&CK T1059.001 – Command and Scripting Interpreter: PowerShell
- MITRE ATT&CK T1562.001 – Impair Defenses: Disable or Modify Tools
