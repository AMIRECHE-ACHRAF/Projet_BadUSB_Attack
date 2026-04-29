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
│   │   ├── autorun.inf         # AutoPlay/AutoRun (Windows XP-11)
│   │   ├── launcher.vbs        # Lanceur silencieux VBScript
│   │   ├── payload.ps1         # Payload principal (version lisible)
│   │   ├── payload_obfusque.ps1# Payload obfusqué (évasion AV)
│   │   └── prepare_usb.ps1     # Préparation clé USB (bypass AutoRun W10)
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
| 2a | AutoPlay (toast) → l'utilisateur clique → `launcher.vbs` via `shellexecute=` | T+0–5 s |
| 2b | *Ou* : l'utilisateur double-clique sur le leurre `Documents.lnk` | T+0–? s |
| 3 | `payload.ps1` s'exécute en arrière-plan | T+1 s |
| 4 | Anti-analyse + élévation silencieuse (UAC bypass) | T+1–3 s |
| 5 | Création du compte administrateur caché | T+4 s |
| 6 | Activation RDP + WinRM + règles pare-feu | T+5–8 s |
| 7 | Collecte des informations système | T+9 s |
| 8 | Exfiltration vers le serveur C2 | T+10–13 s |
| 9 | Nettoyage des journaux | T+13–15 s |
| 10 | Retrait de la clé USB | ≤ T+15 s |

### Mécanisme de déclenchement automatique

#### Pourquoi `autorun.inf` seul ne suffit plus sur Windows 10/11

Depuis Windows Vista (correctif KB971029), l'entrée **`open=`** de `autorun.inf`
est désactivée pour les lecteurs amovibles. Sur Windows 10/11 en configuration
standard, insérer une clé USB avec uniquement `autorun.inf` ne déclenche
**aucun programme automatiquement**.

#### Stratégie de contournement (deux couches)

| Couche | Technique | Interaction requise |
|--------|-----------|---------------------|
| 1 – AutoPlay | `shellexecute=` + `UseAutoPlay=1` dans `autorun.inf` | L'utilisateur clique sur la notification toast, puis sur l'action affichée |
| 2 – LNK leurre | Raccourci `.lnk` avec icône de dossier à la racine de la clé | L'utilisateur ouvre l'Explorateur et double-clique sur le « dossier » |

**Couche 1 – AutoPlay (Windows 10/11)**

Windows 10/11 affiche encore une notification *toast* lors de l'insertion d'une
clé USB. L'entrée `shellexecute=launcher.vbs` dans `autorun.inf` alimente le
menu AutoPlay : si l'utilisateur clique sur la notification puis sélectionne
l'action *« Ouvrir le dossier pour afficher les fichiers »*, `launcher.vbs`
s'exécute de façon transparente.

**Couche 2 – Raccourci LNK trompeur (ingénierie sociale)**

Le script `prepare_usb.ps1` crée automatiquement :
- Un fichier `Documents.lnk` à la racine de la clé, affichant une icône de
  dossier Windows standard — indiscernable d'un vrai dossier pour l'utilisateur.
- La cible réelle du raccourci est `wscript.exe //B launcher.vbs`, ce qui
  exécute le payload en mode silencieux (aucune fenêtre visible).
- Les vrais fichiers du payload (`autorun.inf`, `launcher.vbs`, `payload.ps1`)
  sont masqués avec les attributs Système + Caché (`attrib +H +S`).

Résultat : l'utilisateur ne voit qu'un dossier *« Documents »* sur sa clé. En
double-cliquant dessus, il déclenche le payload à son insu.

### Fichiers à copier sur la clé USB

```
Racine de la clé USB/
├── autorun.inf             ← masqué après prepare_usb.ps1
├── launcher.vbs            ← masqué après prepare_usb.ps1
├── payload.ps1             ← masqué après prepare_usb.ps1
└── Documents.lnk           ← créé par prepare_usb.ps1 (visible, icône dossier)
```

### Configuration avant déploiement

1. Lancer le serveur C2 sur la machine attaquante :
   ```bash
   cd partie1/serveur_c2
   pip install -r requirements.txt
   python server.py --host 0.0.0.0 --port 8080
   ```

2. Noter l'adresse IP publique/locale de la machine attaquante.

3. Remplacer `ATTACKER_IP` dans `payload.ps1` (et `payload_obfusque.ps1`) :
   ```powershell
   $c2Base = "http://192.168.X.X:8080"   # Remplacer ici
   ```

4. Copier `autorun.inf`, `launcher.vbs` et `payload.ps1` à la racine de la
   clé USB.

5. **Préparer la clé USB avec le bypass Windows 10** (depuis la machine
   attaquante ou toute machine Windows) :
   ```powershell
   powershell -ExecutionPolicy Bypass -File prepare_usb.ps1 -DriveLetter E
   ```
   Ce script crée le raccourci `Documents.lnk` et masque les fichiers payload.

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

Données transmises en JSON via HTTP POST vers `$c2Base/collect` :

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

Interface de visualisation : `http://ATTACKER_IP:8080/status`

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
mstsc /v:<IP_PUBLIQUE>:3389
Utilisateur : svc_<suffix>
Mot de passe : <reçu sur le serveur C2>
```

### PowerShell distant (WinRM)

```powershell
$cred = Get-Credential  # svc_<suffix> / <mot de passe>
Enter-PSSession -ComputerName <IP_PUBLIQUE> -Credential $cred
```

---

## Références

- MITRE ATT&CK T1052.001 – Exfiltration Over USB
- MITRE ATT&CK T1548.002 – Bypass User Account Control (fodhelper)
- MITRE ATT&CK T1078.003 – Valid Accounts: Local Accounts
- MITRE ATT&CK T1021.001 – Remote Services: RDP
- MITRE ATT&CK T1059.001 – Command and Scripting Interpreter: PowerShell
- MITRE ATT&CK T1562.001 – Impair Defenses: Disable or Modify Tools
