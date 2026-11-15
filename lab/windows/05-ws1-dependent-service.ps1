<#
 Stage 5 on vglab-ws1: a Windows service that runs as the AD account VG\vgtest02, so the
 "dependent account" update path (ADR-0007) can be tested: after VaultGate rotates vgtest02,
 it must also update this service's stored credential and the service must still start.
 Lab only.
#>
$ErrorActionPreference = "Stop"
$pw = Read-Host "Current password of VG\vgtest02" -AsSecureString
$cred = New-Object System.Management.Automation.PSCredential("VG\vgtest02", $pw)
# Allow vgtest02 to log on as a service (assumes ntrights/secedit or GPO in a real setup; lab shortcut below).
$cfg = "$env:TEMP\lsa.inf"
secedit /export /cfg $cfg | Out-Null
$sid = (New-Object System.Security.Principal.NTAccount("VG\vgtest02")).Translate([System.Security.Principal.SecurityIdentifier]).Value
(Get-Content $cfg) -replace '^(SeServiceLogonRight = .*)$', "`$1,*$sid" | Set-Content $cfg
secedit /configure /db "$env:TEMP\lsa.sdb" /cfg $cfg /areas USER_RIGHTS | Out-Null

New-Service -Name "VGDependentTest" -BinaryPathName "C:\Windows\System32\svchost.exe -k netsvcs" `
  -DisplayName "VaultGate dependent-account test" -Credential $cred -StartupType Manual
Write-Host "Service VGDependentTest created, runs as VG\vgtest02."
