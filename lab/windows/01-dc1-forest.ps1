<#
 Stage 1 on vglab-dc1 (run as local Administrator, elevated PowerShell).
 Sets the static IP, installs AD DS + DNS, creates the forest vg.lab, then reboots.
 Lab only. Untested until you run it in the VM.
#>
param(
  [string]$Ip = "10.77.0.11",
  [string]$Gateway = "10.77.0.1",
  [string]$Domain = "vg.lab",
  [string]$NetBios = "VG"
)
$ErrorActionPreference = "Stop"
$nic = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $Ip -PrefixLength 24 -DefaultGateway $Gateway
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $Ip
Rename-Computer -NewName "dc1" -Force

Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
$dsrm = Read-Host "Directory Services Restore Mode password" -AsSecureString
Install-ADDSForest -DomainName $Domain -DomainNetbiosName $NetBios -InstallDns `
  -SafeModeAdministratorPassword $dsrm -Force
# The server reboots automatically. Continue with 02-dc1-setup.ps1 after it comes back.
