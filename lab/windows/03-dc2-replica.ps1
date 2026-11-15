<#
 Stage 3 on vglab-dc2: second domain controller, so replication-lag behaviour can be tested.
 Lab only.
#>
param(
  [string]$Ip = "10.77.0.12",
  [string]$Gateway = "10.77.0.1",
  [string]$Dns = "10.77.0.11",
  [string]$Domain = "vg.lab"
)
$ErrorActionPreference = "Stop"
$nic = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $Ip -PrefixLength 24 -DefaultGateway $Gateway
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $Dns
Rename-Computer -NewName "dc2" -Force

Install-WindowsFeature AD-Domain-Services, DNS -IncludeManagementTools
$cred = Get-Credential -Message "VG\Administrator (domain admin)"
$dsrm = Read-Host "Directory Services Restore Mode password" -AsSecureString
Install-ADDSDomainController -DomainName $Domain -Credential $cred -InstallDns `
  -SafeModeAdministratorPassword $dsrm -Force
# Reboots automatically. After boot: certutil -pulse   (to enrol the DC certificate for LDAPS)
