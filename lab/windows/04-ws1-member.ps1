<#
 Stage 4 on vglab-ws1: join the domain, enable RDP with NLA, enable WinRM over HTTPS (5986),
 create a rotatable local admin and a service that runs under a vaulted account (dependent-account test).
 Lab only.
#>
param(
  [string]$Ip = "10.77.0.21",
  [string]$Gateway = "10.77.0.1",
  [string]$Dns = "10.77.0.11",
  [string]$Domain = "vg.lab"
)
$ErrorActionPreference = "Stop"
$nic = Get-NetAdapter | Where-Object Status -eq "Up" | Select-Object -First 1
New-NetIPAddress -InterfaceIndex $nic.ifIndex -IPAddress $Ip -PrefixLength 24 -DefaultGateway $Gateway
Set-DnsClientServerAddress -InterfaceIndex $nic.ifIndex -ServerAddresses $Dns

# RDP with Network Level Authentication required.
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 0
Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name UserAuthentication -Value 1
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# WinRM over HTTPS with a self-signed certificate (lab). Production uses a CA-issued certificate.
Enable-PSRemoting -Force -SkipNetworkProfileCheck
$cert = New-SelfSignedCertificate -DnsName "ws1.$Domain" -CertStoreLocation Cert:\LocalMachine\My
New-Item -Path WSMan:\LocalHost\Listener -Transport HTTPS -Address * `
  -CertificateThumbprint $cert.Thumbprint -HostName "ws1.$Domain" -Force
New-NetFirewallRule -DisplayName "WinRM HTTPS 5986" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow

# Rotatable local administrator and a dependent service account target.
$pw = Read-Host "Initial password for local admin vgadmin" -AsSecureString
New-LocalUser -Name "vgadmin" -Password $pw -PasswordNeverExpires
Add-LocalGroupMember -Group "Administrators" -Member "vgadmin"
Add-LocalGroupMember -Group "Remote Desktop Users" -Member "vgadmin"

Rename-Computer -NewName "ws1" -Force
$cred = Get-Credential -Message "VG\Administrator (to join the domain)"
Add-Computer -DomainName $Domain -Credential $cred -Restart
# After the reboot, run lab/windows/05-ws1-dependent-service.ps1 as VG\Administrator.
