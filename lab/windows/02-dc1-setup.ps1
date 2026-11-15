<#
 Stage 2 on vglab-dc1 after the forest exists: certificate authority (so DCs get trusted LDAPS certs),
 the delegated VaultGate manager account (ADR-0007), and test objects.
 Lab only.
#>
param(
  [string]$Domain = "vg.lab"
)
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory
$dn = (Get-ADDomain).DistinguishedName

# 1. Enterprise root CA so domain controllers auto-enrol a Domain Controller certificate (LDAPS 636).
Install-WindowsFeature ADCS-Cert-Authority -IncludeManagementTools
Install-AdcsCertificationAuthority -CAType EnterpriseRootCa -CaCommonName "VG-Lab-CA" -Force
certutil -pulse | Out-Null

# 2. OU for vaulted accounts and the delegated manager account.
$ou = New-ADOrganizationalUnit -Name "VaultManaged" -Path $dn -PassThru
$ouDn = $ou.DistinguishedName
$mgrPw = Read-Host "Password for svc-vaultgate (manager account)" -AsSecureString
New-ADUser -Name "svc-vaultgate" -SamAccountName "svc-vaultgate" -AccountPassword $mgrPw `
  -Enabled $true -PasswordNeverExpires $true -Description "VaultGate delegated manager (reset password only)"
# Deny interactive/RDP logon is applied by GPO in a real deployment; documented in the delegation guide.

# 3. Least-privilege delegation on the OU only: Reset Password, write pwdLastSet, read user properties.
dsacls $ouDn /I:S /G "VG\svc-vaultgate:CA;Reset Password;user" | Out-Null
dsacls $ouDn /I:S /G "VG\svc-vaultgate:RPWP;pwdLastSet;user"  | Out-Null
dsacls $ouDn /I:S /G "VG\svc-vaultgate:RP;;user"              | Out-Null

# 4. Test accounts inside the delegated OU, plus one OUTSIDE it to prove the delegation boundary.
$tmp = ConvertTo-SecureString "Initial-Lab-Pass-1!" -AsPlainText -Force
New-ADUser -Name "vgtest01" -SamAccountName "vgtest01" -Path $ouDn -AccountPassword $tmp -Enabled $true
New-ADUser -Name "vgtest02" -SamAccountName "vgtest02" -Path $ouDn -AccountPassword $tmp -Enabled $true
New-ADUser -Name "outside01" -SamAccountName "outside01" -Path "CN=Users,$dn" -AccountPassword $tmp -Enabled $true

# 5. Lab account lockout policy so the negative tests are meaningful.
Set-ADDefaultDomainPasswordPolicy -Identity $Domain -LockoutThreshold 5 -LockoutDuration 00:10:00 `
  -LockoutObservationWindow 00:10:00 -MinPasswordLength 12 -ComplexityEnabled $true
Write-Host "dc1 setup complete. Now promote dc2 (03-dc2-replica.ps1)."
