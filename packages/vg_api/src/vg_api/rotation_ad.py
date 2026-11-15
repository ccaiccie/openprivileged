"""Explicitly allowlisted AD-lab password reset; never provisions rights or users.

No network access occurs at construction. Operator must separately approve exact
synthetic account GUIDs, SSH authority, LDAPS identity and credential storage.
"""

import base64
import json
import re
import subprocess
from dataclasses import dataclass
from uuid import UUID

from vg_core.rotation import AccountBinding

from vg_api.directory import DirectoryDenied, LdapsDirectory
from vg_api.lab_access import SSHTarget
from vg_api.ssh_sessions import ssh_command


@dataclass(frozen=True)
class AdRotationAccount:
    binding: AccountBinding
    object_guid: str
    distinguished_name: str

    def __post_init__(self) -> None:
        UUID(self.object_guid)
        if not self.distinguished_name.casefold().endswith(
            ",ou=users,ou=vaultgate lab,dc=example,dc=local"
        ):
            raise ValueError("Only explicitly approved VaultGate Lab users are permitted")
        if (
            re.fullmatch(
                r"vg-[a-z0-9-]{1,40}(?:@example\.local)?", self.binding.privileged_username
            )
            is None
        ):
            raise ValueError("Only synthetic vg- lab identities are permitted")


# Fixed script reads data through stdin, never a password literal/command argument.
# Check GUID, exact DN and username before reset. Never modify group membership.
RESET_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
try {
  Import-Module ActiveDirectory -ErrorAction Stop
  $p = [Console]::In.ReadToEnd() | ConvertFrom-Json
  $u = Get-ADUser -Identity ([Guid]$p.guid) -Properties DistinguishedName,SamAccountName
  if ($u.DistinguishedName -ine $p.dn -or $u.SamAccountName -cne $p.username) { throw 'scope' }
  $base = '*,OU=Users,OU=VaultGate Lab,DC=example,DC=local'
  if ($u.DistinguishedName -inotlike $base) { throw 'scope' }
  if ($u.SamAccountName -cnotmatch '^vg-[a-z0-9-]{1,40}$') { throw 'scope' }
  $secure = ConvertTo-SecureString -String $p.password -AsPlainText -Force
  Set-ADAccountPassword -Identity $u.ObjectGUID -Reset -NewPassword $secure -ErrorAction Stop
  [Console]::Out.Write('VG_ROTATED')
} catch { [Console]::Out.Write('VG_FAILED'); exit 1 }
"""


class AdLabRotationAdapter:
    def __init__(
        self,
        authority: SSHTarget,
        directory: LdapsDirectory,
        accounts: tuple[AdRotationAccount, ...],
    ):
        if authority.host != "192.0.2.116" or authority.port != 22:
            raise ValueError("Only the explicitly configured DC1 lab authority is supported")
        if directory.config.host.casefold() != "dc1.example.local":
            raise ValueError("LDAPS verifier must use the pinned DC1 DNS identity")
        self._authority = authority
        self._directory = directory
        self._accounts = {a.binding.id: a for a in accounts}
        if len(self._accounts) != len(accounts) or len(
            {a.object_guid.lower() for a in accounts}
        ) != len(accounts):
            raise ValueError("Duplicate allowlisted account")

    def _account(self, binding: AccountBinding) -> AdRotationAccount:
        account = self._accounts.get(binding.id)
        if account is None or account.binding != binding:
            raise ValueError("Account is not allowlisted")
        return account

    def change(self, binding: AccountBinding, password: str) -> None:
        account = self._account(binding)
        if not 32 <= len(password) <= 200:
            raise ValueError("Invalid managed password")
        command = ssh_command(self._authority)
        command[command.index("-tt")] = "-T"
        command += [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-EncodedCommand",
            base64.b64encode(RESET_SCRIPT.encode("utf-16le")).decode(),
        ]
        payload = json.dumps(
            {
                "guid": account.object_guid,
                "dn": account.distinguished_name,
                "username": binding.privileged_username.split("@", 1)[0],
                "password": password,
            }
        )
        try:
            result = subprocess.run(
                command, input=payload, text=True, capture_output=True, timeout=30, check=False
            )
            if result.returncode != 0 or result.stdout.strip() != "VG_ROTATED":
                raise ValueError("Reset not confirmed")
        except Exception:
            raise RuntimeError("AD rotation outcome uncertain; reconcile before reuse") from None

    def verify(self, binding: AccountBinding, password: str) -> bool:
        account = self._account(binding)
        try:
            with self._directory._connection(account.distinguished_name, password) as connection:
                # Binding alone is insufficient if a DN was deleted/recreated.
                if not connection.search(
                    account.distinguished_name,
                    "(objectClass=user)",
                    search_scope="BASE",
                    attributes=["objectGUID"],
                ):
                    raise RuntimeError("Account identity could not be verified")
                entries = [e for e in connection.response if e.get("type") == "searchResEntry"]
                if len(entries) != 1:
                    raise RuntimeError("Account identity could not be verified")
                raw = entries[0].get("raw_attributes", {}).get("objectGUID", [])
                return len(raw) == 1 and UUID(bytes_le=raw[0]) == UUID(account.object_guid)
        except DirectoryDenied:
            return False
        except Exception:
            raise RuntimeError("AD credential verification unavailable") from None
